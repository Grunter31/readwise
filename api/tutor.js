// api/tutor.js — Burrow's serverless proxy to Anthropic
// Hardened: origin allowlist + per-IP rate limiting + method/size checks
//
// To allow new domains (e.g. when you buy a custom domain), edit ALLOWED_ORIGINS below.
// To adjust the rate limit, edit RATE_LIMIT_PER_HOUR below.

// ─── CONFIGURATION ──────────────────────────────────────────────────────────

// Domains allowed to call this API. Add your custom domain here when you have one.
// The wildcard match for *.vercel.app/grunter31s-projects covers all your preview deploys.
const ALLOWED_ORIGINS = [
  'https://readwise-three.vercel.app',          // production
  // Add your custom domain when ready:
  // 'https://burrow.com.au',
  // 'https://www.burrow.com.au',
];

// Also allow ANY Vercel preview belonging to your account.
// Pattern matches: https://readwise-git-{branch}-grunter31s-projects.vercel.app
//                  https://readwise-{hash}-grunter31s-projects.vercel.app
const ALLOWED_ORIGIN_PATTERNS = [
  /^https:\/\/readwise-[a-z0-9-]+-grunter31s-projects\.vercel\.app$/,
];

// Localhost is allowed for local testing only when running `vercel dev`
const ALLOW_LOCALHOST = true;

// Per-IP rate limit (per hour). 80 = roughly 3-4 full Burrow sessions per hour.
const RATE_LIMIT_PER_HOUR = 80;

// Maximum request body size (bytes). Prevents huge prompt injection attempts.
const MAX_BODY_BYTES = 30_000;  // ~30KB — generous for normal use

// ─── RATE LIMIT STORE ───────────────────────────────────────────────────────
// Vercel serverless functions are stateless across cold starts, but stay warm
// for ~5-15 minutes within an instance. This in-memory store is "good enough"
// for blocking obvious abuse — a determined attacker can wait out cold starts,
// but they'd need to be patient. For bulletproof rate limiting, use Upstash KV.

const rateStore = globalThis.__burrow_rate_store || new Map();
globalThis.__burrow_rate_store = rateStore;

function checkRateLimit(ip) {
  const now = Date.now();
  const windowMs = 60 * 60 * 1000; // 1 hour
  const record = rateStore.get(ip);

  if (!record) {
    rateStore.set(ip, { count: 1, windowStart: now });
    return { allowed: true, remaining: RATE_LIMIT_PER_HOUR - 1 };
  }

  // Reset window if expired
  if (now - record.windowStart > windowMs) {
    rateStore.set(ip, { count: 1, windowStart: now });
    return { allowed: true, remaining: RATE_LIMIT_PER_HOUR - 1 };
  }

  // Within window — check count
  if (record.count >= RATE_LIMIT_PER_HOUR) {
    const resetIn = Math.ceil((windowMs - (now - record.windowStart)) / 1000 / 60);
    return { allowed: false, resetInMinutes: resetIn };
  }

  record.count += 1;
  return { allowed: true, remaining: RATE_LIMIT_PER_HOUR - record.count };
}

// Periodic cleanup — purge old entries when store gets large
function cleanupRateStore() {
  if (rateStore.size > 5000) {
    const cutoff = Date.now() - 60 * 60 * 1000;
    for (const [key, val] of rateStore.entries()) {
      if (val.windowStart < cutoff) rateStore.delete(key);
    }
  }
}

// ─── ORIGIN CHECK ───────────────────────────────────────────────────────────

function isOriginAllowed(origin) {
  if (!origin) return false;

  // Exact match against allowlist
  if (ALLOWED_ORIGINS.includes(origin)) return true;

  // Pattern match for preview deploys
  for (const pattern of ALLOWED_ORIGIN_PATTERNS) {
    if (pattern.test(origin)) return true;
  }

  // Localhost for dev
  if (ALLOW_LOCALHOST && /^https?:\/\/localhost(:\d+)?$/.test(origin)) return true;
  if (ALLOW_LOCALHOST && /^https?:\/\/127\.0\.0\.1(:\d+)?$/.test(origin)) return true;

  return false;
}

// ─── HANDLER ────────────────────────────────────────────────────────────────

export default async function handler(req, res) {
  const origin = req.headers.origin || req.headers.referer || '';
  const originClean = origin.replace(/\/$/, ''); // strip trailing slash

  // Get caller IP (Vercel passes it in x-forwarded-for)
  const forwardedFor = req.headers['x-forwarded-for'] || '';
  const ip = forwardedFor.split(',')[0].trim() || req.socket?.remoteAddress || 'unknown';

  // Allow CORS preflight from allowed origins
  if (req.method === 'OPTIONS') {
    if (isOriginAllowed(originClean)) {
      res.setHeader('Access-Control-Allow-Origin', originClean);
      res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
      res.setHeader('Access-Control-Max-Age', '86400');
    }
    return res.status(204).end();
  }

  // Method check
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed. Use POST.' });
  }

  // Origin check (the main gatekeeper)
  if (!isOriginAllowed(originClean)) {
    return res.status(403).json({
      error: 'Forbidden. This API can only be called from authorised Burrow domains.'
    });
  }

  // Set CORS for the actual response
  res.setHeader('Access-Control-Allow-Origin', originClean);
  res.setHeader('Vary', 'Origin');

  // Body size check (Vercel parses JSON body automatically)
  const bodyString = JSON.stringify(req.body || {});
  if (bodyString.length > MAX_BODY_BYTES) {
    return res.status(413).json({ error: 'Request body too large.' });
  }

  // Rate limit check
  const limit = checkRateLimit(ip);
  if (!limit.allowed) {
    res.setHeader('Retry-After', String(limit.resetInMinutes * 60));
    return res.status(429).json({
      error: `Too many requests. Try again in ${limit.resetInMinutes} minutes.`
    });
  }
  res.setHeader('X-RateLimit-Remaining', String(limit.remaining));

  // Periodic cleanup
  cleanupRateStore();

  // API key check
  const apiKey = process.env.ANTHROPIC_KEY || process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return res.status(500).json({ error: 'API key not configured on server.' });
  }

  // Forward to Anthropic
  try {
    const anthropicResponse = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(req.body),
    });

    const data = await anthropicResponse.json();
    return res.status(anthropicResponse.status).json(data);
  } catch (err) {
    console.error('Burrow API error:', err);
    return res.status(502).json({ error: 'Failed to reach AI service.' });
  }
}
