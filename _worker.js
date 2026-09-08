/**
 * Pattern Pages — access-key gate + 7-day free trial
 * (deployed via Cloudflare's Git integration from this repo)
 *
 * This is the code layer in front of the static `index.html` deployment
 * (Cloudflare runs this script's fetch handler first, per `run_worker_first`
 * in wrangler.toml, before ever falling back to env.ASSETS.fetch — an
 * unauthorized visitor never receives the real file at all).
 *
 * Originally this only checked one shared secret (env.ACCESS_KEY). It now
 * checks a KV namespace of many keys instead, each with its own type:
 *   - "lifetime": never expires (e.g. "82667", already handed out to real
 *     Etsy customers via the digital-download PDF - it's seeded into KV as
 *     a permanent entry rather than living in env.ACCESS_KEY any more).
 *   - "trial": expires 7 days after it's first minted.
 *
 * A brand-new visitor (no cookies at all) is let straight in and silently
 * starts a 7-day trial - no signup step, matching how Etsy buyers already
 * expect to just click a link and be working. A returning visitor mid-trial
 * is let in via a `pp_trial` cookie (an opaque id, never shown to the user
 * or typed in - only real access keys are). Once the trial's KV record
 * expires, they see the gate page again, now with trial-expired copy and a
 * link back to the Etsy listing, instead of the original "wrong/missing
 * key" copy.
 *
 * SETUP (one-time, in the Cloudflare dashboard for the "ppages" Worker):
 * 1. Workers & Pages -> KV -> create a namespace (any name, e.g.
 *    "pp-licenses"). Copy its ID.
 * 2. On the "ppages" Worker -> Settings -> Bindings -> add a KV namespace
 *    binding: variable name PP_LICENSES, pointing at the namespace from
 *    step 1. (This replaces the old ACCESS_KEY secret - that can be
 *    deleted once 82667 is confirmed working via KV instead, see the
 *    generate-etsy-codes.js script for how 82667 gets seeded in.)
 * 3. Add two more secrets under Settings -> Variables and Secrets:
 *    - RESEND_API_KEY: an API key from resend.com, used to actually send
 *      the "here's your code" and "here's your code again" emails.
 *    - ISSUE_SECRET: any long random string you make up - this is what
 *      proves a call to /api/issue-code really came from your own Zapier
 *      automation and not a random visitor trying to mint free codes.
 * 4. Deploy this file (same drag-and-drop/upload flow as before - upload
 *    index.html and this _worker.js together).
 *
 * After that, a link like:
 *   https://ppages.checkdesignz.com/?key=YOUR-KEY-HERE
 * unlocks the site and remembers the visitor via a cookie for COOKIE_DAYS
 * days. Anyone who hits the bare domain with no valid key/cookie/trial sees
 * the gate page, with a box to type a key in by hand.
 *
 * Two more routes this file now handles itself, ahead of the gate logic:
 *   POST /api/issue-code  - called by a Zapier "New Etsy Order" automation
 *     to mint a fresh unique code for that buyer and email it to them
 *     directly (see worker/SETUP.md for the exact Zap to build).
 *   GET/POST /recover     - a page a locked-out customer can use to have
 *     their code emailed to them again, by the email address it was
 *     issued to.
 * See worker/SETUP.md for the full walkthrough of both.
 */

const ACCESS_COOKIE = 'pp_access';
const TRIAL_COOKIE = 'pp_trial';
const COOKIE_DAYS = 180;
const TRIAL_DAYS = 7;
const RATE_LIMIT_MAX_ATTEMPTS = 20;
const RATE_LIMIT_WINDOW_SECONDS = 60 * 60;
const CODE_DIGITS = 5;
const RECOVERY_MAX_ATTEMPTS = 5;
const RECOVERY_WINDOW_SECONDS = 60 * 60;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === '/api/issue-code') {
      return handleIssueCode(request, env);
    }
    if (url.pathname === '/recover') {
      return handleRecover(request, env);
    }
    if (url.pathname === '/admin/stats') {
      return handleStats(request, env);
    }
    if (url.pathname === '/admin/reset-trials') {
      return handleResetTrials(request, env);
    }
    if (url.pathname === '/start-trial') {
      return handleStartTrial(request, env);
    }

    const cookies = parseCookies(request.headers.get('Cookie') || '');

    let attemptedKey = null;
    let postForm = null;
    if (request.method === 'POST') {
      postForm = await getFormData(request);
      attemptedKey = postForm ? postForm.get('key') : null;
    } else {
      attemptedKey = url.searchParams.get('key');
    }

    // Any request that's actively trying a key (right or wrong) counts
    // against the rate limit, checked before touching KV for the key
    // itself - this is what actually blunts brute-forcing a short numeric
    // keyspace now that there's more than one valid value to guess.
    if (attemptedKey !== null) {
      // Only a typed-in form submission needs the CAPTCHA - a GET ?key=
      // link from an email is already a private, non-guessable link, not a
      // brute-forceable surface. Checked before the rate limit below so a
      // bot that fails this doesn't even spend one of its attempts.
      if (request.method === 'POST') {
        const token = postForm ? postForm.get('cf-turnstile-response') : null;
        const human = await verifyTurnstile(request, env, token);
        if (!human) {
          return new Response(gatePage('captchaFailed'), {
            status: 401,
            headers: { 'content-type': 'text/html; charset=utf-8' },
          });
        }
      }

      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      const allowed = await checkAndBumpRateLimit(env, `ratelimit:${ip}`, RATE_LIMIT_MAX_ATTEMPTS, RATE_LIMIT_WINDOW_SECONDS);
      if (!allowed) {
        return new Response(gatePage('rateLimited'), {
          status: 429,
          headers: { 'content-type': 'text/html; charset=utf-8' },
        });
      }

      const record = await lookupCode(env, attemptedKey);
      if (record) {
        if (request.method === 'POST') {
          // The gate page's form submits here as a POST. Cloudflare's
          // static-asset binding only ever serves GET/HEAD - redirect to a
          // clean GET instead of trying to serve the file directly in
          // response to the form submit (matches the original behaviour).
          return new Response(null, {
            status: 303,
            headers: { Location: url.origin + url.pathname, 'Set-Cookie': buildCookie(ACCESS_COOKIE, attemptedKey) },
          });
        }
        // GET ?key= - serve the real file directly in this same response
        // and set the cookie alongside it, exactly like the original
        // single-secret version did (no extra redirect round-trip for a
        // link like ppages.checkdesignz.com/?key=XXXXX).
        const response = await env.ASSETS.fetch(request);
        const out = new Response(response.body, response);
        out.headers.append('Set-Cookie', buildCookie(ACCESS_COOKIE, attemptedKey));
        return out;
      }

      // Wrong key. GET requests with a bad ?key= just fall through to the
      // normal cookie/trial checks below (so a stale bookmarked link with
      // an old key doesn't lock out someone who separately already has a
      // valid cookie) - only a POST form submit gets the immediate
      // "that key wasn't right" response, matching the original behaviour.
      if (request.method === 'POST') {
        return new Response(gatePage('wrongKey'), {
          status: 401,
          headers: { 'content-type': 'text/html; charset=utf-8' },
        });
      }
    }

    // A valid access key (lifetime or trial-as-a-typed-key, though trials
    // are never typed in practice) already exchanged for a cookie.
    const accessCookieValue = cookies[ACCESS_COOKIE];
    if (accessCookieValue) {
      const record = await lookupCode(env, accessCookieValue);
      if (record) {
        return env.ASSETS.fetch(request);
      }
    }

    // Mid-trial return visit, or a brand-new visitor about to start one.
    // Uses getRawRecord (not lookupCode) because lookupCode filters out
    // expired trials entirely - here we need to tell "expired" (show
    // trial-expired copy) apart from "no such record at all" (treat as a
    // brand-new visitor and start a trial), not just get a yes/no.
    const trialCookieValue = cookies[TRIAL_COOKIE];
    if (trialCookieValue) {
      const trial = await getRawRecord(env, trialCookieValue);
      if (trial && trial.type === 'trial' && !trial.revoked) {
        if (Date.now() < trial.expiresAt) {
          const response = await env.ASSETS.fetch(request);
          // /start-trial redirects here with ?welcome=1 on the very first
          // request of a freshly minted trial - inject the banner exactly
          // once, right here, since minting itself now happens in that
          // separate POST, which never sees the actual page content.
          if (url.searchParams.get('welcome') === '1') {
            return injectWelcomeBanner(response);
          }
          return response;
        }
        return new Response(gatePage('trialExpired'), {
          status: 401,
          headers: { 'content-type': 'text/html; charset=utf-8' },
        });
      }
      // Cookie present but no matching (or revoked) KV record - e.g. a
      // very old/foreign cookie - fall through and treat as a brand-new
      // visitor below.
    }

    // Crawlers, link-preview fetchers and uptime checkers never carry
    // cookies either, so without this they'd each mint their own trial and
    // inflate /admin/stats. They still get the real page - just without a
    // trial being counted or a cookie being set for them.
    if (isLikelyBot(request)) {
      return env.ASSETS.fetch(request);
    }

    // A brand-new human visitor - show a quick CAPTCHA interstitial before
    // minting a trial, rather than minting one automatically. Turnstile's
    // managed mode passes most real visitors through with no visible
    // challenge at all, but it stops scripted trial-farming and keeps
    // /admin/stats meaningful.
    return new Response(trialGatePage({ redirectTo: url.pathname }), {
      headers: { 'content-type': 'text/html; charset=utf-8' },
    });
  },
};

async function handleStartTrial(request, env) {
  if (request.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }
  const form = await getFormData(request);
  const token = form ? form.get('cf-turnstile-response') : null;
  const human = await verifyTurnstile(request, env, token);
  const redirectTo = (form && form.get('redirect_to')) || '/';
  if (!human) {
    return new Response(trialGatePage({ error: true, redirectTo }), {
      status: 401,
      headers: { 'content-type': 'text/html; charset=utf-8' },
    });
  }

  const trialId = await mintTrial(env);
  const separator = redirectTo.includes('?') ? '&' : '?';
  return new Response(null, {
    status: 303,
    headers: {
      Location: redirectTo + separator + 'welcome=1',
      'Set-Cookie': buildCookie(TRIAL_COOKIE, trialId),
    },
  });
}

function trialGatePage({ error = false, redirectTo = '/' } = {}) {
  const errorLine = error ? '<div class="err">That didn\'t verify - please try the checkbox again.</div>' : '';
  return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pattern Pages</title>
${BRAND_FONTS}
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<style>${BRAND_STYLE}
  #pp-trial-go:disabled{opacity:0.5;cursor:default;}
</style>
</head>
<body>
  <div class="card">
    <h1>Pattern Pages</h1>
    <p>One quick check before your free 7-day trial starts.</p>
    ${errorLine}
    <form method="POST" action="/start-trial">
      <input type="hidden" name="redirect_to" value="${escapeHtml(redirectTo)}">
      <div class="cf-turnstile" data-sitekey="${TURNSTILE_SITE_KEY}" data-callback="ppTrialEnable" style="margin-bottom:0.85rem;display:flex;justify-content:center;"></div>
      <button type="submit" id="pp-trial-go" disabled>start my trial</button>
    </form>
  </div>
  <script>function ppTrialEnable(){document.getElementById('pp-trial-go').disabled=false;}</script>
</body>
</html>`;
}

function injectWelcomeBanner(response) {
  const isHtml = (response.headers.get('content-type') || '').includes('text/html');
  if (!isHtml) return response;
  const rewritten = new HTMLRewriter()
    .on('head', new HeadFontInjector())
    .on('body', new WelcomeBannerInjector())
    .transform(response);
  // The injected markup makes the body longer than the original
  // Content-Length the static-asset response came with. Left in place,
  // browsers stop reading at that original byte count and silently
  // truncate exactly the appended banner/font-link - drop the header here
  // so the response falls back to chunked transfer instead.
  const headers = new Headers(rewritten.headers);
  headers.delete('content-length');
  return new Response(rewritten.body, { status: rewritten.status, statusText: rewritten.statusText, headers });
}

// Loads the brand's Google Fonts into the app's own <head> so the banner
// below (injected into <body>, possibly a different document context than
// the app's own styling) renders in Caveat/Patrick Hand instead of falling
// back to a generic system font.
class HeadFontInjector {
  element(element) {
    element.append(BRAND_FONTS, { html: true });
  }
}

class WelcomeBannerInjector {
  element(element) {
    element.append(WELCOME_BANNER_HTML, { html: true });
  }
}

const WELCOME_BANNER_HTML = `
<div id="pp-trial-welcome" style="position:fixed;bottom:20px;left:50%;transform:translateX(-50%) rotate(-0.5deg);z-index:2147483647;max-width:92vw;width:400px;box-sizing:border-box;background:oklch(0.99 0.012 90);color:oklch(0.29 0.045 40);border:2.5px solid oklch(0.29 0.045 40);border-radius:40px 14px 40px 14px / 14px 34px 14px 34px;box-shadow:5px 6px 0 0 oklch(0.29 0.045 40);padding:1.1rem 1.25rem;font-family:'Patrick Hand',cursive;font-size:0.98rem;line-height:1.4;display:flex;align-items:flex-start;gap:0.75rem;">
  <div style="flex:1;">
    <strong style="display:block;margin-bottom:0.25rem;font-family:'Caveat',cursive;font-size:1.6rem;font-weight:700;">🎉 Welcome to your 7-day free trial!</strong>
    <span style="color:oklch(0.48 0.035 55);">Explore everything, no signup or card needed. Bought on Etsy already? Just enter your access key any time.</span>
  </div>
  <button onclick="document.getElementById('pp-trial-welcome').remove()" aria-label="Dismiss" style="background:none;border:0;color:oklch(0.48 0.035 55);font-size:1.3rem;line-height:1;cursor:pointer;padding:0;font-family:inherit;">&times;</button>
</div>`;

// Not foolproof - a bot that lies about its User-Agent still gets counted -
// but it filters out the well-behaved majority (search crawlers, link
// unfurlers, uptime monitors, common HTTP libraries) without touching how
// any real browser is treated.
const BOT_USER_AGENT_PATTERN =
  /bot|crawl|spider|slurp|facebookexternalhit|slackbot|twitterbot|whatsapp|telegrambot|discordbot|pingdom|uptimerobot|headlesschrome|curl|wget|python-requests|go-http-client|okhttp|libwww/i;

function isLikelyBot(request) {
  const ua = request.headers.get('User-Agent') || '';
  if (!ua) return true;
  return BOT_USER_AGENT_PATTERN.test(ua);
}

function parseCookies(cookieHeader) {
  const out = {};
  cookieHeader.split(';').forEach((part) => {
    const idx = part.indexOf('=');
    if (idx === -1) return;
    const name = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (name) out[name] = value;
  });
  return out;
}

async function getFormData(request) {
  try {
    return await request.clone().formData();
  } catch (e) {
    return null;
  }
}

// Looks up a code in KV and returns its record only if it's currently
// usable (not revoked, and - for trials - not expired). Callers that need
// to distinguish "expired trial" from "no such code" (to choose gate page
// copy) read env.PP_LICENSES directly instead - this helper is for the
// "is this good enough to let them in right now" checks.
async function lookupCode(env, code) {
  if (!code) return null;
  let raw;
  try {
    raw = await env.PP_LICENSES.get(code);
  } catch (e) {
    return null;
  }
  if (!raw) return null;
  let record;
  try {
    record = JSON.parse(raw);
  } catch (e) {
    return null;
  }
  if (record.revoked) return null;
  if (record.type === 'trial' && (!record.expiresAt || Date.now() >= record.expiresAt)) return null;
  return record;
}

// Unlike lookupCode, returns whatever is in KV as-is with no revoked/expiry
// filtering, so callers can tell "expired" apart from "never existed" (and
// check revoked themselves) rather than just getting a plain yes/no.
async function getRawRecord(env, code) {
  if (!code) return null;
  let raw;
  try {
    raw = await env.PP_LICENSES.get(code);
  } catch (e) {
    return null;
  }
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch (e) {
    return null;
  }
}

async function mintTrial(env) {
  const id = 'trial_' + crypto.randomUUID().replace(/-/g, '');
  const now = Date.now();
  const expiresAt = now + TRIAL_DAYS * 24 * 60 * 60 * 1000;
  const record = { type: 'trial', createdAt: now, expiresAt, revoked: false };
  // Storing expiresAt as KV metadata (not just inside the value) lets the
  // stats page below count active-vs-expired trials straight from list()
  // results, without a separate get() per trial.
  await env.PP_LICENSES.put(id, JSON.stringify(record), { metadata: { expiresAt } });
  return id;
}

// key should already include whatever prefix distinguishes this rate
// limit "bucket" from others (e.g. "ratelimit:<ip>" for key-guessing,
// "recover-ip:<ip>" or "recover-email:<email>" for the recovery form) -
// each bucket is tracked independently.
async function checkAndBumpRateLimit(env, key, maxAttempts, windowSeconds) {
  let current = 0;
  try {
    const raw = await env.PP_LICENSES.get(key);
    current = raw ? parseInt(raw, 10) || 0 : 0;
  } catch (e) {
    // If KV is having trouble, fail open on rate limiting rather than
    // locking everyone out - the key lookup itself is still the real gate.
    return true;
  }
  if (current >= maxAttempts) return false;
  try {
    await env.PP_LICENSES.put(key, String(current + 1), { expirationTtl: windowSeconds });
  } catch (e) {}
  return true;
}

function buildCookie(name, value, days = COOKIE_DAYS) {
  const maxAge = days * 24 * 60 * 60;
  return `${name}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`;
}

const ETSY_LISTING_URL = 'https://checkdesignz.etsy.com/listing/4562855179';

// Matches the "Seamlessly Creative" brand (checkdesignz.com) - same tokens,
// fonts and hand-drawn doodle-card/doodle-pill shapes as the marketing site,
// so the gate/recover pages and the trial-welcome banner feel like part of
// the same product instead of a generic dark SaaS auth screen.
const BRAND_FONTS = `<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Caveat:wght@600;700&family=Patrick+Hand&display=swap">`;

const BRAND_STYLE = `
  :root{
    --cream: oklch(0.965 0.021 88);
    --ink: oklch(0.29 0.045 40);
    --coral: oklch(0.76 0.11 35);
    --coral-foreground: oklch(0.27 0.05 35);
    --card: oklch(0.99 0.012 90);
    --muted-foreground: oklch(0.48 0.035 55);
    --font-display: "Caveat", cursive;
    --font-body: "Patrick Hand", cursive;
  }
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
    background:var(--cream);color:var(--ink);font:17px/1.5 var(--font-body);padding:2rem 1rem;}
  .card{max-width:380px;width:100%;padding:2.25rem 2rem;text-align:center;
    background:var(--card);border:2.5px solid var(--ink);
    border-radius:250px 18px 235px 18px / 18px 220px 18px 235px;
    box-shadow:5px 6px 0 0 var(--ink);transform:rotate(-0.6deg);}
  h1{font-family:var(--font-display);font-size:2.4rem;font-weight:700;margin:0 0 0.35rem;}
  p{color:var(--muted-foreground);font-size:1.05rem;margin:0 0 1.25rem;}
  input{width:100%;box-sizing:border-box;padding:0.7rem 1rem;border-radius:12px;
    border:2px solid var(--ink);background:var(--cream);color:var(--ink);
    font:1.05rem var(--font-body);margin-bottom:0.85rem;}
  input::placeholder{color:var(--muted-foreground);}
  button{width:100%;border:2.5px solid var(--ink);
    border-radius:140px 26px 140px 26px / 26px 130px 26px 130px;
    box-shadow:4px 4px 0 0 var(--ink);background:var(--coral);color:var(--coral-foreground);
    font-family:var(--font-display);font-size:1.4rem;font-weight:700;
    padding:0.6rem 1.25rem;cursor:pointer;transition:transform 150ms ease, box-shadow 150ms ease;}
  button:hover{transform:translate(2px,2px);box-shadow:2px 2px 0 0 var(--ink);}
  .err{color:color-mix(in oklab, var(--coral) 65%, var(--ink));font-size:0.95rem;margin:-0.5rem 0 1rem;}
  .buyLink{display:block;margin-top:1rem;color:var(--coral-foreground);font-size:1rem;
    font-weight:700;text-decoration:underline;text-underline-offset:3px;}
  .recoverLink, a.back{display:block;margin-top:0.75rem;color:var(--muted-foreground);
    font-size:0.9rem;text-decoration:none;}
  .recoverLink:hover, a.back:hover{text-decoration:underline;color:var(--ink);}
`;

// Turnstile (Cloudflare's CAPTCHA alternative) - the site key is public by
// design and safe to embed directly in pages; only the secret key (used in
// verifyTurnstile below) needs to stay private, as the TURNSTILE_SECRET_KEY
// Worker secret.
const TURNSTILE_SITE_KEY = '0x4AAAAAAEsKixos7mXlnT_O';

async function verifyTurnstile(request, env, token) {
  if (!token || !env.TURNSTILE_SECRET_KEY) return false;
  try {
    const body = new URLSearchParams();
    body.set('secret', env.TURNSTILE_SECRET_KEY);
    body.set('response', token);
    const ip = request.headers.get('CF-Connecting-IP');
    if (ip) body.set('remoteip', ip);
    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body });
    const data = await res.json();
    return !!data.success;
  } catch (e) {
    return false;
  }
}

function gatePage(variant) {
  let heading = 'Pattern Pages';
  let message = 'Enter your access key to continue.';
  let errorLine = '';
  let showBuyLink = false;

  if (variant === 'wrongKey') {
    errorLine = '<div class="err">That key wasn\'t right - try again.</div>';
  } else if (variant === 'trialExpired') {
    heading = 'Your trial has ended';
    message = 'Your 7-day free trial of Pattern Pages is over. Enter your access key to keep going, or buy on Etsy to get one.';
    showBuyLink = true;
  } else if (variant === 'rateLimited') {
    heading = 'Too many attempts';
    message = 'Too many key attempts from this connection - please wait a bit and try again.';
  } else if (variant === 'captchaFailed') {
    errorLine = '<div class="err">That didn\'t verify - please try the checkbox again.</div>';
  }

  return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pattern Pages</title>
${BRAND_FONTS}
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<style>${BRAND_STYLE}
  #pp-unlock-btn:disabled{opacity:0.5;cursor:default;}
</style>
</head>
<body>
  <div class="card">
    <h1>${heading}</h1>
    <p>${message}</p>
    ${errorLine}
    <form method="POST">
      <input type="text" name="key" placeholder="Access key" autofocus autocomplete="off">
      <div class="cf-turnstile" data-sitekey="${TURNSTILE_SITE_KEY}" data-callback="ppGateEnable" style="margin-bottom:0.85rem;display:flex;justify-content:center;"></div>
      <button type="submit" id="pp-unlock-btn" disabled>Unlock</button>
    </form>
    ${showBuyLink ? `<a class="buyLink" href="${ETSY_LISTING_URL}" target="_blank" rel="noopener">Buy Pattern Pages on Etsy &rarr;</a>` : ''}
    ${variant !== 'rateLimited' ? `<a class="recoverLink" href="/recover">Lost your access key?</a>` : ''}
  </div>
  <script>function ppGateEnable(){document.getElementById('pp-unlock-btn').disabled=false;}</script>
</body>
</html>`;
}

// ---------------------------------------------------------------------
// Issuing codes automatically after purchase (called by a Zapier "New
// Etsy Order" automation - see SETUP.md) and recovering a lost one.
// ---------------------------------------------------------------------

async function handleIssueCode(request, env) {
  if (request.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }
  const providedSecret = request.headers.get('X-Issue-Secret') || '';
  if (!env.ISSUE_SECRET || providedSecret !== env.ISSUE_SECRET) {
    return jsonResponse({ success: false, error: 'unauthorized' }, 401);
  }

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonResponse({ success: false, error: 'invalid JSON body' }, 400);
  }
  const email = normalizeEmail(body.email);
  const orderId = String(body.orderId || '').trim();
  if (!email || !orderId) {
    return jsonResponse({ success: false, error: 'email and orderId are both required' }, 400);
  }

  // Idempotent: Zapier (or any webhook sender) can retry the same order
  // more than once - always return the SAME code for a given orderId
  // rather than minting (and emailing) a second one.
  const orderKey = `order:${orderId}`;
  const existingCode = await env.PP_LICENSES.get(orderKey);
  if (existingCode) {
    return jsonResponse({ success: true, code: existingCode, reused: true });
  }

  const code = await generateUniqueCode(env);
  const now = Date.now();
  await env.PP_LICENSES.put(code, JSON.stringify({ type: 'lifetime', email, orderId, createdAt: now, revoked: false }));
  await env.PP_LICENSES.put(orderKey, code);
  // Recovery lookup key - stores the most recent code for an email. If the
  // same person buys again under the same email, this simply points at
  // whichever code they most recently received (their older code, if
  // still unrevoked, keeps working too - this only affects what /recover
  // finds for them).
  await env.PP_LICENSES.put(`email:${email}`, code);

  const emailResult = await sendEmail(env, {
    to: email,
    subject: 'Your Pattern Pages access key',
    html: purchaseEmailHtml(code),
  });

  return jsonResponse({ success: true, code, emailSent: emailResult.ok });
}

async function handleRecover(request, env) {
  if (request.method === 'GET') {
    return new Response(recoverPage(), { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } });
  }
  if (request.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const ipAllowed = await checkAndBumpRateLimit(env, `recover-ip:${ip}`, RECOVERY_MAX_ATTEMPTS, RECOVERY_WINDOW_SECONDS);
  if (!ipAllowed) {
    return new Response(recoverPage({ rateLimited: true }), { status: 429, headers: { 'content-type': 'text/html; charset=utf-8' } });
  }

  let email = null;
  try {
    const form = await request.clone().formData();
    email = normalizeEmail(form.get('email'));
  } catch (e) {}

  if (email) {
    // Also rate-limit per target email, not just per IP - stops someone
    // from spamming one specific inbox with recovery emails by rotating
    // IPs/VPNs.
    const emailAllowed = await checkAndBumpRateLimit(env, `recover-email:${email}`, RECOVERY_MAX_ATTEMPTS, RECOVERY_WINDOW_SECONDS);
    if (emailAllowed) {
      const code = await env.PP_LICENSES.get(`email:${email}`);
      if (code) {
        const record = await getRawRecord(env, code);
        if (record && !record.revoked) {
          await sendEmail(env, {
            to: email,
            subject: 'Your Pattern Pages access key',
            html: recoveryEmailHtml(code),
          });
        }
      }
    }
  }

  // Always show the same "if we found it, it's on its way" confirmation
  // regardless of whether an email was actually found/sent - so this
  // page can't be used to check which email addresses have a code
  // (email enumeration).
  return new Response(recoverPage({ submitted: true }), { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } });
}

// ---------------------------------------------------------------------
// A private view-only stats page for the shop owner - counts trials
// straight out of KV, no email or any other visitor data involved.
// ---------------------------------------------------------------------

async function handleStats(request, env) {
  const url = new URL(request.url);
  const providedKey = url.searchParams.get('key') || '';
  if (!env.STATS_KEY || providedKey !== env.STATS_KEY) {
    // 404 rather than 401/403 so this route doesn't advertise its own
    // existence to anyone poking around without the key.
    return new Response('Not found', { status: 404 });
  }

  const now = Date.now();
  let totalTrials = 0;
  let activeTrials = 0;
  let cursor;
  do {
    const page = await env.PP_LICENSES.list({ prefix: 'trial_', cursor });
    for (const key of page.keys) {
      totalTrials++;
      let expiresAt = key.metadata && key.metadata.expiresAt;
      if (expiresAt == null) {
        // Trials minted before the metadata field existed - fall back to
        // reading the value directly so old records still count correctly.
        const raw = await env.PP_LICENSES.get(key.name);
        if (raw) {
          try {
            expiresAt = JSON.parse(raw).expiresAt;
          } catch (e) {}
        }
      }
      if (expiresAt && now < expiresAt) activeTrials++;
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);

  return new Response(statsPage(totalTrials, activeTrials), {
    headers: { 'content-type': 'text/html; charset=utf-8' },
  });
}

function statsPage(totalTrials, activeTrials) {
  return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pattern Pages — trial stats</title>
${BRAND_FONTS}
<style>${BRAND_STYLE}
  .stats-grid{display:flex;gap:1.5rem;justify-content:center;margin:0.5rem 0 1.25rem;}
  .stat b{display:block;font-family:var(--font-display);font-size:2.75rem;line-height:1;}
  .stat span{color:var(--muted-foreground);font-size:0.9rem;}
</style>
</head>
<body>
  <div class="card" style="max-width:420px;">
    <h1>trial stats</h1>
    <div class="stats-grid">
      <div class="stat"><b>${totalTrials}</b><span>trials started</span></div>
      <div class="stat"><b>${activeTrials}</b><span>active right now</span></div>
    </div>
    <p style="margin:0;">"active" means still within their 7-day window, not necessarily online this second. No emails or personal data involved.</p>
  </div>
</body>
</html>`;
}

// One-time cleanup for the test trials minted while building/debugging this
// system - safe to run any time since it only ever touches trial_* records,
// never a real access key (lifetime or otherwise), so no paying customer is
// affected even if they're mid-trial when this runs.
async function handleResetTrials(request, env) {
  const url = new URL(request.url);
  const providedKey = url.searchParams.get('key') || '';
  if (!env.STATS_KEY || providedKey !== env.STATS_KEY) {
    return new Response('Not found', { status: 404 });
  }

  let deleted = 0;
  let cursor;
  do {
    const page = await env.PP_LICENSES.list({ prefix: 'trial_', cursor });
    for (const key of page.keys) {
      await env.PP_LICENSES.delete(key.name);
      deleted++;
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);

  return new Response(resetTrialsPage(deleted, providedKey), {
    headers: { 'content-type': 'text/html; charset=utf-8' },
  });
}

function resetTrialsPage(deletedCount, key) {
  return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pattern Pages — trials reset</title>
${BRAND_FONTS}
<style>${BRAND_STYLE}</style>
</head>
<body>
  <div class="card" style="max-width:420px;">
    <h1>done</h1>
    <p>Deleted ${deletedCount} trial record${deletedCount === 1 ? '' : 's'}.</p>
    <a class="buyLink" href="/admin/stats?key=${encodeURIComponent(key)}">view stats &rarr;</a>
  </div>
</body>
</html>`;
}

async function generateUniqueCode(env) {
  const min = Math.pow(10, CODE_DIGITS - 1);
  const max = Math.pow(10, CODE_DIGITS) - 1;
  for (let attempt = 0; attempt < 20; attempt++) {
    const code = String(Math.floor(min + Math.random() * (max - min + 1)));
    const existing = await env.PP_LICENSES.get(code);
    if (!existing) return code;
  }
  // Astronomically unlikely at this keyspace/volume, but fall back to a
  // wider random value rather than looping forever.
  return 'PP' + crypto.randomUUID().replace(/-/g, '').slice(0, 10).toUpperCase();
}

function normalizeEmail(value) {
  const email = String(value || '').trim().toLowerCase();
  if (!email || !email.includes('@') || email.length > 254) return null;
  return email;
}

async function sendEmail(env, { to, subject, html }) {
  if (!env.RESEND_API_KEY) {
    return { ok: false, error: 'RESEND_API_KEY not configured' };
  }
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        from: env.FROM_EMAIL || 'Pattern Pages <onboarding@resend.dev>',
        to: [to],
        subject,
        html,
      }),
    });
    return { ok: res.ok, status: res.status };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function emailShell(bodyHtml) {
  return `<div style="font-family:system-ui,-apple-system,sans-serif;max-width:480px;margin:0 auto;padding:32px 24px;color:#2a2438;">
    <h1 style="font-size:20px;margin:0 0 18px;">Pattern Pages</h1>
    ${bodyHtml}
    <p style="font-size:12.5px;color:#7a7488;margin-top:28px;">Check Designz</p>
  </div>`;
}

function purchaseEmailHtml(code) {
  return emailShell(`
    <p style="font-size:15px;line-height:1.5;">Thank you for buying Pattern Pages! Here's your access key:</p>
    <p style="font-size:28px;font-weight:800;letter-spacing:2px;background:#f7f4fe;border-radius:12px;padding:16px;text-align:center;margin:18px 0;">${escapeHtml(code)}</p>
    <p style="font-size:14px;line-height:1.5;">Open <a href="https://ppages.checkdesignz.com/?key=${encodeURIComponent(code)}">Pattern Pages</a> and enter this key the first time you're asked - after that you'll stay signed in for an extended period.</p>
    <p style="font-size:13px;line-height:1.5;color:#5c5570;">Lost this email later? Visit <a href="https://ppages.checkdesignz.com/recover">ppages.checkdesignz.com/recover</a> and we'll send your key again.</p>
  `);
}

function recoveryEmailHtml(code) {
  return emailShell(`
    <p style="font-size:15px;line-height:1.5;">Here's your Pattern Pages access key again:</p>
    <p style="font-size:28px;font-weight:800;letter-spacing:2px;background:#f7f4fe;border-radius:12px;padding:16px;text-align:center;margin:18px 0;">${escapeHtml(code)}</p>
    <p style="font-size:14px;line-height:1.5;">Open <a href="https://ppages.checkdesignz.com/?key=${encodeURIComponent(code)}">Pattern Pages</a> and enter it there.</p>
  `);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json' } });
}

function recoverPage({ submitted = false, rateLimited = false } = {}) {
  let body;
  if (rateLimited) {
    body = `<p>Too many recovery attempts from this connection - please wait a bit and try again.</p>`;
  } else if (submitted) {
    body = `<p>If that email has a Pattern Pages access key on file, we've just sent it. Check your inbox (and spam folder) in a minute or two.</p>`;
  } else {
    body = `
      <p>Enter the email address you used when you bought Pattern Pages, and we'll send your access key to it again.</p>
      <form method="POST">
        <input type="email" name="email" placeholder="you@example.com" autofocus autocomplete="email" required>
        <button type="submit">Send my access key</button>
      </form>
    `;
  }
  return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pattern Pages — recover access key</title>
${BRAND_FONTS}
<style>${BRAND_STYLE}</style>
</head>
<body>
  <div class="card">
    <h1>Recover your access key</h1>
    ${body}
    <a class="back" href="/">&larr; Back to Pattern Pages</a>
  </div>
</body>
</html>`;
}
