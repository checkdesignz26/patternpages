/**
 * Pattern Pages — access-key gate
 *
 * Your "ppages" Worker is currently a plain static-assets deployment (just
 * index.html, no code layer in front of it - that's why Cloudflare shows
 * "Metrics is unavailable for Workers with only static assets"). This file
 * is that missing code layer: Cloudflare's convention is a file named
 * exactly `_worker.js`, uploaded ALONGSIDE index.html in the same deployment.
 * When present, Cloudflare runs this script's fetch handler FIRST for every
 * request - it can serve the real file (via env.ASSETS.fetch) or, if there's
 * no valid key, show the gate page below instead. The real index.html is
 * never sent to someone without the key, so there's nothing to view-source
 * around.
 *
 * SETUP:
 * 1. Rename this file to exactly:  _worker.js
 * 2. On the "ppages" Worker's page -> "New deployment" (or wherever the
 *    upload/drag-and-drop for this project lives) -> upload BOTH
 *    index.html AND _worker.js together, same as your original upload.
 * 3. Settings -> Variables and Secrets -> add a SECRET (not a plain var)
 *    named ACCESS_KEY, value = whatever key you want to hand out to
 *    customers.
 * 4. Deploy.
 *
 * After that, a link like:
 *   https://ppages.checkdesignz.com/?key=YOUR-KEY-HERE
 * unlocks the site and remembers the visitor via a cookie for COOKIE_DAYS
 * days, so customers only need the link/key once. Anyone who hits the bare
 * domain without a valid key or cookie sees the gate page instead, with a
 * box to type the key in by hand.
 */

const COOKIE_NAME = 'pp_access';
const COOKIE_DAYS = 180;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const cookieHeader = request.headers.get('Cookie') || '';
    const hasValidCookie = cookieHeader
      .split(';')
      .map((c) => c.trim())
      .some((c) => c === `${COOKIE_NAME}=${env.ACCESS_KEY}`);

    // The gate page's form submits here as a POST. Cloudflare's static-asset
    // binding only ever serves GET/HEAD - handing it a POST request (as the
    // earlier version of this file did) gets a 405 back instead of the page.
    // Check the key, then redirect to a clean GET instead of trying to serve
    // the file directly in response to the form submit.
    if (request.method === 'POST') {
      const keyFromForm = await getFormKey(request);
      if (keyFromForm === env.ACCESS_KEY) {
        return new Response(null, {
          status: 303,
          headers: {
            Location: url.origin + url.pathname,
            'Set-Cookie': buildCookie(env.ACCESS_KEY),
          },
        });
      }
      return new Response(gatePage(true), {
        status: 401,
        headers: { 'content-type': 'text/html; charset=utf-8' },
      });
    }

    const keyFromQuery = url.searchParams.get('key');
    const keyIsValid = keyFromQuery === env.ACCESS_KEY;

    if (hasValidCookie || keyIsValid) {
      // Serve the real static file (index.html etc.) from this project's
      // own assets - this is the binding a static-assets Worker gets
      // automatically, not a fetch to an external origin.
      const response = await env.ASSETS.fetch(request);
      const out = new Response(response.body, response);
      // Only set/refresh the cookie when the key actually came in on this
      // request - no point rewriting it on every single page load.
      if (keyIsValid) {
        out.headers.append('Set-Cookie', buildCookie(env.ACCESS_KEY));
      }
      return out;
    }

    return new Response(gatePage(keyFromQuery !== null), {
      status: 401,
      headers: { 'content-type': 'text/html; charset=utf-8' },
    });
  },
};

async function getFormKey(request) {
  try {
    const form = await request.clone().formData();
    return form.get('key');
  } catch (e) {
    return null;
  }
}

function buildCookie(value) {
  const maxAge = COOKIE_DAYS * 24 * 60 * 60;
  return `${COOKIE_NAME}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`;
}

function gatePage(wrongKey) {
  return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pattern Pages</title>
<style>
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
    background:#141225;color:#fff8fb;font:16px/1.5 system-ui,-apple-system,sans-serif;}
  .card{max-width:360px;width:90%;padding:32px 28px;border-radius:18px;
    background:rgba(255,255,255,.06);border:1px solid rgba(255,232,248,.14);text-align:center;}
  h1{font-size:20px;margin:0 0 6px;}
  p{color:#c9c1d6;font-size:14px;margin:0 0 20px;}
  input{width:100%;box-sizing:border-box;padding:12px 14px;border-radius:12px;
    border:1px solid rgba(255,232,248,.24);background:rgba(255,255,255,.07);
    color:#fff8fb;font-size:15px;margin-bottom:12px;}
  button{width:100%;padding:12px;border:0;border-radius:12px;font-weight:800;
    font-size:15px;cursor:pointer;color:#fff;
    background:linear-gradient(90deg,#7c5cff,#ff5ea8);}
  .err{color:#ff8ea3;font-size:13px;margin:-8px 0 14px;}
</style>
</head>
<body>
  <div class="card">
    <h1>Pattern Pages</h1>
    <p>Enter your access key to continue.</p>
    ${wrongKey ? '<div class="err">That key wasn\'t right - try again.</div>' : ''}
    <form method="POST">
      <input type="text" name="key" placeholder="Access key" autofocus autocomplete="off">
      <button type="submit">Unlock</button>
    </form>
  </div>
</body>
</html>`;
}
