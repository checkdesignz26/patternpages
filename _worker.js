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
    <img src="data:image/webp;base64,UklGRv7kAABXRUJQVlA4WAoAAAAQAAAAuwIA8QEAQUxQSIgOAAAB/yckSPD/eGtEpO4jbBtJUvS992bnn/AxPJgR/Z+Aq5eh1gsCgsWSZir5XSwE06P4gZznLvE94pfhbbhUPJhTVNBMMaUG6qqgDC4sS2HctpEjaaf/qjfHu2dETAC9FlFQDXPaA2zGRkbMJzUukH4Zl0rHiqVcKo7lUnEsl4pfRhoD64xOjUBGVVHFsbGqJ9u2VTu2bau0IcmYbW1mZkY3BmFHYqft3UHY4diu7WdmZmbexgzCOcforRXHFMtS37x3REwA5di2ZbfN3ue+D8gO2pk5CifT4p0B2H4CamYRMQFyI0lyJClB1eyuvf664m0NguhnImIC6NjW5khSvu+PSLTWGh+Ptcz+94CmOiPi/xAWFtPvjBERE8D//f9//4Pe4nn8lwkfSj/l/LE7/5nkWQwPw2PVVwR9TQEFlIJvKVAU6513ZWVauyPAf0T5BCTcy0NVvFOk+oKBRCqC4IuJ6jlc/rdUjjBrzZE1axJKApM1SFuYCeZ6xEjBQCXQQtEYKCDBynHbaT4ftzbHaZpvzVIg7D3nieTXKdAncO8LoohREhA18eWYSExszYyoThIrFI1hJlAmgRzHGOqSzcguulZm1lqYRHKXzCSaEQSVKhhCBVVRyst7b0AERogqBRALCBSpyBsFypqytcpp2tyYb22sPrr715v37qwa2G9WFAEBuBCHqp/x9WOizpggIIWYRIgxaNKC5giJSbwLpQ2amRoGQKlSBHPoTCjOzIqZmcn1GjJHMmtF44xJQIoCG0ABQZBCQwgFBYz3VVuEAhrVBBVBRM4Z8dKr8hDbOFu9f+03P/rOdYhuizzcJYsRFIfe17QWAQFVgohGhVuSEfHy7chwIzOJ63I0c6zRScwkR8iUkJmBoVVikAAi1lIs4lw0gRH2HQWVcUDZVizEwMnoUJgwKAQTFEFEkM+VB9hzPJGDxZzufPUzP/pLI/rM3/3w/TfXY3WLNsXysWM5n4+zebaqYYmsZaCSKhskxiRkpBsYRTVq4i6ZSUjWrGMdM47HOgypzoAVuimhFrpv23Jr6abssv+H2//0xq28qHx8eIb9oC/qO565QEBd/9O3Pv0jjP5yfnzx9aP1epaVEQNmTS1bydJAOhBYWluChGgoaGGXAoggFAki8WVEBTC8V05c7Mc9ZN/nI/nOlID59c+/Eu0t9/svIkmDI6mcuXxVXxJ8Kj/WBvjG11ygv9/6RJElj8RJfcUv83NciLPPvLwUvfXb75/LAqDU2sZ69tZ6esdCYMR89foj7CuXYgQAeevqFH31WgmE69ful331Oghk/fZjoqsuEEA9urIVdtQoEhjTlT82esokANZ/fqOnSjS88pPHYTc5NHjt+18s3RyzIFx59/uO95OKBYTPeM/ziW4yDCDe/JaBXi4e8Kx3njM6iYfhypueRS/bNABe/DLsJB0gXHrtCsHo3DIMghPPO0kn9xIOHZ52rpfO5gFcPPuvXOfP/CvX6W5afxLh5KleOosIyyd6KYcIK8f6KUAoptMmwlLSkYKD+fgw6iMg9l0xDhJSU0qA4Ary2QJixoiiXkRwLQOS0kRQxNhQOGYknRABNBKCqYng9uJSfXGZU4ggi3KLXAkSTKmJcHQuLgszEmRTOkwQZiTEmIhoTkUEGdMoHFiyMImIlFJMSBjJo4gwmF4bRHhKaZgIDSLLFhGje/sIc43igTSBpCEifhaShcSlBMUNJBsJoSSZCC0mJCaUEiK0lJjIKUjIYAoSCsllJARSSkSsIUExpWQTwYZki4gJJNlEsHUYlYiYyohsI8E6iFSCAuNiggIJisFkyUAoJSZmDclMeOnmWt9cj2VETPSIcRoJGTNSpPBAEWOXZB6EkiwkbiAVEryCHCBY2UBiokc3d83ITHAEOUhQDKmQYEp1KUBQKU0R0QPJZkIgdTNhIMlIUCBZTGwZpYlwPJComEAyE3oYlcglM2GuroixxcR+ry5BNhS+jCIjIYaUQsJ8GSlmghjbQqIhVUHhXF2CJCiYUcyEFeRiQs3IZkIESUwspFYxwYx0BhIWUttIaBjZQmIglaBYRi4mVJDERIcRFQdSeiDBZdRhQsQ4MhIcRmUhMdIh5IJCLMLpgQRDUgSubibEIMqBQiQDUphAIsKBghoRFVWI00wgRuRigjCuwQQSRDa5uqGwGClQ+F42FQ6jUIFxkCBMEEGx/j6IEiRIL0YWFGNGBYXJfy+9oRAjSkNBjMbrUJhhdEFhiyiC4gyjpkIYCYpbRGUoDCMsJohMhQ6jQYUgqgkFC7ELCs3NBdmmghkVFSAbCjaihApBJCoEEhVjRqFCEO2bXIcKHURY7KMDyAWFeUR4DChkTciTCsOoqFAhDhQ0JtQNBUcXN71MqBcWJAMKFSrCY1JhTGi+RoVFZFNhEHVDQRaijQSrHhOSkSDVJ4SKChoT6lDBjA4UHCEOFQZRFRZCSIYCiyjNhFLfWxBEChUswmkqxIT6UKEhJKMLiy0hm1zCQkLIXCiiQYUiKlMhIdTBQgmlqWATclFBjAYVEkJqKlg3d4LIVOgQqqJCSihNhSJqLDiEEiqkhGwq2IS4yCiNhSEkU2EYYTFFFCp4EGFxenMFUUKFWUJczBCysVBCXDSiBAvR4cNFVxd39+ZKCQUMAVRFBVUyHpsK3eje9iAqKigibCrEBpRDBVmAe1PBDaCEChkDspgo3gICY31zGZG5oHu7igkFCjDqxQUROlwIIDDahApdwcIQOgsLLSAbCxHgcWGhBqTCQgjlcCGA+sZCDSiNhUEULDSAXOQSu4yFKaG8kqYBlIOF/PfS5FKwMIRsLLSAIi4MoS1DIYiWqMgoWJgFZGMhQ2hioaODB4x9LL4bC1lAOVKoED4uUdGP+SRYyAA6NxYc8U2woEimMy8seC28Li4MoJgLC8hDMhPyFmCLin4VUKCg/IRPWgoRUNZ8FFHRGz6+JEOh4luXsBhAiQIFJ3zOLUNBMZ/9kEKF8FGExS2fuqhwtMtHlowEacunbylQGEDZwmLDR+bCmE/ChYaPmgspoKDLaDh0XFzYFd8OFp4Xneg8GguzMhv5/L6wkAhvdrhQPrKwWEJg7NxcIWQulNAwFlw8qeJCF4/ztLnw0oGj/PKEhTzCm8fmwvBRN7gsLjiW4ejeaMA7Cwty+IyJBVd4UwZD8CjiYsS3AwXLDZ99oHDkI75zQEGSAb02oWCp4aNAQTKh1VjIAlKw4AKakwpHEd8yFaSYj8kQPgoYxPc0GAwoXHiGz9MNhvJZiws1n4hcbjCUT4cLEz42GIbPnFzY8JG5EEBnc2EALTC0fPbhwiwfhQtbQGAcQGUu7PCZgwstnwgMw+c0GJZPmQsZPiZDfehEXPQKbzcXEuNZiwuO8CZcCKA5uWBAZEyNZy0uGNDjwYU8fEpgqPBOMHiNZ+niwjsynFZhIW+L7mviYj58hsHwo3giQ8HyK3g6AwqS13iOuKAGT2QseHxxaYNHAcMYTwmLRymetqlgOXjAeGTjMRekFM/eYCgfC4zDZ0ww2HgUMCR4IjCaj8nQ4imTC40LyGCYhw8Zn8WTgGFefJoMbzyPBYY+fP4AQxbPWWw4cOYAQ1+i+/rrYMjgqQEGVzKbfcCQim43GBQ8Y4LB5VNgOP/wnAbDv5/SYbM2GM4/0e0Gw/eLpwwGHTzdYLDx3IsMY5nNIkNGdM8Gg2s6fcAgHTaRyPD9C0fqBYY2gj1j7Q2GcZPomqgPGLbmdG/LWFhr2DnnjrB4e5mwZ6xzNxWi/fEMvZsWFI2HfwjsHA8qwK+T6J0qKBjj90/RvzYTiN/9DeydKEhoTF85R3SPjqDwoz+D9G5WiFBvff4UHewhJP796WW6qAyE8uefoovS4mH9648VurgTHnD64ooY5/fDg7OXVzAj31FgMFw8jYJcoqHDQDd7oECoFvRy5NdK5kCwutro6dWCoAZrf/jrJj19floKADSC6fff/NUW0U9Wr9bzvgsROPv9179xdUT6OcrT85p7CYiFevS7z330Yz9fI+hr7/P84VETAoiFfaxqG7evXLny4Y987zH97bfrpZVHKzB2OvLB9paVU8uqVpVtms3mLTdXb99tcWK4MSPC7qp3X3vJYHhUYm9PTnW7YlCNKJRAIwzAxdKwVQltqqVhHDNqHLXaVG0+TtNsnOYb67PWxklygiGGEydPsm0o/T3fm/L/Cg8iDsdRVkQCAUNUREBRUArTCjWniCKwSnVsyVA5tK3p5DCbz6dsWW2qqqyiyqVIBqeWDlppkESwWAoYqFGUJUYGJgUxMFRlK7dH2XUASodbb39Y+k/7ST4bDya2O/yiOyhRhi5YuCBCNqWy0jKrZcXQLAarMslqmq1li8oIlUqiamtOTaMRNWUl2aRGMktMDGXbIMyUsKKmWo7WskrLKkoUjZCgSg5QdpkCcqCxU9Hv5fx7b0KR+kn0ecTCQYuIKFZqpWVma2m1zNIFyzBVqyyzVVlmy2pVLk0zMsEqSlDFioqKmsoSWisHKAgUKiKw0gINBAREKQUwAoK9FuDC4Q6OvDu4U8+f+dAHL7CfTrEc4uYs1UAoLsndikKPyXMwsBS11MyqcmpjmVO10WzV0tYyqzKz2tTm82yz2QS5NbamTYVCAalCASORWpYKVSpCyx0P1zedvL5QfiKGy+/6wEtPnzllglZN08b65jRu3V89fvHM8vqNvz5qaUakdc81+4Dy20i6L5cVRpixeL0kLx3flnFmxu45lhJEZajHVxZy1paPN4lCS4fIMqCoSTLbWNqyVeaYihpaYlKF5ZRWawIMLEmJqEipYsk+b84pj9E9/Ww++cKLJ0+fjykjK3PeZvN5a9PGdOzE8ZXZnU0Op6G4RkE26xhDMrG3WSMLtojk+DJgzWtpJStCihIIEAYCGCKWAiIGhhjYXo5m7MdJyy/gOLC+8AhLDjo41O7mn90R4Dax4B48KHmeAh6e//v///5/tTFWUDggUNYAAHBwAp0BKrwC8gE+PRyLRCIhoSMnliuAYAeJZ25vCBv7OrprSG7JIIDqqef74xt58iH6R88nQ4k38MGLiNv9sA5AWwMVF5pbQpmZ+ctnvxH16/gv0nZezz9Lzp+23fKXn/y9tnbHmJdSf9f7fPnB/3fXD/a/Uk/rv+J/4/64/Fn08/vB6sf2W/039P/fP5VfUP/Z/3U9xf+X/2/7//jQ9rf0Hv45/UP+n69n/d/6HxJ/tf/1P9F++v0D/xv+j/7P88/9x3gHqC/wDrQPxc/Zj5t/Iv6P/R/3b/Kf8P9yvW38h+k/w392/yf+x/v/7ifJh/xeX/1H+i/6/+c9Sf5N92vzH97/y3/K/v/7r/M3/J/zv7t+kPx8/0/8n+TXyC/kv9G/0X9y/dD/D/uX9TH3v/c/1fgNbH/sf+5/pvYF9s/sP+6/xn+q/7/+Q9ND/L/xf7ze636b/kv+J/lfys+wH+V/1T/W/3z97/8z////R92f8Dwkvwn++/a34Av59/bP+h/nf9n+130vf3H/i/0n+k/9f/Y/////+QH6X/pf/L/qP9N+232Efz7+2f8X/Ff6f/3f6b////r77f/57xf3T////J+Fr9nv/L/uziP+eSdJ08D94dzlokabwwwwo2sQBuuRjht8sbVd4+sxnNHc167AjVJHhyhaM9zm+7Np700Msu8Y7o5khYQTzBudrC1sWH/PJOk2fzwDXJOK8gqDn0+U2FYyTEhpkIlPc0Ll/9B+uF+SJEKghU2mzM6+wbJPnfkzhkcNSlaeDHAXVb8EbTroKmPz64V1FNsIeuUDk8yJ5JN4GTJceBlOahLAgfwrZefZFKZxQo1vsUy2mqc+qDlMbpzelHsR72u8+PMHb05AzFyx7JZXQ3LrisJ6VkOf4r/gGmCD57mQrjr3AmLnm8tpp9tdQnw9wr1Quvz67iQ/XLOxxWwhV8xu5XOOWnuGD04DHjJYnrt+0mSTFY0yXBDnA4g7ODM2f7UuhFzk1g1Xurc464i84S+4cOLLHhB0Sl0MnThBUfKQDDfrZiFNrSlW/sZtNnZzA95n9AjjCcrulLfqlwsH8K5CbSTcrjWnuJdHlW6d37ohk+kt+gyUT2mlzwmMy1u++genGZiOc8z+S6a+rlzN8UZzFY/37KEnrsUm1BaXwT44CThX/v6JKOOrAGCV0EkKx5MN+knWR+MYMtzmBRgUS+h06rB4F9XDfOyF1G1fcWrkK5CuPDQ6lQUXOlvmIY25YBL7BpWscGhH7j35uBNyjjft9scndQ09+1Mv2deFkoanmVHi46cWDL5GW1Oc+TZGb6g2MICbv8FepML8YKK7RCkG9aoeDQQg0XS+LBbWWvVQW73ttXR7GQov2U+N4Fs1UsNTGNK52vSaFPLwJS4+wQLq3hTNcH6iNz3JEgy/190WnGVW+XhYo0O+Sqwqt6XXcP/Apr3yyaamyfIbwCVFl7ErMQxsQWzCJqBuPCuPToI+BWR7RIGeatB7BwmQqhyQ3kgn1Bom2+JqmbkYVD7UGXB/JYA/smHRXecf4T8kpiOOliND096Vq6/X0hgzHUUy8GCJqd16gFTFxKRHtzKapPrUROA8xO7Upt0yOTBW3Yd1wG4ftAexmDqSmJ0YKYRNgMaVcLvWyyx6sDQKIpLafvF7e8USZq+u/O5Aafrmd5Jc8IyNeuQrjt4yFptzNSZUlt2cs5nxK//baByvu49hxFPIs+IafvniZS8CBEza4cdsooCrKOL4K9X6W0wmqc9uo8Bg5z6LmQ6C4Pd2SAxvNpIwnAZ7IsOh6w3bO2fcifVvnE0helL70Pa8ZZXh22hyAXblt9Qs6si7S9zeRASMAra7gWaD1gxTVq//esXy/IKdLQVhewDvKDvxxWiCeEPGR8w/nknSdLA3fYDVR2Wo5KRHWaL6oFvpDpozmxhKOhoJgFsfE3I8/iKy/9/VmtM8RrpAeLt//RX1zhNt+s4b58MqhP67ckDgh/xA/jPQ0375pVckSny+EWuPJT6hYH7avQK+C+PZMiynDTURjXzZ+MdPA/hMzcjSuyc+a9c4Tn24EVVXjA9GK5H2rHUTly80pAxK6UxN0hhUUPe3yknWJNjTCENqhtxdyfAIg+FQlF28XnUEgzfdY4fNPD1GgtU84HRja+4pDjARXxaMNiGZmLpVjjUnjmslbjHpDudZWjRurX/ba1PZTeaiKSrcoCFOIlp018LXrRc/BS6kAKKyuU00LVspSlqdbnC39EpxtXHtbxL+vsED+FceyC94ksWhDhP1uNllq9lNQbK1f5Q8bKM7PWBUnngNEe8slIeN+G1rIv5cCkCDC8ij6GXKjQ6PcyADVe/lP3SX1yaaDlKjTL4O7z2Cag/SWc3Te/fKcfuoYvAttjcLbg4CW9pdNQcNzScOwSfLr/ZMGqmXGQew0sfyd91XagZEVB4p38+PzXZbT+9zg8go3SHVLTB1bI4HLp10C5oHVLxYbJo/HXXO8rouFyP4VyFbAvPYoCbTB1YZWO0rHMr/xRj4CN8tszzUTY7D4e3To4vTG1+Y5+bRzKxNceYpRAdG8LaqY9NR7MW/heeBM69em+kz8qmsdYDEbRg5Zphvtp77tWgLeMsjQypmj+6n7zAUY4kFlZt4tjwNbITpUUqnFWVcsAOxjEWEwAPD3kENdL2/L9vMejW4NZ9qnbhIaWdQxaVNC/k8Qv6RVjWeUuc1luavxlKnpdRYRZkU9zQKie3groUclxA/hXITe+GnpHus2+FeEZEMdv29DD81VHuizDTRFiFhlkmwAmyAs6a29M22iHZiheJukNuvCkyDuZsizvt9QO5foyI/+FhmFudFD0gwe9zoFE7poMXCnMVWRSIEfHZh7alblSUexLAWkN0dEBnDQ9FnW2ETCkPLBaFblvdNz3hEZGTj+Ejhn0qrjgn2TkL7MhJlN/vqn4GI6AcBoPA/hXHsi2TWV38jC25Xxwx+YFPbJqSjWxdDJWKis6jac2wGP3CoyDoF9vIIbE5ZZOrWue/p/Eyx9grNvw7iy0VO+eDldjBiYG98KVT/Lsz4Q95vLeo4GJcmGZUqYslqBEOL6m4wBJHzL+UQH0aodAzgLvDxQp8wQQn3kZOz29FMNiickUAA9VOIwdQ6yYZEYnknSdOxSPurFBHh3NKMfMSjwNatfTLzmgY7jmisuHVk6AFVspAMfzef16AJ7kwmFn8NA0JsT94CHzW9TyVWg7VUwUw5LN+4UgZRSbu5GNdfFzCXPjATHXsAsRtVzBuUWyYCwjKp+XaAratjxUiRGXTjwyBculn2q05HV9PE52p7yYYKd6+kHPlXqzJEVVZvcHdliXSQxAJ1OvUrxLJtsZGLCCpotWT5TJ0nTwJbN0BRNpv48xrYFbcyRNzhMAkoA4uSpSWuPxQw3aCP7G2A7r+TJ+DXybeeDh652lRukV9WsQab44Kn/1sUbcJaFC8rhOCclMf2l+TStJ9wVzDMEviWXZtxnu0bSFgt9LdpSIB5vaGVPSf/EyAjiWgxPyoCFS0BLEUACEa04wtSKu0G3xz4D8xRicL1wt6RSncywF5uGcyxEbpr7i7Jz6L1BaeViPIRdwBAWSxyyPTJ0nTwJaK8pJgILjAv2Jg8Aayb6Fh+n/MC/CrPd+LNqi3nj8pRAQLdF9x5prXsja3mYrdRiy3RyKhTeD0O0UGB1KhV/VvgkYUkHOw6QGgCph4wkQGmJXRAB2/tvkJcKvmd6lTSIo2XJD6rMRDNRoeJYhcsQSxK4hK/8OSSyORCh3OcR0Bdj5dM7tUJhC6hRmFAggZ71UufsfnN2WcgOj8/+mydAGRJ1j0TG7B/CtwFcLOeHRCpT/UfE6GVaeLJl2Z5zcgtgs0+6PkcrLUlFTKtqXB0nPuFFunc+nvaxbA1kVMtLYk8dZXWnITncNxW3IqmkCDqPFvKuLCCfZqQokj1lJY6S3wzxLsQ9eURwerHp5m4A7RQBrnGwekz80LeiHxTw+/VCAq+kXNbs27Y9oA27B/CuQmfzSYql/3SsVdiqHjfCq+yjN2lIdGSsRY8bBwsjPGSFx+8ZUqOsk58mpJR4CTHsV7LQW6ipRKjsohbkCorYlfHyPt+fXo8/NtnMb6JPFNEPEOCG/mckVQDJrACOP9lCX5tNa0SDNGJbqStepRawJ65pAWebG3WvVSiK3szuY5uK46flNBPq8xetSmaOkmNdc4+RReSQtej0ELVyHqVelDrL1xJfkLD3onB4H8K48M/Ub8kJ4OrxcfPwedNkrasEdVSRk1vqmf5Pgzojd1+lIqRJzbiW1f52j+zxFGeaIEnD6H39vQAYxdV7kFTI9sFpKGbm0451VHgGipT9wLENBY3rAqVlXmnVaixaO9E7OZysYY6W0j49PXEOftCRgE0l9QoMNQ5H5mFs/ENqnmanAFvqwD0cCpFQmwOYYDXTdD+BQl4a0ijjtAzLgsGYJD/hE7S2zAM8dfVIrln2p2qWkCzHJ+g8D+FcdpG/7Lv5Rwe+b8+3KdJt7UZIm1YkBnrF33hLUtr45f9bYiN53EZbpypXeKUT/HfqY7oG8jnG84iBUAOd13VeivdbNL85hT4n1CZz2qRRypz7/jl/rXZyO99zKJW4O0CyQGH4881zuN8HTN2CgORPm/6/vCTh+PuXsJFSP5fX25G+cVOUNXvCvB8HDW/CJY5VAe7uVFSREPT+AjjwbRw2EpEuL5MYfxzSOBxR77B/CuQmsZ2mcogjwDd9sSeRuPf442JbnGN0gVOAIEg2rmak6ZSe9yiP7Vn92mve4vNIMbnhZtk1XLO5iWqBrdY4fj56qdxNqm4ah8tHn9uvVp8Wy2acce5nK+BF7D93NdtX4nGWg2vn6YMxx0R931mTeIzjuSM8M/VGtpGhi93d0k8/HTJKC7BmccQuMUmcPybzfe82NXiutykP+WpBfijmmsn5qO6GUtswz62fQFWTXrkK47enuaL2sIBe4Rm3qr0/VKM+t31qIImxuZgpkAEJV8sFheDfLPTfXI41ZUVqvK7WQkghlvJVmVZTdFO0LknozO1BKINcnT5K4xMt6BzqJPs5P+pjz8VLi6/uXGnNa2fDQU63v2pyJ7z+WGEO1306gMUmWE/jilM5sLMUMmVvcHJ2e4/Ui6DwP4Vx27n3usRRyyzISD44IIAu8oe6AmamOl92i93GEAphihF9mJeSAkbCYu0X3+d7B+IotLlP1G0MV53y8XXww/ubS2DCVxtS520Xw+CHbNsYL7fUZcnL8A2oOvtkUbW24wM9hKtVTfLnHEaRtx8eOufCUc2OoUomqXfP5T6miuOTQj1w/qmr3nNa1ElaRQ19jSbXE9s4tkmyF33IDxfgtihyE8bKmSPSsxDHTssXZPDNyFGh3aeFQiY1BLMH06EFZ8sIMziZXvYyOggAX7m/xRiGBiPcDTgvApLBOwJ7Z5HRN+gUBi36s+I/vyPWp+5YGReb/zCs2/i3gyVP0Rzt42nhlp3cQKnubExP/Z8jqopfwlFgaUwWSHF/V78Qd9R5jN97H1CclfzUAPYChtOaUnwqUwOD8Z4IFqygOfXqSLAhpg1XqaNliR+7/KfbVH/rUfGTzyTpOlk373dmMz1dfsumrTgvjXM/WC5ouIHOTK0RejIgOugDc4SalczzxP4crKrfNSjOTQwVfbo1qZZEVQmm9aVnnHgaIO+WYEHcEkwMShP3kRc01w9PbWasLfuaJC5pXH/myBqyZxPiQxsvT67Igr+hkZiNG8d5LRzukbHDYT8T0ykcmDccWkMuJyOXruG2PPbAvwYykT7PxarBhCXXoNMNZk8dH+eSdJre3ooQCVe+Y28gIz+9hlD+xT+F2qL3xqbQ7G8DsVH1fXjDer8ztHPP08CHBnwuQ++V4z1EBOBM8c4prAL2mPyNYLvWsRFk3T/t99AsyHD7jMxaMRH/fHJ+etT5RNP/Co+QZL7kBp91FdY57cu7q3nN4QDPTkySt4eL2aUOHO6hUD6Rgb3d62RVOKWft1QmPngDpom//JQJzoVzjLLHAg5kWrrbeOx9TKmbp1hiGOngfB8mI9Fyi0RR6VD0GP23P7myIIB9df4IY8+BpCoP74gefsLxqd9yDq7uoUxt23dP1C8zOPMP6ZiqKyA6Kq9JzVPM5o2o5AoN0hYqcpIsJORtCoYyIVzIPiAuOtYtbu5HP1qRFBzZCLddoVb1DcXiwwrDckyHzISF5M8chXIVs5i2owXWYvTmArryFbQ6J9mAOMX1vgWcUAkv4C4lHXTZN/yt5TbwrSZ8wDXGZnlUp56TEZMoPqkYZU0lwMfiXWXdPXp0ggSh7kyjwQl7k5EC4iKRcpSLZbAIY+ubqfcO6EIrbnqjgpVS69rQIkvlSz6fTPcyFchNryhk8It/jAgKyEsmfPt0Q9D7u3myfj/p1/86y17xxNbfNajKfCXqHVdDgVnuMry4Iypus7hoavzxH7JDP8dbjej0tySsGSUgtVopQ/P2cf8HGNtOUYAYYjtq9Wruc/0nwbsH8JpW4iY0tOimMOM2AdOMvv4Pe7eLbvF9UFHAOm06J7yeebFzgpLLk3Krjv//xSxNWfg9oLH66+dsV07dbXaX9FJGetsm7qPuQCUPuhVcUw44RmFAT0uwkbiyy7BFqYngfwrkK5CuQrkK5CuQrkK5CuQrkK5CuQrkK5COAD+/8D6AAAADC/zWFMgkJLyZk4+w4oLPIHVDLSWE77IB2jJqCmY8KYdiQYFpDnFue9KXDCFGrM/7I0fpeSfKWV7eJjA9EDjBTo8G1RreVgg9rgHoTTX3t8aydtskzKPdeF8zJmvRZiX+Bdn4PEBZ5/wG04oL+/iYIy//6el8E/t/50wYh5nkji+fH2hDuJMPLuBzjmZ05OioIIvvpS1wcIY5H6fE5cbe9ZD0bivGYj20o6cMflTutxh2h8RjkytORfZJizA+WiqC0e/m213r59W/a0/84Nye75L9ocW6Wgu59tePqZM6kiO6zmwbh7h4CeWQ2iSDxup1b2A+lxDwfPcNbhwFsVXvBenijtdIDpOLON0bNuayNZAS7ME/UL/xzdDbRf1DkD3Yo6hDMZTrftOfltU3Iws83mJWjYJSen8P0qhxIAqZJ8OARidDXjeymjzWJom++Wo3ggj8mWI8CMxVM1/PbtZ6/nqo2i+CLje51KzNBOrLRlafdvFHNbG9aLS/0eXJY8b9S39ag0Ca8orBJS/pbzzUSs4JvwYygrmJ8bqVexKW8+P4gEf16qi7NE0Gcc/VQRhqTqwHQauoNhs8mar5N/pc64ctiTaOX0juBAe8fXrBwd9NRzf75yjVLJza+nZodm6qiA96SOU7Wzm0GrGZ/O4jl/+5QymMFXOgAJT/WV5CV82e74CQbdkO3Z0CYKLTmea7bPabHZn/ZuOApPB2za8L4PEzbMrQnFI8CBg0PQBtaTdyvsQ5co4jrpLvtA7HEq5NPXUG+7WxwfDu/G/yHf41JfKcPBOvIxTLOG+g1jANGiJlxkFQ5aE/tvqpF+jV4dO+ZCqKkPdOfYaLnH5f54JSgV2Jhi1xsHkKPxWQLLPzuXyaS6WYLoTHkYXA3JflZiQt+l3Y9JyEHN2uoZfyp+4VP6CpYOlqF4kFM8KhePbdfQcEX/4zSfjFqTK0xF1tf95nyvuWW2WK7nWlT1yJHuUKxSpY8rAhS7yN0fK0Vr6wHIvbGsLfozbDnt9ck1N+H0P/LUCnjS3UAcBB+5f2aSsRPuSQiRlDPWao1FeoiUrs6+X5+OZ03oF/UVTeu0JeC9UMWp8drGtUq+QrRfhBV3N1MY/n5se0cDsQ9aNfOq3OYZXXYZObIPWEV64CId49Zl/t8ECzwKjCFslpp+3m+bTpwhLfzdPx+zkW9L4jZPNP7q4gtRwq8MkB78/bZxMmvy2Irz2RYlEImdAQlCNwxsRZoYbKANS7bTaUJBuiakvzkeiPv/FPy3K6GJHrTEwXyfppR9zVVciiDF/N/kYtg19UQql0KIz7N1vNx8CZ8ixLyv+4sfIAnxLSw3RQcmabmE9k0ETqJb8o58PIaYw/DxYOThp+82GV762YDfxSEKpvsjSpCP3KLf1oncW8Bw0pRf/xAC3GcsOYbdJK+c6XhYM1kpDo7e7U8NCDA4jKl+PpPhAsNfianhCB+TlYCnc5p2VeCFkrGghZFK3YnQiXd9z9dIirWoXRKvNVsfCWcSynBzJEScpK1ri3IhgqUrXUui4DFirvhMzp3J3vTGzReHG9w0DpuDVFu9R/kB/tl1e3SnLdYE4tr3WBsWd+SDYciungAAQVBHn68exKInlLwi3wS3+91OcC9t4ZBLrxNEaYLV2/kgGR002IRZq2OkSabc03+EnmxyqlgMkIURBzYCl5I0AVCCoQqIvbyk7lyXloeWdfYSsAvEKTnfTPtMX7Mb9yZ0fg349LBXPwTddH2dYdchkFiEFchNn3hdFF+qNihxuvBOoGnrEMEf5wkofUGlCmuOvEDtKPfgAHdgsBEd3PA1cDAIj7STaGuSOeBvb4BcKFw8A3t8h4YjCw2hfn8COXVdU7Xlrs/DI5/DIU7Zoj6K7RHLqO4baHAY0F2hz6cRyfr0vRVN/WqIAADmQsLlIPprx+DWuCxJUfpXtHBIVxDBkZmtmLiSdvIY8nAZP9NQjcLaCWH6Hv5FB/5EfddsEcpKy8LnBHWgSc2X89rjq/Q+ZlZQwvAEUwW+6DGksEdet80PNuE8kQLAMUC9Vdm4qc4y4PopJQrPJWBv0g0YRHfn1+4js2aNwTBHzkQvKhAgxGW4rLjtYb8Nm9BPj9sf4xdl8K3SnCPlL2w5/SBbgDhu9SD02pSneH0afId1nprL5+FWP2cyrnyzlpQ1OlS2YkzFF2k9Dhm36ZaLtbAFmuiBby5P2Tzc0cxVpEV/EJ/rPvFAeQh2px/ayh15nIXtBMU0Iq2xb8R4N96nxAxbuphtGpbevOrjOOyCnlKUi/GJZx42+gg4g3EYOIOIyXzktehJg1MY4KymnI7DDlhUFUGWMUqmKOiuxmnKM1N8zWf+FUyNJ62GTOyRSxeHbwN4aQCFflhmBT983v1JWRswInYYE5c0KhJPaM0J8hiRyJZBq1T67DZ67MhtKFDud6mTQ1kWYVcNkIYS/kXLc1b2vc/gjyqWNdUzHHPCQox8ETHrOO7ptqp4VIeadowbl7SAoXDKxK2nnd7NgAdYABbYzVSmSaL/jSOpMCLhufPjjAoUSqCFGk5PfQCKZrSVmMx8+EjAIiiU4kCJA7TvFyN3nLPcteMIiXo2nwzUsiec1ebKQienQp5AmKSWAi7s76sMpBK7D1nPbBCSzmZ83c3vz/64MnLeFpV5Dx7vrZSyq7C9KtHQnc7zgmbJBSnxP1W+zQ3HSC1MvrkCyuAHeiCaHuRFEGcZZLkFLf7PGwS8jo4sW8UwG+y15B2tXFrSiwHubmeRvbyTlNp94AzS3EsMHjTrShEbrNKJAHHQMk4GVVLmACKOR4WmUVr+KyVRq5GiOux/HdLZ0zkWQp1GS3OmgL59na3W8qDxgxBiSj8mLObwOhwtNYBFp0GlZbrJnYg5uBPinDyoGuJxYKnXNGeyx8A+0jq4jFhm8G1RlrWhpojwKih+ca+RTDo2ESW8M17G9BKTLmNNvUd/S/c30/vSx4TSl8d/eN6+o5eJc6TH3rL9bXpQr2bqkoG40u40tt91gDewni0svfyri6Bsxc5IqknbTZ5vRxDUOVD+NE+uC5yBfszxV5mkmwjypaWpv13ryxkATP6Eml6BPCYWPqCdVZzAAAkVxTLkt99IP/Zz4T94C/334WqmsZ8BeOl6B1T1tsrNKmxgppn+9H7EWLSEaaZrqb7wlwC5+tIxxjROsJfABwn8Yo4F6qTnMoXQMh2LyTDhyo+7fnKAPtAT/YACU3ZVxYBIcHdZAKJtnvmfh9khpvT5fITLt/nGP+UjmsnpQsx2yi8Zyoq/McwL3cN18aITkSU5ro/2azLO61AowpCE5/hZS4YDiampe1OA0xf8YWAybjOnwIgomy1o1wuveP/WM0CgIsz1G1ifuQd5jUVP9bIzTlZv+O1TzV6FjjB4ZUBdPF0JAYue8mmGzmLReYJxnqes//KgPBTIbsPa6DPeSkXP/zY/9+yQJ94NfDV5jRXavyReN873F3+Vl8v1pzTkIiFY7qjpilJtJw7E4aYSC/41IROVDkK/cus1O+LmXelvms7id4GFkty/81kgLro8cLuFIwnE/EKl516+a4EXi7dfAp43fkiRynBPRU4dUdYfTblbjF6U/zHwd7YItb8d1D6p6eRKFoLPs83HOzB5CUwkrYolxapCwg0lSsTXBsO/l33jZ3ixipmRmTRR+sJHDl53/aCIXB7b4Nv1m4v7tkD6ocKDjhxjpf60l2HZsP9PxYx5R7LCES5Kv1h1UJFRhsZNfyCKUFMzKBmmcpL768cVmEjxA5VnXrEgiHczzARqXOp5m96Fuz85HT+qcqA4g1OrpFLu20mYqYCRbUCVeN+PAi5iDr1KnyI28JkJKJqAUtdOSE3kplegBWoIdNuc+iWR+C3AhZQBc4efUf4uKoavToIO2V40jxis+DJV4Y5qOeYu75kVWUkTaH4DK6Iespew5YQK7farr8sTb50j7n7FXjIQUUeW7PC0c0KvQJxOQRXOFbvVTQUyd0i6STXdtIgXCBD/S76ov9D17VtsCv/4rUUApPBldkFk2tWiPre92GFP0YstwB7sSZGlqQCNWgCnRDh0Ze1UlnOQFGkR511iwo3YweWTzhp/dcg2hk0hHlDXhe3KtCK7+pkuA9kgSZocNSWfvEt/P/lcvOJqb9fg6QK1+QTh+i2H+/kvfnrWu6KQmQDjRvME4q1K9DV/mgTb61mlUj037Rc/BZ3/EY+MgSFLPuWW3w3OOUg6K2H6f7J6o1J75v/48VrSUn7WZS38ZWKijCC2Jq9RnSL8dJH8IoF9DPppEl5KEDxFHKd57v+g9pCqkETVGPGjNTBqHwD2cJ3bz47ppQJz4/Spg3ft5ic9d1c6ctH3GzXbk4KjgWFJJ4qvzTi14agyAyy7fL5hDPKK9CeznSLGBJREIDwwCox135lkdVJtsHzL1r1EqMdtIWk0HTWwb24XAZnUJVUYnDW7Emr4pEy2Lyw9fXPxDEhIw1QfnKkOonlIVFdD2fhwwkwjLpE5c7MFxC+/Cc6neGa0gEXMHBfaJoTStwX/9hiYQnYU9goOsJyegHoP9xit/635og5ol8Xi4zERluBsWraUPl7Rvuw6036FsmP0iVvCDu0ltTcChozNwue3Ou2RA8wHs+sS5MH7eTzCkjZMJVg5OoZeFvJygQx0l6hh9Z1+owUQkpp3AGXH/r9AdR5AAnctC0pz+ApvJofZ/1Vbia1TgmtK3U9mpAhKYUDKNEgi+BTq1a5tfz3i0SEEEpUfpj9/WafaeNyGiFdvYicmkFKOQDxWEkAeMvV0aeM2s3gS2KuAlkxD7rHm4Wv03fK4yDFyh96mtCfvH1UvP525OEBu/VhbRm6/G9HFPINeJkLhY8PyyY/PdX4GfTrsH+RZ6HKe6ZAuK5bo4RsyINcRrSCNwg1ofRyFJmFldYutl0Ei9wC7bySVVTwTDhGNyd5FZutoai7rkdTmLJ0KafB6gWEWd+BESADAA+CiXY8QCxPFL9rIhbho8kBXZm0l0WoRu87DIPi/7zrT5kUnLSvq+hqEhw9I5ulN5uUFglGmmHlbbkGV2INFSqk8AjREviB6pXW8qgJG/frOn1t/oXfNpI2oRrrGlUTDg0g3ZxjkdlaHPa/3ePRPxnJBeMEkdJgY+eT7qBJlUGcbzfbMeoHRfytjcTtvCflGSfTu0hZylfxaiBJpxvtpnHBybcFWQMzG+vQT5w3UynzyVNXKy2yYATaKEaeMgLujVTa57zA/TpzAxXev7O7kLA2Y6PuliTeYMy2+R+H4bFnPz+XVuYN3QsmO6QGgznqs1VJjLUpSyqI1z3MkimC3rhy+TwVZ+qC4hfuQhLux7M8JvLos4AAekhEX9cTMYpso2e1xl9PKIgrH+m+HzgC/tMW/QPn/jgSt3aFpb0RpPRgm0lpvAQvTB6U35TnvmGNOtW+21tLx2HIfBK0teLvov9TdZrSn0y/BY1wv/dAAB+35BhGQru19bBaVVVwzKxGZH/N42TgfZVtQuzwg5cljxRQWhoT6Kgq0ejZzh0gkR1s605uB46cUrurpkjY5DzBlZ1jqqoYUGLQwGnrtu9mDPJkk3b0AZPqTmePVUiRX0vJoT73BKKCE804bFMqRcZMjzzBXLOjxLRDOIi49/QOJ///3FCJCnK1eAAC4bpEj2r11PqnFISNe5/JM0wDeG1e7jPLPdikPqTYm1Qi/4m4jNqyZ2NGzrVAXbD8lRdL6j4utIE+xIo+OhD3unJP0NKtJ9k59kfZ/r6C9ufxHqo9P+/d4BWY0TEyVNP3lJVj/W0shb1okI7woBPKO9CMOXyYTAc60nhbg46M+C0rXQLYxhkyKtqvTIhQhafJD8u1m6TqiWGG5YuKGtplkPWDMeJq9oIYKxwoBT0JpN/JM17gM+hy8TBFjhL75Whcid2KUjj2V9o0X25Hsoh33t3JybHfcKrujpFfY6H86s6O3khtbs+sNThHR11/oPT5AYV4KO+P20Ewgg8YZzYVIy7izM8WtB6qe0/IkmGS/skO5pDnzG+mFNyWnBjZlbWtpHL0JTjSnvwPiaMWrpjmAbro3eIatq9rX0hgzcht9VnSc3Efh2eGVD0fYgs8Im7uF/Nz5+vh9RI7WfjzxYkgs8RB8glZMaj+JThZashUKPIIGB9WQEo/IsxcfhdBP7GK0TYYRfHvFdIcV5qOCEVa+kc0etXxseNt3rhTBiPKtVucG4oMadiWjH1F8rwUJfEBLxAoEoqRz10rX6fmzxEN58+e9bn7yFIT940RKTtIsex26OXEp1FQDrBRoj866Z23cHrmSjLDqscnsoz8tomHnzxjHxxi5hT5fFOlpx8YyUynxJs+byvLqrceC2G2FkeqN5eym8x17u0aAEagC43Ox89y/CTRtZtsL+RpKDmDsfsO6wfpNB9cupB6UijD3CpczH25e+pm++B0OsXTvR7ZnqBlNGAGK61R33Z9N6jGZmvtShPF96zNJR+6HmJIWyZPM6VA0TFsnBRlG+ABkKatrubbaBy1VEmLoTUQ+AylmazulV+Q3wFtBAl7zUTdllm9fBXDExMYXSRS0+BOv+gjBaA18AEfvmoetSHfH/GuWsMkxCQfK6Tr4AJVSnqiAoEmeeHUMaPlFSCbCBDgey4+6pZRqOr1NGah1uow82QjVLh/W3HxbnKjcxu7jcFDOmNFIKulNozBoKeBNvJYzg2Iob4HnuMCIJF/fwR7f1cyKkH6oFiiS/qiTlba1lalDZmdI57PpC1R9uGARKrxWFbufK1xRCmKvahSEKLqA73j1pzPf3mqM2KFZxiXQhCoh7jV0djyM5sXaFPI9gbhANnjEqU+0iPr9O8SzTgLgiBYms4lW3mQu6OeViENLfOK/711+fhEJ1UHS/qrUYSMiwi+9LUj7RHJn7czxDJ3VzAv4IKF95RbqlPecWcFdLMHRernY12kR5PYaNpRbAzgZmaKolWsZYe+IGRRriUuyuXkxJ7vPP3WKoLRWDPK/0QOUYPiSK8SUY7DEG2e6T3mZZMI/doyl/fcBchgM0I7HMUG4Mfs5sUlyd4NBC1GY/Bhklh8y0GKbdYZAhwVA4oXmGoxfzEEXLnw8owHT4RpC5VQY7fZqAPu4I6vgbBPJtGBgtdTanh3r7oVa8bEaNHUWHEA11bNqpms/6YZ6XWyqZMEvqQvwFkYKPP94MAYj1uTEkNEKnbt/UoUsxEgm1/4i8GA9KSpFDZvLfsttQLg9gZ9R6+Vab1eEAQyXYVgV21z+f0TjIkA+WOVktvTaPqQhTW0s99/3a4c9T0Re4J9V2bNknV+AyKna5zLtF52vF96NrEZJAyuvhEHy1xWa3LKc0KmJ710tgu7LgEE1HHEWFmt2w6KBhp7VGoDX5mtizz3z45ZSqD7SD99fwkyNSlJQIBH4cy4Otr+U7afQDlR+UQG0Ygye0UhAA4Lv+bBkNomGwgwo1wjk8WfnZwd0yBskb8DFbipYqchgl8kJzo/XzfrCsavt7b74b2kqzraErHYidjZFzTvp1pT0jPr23pXJYXy4nm/hULNRPeuxeFkXNGtxgBQz/7136UZE9kwTOJ5CigIPTqNhVU2U1oB78ZNw/M5Ia7QLSck0dBWQbhAadot/pV5a9Bh0g7gvhV0jsHJv0w3x7UekULBO8BbSSgp2nrC8F8qHECPJyzVssP6rPZIg82jA7l7IWrOG35yN1foQDJDVu8uLYtUav+QFo2FpFuXsopJBB5d2+OcLTrjnuSw8AWnK4+RL+kjuZ3f0/2/GpjmlwlR3BK1J8nlSE/DtSPYegQG2op1LCnJhU9XgdZJfZ2+tJsCrTvZyce/xlalC85AAGjbTp4y+I5y30ozEXghALi/N4FQnEPMc+zEF0SdpfvMA+PV5+6/kGDoUtbHpHJMOR8o1v0vqs+vPRUKXeCHy5D3MF8dASqVQFWxaDeEiHtFT4E8cfhxov14q3BBHMFxLrgcwlusKUifDyYqlnwsWoU/1Rvrqfo+TEzXvxkJXoQ3Kkt4OdVAqivmtGoLroEYX4yzcOGzJR0eZuML+yinaOXF1eZZ1zED9xz3bkt84MLqxj6rU0P+wiyR5kIrQ5XmEn+ttC4NgAyMaeIPA7MoRoz8Oxque1K1JEaCqSsyi1rTmbNtX4D3qZx2NDcOjSicazumLOBYDt6Y6onFkxE8FAnE6FFPF8D5gM7H1Zc2ONzKnQQNcby+LNqri5SH+EKR3Bnw3FCYMg0VUrH6nIsIe0vwns5DgDIKPGyFtjyYd2fKtB/0pEqXoMi/qqVI3zwhUClcE2UxJ7FxNt+YwpU3p/QQMKBhGQRx9Bx+GrGHuepbjLJlro77MbuL1K6ox7QOFF1+QbxYEorndgAQ320R6BYaYdh28GaEl6AjdVeMuI8h9g8YwrD0maD6R7KYfpMd3NPMDcvYrRmTbyg282ZsSwS6QxfaP+q4L4928+vP8NBFHj+vXorLaVsXVts/EHexhwtI78okwmit2X5hllxglt+YOPq3BvChv37erYUBiR1BXZ3WJ5VOMFdfu97Bk1KyplRcMIDNYW+F5JwmwqKxfH8EfDVF9R7DtsYMHOyTi6TfFOGYhzYIEctW9wKyN++VMXt1gqWQHdxYuLizBAc3xChvCoPKXwdBkPD492TKHsWfSGRoJBYHdaVCLuY7rkWUPn2ytOygjO23S3HefJBBzNVEa8UDQTArVDgbHnKs8NghAlBCfD8nnNfCaT+C/ISdOSy97YIWPPgNhnkxBbWGArf/kwjqWzEakHYBl6r9YjddvJ5tNj17DGtJMFj3L9EZiFyLh3aadS9ZOpa4a4vfJhJdRUUXkhgZaPL9/zvBvIJnoiJvYps/yUHQqMAlns9EdLkxESgMrrekY71PYoJ/RdA9Wm7s/7BJ634ooeTev6dY7m2n/QlsLjfhXJWwre/myKa1xARCjzSYvD5ccKnFgPN2SHSE/Qhqgjsb+vZQunyCOdKHP1px66ZPybn0KllaX4xxHjpASmqETH2TJ1vp6EBkzvnUTFos/m/IImrYAMoD6SYQlWVEWMIKod2guUp2dXV8DMnXIr+tFdFVYJUZdld4f0oez92alZ9g1bi3RcrX4Qa/t/bLmosLHXII0EGV3bL/NKvuuhbGavzwfU2y8zVj/eowyXCt63E2PPV/BJqFvN5ArIkx5sEiOE8odl6LlOoGQUSQHXWQFN9Mw1ttWcUjRNjchnJAS4q/EcPlYMhYJ/suE9m0sByuO5viFz5DjdH/UFNtzwrBsvYAmQ2NtU9gmEV2u4WepKzBmrRj+lz/DnmLlraDS5HBB49C9SjVysi7iBrzAAMqkdzglH81GpnQsrtrx5o/XfhKLeCiRH6icbs1O2FFVggF2Ll62YLB7Vyb8EgpuO9hf48126GlNlr+ehC71TX+uQgO6aAyA6V9aEj9/d7zE8ACjfxq2/qi/H3ESOgU8en5uXWaegbHqZvrIGdYVDdcaA+/tqAgzDvdNp1XanSPOcpXyRngFuLDxh+JSssD0Am4fYCgQh+lwALX0e3A5tmdXxqumMdjSrbXtkWtV5az5+lOIrKuo2ZWINHCCpvsjD5nWoY5ofk4Pr3E3Q6+GtHU1iXGduMbw4ICQKEKGD7/e9hr9OiS0ylcw+llGRHP/l9hHKwaAwrgSi/uWb06T7jXKqlOod+03yY+689Mx7hKV7P5CIJl/DJe5C9Ljof2Iv55YYQusOYdDs9xyPXuJdRS4v8KBZfLYB6oWC3kXQBIC8HryX9pN9AdF16RX3aKVwBKVVOKQfw79tIetBPQC+KGACbV14tQMmoMXTOlGY0YJ5HNeiikuMPn1Ev/JCh3Q6pc3TMw5TbxV2wTlom6wBeM8y9qJ94ri4VjRihJT9//fmuj58gtQv5LQbMlbCI79bPcsx6K+8EP/1vfuAS1RmXyL/e1YnblJAiRKfrPhUGJ+uTYUE93PwDsdiM6ipdVeQJmq5AGk9eqaqsdZ3aWpzslsb0rcr9DVJM4LE47iW4sIzOLjgnjEYYEIixA2HVGyGHhGfW6l/OZP6DFGGAeH2JWqs5bsf2lJ3NWaGJuhDgwWZR3+nW/9mCUUxyUQQU/dhawAAEPLhlTUcOevPlKLQfnSwa4o1DqRfFgK42ylqahHed/VCu/Yv8y3/7Iv+Ge0Nw7vIAZ39w/ygJ/gxR+/MKE//kLkmvt07svSOd8UW4xHMSGy6G1vrnDMw1/LChdDjBKq9Kk540NsImRtstdYhcqCSfKMGa9ApGsWL+WsLLgvOAEWWakeiIiRB/gDtdlKYvOSa9rQJgO5Oj5ZZ8RXtuisuUTd2OwXYitAiztXfuZuEux3/mRTZhA1Y1fYh0Y+phmui7O9kvZzEPpMgJstk/ZYCxpDUlOJGGfjLOFNs79InHT75c0Ek18tYBV7OCbD6/nmDsquUtUlQNPZCj17i98dFQzxDDw42DYslX6KD/VjM8GdJVprq8lvs5B/eDglF0bTbcJkRUJ4flWxc/rRbkE71kWSHCv53sBWQ13v62LSR6CVrSj3u4ooo0xbDq+JvXE+SjdCl2wu5+19A9FTVoNhB1+PL78wTb6JJzSKxT74QxCYvqFLGcdL/HUeEEKj/14t2efdQLsv8kc3EE8klRCbLaI5PyJFGg3jRljE7oobFc2tn0p39PeaetkelWdNtF8uMFwYCk/10zZppD1pFDXen30MP2Bc9SruMu/b4RDwwgB4Bdqnb1QBBxa+61QgW+iWjbPzffTwoeiDhKIYMjYX19m1pTF8fEGhRJDxQPHY8Bj8+1GmIVameSCfvl91MZ39Ht0U08GhkvRIuWPiwf68ZY4Astcke2iVsyWewO5nlboGvoFO5RClxoWI4dwMyQslivB/HKp+oNZFtf0FqUH4UZIxHjc1h8I8VQuEsm/c7XguIrLfMFEKxb46VlrODLlB4EaI6zxC3Qx214QGSZr0YnXuHB058k5KmqZl7XX+bU7HsKOHaTe8uxUJR8TFF6VUxt8SZpkn1RE3Ghtl9rtf+UXUS4tsB1dL14LSS3sUohTcaaBXrE74jyeQdPO5Gid18KPtb3eMfUbvsPIhiwz3pBnSd+Nz9P4qmrg4TYaXKXpOPMBYVXUyVXmdacs7gpSKVwtTMOqwUxObwMUPfVLNsojRp7FM6SuhD0mCyDzlTtOkOzpVH3JiZ35cDz0kG5ZyQja8j3g5uBmG+8MoFWAAO7EsWrG4+Mpn2mElLVyMat5cW3H1dK4MSkUAjK+EprogFLQh7mJl5v5QFd2Y8i5hcZcUFFBasOypTDX/GB7N4sfoDykG8p4F3P4EaMsZElxXmMqSjro9IVm82HXTk45QuN9UroUOLnnBKAb9+Qh5mpTT6ifZ7jwtBsN0UKoQVGIdfp+gMYONJkzHfzG4jr38/wvMKZVWgV2D/dKrs07uuUKrux0Gl9cLHknEuilDrS6vZECRC5f4gYzc2cKpbriLfElvsywMnCxjtN+XDkdIbrPvzseAAB7CBcroi1HT0PKTRAK2mlAMmX3aOCLXU1HOqnkofsRkIlHxigbXHC8YUpAiAh0Cflc28a41C54u2HazbYJk5zM6aHuXVS/4DceIugFyQTIaWh2xqaSYI0AJHuQepQ0MLu9nH5nQHWsZd/6FJwyX8xfNY24fRMiQ6cNaokM9EGYm97Q4E77kT+IFVXSart3d78Qc68lqz099A3jS694SUG99aTyNCAOGh0PRIuQmoU1sAUuY4/6+Bj3KOxXnoSNkYKk41DK4k+BBmVEbBruuONZVxLW5epk6XfdtkiJv3wWhLligdpq04Uh1shCzKXzgNdWAcOHp7zowfrcuh5C7U2ohhPnTM1NtPiVne02hlywMVLIU3XZC7UudUmzPthXq+tqGEzJ0tvfyUS2PCZtYCnGktfvuy/hAZ9UtbMK+p6fbgl1WHVWtiejvZT9spfpcbNWKzAmGw6JSO21RIwXThI4Y6ZJvIaaUyzj71W/nyJgEkQFy6m/CT6dr5jvvXaEVC7HKBSOBLiH6/N4L3axXGoYHIHeyvqPASxQBqgqgVQYzpz3AgopL95/uhaVBs3ghdgbuxfI6ouL20tUqTr5e1NU/LWhyVemF/pe0dQkDmGqIKvVCSXv6BDz30+T/a2V1xeb7AnuagfzqPxMiUtYulcg00TS9VHTAMkmlmC0k72/3h23gm6QYLDa47s/rXoBMMHZMqMyzNtVzTeVvzf9WX//9xQjvT8uYxJB8AA8/sTfr2b1/9GtqbSynm6Hk9cdGqyGrDCsm3By5tiyYhbAN/7IYehY8u0qwDf+yGIKyIzOQcByvJO1BhdADTnk7H0vISfibe7o8OaYmOH52/0by0GO5dZkiLoO8l9neoFHkK8fuROinntRFYY86UdAJ0uUwX5aE/2c0eFgGMuqrfLZBjRvf7zzWjUnMgxeuHuLnZXKuff9x9EfD9quuZQVSp2BFj7vE3XgTyRJAGzoZMYhKZplMgWqDLvfJylfI3+rGrMvDXGWyrwo/GlxvHnI1S365D9SiZueKlrpRNNBQVztBpMqQDdp4j8XEhJ+hhOVpvC/HLOlqM3s2Fxhz3DiE0E8tsghPQpofKcuAPMm0w4ktEgAbXRhmXaQJQBW8wNS7DGDgbcAKR/vjWYdBRms0/nl3fNVZ04Epa0mCCSWBfJFVnXZUsgLkIah5XMJwOKiwoY7LrcGOZMi2RvHjBDNNg0Ir/iO2HuvunskflED4LOIm8dYDyXjADBRuXtpNAlbwu94ZEXy2OrLXEEOP1Zck8fgrqRmeVHukBDPJPrsMf1gdY/aYKkjWY33SGRGhHpmJ5NU5Y2eUZXIecybKDngWUw/erxzbCigKjiTTj/C9TDpzsesZkDnkHoHqg1HRGd0ZCZtkklwRmU7+F/lvtaoZ8WphmNCmBj+HzV/SXnu0QUvhKYMdhvt3pnmU4971+DWU7KPcb8ma2kuMnIx2Q9jRB0FVJJx0rMfw0sa0Yq2q41pWuYq8tlcUm/PNvMjyYM5Y7bwQNfDT1rFbR5L6s+5yPof/+5stqHMR6KggIROGAYVg0EbC9y/g3IG7a+IssntE2RWlIem0kHhMyzlzg2rDVG7EL5UB5/9I5OE1fLs9TOKvxKpVDZ3L8RyVdZY+oTAp8VnWuNFe7BjnvJnPVbFMgX+BvYi9IkhSU4YyKeb6e+JxCgfVrxdTJNKqWQGNCG2y9aCVzdDi2MTeQPj5Nurzvp3ckwYgeDA30HF6KZBlQx3rbZgnp0WUa0XUSHuHscgC/sxK4TzMrvJsbBLwViHE/ZeExoS6wpInX+CztBNzuqJin1vnq3wTrJdFxiBWOe9JyLzQYRj+876xJi4tv/OppHksrkItBuIxktHB3TT90yasCCQVm0zkGOILj+DtM1A4HGwPJqw2aPhJ3MEfLy2zlOY99ZH1fE6e8ZmLpC6uqcipjyhEEz8uxsTEWCzVA7QgU8fs+4/0Zd80KaTfwQEU1IQ9QsOC6QX6iZiH9mqHysaEgTPz+VqKxosQbCpffV2Nv/YusM5vQG4xS3DmzPorWAdMxKf/sfYOAGQl3y/7BFNsgt1xqbka2TUwDTocfelCxAwVpxmVEBrtkuV6bx13EYvFlUScXDrCl4j3ZPN90+72CXrqXDyz4jyO5KBo06LE0esGegRs93DgbdhaGf+oGuwCwSfRjAqFrm6YNV3V+EkiRxKOOK5NR02CMrVOuY5wFvTd3x7I5ske5nrxpYhYIS5vCdfsbkQL10vizjh03z7O4rVrfZGTo11BJT/twg9q+vY86ymYNVCSM7/kYMfdHsylniWd7S6ABEiyKgpaiPIidua2Tvo4mOnRH7/VSdOkul5A4IgUtvzgqBCnxeWoAl/ltvPQ0o+LNs66lvHQdjRq7xaKa31BLMbhTKRFRrKxBxA28ROinplwV0MX+JnhF0tJ02F6Ma8K029MAAs8FHrYjQb3nC6m8ZnCtewxAKGgnQHoudFAj0lVqEpmnaFrjS6IGGCnBpraUf1sual7lMaqVeiNCRU+eKA+RrjQL6tzLbJ/jzIeMjx5QS/JOUZoeW+Z/Z80xBYG8zOAxTvLbsac2ch35nofQJXv93ywL3yZmi4uCi4j+8Eo+dcwQcTZysUwFFOIGzJOyclIM9K7/On0QPcoGnEJtctrZgqPqq4OtfXJE+rGXXojnwvz/5Xyr3XC2/jtk77LvcM/usdol7JNBhxif4mrvTzA4FEyfVmSFauLGx3M3xbk1YSPkRJDFg65537y6Y88gPqqrXeEUBN7d6zsVs/gnw/MmkULBuu8UAsO/dn4qimHemidRWDT9e0aLxLOByv3NgU7VosB1ivN8eehMoW4LK6ixSlQ5yD0d6Q2JeDHXixmutXlG8MOgKX5M8Z6rybGHyhhSdlCvnTaFUJgf8QpnyfIHEbx/OTeHpyKebIWltpbw7Te/RJ2dqQEB9EVzwttd71gd/taTqBZ9ufG5bdwcSQ0LbYqJvPjbs960BZQSxQ7If6n68mQyM9UcdB0QLSm7KswN97rucDQeqSoXkL/IRA/B5qbyn8Wf27pQzD3WLmj2Qd+pdrsBL879O5Em2gbBBgi850/PEWRG10xPNpOun28Yxciyt3oV+SKt0gqqJ1qY25FtqMKMCAWgnCAXG043RZ8GQ92rPloPeK3Bb16Vh374PjZlxqsQTVs6NZoxs9OswCe/9mxzWttrqhnuaIwVTU0FEOIagrKsYBoGmrEJZESSdlL++r+lN0Cw+2pal5VNkh0yJ3mXmIPYwPj9dti/0nPuLbj7YfTQewapIk1WhH+DsJxIo1LRpeOmYiExUzQv5P1w1TsoNIZvcxORa0lTqHdk0TcFm97bcPfWXMrEVkuXcBFpVOklsEsreaN5oX1LpYcWzNV9012nynAsrT00PFh0E+9djIbQH/EeGufXZQ0/lm8IPvY28Vd+DlgphQhjPyS0+A+cYBwEA8J3KVs/OmLVaPyyJaRbb7wF2S7cxp9YOG/TVJ/6kShQ72mMUUDCz7vS24OytJVhQtqENUh0Z5LXWR0/2ZBFtiWXNAXu+0/8n/YGoJl0eFmeDf9GKrjsAO0HYDjGO4Zb1h8o9h7E8PM6a2rbv/Cu+Co79wqEip5ceNu3k9/zXxA1xQcT0503bKVhsX9SrylwLdeYve9+xPNs2D5vrI4LV5jneTW+ct2Ww10w5155IM+6yUOlgxS0IzrNP2MXPYYMuvLGTZufuoyHxDxWzH2Q05I0rbHkvXVBJtencOX5mAJrcyFS/kk3W2M4rVMvfZMlf8b10EfrZU54UeCQ9HNdbUnr8vvaUvtoJUFr6fpZEwfNAtvd9/cKVLM1v8eWhQwnnGgk6+DdLFrYAP4Zm9idbfsq4iczsAtM07RPyMOeZ4sV/yjmvh4f5xJ7Po0jghEh8PL3mrl/fTsyaouE0A3TOmCK9WP75gqP5jykvqMdiRi+gNxQORHuAQs9eeKfLXg5S8OqzXwA9xkwT9C8XkwJH7mHxykOwlHVRUmbyKzNOJ/r4RRfs6AdYjIkJ/LyD7tXXd7/U9HtaDuKzFDDWTeIBRAnc+kf8teY4v8A7f6wB9/Q1yUA/cFIMaOjYb0LqMVyVosj6QnMVkT/h05XHbaubTaJhp+laoTdEr/WsQ1HPoPvBB0PjPKiPNx4pjByFRL/1FPy1QfzU/4TyauatTIqzo8RmvRiU+PcYqoJ35wZdQwEWT5STg4SGs6mgr6slZJQAUukdAlIMbkYBKs2Az3mTdH0D+Yjb9/LGEQXp3rflEcha3/AjE5izstyoWOHg6nQ8laVECa91SEYn9JZzFw0G7DngrYF1rSJWbTk95xi+uN4kXGhp1rOQQL1rN/ClAjctAUAc9RSYhZucFehxjQYp3xBEiwiTBTpV00xXZ6VYXnKidwG9SWHYdmraemXU1t090y4gvdY+9/KBqqoLtdvC2bDUyn4LXEWQw2rxJeZWwcwuAq67UNqyh/rgnls1NeWgGsGuUrYX23uECaKbzlX0ZsZo2Suiu8zc3u/D17d4IMbUVUlGAigD95bMtPBLp26zwlHLJ7faeCsTmSaYKTyi2UkHQITj3+xQago9GJmzlPs3eA2D7foOBzzAcUDa9dpMbujDhDw3JPsw+M7wxNsu7w0YLQ9iH+huQa1rU2wGtlMkjDM3pTEbxFJnS0UrKvtTIIuHeUVWGrLp4rejBmj+ItayuEEZ2DrOAKO4Y8N/BiN+GNH4CxQLt2HkHYyAGRZV0BRF+K+Ly0jteMB7dNiup9Hmzp0B2H+gWS83L6iy+MsVNcEZI07r4Z+9bHWUUqIYtY9Y3AkhQR35jsQE5tzN1qLz3pn+JQMWa/2r1gfmYsCsVLKyIfZPDimd/ZpqnmxuEwzb8jl0PgKTulITMcZ4fJp5Mdyhdro06o5C2Gr+GTyiRNMcPJcEHNrztU/5SRBnUyC48edm+ps4SmMS3zXno+I7WTqwalm18frdvQXN4Kh0bVnK9WJCK7ApIAVG52gDi3bhgyOMgVCwEimIxfiGVtjZyv+X2/HBAPH8Ks47TbkytBGaFB8Jz9rmq4NDE/7ieF404K0cRJqH3PEYPnpeYbyFdS9ddkVoM6DcOJxr4Brw2qmkUT8OzOI3vPwNWWe2WDJStrY1eyKWsHycAJE7lM1q60F5FXAIiCYqHAB4GEL1aDixDDjTMExuNhFQXsJOg3qWgzBvgCPFMzYaOOnr/bhaNL8HG3/k4bkXMEE72tM1/b5q4hOZiWALy4ABndq/OO2JhaCjYB/E9+obemciGnFtm14CxP088urYzqwyH1vL6mdcCUm/9spuxWrezW/PaDh9Pb5jsLRqdMSAVtehaViSLn2qRwOAHT7+lLabOVl7XGkAEY1Nu74TgKsssJ2LBsUJYiX8dvL7pe9GVTyKN+ENrGVmBZzNf/GzAaRrG2tkMlywJZfpqMftXJt6jaeMj1Qm4XoqKSnVoVfKg6bLWAWLhnDfDzwCUg8c3wLS+2MbpU8QYBNQdJ9iZyarbhKZpPGB0V5OMNsntdbQ4wNI1VnUmEkD158hpHH6XNlv53N+8fXkd1SB+ZZIOoAON3yJasGLGc7vVd7zu4PAEH2fAWsyeiRhp9+chylzyyjIIiqWppdchEUjnDg80p+Y5Bc289/VWnKpKyY/GLLhNqvgfip67A/2kkzwvRxzI9VBrt3y+CAkmRJJcBv/RA7teHFqcp0LSv6MWtxxEl2Jr6ZMz4ixC/PHDTNuhiNLW8omSNYmVqQ3sTw0nyFSCFoPdF+g/KjsoBT/nSA5+bwjLx5SU4V9gS7bubpQ38hhAekYvTAZ+lUt/UKL8zjD5D0UK/AgVkc0FCQslGChVPjlqAN3sZvM836K+1X5rVwP2oON7bE6/s3DMc6M1mIdfSX5tm7rHxLkw+G8a7a6T5Y9NpZRBDmfzeucmy9bg6FcWbx3j90jOe2/zOm3GTtGBrsbOQ0A7elZHc8wlvqSb4dWVqYClFZ5CDo2NWY4ddRtd7j34asOcmSHLkMV2ybqQF+IrzPXOsuUufcnfENQLeJBXgVJHHacfZUUw/WQKSiGPy5MAPWczUzf48rOXPRLKxpIdePTMsiaV2JAy7O/2LC6HJKh4RzWfgSteL+vH4ZNbZtC0PVKfXQAk4bSgAUNwCDcQ22SzxCyX/bhEnqrm5MCpsC9PqRZ5SwAYlbAeTdGfzVSxVwBfL5swz+u4y8kSDvTLBXxXOaloE1PtaZ5y8X/EuvNno346qjmb3nsmFfM1wziSmeon6iiH1usVMeWAYdSMej3pF6poyCv0+mqoG0yFFkSpGVPRoWF92rfmbQgEiPgyNZ2AC28WP42Dy0l1E9UzEfmFUpxtCWxH8d0F5QViCl8sb9Fla3nguR+d+hPHVNcC7PEe0xxJiXRaUC2FZgD6i5Ev7LLZuPysAHJ2NmcAVfXIUUMDmpE+KD/TNhwpDvbMIYvrjcTXv08MueZnM/e+BUg+CsT8/ofrCj+dU0SpcRPAS1xNI/uc4EC3XqdXJtYs+ulXlc8jA9TKxUOHoFTpKgyjX3n70DVtYfsXT0S5R1CH9Dhc53XUtb6qZs75eDEp6o3mJHnh8fzjd8XSR9wEOAZFEsYOC8Bdu673vPgz8VTpunupOlV7IZ9XRulQjaZsXTmF8VcKr8fHUxR2YWBvgmQCYPLJLW+sIddi6AL55XQGLz27cemI1qJ0GZSOUM1YvRXSlxN/SZM9BubCuIxpwaJjb4d5BDgVsog6TC2Sw/UDM91Lg+eHJrLkiSyz0P4eBAax5Kazdn0+IxicYmubM7w9l0+rOF5G+ctDwypGsqIZOqsKw51CP/dSmHDoGhOuAI4nD7tHqpLT2Z8hwiCwmkZ+nxM4TyRLhVzvTwL3DxZZqksG9JsXUTLLcxCp2VFjRyj6BrBzp4M5f5acy6FtosBfp6BCpjds26K5jG1ju4K4zkliWZANsnStbDXttckxgXTtoqRxXbU7afAV/lweUQUrl77bTDkrjMGTzktntlMWKopqMAZT5nrQq+yUylPkGNGhCOi1LsADW3dJUCePMJuDid9IyEkF0VqQYTaC4w/ecX2xHj4MNWRrEKb6dWCdK6U4LTQfE86zxycHgsll973i8WarffLaPCFdHOQ60iNfl0GTWXpqAsATZrFjA6oJqUzQk+8uO9IfXkVzHOA1tsphui34/4PWXEnCCBxnPEWeFXaz4ylv6MtEt6UQxDzxvuJK8oafx92T1yKfYuGvw/V2/dHjQ2DYiSdmCNQVZ3OztrOQ3TSkjbdIUqq5oNfPpKgQkk3QANSeZPWOK+NnRtOunD/xsZvLbTGdoHvKtbgVC9GYbpDIESUsMgN2eiTJKZT6sU5Y2RNIHJbyiW4AHCY2zks0i1GwX9A3KE2V8WDmH6PwlfsuceFUs2mQMG2/DbO44YuEFTTIHBM+7NtK7VYE0uvZ/9Wst+5YVhPxza4wgXnhHDrC8A6wJdjnbJnlZB5/kvj8n6Fse7MhtpBWwte01WdqBtwQe9KExsD71Xs/2F8d5SGZPCRxlQFzSaLXR2JyePd/KjEIcS9ejcIGo/svE7vAQ+r/OIM1se+VQFQF2V0ifNz7jUiP5Zd85Kd16TbahqpSgpBFyRy39dmnNtIhkIL6+KERtdf38XJmOe6yPRVk3ULqytNbFXD8kswWdqjVAt4gIrMRBEEfowjSNQdsPgNUkxdTrn4nJ2iEqkhZ19kFtxXGkLgz01ZUDvTgXxeDyKkhvAzkDsLqrQsLR+nrHSfIi5FYD4tD43cesLtG2wOA9KW1FKdPUdXQnnXqzvWdF3GEYPLXC0A2KlAk/GojDGQRQSnmm26/IdEVuJ0J9bqLa94nVuEuqdGI20ESLyaoZHDjF8vLjnA97NhuteGkqnrfQCV1KzT24rN+VSzmH3ljSAledcHgHCLz018gAC+LOaGZT/LTJOjAEfgAShGf8gJo0I7XOh7P4MN31ViBGuQnbjufvDJhFgYbqr2atefU8S9M7PTCx0FYZTAyiQXWkTXW8aq6tbEe4sVBNLbNbGHoJc8HzyQrG6Y0vOd9Enz8wk2wRDVsgwxALcqXztB6Ih2osfMyMPW4ZgJsx6r4hQQ3olWO8iAv2vp/DWe3Pk8WtqjDmlwxghE1PqNqLk9VpGxwgzo88dBvjsCvpdms+dD3MksfFAbSe5kPEr1W8BpbnlM1BQlW78HzHVhqhxMVGZaskL0+/4psDaC5D0v8U86HgtauJKFCb1duEExD1qFW+DrdaKqXqAbpZ9tVqbR2FdVXK1SwS6oryB3gBwZu8+aUcyb7AhfHCLjnKZ/0Bo4jKr61okA/wymAwVagA36/ncbP7kdljtVWQZ1dQe07e6beht5c4qlKKj04WKi+EqGdmxi/Z02d4A5BwmKSNUzZfWEsyinC64o/SckoxVTnZYa7RdY0yuFXbHoe7ibgG0GXRpLYQ+AY/LMQN2+OuMP/Et1rVtq3D7K0jPlapzntp1Nqp8IguQOb2YT/QC1Ddi/rvfsdkRsjZl07w4PzSLBKylC7SfG7PgfO9rzu5QUiVjKS1DmDnOgh7gyvfHxbVPQ0Er2FERuWR4p93qpMRxi57e/Umw/1FNGWM3UyDOTFgsAudxihGATmUaAjBk+vXzMm6DjIwkqyS+g2URmmBSBVqIsikGl8R+zC3SOOf+1zJME4Qkiqupy3lmoghgLNOZuCFRluK0897eIgYmy+RM7MLuF81jqZ6ZVK3LEVGSW0uK344HfspzvDGXXSCtDhYhQxiUfkiThcz+SP6OxVyl028zu75abF3GjFiAAD3/PUjeUoIieDpGm3xR3PMobdILiwmvBYgQVE/Il4BzCVNAO76xaBRxHxV2wv/yXErtkfH8Bj5FE3U/vFc1WxE9+nuiMFHR+mtB9T2bDNzyTHqa1t/v1VkVnvu3ftJRfwnrPqX32nvGL5V5ATVBJePaDkQQMv5XVScMJud7S4kaZ5LtgDd5nt71ZAyzyOUIHVKeyOqK3byXFZz5R9FkGChLapRvhrXayYC6L5GXl1/YRE8xa/VRJ1p6xoMPE6jKYWaIWQ9PGhkVvhqNN8Flilxr27CIx142yNUyElnJSfE7BgIymnPNIDpFNpx4iFOkL+lvoWEBeHvJiUtW9eft/t8jKWcI/+rspaTq4GQcGIzrRwJ7Wtxla4rGmGxkHaKvhcPu8PqvD3MivwBpOfrJICm+WmYawXNagginMcvVyToFTuriCJYqn7tPS7hSJfOKvmjj5W7QBHmis/AZPxzUSdMo5PQn701sx7bc7aBMj7ilusRAqBbNspvx6TXeY/9aocanS9Fe0bkbmQ8xFfPhLqcWcwfQ0UOuxh8lEfbGJ70KMO1l1V9ZgwR2maxOJMtWPOcVQofEZaoFpdP6HCrwswP6Xk7yTay+MPM8PP3dBnhwkgyYFPyFC1mOxPzK9+e8i2SibdnauD7sSJ5jViscI4Bxqd7t1IW1sjSWN0w/xoYpEH314dssDA1rAKycnZj1FcFZ3tBEtTj7alE/a2Bf3GNoCEY+n7+8hIPXishihAi0JQA/JWkmK/TwmiteAgYK2h58UZRpu+2E1QyyJAYNw9inFawl1R4gkBOuz0TAsr0WWzJ6uwE8pN7jjLM0B6ofi89g496qijhJNeCrlBLYqdBZe69PCBt80Az10SzakASlew4B/FKklnotjihI8qml2B/MIvckACXD5rnaJfyxLYlMzgAIuo0E0AcgNxTbpCjrGXQGGeY8oOaUXH7uK8DLZmpxKPgePF8uR4FfBXow5E+IsnHE/oZPAPkg7rVUwtp7dj2fmh+N8LudcU75gSpkalpALsedmUmiHhtp/RCsdi5qCm2mXsMIk6iuC0ZvVAV/OzJLWDdwJsTRylGRbqte0PjDYbVgnsXAuaZajGp9u6OAFWlW0ddA+1ozxFAzUSUJxPwmZpa4l/2TNTQKVQ39a0qxzfMOHuEHbxKW5VlzL3d/cIfa/V7MSuwxGXC71i8W1ZVpA4GO7OP1BhX53wtvBIcI6mNAchIgg5eyLj/qe++vUbDzxAoQ4tuVmKB7qwZCiszqZqldNQhemHR0dQLPKrFUlZVYLcWVAC9j5x7JSa0OsTCWNISk2wN89MbxwwIV+nMJsgSxv8sFML79Bo5EYoBI3chiRFHlXb6mdVPnACIA/uajiKAR4Xa5N7O0GhWR0Knf9BpvGvUEzroUIY9b8fUDO1SMM9theKvSMXN2+cS9edhzI4pCfKj/gZjb8NIh85eDiSUoRm3/0ty1/6BJgeoEbRcWFVPudY0AYnPLNriIA/u42SBnBsNqhFEjDhyzckLVD80ZqjI+xxDGBXTE2W9vhgP74eDIVglcuDKWj0vWPSoYH0/JNncZ2qkkxuRQsQhs7iEoF4dkqJMDajspVCFoju1mHtTG83SM9zU6JXpzw3gf3KSSTqSmyz3KEqACb5am2aoRJydGPR676arkB0Om4I/MG2sbdfR/Cn8/GmToyWhxo7XEMmHYsFV7vEUiV+qgGTQ3ibAAPQrUHH4YtYX0J5rGvs6YHXXF/SCtgBAjrIpyGbsrtEryosBFRWdGJs3ZKFr/dxq7UTeQE8E4mw+khGiDusWqfrDGNwmbMAv2TI4VSnkoBf2owBMHBlR44fIz0X8lkHXPjVZrhP1Up7THnPJc7wLDPaBdne3SQWojPJaqWuu7GBiCObome3odWvGkr78NrYVABTRjM3S44jm2vkubXZOz+nPthUrpeEOHXLTw+rU7bPPQcU73ZUg/8GWRRVVmAokVmvG2mIZcPeLiOn/C20Z7/NbN2O3531dEqM3NRmOAKnI+dSfH1bxiH4Aw0Kjol5XmmOVMqCE1vc8N62oeb9UbNIBOo5iPb70VFB3nlFJn341quuj/ir55XjyCp9UDKde4fKKo5Wcjx1O1TkTNC6VDMyJqrUwlCd/Zq1l8B8WBaJJ5v2QXY2TMaJB9Hx2sgz5qXwp/hKpKPLvlyfV3SBL/1b0RQjMJ7MDxIPq/OllMMjTdynB3uxUyzbTfejVPqZJDYMxthVeGoE4TO4RQ2QylllMgS7Tb3W8jscaZxny9vwbvYaEk76IpbG3zJdzG2ha3+WS7QDTiXxEc++A4W0ahVVLbsD1Uw99pEaKK7xI9a7BeXtlCwBTwvdttms+oRGtommCaqkjvQ41X0NGUL+V1Adu4nEqrHqcpm+MnpMezmE6gSbIlyaJdpLP+K9n6Wc3Dh9i5NWtR/qN3vosx2K09EwgpiRAwP5aw3fNNTQAJbAbs4tJQH4JRgVMBuYZvI09zNfA88R6g9RVTd9PW2Sr+tQvRvX3q2q4Qd3xoFK9FzYz/6YQ52QxgysDI79XBxrrrkMLF7XMq/cF8ztoo0eAtiQ3xjzB5L7pizAzlQBuQG9fZPyOuuhiy+YpTqL2hioilObGWYrZLnRyK6pw9C3ZMXcb2qd5hUK9eWD1m7HohmG/+I+zTzNbqYI/GTk62wsBQQtrV4fkh26DgjruDOTIY6VUD6mm8HYjtby39AuXsrO58iAes4T4RiyOju9G06Pr+PNJV1ewR5havUjSxL4q79xUVYlPh/GXRJne2mrc8q4IE/xhKfQk52D+cmcHzsXO9rlUUyvC2AX7M43Z786tCbbKYt50380HYDJD0eedtzoYQtOgP3OvUtGCNgdER3ObgvfJqokmy1cQApv+CwZE5pyu2cNIKlKxAaFXMcH10vm/KJeQHfl9JwFdDQcCOiXWuCPS07KtVTog6fNQp8QagLcwZZg6kV0Qnvu4MLGOFajNqhuqDUyzEkUMvxWOTY6/4owROydZ2wIt7WNKYkeodjkVLLRX8/NJRwfBzUzllh1EdxBgKIg0IPJL8Mhv6GYOAfe9U+2mw5y+d9O6oDfuzLAA9X9BXfdRLvFqHABSdkzRLt739lEOQRSrngmPmICEnSibk/pmetzPsDcl9SR2qXb3+f2FlCkNkKBzS0YctASj8+QhccxCfooo4AsV5owRn5R+Zw3/LFldK1dVLoaxNn4svFu0NgWHDxXL0LLNIx4D6vn+xE7Du4ba76YE0/3WsHf7e5g8T2aiQ6v3974sMdQLhr5w02KXx2+ccOguvF0oBRrkjWuUXxrd3U5gQ+/yywtM5UArA7lOQEAAr3fKaRboPowWE5BEzHM8n1SgXlnxlK7fni+6yVwQzKT/rVZ5gVk8tFaE1OuDWTNwvp+xC2nmuJiCSHzt7PM/icW/Zc9OCOxGdScnw0GK2xa4hSjw5qhtQ1MEfLiqekLMWAWGPs0llFjsdVwhzr4Jd7e7t/VCMTPKdFLeIRYC5tI2cwbVnYk2MTIOedRIiaK+f0lVKh1JRoMqNsI+SZLS6ZpR/LsL0uBlNqIvRd/qSwuRPwXbxVKHm3gwVmK9ISH6KSWgngs250HEYbOq2Ys5768yPb6hOvYL3JGi0BlLeAUhmHdL+ETVWrb+ha8zDc5JCTcLNd1FCx3cPPsD8buBKbqBPXqGPZX8KAVpsOmsUBt84DJivHnLlBf+03qKQVZCtbTmt0rz6RlZYSzzEXik/818+RAflBPzntoj4zFiOhVWlJ6tB3UufkHKQzxA1ZgtvPHZxxvXfVUP7o0typVPS6lMxBnhJMH9z0jfYYsyZDBKcR27y0hPQWJGpFIZUoaQMzpuaXh7RM2lj3T1Dv4rtRAUppKj0gf6H6DkT6c1f3fi/gtjtjkDySIHGMeZOITW0Ns5E//WQXKZ5K3W8Ej4HH6NoOU9mOfDJDGqU5dD87G+kJtvk3FHESilD+mkcTN9W7G2IS9Z6Oe+PZPJXha7gmVSs9mwbLOA5b9RJXYo1klqmMX/2YiLTOmjEQd6xWkC6VfOfORdDg98SDtBO2jpofUhqY0zC0SOEOeYndQqN7DTPKc+QcMqbE5fkwj1gcG/hCjGSdY7xI5EHyuhaf9YGpMaMf321NVT1KVynFFKXxboAwhqZf430ipOWMb+KQ1JK7LJrz3Wz3G4LVgAAQ7RMp2tnOT3gpYAqTE3406FRsQhiPefBSk8PvZ2v6eIX8G7b3FuzOOmpaUAnakcbXCrhOTntE64PFJ9P6icR+Wdxy73P+yt9YMJjl2CnF3irvBva43X08KCheZ+CCmN3LY0rE7I/+NjDDTDaaveVjd3qkQg3oLrtbcf22PLgr/aAHSPNAsab7GZ/ECPm4UdDVlg2HoJz3xm1CNHaE3I5Nz1G7hySoVU6qWTHY4WGehxvtLfRT0f9zl9vDhr8BwMQAQD0eEpLCVMhRxKGD7txh2BpGB/SbRJqGl8DX9NhWuE34qL8AK6KMK70odShd8fiyZTv0o+eOGVVCqQ8qoYJHTJ8Q3nbS9URQVnZodk2/1QHz2kWGg7sY80nidrqUqYXDYIZSORMdVjnnFX79n/C7ZV5fl1+ZjaQxaBo0lTy7miEiHeHexMGs9mzkpuaUMFyUAF8S3ncBVCu2QbgHiTFFia4yMs611RD/b/EgePld1FzJWUI9kpNmXoqCk0XJhE0Kt4+Zf3WiDvgUFDdHNFI3bjXJ6pVt3EW2Xr9kJj0RMWIRaBYTWmPaq+Pv0dvryIx/tKuz8Czzezrb1Z+e09RxcYY6WFqzN2cq+aOdZCGB00nq0bHePpYMTAlNk07ZcXsWc4dm2vX/9tV49jT1DEQbbj40sKUYxuM9rD635WkS5QeJ9aPup5iD8ZxVK72N/r1dBl/GZfCiVDf9SfpTs8cX1mS8O5HIjca6dICPF8sOixgOvYQ6DmwOzyr0voWDPIs0uyChHs5CuVTYG380O+EzA6m5LRUnRvQ81xuOLGAoesZ5oQWJw3V49uc3fXWxR8DEwAUkrvnDE7HzBj6y4VeuNYBEJLaqhpUzbT4klcHxXzCXrccynAhsA9j9L8+licW5/gsSYbQiVL2WDuubI3vJIEbuhMQ57AsZN8ftZblrDUs7rPtybkfTf9CX6swWoQsIe+9Fdvgeey+ebY0zBQsM+VHpdN1jnqfQS/QCj8PAIOVm4R6grm9JL//nuFCZK6pz7Y6jmwRtG+oSBwMUX+YBQzUVWfzLiQawPEnmMaj/nBfQz6vjQmj1EbPIp+pHhuoQrT0J7WMOh9iXd0T+ZkAsiUAJ1486DDVaeV6EggDzNOB0hOmGVD0oZPes2373UfwA5CxFFpmTOvzEwmPIl0PRUo4GODVJrZYElU5A4SfVoL64ce2jfKRYUpTmznIfJeRKHl3LaparduMIrITfl+gDpyMpr0+PkH12K/UJiQ1OdwHqLHTyBGzeHQ1ug8OhWxxQZzx0KuZl+ogn7co2Hk//YVnYWAOhWKDod6hkkdwD6JrtYx1pycKanNO9mZoxMe/gpCGPRKEMVEyLjJgrObGcKMWaes8siDrPMU7JE6Hozk3GFRuPbdID9dMxBZH9vsYIKtYcINWtf3wAzQTMbbz5FiNEbfNSDl+lcIjOv+zu7pHdL/PQ4qEDJHR+t8IyxP640tIl0sj+N+b+oy3yejff4ghIbjeX86zSATJCh24oUrzlh7VClgEd9E8vH069LBlkUrb/M3zJeP4Cex0yzK0uiaTQ2Uz3ed5tJeNmkfTNqQCT1wspwkhaHosnwpJecd8NZ3rqQfISANJAwE7lHLQgaa+C7PwPF08DHXwPgBRqbwmBw8sX2tQnaOBWb9ii77I2stTmi0R5A7ttca9r360wijiWrQzMUhzrEBfrU/xwJZW5o94Udvjjg6ozdxLJ5EwZzgTIoOD3j6QITyf1nKiTXQblR7MmRta1/ePvr+5iW6Q4rJjgTTHiMaTnjCVhyuQGmWyOq6FG+iAWQ+9x8nMTAne/HewN4NKbOjpvKdrTFWLIFHHRVkXM/3ppmdN7iHxTOBDAQx+vdFHVYLrn8erem2cmkw1InaJGCs85KUcCkeMA6KX904gBf7PyekYmfX5UjmgzC8xsPp5Z97SUv3B3/ePW+8A7ekRv1/kURxA9chk+CxH5bCvDtc8m6Itq4AV3aeMZ0tCGtt0aDuCrGCtifVaDrekQuNeOV4nxYMJffk6qlQMHmhGjyBEgx3BoY5dGjXLZgti5QeVF+PsJiWn8Ynq9UotuJEN7FBCWViYg2i/vrfReS9tWgrBzIqZ9oMz8jqYH5HgylUrgnO2V+VMuO+gjFlxzEI4KTZe5xJ6xLr8pZj1B10GSExos3AAlOWoNMXmrp6NePXyWleaimUDrlPiRdYrrkxOxMuKjvAFr7g9aMBM0TxpqP1b24OMNRWIAyYK/YJAvfSVSftuwnBBaq47jhlDj3eOADkksUm1r82hFtHvuzKiBRfVBmUAAGyw1oFsihx2Tl9e0iiBtlFC8b/hAnx+5bLSEUG5ZFUIiMkrb+Qv0f4iQsaoJc0tbR9vESCuIGLjOaWHRdpZdz/cqMzbnYU+pPvEJZ6T+a9QgZ5ODvwNqdfjgnzFdnQehqX1twslQLLRBYiCQeGW6HD7/wLPN93blRU3jzP0KhOgrFMkeohXfF085SZdvjvmkWnwEMoHkLx8kR58nw7B3xwJSmTg0bRySKMHs+IkMrQjYkzn3PdSX9AVyZP+7faP8w72/qiz03z9QTopHKrVNEFkbGf3iRWgQa7cF3alfUEP0kH0mTNKPCPbe8qJFODgLpZ1C/1xUKEH7nDnnECibyNzuNgvALF2MFYtNGmnupOcErxRL+AyWYJccIFKOROG+fZk8I7jkwQXTm31Yv+oBiqoQdATS37x/W0AWzkv/qKoz3MOkbhN2P7HcS/iEMenG2EcVqjmMioGz0QnrVR0wkm05jDdhvTDnBUd/7T+9MVZJcUjyp+5yZAVq2pKP15TvNuFga9O3AR2FnO7tUJh+2rJ0SgY9DZroPgK50YTiqMOM0l3K47FuzabbVp5kJf2K5tdoTuWrCoLsbqtwnNK2wh5LaV9v5z+OYjCeTh1IG5pXgJMTnTh/Ozi+8QessHV8WsxPaL0RJdlXhaFLcoulNbpQM45RgId6+iMv3mSH+b3KbXhD2jeRdow16hYEbz3GblgudUwRGuVr/H3H1ap6Td6hMYVSwwthShVwFE2Ea/DAKCJwdFXAPC41jVKfrSrxiL7aZGihsSTJCphq62Ms2iohzx5449t6lVd5PaPCKJ3YTDmE8oGj3NJliPqEpFeQCqjAy2cWgrAdNBLUA8TIE9YyJ8V6I4EMUiDel8VbFlD+a2QjWC7ZYy6iT6znjx90N6Oq51t6nTm2CeQjhF56G0xxhZmcqB8I2C0jJuY11eXOtT1Jcj1P62e+hWvgh/BMR0C0qcn8BrXmB3be/2bxIR5CMyXw7czDMQVTxxCqkv38xplJs9bN7m+xLqVjY70AupoI4SvDf74xmOmiepVD6q5IQFpUZuUqtelzBardBOncctqPqfHj51FP19ucgzugr0hrMAAe9mLmF3PM7yhIddab2BK4tYYL14uQdaPaMQb7Wi0Fg+SMlE27O0yezITZ+cc7+lDqT/ShiCLOYL2HZMzipIgeTlJWb7TDKEO5uPlLCmphsN+fS50obTWYAxOS2H8wGA20NCyOojyOhqVVZ4Ga6MEBKebkZ5jL9mLBtccS3xjmXIIn2VYvMP9u3rNKOqrSwQ7FhI2G/vJlKhrW0UiTJE9QYafQG0yJXPDPqjD9wSr/fCwOyRo3of8ZDhQerkXnIXkqwZKTlnOmtBc75TbrhKbNf+Zx+CxMKCjnynOHcKdF1IqJwfZvkt/JUMK01Jmf2NI/xsbLjPLkqrLUVHZyKeExVXP0Ep0FvHN2sOUIuof89Oo5VoIoKpcQdD6NsWSsBXMX0LZthkOY8oIuvcRr2sLUAMh5f07x2IPF6BLI2q3ROLXHXOVLq5JyLIp4rt8reM0FIE+s1abZHWJhxXqvd6U07Dd2FZAEX7WUWMOEK2dIfXc/u1p1k7+i0HcvT2auvkI8/rl/5HswmrMoyZvb2F8SWoYBi7eQxRYtvNjADcEDKqNXW3ipDaN0aACxL03lQ11JhgdYDwJSsOKwlSEq6WidQ/Qnz+1ejLn4yQNf2PZIGWvI1J4VWGQndp6BoCgvZ/epHo0HtQJ24Vn3KJcQWsYNSHCk2Wa9rdwK9Fwthr8nw+XUFI55DsmnPdPs6BPQxouk6v4ng1rRa9B1vKXM89RZ4+hjNqJ2vT4fkMAVpNdCndaIVoUb5rkV/OyN7vRwTzkqNXiblDYRUPMaHiyECV3+GClEqa3Oilch1J3Z42NhAwsvhOhxOBL+24zHHbNgUm91cefLqI5ltRtHZoIi8G1ZiYtU5OCR5YFmZtWGposgaK/vuGFvkZ2NFlcX8SlQSXLO8yUrp2s3wdvRej39XIYIP41sQttp/wB5wbtYmhbl+Mb+nhnIEIhGf9I0HwcaIvKsCOqv77NcQDBY5aGamJ1vm9mqXP7IsJXZqbZKb9POlS0CBbhFurMZ7tNs/SY6tY6pjmMCnqTx8w/PnQwRG+nF6ZLkBJOle9oNqBcO1rWw9GWytYhZMFEhgthkKrk1t9+ikrOt4ltbdZu4MJqr9/5/OpFKXkkq4BGHJSkljNUsE09GP//ETiyg9qj/rRCn8gL7FhbCQaYnMRZEhYoEJG0cPfOGniSXOk1l0k+OaBwVd5qvoKIMY5llKvF7ON07ysR0p5cMC+7k3YoLJ88BSjjCkBiolaz4zGe3kz2SVy9ppPtz6Sq9Wl5VVwyU3NBPMELa3XgFlWGBb49m4nApkHdmH5hKLufFYLRCDNCD1ftqCd0oHBT/HnxwwY2CeHfeEUuvvxz6TBa+jMREx/UNZAYh8VOXKyOuunsvUvsgiaH7uKGVMA9wdUaqQ77wmONFaUZm6JLWH6PcyfDXIhcoCcuoKkrc09WpXNbHFoq4qGQQs2CW4wRXgmnC2l4/ZVbAAFdwP1rsWyRyUT7kH58a5qshPvhvbmro8ZY/3DQR2t8JoLSJDERFrUOMEibJhaWDnUv+uHuoTqbTqlnh6OM5c3JFpH6IYpOy1lBUIBPjWexdhOch9VMcopMHHZmBGybSJBfKu0xfyh1QoBqJALS8MZWEyYGOO49/hwT+1gbqyo/rZnFDh3Xf8Iow2gvCcYHzIEoD2kAxnVmq5ZTmuaxswxNID9L7dUwZucYc9B/c38WX++rbIx95oGk/i2s4jMBftKHeb81iPeaotCdP2sqAbnjUupS5XQI4Gk3q/X+O5orCfe5z+jdJ/F5bhow92uGhMzBFTdqXyfBza6Zs6PLmL08ApKL6m6nwKhC/a9DLQPz0rLF9i3CmnNYtfHwf80/HZU8MTy+F9rZmG95BPvg7pAmZ5eniOhQ5s5sh+BdJdfFvr8TE+ELSoU6EpPeQlb1ziINkLFXGiMzme21/yNgqky3Ijbfh256bJjz+SFgfStzlIAexavFy5h/IUx0eiu2XGbM4rVX3Ous5cI1/IqKWJiEHC0M02Bde0B7YfqwFZSm6UauX3SfTnCpHfzNJjFl1LhV9Y2JzQOpqTHv3+0ha8O7oio5YSah9jAy9bVY9SGj/Of5+eMcUGbkJj7tlV/v9aPDzHUVUa13ncezrZnVY1akvq+szF/HW4nN/4Hj6xjlSM6yEDDxEbzvG06nUfq8I2FUrstee9ldSOcnHfYcydGQ+Q5TGWzqE5DDASciWK4KvsG3+IZaOwnWGQNVYeTRYVKYcDw2wgsQzYRfCsvQXvFHMpl2AV2MACOXfgo9GfQGiqe3/ca3J/iVKro4qLfIvh2+jhPMNwyW7BP/YMHyGJKbl7cs81kMQbpj6bVFv4ucddxSHzyEOxxSLnQfxoADDXIbKZYtUwlY00BklZfq1j8L+1m3qL9OCF9sCsBGXJFtvx+EYkSdwzTZ+cRg+NXAAWO5Yfu4qq464S+z6s+Idz3KBoCRGwSGdDXI/vlyLl2km631rl4Cf7QsA09RtXZIZpY4e7rjVk7naQXSz03nWojqNU+ZfXKfjc9DGqFabAkm47uMcTrBJQ1IaXq6DL2V44LOntIkUgaK5pEyfw2XSgFvfJxhEDORIJtmyBIlhFBYMc8OeC/QvBvTRHBbMApfZCaSwGE55sic7Y7dRP9X3g/YbX6tpaG/pL6yxBuNN+GIqDQwzM5wjkSS9sciMECWu+rQrKM4pfjoi8K1/T/sZNUHEh+JzCSOcWY15SU1lKf63NDvhnn27cCDqsPwsdtajX/ImlbUeP4q4ArRJw07WO0+9azIBZrw5VuGVmRssXkhrM9+FIZmxvyiFGkycXmCPYEqrVMMSV0iRyusYxEaQ3s8VY66cZw5uCcOzwA4nUfZxxwfRarrtgNIeQBwwIeWSoiTltq1iVEL0bcOVKDDqot+8cuVJKsE8YRifJzVU5fycmwnAqQTTiTjaKz4YMiYV9M7rtGIAuze9LzT1AX9XdG9GAxkRGataZ0BQxTFOkz+mkniXWU/+p0EDjgrdsqXLJbZBiOYwcDrdWhgHkVPK03bPis4l0UcXyhzaDdBVuJhMuWLpk79CdCeLGOlfZ6Xb5ATv+Ytm1qXNNsTRhH4s4jG00DkXgzyZdTro3HpHK8gZvuTJ9jNLrt+TbdTzoK7yiuOKW0i9JCVnHpLOIJHeuLHhK0BeGHjyiHL34b3pktBkwzin8vomuVu0PNuWpM30/2svq88Oq2B3yKT3k4zptNzpO1oMSGq3sZcqlcOp4Ij8aZy3e66+r/Bg7L/RKrHC6xwz//QtQnMbrjjSpNw2HohaHcLvsK8JPheMIJQ7YGMH8qrda1aCa+hyBHTM3q7qR7+obIEHvSUm0U1xkaevjC5XeLhIXvKv0ChsoQCXn1WaznyH9RTHoHUnv/cnlcCNpQVtyzKgHQG/d7Ulemkn9X20O6hCJie8LLRsYupj7LgVHEAPUV8I1ZNHdrGWamS9yMQooQtwJM8BRbtOI6QuFIzRwiO9SwE660pmZW0AzyF/K1CDSCfOszZ9QkNOEscs3mhiNBdio9Zbte+dhmG0ZWosgaQq7uKX0irHtumQHGWvhsp3+EH/ImIUEe7jUnFGLLiChatAUzwL71zrXiUp22Hfu0P8mY0K4XwVLgtoeGFeroStcpmwN9MgLeuOn/ELw3zxX7bnLbj6DvSXaoFtu8H6CTSQLUiUPT4zSgxaEh7RLz/mrFUm0jx1ww/goBTVmxhZnHIndVMugSD3pjl2doQ5Azj2+BYppHUAld3gdBwM627yd70hOrVhjalLxWhLB/DUKg9ETJIma7lG5Hbq0E22Ojuc/GgbaJrB5D6nVY30tDZYUnyVrX1ZsBsyXo9fpTKF0P3SIniV9p+h1HITohDOeWMNJOMVsS6ZJ4wLQddFolWaXZrg3ajxxdLMYgfXN/XpPhFLhW+Vv3XaVp/M4j3MGU32ViiwEFFpZ3AxMgKIfIcHG8Czbc9lBYc3vUrgloutS9omd3xBvjmwUIvb8AJnNlgE+gh2AB5KEVyZ81wa6Ykp1RnGslC7FNe+dZ7HyoFfWV86Z2HHAhXfOSQK6xnZrOuXHsv/n1GEGVwsTxxz0MFQxckvWGQL06VISI/QIXsw0lRY9F7pB5ydvSfKR6JdNImhChlVVkPg1sTwksn00aqFuKzT+UkahlP/l36AYh5oc8YRlcv1QvQELLUXDVgYyXto9Kw+oJ2MVq18S6hKNMogQxXLqoLoxCMzRFRApfvA8kM7QrOvSbHJfWDHVPUkdJDMXmoaV4W7amP9dJ/tthFgIEwv7wbOdvva7GvTnuVlMC+8MufCN3xNC3mRHo9RaDg3I+A+X/DofFyIEiHXmwr2yMcrI+fHAfSA9RnUTayH2pgc95a+NVjBX3/5AjrOAbf2e5Mr+mQctyWIV/4nm68yCucU9D6YbSAPInZ4rNycoC9z+xG67oIvmoCXv1OZna2kH+UDHl4boFm/YjmMtbNKgy2bsUJ6FU40pJ0AxmqIrB15JgP5ZztYb9FJ3RKh4j7+unjuiQcZfOR7OS/VaGEOc71A8go2QuedxaHYy3WischwEZ1xmtol9BDPAxwy01IfCpJzBYyHLVzkLb/K+y0VanridBr4tbKuaHeygu2PPKjCORQasUsJ3TZjqc5yoh3HninP+XMNMgrFNAX27zWmM71/3b2eCsCh9e9h1Jlu2pYJKAnfPFSGWYOOCq+JLuB6DrWV983D0gLG/Nt06fdfImB5b3NZAuuprdoTBbNiOCpl1ZW702GGWIIqtRztViDn7h+YYVc0OCSLtnIRiSSsqd6kbCE7l/l8fJP3rk/Ah7ucLdBHlzk6xxOfI+KA7Z3o4BWuopPxtHyjd6iVawnWj1SePXAurgdg31/b7KO5Hf7bIbx7n+0//jzo5vcFqfxtqEq1Mi2WKnVpXRUAEZCRSCDC3rWGndqZ62OYsdK9fSyQyKN9VjkLRWMY1VTl4aNrt9+JiJA62TWhW5aHxzCLfQtVooxsanaTvuSZgBLMJVHcXS5iQyRhK4j39nh290vsHhVG413TU4eVqRE534XM+HXOjDu/ivg9iZ3SzGX8+Qlm/LVLHZWy0U5gi4ND7n/oO9GNvrvktWtolPIur5f6fCTLfktObmqAQ24W6CfMe9CwhCJclxy8v5EfLsGLUWtfg0DBS4ObSUybe+/I07m7BB4O5rVYSA0UOJnPR2Mvn9Ho1v33zsqkL73uqTP3Ivzm/sPXKyAfIUYFlNvG6ZCXlvw6f142lcHlwCgJxNRayiEIDrOqPkuRXPjNxfQSLIUWIcRJEU8HDff089gOam7MmCsvW4MRvkqKQ/2XFZ+RLvKT9zFm4yLHwF80ICE+91ZRy4CdYhZF2ohWNTcWnUTVtjrzqC5ax6mbTqvygRdjGc2wNQvXheq2zC/+FOoFy6eTcr53OCgp0wzXp26W6HGNNata7QfKTH4HEJz97gX8tUlDFRQ8PYZLbzn/jldB0y4W4EjxZCPy98bcaw5saS+wrgHWKTb34JHb1nactAEV0ix8e8mYDiehlciwJazh0knr9hYZdHeJt4eBP+WfWXIcn5J1rNSbgw9BEceC4l3KeHXd6xbLXhEZOQ8obsT8wMzkL5TEfaRG0aMvBMGSsi2HNp1caEZWfmxuErEwhigIEFcSh5g5/p/IwEuf07O9FyVrBGm8hVJ5mm2a3BH6yDqP53X/RNEJG9gxtshiChOOW6OEHESrWm5hcdgyW5xpMv+rqHUJFD/VA9QHyxwLZCwC36Ma8FY8r3JlsPsKkTabhFHqqB3kvTLKnJvA2y9kB7fNoIjKSqleLkOj5Jtq4JVG5WTXr5iuMu0ssP3fm6zC/cPcLHP6S6LHDQRjjULBFVqVCgnTGCrQKeHokmzrv0L27vlUeQrSxsUUVjjZczCA5QcDxXNYgSw5UJ0/ncdGjM4JHwAmsOhFvZJDGOw54HEH+YeargZrTSKwC4aDLz/pt6rhYBkdsE4m24UuXjZ6+ZfisUV5RMdla+MUjy41pJlgA+ie8pzSKMoTsdpeb4ZXwr1Xblkn61l66DfYBXlkLEqYxH2fKig3HZHxTyLPXScZBe7TTF9c29zx1eYWpFjUnlqOdkYonPs3wIIqkxs3Cl6+2Hv6lhvVAx3DPNQyhTafhFbshG5WPnhAmXDgll4a6vp0EsIBt5L3/CZ/7SocVMMlczvNwBgxfp/mvr/ugYVuDLU/P8fRNbIrCDc8mQasJUPZMM1KmVLl9uNZFs5Guq6l0JIyJsSQVZ8IVZ2wJB7tiapN4SRfUGprCMDUIlUOkYevFEKZ5sncmJJQDmCTASCgJldBepBO+lIHsE5UYdquTEcw1wPFH9z/pUWpfJ7LI9zKXVcSULkIDBeFiz/uNd6nmTDy3YOk+q9KBWP4vvQ/VT1Ijm48URtiE5V2yzPmxXxmzECYknHLIlgylEkCqDDFoiz/7PHNKTMN/9CRV+KABt+1iZ+r4F6tpRIcftPGaixJsgtds0WjFCfaC86uUkehJR8Ydn7odqNuzVBVEvvkUcLk6xRUYiBERs3Rw16UVgdUovg2YBsZSNSLEKRnh26IERI0XJ0JZ8JGl4JM91oBmHT7HhJFMSK2of7fL88u1AdlWlI+zvWnCQpsUYEke/9T3wBZyjSTA6DwZRGNy2ttHlI9KajqFjKk5FUTNEkzEBI0Y/HXvHkywpVKeymMWrrJGFW5pXCygSJilevNjljmAME6msWeFivPx6WYe4phEkXY0eC0QUdqn8XYy7ldlxOMSl1ep6fLYSaAYCyntRU9LOkh/CH/+gmXES/0n2tuw3cv8kb6aakGoof5Kesj1Hdf1IM/Mn0O9ivK6LMrHCWviC4K0r7b/iTtiO4kndkeaNhSNsYHPmt+6v4CDD1Jtz28yvtiH7Cl6Wj4ZJv9JkTABjKraEgQbUAAY9p4pfpeG7Dyt8YTMh/jRAg0ugKM6Hj1O3Q2rgWBNpmdz97rwB02R5nKgXMCeER+Ip8AwJ4sTr+ui6YqZjP/vv6uOpVw24Dav4Ny3WbNFI2DkPyGxSGumZXrzjC+LWGiOgkvTrNI6Gw3cbtahQJk0q13YPMn85YrHLo9+9a/5gjgDR4Ef3ED0B6oDL49PtjwwDWUu45+g2BASpgDXI01SGn+FzJmAdsFWGtvn9gFNBH62eZY182GS8+3kZINbqJ2aQttjEsfdbFnkoTdktzjN6DIFUC7B/8veDDD+DFf1ZH/R/4WReKpJSVBrOGIqvKMqVFBN6GWeyNLsLdzTXCAD+P06p28Q6gbrEawweTzJaqZzxLzqEW3L40q4ZOc0C/0inEZyq1iCxEtfN2+a/lKFo3aqS7V+q6gLquC4bT7NHLIcpPkAn1B/SDx1Uci/MvtoyYanc1yJwVx9h916qg14sV8inuxT3y4vywwAciSVDAS1+h/SrL+Qwu50BOLmso6BVIWimaTExbP9V8eLdIh8LmlcZLASN0qJoxqU9L0sh7pB8W2Y+/cfDGoi+BxDLkPSnFkBm1WvXPPbO0o3e/YZwd63S/wGNL7JLQ0d3Omi/PKYKPIO8N7j5Y5VnE0OAi7IO/wpDEuf08kQX6uBuuD3gtYMFPu2HPY3XPAsQTVbEFwLj6EEDqBxhalx9P3Utt9z6VIw5SGt2xa2uSS6S5nnzAWH9zYIuR9ILsMFq1bZawY8a/bOZllf+LZiRrX5ybFrCGMd/jVlmVFKmuO+l5dAhtGcBT+w3J6MkMzZghBN5y4LKEBDmgedfOA27bi4SH//ccFPEkq3kl5Zi8JxuCm22ufzijyOy048hNM0yQnq3zbRSPMByNyhNq4Nmw6j6M0pHx/cBueeQ+i6mP5LN2wP8dzAuGG3n2Bcnjq1WJjpjBeA2OWcEERZLf6aLH0qZWXEhvdCzbdDqMg4MHr1yVI00b2gSSjkzPMBOOvUzFBd/EcOnfcHtuOVmtnDNfLcRDU8v7z+qy1MhTDcllusVdlkLF/gZt3+LsxGT2nB/gnu/XWQA4gCjxFwr3w3wV9I1R7hh6MQnm92vtJewKoROL7A9RDfWP9kOEkthnPigcVm53qJsQn9vZ/Qj2q1J9K3S+3jQ4Hz6cxg+kXo3X9tuteQ2gRu3QVNleFYEE7QCMxazwTDvvXviBdqgGPdJeZf+owvgu5pk45LmnQnvUV69bg4c1+U/C/4AhOwPGy7oTi0LfB62D45FKZEWEMaizvmBG8cce93vUv6TvzJhYNb8WXTj87sZ++/5nj+R4MOEL7NFuYcza0IyPiItMdycWHz5oE0f42XRaC4ImKYPiaO11ai6EZuLlSCekJfXNyee5Rrg68apVhHhWq30IUt3EebJU4bPSgI3WU8+CTUvmAwWqx4IXeDhF+nNxChVtOOXwKFVoOBqkvfDLjcMxkDfY4ItvuC1r7+wUibyNdPH+FJ3V6QDcFnavDyghOROunRzst8/AoewMwNGLd3M+v3gpfNFi0Yz8kuwHLWuXjWUuOFW10kkdcO2orkuWltSqYrpmRx2u4ciFa2pHfrKX0bGjousS7pf+DxN45gCyrqaJ1L5DdFWM/2wL7YOALpYWd9ukAnTp/wFGhR4mjwpHaF7EsZczf7OsawkfwB1Dha/q5G9XodFR5KBMXUWh9u6Jd1UhBQ+uSfKg2Q+KMTKZCm3uKJfK1a+jxk2h15qEdxKh1aiu0N0Jlp8BszJ/YMtTc9KrshWcOWGvBWLspQg8lKM5WgbW5fytEm5SYr9fYkMYttqlBKWsQum7lC1sQOUQAqpVeKP9g0mrAdMbMNcdpa5/3YYEHCXLBWTsfYt6T9n53Q7kBORDLQcvOP/f1XI9AzN42HhEzyo4T9e+c9KH5b3VdTWyXGKjThtfQLu5ns6MaV7RhfKKg61Ylg5YjyXAWaYmTtPXOxK5yThPnT9emdXPoMZeauivVUfaE4wqtfjkfJ82aPtkNQPKmiLf8G/i+JKPc86UZGWs2p4w5K47ud98FCcShT8k5uJ8kdLUzm7wXDIAAS0IBP/TPL0r83Q0uNYs9cE8h1ddJKacf8Xa0Bgwlut8GyxXdS3HVrifknaN/IOaOSf4Ep9IZ4JvihfiGg18SOfPH4xcjL5nWWEX7nxWzzJwPINhfMXxpHadi/yXduOMkuZzX2iC8mRbeKQnqXJIuusEpE84i6ZlD+yE8xOrzw3L9SZQxfgLR+nGNHKvF8zRbSjivZ7qD7G3w0vkkfDskTcwtr7buLkOsJtOWXaRVVrMO6QyrgbQrgiTG34o8gx/aH9x/TCqzDxCMtDg1ZInhbfgI8GvljfUWgo07wvqc3zDask9SE+8i1GwaRz35JqpXDCq2xCietFc7M8qje2S01CSpvGMEK9WNtGpdjhXWM5GekeuQ1/Kou/EphV3+qqUkcMQg1LUAqItwQ/ITpV2fI6sILo2/O7p80uXGOlRPQlIVoQAiBso8P3dVRyOC1yxNgMoMUp0IryHmrHaMC3eFhrqyHMuv3k0woIT6tySegTdMbKnM/GbEllOGt+gR5J+kK3kamiUCBJGJidK1C1uKth+fcUhO3kwjWBAGzXB92OUJQDuF6CQ2/CLZFX6SYzSXOH/mh8L+kXr0/LxOj5zGZkVQtDd0ZdB/U/ACE0aeDJ/B/U9aIfzyn+rTqRsSzhZBlHcmlpVHAP99nxB/RFNKG/8j9CJOuQv2foV5ezZl+6yejQSsVyZq7Y/kImCiogxC0wVMiDDLyzZmalgZlg8VUhLIPSDUUORzswFg8UBSIjHMzvBdE1aCypyv5sd4ft5/CTmrtW/vNKptTTW0c1x0Ui7HJ6hr1/JDPITAdoV6KBtZn0FHguopTTzgLlJIhy6+fjvEcLRhG+QGqrpM7N2epDVK8F3GS1zUrK5RaEAwL7fveEkc+3Zw25WLLLqhSCsgA0/okYDilHaiuYjyIZDxTn6kJBxAZjXb473VjuSSX3QJ3/uVDvIpCMJt+nAhfGNIoMEWDZEKAAxRqQi4DaEhZ5bBBM51GonHvAwcT0rF+qwfM2gqTo9ffsvT+I6bmTGUjf90ptyjFK6Fj3Blp9nl87RJYhlniwPUDgogaLlaYCmmXX1yfCiPOqD3Zhs+bP7qXdnkd8rRmILI9PM+trN8Q+Wb4gIehXP07rIevjOa79qWjbqXGUI9mHFw4mD5MzvPZp5iJAXTIhQvvXPou8wrGT4jp1sCocKMaxe8vOCXiekSiazI93wDBdasJor6IrbweTaWO/HKBb2VBkGhTBYNeA9k/YqcMKPpFdGWka8dnYGYqTfNQMYHDHk3rcPEsK5Drt+3LotNZm1dcP68Oh49LTpONlcs7hA8kDUmSe1i/j2Wa4qPvbxpE51KoT3+qNOKYlKREj8aJqPALFzBkHiOvsIwh0Irl4IzXjRjd/SyjcAq/tLoFDNRv/kSkFE61Uu27LEmKtgJ4lBitPLLtbZE7FWfa9X4PrSmlJX5ntonBgV2lb1N5yavkjLse+sv/GcGgsmKB7a3LswIDpW3z+sdQA6DJ49vOpx5JtC20WEBwEkcnbpUvEKK+YijeqkinNVfRJtyr6LfQwOxrZQ5LgTCbFiPiAMXvjqanXLntJzvrYMYPfUQTIn75shO7DHL4smyb6H1cWKdUJwwyhB+8ymhkYIamb/2wCznerk6vQSH05WcOTviSSSmuYEMi19oZD7Ox4m1pgM5irCqk1cLL4W/svG7uakcdRvRBRWuPlMUiONE+796Uwa4zStm0SAIiOPYsuTyJNLHIENOuw8CbXzJt6eTqe4HSnqlL66u0j33E/U1KT9Jz+XSjCRIZhqlEKa62t0nJldcFUOusmJCS0aOp+QHqLHS3L2o+uvxZGeT7vCG17sm2LAe05v0roIj3pqLb17oBWtrTRrZFHPuvtGUgJ1KozUh3Rxl4gxlgyB/T6YXN1wkFZi4aVPv118Pqh2hvARk/ybvJfZv52/4ekP2Y+ClYGRPPH4PO3Ov0kxK4w06wsCXwQvLSFBunXrU4b6L5dDQxY7G21xFxE8CFzWmB6ABfc4hqd4oraWPvbsB1m3PmhSe5+PzE4DCB84myp0bftvKQqDH6Jk/MdcPJMMuM3uWJAmvned9X4jxF21A4vXzWKRd+qGNAumosdNpoC2ryR7OzRorQx9Neu1QcPQJym2II7txA6PSS6y8xQVYbTmAc0PJrPYZxW59AYjTyf5kovf2DorTF3hIrI65wJHrJbWYr/zUk7Bb+t9Wf/6jRV5mXZrHJwkhgDhv9KfkCj5oumibWolYT+XYZ52IwiAfp+7zbDPIFur/CKYKe0rDGRetpRwhyNNbranT0FG+8ehttLf9snOXIuFwWLW4jcBn28v0SUiuvHz+5ch2PZoiN9Z48glFpG9maGzmTkakeKVGXft7fblF69+umsYp//tFuKyMQBIpYq3SUUynsIP9kvm3ETcvrQj0OL8iwrEFpj7W4PrJOTcwqlk4PjJ0ihUY2j+1Ikd3F4V/RzO690jnXV1oEp3MabExK1VjpbQibz6mr5cWnC7b4VmFXavu8Q1B2wIivXWEVpzwaEdjToYvznJriN0Fz4YRSQPejTL1yLKvVpvWOc4yGhnNHc8FuIk2xmDCDoZuYzGZLgHG/QCRYQzzEaIXDfyAPO7Gy/kXAHuSg4TC3mZc6AcSiTqoueSK/xKgL884/2yFYMIJw4pAn9+d0/8L68TAbFPe3LOR9e/lIW5HUBlW3+8q9W2mUl5pF8wHdeTl9Ep2r1vv/+ioGltD1vQZ8XdXA+Rk4ONe641vAflY5OBg2/2Q++bKavHywCfR/Czk2+MDBlvvO8gzyMitJ9OrI+QhRj/GLi4dkNS4MfSU4bUdR+W26vO6qdmT25scUS+ks/FEZAR1P8lOU9qtDRd5Iq6Eb8PlEPWIcV9CHvOiUyfosi89GL9FxdvYE6OUK5eQdAbVWpbIaRwrACEPkCSVWGiHmUCyDfB4Q6duUlnRguoyOnDm21240/YpKvV5uqQHMYHslL54+pPV4vMFg6civBz9MhJUSxanbaXR5JH3U80rHTxTMyQpv1ThXuAAifYSBNzuNZol68UoK/VMnMC6h+ZKJBwKF8YbZCW1P0h17UEdyxrGCR5QAp5ZsP1D48bo8zdK2O7aZr0VDQcTBoEtSp/XttwuK3S3W3n4d8qe83wWmcC4b0w5Dvb7oAIACPnvCzWnEViMAHqhNIQx6z4jhyyHIICK+XIpGcTm46hg/L7gOaq9v3gX0GgzIm5GkXtEVneEtMpwdF9zGON5dEZjzhrT8b0QjhUmq++bwMLB7rkjQpU049nhk4PI5okAUR0LhBLNVcKSUO+GI/GYkQz2hHivQorfPT1F+ImQWHAlO9hqLnyc4wU+HbXrtjD4xvYTcDp+hScbXi5D6fsL1wvoTss7YHsKvlUfNi84sl7xYIt0T5dP6D5XRIC4BsZ2L2DIwY8ASul/dp+qbRgEMRjThVPRQqby9M/ULii0bXmsbJ6oRaF8MExnXMinbGNyL+IwqpT2+ZpNblnyqTKjUL5tmtf0c718BGQk4n3awgYc1OlyaMFjjOwcLvM4WqX1clIYjcJNOdoXk/ikQfFGioxUlCVI2rw5nc1z9GzWmLNkXEX5Vqq4+ffmHLyVHvyuzWqBBgwvb6kY223z7SanzquoAc/JF/IWezS7Zvdzuo2VGf27mgPiDTOZM2hdi7rSGH2eMa/2PQxgj+Jb8LRz6Igg60zopQtzH1NBjNtB+C7VGf0x5Rfm/wRxhJhqxHRhFlsEm171HtmiTDiG1ifLNrADebT5DA6z9kWqsR1S94x+p1IhBsN2Gdfh0OXfCEjyojah3XNkbdUL1BuN62vH+Vi7AGnue8ehLa4DfQo6N/y4s47qq+S1SvN29WS9/maHA2qRKghRbGxcUY1trzpUJYhvRjkYCDW8Q48kQ5F+k6cUKe9LHDwEUaVPxIPRhK+Gizjl33l3TRF8mCwCczVlcvj1+PHXH8eTgqmVLbRy8Y7wIJTetm9COUOlpgJw3twz7HDfImXBvtC/MS9hyUGVmF5Uxg5pg6Psg3iTC0bBF6cQK/JCTExgMcjtxCNKdLV8EQyzm66e+MnfmBGFFRxC+UyQcsHdMtIGzr5opsaNPKtC2No5/VlFU+jzgzCuztEGHBrKsPRdLggO+chT9PYJOFyGcquakx8CsxVwzuO0R0RJBFD2DdHOW7/rBrnm3ZL/QF87Cg3NUl8GtdKPZZv2OwgYoSMosQbCZXgds2YVuqLQZRWu5asivHarjHCU8hldeEciJieXzFQmU175uOMbpj0s9rVbjWJWG94DqyshdKsvnVXXmzYl2AopdpTr6t0YIVUhW4+xov1FVbtszGTlWxjabtkRsSOff4QVBph5WogXC/xFzztj1aSlP1c6H7zqRf1dUtiO/Nwao2ynRUCNTF/4Ce5ePKniHKJXC9444MVMcj0MDigVy71CAdpWBNLKe8W7G2AdLwnj6wEE/PClPMjbgl5dc/TEZLxayfhIOUAYOuSnATcNQBJ/7Yz176DYHClydgwUHsfVws7Iu+nog7SFk+PLjC+CaF5HtZ66RAyPg3aNXOaahqut8tOwPTwLtJ13wYs8BY+IK/YhX5TmmuPiUPVGragaon7zcc9rv7p1ShcGFSRqkoPU9i0mkmWKkLHwSK4OiWGbDzciPLJQ3kiYoU1KQ2vZDTrs7wsQeYpdDxKtUYjt2G0x+1xlW2b6m94qyREyTLCIuoTuEn0XxTeuc+KNkgjzA7c6LJG++67H19THdnymwdZ0WJoeiujBhV8hNvf/YibD0SzZZM1fVDpiA3Q0klY1+2hLkv5DvOGzF2A2qO7446QC3+QwWX2RFeo/CCkc1mweknMEL3fMRz06l58oFBb0jXnF3ng5lsJ9Vs8p5N9pHjhsKp99EBl9TtfPivn+/IuydhEYO5vw8H5oucna1aoyrViDbQbzdfEOkrPVxXyjd2Kba6YQm8cwrjIGyhZAPWVJbEt4r+Xu299EcPxAGaKcarALN6U5cG6k0ZFylN8rHNf+XzJ5iIWlFgcNo72qbyvO3JCESp5PT0v47H6leC+JbD2qe+wBk0cBIgAvsYSeB0psBwr6Em4fZy950Opb7vRvAqRdS+F/Ptqi/zk0K1EpYdCO5DHJ8xaHMWgOD5SM9K4JSkbcXGRTwOyj/1Y+lnDCRrGs/4GhP+WJslQdHr3W4oLk1g0rzWrak3eJq2ziOMmfz6k12mwsPOmkh/nU2Lnamtf6AjtqpRjCIrBiyfwsmA9gw61h9IO1hfGFLRPPaBnMVMGS6kGvySrF0pvwe/xoKKj+mnS8xukNtis1AD9s7oUR9TlaR6H7v+hB6NplI/p6ZJI1oQRY44ZT0VEFpi2t/LWyyfI7DQ3fHDpzD/03mesuTOPVzYW6m12mfafwAXCLh8XSPyeebSc5lxYO2KC+bJWMRRe04Mbzbp7P4WK4LGVbW/fKqKAORp+h8YENhqJlTnCLXNc+n9BBiH0LLkkVnS3GcfFJEfTU4levm8irRm1++iWM1jq6b1CcMJuFdJzzxpf0xSpRMjKxzDNDWIrYS6bvh6A7vdStMsd5v9iKFZNXaXLCchrMRUWYF4M43U4O1qXogQR/KYk27dse5JHX6Ea6LbAZFNkKyNGlU/COrFngOHknDq4HqlOBzYXLgIKCv1509ePfoxHQVzh5csjjfH2us9AGYFsv4S7uHa+z5HslRVxcww4MLKMFecMxgjQDUWj60vZ64yH7RJkpcGuwly/nPYLm49ibsJ1GYxCmpZv9xP0EDOb8A3E2YDVPVo5UKAr84tZZ5gxXaB3vAprVnsOPJzdj/I8WqxJudojd/IZ5YisJz3YHJc3b79S+mXM4i9uaiHdkFMS1loALDcKaJCvV7URfrT1c0wQu97HdHXTmGVLRqjEY0lCK3EC0FAs0KDrP94YtcqCTH1LNqBVovx+AjCvbmUfyq/L7XeGpLicytNm/evzd+oAD2CvKWCpPTKuD63ry38iMV/TnK9RFwGSkzDjtole2ue/6tBr85CWZG1pvjG9Q+B+gHprHC0ap37Rm731pmTHrFBO1zNC1Cyh2hMTJMaljA24cVh1I88qaMmxFryDlIk1KCW21kKz8EMdFrAZuFtSEV4IQN8Tw5TmlbwAdcuOEjRISPcpWkX+T6JFxF3DJJ1qYHNMgKtKmOCO+Cdx6QfrMsxv34NxVVQKj/AzKvO+3cbbCLBXenojMGkWTrCPO/4JqhrRAHhq49FsJGYnytEhfqUpfJa8LOi/RptrkPwowejtdg4gOv3xn/Vv9HRFPxw8FDSTNWRaHmACOWlA6HASS8ykysk+4VeQu8+P5xiKAk6QAaf+wMQctANn0lTaBDD4SCTBqTi3ehB18L+Ki8Q/9vTo90VVYvvwMQSPQE6pHO4w1CmTsiwsP6mPcaajRqeOQvzKaRCrwe14ZYEYiPYPpcMBrmbwxVf9QKBTFN/6N0YzneVaLOd2LP2Fdw+GI8XXgCdahPaUegjx85P4cAnlSHC6RiOzYmNsJ/oEjuNG8D5hA1SVISsupjVvumUK5Q2zWKh63Uv6/Af+KCwsoX4GVWofGfrE9TueE1d7ivmkz0Pl/B9FxowBOhbNQiM6aryMB9uHDJB2aqIfJXJAdTTUbarqHkReLbbKlwT5+lrD2twg9v2OKcI8OR4KCDKMnqYeMpnklIl++nAXMpcHhYay9iUfucD0D140XSmQ9mBG10j/jLngi7j9D+tic3z2fBY3HgBx5iYMok14cf1qlol8NC5x1JtrD3wg4fBuGCXIiteJEq94aAPETDgfWM8qqcDCrv2c5qscDwKam2TzXZ+XstnK9g7Ttpqghf7elXuWZv0nV0xZQhxSrrQMgCgKrMsFynYj3k9uwnZE3icqt+w9//rPFDYeelJxIHtCqJqCJV+X+Q8P9RM911fMa2SRekhjGoOQCaAxVjgPB7+lBIic0hVgiMDUP0m6cu72uUcTV8rn5ottCk8DSpZYxH2forTc5iBnYXI6pSgqh4A+2pDsGm5iufoRllYmE0guvir/xlGZNH/Ju/RvZRtJ0mmLS2LGxABgzi4GYENEfS/K1fkewkWJoIOdByNsPNWada9HYNr5mGj0cfmqUrmnogidyAVsys4oOIlYNhfm+Ma2eNeCMOUSH638l0U+GkUegA6qOeLJ93mTo8/HWJ2HA6wJIqpiUeS2Gza+HVle/OKD45PE8llRWijEBQRnW8k2C3lrU5Kd9LtIInSGmSphSgYuD3J5ilYSppgdZj4gvAvvYhIPfnWRzztBL5USDFNSGtxtGVQUMFSnmOY392/xYRlzPSsqYhbqX2qZOXxsy9SHyQbcTApNqAfAE24tSqM/fUa28Tkr9pXsgyBx/qK2ubumjWvz5gleTqRnOTuGwVil6NRFRPlkGxdfeO5n7yJQ9RJGlPM9nST/J6rQdssLH2eoHoAPP4V+cHfi1b257YLwNxg1Q2+lZWQO6Fo8We2xW54y+N4zkSWXRSCp42i0U/bDJpse7Ukp9wb5ep1fNgzFZ6EG1C5E+RYrFOanUBydUfO4Bb31eDxKGmQ6gld0YINwX8PVKk3xXOHPJEqOydHwnuJ0ojgQNSI5UIc8xzMKZjqdikWrLzrFMvEC8Ms9W/PyCqesoyleRbLX9zo0UoJdnb5j2EB+QBgCdTFuXJsew5kg84+mTTp+bz+xaqgaOFP1tEOJbzG66U9ds4cDW+qQr0pkK9hYcHGf/PbWmBaB5CySLXVHOsc0ZOrESFrKFW+E4d9NUt1r4biMSyIMb0pdBondT4+11g/vBK/CLmmAWC9qwKxP1DOet6N+QTtUQw2LN20Sbyl8mvwpfee2SsmzzjHXKJ5RF6oxdSCw5rsxiP/LS7xYWtlbb/k79AahBMJ6CmQJu+ZZcwwJiXeTWy9tdeWZJq0ysDNp9Fq4o4IxC1n53gns2nOXM+P2xb8ZH+BsWSH1/gK/ZoAXaU9LRqRlOo7AGSvrvYur47H19csw9k4Z7BjzFBByd2iUH89QD7a/h0vtd/Gi/HJxqMa7Mpuj/pb+dcNPCEWcohcGDNtozMBUuYHHZBvSMZeEq701HZgIo9T/mNfpvhL88xvonzCnSiUdZ07syFUIYUgCfc+8ErUfHwmbjUsVJ4ajBAFmguMuoGzyf05/lDunidwKuwNaebJEBiQ7p2hNIrjfsIQEdlLhKKPO7ugcnaaTOnItBgRj+IJReqQGJGViE+GAUdp3BOIIcL6uQQEdWExZT6A2uBwXXT7YtpoYI2XsajU2kMwrsuX8li01PkPpwt2o4nL+U6fN33cgVSYMUkiYVwYTpUdJLeb1557ExlAajUDpiWu47Dwk1/5jfDp/lSuAJD+vsxA6k5bnoRVEk+scnbHlXo7PxpTAtdP39BOZmuiL1oZiKSZpjmcWPlCoHZ22JDB+BnJKiOzUJvXkAeyrKAgka+aeHNYec8pQS6weoWKUYBlT/nhQPW3qh5X3nYi+7hPgI/kTnnxkd+J4hek0orb1/lzsEq3HxY8IZBuq5t6qgM2UrVLUicVj+dn+DW8QdLqNgNfwOiVKRRJqIw3CSykL8hDy6PfpbtB6KN18SD28i2r9DpsEbU9qnEzeRXheTSaI0+MKp2wj+zr4+ODQkn4M3fF/PjLQuz19W5jNcwVzn858JPuo3V6sVXtKhL/S05pERjA8ikAWuvVNgYlauPOCcdk+6QBsSWMoBJWyuYJP3T6JgzWUhLJLD3A6YvyJPAANNkyHw9GlDVf1UZn7M3xYJOdMYAC4yF4dSecdoTV9RQk64RGJ94CroC0JXR7oAr0kDtyVY+2AGZ+sWnOPq2m/7lqRo/h+GbDkBeo8ZiG23UhpDsmnU0KuVk4ijdS301HsPbpCScimFtV0rkYJdIzmf7n3SU7acNLFqFgZqo2pz1Fbs/91+oztXobIK92zi3DavY7YlgVKiIhsO7MSFe73LONEjBnl0eZfli4CFcWEoCedxoTYEiT3nDPoRJ6Av8/I8PDxLlNIXkMGdGrJH/UXHJ1jVnz3++8jbcwlvIG+ej2rWKf4sp5nTjGXLeKofhdRuh4b9Ws2tAgVWxHiGc9bMp4Xy+QFJ3tp089hEgEF9TT1N0nQad4VfS98U9Hz93cjKLlE6IXdjtKkVh6ZTm7aNQvAdmhJ3Zb5YGHaIGXFXV43litT73jnsoAVRQIBO4DBq2x0/9pGIDodTvmNKtXPXAC7aVFMXqW/MfKSaJPdJHA2gAE+pU7J6Y4r5cIEPbWPS7xLvBhHpH6YFVm2PLX02OsRJyr1VcWh3jjkg3iFdOJnI4HH6aUZjkyo+pAs1xZ2Kj8YMqR8e6gps31BV/UIh92UwVZ8SLWcdOCX5GITYufYKTNLSx6bfCJ038hrhiLf+eAFoYSkxhfTKlRAtpFZV/d1W482KNmRsvxqBlm3UCu0ZaEFJQZcdCxki+iygxejTniuvMV4x84Axce6pxBtuf5SqJvJxlJO4SFFWAw6fsB60iA7QrUfLngLn2wfWUI19RmJt0TsO0MLWbVbfhbxm2e4/5V7t+2NMfRQrN+HIYAtXEeFYa/JHdi/0gztYPTzc+Fy+T7xbksrDEuo4UjP13tqxiPxEW4K24Dsa6Ki9BMZNo8gjxzaOBtrhPjcYh5O3XHzmmyY5d0QVJ7O1ySjP7BJW/9PohwJTlTIxGLT8l4Vq7k7DZiuxtEqT9AMT38v+W8oF0w+7dmU2Sf++jJVNZrId62PqBwcn1qtBVJvGXrVr7hfFjKTf6FTvfTHqtpLd7XKWsZfwJHQZAxJ7cFy2PnYeEnBWPREma/yh4w+/12XyH+6U7zFLreyCYvdt59pCXMfBSqognX3sQaDqkcN0r9cUKO285ub839y7q8teB6JtkJtb6nSdsVCBF7+Qsc0HP5PyR7SInLMp8kVPvtpE95nHbnYXMjy4BJLt4eTLLcNwroj2+x2vq43FSykKvPk1/92+tO7nM2yLcP6U1cZzRzgKGJO6lcVdp1RkZ0HzI9G7l+daGMmfTQrrUHndiNa1vRuQ4q9eTK04yR5aDRFpxEJRlMelblYHsivTK61kqL4i6qdIT6iJvgqvwJjmC0Zh2KsGM2QBzxdpvc08sNkUyPi7iL4ckcrVKywUIAyIWTlXQjCLn6H3z9Pm8/zTtuU9EmqOJDrW2rpMx4OhlG2ECtEdU7bgpXXC5KwnHFqJqoDJLx9CBWx8dcBV7IGtKhCMfCl/u1zNlNWtHVrSollJbxchSSFjak9/W7sZ0ei6klJxEacNL8NVbCVIKyijW5TezDXd8B7DXh6TEuj0fwz1mrKpTMWKeaqzcNoO3GuULv0zGdbap1/S7KPHKA6KAqhvX9pQyNbZsz9R5mCKFM+mxBIlcQDW7E3eput9UfA7BN3MA6PQvlA5Nn9ynFBSh9M3nEmGpLUneb7dgg0j5c/8zt2EIwcXl9tZwn7nnW2ZUFBonthbBONoQ2dYSwdmoj/LXYobD9qv0xszKBKve3j3cJf1/GhE9o+Y3OY6KryCkKpCZypP/m5fiK4mz2c/kNDNK2iwd4OUT0GljCsk+o4m3eVBug1+7jGI+NLpxL3H5P3xkuYJkVOjVbvrjwfvisZ0Eg8nhg4/EAXboXGCSgTpEuBH39fle18k/r+HCaZJapzJIKJ/MxubJaBzte4GhOYrJAjaaUqWZPrQWgfJeXSp2yHkKkkhHHNgUmLN18X+26E4PlA6SrUVwbNVbKjzvsEeWiroAdFkv4DWQ18D7pwDXj5LIAZRED1v7w2kXkew6qWtc71gcNyjvF8qM82G3b1D0UP4Gn267JrYSqH4kG7Qz4CXRGv7PpLzyNw+WNYDvhhgwRa+lLF4NOqu/CP9VZp+jC4dFbdwX9eq0CoaK6/Qe8H2YQgt0H+IvywbNd5jTvX3Gc4JlRDhgkkIygNOMzmOnOOG5kdt9rjXzvQFsWLN8i3wab6S7skrau4Z53bxJTCKoWSQG8wLP/TEkgmr8qGo4uXXXJbnCsmqhnEseB/PFNw/IEIG2dChd4Pia3cS09CM84Oaqj96Hw2qmfBpw0dFs8+DIGDaqUy/QeXYQCMwlySaXhTLu2BlXCZFloOZ/5ur6l4N1DhEkuguofFl/veRLXJ7RP/UUA7HQkmxNAkKiF5qESQCOCvqFm4EhqLCnBqjy33n4cPkObKPENc+zB9r9FGABn0JooAxUG98Y2wl7BZoXz+o7rE4mrlAnjDO/BtH9ttwCm1WVqMCeVlx2osfy/NgX9gdmghPITTRyiuv7Lm95sspshUmRcB/mkQMUxskkutdk1E7OGGJE434l7yYD62+X85nlnyvMhgCCXveTgsHElFY/bJyrn7VH3BiTLqrvEtfEtFcw1Qvv5jCkPCDvY0ui0HB34sYyswZrCrjFsLnCfsDtUfL8zmZzl7TkdasAPH04HXy4ueRGaJVf8TCdUfCWadmcqs4C2F4JJo3MoEJR3wKjDhhTrcFy1M6By5yrI2aA/3gczrb798MOkKUQXzUMAnQU2Cm1W0Z36FeDDmsUdn+JWP4+zHBvdnNr0q/tJk5QseUy4cBl8ek2GhsjuWsBPc3y3Onmj57+LUuq+aZQVvHpOJvabanRNTZp5/nwUTuCJHgOdEo60zxJn1Q8Ms9wLxtWmpv74iAAx56N8tfm91swIPMphOqIuSpFUTvTnt7SBK6WNLjf7Ew21EdaUdJCAw/GM3q8i6arg5UaZ/syuGnsyY+EtgYrcVUazdmnocGLMhc8JzXygs+veqilTpurL8nrPMfTKtGFXDc+Be6n6vrKCzwUECk/QDlm7zXeTV6C5imjnB1qerJKj/J9uSfcbpIvfZWrU4NT49cAGVqBzR/UKEBINYHJtnf+whIKtyStBQYuMszeSt55VXU/2UzWoqJdKYuxpGKTU+ydHV38M7mMmKVyorrSDcg0PtqozctcBqCgLbQHpBsvBwuiwf61O/kg8LzFviD/ruM3khJIK+nkNZzwoPNApSW0m8PtpG5UKk+cPQhjiPAbdfIbqlsSJB6rJmnrCLYz82U6AYFb2/Dtd4zHrcFepkmlrPiblwrlBCLHy2xSH5rS1NrjjM1wazocmCpvahj7bqmKhCGb9m5c1V0PgVdDYyiyWfwE4/lFh1Z649riDR+JcD6rDrd/4ZUT7j6E8Tx8ydwCMYFu48ku/PAYbolzGQ64gjq5Cx0thdjCkYLN1q946/NFwNIx9d3mpsyzKIQWKg02OshRU47+HyujFF9/SGROHBEIOL8aeG3PkRcmCnepFmSQ6JcghTkpZBP69acrEFP/jkxHgqt4b+OpliHwZxA0EldoPgWlQ3aW0IB9cftEgpjQSIA7r7SZXRcJ1n+SFK4+CJ4C9640JSqwpUCaPMiG8u03ZuxZfU61bNgkHQe75Cqi+IcawamUmXsAykUI+7Q/1TIODTgH64SVP6C/dg3YR1eU/HWefQRT3+y9bZa1CmJ53phNmLRk9ChY1kpZiCoKrM/VBfkJlA5Z/pIV4/7t6z/64jexgE+l1uV88v7n0clr8rX+78dLMSe9Xm8tlN/NYnaIfPH9SV1xqtOUWUYAUYX4T+yw2MYYFPN8Y/nZH3y5ExaCRmkA6acgKL1atdBGd9m0TGxnzJhjVybefb4veCXtIezImYgxQCrEDukD3Io7ANEeNBsmPJU66UOEei6A0LdvCDMNbpYZ0uwOc02lZI6plk+YyzC7V1RP5Sb0WmveMfVPZoiGHoeD4Y/0Q0xgKB5YfTmx6SSJc29CpCswj8nyeCu4GT745eMi4r2SulsuHVMiWCGQo6cisyPoJdl6WVJVIbbxrvKP/iHfIfQMfqeHJb69cxIeLLqz4uxVLpIw3oOTRFnFWIyhxJS/hzBShX+M7qdLDLMLWJsbaubHT283OL7xbZuSzvdRhETAB2w9BiaK/1qIXf8R1nD/YbznZOKHkFDLjwrrH/5EQisAWH27G4f6OhqxyRWQuPDlaxhLDWBH58jcYazMUgXnQ9YnJX/LkBBdKNRTfUVbD2ikouyjl08khpWJhDQa4fWPQpLDAPeZeg3pj4fKohD4GEnkikGsShNy/CmVxSC7wtVmXLl6ezeQh4AmE+uJXH8YyaFVFBcn3u1l8bdvx+jTeJmNraVvJtKNZf9Kl8EkZT/9oOS1bCY6QtZM7ML5jVipeH7YmBfwfgQ9z3yMGJebofg+3n+MLN87H1rTN1FAPv5ygMnxydkQWrDAkfLyk3Hos3VjstVu+pK7Bb/gmizgJ3sHEZS2rMM/TbVTQQWxofeuqVRLBdExd1TvWrrs12c0qcUFHrMY0Xrk1rlJtLev0xgi4+nJiLOnR+XsXRr8BPAa3eQo+xtHsdn39zFnF6h/xql/z0bVccjZm4zMUQ00paBTz7PZS8jZqQRmdzeKBFYgd9xyPuNuaPCGrSKNFNzVoJ2bvhrfv+YdPawizamSQT0hbIWoHeTLx/C41lRaqoVJ6f+SxRA96UMAQ07uvRzrMCz3MQkPrWxtwX+H10juXmRXFb8W1CwzFIoNtO4IQkz9P2sYkhGEG0WMdxWCa7A1CIN0aidrhOiPZ4e8Uq7jzntF5XvBvCA43Ymdx8Hj3o/Y9uVxZnpgVnabl6Us10z8d3sEKZf66ik/dXumvnUtu1Z1JzDIJ+KXlOU3QABmFS3LXEZRmjgc2CU/JwQgBLtmMyIlQbDmQXvketBbDB0sEZnOPHz2H5kkzjD9RAdpLNgeiRpfx192MMUiP/t+/WH5o1CsASnvqNJEWr8GKjNLPYdvh5zOcDACLhHc1eYF+bjVPv1DGsEs+qqFUulWSUAQym7dJTiw6FWUSUbzMyPH3T0rKQJTFTKQ3eZQRtGufNw3O6QTQ2AABDTWqPE0rUsrTFZrGIuP6czfiSxGYnY6CONK5aLWnlAN6C5GilU8YL17+dHnJJJTz6jUuXC237wruOrQ8mbnJlCBPnl/qav8/DS+lwQftDtz/zFw1x+cERsgV22knfos0xwHUuu1OY1EW+YgY6m3vY46bqXiOIyiNWN3ToGBOnONcXfnEtAlilYAdphhgU94yediXc8VTXWi4BSUwXErOfCXrEXh0w2E98EFKT3ew145BuwP4x0cACX4bzztvkle3cg4CeQkowkWNPAuSW+urVbrdgD/8QKFsqi5oqRA+P/xJe/z8a3dDKvqxu9J552NqOdhUKuWETYBMzcLJzO6rOLJoO9NxqHQketNnJuhVGF8jAXjXM0aERYHoLmjMuXG+EZsQOIxP/mgrYrRxfaYi+kw3RSfeqHeKBBy7pUTWASlMuXZ2SN7KSuCBeXwW/KNShKd/H44yKJfPBmbrQbPWu4WRfEAWQ8aa2FYGmnE/QR0M+TZ5EK8PSNCYbcj6Mf2nRO5L1W2XRbTlXrrPARI/KBKkmgTi9IR4436/A1SyZB1TZymO3O5/sXRVMEICL74KBPED445C5j4M6wABF/n9b8P9K/9IeOJLX4mCEp6b8EQmJ6SUDGM9jp+0/R+nQZDr0+KYWHH3Dnp3/hYkq1EFku9MTarB0dlkV+5asqFCjj9zX+fd9L+C89JA8B2d92ae7uFJnQV6AUbMmRZMhB82nwdez7j5ER7xGat9s8jJY8O81zzXYOZ4ccpTLMg4y1VCa4Qnb6IkBXP6UgR+zM1F6aiet1F8MI2eI+1184062RiSPOAD2jhNJ27ZXvIBc/+TZQulzOG9VS3Vz8Jhi4OWy23OuZrYm3tTvICZF3gkR8VBp9RdYb1AmTSC5NZURrWB7WdIvnUxix2R3lY0ay3MYdZswXL4wTGNmiHyzbphALJHLtOTzSJbzXXfs+oOWvwhZ8+4ZnI4wxUxI6yYwk4vm6+c7WT/j9lL9HKaPz/maw+U2/lN2BbLfqOLt7Bwd0OkEIqHPkk/u915xsfgWc3nctF8huspGN7pakMl+sqpFYadytvIgV7UvlRXfKAy5OWa35sxE4sCxoPo6VGiLYL9GIh/9eueI/AEUPzWaclQ47U9/Pc/86EEgq5GaXc9LdQJO88epXu6+JkrxIBfhyRr1eG4Nrbp6ZeKiCxzpFP8lir+7oXRupRkIz30bj3cBMf2oT44Z/j5lODTPfmqCAAQ9ym+UGqzQOfdS1536oryrBdcQR4UJBvbNFo1AeLtcCPBEUpZ9lTNmFhIGMjQFPu5R7HAMDN8Pa15ttAOoEip6diZGy77bfydurdHQHkNkRsx9npeSytjjVckgXuRQAJCbv15HbTA4jnOJOoIdWsUtVN3Zf0/O2vt6fMGXIWjiiccfTs7rZY53ag+BK2FOimPnDsN5z8ukbPtkXJfCCvEjRj68A4QajcAkDo6VfvnvK3RnIz73ju3eyhJ+zm1fHJ+5g1QSPdlYAgMXhMk9QAy02A9ROzbYAkH7gQIUHa1wMYjqRiIctHq71G6Zd/9D8J0UXBqFmDZW1u/OPXWAz/yM+sR5XQ1Dg+qCc7JJLYqpe1wEXjVRYGT5HUBIWIcTblrJeO5vftAzfAnkYwrJZHgZ4Atlttcwp7n2Pn1o7O/zMcLfSTtPCU8LHfa87vdpO+5R8cnreYOITwY4gZKifqNC6bIj5pHAQuLEQyaOjf/AZ/r2MsJlBVX1Ae94QWmDwbVlJeH0m5yokEXkzmlza01hH+7b82AFw1HXr98TfZuPQr3kE6HZRX6CaeKDWfPO9R1hGsqZXEB/7X2aogeqcsqFrdtF0JlfCgkDhTYidVMDQlDpAZohq/ggc6dYUzNwCxmcnmlM33zZ8gyNgm7PQqhkqMec/P2YUjFBRzQT/deHmmZGGsyq65FKmbNkYbxU5KW2ShcAuZUJ4HeYZ5ydUFzZO0fIx5VFJ6jklE2z4p4EJLidnrjlZ+BZtQkbtC8LnjDis3Pq+xNPanC+/G724bORVqSkFZq4E7TQJeFJIxIhiI1o412W3+tw5SY6jE0uq1B2RoZ13CyNHfO9Cw0QX6ks58DTYsW1pU6bTg+ZNvJ4af7/KFhu+mxO62VdCt2yoXiI3STvR7k+/iKxMFd5UJscy7Kpsc6OcF7O0IYHqKEzzLATwU0vFg8n9BYMWhjtv/NK9otwkvrckLMOZN8Kvpzx7ywJsoxM+R4dt2CJIktz+bIDLTYGVlRXLfUJ4UoqaNtpGQuoKzT2NTjTjDo0pjWQGFV9ES0YC8Mph+8+MoW+65kKMJOTHVGaR61FcedYTgQs5Oulwn22DZD89K/sTdkPB9iOTyANLuygLLsOR1IiQ8QG6KRn3JKz4eB5DxSIgNyfYFu+Ece8Bj2px1oSovUV2p8hFJZTqvHfvEpDc5hBGasQPCTzkwo8+Qd2eF5LzVzbuXiUHpPgxQcjqFme+q8rpqot1C6g4n++DdDcWpjZVHocXiI2DTiaXQjjdiV+3xNB/qDS47LcBoxUIr25xpwVe2EHIfzrlS5aFaimKoMGW0D3zDVbYP6mR9SJLbuKnHHGcJeRNCqBefH9jpps49jKnIwxUqJ0jOhLj0SRrA6W7ni5utCi+6PlBF3omo0lYJ3xYeFpxBtKyO25KiS6GYKyx2Ipo+64SLJFZUqTr96ut472HHU1BPdNQEGIaXMWoABfacWOfuNaYdRw8WRMysQOf/p/W4GFX5NUXuaFm+Nb7FpD4W2bkVTN5SJorn4R0RI6Qg4uS0dKUoCNBnXRMZihpqwo1gQqXQqmLPRuMqIN6FGJqGObZh9s/3qW5MYDDyvYkl/Q1UnpiXASO3asUyU6yxms1V1Wt+dvBG1629vSZmTDDUIyjF7kTSeeCnjkd38o/NOXn47YHIR+oNDGiFHKFrBfVMLW9j77Qa+jKojX6pbDMlbbAkHOsqGHtVBLd+KqEJq9gpAIl3TSfuMx7AU2iS5cAJyV0U4b7mYLSiOCNBDFVaDu+w3C43elYywmeOJkB/HMuibN3cJroIMea32kFETlOlETUpEjXGtIKzF31zhZdlmTV0KYOq1D1r88COYZJ1QkIvvq8u7B7AMb8tZQm8jWW1J2puEkvM8Uppb+RzKZedFd7GcxMRvmkKJ52sh6YPkv1ujzW2uve8XTVIxr5YRkavL96/n9qlyld1a1yKpX2Ih6Tqb7bXXDfkiRtbWHeODm9DI1g+FaTRA6iPPQU168Bxer43mEq+FZxMncgMdgS6Pn9sAyKL0ikc7InkOSJVR8hx/yW/I4cYXLT/x2pJ9F1t49zjOri2fM9bjFLwyYj4w7etpR7YRvf0wSZOvfoqMBU43W0cmzlgt5+f13nh6SV+dVkC4b59JTG4S0bHdIX2s42cS8IG2Iko1E5jp2dWtlofTavkcl3R3DwwiFxn2PcAvsiGG+u64ASThgBg0VW67M6udnPkZ3Sl5c1NnAmmat3n34kAXN0dv50mW8VQox/dViGbOK/B+hjsJliQQ3Zn8mgHwaZd42t71hQRz8OM6cOTar6d1MjNXtKpCBhtbfhLhfdl4OpyZylLLNR1F8EcmCLSiDmNyYoIvBwGCqSFBIjGq/MMqEGiKwcjbpAuFpRt7yr/7ZBJFhqx2Qwa4QnVxqIXdMHJrW+FTuP5Ef289x8O5d+eYFLs5m8IfS4NJEgv1YyrsC11ih2oytD7Ks3FJ/RAdRgvvNjqqElZ46u0yvdsYh/9jZ7Qk0rTbMQxNbVl+EQgc3C5Fl/KNDZZ5JeunQfXK7ZCUaz1OLblQ+W/tCp4hGbDmizO3YaEDPF1YFyVFHAuqqHt9TsPUXq4zOAVRKFuCQ/3MManpyNA7QK3KeM89d7OCFz6vppOVNqx6lpuyEaQiN2k5zDNx/M3IYCxwdSG5hCHbyR35eCQFsalB5GLjCfxNxALTQfdFZ4gj20w7nM5sKBOhN4KGTrPQKyzcxCRSY9nJS/6Z545aqJ/bgYmD1xuUaSxWX+tVwRe/A8rhNSZFFSEvw5MYh6JMPiQMOC76vyEuhkkQg9ykzTdFDy0UIMk1ulyexS/zR5dlAQxk76/a2U8MvWlu+E87SiiIMmzLBjKo4PWkcP+Mslmj8HuxsnxKAMkSODJYLFG/1z4kglNxqjQBBpnVyxQ2A+8EpBvja/EGV0Zn8lL3yMh4eXMKEYrgJjXt7d2G9W43cu42DZeLjQsV/4Ohi6K2tlgcYDuzCWcdQSX28rn/aKaeGJsHBXJQvsD01qvpKSDbFbdOjxKOAMnDfJ1vEgNVbfDF13noScW7Il9jhuTfiNI3975dVMqI7syrvwMQk5TPMsFJUhWKfueWn+UUhbOEmYMn3fGohGT29IRDWcTq/6LEMaRPRl3hBv1Oitz5f3arisLMHaHJ5rbwjAicjFmVKp8Xdid4CQcS3ka2KWy7qKzvwW4lsDs6yoZU0QnRAvpyGJUwrMdQBy9zHwK4S7JP3jPol81gXPNFyThXunIYp4lbGD6g2yg+Ijk/AnBE2r1IL1+rCqi+YYF/atXiLDioVH78hCFUJ65oO2i3895FAdPV2WHD08u2ivNySCUsypdyzOv0jUEdRrRN2XYDTO5rzMP4SzUxs2ww9rH1ly7WMcNxKzCD+b9ACO9ShIdDIgnBOhYrStivs+XfDUXgODy11yWEon8+advxUsF/eUo5AVsPeufCR+8tu1Y234oi4BXcpobacpfEUdiRq3PGRGClQ6XC25T5r7NVoG4wLhZaTWjVRz1cZ7+pPfXWW75WCl7JLe/08d1t3WwrI5d7XPXPMk400YTXo26hFhci4VTIcbzQDHskvOg/2YrQg+OLq8SojbvLyBiez99uXh/blXj3idX5IEg4OmTHBqV4O2KUA12UQ3kcRd2P4lBzc7EHCMUYGDDajm7IuqEO3e39Lu2YNFM27i5Whl3mTIw8XweZfG0tVRaUOUDrh0QQ5pmWuk3ADqjfsOknZYAh8y4OqUCcBraCcxSdPdEIVJZvuzTB61Xu/KDsZzAAYF/HskmT2VWr4pc1RQuhNHJw64ZpR/f4+Q8J/L3FjJyv1dQ6AanhLFiZNKW3H3Bei/O1BvpfwVuC5nCQg7KEqU8dO97E/8I9wuwSBmKQdJElXcgXdpBTl02vCFPO2VbaZgJylKeUa9PfR2karwbNclBvHChVDZrKXwlPX76Ba0gBviPnPvQn2qQGPTPxK81x9lAj5eF/9xm8dpsNzDMmJ1WV7mS1G3VnCZqkJphO8c/ljZgAACbVDlC9/NLhA7rDID81bRkQv7865EHk8fFPW1Z7QX+vOen3JDXNX5Ap1G/DkUxJtF/Lxw8Sru8f3UGP+uZjp4zpeyu6maRcy00r0VMmld6/CEb6XOtbu4cOZy7UqcBrBeXgXlFbasBjXH4Fhc0FpNRWhmv69BYYqzTzSkj9nLoiwwKy5O//Ecf2oXOwPSd+i815IAN84hUOCUi0BAUeYxS72XZ3QvK47MQLyZvn32JAg5ZP2J4O+mSmAerFu1UdkmZN3aCRdgw/k92j0FBQF1T+freTtF3UdDc48z7/xywtFg0nr2Rx5DM9c2/hmd6SFM/AZH1uienY+MtCgwWylp/XiyJGEpF28WAAselWG67pW1PXmeWeuJzKOY9KxXOXClI4zqyALDAGP9ehiyYykMCZsq2F5AZpI0LhM5d7XaqJ+4cdP2J8KNFrpJWkL5zuziGrez8Uqk+srkJuvBMvwDCoiCPEIHqiFfYXrOk41AejaCXNYKMuYhNpq4OSVN+Ekskr7SSDBMeKAsn3v6oteutQCkEK5WVmJP/5vhrMYTK5tC8Px08OoZAXrzSXCW2upebmF+O7pcF8FbFz8CRnb9kJZ3UACCNO/hq4ta74pcsQvdGhU4WWfwJrbPyONny6Jmyc5+XToy0FnPHIJzMsB+nUfMpyz+aH8qFVstsCJdhTxXBJXVAelKPr8jKxgDcUXWeEt+NMNNwR7y2NcUtaxT0t9GeZgOTxF0oG5sYidLISxLN7OE76MzJLsRNeXR0IotzGKdvBGd0+MqbKrp68btTLd7mX/dlGXW+6AX4dHz7xuAQ4jjbAIKNht1FGd2ezT6UdRDPIPHsi7Ha8kfIjkJg33QYJAZTj2I8ugYLUXChv6Hygd1NQNmacgpNNDrxYHFy5laq3HKHFu0CUbpNGUMJUdBvIpRLecVDeMNlAe+DrhF/wLYr7oMBBK3OkTOAsgEiCx0kffyy5DwmKJBs6K0DHVu3yZo7X20f6kCJwK6fFcSR67pydyHh0EU7zMnawGHGO43fu/h3oP0vz+ITLZTZnVBt5aXJralg1fvlnchTCT2gpskGP2K2HDiLL7Q8ESveW+D7S9BL5VpCNOyCBByyxBz6mPl8pmYd6dl8ow4kh/c11Uxom9oOwudpAy8xBmaZ/gTV3AgUWrsPqcg1VIMMYItwQCQLbpbaRFFon1EQFhKY/7ZPv2y8vyMXlCnIN0eYq8SqqoDDUALATRVH1MmUe/8Q3Ifam3DCkzdKa9VsZ7++78c0fbCIhlM7aiYPBnCCtTe8nk1Hc57sArHHNxCtfRQSem9TnpvwnW+gJTiwRIO7DKJS/8o3akzICgb7Idj2Sfb5cm9H0kOxwQuFxUBFfdyAoorKq5srYWwNSCHYNaz+vGdCkWLSt2PHMms3dymr4aCVmMuTNG0U5XyQKYqRWth8RlaBkaSRk1+6kIG6WCUr3I9TpAaDtTBbvZibIpGEpHWdhm2VVV3xYSY5yjNrUi/1G+QfKp0GbS7hAlTTjlfjwfn6oc4y3eomTJezbrknL7UAhuxnlTWPJAVvb8X+xKdOcPBiqIpMOm0M7UUKjl7vsps62Fe8NZxaWPhm12Zm8dBygXiFHeSpgGAoRIvJIk+gpxjOpvGel8UMv2j4QjwRbMxnVPbYMyo01HKDGNfgrcG6XtUPNeX6sSebNI8nTAjG8HRZXGnYiwKCpXWdT1+m9pRawebLKTGDcObF99BhIZgYweDVzxcmIu+V6X64VOb+33BnSW0S39jBcFexNxhrYztfYIL3b1qUBl9Pz6FSZvGTaeg7bjR0HuV3PO4fDtCF4MO9cxZ0LAQ1wDuJ/23tpK9FKjnGCXVMCSYUFtX5cUUJfxJKc3T1Ac3bilj5dbQ5KRB8jQte6BtyG1K1W7wodYrNyvkJMC02x4r6h4a+pVYT6t2bAST6vOY0Flbeg/IXVZKxS3xUEvNpRHWJal3yN5kOqB0+ck26f2zJgEDZfbyChRmbO4ooRH1pe3T0qxRUghL9J8cEosCLWBGeLjWqrDfga15ZSBnGDRx9HRJ5irY2i4Dq5zsLONrmFKYFD1BxNERgwCO9HVm3vllOyxqsf2ZXgaAbvCQKRBO6f93TEHE/5qVdCj6VKD8cnmqZa1XTBw/5S9KRw2pWdFxMf6KNCaitPOtZWedyTeMwcQS1MKaNHFfyBnKSSQnHwmPO+sNRK5NxB5ZLzE3BhhkbMVIkWo2WWQWTz9X1fO4XIrXrX2xu6DjjD09fRBzYAdh1oDzaXMVRQfhwghcQTfmHrW3wPYPlE6886nghV0h4SvwlwYv2obfxeZZdrwxyxmKy8UYXnyicMfJDORSfx6EGZT+VqiWnfDF/WT4DYz/nPBbjRxwPjRfSxun6b0a+MdWrU9yHh8ewpQWTrIHOF96QQYsPVgeFO2kGsnfNcxuk05V00Rz9QVC5MsT7ApHlh3uvP2sWi7Xt7shDQqWhoYQzIG9cQaJsMVKTbhUgF3sseVQv8T2p16l4AIAYT+O9IcKK+21M+KgAAu5LjCn78Wq56lG8BObe5/tmoL+M1DNfuRp7Vv+dQr4CwJtMzdESndKU+HFETYYA5UrLlCgMIZmmzfWMugznv5CK1Z8Q2lmdzRUwVDRvCk2TBFovWgcJjAFIrzc4JLXCX2eU9OY3+KcJ4+5CsNPserB2+mN+ipjEt2RIgFTwPl7XW4ydz2R7f2LUTiYzDqpjZ1xIiNCHD1i1/E3cMWLXttpTNxSmkVEDkoi7xKOWK2C8o17BXnf2xecNmOdYDqlXw6kRTLr2cV+qMz+daetwwRH/K9715mj8AjAAAR8GjnjrUoMwsSHPZsjG7X3dy/M73+STgvSYBykrBaIcWWcZV0+/AtLXUHy/UoG2uLhEAW+MCfoej9LE502YEtM9sIA8IL14vH43Vg4RWvcdWO6UvDQ+u5F6wDyJ2T5gaYeUke7KvxwLVHe914Uvh051y4FbHxf8BpDBcN8cuxyn7I+lHX8eRWx/PgK7rwk+APzVPLpGr+W6ANdQf9LnKoaRsMN9pidnqYijvXhb2/qoU15Jlz5ylUxrIWPBW4mSYQQ0tJComa/w+m8XdHUsgwuuPJaeiqzyiWIrpA1ifMCxNXKLEpNVG6dTf7eyQuzhmYUndx4nN8r/79Tc5ddyYlQ+L4MZdLYxRxcNuY9LoLbC+CbHZLzChmv7/VY+9RaCVDy4xHY9TV8y5j9f19MJlqGvANhpTNgnoA3RN1V+/pHEGdKcnZcOH6Tee2DitdPrXZMro8Jb75Pxnq0denQV3zXWe43Bpz0s8pi35/3fhfZwGmHU8H30OO1fB+CkvYvaTrdMKE6S+r1G5h3RmLwPaauSJf8eUBMpiAlNRoryI+9r/A8Zm5VINIVF3bf0GfPFc0fTTaK7OBltB9tYJCtXcHKa0E20tk3NvcN6lnxeAS+yemdfKLAmBZJduDNO1iBhR+o6Zjmu9yBjj3RJZJYwnipcCSRBvK0CKLhR9oqroi1LdYNmKEMVSE2J8o322v21uYRLIOXbvyHoSHsXr4+ebeu3IF05Heg9Gb4fuW9T2DbZ/e2XOqhw6RNWuK/qn2nXkWlKmNVZPAcP4CGF1dt9MxaGwtrSCDwq3oTz+Be0HsrQ/a9ptZR3qWvZiG3ubncsry0RGGAH9pcjEYwpCdkaUAexTLe1AlcWTmmsBg1XX1GtBJqHrMZE/PmHbSjsEZaVMPh3K99K620ZcRseu/WabOmbKiGPfNGtIIdv+BQ7mEum8l6jO3f68EPcknNriB0Z+TWoqlxuwz/QRjTYOByQX61rfhDJSOWddWCUPPXNgwKMu562gt9saThitA7JMb7KBu1EI3C7qF5PEdQOqpACNsitYWZ4tDZk+ZfhlqkSx6vJ/4frNE4wHoCZ7HwI41MwFBj1PCwAT65d9JuNcsAfmdaDeaW7fVBy3HN6EPSIq9pqXBK/xyZYtdx1ZvE+aEOyG+aJGHiUvmpwqa/S8q1gSMJsd45B2gxRllaS3GhC5HR9rxE3kMG6IG1pM5gKMjOjnZ5l6iFw+bDwHNZDPR+UwFLDWGjEnh62mrIsdTGZmW8+wcJvoqQRW8hW8knHZSyTjarVHxDseFai5msX6ht56FKqy1fxYvMs3638zFaSsJOm02govFya/zIFK0TBHS6+66XwKXzRwtNgoL13IJneBuv3IB5FUa3rtcMBlhSdQAedsfLmNKWSPzGu7xvBkNQQuRQyx73KjcYTRsszayYniU2s9D/YhIwYYYdl3oE1z3bsi9qVZTJ1k8o6BuCiTW/nMK+P4xYgaIvdFMuCeyNPFWGhrDQsl4gHJr7vHDmoJMLYDv95e4yCVOEp9iasVkV04m2Hv7EqpMstpvme1uTr6ZN9UwkocDJ7NUPh+MFetCjtHMhwJJ4YNJSevMTp7ByzjGOcUrLw+VqXGbvHeiaw55cOebhtRz/mKnR3MAJma0fVm+4jN9xHTKlQHBI3Gsaeq8Y0ulRmf3IReFZkg1MrQJjvkMUoSe3m8AQWZaEHdD4iISBOPHvwzsmrMspp6sByj2VZzEsI6vwllT1Z1mXuQmZHKRnOYywCAX9Ew0QUkL+m6hEMkFjtP+WUb+cIVQEWlW8dnzuqzOhf4eMDcqMpzgvnDmZzE9mNY9DycFMS4dkKfxGsZI5i2gSDJo53xHYPu69ZaV5XugDr5Q0p1/aadbShURg+iOllrzJY/MuiqL3IETCm3Y8TfMhpdLEcHVqauD90M6F4FXlCizdip+DKojGGnQXZ7nNRkSYsQPlPDvqcHYwf+OT5i0DvYyxhHlV852RLZepJ2UFv8gsVHu00ZFkm2dh8uD9covyz+0hF/pOFlV12POefhEEnXPuWKyMWAsXWyabQgbkUjar58m90atjBtjFvPuVYS9BKF1jCLA/An5/8wv5lR5X3hrFyZfdqr5UffxVfqIigS+dPExhNjWpSv7MGRvcsXz318Rks8rc6D2dEsZy/txb/hmUPWRNh+LsLQ1l4qhLrfobogyaIiHqNP9j0CfQFaRn596WDydwQUoSAuq0bev3RvibJuzXkovY9kxRUDgPqc9SpmoU7MLi881r7EYkfIm1deWCpLz+pd8VsNNbk/nOu30tYmOfv+NjFzXh/F5NVhqoFAa2yezUpADgXATGwhwZ5Yl9xNypAVEmX4dwxmS70yXh2Hgl+BKKegAAoUuzJ//A1R7BOA0dbqIEwkxhuZjQAKK9Z1hr0TapVvQfdUl6d03LzCaKWmXQ5VZaik4GGe5k+37kC/CzhQ6H7/B645k8OsFEWzs8BXgxafBQHwjLbFpfMdKRF4iADlZBDZw+iT6VfqF+qvZIfwaE2+i1CrPWO+7Ec96ejkrBfdhjHyJwObuPjlzuaNnDi8PjmuA4LPtbk8PT7t0jjz9EkFjdfWJI5ZWsfK3y6KI30ISkPfSVltqBwxyihg7q5QuXQ9W6pt7sm5LPu4UJzxhnxt+N3c53tUBDxMeqq0VIUUsgudFJ2BA/BqMHyUDq/8t4/zKsQeaJjbFmzT0gLwrh+3+qMwk+Qvch9o4Mjo+w2csI1pQ7HSGzwc3DzUAX2uJoj5Ty3LT9WIAtEAXRFpGENy0GjGxtmJb/X9Ju1imBmfLeVKvKkpHvRw6ykvMhFfSjiecZsouEPpx+w0P/8JwDQEfl7yXobR4sc9vmQGZlc1QNRUYbwPKUqwsSzjS6ihR6S6JudcU6gDtneLYEgemZC5cQ4BJmOOHKAs+1oKEHDApih7ty2GiwzE5VlY615eKtQgHhaYXkNgVje+JeUXAyGLdEM9EIU2NuU3Hayw4xe3Mvh6qcNRKoJzQqiWlbWiUNSgYy6yEDB/i6mNevYr3PHNLrtjpwXl8oqV0GQdnWhR5bHk8pt2d4LV2wjyv6els7SwzZ7DxVNe0UG0k6yk2vs2o7ijf/vRauH7Dsp5SB1T14trSCLuqPB6AkM4Uj+R7U6MpNsy5Y4mTvu+YcbRwGV3ATKf+MLmVKDjmkeclUd8fqNkhH1MfvDkOVQlETz8qsCPshjNp2/RxQpiwxXBaaM9bfiRGSGm91I4fGyn01KVh12mxKcc4nu1bkWBB10eNgfQwA4DIKkVUjocpQlyEPzs4Gtg6O726FmWPnfRHeV/R7yy8VSmHujuZda68TlAY9noG31w45dTHBKa485ZYJSfBJiK8hD72p/NM9K3SgX0tvYr1h8dpbXlC+rJjS9My9pHTV82CcX2uWLL5SPKGERm2nm/QIDs9U2PcqTmds9iaVpqQ5ecOqLMgHbjWCsKGBW6WTcxIajr0K6p+j9St4W61hADQYRKQuyrdXGfYgBcoA04fnYwaeDUUc62sjRqkuM2Y92oLCiGHau3b3sM7mQzGvnOeDBamoH+wXpytvgzh8wE0NsXR0F+F8PLf/iPIeRqPeGSiZqPbaNC7mq1igmKMDz1j8H6cugunRtzQcYn3p3vvk88AzAsbSMbGxat4QAnT6sBxmNS8T+nE5sfnZQcu6JEXDgdqrOqNzLLO6+uVbwwuA3U6Vuzj/1sI4vt4YeCrsJGbZhGmwT9fvTT5/5W7MmQdLtUx3UV8q7rJTiMN3WLIi0sxp1dEpZN0NujcRSkbP4u1F5mxT87qBWLzl65nZsUnXCLbZZPrZHrHQrwARyOe1upvlo4aD2+5kUF4XZycsn4ylkIeuaK3/d0bBhpwo6994sBi0psHm3CpabCWDZ1Z3Z3TpTMiZwjxJ800RrbUR/XSsD8XPg3VsavVJmYNbEiEMAI/YaImzYd/eIPbWuUb88qklSYj1o6fwZnxH4ygHQ8MBNZaL/IZ9+LgAU8nmDAALOMfpqokdh5/adHMi3XSMvin/uC11ei/3CY0aUlR5DXVBQfG7WE7Z6Hbv9+Io754RI4gA2SF+xqXGti4NKaR/5wlUQIVBhhm8BEFQC70d1koWAIMb42P7JeF44FiwFXZtOvy1Da4C8WaJCdJmVwzPFfF+jzHt36JyD1SgIt3W+INHkbeAjn1vZDnL5QO/zvYf0VMBDWASsrW264h/pguWJF18rsmqXEWMP0KypN6/iZYB5MUpHgjRZZZi6Do0u0ziCd4i9qGGL+JzVALcIhoAEY/URSRR2EUU4D9tqHWc6ZVKNVNgza+nZV98PzeeW7W9hEedVA8XwGASn7ZL3Aq9ZeBU63ItvrUquSS44VVxIVAJyr+fSM4rGREHtQy/BCp8yGWb4RIgtOD8v65jP8F5zm18q9zGW/uP+he3YjOfbbHk8rUV+XE3t6R/8wBwesTZvnnkz2NB/d11zdhxKCXip/pkcAABYw+ON5/Arpk+RZO/uLc5hneb76U+VGdod16/UWcCSO3PByI+EJpvNGTsw+459KJQwDbndlYUZ2c585PP8Ph3M9xBCORIFqsJtuombiLgu/WbGLdwsea1E29bszqxIiwaSFXaPTvxLor0CzX3PHyn/5DDXP8ago5c8KcMqkhE23fMG22CMQFgTTi7WKZi3g/S+h2A3KAbxfV4bK/MhPwMcvDKoytuLabe6K5t/viX1AfdKaEZQipQ5a++ChBLGMD8WVzKEEj7aaerW7n9WV5KrFah5RqCmeC48vaRzvA1dss3JyC47y4xi0+T/vyQJa8xznnbBK78/pjJlg5PS7UGn7SWschgAT8k0vT0F1fBgpH3WTcJlfj53KfaDb36iWJasZSpfkicJDScUi3SJKsdgfcnzys+tHcCG3mYYQDLtcYrtKrYXf0uXm+sq5slHw6QH7v/9Kt4OFYo91Rbsays33zUkf4GCoTeWL4h/fOXl6dZYDAzaesCFyPosaOguC/FBmhJjfV4OBQDSbBzn9R0vbY16iI5ErzOQB5L2ng9If8Hp4W1fCF8bAtnFYTLzYUU0FbVslYZCjApNeZarw5HtgNnRBBZwEdRL34glZmJgbtJ+p29l7hvyOC8mG1nOEnbSHDNoEzKAMVjvOjqkc8qnR+VbxN6qXttdnQw4NCALIkDuRozh0jsbNPHYgzbdxGeRhCoOHSWRy9W5JCs1UZTPk9xNdMB+dNHd04JsvbrJB0kiKEuoN6KyjO+2kn9JN5w12dDary/2RPAkpjnSBbuoRQ54nNS2oe+yxejYlRjFke94OBTKA5C21+5OBTzwEDwbi4rLWe4t/a168ekmGQsLtkQhSnJSSkJp90hxavAvjVwl+qLa7q0la93q0PwgFVMSSOwwn02GBbMtd85WXHpbPkNIwLZLgOr54QnB6Oq6MZoIkqjlZogfZJ8/l4qBUfhyYr1UHHioq/3uYpth9On1o1Q9SJsg3pGIEdYE5xNqIyV4dDKuYhdIOFOLcj5BrasbgXuZG3DthtRC2/2lWaI9NKH/VM90B+VLlIk4fD+5KmXkMBfWHxJf+o3tttRvn+2CZUmXE8WTFC9n7NwMuI15rVURx6bE03m8l8u9r6Lcp4jjTfzBBCOGcWwAAjkQBiy+YAC0vUplW1EIUXA2HnaoreOC4AtjsyoPXDBEoLoYxyE/pAEHECQJBQ2LcXmbQf+KVZ1MrZad8Rj+N9a/0H/Hx1KoNgkLGBOjWjTlu3ASNgFy7L0ezvDHmYaaQZ6WWri/92EumzKk/TskE1FWHYEjcwCqK9+WahKEWi9HcvIdVR4+ukHNNEK0J3/MZBnTvmM8pBmSHLHUzBYZawuC/o21JaR1x2VUK9rltnBJ9+YSAewRhmIhXVGJHus8y4LOAljdZbkSMKHhQVV3m9Q9pAAO2rPuKw5MMhjC/15X1pkh53wfwjbTMsmKlVMISuaC0pMDZy4fVn5VhK6O1wmDKDMlLA6ZkJ70WR5J844hjN0FTgEEw3wSJuoInkSrH/yrNeC3nw66qzCEAfHPEQLDB3EfayyB/F1J/7AWAkCZUchj/1VIHEjs1QNfPXfJZfuFlgPA7CBxuiPqO7YWqPtNcXQoiix7QMBFZ9rWJW7qZ39TVP9AwIEbV5Krqe7EcTX2nFwA3F8zMIapnWh4cHOG2Bw2Nj/AZ4gp2kVteiwU87pclnRNlIfUFVyv/DqiuAVoAev5L5ZmR/XfE8JTVEw+cviNsyStYpTf6solFbr+Pww9FNoXuqinCWq1qH0UMPhyPfVr5j0E7Eix9jFfavALDuwBU8Z6R5UQSHAu/8LnLBxtGSMCjRg2YyexXQtOn/aa4gaW1lS9JL906EXF//hk9mqX8bqUEX9c9AcPjXF+DWVMTIwHVz4gP2igLjA7p/Jo34sA9EkB2CaWv8KIJJQJqVfaLuN3bHC8Cv5Lj1uFzUhAyOy4TbYE/XbvcWbEBtmb8AlZsnOYy346v6qLPBconmEh0JaSjFDreqM1P2s8v/1TBZIQgZbeXAD0ExncDdpcDDL9llTHbh4p5MB3hiidoYkC52+zi7UXHCEXIEsj7NdH/XaCuBVRw3ImewBcUCKY4Wv9JMUsiEBGMy+8HMHEo68cSPe26ar4PMworyBIWJO5ZZ+AABaE+RA1BN5mYMCvueBUJ1mKoURt2rA2D/82J1K3OzdmzOIDN5BupZ163D0DuQcJdyk6dsC7/nExg7i7tADMhwXA/Yx1dqR6/CjJm8nzeDTczJuVVu4dRXUJtJ1T3foklKcsRYfCbtRhO6y8ct1Qig4coz58ksu6fi2Dua+Y7YaD6M1vE/AJK3velPMWHbRslrpwQqeFWh8Nl3DbZ01ewsvh0opbLlB5CNe3fveWv3BHD3SiROAELa7Lj8y0Kyx5aIiTbty6/4PKpHYf6kL3d/NypyjKN2fm8vGYCYIJQAersS74cP32GH5u3eWisLZQ29OL0nNohwBTHlyantMS8E5bKnak57mL/DyJSzDcVvfY7yrxhqLietLMrT8ZfwyolDOtIlhfMFhndSvuze4pixD7nt+NOG9Y4TxMjO7eK3b+kgYF7T8H7pEHy+21wtTL85K/Gw41Iis9F63ycXYHC4acx5VlbO5oTsdawfeihkZr6oJkUkS/7+rEvdCYf5pQSYseov5lmoor1pRn9ZTSKDtalenZtW+W73JpPiDQB7OmVUiNB7uZhM7qlvZJehxcyhpEEQCkENUBaW4TFztjN1P3z1BNlJmSKnBV6T7qf4R2/CMVsc1XD0kNwm2wifR1euYPrpXm7Klwv9as+nla8G//ezUUgvJ4mGqVgYcV6pKDwvKbzwtjjvV/x3Lwtjdc7XMH3wxMspDqHSZAzU7JfXBtjBQmjiMMmtWpL/jmwvPM/jheHElAMXMnQHp7Lr1YbXZSxMHvQa6qYHbZPiT0TzouzQsDa0uUSLhyeVoyNi3iwlcgBH8tGIqN+aQL1L+wSaPecirPE+UOs/40IeGkbcpQWGPqRbChdanTreyf+COeysIqpw/nMa9qaXi63D/yXb6lH5SFHMvOyiKElvVnLYnZtK1QAAABP9cPkBbtLkUn+cB1T94Dz4UC5tVRsuGkLamaqa+KjrY02xSUUkXLYfvJ2HjNN2KITNeIDn8BoJKcVfocCgwS3kZM19Rq1AMAv7AE03fA5OthXhiG8wDqoaw2lJ/9FLT92qxAVYBm8DXWepn/DdgbzSPvJN6wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==" alt="" aria-hidden="true" style="max-width:170px;width:100%;margin:0 auto 1rem;display:block;filter:drop-shadow(0 5px 8px color-mix(in oklab, var(--ink) 30%, transparent));" />
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
<div id="pp-trial-welcome" style="position:fixed;bottom:20px;left:50%;transform:translateX(-50%) rotate(-0.5deg);z-index:2147483647;max-width:92vw;width:400px;box-sizing:border-box;background:oklch(0.965 0.021 88);color:oklch(0.29 0.045 40);border:2.5px solid oklch(0.29 0.045 40);border-radius:40px 14px 40px 14px / 14px 34px 14px 34px;box-shadow:5px 6px 0 0 oklch(0.29 0.045 40);padding:1.1rem 1.25rem;font-family:'Patrick Hand',cursive;font-size:0.98rem;line-height:1.4;display:flex;align-items:flex-start;gap:0.75rem;">
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
    background-color:var(--cream);color:var(--ink);font:17px/1.5 var(--font-body);padding:2rem 1rem;
    background-image:radial-gradient(oklch(0.86 0.04 80 / 0.5) 1.2px, transparent 1.3px);
    background-size:22px 22px;}
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
