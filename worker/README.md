# AI Vision backend (Cloudflare Worker)

A tiny proxy that lets the Lab analyse **image** diagrams (PNG/JPG) with a
vision model without each visitor supplying an API key. It holds your Anthropic
key server-side and is **passphrase-gated**, so only people you give the
passphrase to can spend your credits.

```
browser ──image+passphrase──▶ Worker ──image──▶ Anthropic ──JSON──▶ Worker ──▶ browser
                               (holds API key, checks passphrase)
```

## Deploy (one time, ~5 minutes)

You need a free [Cloudflare account](https://dash.cloudflare.com/sign-up) and
Node installed.

```bash
cd worker
npm install -g wrangler        # or use: npx wrangler <cmd>
wrangler login                 # opens the browser to authorise
```

Set the two secrets (they are stored by Cloudflare, never in the repo):

```bash
wrangler secret put ANTHROPIC_API_KEY   # paste your sk-ant-... key
wrangler secret put TML_PASSPHRASE      # choose a passphrase to share with users
```

Check `wrangler.toml`:
- `ALLOWED_ORIGIN` — set to your site origin (already `https://bensontan123.github.io`). Comma-separate if you have more than one.
- `ANTHROPIC_MODEL` — defaults to `claude-sonnet-5-5`. Use `claude-haiku-5-5` for the lowest cost, or `claude-opus-5-5` for best quality.

Then deploy:

```bash
wrangler deploy
```

Wrangler prints the URL, e.g. `https://tml-vision.YOUR-SUBDOMAIN.workers.dev`.

## Point the site at it

Paste that URL into **`assets/config.js`** and push:

```js
window.TML_CONFIG = { aiEndpoint: "https://tml-vision.YOUR-SUBDOMAIN.workers.dev" };
```

Now anyone on the site can open the ⚙ gear, enter the **passphrase** once, and
click **analyse with AI (vision)** on a PNG/JPG — no API key needed.

## Test it

```bash
curl -i -X POST https://tml-vision.YOUR-SUBDOMAIN.workers.dev \
  -H "content-type: application/json" \
  -H "Origin: https://bensontan123.github.io" \
  -d '{"image_base64":"<base64>","media_type":"image/png","domain":"it","passphrase":"<yours>"}'
```

Wrong/absent passphrase returns `401`; success returns
`{ system, components, flows, model }`.

## Cost & safety

- **You pay** for every analysis the backend runs. Set a **monthly spend limit**
  on the Anthropic key (console.anthropic.com → Billing → Limits) as a hard cap.
- The passphrase bounds *who* can use it; rotate it anytime with
  `wrangler secret put TML_PASSPHRASE`.
- Keep the model cheap (Haiku/Sonnet) for a public endpoint.
- `ALLOWED_ORIGIN` restricts browser calls to your site (defence in depth; the
  passphrase is the real gate).
- Optionally add a Cloudflare **Rate Limiting** rule in the dashboard for extra
  protection against abuse.

## Change the key or passphrase later

```bash
wrangler secret put ANTHROPIC_API_KEY
wrangler secret put TML_PASSPHRASE
```

No redeploy needed for secret changes.
