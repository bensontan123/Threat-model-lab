/* =======================================================================
   Benson's Threat Model Lab — AI Vision backend (Cloudflare Worker)

   Holds the Anthropic API key server-side so the static site can analyse
   image diagrams without each visitor supplying a key. Passphrase-gated.

   Required secrets (set with `wrangler secret put <NAME>`):
     ANTHROPIC_API_KEY   your Anthropic API key (sk-ant-...)
     TML_PASSPHRASE      the passphrase the app must send

   Vars (wrangler.toml [vars], safe to commit):
     ALLOWED_ORIGIN      comma-separated site origins allowed via CORS
                         e.g. https://bensontan123.github.io
     ANTHROPIC_MODEL     optional; defaults to claude-opus-5-5. For a public
                         (even passphrase-gated) endpoint you pay for, set a
                         cheaper model like claude-haiku-5-5 or claude-sonnet-5-5.

   Request  (POST, JSON): { image_base64, media_type, domain: "it"|"ot", passphrase }
   Response (JSON):       { system, components:[{type,name}], flows:[{from,to}], model }
   ===================================================================== */

const MODEL_DEFAULT = "claude-opus-5-5";
const MAX_B64 = 7_000_000; // ~5 MB image

const IT_TYPES = {
  external: "External entity (user, browser, client, third party)",
  process: "Process / service / API / application",
  datastore: "Data store (database, bucket, file, cache, queue)",
  dataflow: "Data flow / channel",
  identity: "Identity / IdP / auth / Active Directory / PAM",
  host: "Host / server / VM / container",
  network: "Network device (gateway, load balancer, firewall, WAF, proxy, VPN, CDN)",
};
const OT_TYPES = {
  level4: "Purdue Level 4/5 — enterprise IT",
  level35: "Purdue Level 3.5 — industrial DMZ (IDMZ)",
  level3: "Purdue Level 3 — site operations (historian / EWS)",
  level2: "Purdue Level 2 — supervisory (SCADA / HMI)",
  level1: "Purdue Level 1 — basic control (PLC / RTU / IED)",
  level0: "Purdue Level 0 — field devices (sensors / actuators)",
};

export default {
  async fetch(req, env) {
    const origin = req.headers.get("Origin") || "";
    const headers = corsHeaders(origin, env.ALLOWED_ORIGIN);

    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers });
    if (req.method !== "POST") return json({ error: "method not allowed" }, 405, headers);
    if (!env.ANTHROPIC_API_KEY) return json({ error: "backend not configured (no API key)" }, 500, headers);

    let body;
    try { body = await req.json(); } catch (e) { return json({ error: "invalid JSON body" }, 400, headers); }

    // passphrase gate (constant-time)
    if (env.TML_PASSPHRASE) {
      if (!body.passphrase || !timingSafeEqual(String(body.passphrase), String(env.TML_PASSPHRASE))) {
        return json({ error: "invalid or missing passphrase" }, 401, headers);
      }
    }

    const data = String(body.image_base64 || "");
    let media = String(body.media_type || "").toLowerCase();
    if (media === "image/jpg") media = "image/jpeg";
    if (!/^image\/(png|jpeg|gif|webp)$/.test(media)) return json({ error: "unsupported image type" }, 400, headers);
    if (!data || data.length > MAX_B64) return json({ error: "image missing or too large" }, 400, headers);

    const domain = body.domain === "ot" ? "ot" : "it";
    const types = domain === "ot" ? OT_TYPES : IT_TYPES;
    const defs = Object.entries(types).map(([k, v]) => `${k} = ${v}`).join("; ");
    const prompt = `You are a threat-modelling assistant. Analyse this architecture / data-flow diagram image and extract its structure.\n`
      + `Return ONLY valid minified JSON (no prose, no markdown fences) of exactly this shape:\n`
      + `{"system":"<short name or empty>","components":[{"type":"<TYPE_KEY>","name":"<label>"}],"flows":[{"from":"<component name>","to":"<component name>"}]}\n`
      + `Rules:\n`
      + `- "type" MUST be one of these keys (key = meaning): ${defs}.\n`
      + `- Use component names exactly as written in the diagram.\n`
      + `- Add a flow for every arrow/connector between components; direction follows the arrowhead (best guess if none). "from"/"to" must match component names.\n`
      + `- Ignore titles, legends and annotations; only real system components.`;

    const model = env.ANTHROPIC_MODEL || MODEL_DEFAULT;
    let ar;
    try {
      ar = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "content-type": "application/json", "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01" },
        body: JSON.stringify({ model, max_tokens: 1500, messages: [{ role: "user", content: [{ type: "image", source: { type: "base64", media_type: media, data } }, { type: "text", text: prompt }] }] }),
      });
    } catch (e) { return json({ error: "upstream request failed" }, 502, headers); }

    if (!ar.ok) {
      let d = ""; try { d = (await ar.json())?.error?.message || ""; } catch (e) { /* ignore */ }
      return json({ error: "model error " + ar.status + (d ? ": " + d.slice(0, 160) : "") }, 502, headers);
    }
    const j = await ar.json();
    if (j.stop_reason === "refusal") return json({ error: "the model declined this image" }, 422, headers);

    let text = (j.content || []).filter((b) => b.type === "text").map((b) => b.text).join("").trim();
    text = text.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/i, "").trim();
    let parsed;
    try { parsed = JSON.parse(text); }
    catch (e) { const m = text.match(/\{[\s\S]*\}/); if (!m) return json({ error: "could not parse model response" }, 502, headers); try { parsed = JSON.parse(m[0]); } catch (e2) { return json({ error: "could not parse model response" }, 502, headers); } }

    const components = (parsed.components || []).filter((c) => c && c.name)
      .map((c) => ({ type: types[c.type] ? c.type : "", name: String(c.name).slice(0, 60) }));
    const flows = (parsed.flows || []).filter((f) => f && f.from && f.to)
      .map((f) => ({ from: String(f.from).slice(0, 80), to: String(f.to).slice(0, 80) }));
    if (!components.length) return json({ error: "the AI found no components" }, 422, headers);

    return json({ system: parsed.system ? String(parsed.system).slice(0, 80) : "", components, flows, model }, 200, headers);
  },
};

function corsHeaders(origin, allowedCsv) {
  const list = String(allowedCsv || "").split(",").map((s) => s.trim()).filter(Boolean);
  let allow = list[0] || "*";
  if (list.includes(origin)) allow = origin;
  else if (/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) allow = origin;
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "content-type",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
}
function json(obj, status, headers) {
  return new Response(JSON.stringify(obj), { status, headers: { ...headers, "content-type": "application/json" } });
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
