/* =======================================================================
   Benson's Threat Model Lab — app shell
   Visual model canvas, KPI metric tiles and an iconned component palette.
   Driven by the "tml:model" event dispatched by the engine (threatlab.js).
   ===================================================================== */
(function () {
  "use strict";
  const KB = window.TLAB;
  if (!KB) return;
  const $ = (id) => document.getElementById(id);
  const SVGNS = "http://www.w3.org/2000/svg";
  const svg = (t, a) => { const e = document.createElementNS(SVGNS, t); if (a) for (const k in a) e.setAttribute(k, a[k]); return e; };
  const clip = (s, n) => (s.length > n ? s.slice(0, n - 1) + "…" : s);

  const compIcon = (domain, type) => (domain === "ot" ? "plc" : ((KB.COMPONENTS[type] || {}).icon || "cpu"));
  const compLabel = (domain, type) => (domain === "ot" ? (KB.PURDUE[type] || {}).label : (KB.COMPONENTS[type] || {}).label) || type;
  const typeOrder = (domain) => (domain === "ot" ? KB.OT_ORDER : KB.IT_TYPE_ORDER);

  /* ── derived metrics ───────────────────────────────────────────────── */
  function techniqueSet(d) {
    const set = new Set();
    if (d.framework === "rapids") {
      (d.domain === "ot" ? KB.RAPIDS_OT : KB.RAPIDS_IT).forEach((s) => s.ttps.forEach((id) => set.add(id)));
    } else {
      d.comps.forEach((c) => { const sm = d.domain === "ot" ? KB.OT_STRIDE[c.type] : (KB.COMPONENTS[c.type] || {}).stride; if (sm) Object.values(sm).forEach((r) => (r.ttps || []).forEach((id) => set.add(id))); });
      if (d.domain === "it" && d.flows.length) { const sm = (KB.COMPONENTS.dataflow || {}).stride; if (sm) Object.values(sm).forEach((r) => (r.ttps || []).forEach((id) => set.add(id))); }
    }
    return set;
  }
  function renderStats(d) {
    const el = $("tmStats"); if (!el) return;
    const ttps = techniqueSet(d);
    const tactics = new Set([...ttps].map((id) => (KB.TECH[id] || {}).tactic).filter(Boolean));
    const tiles = [];
    if (d.framework === "rapids") tiles.push(["scn", "scenarios", (d.domain === "ot" ? KB.RAPIDS_OT : KB.RAPIDS_IT).length]);
    else { tiles.push(["comp", "components", d.comps.length]); tiles.push(["flow", "data flows", d.flows.length]); }
    tiles.push(["ttp", "ATT&CK techniques", ttps.size]);
    tiles.push(["tac", "tactics", tactics.size]);
    tiles.push(["ctl", "defensive controls", countControls(ttps)]);
    el.innerHTML = tiles.map(([c, l, n]) => `<div class="kpi ${c}"><div class="kpi-n">${n}</div><div class="kpi-l">${l}</div></div>`).join("");
  }
  function countControls(ttps) {
    const set = new Set();
    ttps.forEach((id) => { const t = KB.TECH[id]; if (t) { if (t.sigma) set.add(id + ":sigma"); if (t.yara) set.add(id + ":yara"); (t.detect || []).forEach((_, i) => set.add(id + ":d" + i)); (t.defend || []).forEach((k) => set.add(k)); } });
    return set.size;
  }

  /* ── component palette ─────────────────────────────────────────────── */
  let paletteDomain = null;
  function renderPalette(d) {
    const el = $("tmPalette"); if (!el) return;
    if (paletteDomain !== d.domain) {
      paletteDomain = d.domain;
      el.innerHTML = typeOrder(d.domain).map((t) => `<button class="pal" type="button" data-type="${t}" title="${compLabel(d.domain, t)}">
        <svg class="ic" aria-hidden="true"><use href="#i-${compIcon(d.domain, t)}"></use></svg>
        <span>${clip(compLabel(d.domain, t).replace(/\s*\(.*\)/, "").replace(/ —.*/, ""), 20)}</span></button>`).join("");
      el.querySelectorAll(".pal").forEach((b) => b.addEventListener("click", () => {
        const sel = $("tmType"); if (sel) { sel.value = b.dataset.type; }
        highlightPalette(b.dataset.type);
        const name = $("tmName"); if (name) name.focus();
      }));
    }
    const sel = $("tmType"); highlightPalette(sel ? sel.value : null);
  }
  function highlightPalette(type) { document.querySelectorAll("#tmPalette .pal").forEach((b) => b.setAttribute("aria-pressed", b.dataset.type === type ? "true" : "false")); }

  /* ── model canvas ──────────────────────────────────────────────────── */
  const NW = 158, NH = 46, COLGAP = 48, ROWGAP = 16, PAD = 18, LABELW = 180;
  // canvas lane order for IT: left-to-right by trust zone (DFD style)
  const CANVAS_IT_ORDER = ["external", "network", "process", "host", "identity", "datastore", "dataflow"];
  function renderCanvas(d) {
    const card = $("tmCanvasCard"); const host = $("tmCanvas"); if (!host) return;
    host.innerHTML = "";
    if (!d.comps.length) { card.hidden = true; return; }
    card.hidden = false;
    $("tmCanvasMeta").textContent = `${d.comps.length} component${d.comps.length === 1 ? "" : "s"} · ${d.flows.length} data flow${d.flows.length === 1 ? "" : "s"}`;
    const pos = new Map(); // name -> {cx, cy, x, y}
    let W, H; const root = svg("svg", { class: "canvas-svg" });
    const defs = svg("defs");
    defs.innerHTML = `<marker id="tmArrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="#35e0c1" opacity="0.7"/></marker>`;
    root.appendChild(defs);
    const edgeLayer = svg("g"); const nodeLayer = svg("g");
    root.appendChild(edgeLayer); root.appendChild(nodeLayer);

    const mkNode = (c, x, y) => {
      const g = svg("g", { class: "cnode", transform: `translate(${x},${y})` });
      g.appendChild(svg("rect", { x: 0, y: 0, width: NW, height: NH, rx: 9, class: "cnode-box" }));
      const use = svg("use", { href: "#i-" + compIcon(d.domain, c.type), x: 12, y: NH / 2 - 10, width: 20, height: 20, class: "cnode-ic" });
      g.appendChild(use);
      const tx = svg("text", { x: 40, y: NH / 2 + 4, class: "cnode-tx" }); tx.textContent = clip(c.name, 17);
      g.appendChild(tx);
      const title = svg("title"); title.textContent = c.name + " — " + compLabel(d.domain, c.type); g.appendChild(title);
      nodeLayer.appendChild(g);
      pos.set(c.name, { cx: x + NW / 2, cy: y + NH / 2, x, y });
    };

    if (d.domain === "it") {
      const cols = CANVAS_IT_ORDER.map((t) => ({ t, items: d.comps.filter((c) => c.type === t) })).filter((c) => c.items.length);
      let maxRows = 1;
      cols.forEach((col, i) => { col.items.forEach((c, k) => mkNode(c, PAD + i * (NW + COLGAP), PAD + k * (NH + ROWGAP))); maxRows = Math.max(maxRows, col.items.length); });
      // components whose type has no column position (shouldn't happen) skipped
      W = PAD * 2 + cols.length * NW + (cols.length - 1) * COLGAP;
      H = PAD * 2 + maxRows * NH + (maxRows - 1) * ROWGAP;
    } else {
      const rows = KB.OT_ORDER.map((t) => ({ t, items: d.comps.filter((c) => c.type === t) })).filter((r) => r.items.length);
      let maxCols = 1;
      rows.forEach((row, i) => {
        const y = PAD + i * (NH + ROWGAP + 10);
        edgeLayer.appendChild(svg("rect", { x: 2, y: y - 6, width: 10, height: NH + 12, rx: 3, class: "cband" }));
        const lbl = svg("text", { x: 20, y: y + NH / 2 + 4, class: "cband-lbl" }); lbl.textContent = clip((KB.PURDUE[row.t] || {}).label || row.t, 26); edgeLayer.appendChild(lbl);
        row.items.forEach((c, k) => mkNode(c, LABELW + k * (NW + COLGAP), y));
        maxCols = Math.max(maxCols, row.items.length);
      });
      W = LABELW + PAD + maxCols * NW + (maxCols - 1) * COLGAP;
      H = PAD * 2 + rows.length * (NH + ROWGAP + 10);
    }

    d.flows.forEach((f) => {
      const a = pos.get(f.from), b = pos.get(f.to); if (!a || !b) return;
      edgeLayer.appendChild(svg("line", { x1: a.cx, y1: a.cy, x2: b.cx, y2: b.cy, class: "cedge", "marker-end": "url(#tmArrow)" }));
    });

    root.setAttribute("viewBox", `0 0 ${W} ${H}`);
    root.setAttribute("width", W); root.setAttribute("height", H);
    host.appendChild(root);
  }

  /* ── status ────────────────────────────────────────────────────────── */
  function setStatus(d) {
    const s = $("status"); if (!s) return;
    s.classList.add("ok");
    s.querySelector("span").textContent = d.total ? `${d.total} findings` : "Ready";
  }

  document.addEventListener("tml:model", (e) => {
    const d = e.detail;
    renderStats(d); renderPalette(d); renderCanvas(d); setStatus(d);
  });
})();
