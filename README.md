# Benson's Threat Model Lab

A browser-based threat-modelling tool. Import an architecture diagram or build one by
hand, then generate a threat model four ways — enterprise **IT** or **OT/ICS (Purdue)**,
each as **STRIDE-LM** or **RAPIDS** scenarios. Every path resolves to **MITRE ATT&CK**
techniques, and each technique expands into an offensive attack/payload sample and the
defensive side: **Sigma**, **YARA** and network detections plus mapped **MITRE D3FEND**
countermeasures and **ATT&CK Mitigations**.

**It runs entirely in your browser** — no backend, no build step, nothing is uploaded.

## Features

- **Four methodologies**
  - IT · STRIDE-LM — per component, the seven STRIDE-LM categories (incl. Lateral Movement)
  - IT · RAPIDS — Ransomware, Application vulnerability, Phishing, Insider threat, Denial of service, Supply chain
  - OT/ICS Purdue · STRIDE-LM — per Purdue level (L0–L4/5), mapped to ATT&CK for ICS + enterprise techniques
  - OT/ICS Purdue · RAPIDS — the six scenarios adapted to OT/ICS
- **Diagram import** — draw.io (`.drawio`/`.xml`, incl. compressed), Mermaid (`.mmd`), JSON, CSV, or an image (PNG/JPG/SVG) as a visual reference to tag. Components *and* data flows are auto-extracted.
- **MITRE ATT&CK TTP cards** — each with an offensive attack/payload sample and the matching defences: Sigma + YARA + network rules, and mitigating controls linked to MITRE D3FEND and ATT&CK Mitigations.
- **Export** — copy the model as Markdown or download it as JSON.

## Usage

Open the hosted page, or run locally:

```bash
# any static server works
python3 -m http.server 8000
# then open http://localhost:8000
```

There is no build step. The app is plain HTML/CSS/JS:

```
index.html            app shell
assets/app.css        chrome + layout
assets/enhance.css    TTP / scenario / code / controls styling
assets/ttp-kb.js      MITRE ATT&CK + D3FEND knowledge base
assets/threatlab.js   parsers, threat engine and UI
```

## Safety & scope

For **authorised** security testing, purple-team and education only. Offensive samples
mirror publicly documented tradecraft (MITRE ATT&CK, Atomic Red Team, the Sigma and YARA
projects). OT/ICS process-manipulation payloads are bounded to recon/read or isolated
test-rig examples; payloads that would act on a live physical process are withheld, with
detection and mitigation shown instead.

## Credits

- [MITRE ATT&CK](https://attack.mitre.org/) and [MITRE D3FEND](https://d3fend.mitre.org/)
- The [Sigma](https://github.com/SigmaHQ/sigma) and [YARA](https://virustotal.github.io/yara/) rule projects
- STRIDE / STRIDE-LM and the Purdue model (ISA-95 / IEC 62443)

## License

MIT © Benson Tan
