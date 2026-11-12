// What a package or skill says it is for, against what its code can do. Hidden behaviour
// shows up as a mismatch: a "string formatter" that talks to the network and starts programs.
// The profile goes to the reviewer as the main question; clear mismatches are also findings.
import path from "node:path";
import { finding } from "./engine.mjs";
import { capabilitiesOf } from "./capabilities.mjs";

const readJson = t => { try { return JSON.parse(t); } catch { return null; } };
const CODE = /\.(c|m)?(j|t)sx?$|\.(pyw?|sh|ps1)$/i;

// Purposes that need neither network nor other programs, unless the text says otherwise.
const QUIET = /\b(format(?:ter|ting)?|colou?rs?|strings?|text|case|slug(?:ify)?|utils?|helpers?|pars(?:e|er|ing)|math|numbers?|dates?|times?|css|styles?|icons?|themes?|types?|typescript|arrays?|objects?|deep|merge|clone|uuid|random|validat(?:e|or|ion)|regex|emoji|ascii|markdown|logg(?:er|ing)|i18n|locale|calc(?:ulator)?|convert(?:er)?|units?|uppercase|lowercase|trim|pad|sort|diff|hash|encode|decode|escape|template|lint(?:er)?|polyfill|shim|tiny|minimal)\b/i;
const NOISY = /\b(https?|fetch|request|client|api|sdk|network|proxy|download|upload|cli|command|server|deploy|git|docker|shell|exec|spawn|process|browser|crawl(?:er)?|scrap(?:e|er)|webhook|bot|telemetry|analytics|cloud|aws|s3|gcp|azure|db|database|sync|install(?:er)?|build|bundl(?:e|er)|compile|runner|test|devtools?|update|notif(?:y|ication)|email|mail|sms|chat|slack|discord|telegram|oauth|auth|login|scan(?:ner)?|monitor|agent|mcp|browser)\b/i;

function manifests(files) {
  const out = [];
  for (const f of files) {
    const base = path.basename(f.rel), dir = path.dirname(f.rel) === "." ? "" : path.dirname(f.rel);
    if (base === "package.json") {
      const p = readJson(f.text);
      if (p && !p.private && p.name && p.version) out.push({ dir, file: f.rel, kind: "package", name: p.name, purpose: [p.description, ...(p.keywords || [])].filter(Boolean).join(" · ") });
    } else if (base === "SKILL.md") {
      const fm = f.text.match(/^---\s*\n([\s\S]*?)\n---/);
      const name = fm?.[1].match(/^name:\s*(.+)$/m)?.[1]?.trim(), desc = fm?.[1].match(/^description:\s*(.+)$/m)?.[1]?.trim();
      out.push({ dir, file: f.rel, kind: "skill", name: name || dir || "skill", purpose: desc || f.text.slice(0, 200) });
    } else if (base === "pyproject.toml" || base === "setup.py") {
      const desc = f.text.match(/\bdescription\s*=\s*["']([^"']+)/)?.[1];
      const name = f.text.match(/\bname\s*=\s*["']([^"']+)/)?.[1];
      if (name) out.push({ dir, file: f.rel, kind: "python", name, purpose: desc || "" });
    }
  }
  // Nested manifests own their own folder; the outer one keeps the rest.
  return out.sort((a, b) => b.dir.length - a.dir.length);
}

export function profiles(files) {
  const list = manifests(files);
  for (const m of list) { m.capabilities = {}; m.codeFiles = 0; }
  for (const f of files) {
    if (!CODE.test(f.rel)) continue;
    const owner = list.find(m => !m.dir || f.rel.startsWith(m.dir + "/"));
    if (!owner) continue;
    owner.codeFiles++;
    for (const c of capabilitiesOf(f.text)) (owner.capabilities[c] ||= []).push(f.rel);
  }
  return list.filter(m => Object.keys(m.capabilities).length || m.kind === "skill");
}

/** Findings for packages and skills whose code clearly does more than their description says. */
export function purposeMismatches(list, out) {
  for (const m of list) {
    const caps = m.capabilities, has = c => !!caps[c];
    const risky = ["uses the network", "runs other programs", "writes into home or startup folders", "collects user and host details"].filter(has);
    if (!m.purpose || !QUIET.test(m.purpose) || NOISY.test(m.purpose) || !risky.length) continue;
    const codeFiles = m.codeFiles;
    // Big, established projects grow features their one-line description does not mention;
    // small ones rarely do. Only the small case decides on its own.
    const strong = codeFiles <= 15 && has("uses the network") && (has("runs other programs") || has("reads environment or credential files") || has("collects user and host details"));
    const files = [...new Set(risky.flatMap(c => caps[c]))].slice(0, 4);
    // For a skill this is a question for the reader, not a verdict: a skill's scripts routinely call an
    // API and start a program, and its one-line description rarely says so. On 1,029 clean skills
    // it was the only reason three were flagged, and on 361 malicious ones it decided one.
    out.push(finding({ id: "behaviour-purpose-mismatch", category: m.kind === "skill" ? "agent" : "supply-chain", severity: strong && m.kind !== "skill" ? "high" : "medium", confidence: "medium",
      title: `${m.kind === "skill" ? "Skill" : "Package"} "${m.name}" does more than it says`,
      why: `It describes itself as "${m.purpose.slice(0, 90)}" but its code ${risky.join(", ")}. Hidden behaviour most often shows up as this kind of mismatch.`,
      fix: "Read the listed files and decide whether the stated purpose explains them. If not, do not install or run it." }, m.file, 1, files.join(", ")));
  }
}
