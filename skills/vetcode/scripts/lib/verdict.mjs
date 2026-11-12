// From findings to a verdict.
//
// A scanner of several hundred rules that lets any one of them call a target malicious is
// wrong somewhere on almost any large code base: each wrong verdict we measured on a clean
// app came from one rule matching one or two lines. So findings and the verdict are separate:
//   - a sign is a high or critical finding about malware, the supply chain or agent files;
//   - a verdict needs a sign from a rule that has earned it (data/rule-trust.json, measured by
//     bench/calibrate.mjs: it flags malicious samples alone and almost never clean ones), or
//     two different rules pointing at the same file, or a sign in a file an install script starts.
// Signs without a verdict are leads: reported in full, for a reader, and no reason to stop.
// A rule written after the last calibration is a sign until it has a record.
import fs from "node:fs";

let trusted = new Set();
try { trusted = new Set(JSON.parse(fs.readFileSync(new URL("./data/rule-trust.json", import.meta.url), "utf8")).decides); } catch { /* no table: every rule is a sign */ }
const CATEGORIES = new Set(["malware", "supply-chain", "agent"]);

/** { level: "critical" | "high" | null, decided: findings behind the verdict, leads: signs that did not make one, signs }. */
export function verdict(findings, { anywhere = false, install = true } = {}) {
  const signs = findings.filter(f => CATEGORIES.has(f.category) && f.confidence !== "low" && (f.severity === "critical" || f.severity === "high"));
  let decided = signs.filter(f => trusted.has(f.rule));
  if (!decided.length) {
    // Two different rules about one file corroborate each other (anywhere: about one target, for measuring).
    const rulesAt = new Map();
    for (const f of signs) { const k = anywhere ? "" : f.file; if (!rulesAt.has(k)) rulesAt.set(k, new Set()); rulesAt.get(k).add(f.rule); }
    // A sign in a file that an install script starts is corroborated by where it is: that code runs before anyone chose to run it.
    decided = signs.filter(f => rulesAt.get(anywhere ? "" : f.file).size >= 2 || (install && f.atInstall));
  }
  const level = decided.some(f => f.severity === "critical") ? "critical" : decided.length ? "high" : null;
  return { level, decided, leads: signs.filter(f => !decided.includes(f)), signs };
}
export const decidesAlone = rule => trusted.has(rule);
