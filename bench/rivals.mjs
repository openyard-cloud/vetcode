#!/usr/bin/env node
// Runs another scanner on exactly the samples vetcode is scored on, so the comparison is
// head to head on the same data. Static only: samples are unpacked, scanned and deleted.
//
//   node bench/rivals.mjs --tool guarddog --bin <path/to/guarddog> --cache <dir> --out <dir>
//                         [--only npm,pypi] [--shard i/n]
//
// GuardDog 3.x reports informational "capability" rules, "threat" rules and a risk score.
// To be fair to it, four verdicts are scored and the report uses GuardDog's best:
// any issue (what the papers used), any threat rule, risk score >= 5, risk score >= 7.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const arg = (k, d) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : d; };
const TOOL = arg("--tool", "guarddog"), BIN = arg("--bin", "guarddog");
const CACHE = path.resolve(arg("--cache", path.join(os.tmpdir(), "vetcode-bench")));
const OUT = path.resolve(arg("--out", "bench/results-rivals"));
const ONLY = arg("--only", "npm,pypi").split(",");
const [SHARD, SHARDS] = arg("--shard", "0/1").split("/").map(Number);

function unpack(file, into) {
  fs.mkdirSync(into, { recursive: true });
  const r = file.endsWith(".zip") ? spawnSync("unzip", ["-qq", "-o", "-P", "infected", file, "-d", into]) : spawnSync("tar", ["-xzf", file, "-C", into]);
  return r.status === 0 || fs.readdirSync(into).length > 0;
}
function remove(dir) { spawnSync("chmod", ["-R", "u+rwX", dir]); spawnSync("rm", ["-rf", dir]); }

function guarddog(eco, dir) {
  const r = spawnSync(BIN, [eco, "scan", dir, "--output-format", "json"], { encoding: "utf8", timeout: 300_000, maxBuffer: 64 << 20 });
  const start = (r.stdout || "").indexOf("{");
  try {
    const j = JSON.parse(r.stdout.slice(start));
    const rules = Object.entries(j.results || {}).filter(([, v]) => v && (Array.isArray(v) ? v.length : typeof v === "object" ? Object.keys(v).length : v)).map(([k]) => k);
    const score = j.risk_score?.score ?? 0;
    return { rules, verdicts: { anyIssue: (j.issues || 0) > 0, anyThreat: rules.some(k => !k.startsWith("capability-")), score5: score >= 5, score7: score >= 7 } };
  } catch { return { error: true, rules: [], verdicts: { anyIssue: false, anyThreat: false, score5: false, score7: false } }; }
}

const work = fs.mkdtempSync(path.join(os.tmpdir(), "vetcode-rivals-"));
const results = [];
for (const eco of ["npm", "pypi"].filter(e => ONLY.includes(e))) {
  const rows = [];
  for (const label of ["malicious", "benign"]) {
    const d = path.join(CACHE, eco, label);
    if (!fs.existsSync(d)) continue;
    const files = fs.readdirSync(d).sort().filter((_, i) => i % SHARDS === SHARD);
    for (const f of files) {
      const dir = path.join(work, `${eco}-${label}-${f}`);
      if (!unpack(path.join(d, f), dir)) { remove(dir); continue; }
      const v = guarddog(eco, dir);
      rows.push({ id: f, label, ...v });
      remove(dir);
    }
  }
  const metrics = {};
  for (const v of ["anyIssue", "anyThreat", "score5", "score7"]) {
    const c = { tp: 0, fn: 0, fp: 0, tn: 0 };
    for (const r of rows) c[r.label === "malicious" ? (r.verdicts[v] ? "tp" : "fn") : (r.verdicts[v] ? "fp" : "tn")]++;
    const p = c.tp / (c.tp + c.fp || 1), rc = c.tp / (c.tp + c.fn || 1);
    metrics[v] = { ...c, precision: p, recall: rc, f1: 2 * p * rc / (p + rc || 1), accuracy: (c.tp + c.tn) / (rows.length || 1), fpr: c.fp / (c.fp + c.tn || 1) };
  }
  const best = Object.entries(metrics).sort((a, b) => b[1].f1 - a[1].f1)[0];
  metrics.high = { ...best[1], verdict: best[0] };
  for (const r of rows) r.flagged = r.verdicts[best[0]];
  const count = label => Object.entries(rows.filter(r => r.label === label).flatMap(r => r.rules).reduce((m, k) => (m[k] = (m[k] || 0) + 1, m), {})).sort((a, b) => b[1] - a[1]);
  results.push({ name: eco, samples: { malicious: rows.filter(r => r.label === "malicious").length, benign: rows.filter(r => r.label === "benign").length }, metrics,
    rulesOnMalicious: count("malicious"), rulesOnBenign: count("benign"), missed: rows.filter(r => r.label === "malicious" && !r.flagged).map(r => r.id),
    falseAlarms: rows.filter(r => r.label === "benign" && r.flagged).map(r => ({ id: r.id, rules: r.rules })), errors: rows.filter(r => r.error).length });
  console.error(`${TOOL} ${eco}: ${rows.length} samples · best F1 ${(metrics.high.f1 * 100).toFixed(1)}% (${metrics.high.verdict}) · ${Object.entries(metrics).filter(([k]) => k !== "high").map(([k, m]) => `${k} ${(m.f1 * 100).toFixed(1)}`).join(", ")} · errors ${results.at(-1).errors}`);
}
remove(work);
fs.mkdirSync(OUT, { recursive: true });
const stamp = new Date().toISOString().slice(0, 10);
fs.writeFileSync(path.join(OUT, `${stamp}${SHARDS > 1 ? `.shard${SHARD}` : ""}.json`), JSON.stringify({ version: `${TOOL}`, date: stamp, results }, null, 2));
