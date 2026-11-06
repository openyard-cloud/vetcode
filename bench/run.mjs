#!/usr/bin/env node
// Scans every cached sample with vetcode and scores the verdicts.
//
//   node bench/run.mjs --cache <dir> [--out bench/results]
//
// Each archive is unpacked into its own empty folder, scanned read-only, and deleted.
// Verdict: a package is "flagged" when vetcode reports at least one finding at the chosen
// severity or worse in the malware, supply-chain or agent categories (web/config findings
// are vulnerabilities, not malice). Scored at two thresholds: high (default) and critical.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { vet, VERSION } from "../skills/vetcode/scripts/lib/index.mjs";

const arg = (k, d) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : d; };
const CACHE = path.resolve(arg("--cache", path.join(os.tmpdir(), "vetcode-bench")));
const OUT = path.resolve(arg("--out", "bench/results"));
const ONLY = arg("--only", "npm,pypi,skills").split(",");
// --shard i/n scores every n-th sample starting at i, so n processes can run side by side
// (merge their JSON with bench/merge.mjs).
const [SHARD, SHARDS] = arg("--shard", "0/1").split("/").map(Number);
const mine = list => list.filter((_, i) => i % SHARDS === SHARD);
const CATS = new Set(["malware", "supply-chain", "agent"]);
const RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// Packages can ship read-only folders; make them writable so cleanup cannot stop the run.
function remove(dir) {
  spawnSync("chmod", ["-R", "u+rwX", dir]);
  try { fs.rmSync(dir, { recursive: true, force: true, maxRetries: 3 }); } catch { spawnSync("rm", ["-rf", dir]); }
}

function unpack(file, into) {
  fs.mkdirSync(into, { recursive: true });
  const r = file.endsWith(".zip")
    ? spawnSync("unzip", ["-qq", "-o", "-P", "infected", file, "-d", into])
    : spawnSync("tar", ["-xzf", file, "-C", into]);
  return r.status === 0 || fs.readdirSync(into).length > 0;
}

// One benign sample per skill folder (a directory holding SKILL.md) in the collections.
function benignSkills(work) {
  const dir = path.join(CACHE, "skills", "benign-collections"), out = [];
  if (!fs.existsSync(dir)) return out;
  for (const f of fs.readdirSync(dir)) {
    const into = path.join(work, "collections", f);
    if (!unpack(path.join(dir, f), into)) continue;
    const walk = d => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) { if (fs.existsSync(path.join(p, "SKILL.md"))) out.push({ id: `${f}:${e.name}`, dir: p }); else walk(p); } } };
    walk(into);
  }
  return out;
}

async function score(name, items) {
  const rows = [];
  for (const it of items) {
    const res = await vet(it.dir, { tools: false, noIgnore: true });
    // Same as --fail-on: low-confidence findings (tests, docs) do not decide the verdict.
    const hits = res.findings.filter(f => CATS.has(f.category) && f.confidence !== "low");
    const worst = hits.reduce((m, f) => Math.min(m, RANK[f.severity]), 9);
    rows.push({ id: it.id, label: it.label, worst, rules: [...new Set(hits.filter(f => RANK[f.severity] <= 1).map(f => f.rule))], files: res.stats.files });
    if (it.cleanup) remove(it.dir);
  }
  const metrics = {};
  for (const [t, max] of [["high", 1], ["critical", 0]]) {
    const tp = rows.filter(r => r.label === "malicious" && r.worst <= max).length, fn = rows.filter(r => r.label === "malicious" && r.worst > max).length;
    const fp = rows.filter(r => r.label === "benign" && r.worst <= max).length, tn = rows.filter(r => r.label === "benign" && r.worst > max).length;
    const p = tp / (tp + fp || 1), rcl = tp / (tp + fn || 1);
    metrics[t] = { tp, fn, fp, tn, precision: p, recall: rcl, f1: 2 * p * rcl / (p + rcl || 1), accuracy: (tp + tn) / rows.length, fpr: fp / (fp + tn || 1) };
  }
  const ruleCount = label => Object.entries(rows.filter(r => r.label === label).flatMap(r => r.rules).reduce((m, k) => (m[k] = (m[k] || 0) + 1, m), {})).sort((a, b) => b[1] - a[1]);
  console.error(`${name}: ${rows.length} samples · F1 ${(metrics.high.f1 * 100).toFixed(1)}% (high) · ${(metrics.critical.f1 * 100).toFixed(1)}% (critical)`);
  return { name, samples: { malicious: rows.filter(r => r.label === "malicious").length, benign: rows.filter(r => r.label === "benign").length }, metrics, rulesOnMalicious: ruleCount("malicious"), rulesOnBenign: ruleCount("benign"), missed: rows.filter(r => r.label === "malicious" && r.worst > 1).map(r => r.id), falseAlarms: rows.filter(r => r.label === "benign" && r.worst <= 1).map(r => ({ id: r.id, rules: r.rules })) };
}

const work = fs.mkdtempSync(path.join(os.tmpdir(), "vetcode-bench-work-"));
const archives = (eco, label) => { const d = path.join(CACHE, eco, label); return fs.existsSync(d) ? mine(fs.readdirSync(d).sort()).map(f => ({ file: path.join(d, f), id: f, label })) : []; };
let seq = 0; // unique folder per sample across batches and datasets
const unpacked = list => list.map(a => { const dir = path.join(work, `${seq++}-${a.label}`); return unpack(a.file, dir) ? { id: a.id, label: a.label, dir, cleanup: true } : null; }).filter(Boolean);

const results = [];
for (const eco of ["npm", "pypi"].filter(e => ONLY.includes(e))) {
  const list = [...archives(eco, "malicious"), ...archives(eco, "benign")];
  if (!list.length) continue;
  // Unpack and scan in batches so the disk never holds the whole set at once.
  const items = [];
  for (let i = 0; i < list.length; i += 200) items.push(...unpacked(list.slice(i, i + 200)));
  results.push(await score(eco, items));
}
const skillItems = ONLY.includes("skills") ? [...unpacked(archives("skills", "malicious")), ...mine(benignSkills(work)).map(s => ({ ...s, label: "benign" }))] : [];
if (skillItems.length) results.push(await score("skills", skillItems));
remove(work);

fs.mkdirSync(OUT, { recursive: true });
const stamp = new Date().toISOString().slice(0, 10);
fs.writeFileSync(path.join(OUT, `${stamp}${SHARDS > 1 ? `.shard${SHARD}` : ""}.json`), JSON.stringify({ version: VERSION, date: stamp, results }, null, 2));
console.error(`results: ${path.join(OUT, stamp + ".json")}`);
