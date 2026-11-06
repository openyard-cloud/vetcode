#!/usr/bin/env node
// Merges the shard files written by run.mjs --shard into one result.
//   node bench/merge.mjs <folder>
import fs from "node:fs";
import path from "node:path";

const dir = process.argv[2];
const parts = fs.readdirSync(dir).filter(f => /\.shard\d+\.json$/.test(f)).map(f => JSON.parse(fs.readFileSync(path.join(dir, f), "utf8")));
const merged = new Map();
for (const p of parts) for (const r of p.results) {
  const m = merged.get(r.name) || { name: r.name, samples: { malicious: 0, benign: 0 }, counts: Object.fromEntries(Object.keys(r.metrics).map(t => [t, { tp: 0, fn: 0, fp: 0, tn: 0 }])), rulesOnMalicious: {}, rulesOnBenign: {}, missed: [], falseAlarms: [] };
  m.samples.malicious += r.samples.malicious; m.samples.benign += r.samples.benign;
  for (const t of Object.keys(r.metrics)) for (const k of ["tp", "fn", "fp", "tn"]) m.counts[t][k] += r.metrics[t][k];
  for (const key of ["rulesOnMalicious", "rulesOnBenign"]) for (const [id, n] of r[key]) m[key][id] = (m[key][id] || 0) + n;
  m.missed.push(...r.missed); m.falseAlarms.push(...r.falseAlarms);
  merged.set(r.name, m);
}
const results = [...merged.values()].map(m => {
  const metrics = {};
  for (const [t, c] of Object.entries(m.counts)) {
    const p = c.tp / (c.tp + c.fp || 1), r = c.tp / (c.tp + c.fn || 1), n = c.tp + c.fn + c.fp + c.tn;
    metrics[t] = { ...c, precision: p, recall: r, f1: 2 * p * r / (p + r || 1), accuracy: (c.tp + c.tn) / n, fpr: c.fp / (c.fp + c.tn || 1) };
  }
  const sort = o => Object.entries(o).sort((a, b) => b[1] - a[1]);
  // Rival runs pick their best verdict after merging, so per-shard choices do not leak in.
  const named = Object.entries(metrics).filter(([k]) => k !== "high");
  if (named.length > 1 && !metrics.critical) { const best = named.sort((a, b) => b[1].f1 - a[1].f1)[0]; metrics.high = { ...best[1], verdict: best[0] }; }
  return { name: m.name, samples: m.samples, metrics, rulesOnMalicious: sort(m.rulesOnMalicious), rulesOnBenign: sort(m.rulesOnBenign), missed: m.missed, falseAlarms: m.falseAlarms };
});
const order = ["npm", "pypi", "skills"];
results.sort((a, b) => order.indexOf(a.name) - order.indexOf(b.name));
fs.writeFileSync(path.join(dir, `${parts[0].date}.json`), JSON.stringify({ version: parts[0].version, date: parts[0].date, results }, null, 2));
for (const r of results) console.error(`${r.name}: ${r.samples.malicious + r.samples.benign} samples · F1 ${(r.metrics.high.f1 * 100).toFixed(1)}%`);
