// Known vulnerabilities and known-malicious packages, from OSV.dev (the database behind
// GitHub advisories, PyPI, npm and the OpenSSF malicious-packages list). Only package
// names and versions are sent. Used with --online.
import { finding } from "./engine.mjs";

const API = "https://api.osv.dev/v1";

/** Exact versions pinned by the lockfiles and requirements we can read. */
export function lockedPackages(files) {
  const seen = new Map();
  const add = (ecosystem, name, version, file) => {
    if (!name || !version || !/^\d/.test(version)) return;
    const key = `${ecosystem}:${name}@${version}`;
    if (!seen.has(key)) seen.set(key, { ecosystem, name, version, file });
  };
  for (const f of files) {
    const base = f.rel.split("/").pop();
    if (base === "package-lock.json" || base === "npm-shrinkwrap.json") {
      let lock; try { lock = JSON.parse(f.text); } catch { continue; }
      if (lock.packages) for (const [k, m] of Object.entries(lock.packages)) { if (k && !m.link) add("npm", m.name || k.replace(/^.*node_modules\//, ""), m.version, f.rel); }
      else (function walk(deps) { for (const [n, m] of Object.entries(deps || {})) { add("npm", n, m.version, f.rel); walk(m.dependencies); } })(lock.dependencies);
    } else if (base === "yarn.lock") {
      for (const m of f.text.matchAll(/^"?(@?[^@\s"]+)@[^\n]*:\n\s+version:?\s+"?([^"\s]+)"?/gm)) add("npm", m[1], m[2], f.rel);
    } else if (base === "pnpm-lock.yaml") {
      for (const m of f.text.matchAll(/^\s{2}'?\/?(@?[^@\s'/]+(?:\/[^@\s']+)?)@(\d[^:('\s]*)/gm)) add("npm", m[1], m[2], f.rel);
    } else if (/^requirements[\w.-]*\.txt$/.test(base) || base === "constraints.txt") {
      for (const m of f.text.matchAll(/^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([0-9][^\s;#,]*)/gm)) add("PyPI", m[1], m[2], f.rel);
    } else if (base === "poetry.lock" || base === "uv.lock") {
      for (const m of f.text.matchAll(/\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"/g)) add("PyPI", m[1], m[2], f.rel);
    } else if (base === "go.sum") {
      for (const m of f.text.matchAll(/^(\S+)\s+v([^\s/]+?)(?:\/go\.mod)?\s/gm)) add("Go", m[1], m[2], f.rel);
    }
  }
  return [...seen.values()];
}

const SEV = { CRITICAL: "critical", HIGH: "high", MODERATE: "medium", MEDIUM: "medium", LOW: "low" };

async function post(url, body) {
  const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body), signal: AbortSignal.timeout(30000) });
  if (!r.ok) throw new Error(`OSV ${r.status}`);
  return r.json();
}

export async function queryOsv(pkgs, out, log = () => {}) {
  const hits = [];
  for (let i = 0; i < pkgs.length; i += 1000) {
    const batch = pkgs.slice(i, i + 1000);
    const res = await post(`${API}/querybatch`, { queries: batch.map(p => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })) });
    res.results.forEach((r, j) => (r.vulns || []).forEach(v => hits.push({ pkg: batch[j], id: v.id })));
  }
  log(`OSV: ${pkgs.length} packages checked, ${hits.length} advisories`);
  const ids = [...new Set(hits.map(h => h.id))].slice(0, 300);
  const details = new Map();
  await Promise.all(ids.map(async id => {
    try { const r = await fetch(`${API}/vulns/${id}`, { signal: AbortSignal.timeout(20000) }); if (r.ok) details.set(id, await r.json()); } catch {}
  }));
  for (const { pkg, id } of hits) {
    const v = details.get(id) || { id };
    const malicious = id.startsWith("MAL-");
    const fixed = [...new Set((v.affected || []).filter(a => a.package?.name === pkg.name).flatMap(a => (a.ranges || []).flatMap(r => (r.events || []).map(e => e.fixed).filter(Boolean))))];
    const severity = malicious ? "critical" : SEV[String(v.database_specific?.severity || "").toUpperCase()] || "medium";
    out.push(finding({
      id: malicious ? "osv-malicious-package" : "osv-vulnerable-dependency", category: malicious ? "malware" : "supply-chain", severity, confidence: "high",
      title: malicious ? `Known malicious package: ${pkg.name}@${pkg.version}` : `${pkg.name}@${pkg.version}: ${v.summary || id}`,
      why: malicious ? "OSV lists this exact package as malware. If it was ever installed, its code already ran on that machine." : (v.details || v.summary || "Known vulnerability.").split("\n")[0].slice(0, 300),
      fix: malicious ? "Remove it, then treat every credential reachable from the machine (tokens, keys, browser sessions, wallets) as stolen and rotate them." : fixed.length ? `Upgrade to ${fixed.join(" or ")} or later.` : "No fixed version listed; check the advisory for workarounds or replace the package.",
    }, pkg.file, 1, `${pkg.ecosystem} ${pkg.name}@${pkg.version} · ${[id, ...(v.aliases || [])].slice(0, 3).join(", ")}`));
  }
}
