// Uses dedicated scanners when they are installed: gitleaks (secrets, offline), and with
// --online semgrep (code), osv-scanner (dependencies) and trivy (containers, IaC).
// Their results are folded into the same report, tagged with the tool's name.
import { spawnSync } from "node:child_process";
import { finding } from "./engine.mjs";

const has = bin => spawnSync(process.platform === "win32" ? "where" : "which", [bin], { encoding: "utf8" }).status === 0;
const run = (bin, args, cwd) => spawnSync(bin, args, { cwd, encoding: "utf8", maxBuffer: 256 << 20, timeout: 10 * 60 * 1000 });
const json = s => { try { return JSON.parse(s); } catch { return null; } };
const SEV = { CRITICAL: "critical", HIGH: "high", ERROR: "high", MEDIUM: "medium", MODERATE: "medium", WARNING: "medium", LOW: "low", INFO: "info", UNKNOWN: "medium" };

export function availableTools() {
  return Object.fromEntries(["gitleaks", "zizmor", "semgrep", "osv-scanner", "trivy"].map(t => [t, has(t)]));
}

export function runTools(root, { online, only }, out, log) {
  const tools = availableTools();
  const used = [];
  if (tools.gitleaks) {
    // `gitleaks dir` replaced `detect --no-git` in 8.19; fall back for older installs.
    let r = run("gitleaks", ["dir", root, "--no-banner", "--redact", "--report-format", "json", "--report-path", "-"], root);
    if (!json(r.stdout)) r = run("gitleaks", ["detect", "--no-banner", "--no-git", "--redact", "--report-format", "json", "--report-path", "/dev/stdout", "--source", root], root);
    for (const g of json(r.stdout) || []) {
      // gitleaks has no severities; keys that are public by design are flagged for review only.
      const publicish = /gcp-api-key|firebase|publishable|pk_live|stripe-access-token-public|sentry-dsn/i.test(g.RuleID);
      out.push(finding({ id: `gitleaks-${g.RuleID}`, category: "secrets", severity: publicish ? "low" : "medium", confidence: "medium", title: `Possible secret (gitleaks: ${g.Description || g.RuleID})`,
        why: "gitleaks matched a credential pattern; check whether it is real and whether it is meant to be public.", fix: "If real: revoke and rotate it, then move it to an environment variable or secret store." }, g.File?.replace(root + "/", "") || "?", g.StartLine || 1, g.Match || "", { tool: "gitleaks" }));
    }
    used.push("gitleaks");
  }
  if (tools.zizmor) {
    // zizmor is offline with --offline; its SARIF is a stable interface across versions.
    const r = run("zizmor", ["--offline", "--format", "sarif", root], root);
    for (const res of json(r.stdout)?.runs?.[0]?.results || []) {
      const loc = res.locations?.[0]?.physicalLocation;
      out.push(finding({ id: `zizmor-${res.ruleId}`, category: "supply-chain", severity: res.level === "error" ? "high" : res.level === "warning" ? "medium" : "low", confidence: "high",
        title: `GitHub Actions: ${res.ruleId} (zizmor)`, why: res.message?.text?.slice(0, 300) || "", fix: `See https://docs.zizmor.sh/audits/#${res.ruleId}` },
        (loc?.artifactLocation?.uri || "").replace(/^file:\/\//, "").replace(root + "/", ""), loc?.region?.startLine || 1, res.message?.text?.slice(0, 120) || "", { tool: "zizmor" }));
    }
    used.push("zizmor");
  }
  if (!online) return used;
  if (tools.semgrep) {
    const r = run("semgrep", ["scan", "--config", "p/default", "--json", "--quiet", "--metrics", "off", ...(only?.length ? only : [root])], root);
    for (const s of json(r.stdout)?.results || []) {
      out.push(finding({ id: `semgrep-${s.check_id.split(".").pop()}`, category: "web", severity: SEV[s.extra?.severity] || "medium", confidence: "medium",
        title: (s.extra?.message || s.check_id).split("\n")[0].slice(0, 120), why: s.extra?.message?.slice(0, 400) || "", fix: s.extra?.fix || "See the rule documentation: " + (s.extra?.metadata?.source || s.check_id) }, s.path, s.start?.line || 1, s.extra?.lines || "", { tool: "semgrep" }));
    }
    used.push("semgrep");
  }
  if (tools["osv-scanner"]) {
    const r = run("osv-scanner", ["scan", "source", "-r", "--format", "json", root], root);
    for (const res of json(r.stdout)?.results || []) for (const p of res.packages || []) for (const v of p.vulnerabilities || []) {
      out.push(finding({ id: v.id.startsWith("MAL-") ? "osv-malicious-package" : "osv-vulnerable-dependency", category: v.id.startsWith("MAL-") ? "malware" : "supply-chain",
        severity: v.id.startsWith("MAL-") ? "critical" : SEV[String(v.database_specific?.severity || "").toUpperCase()] || "medium", confidence: "high",
        title: `${p.package.name}@${p.package.version}: ${v.summary || v.id}`, why: (v.details || "").split("\n")[0].slice(0, 300), fix: "Upgrade to a fixed version (see the advisory)." },
        (res.source?.path || "").replace(root + "/", ""), 1, `${p.package.ecosystem} ${p.package.name}@${p.package.version} · ${v.id}`, { tool: "osv-scanner" }));
    }
    used.push("osv-scanner");
  }
  if (tools.trivy) {
    const r = run("trivy", ["fs", "--quiet", "--scanners", "misconfig", "--format", "json", root], root);
    for (const res of json(r.stdout)?.Results || []) for (const m of res.Misconfigurations || []) {
      out.push(finding({ id: `trivy-${m.ID}`, category: "config", severity: SEV[m.Severity] || "medium", confidence: "medium", title: m.Title, why: m.Description || "", fix: m.Resolution || "" },
        res.Target, m.CauseMetadata?.StartLine || 1, m.Message || "", { tool: "trivy" }));
    }
    used.push("trivy");
  }
  if (used.length) log(`external tools: ${used.join(", ")}`);
  return used;
}
