// Turns scan results into a Markdown report for people (and for Claude to triage).
import { SEVERITIES } from "./engine.mjs";

const ICON = { critical: "🟥", high: "🟧", medium: "🟨", low: "🟦", info: "⬜" };
const PER_RULE = 15;
const code = s => "`" + String(s).replace(/`/g, "ˋ") + "`";

// What the malware, supply-chain and agent findings add up to. A verdict takes a rule with a
// measured record or two rules on one file; one unproven rule matching somewhere is a place to read.
function verdictLines(v) {
  if (!v) return [];
  const at = f => `${code(f.line ? `${f.file}:${f.line}` : f.file)} ${f.title}`;
  if (v.level) return [``, `**Verdict: ${v.level === "critical" ? "malicious" : "likely malicious"}.** Do not install, build or run it. Decided by: ${v.decided.slice(0, 4).map(at).join("; ")}${v.decided.length > 4 ? `; and ${v.decided.length - 4} more` : ""}.`];
  if (v.leads.length) return [``, `**No verdict.** ${v.leads.length} sign${v.leads.length === 1 ? "" : "s"} of malware or of an attack on agents that one rule alone does not settle: read ${v.leads.slice(0, 4).map(at).join("; ")}${v.leads.length > 4 ? `; and ${v.leads.length - 4} more` : ""}.`];
  return [``, `**No verdict and no sign of malware.** That covers what patterns can see, not logic flaws or new techniques.`];
}

export function markdown(result) {
  const { stats, findings } = result;
  const c = stats.counts;
  const out = [
    `# vetcode report`,
    ``,
    `**Target:** ${code(result.target)} · **mode:** ${result.mode} · **files:** ${stats.files}${stats.packages ? ` · **installed packages:** ${stats.packages}` : ""} · ${(stats.ms / 1000).toFixed(1)} s`,
    ``,
    `**Findings:** ${SEVERITIES.map(s => `${ICON[s]} ${s} ${c[s]}`).join(" · ")}`,
    ...verdictLines(result.verdict),
    ``,
    `Checks: built-in rules${stats.tools.length ? ` + ${stats.tools.join(", ")}` : ""} · OSV lookup: ${stats.osv} · git history: ${stats.history ? "yes" : "no"}`,
  ];
  if (stats.ignorePatterns || stats.suppressedLines) out.push(``, `> ⚠️ ${stats.ignorePatterns ? `${stats.ignorePatterns} pattern(s) from .vetcodeignore` : ""}${stats.ignorePatterns && stats.suppressedLines ? " and " : ""}${stats.suppressedLines ? `${stats.suppressedLines} line(s) with vetcode-ignore comments` : ""} were skipped. For code you did not write, run again with --no-ignore.`);
  if (stats.baselined) out.push(``, `${stats.baselined} finding(s) already in the baseline are not shown.`);
  if (stats.mcpLock) out.push(``, `MCP lock: ${stats.mcpLock}.`);
  if (stats.partial?.length) out.push(``, `> ⚠️ ${stats.partial.length} file(s) over 1 MB were only partly read (first and last 256 KB, secrets and malware checks): ${stats.partial.slice(0, 5).map(p => code(p.file)).join(", ")}${stats.partial.length > 5 ? " …" : ""}. Read them yourself if they are not known bundles.`);
  const told = (result.profiles || []).filter(p => Object.keys(p.capabilities).length);
  if (told.length) {
    out.push(``, `## What it says vs what it does`, ``);
    for (const p of told.slice(0, 8)) out.push(`- **${p.name}** (${p.kind}): "${(p.purpose || "no description").slice(0, 100)}" → ${Object.entries(p.capabilities).map(([c, fs]) => `${c} (${fs.length} file${fs.length > 1 ? "s" : ""})`).join("; ")}`);
  }
  if (result.surprises?.length) {
    out.push(``, `## Read these files first`, ``, `The strangest files in the project, whether or not a rule fired: check that the project's purpose explains each one.`, ``);
    for (const s of result.surprises) out.push(`- ${code(s.file)} · ${s.why}`);
  }
  if (!findings.length) {
    out.push(``, `No candidates found. This is not proof of safety: logic flaws, authorization gaps and new malware need a manual review.`);
    return out.join("\n") + "\n";
  }
  out.push(``, `Each item is a **candidate** found by pattern: confirm it by reading the code before acting on it.`);
  for (const sev of SEVERITIES) {
    const group = findings.filter(f => f.severity === sev);
    if (!group.length) continue;
    out.push(``, `## ${ICON[sev]} ${sev[0].toUpperCase() + sev.slice(1)} (${group.length})`);
    const byRule = new Map();
    for (const f of group) { if (!byRule.has(f.rule)) byRule.set(f.rule, []); byRule.get(f.rule).push(f); }
    // Low and info: one line per rule. They are hygiene, rarely what the reader came for, and an
    // agent pays for every line; the JSON report has each one with its why and fix.
    if (sev === "low" || sev === "info") {
      out.push(``);
      for (const [rule, list] of byRule) {
        const where = list.slice(0, 3).map(f => code(f.line ? `${f.file}:${f.line}` : f.file)).join(", ");
        out.push(`- ${list[0].title} · ${code(rule)} · ${list.length}×: ${where}${list.length > 3 ? ` and ${list.length - 3} more` : ""}`);
      }
      continue;
    }
    for (const [rule, list] of byRule) {
      const f0 = list[0];
      out.push(``, `### ${f0.title} · ${code(rule)} · ${f0.category}${f0.tool ? ` · via ${f0.tool}` : ""}`, ``);
      for (const f of list.slice(0, PER_RULE)) out.push(`- ${code(f.line ? `${f.file}:${f.line}` : f.file)}${f.confidence === "low" ? " _(low confidence)_" : ""}${f.evidence ? ` ${code(f.evidence)}` : ""}`);
      if (list.length > PER_RULE) out.push(`- … and ${list.length - PER_RULE} more (see the JSON report)`);
      out.push(``, `**Why:** ${f0.why}`, ``, `**Fix:** ${f0.fix}`);
    }
  }
  return out.join("\n") + "\n";
}
