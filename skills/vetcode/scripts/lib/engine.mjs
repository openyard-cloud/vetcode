// Runs line rules over a file and builds findings. A rule is plain data:
//   { id, category, severity, title, re, files?, skip?, unless?, why, fix, confidence }
// `files` limits it to matching paths, `skip` excludes paths, `unless` drops lines that
// also match (a sanitiser on the same line, an env lookup, ...), `requires` skips files
// whose text does not match (e.g. shell rules only where child_process is imported).
// A line containing `vetcode-ignore`, or following `vetcode-ignore-next-line`, is skipped.

// Inline `vetcode-ignore` comments are honoured unless --no-ignore (third-party code can
// use them to hide). Suppressed lines are counted and shown in the report.
// Only as a comment (`// vetcode-ignore`, `# vetcode-ignore`, ...), not anywhere in a string.
// `vetcode-ignore[rule-a,rule-b] reason` limits it to those rules (preferred).
const SUPPRESS = /(?:\/\/|#|\/\*|<!--|--)\s*vetcode-ignore(?!-next-line)(?:\[([\w,\s-]+)\])?/;
const NEXT = /(?:\/\/|#|\/\*|<!--|--)\s*vetcode-ignore-next-line(?:\[([\w,\s-]+)\])?/;
export const options = { inline: true, suppressed: new Set() };
export const suppressedHere = (lines, i, rel, ruleId) => {
  if (!options.inline) return false;
  const m = SUPPRESS.exec(lines[i]) || (i > 0 ? NEXT.exec(lines[i - 1]) : null);
  if (!m) return false;
  if (m[1] && ruleId && !m[1].split(/[\s,]+/).includes(ruleId)) return false;
  options.suppressed.add(`${rel}:${i + 1}`);
  return true;
};

export const SEVERITIES = ["critical", "high", "medium", "low", "info"];
export const rank = s => SEVERITIES.indexOf(s);

// Docs and tests describe attacks without being them; their findings are kept but marked.
export const DOC = /\.(md|mdx|markdown|rst|txt|adoc)$/i;
export const TEST = /(^|\/)(tests?|__tests__|spec|specs|fixtures?|__fixtures__|__mocks__|examples?|samples?)\/|\.(test|spec)\.\w+$|_test\.\w+$|(^|\/)test_\w+\.py$/i;

const clip = (s, n = 160) => { s = s.trim(); return s.length > n ? s.slice(0, n - 1) + "…" : s; };

export function finding(rule, file, line, evidence, extra = {}) {
  return {
    rule: rule.id, category: rule.category, severity: rule.severity, title: rule.title,
    file, line, evidence: clip(evidence ?? ""), why: rule.why, fix: rule.fix,
    confidence: TEST.test(file) ? "low" : rule.confidence ?? "medium", ...extra,
  };
}

// A line rule that matches no line cannot match the file either, unless it is anchored to the
// start or end of a line; one pass over the whole text drops most rules for most files.
const anchored = new WeakMap();
export function presentIn(text, r) {
  if (!anchored.has(r)) anchored.set(r, /(^|[^\\])[\^$]/.test(r.re.source.replace(/\\./g, "").replace(/\[[^\]]*\]/g, "")));
  if (anchored.get(r)) return true;
  r.re.lastIndex = 0;
  const hit = r.re.test(text);
  r.re.lastIndex = 0;
  return hit;
}

export function scanLines(file, text, rules, out) {
  const applicable = rules.filter(r => (!r.files || r.files.test(file.rel)) && !(r.skip && r.skip.test(file.rel)) && (!r.requires || r.requires.test(text)) && presentIn(text, r));
  if (!applicable.length) return;
  const lines = text.split(/\r?\n/);
  const longOk = applicable.some(r => r.longLines);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > 5000 && !longOk) continue;
    for (const r of applicable) {
      r.re.lastIndex = 0;
      const m = r.re.exec(line);
      if (!m || (r.unless && r.unless.test(line)) || suppressedHere(lines, i, file.rel, r.id)) continue;
      out.push(finding(r, file.rel, i + 1, r.longLines ? m[0] : line));
    }
  }
}

// Whole-file rules: { ...rule, test(text) -> [{ line, evidence }] }
export function scanFile(file, text, rules, out) {
  for (const r of rules) {
    if ((r.files && !r.files.test(file.rel)) || (r.skip && r.skip.test(file.rel))) continue;
    for (const hit of r.test(text, file) || []) out.push(finding(r, file.rel, hit.line, hit.evidence));
  }
}

export const lineOf = (text, index) => text.slice(0, index).split("\n").length;
