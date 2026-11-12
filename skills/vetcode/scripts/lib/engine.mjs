// Runs line rules over a file and builds findings. A rule is plain data:
//   { id, category, severity, title, re, files?, skip?, unless?, unlessFile?, why, fix, confidence }
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
export const TEST = /(^|\/)(tests?|testdata|__tests__|spec|specs|fixtures?|__fixtures__|__mocks__|examples?|samples?)\/|(^|\/)(?:[\w.]+[-_])?(?:tests|specs|e2e|cypress|playwright)\/|(^|\/)tests?[-_](?:utils?|helpers?|data|support)\/|\.(test|spec)\.\w+$|_test\.\w+$|(^|\/)test_[\w-]+\.\w+$/i;

// Third-party code copied into the repository, as opposed to the project's own.
export const VENDORED = /(^|\/)(vendor|vendors|third[_-]party|bower_components)\/|(^|\/)(public|static|assets|resources)\/(?:.*\/)?(lib|libs|vendor)\/|\.min\.(?:js|css)$|\.dart\.js$|(^|\/)assets\/[\w.-]+-[A-Za-z0-9_-]{8}\.(?:js|css)$|(^|\/)(?:vue|jquery|bootstrap|angular|lodash|underscore|d3|moment|leaflet|tinymce|codemirror|popper|alpine|htmx|chart|three|axios)(?:[.-][\w.-]*)?\.js$/i;
// Translated text: every sentence about passwords and hashes is a string here.
export const LOCALE = /(^|\/)(locales?|i18n|l10n|lang|langs|languages|translations?)\/|\.(po|pot|arb|xlf|xliff|strings|resx)$|(^|\/)(messages|strings|translations?)[._-][\w-]+\.(json|ya?ml|properties)$/i;
// Scripts a maintainer runs by hand, and the containers used to develop or test. Nothing a
// visitor sends reaches them.
// A package manager committed into the project (Yarn's own release and plugins, Plug'n'Play
// loaders): generated, megabytes of minified code in which every pattern matches something.
export const TOOLCHAIN = /(^|\/)\.yarn\/(?:releases|plugins|sdks)\/|(^|\/)\.pnp\.(?:c?js|loader\.mjs)$/;
export const DEVTOOL = /(^|\/)(scripts?|extra|release|hack|ci|\.ci|\.devcontainer|\.github|devtools|benchmarks?|migrations?|migrate|alembic)\//i;
export const DEVSTACK = /(^|\/)\.(?:devcontainer|ci|circleci)\/|(^|\/)(?:docker-)?compose[\w.-]*[.-](?:dev|tests?|local|e2e|ci)[\w.-]*\.ya?ml$|(^|\/)[\w.-]*test[\w.-]*\//i;

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

const HEAD_OK = /\.(?:pyw?|sh|bash|zsh|ps1|bat|cmd|rb|php|pl)$/i;
export function scanLines(file, text, rules, out) {
  const applicable = rules.filter(r => (!r.files || r.files.test(file.rel)) && !(r.skip && r.skip.test(file.rel)) && (!r.requires || r.requires.test(text)) && !(r.unlessFile && r.unlessFile.test(text)) && presentIn(text, r));
  if (!applicable.length) return;
  const lines = text.split(/\r?\n/);
  const longOk = applicable.some(r => r.longLines);
  for (let i = 0; i < lines.length; i++) {
    const full = lines[i], long = full.length > 5000;
    // A payload makes its line enormous, and `exec(b64decode('…` sits at the start of it: in
    // scripts, malware rules read the head of a long line. JavaScript is left out, because there a
    // long line is almost always a bundle, where eval and base64 near each other mean nothing.
    if (long && !longOk && !HEAD_OK.test(file.rel)) continue;
    const line = long && !longOk ? full.slice(0, 3000) : full;
    for (const r of applicable) {
      if (long && !r.longLines && r.category !== "malware") continue;
      r.re.lastIndex = 0;
      const m = r.re.exec(line);
      // unless: the line is the harmless form. unlessNot: only that form counts (the mirror rule).
      if (!m || (r.unless && r.unless.test(line)) || (r.unlessNot && !r.unlessNot.test(line)) || suppressedHere(lines, i, file.rel, r.id)) continue;
      // perFile: the same decision repeated down a file is one thing to check, not twenty.
      const first = r.perFile && out.find(f => f.rule === r.id && f.file === file.rel);
      if (first) { first.count = (first.count || 1) + 1; first.title = `${r.title} (${first.count} places in this file)`; continue; }
      out.push(finding(r, file.rel, i + 1, r.longLines ? m[0] : line.slice(0, 400)));
    }
  }
}

// Whole-file rules: { ...rule, test(text) -> [{ line, evidence }] }
export function scanFile(file, text, rules, out) {
  for (const r of rules) {
    if ((r.files && !r.files.test(file.rel)) || (r.skip && r.skip.test(file.rel))) continue;
    for (const hit of r.test(text, file) || []) out.push(finding(r, file.rel, hit.line, hit.evidence, hit.extra));
  }
}

export const lineOf = (text, index) => text.slice(0, index).split("\n").length;
