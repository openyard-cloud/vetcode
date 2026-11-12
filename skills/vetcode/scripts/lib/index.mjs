// vet(root, opts): walks the project, runs every check, and returns { findings, stats }.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { walk, loadIgnore, installedPackages, readText, SKIP_DIRS_NO_GIT } from "./walk.mjs";
import { profiles, purposeMismatches } from "./profile.mjs";
import { npmHistory } from "./npmhistory.mjs";
import { scanLines, scanFile, options, rank, finding, SEVERITIES, TEST, VENDORED, LOCALE, DEVTOOL, DEVSTACK, TOOLCHAIN } from "./engine.mjs";
import { scanSecrets, scanSecretFiles, scanHistory } from "./secrets.mjs";
import { MALWARE_RULES, MALWARE_FILE_RULES } from "./malware.mjs";
import { WEB_RULES } from "./web.mjs";
import { LANG_RULES } from "./langs.mjs";
import { ECOSYSTEM_FILE_RULES } from "./ecosystems.mjs";
import { CONFIG_RULES, CONFIG_FILE_RULES, supabaseTablesWithoutRls } from "./config.mjs";
import { scanSupplyChain, scanInstalledPackage, scanProjectInstallEntries, scanPythonImportTime, hardeningAdvice, settleLookalikes } from "./supply.mjs";
import crypto from "node:crypto";
import { scanAgentFiles } from "./agent.mjs";
import { lockedPackages, queryOsv } from "./osv.mjs";
import { runTools } from "./tools.mjs";
import { checkMcpLock } from "./mcplock.mjs";
import { ANOMALY_FILE_RULES, scanBinaries, surprises } from "./anomaly.mjs";
import { decoded, payloads, stashed } from "./normalize.mjs";
import { verdict } from "./verdict.mjs";

const YARN_COPY = { id: "committed-package-manager", category: "supply-chain", severity: "low", confidence: "high", title: "The project runs a committed copy of Yarn",
  why: "With yarnPath set, every yarn command runs this file, on each developer's machine and in CI. It is far too large to review by eye, so a changed copy would go unnoticed.",
  fix: "Compare it with the official release: run vetcode with --online, or run `yarn set version <the same version>` and confirm git shows no change." };

/** Each committed Yarn release against the file Yarn publishes for that version (--online). */
async function yarnCopiesAreOfficial(copies, out, log) {
  const sha = buf => crypto.createHash("sha256").update(buf.toString("latin1").replace(/\r\n/g, "\n"), "latin1").digest("hex");
  for (const y of copies.slice(0, 5)) {
    try {
      const r = await fetch(`https://repo.yarnpkg.com/${y.version}/packages/yarnpkg-cli/bin/yarn.js`, { signal: AbortSignal.timeout(30000) });
      if (!r.ok) continue;
      const official = sha(Buffer.from(await r.arrayBuffer())), mine = sha(fs.readFileSync(y.abs));
      if (official === mine) { log(`${y.rel} is the official Yarn ${y.version}`); continue; }
      out.push(finding({ id: "package-manager-tampered", category: "supply-chain", severity: "critical", confidence: "high", title: `The committed Yarn ${y.version} is not the file Yarn published`,
        why: "This file runs on every yarn command. A copy that differs from the official release of the same version was changed by someone, and the change is hidden in megabytes of minified code.",
        fix: "Do not run yarn in this project. Replace the file with the official one (`yarn set version` from a clean machine) and find out who changed it and when (git log on the file)." }, y.rel, 1, `sha256 ${mine.slice(0, 16)}…, official ${official.slice(0, 16)}…`));
    } catch { /* could not be compared: say nothing */ }
  }
}

export const VERSION = "0.8.1";

/** Arguments for `git diff` from `base` to HEAD: changes since the branch point, or, in a
 *  shallow clone without that history (a pull request checkout in CI), straight against base. */
export function diffRange(root, base) {
  const mb = spawnSync("git", ["merge-base", base, "HEAD"], { cwd: root, encoding: "utf8" });
  return mb.status === 0 ? [`${base}...HEAD`] : [base, "HEAD"];
}

// Code hidden from patterns: run the malware rules again on the file with split strings
// joined and escapes decoded, and on base64 payloads it hands to eval/exec. Only what the
// plain text did not already show is added, at the line where the hiding happens.
function scanHidden(file, findings) {
  const views = [];
  const alt = decoded(file.text);
  if (alt) views.push({ text: alt, how: "once its split strings are joined and escapes decoded" });
  // Payloads inside payloads (packed, then packed again): unwrap up to three layers.
  const unwrapFrom = (text, line, depth) => {
    for (const p of [...payloads(text).map(x => ({ ...x, how: "inside a base64 payload it runs" })), ...stashed(text).map(x => ({ ...x, how: "inside an encoded string that decodes to code" }))]) {
      if (views.length > 20) return;
      views.push({ text: p.text, line: line ?? p.line, how: p.how });
      if (depth < 3) unwrapFrom(p.text, line ?? p.line, depth + 1);
    }
  };
  unwrapFrom(file.text, undefined, 1);
  if (!views.length) return;
  const seen = new Set(findings.filter(f => f.file === file.rel).map(f => f.rule));
  for (const v of views) {
    const found = [];
    scanLines(file, v.text, MALWARE_RULES, found);
    scanFile(file, v.text, MALWARE_FILE_RULES, found);
    for (const f of found) {
      if (seen.has(f.rule)) continue;
      seen.add(f.rule);
      findings.push({ ...f, line: v.line || f.line, title: `${f.title} (hidden)`, evidence: `${v.how}: ${f.evidence}`.slice(0, 160) });
    }
  }
}

/** Files changed against `base` (committed, staged, unstaged and untracked). */
export function changedFiles(root, base) {
  const git = args => spawnSync("git", args, { cwd: root, encoding: "utf8" });
  const top = git(["rev-parse", "--show-toplevel"]).stdout.trim();
  if (!top) throw new Error("--diff needs a git repository");
  const names = new Set();
  const add = r => r.stdout.split("\n").filter(Boolean).forEach(f => names.add(f));
  if (base) add(git(["diff", "--name-only", "--diff-filter=ACMR", ...diffRange(root, base)]));
  add(git(["diff", "--name-only", "--diff-filter=ACMR", "HEAD"]));
  add(git(["ls-files", "--others", "--exclude-standard"]));
  const prefix = path.relative(top, root).split(path.sep).join("/");
  return [...names].map(f => f.trim()).filter(f => !prefix || f.startsWith(prefix + "/")).map(f => (prefix ? f.slice(prefix.length + 1) : f));
}

function gitFiles(root) {
  const r = spawnSync("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], { cwd: root, encoding: "utf8", maxBuffer: 256 << 20 });
  if (r.status !== 0) return null;
  return r.stdout.split("\0").filter(Boolean).filter(f => !/(^|\/)node_modules\//.test(f));
}

export async function vet(target, opts = {}) {
  const root = fs.realpathSync(path.resolve(target));
  const log = opts.log || (() => {});
  const started = Date.now();
  options.inline = !opts.noIgnore;
  options.suppressed = new Set();
  const ignore = opts.noIgnore ? [] : loadIgnore(root);
  const only = opts.diff !== undefined ? changedFiles(root, opts.diff || null) : null;
  // In a git repository, read what git sees (tracked + untracked, minus .gitignore'd
  // build output); outside one, read everything.
  const listed = only || gitFiles(root);
  const findings = [];
  const files = [];
  const partial = [];
  const yarnCopies = [];
  // Only a file as big as the real thing: a small script under .yarn/ is read like any other.
  const committedTool = (file, from) => {
    if (!TOOLCHAIN.test(file.rel) || !(file.partial || file.text.length > 200_000)) return false;
    for (let i = from; i < findings.length; i++) findings[i].confidence = "low";
    const yarn = /(^|\/)\.yarn\/releases\/yarn-(\d+\.\d+\.\d+)\.cjs$/.exec(file.rel);
    if (yarn) { findings.push(finding(YARN_COPY, file.rel, 1, `yarn ${yarn[2]}`)); yarnCopies.push({ rel: file.rel, abs: file.abs, version: yarn[2] }); }
    return true;
  };
  for (const file of walk(root, { ignore, only: listed, ...(listed ? {} : { skipDirs: SKIP_DIRS_NO_GIT }) })) {
    if (file.partial) {
      // Too big to read whole: secrets and malware checks on its first and last 256 KB.
      const from = findings.length;
      scanSecrets(file, file.text, findings);
      scanLines(file, file.text, MALWARE_RULES, findings);
      scanFile(file, file.text, MALWARE_FILE_RULES, findings);
      // A committed package manager is expected to be this big; it is checked by comparison below, not by reading.
      if (committedTool(file, from)) continue;
      // More than a megabyte of JavaScript in one file is build output: its matches stay visible and decide nothing.
      if (/\.(c|m)?js$/.test(file.rel)) for (let i = from; i < findings.length; i++) if (findings[i].confidence === "medium") findings[i].confidence = "low";
      partial.push({ file: file.rel, bytes: file.partial });
      continue;
    }
    files.push(file);
    const mark = findings.length;
    scanAgentFiles(file, file.text, findings);
    scanSecrets(file, file.text, findings);
    scanLines(file, file.text, MALWARE_RULES, findings);
    scanFile(file, file.text, MALWARE_FILE_RULES, findings);
    scanHidden(file, findings);
    scanLines(file, file.text, WEB_RULES, findings);
    scanLines(file, file.text, LANG_RULES, findings);
    scanFile(file, file.text, ECOSYSTEM_FILE_RULES, findings);
    scanLines(file, file.text, CONFIG_RULES, findings);
    scanFile(file, file.text, CONFIG_FILE_RULES, findings);
    scanSupplyChain(file, file.text, findings, root);
    scanFile(file, file.text, ANOMALY_FILE_RULES, findings);
    // A vulnerability pattern in a test, a fixture or a vendored library is not in the app's own
    // request path. Malware, secrets and supply-chain findings there still count.
    if (TEST.test(file.rel) || VENDORED.test(file.rel) || LOCALE.test(file.rel)) for (let k = findings.length - 1; k >= mark; k--) if (findings[k].category === "web") findings.splice(k, 1);
    // Maintainer scripts and development containers: kept, but as low. Secrets and malware there keep their severity.
    const dev = DEVTOOL.test(file.rel), stack = DEVSTACK.test(file.rel);
    if (dev || stack) for (let k = mark; k < findings.length; k++) {
      const f = findings[k];
      if (((dev && f.category === "web") || (stack && f.category === "config")) && rank(f.severity) < rank("low")) findings[k] = { ...f, severity: "low" };
    }
    // Bundled or minified output is full of patterns that mean nothing there; keep its findings
    // visible but let only high-confidence ones decide.
    // Only JavaScript ships that way on purpose: a one-line Python file or setup.py is itself
    // suspicious (that is how obfuscated payloads look), so those keep their confidence.
    if (/\.(c|m)?js$/.test(file.rel) && (/\.min\.|[-.]bundle\.|\.dart\.js$|(^|\/)(dist|out)\//.test(file.rel) || file.text.length / (file.text.split("\n").length || 1) > 300))
      for (let i = mark; i < findings.length; i++) if (findings[i].confidence === "medium") findings[i].confidence = "low";
    // A committed package manager matches every pattern and none of it means anything; its
    // findings stay visible but decide nothing. What matters is whether the file is the
    // official one, and that is a comparison (--online), not a pattern.
    committedTool(file, mark);
  }
  log(`${files.length} files read`);
  supabaseTablesWithoutRls(files, findings);
  scanBinaries(root, listed, findings);
  const prof = profiles(files);
  purposeMismatches(prof, findings);
  const atInstall = scanProjectInstallEntries(root, files, findings);
  // Where a finding sits matters as much as what it is: code an install script starts runs
  // before anyone chose to run it. The verdict counts that as evidence of its own.
  for (const f of findings) if (atInstall.has(f.file) || f.file === "setup.py") f.atInstall = true;
  scanPythonImportTime(files, findings);
  if (!only) hardeningAdvice(root, files, findings);
  const mcpLock = opts.mcpLock ? checkMcpLock(opts.mcpLock, files, findings) : null;
  if (!only) scanSecretFiles(root, findings);
  if (opts.history) { scanHistory(root, findings); log("git history checked for secrets"); }

  let packages = 0, withScripts = 0;
  if (opts.deps) {
    for (const dir of installedPackages(root)) {
      packages++;
      if (scanInstalledPackage(dir, root, findings)) {
        withScripts++;
        // Packages that run code at install get their files read too.
        for (const file of walk(dir, { skipDirs: new Set(["node_modules", ".git"]) })) {
          const rel = path.relative(root, file.abs).split(path.sep).join("/");
          const f = { ...file, rel };
          scanLines(f, file.text, MALWARE_RULES, findings);
          scanFile(f, file.text, MALWARE_FILE_RULES, findings);
        }
      }
    }
    log(`${packages} installed packages checked, ${withScripts} with install scripts read in full`);
  }

  const tools = opts.tools === false ? [] : runTools(root, { online: opts.online, only }, findings, log);
  let osv = "off";
  if (opts.online) {
    const pkgs = lockedPackages(files);
    try { await queryOsv(pkgs, findings, log); osv = `${pkgs.length} packages`; }
    catch (e) { osv = `failed (${e.message})`; log(`OSV lookup failed: ${e.message}`); }
    await npmHistory(files, findings, log);
    await settleLookalikes(findings, log);
  }
  // The guard asks for this alone: it already uses the network, and sends nothing about the project.
  if (opts.online || opts.verifyTools) await yarnCopiesAreOfficial(yarnCopies, findings, log);

  // Same rule on the same line from two sources (e.g. built-in + gitleaks) is reported once.
  const seen = new Set();
  const unique = findings.filter(f => { const k = `${f.rule}|${f.file}|${f.line}|${f.evidence}`; if (seen.has(k)) return false; seen.add(k); return true; })
    .sort((a, b) => rank(a.severity) - rank(b.severity) || a.category.localeCompare(b.category) || a.file.localeCompare(b.file) || a.line - b.line);
  // A fingerprint without the line number, so findings survive unrelated edits above them.
  for (const f of unique) f.fingerprint = crypto.createHash("sha256").update(`${f.rule}|${f.file}|${f.evidence}`).digest("hex").slice(0, 16);
  let baselined = 0, reported = unique;
  if (opts.baseline) {
    const known = new Set((JSON.parse(fs.readFileSync(opts.baseline, "utf8")).findings || []).map(f => f.fingerprint));
    reported = unique.filter(f => !known.has(f.fingerprint));
    baselined = unique.length - reported.length;
  }
  const counts = Object.fromEntries(SEVERITIES.map(s => [s, reported.filter(f => f.severity === s).length]));
  // The answer to "is this safe to install or run": a verdict, or the places to read when there is none.
  const v = verdict(reported), brief = f => ({ rule: f.rule, severity: f.severity, file: f.file, line: f.line, title: f.title });
  return {
    verdict: { level: v.level, decided: v.decided.map(brief), leads: v.leads.map(brief) },
    version: VERSION, target: root, mode: only ? `diff${opts.diff ? ` vs ${opts.diff}` : ""}` : "full",
    stats: { files: files.length, packages, ms: Date.now() - started, counts, tools, osv, history: !!opts.history,
      ignoreFile: ignore.length ? ".vetcodeignore" : null, ignorePatterns: ignore.length, suppressedLines: options.suppressed.size, partial, baselined, mcpLock },
    surprises: surprises(files, reported),
    profiles: prof.map(({ kind, name, file, purpose, capabilities }) => ({ kind, name, file, purpose, capabilities })),
    findings: reported,
  };
}

export { readText };
