// vet(root, opts): walks the project, runs every check, and returns { findings, stats }.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { walk, loadIgnore, installedPackages, readText, SKIP_DIRS_NO_GIT } from "./walk.mjs";
import { profiles, purposeMismatches } from "./profile.mjs";
import { npmHistory } from "./npmhistory.mjs";
import { scanLines, scanFile, options, rank, SEVERITIES } from "./engine.mjs";
import { scanSecrets, scanSecretFiles, scanHistory } from "./secrets.mjs";
import { MALWARE_RULES, MALWARE_FILE_RULES } from "./malware.mjs";
import { WEB_RULES } from "./web.mjs";
import { CONFIG_RULES, CONFIG_FILE_RULES, supabaseTablesWithoutRls } from "./config.mjs";
import { scanSupplyChain, scanInstalledPackage, scanProjectInstallEntries, hardeningAdvice } from "./supply.mjs";
import crypto from "node:crypto";
import { scanAgentFiles } from "./agent.mjs";
import { lockedPackages, queryOsv } from "./osv.mjs";
import { runTools } from "./tools.mjs";
import { checkMcpLock } from "./mcplock.mjs";
import { ANOMALY_FILE_RULES, scanBinaries, surprises } from "./anomaly.mjs";

export const VERSION = "0.2.0";

/** Files changed against `base` (committed, staged, unstaged and untracked). */
export function changedFiles(root, base) {
  const git = args => spawnSync("git", args, { cwd: root, encoding: "utf8" });
  const top = git(["rev-parse", "--show-toplevel"]).stdout.trim();
  if (!top) throw new Error("--diff needs a git repository");
  const names = new Set();
  const add = r => r.stdout.split("\n").filter(Boolean).forEach(f => names.add(f));
  if (base) add(git(["diff", "--name-only", "--diff-filter=ACMR", `${base}...HEAD`]));
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
  for (const file of walk(root, { ignore, only: listed, ...(listed ? {} : { skipDirs: SKIP_DIRS_NO_GIT }) })) {
    if (file.partial) {
      // Too big to read whole: secrets and malware checks on its first and last 256 KB.
      partial.push({ file: file.rel, bytes: file.partial });
      scanSecrets(file, file.text, findings);
      scanLines(file, file.text, MALWARE_RULES, findings);
      scanFile(file, file.text, MALWARE_FILE_RULES, findings);
      continue;
    }
    files.push(file);
    const mark = findings.length;
    scanAgentFiles(file, file.text, findings);
    scanSecrets(file, file.text, findings);
    scanLines(file, file.text, MALWARE_RULES, findings);
    scanFile(file, file.text, MALWARE_FILE_RULES, findings);
    scanLines(file, file.text, WEB_RULES, findings);
    scanLines(file, file.text, CONFIG_RULES, findings);
    scanFile(file, file.text, CONFIG_FILE_RULES, findings);
    scanSupplyChain(file, file.text, findings);
    scanFile(file, file.text, ANOMALY_FILE_RULES, findings);
    // Bundled or minified output is full of patterns that mean nothing there; keep its findings
    // visible but let only high-confidence ones decide.
    // Only JavaScript ships that way on purpose: a one-line Python file or setup.py is itself
    // suspicious (that is how obfuscated payloads look), so those keep their confidence.
    if (/\.(c|m)?js$/.test(file.rel) && (/\.min\.|[-.]bundle\.|(^|\/)(dist|out)\//.test(file.rel) || file.text.length / (file.text.split("\n").length || 1) > 300))
      for (let i = mark; i < findings.length; i++) if (findings[i].confidence === "medium") findings[i].confidence = "low";
  }
  log(`${files.length} files read`);
  supabaseTablesWithoutRls(files, findings);
  scanBinaries(root, listed, findings);
  const prof = profiles(files);
  purposeMismatches(prof, findings);
  scanProjectInstallEntries(root, files, findings);
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
  }

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
  return {
    version: VERSION, target: root, mode: only ? `diff${opts.diff ? ` vs ${opts.diff}` : ""}` : "full",
    stats: { files: files.length, packages, ms: Date.now() - started, counts, tools, osv, history: !!opts.history,
      ignoreFile: ignore.length ? ".vetcodeignore" : null, ignorePatterns: ignore.length, suppressedLines: options.suppressed.size, partial, baselined, mcpLock },
    surprises: surprises(files, reported),
    profiles: prof.map(({ kind, name, file, purpose, capabilities }) => ({ kind, name, file, purpose, capabilities })),
    findings: reported,
  };
}

export { readText };
