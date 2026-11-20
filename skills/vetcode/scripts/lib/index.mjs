// vet(root, opts): walks the project, runs every check, and returns { findings, stats }.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { walk, loadIgnore, installedPackages, readText, SKIP_DIRS_NO_GIT } from "./walk.mjs";
import { profiles, purposeMismatches } from "./profile.mjs";
import { crateProfiles, scanBuildTime } from "./rust.mjs";
import { npmHistory } from "./npmhistory.mjs";
import { scanLines, scanFile, options, rank, finding, SEVERITIES } from "./engine.mjs";
import { scanSecretFiles, scanHistory } from "./secrets.mjs";
import { MALWARE_RULES, MALWARE_FILE_RULES } from "./malware.mjs";
import { supabaseTablesWithoutRls } from "./config.mjs";
import { scanInstalledPackage, scanProjectInstallEntries, scanPythonImportTime, hardeningAdvice, settleLookalikes } from "./supply.mjs";
import crypto from "node:crypto";
import { kindOfRule, KINDS } from "./sinks.mjs";
import { lockedPackages, queryOsv } from "./osv.mjs";
import { runTools } from "./tools.mjs";
import { checkMcpLock } from "./mcplock.mjs";
import { scanBinaries, scanBytecode, surprises } from "./anomaly.mjs";
import { scanAll } from "./scan-pool.mjs";
import { forgetCapabilities } from "./capabilities.mjs";
import { verdict } from "./verdict.mjs";

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

// Rules measured to fire far more often on applications that are fine than on real bugs (bench/calibrate-web.mjs).
let PLACE_RULES = new Set();
try { PLACE_RULES = new Set(JSON.parse(fs.readFileSync(new URL("./data/web-places.json", import.meta.url), "utf8")).places); } catch {}

export const VERSION = "0.8.15";

/** Arguments for `git diff` from `base` to HEAD: changes since the branch point, or, in a
 *  shallow clone without that history (a pull request checkout in CI), straight against base. */
export function diffRange(root, base) {
  const mb = spawnSync("git", ["merge-base", base, "HEAD"], { cwd: root, encoding: "utf8" });
  return mb.status === 0 ? [`${base}...HEAD`] : [base, "HEAD"];
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
  options.owner = (opts.repo || "").split("/")[0].toLowerCase();
  forgetCapabilities();
  const ignore = opts.noIgnore ? [] : loadIgnore(root);
  const only = opts.diff !== undefined ? changedFiles(root, opts.diff || null) : null;
  // In a git repository, read what git sees (tracked + untracked, minus .gitignore'd
  // build output); outside one, read everything.
  const listed = only || gitFiles(root);
  const findings = [];
  const sinks = [];
  const files = [];
  const partial = [];
  const yarnCopies = [];
  // Each file is scanned on its own (perfile.mjs), on several threads for a big project.
  const walked = [...walk(root, { ignore, only: listed, ...(listed ? {} : { skipDirs: SKIP_DIRS_NO_GIT }) })];
  const scanned = await scanAll(walked, root);
  walked.forEach((file, i) => {
    const r = scanned[i];
    findings.push(...r.findings);
    sinks.push(...r.sinks);
    if (r.yarn) yarnCopies.push(r.yarn);
    if (!file.partial) files.push(file);
    else if (r.partial) partial.push({ file: file.rel, bytes: r.partial });
  });
  log(`${files.length} files read`);
  supabaseTablesWithoutRls(files, findings);
  scanBinaries(root, listed, findings);
  scanBytecode(root, listed, findings);
  const prof = profiles(files);
  purposeMismatches(prof, findings);
  const atInstall = scanProjectInstallEntries(root, files, findings);
  // Where a finding sits matters as much as what it is: code an install script starts runs
  // before anyone chose to run it. The verdict counts that as evidence of its own.
  // Rust build scripts and proc macros run during `cargo build`: the same standing as install scripts.
  const crates = crateProfiles(root, files);
  const atBuild = scanBuildTime(crates, findings);
  for (const f of findings) if (atInstall.has(f.file) || atBuild.has(f.file) || f.file === "setup.py") f.atInstall = true;
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
  // Findings and places. A rule that matches a dangerous call without seeing where its value comes
  // from reports a place to read, not a finding; so does the catalogue of such calls (sinks.mjs).
  // A place on a line that already has a finding of the same kind says nothing new.
  const places = [];
  // places: false keeps every rule a finding and lists no places (tests of single rules ask for that).
  if (opts.places !== false) reported = reported.filter(f => {
    const kind = PLACE_RULES.has(f.rule) ? kindOfRule(f.rule) : null;
    if (!kind) return true;
    places.push({ kind, file: f.file, line: f.line, call: f.evidence, rule: f.rule, ...(f.count ? { count: f.count } : {}) });
    return false;
  });
  const taken = new Set([...reported.filter(f => f.category === "web").map(f => `${f.file}:${f.line}`), ...places.map(p => `${p.file}:${p.line}`)]);
  if (opts.places !== false) for (const p of sinks) { const k = `${p.file}:${p.line}`; if (!taken.has(k)) { taken.add(k); places.push(p); } }
  places.sort((a, b) => a.kind.localeCompare(b.kind) || a.file.localeCompare(b.file) || a.line - b.line);
  const counts = Object.fromEntries(SEVERITIES.map(s => [s, reported.filter(f => f.severity === s).length]));
  // The answer to "is this safe to install or run": a verdict, or the places to read when there is none.
  const surprising = surprises(files, reported);
  forgetCapabilities();
  const v = verdict(reported), brief = f => ({ rule: f.rule, severity: f.severity, file: f.file, line: f.line, title: f.title });
  return {
    verdict: { level: v.level, decided: v.decided.map(brief), leads: v.leads.map(brief) },
    version: VERSION, target: root, mode: only ? `diff${opts.diff ? ` vs ${opts.diff}` : ""}` : "full",
    stats: { files: files.length, packages, ms: Date.now() - started, counts, tools, osv, history: !!opts.history,
      ignoreFile: ignore.length ? ".vetcodeignore" : null, ignorePatterns: ignore.length, suppressedLines: options.suppressed.size, partial, baselined, mcpLock },
    surprises: surprising,
    profiles: [...prof.map(({ kind, name, file, purpose, capabilities, private: priv }) => ({ kind, name, file, purpose, capabilities, ...(priv ? { private: true } : {}) })),
      // Each crate, with what its build-time code (build script, proc macro) can do kept apart.
      ...crates.filter(c => Object.keys(c.capabilities).length || c.buildFiles.length).map(c => ({ kind: "crate", name: c.name, file: c.file, purpose: c.description, capabilities: c.capabilities,
        buildTime: { capabilities: c.buildTime, buildScript: c.buildScript, procMacro: c.procMacro, buildDependencies: c.buildDependencies } }))],
    places, placeKinds: KINDS,
    findings: reported,
  };
}

export { readText };
