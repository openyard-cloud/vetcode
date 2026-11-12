#!/usr/bin/env node
// vetcode: finds malware, supply-chain risks, leaked secrets and vulnerability candidates
// in a project. Read-only: it never installs, builds or runs anything from the target.
//
//   node vet.mjs [path] [options]
//     --json <file>     also write the full results as JSON
//     --sarif <file>    also write SARIF 2.1.0 (GitHub code scanning)
//     --online          look up dependencies on OSV.dev (known vulnerabilities and malware)
//                       and run semgrep / osv-scanner / trivy if they are installed
//     --deps            read installed node_modules: install scripts and malware patterns
//     --history         search git history for secrets that were committed and removed
//     --diff [base]     only files changed against base (default: uncommitted changes)
//     --no-ignore       ignore .vetcodeignore and inline vetcode-ignore comments
//     --baseline <file> hide findings already in an earlier --json report (report only new ones)
//     --mcp-lock <file> remember MCP servers and tool descriptions; report changes (rug pulls)
//     --no-tools        do not run external tools even if installed
//     --fail-on <sev>   exit 1 if a finding at this severity or worse exists (for CI)
//     --quiet           no progress messages
import fs from "node:fs";
import { vet, VERSION } from "./lib/index.mjs";
import { markdown } from "./lib/report.mjs";
import { sarif } from "./lib/sarif.mjs";
import { rank, SEVERITIES } from "./lib/engine.mjs";

const args = process.argv.slice(2);
const flag = name => { const i = args.indexOf(name); if (i < 0) return false; args.splice(i, 1); return true; };
const value = (name, optional = false) => {
  const i = args.indexOf(name);
  if (i < 0) return undefined;
  const v = args[i + 1];
  if (v === undefined || v.startsWith("--")) { if (!optional) { console.error(`${name} needs a value`); process.exit(2); } args.splice(i, 1); return ""; }
  args.splice(i, 2);
  return v;
};

if (flag("--help") || flag("-h")) { console.log(fs.readFileSync(new URL(import.meta.url), "utf8").split("\n").filter(l => l.startsWith("//")).map(l => l.slice(3)).join("\n")); process.exit(0); }
if (flag("--version")) { console.log(VERSION); process.exit(0); }

const opts = {
  json: value("--json"), sarif: value("--sarif"), baseline: value("--baseline"), mcpLock: value("--mcp-lock"), failOn: value("--fail-on"), diff: value("--diff", true),
  online: flag("--online"), deps: flag("--deps"), history: flag("--history"),
  noIgnore: flag("--no-ignore"), tools: !flag("--no-tools"), quiet: flag("--quiet"),
};
if (opts.failOn && !SEVERITIES.includes(opts.failOn)) { console.error(`--fail-on must be one of ${SEVERITIES.join(", ")}`); process.exit(2); }
const target = args.find(a => !a.startsWith("--")) || ".";
if (!fs.existsSync(target)) { console.error(`No such path: ${target}`); process.exit(2); }

opts.log = opts.quiet ? () => {} : m => console.error(`vetcode: ${m}`);
const result = await vet(target, opts);
if (opts.json) fs.writeFileSync(opts.json, JSON.stringify(result, null, 2));
if (opts.sarif) fs.writeFileSync(opts.sarif, JSON.stringify(sarif(result), null, 2));
process.stdout.write(markdown(result));
if (opts.json && !opts.quiet) console.error(`vetcode: JSON written to ${opts.json}`);
if (opts.failOn && result.findings.some(f => rank(f.severity) <= rank(opts.failOn) && f.confidence !== "low")) process.exit(1);
