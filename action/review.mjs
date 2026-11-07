#!/usr/bin/env node
// Turns a vetcode JSON report into a pull request review: an inline comment on each finding that
// sits on a line the pull request adds or changes, a summary of the rest, and the job summary.
// Run by action.yml; reads the GitHub Actions environment.
//
//   node action/review.mjs <report.json> --base <sha> [--path .] [--fail-on high] [--comment true]
//
// Exit 1 when a finding at --fail-on or worse is on a changed line (or anywhere in a file the
// pull request adds). Findings that were already in touched files are listed but do not fail.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { diffRange } from "../skills/vetcode/scripts/lib/index.mjs";
import { staleThreads } from "./threads.mjs";

const args = process.argv.slice(2);
const opt = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const report = JSON.parse(fs.readFileSync(args[0], "utf8"));
const BASE = opt("--base", ""), SCAN = opt("--path", "."), FAIL_ON = opt("--fail-on", "high"), COMMENT = opt("--comment", "true") === "true";
const SEV = ["critical", "high", "medium", "low", "info"], rank = s => SEV.indexOf(s);
const ICON = { critical: "🔴", high: "🟠", medium: "🟡", low: "⚪", info: "ℹ️" };
const MAX_INLINE = 30;

// Lines the pull request adds or changes, per file, relative to the repository root.
const root = spawnSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf8" }).stdout.trim() || process.cwd();
const changed = new Map(), added = new Set();
if (BASE) {
  const out = spawnSync("git", ["diff", "-U0", "--no-color", "--no-renames", ...diffRange(root, BASE)], { cwd: root, encoding: "utf8", maxBuffer: 256 << 20 }).stdout || "";
  let file = null, isNew = false;
  for (const line of out.split("\n")) {
    if (line.startsWith("diff --git ")) { isNew = false; continue; }
    if (line.startsWith("--- ")) { isNew = line === "--- /dev/null"; continue; }
    if (line.startsWith("+++ ")) {
      file = line === "+++ /dev/null" ? null : line.slice(6);
      if (file && !changed.has(file)) changed.set(file, new Set());
      if (file && isNew) added.add(file);
      continue;
    }
    const h = file && /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/.exec(line);
    if (h) for (let n = +h[1], end = n + (h[2] === undefined ? 1 : +h[2]); n < end; n++) changed.get(file).add(n);
  }
}
const prefix = path.relative(root, path.resolve(SCAN)).split(path.sep).join("/");
const repoPath = f => (prefix ? `${prefix}/${f}` : f);

const findings = report.findings.filter(f => f.severity !== "info").map(f => ({ ...f, path: repoPath(f.file) }));
const onChange = f => !BASE || added.has(f.path) || changed.get(f.path)?.has(f.line);
const inline = findings.filter(f => BASE && changed.get(f.path)?.has(f.line));
const blocking = findings.filter(f => rank(f.severity) <= rank(FAIL_ON) && f.confidence !== "low" && onChange(f));

const esc = s => String(s ?? "").replace(/[<>]/g, c => (c === "<" ? "&lt;" : "&gt;"));
const marker = f => `<!-- vetcode:${f.fingerprint} -->`;
const commentBody = f => [
  `${ICON[f.severity]} **${esc(f.title)}** · ${f.severity}${f.confidence === "low" ? " (low confidence)" : ""} · \`${f.rule}\``,
  "", esc(f.why), "", `**Fix:** ${esc(f.fix)}`, "", marker(f),
].join("\n");
const row = f => `| ${ICON[f.severity]} ${f.severity} | ${esc(f.title)} | \`${esc(f.path)}:${f.line}\` | \`${f.rule}\` |`;
const table = list => list.length ? ["| Severity | Finding | Where | Rule |", "|---|---|---|---|", ...list.slice(0, 50).map(row), ...(list.length > 50 ? [`| | …and ${list.length - 50} more | | |`] : [])].join("\n") : "";

const counts = SEV.slice(0, 4).map(s => [s, findings.filter(f => f.severity === s).length]).filter(([, n]) => n);
const headline = !findings.length ? "✅ vetcode found nothing in the files this pull request changes."
  : `vetcode found ${findings.length} item${findings.length > 1 ? "s" : ""} in the files this pull request changes: ${counts.map(([s, n]) => `${n} ${s}`).join(", ")}.`
    + (blocking.length ? ` **${blocking.length} at ${FAIL_ON} or worse on changed lines.**` : "");
const elsewhere = findings.filter(f => !inline.includes(f));
const summary = [
  "### vetcode security review", headline,
  inline.length ? `${inline.length === 1 ? "One is" : `${inline.length} are`} commented on the line it concerns.` : "",
  elsewhere.length ? `**Not on a changed line** (already in the file, or reported for the file as a whole):\n\n${table(elsewhere)}` : "",
  "Scanner findings are candidates: read each one before acting. An agent following vetcode's SKILL.md can confirm them and look for what patterns miss.",
].filter(Boolean).join("\n\n");

if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary + (inline.length ? `\n\n**On changed lines:**\n\n${table(inline)}\n` : "\n"));
if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `findings=${findings.length}\nblocking=${blocking.length}\n`);

async function gh(method, url, body) {
  const r = await fetch(`${process.env.GITHUB_API_URL || "https://api.github.com"}${url}`, {
    method, headers: { authorization: `Bearer ${process.env.GITHUB_TOKEN}`, accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28", ...(body ? { "content-type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!r.ok) throw new Error(`${method} ${url}: ${r.status} ${(await r.text()).slice(0, 200)}`);
  return r.status === 204 ? null : r.json();
}

async function graphql(query, variables) {
  const r = await fetch(process.env.GITHUB_GRAPHQL_URL || "https://api.github.com/graphql", {
    method: "POST", headers: { authorization: `Bearer ${process.env.GITHUB_TOKEN}`, "content-type": "application/json" }, body: JSON.stringify({ query, variables }),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.errors) throw new Error(`graphql: ${r.status} ${JSON.stringify(j.errors || "").slice(0, 200)}`);
  return j.data;
}

async function resolveStale(owner, name, number) {
  const data = await graphql(`query($o:String!,$n:String!,$p:Int!){repository(owner:$o,name:$n){pullRequest(number:$p){reviewThreads(first:100){nodes{id isResolved comments(first:1){nodes{body}}}}}}}`, { o: owner, n: name, p: number });
  const ids = staleThreads(data.repository.pullRequest.reviewThreads.nodes, new Set(findings.map(f => f.fingerprint)));
  for (const id of ids) await graphql(`mutation($id:ID!){resolveReviewThread(input:{threadId:$id}){thread{isResolved}}}`, { id });
  return ids.length;
}

const event = process.env.GITHUB_EVENT_PATH ? JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, "utf8")) : {};
const pr = event.pull_request?.number, repo = process.env.GITHUB_REPOSITORY;
if (COMMENT && pr && repo && process.env.GITHUB_TOKEN) {
  try {
    // Do not repeat ourselves on every push: skip findings already commented or summarised.
    const seen = new Set();
    for (let page = 1; page <= 10; page++) {
      const [comments, reviews] = await Promise.all([gh("GET", `/repos/${repo}/pulls/${pr}/comments?per_page=100&page=${page}`), gh("GET", `/repos/${repo}/pulls/${pr}/reviews?per_page=100&page=${page}`)]);
      for (const c of [...comments, ...reviews]) for (const m of String(c.body || "").matchAll(/<!-- vetcode:([\w-]+) -->/g)) seen.add(m[1]);
      if (comments.length < 100 && reviews.length < 100) break;
    }
    const fresh = findings.filter(f => !seen.has(f.fingerprint));
    const freshInline = inline.filter(f => !seen.has(f.fingerprint)).slice(0, MAX_INLINE);
    if (fresh.length) {
      const hidden = fresh.filter(f => !freshInline.includes(f)).map(marker).join("");
      await gh("POST", `/repos/${repo}/pulls/${pr}/reviews`, {
        commit_id: event.pull_request.head.sha, event: "COMMENT", body: summary + "\n" + hidden,
        comments: freshInline.map(f => ({ path: f.path, line: f.line, side: "RIGHT", body: commentBody(f) })),
      });
      console.error(`vetcode: review posted (${freshInline.length} inline comments, ${fresh.length} new findings)`);
    } else console.error("vetcode: nothing new since the last review");
    const [owner, name] = repo.split("/");
    const closed = await resolveStale(owner, name, pr).catch(e => (console.error(`vetcode: could not resolve old threads (${e.message})`), 0));
    if (closed) console.error(`vetcode: resolved ${closed} thread${closed > 1 ? "s" : ""} whose finding is gone`);
  } catch (e) {
    // Pull requests from forks get a read-only token; the job summary still has everything.
    console.error(`vetcode: could not post the review (${e.message}); see the job summary`);
  }
}
console.error(`vetcode: ${findings.length} findings, ${blocking.length} at ${FAIL_ON} or worse on changed lines`);
process.exit(blocking.length ? 1 : 0);
