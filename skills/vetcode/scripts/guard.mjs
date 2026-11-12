#!/usr/bin/env node
// vetcode guard: checks what a shell command would install before it runs.
//
// As a Claude Code hook (see hooks/hooks.json) it reads the hook's JSON on stdin. Before a Bash
// command runs it answers allow, ask or deny for the packages the command would install: the
// ones it names, the ones a bare `npm install` or `pip install -r` would add, and the ones an
// MCP server registered with `claude mcp add` would run. Before an MCP configuration file is
// written it does the same for the servers in it. After a `git clone` it reads the cloned
// folder and tells the agent if it holds signs of malware or of an attack on coding agents,
// before anything from it is run. By hand:
//
//   node guard.mjs "npm install expres"        # prints the decision and the reasons
//   echo '{"tool_name":"Bash","tool_input":{"command":"pip install requessts"}}' | node guard.mjs
//
// Settings (environment):
//   VETCODE_GUARD=off       do nothing
//   VETCODE_GUARD=strict    turn every "ask" into "deny"
//   VETCODE_GUARD_MIN_AGE_HOURS=72   how old a release must be before it installs without a question
//
// What leaves the machine (every destination is in PRIVACY.md): the names and versions of the
// packages in the command, to the package registry (npm, PyPI, crates.io, the Go proxy) and to
// OSV.dev, and a download of the package archive, which is read and deleted. A name that looks
// like a popular package also goes to a download counter (api.npmjs.org, pypistats.org). For an install that names no package, the names and versions in the
// lockfile or requirements file go to OSV.dev in one request. The install itself would contact the same registry. Nothing is executed.
// If the network is down or a check fails, the command is allowed: the guard never blocks on
// its own errors. Packages that come from a private registry (a registry line in .npmrc, or
// PIP_INDEX_URL and the like) are not looked up anywhere.

const MODE = (process.env.VETCODE_GUARD || "on").toLowerCase();
// Most shell commands install nothing: decide that before doing any work.
const MAYBE = /\b(?:npm|pnpm|yarn|bun|npx|bunx|pnpx|pip[\d.]*|uv|uvx|pipx|poetry)\b|\b(?:curl|wget)\b[^|]*\||\bmcp\s+add|\bcargo\s+(?:add|install)\b|\bgo\s+(?:get|install|run)\b/;
// Files that tell an agent which programs to start: MCP servers, and hooks in agent settings.
const AGENT_CONFIG = /(?:^|[\\/])(?:\.?mcp(?:[._-]config)?\.json|claude_desktop_config\.json|\.claude\.json|settings(?:\.local)?\.json|config\.toml)$/i;

async function main() {
  const arg = process.argv[2];
  let command = arg, hook = false, cwd = process.cwd(), config = null;
  if (!arg) {
    let input = ""; for await (const chunk of process.stdin) input += chunk;
    let j; try { j = JSON.parse(input); } catch { return; }
    cwd = j.cwd || cwd; hook = true;
    if (/^(?:Write|Edit|MultiEdit)$/.test(j.tool_name)) {
      // A configuration file about to be written: check the servers and commands it would start.
      const file = j.tool_input?.file_path || "";
      if (MODE === "off" || j.hook_event_name !== "PreToolUse" || !AGENT_CONFIG.test(file)) return;
      const text = [j.tool_input.content, j.tool_input.new_string, ...(Array.isArray(j.tool_input.edits) ? j.tool_input.edits.map(e => e?.new_string) : [])].filter(x => typeof x === "string").join("\n");
      if (!/command|url/i.test(text) || (/config\.toml$/i.test(file) && !/mcp/i.test(text))) return;
      const { mcpCommands } = await import("./lib/guard.mjs");
      command = mcpCommands(text).join("\n"); config = file.split(/[\\/]/).pop();
    } else if (j.tool_name !== "Bash") return;
    else command = j.tool_input?.command || "";
    // After a clone: read what arrived, before the agent runs anything from it.
    if (j.hook_event_name === "PostToolUse") {
      if (MODE === "off" || !/\b(?:clone|degit|tiged|giget)\b/.test(command)) return;
      const [{ parseClones, checkClone }, { vet }] = await Promise.all([import("./lib/guard.mjs"), import("./lib/index.mjs")]);
      const found = (await Promise.all(parseClones(command, { cwd }).map(c => checkClone(c.dir, { vet }).catch(() => null)))).filter(Boolean);
      if (found.length) console.log(JSON.stringify({ decision: "block", reason: found.map(f => f.message).join(" ") }));
      return;
    }
  }
  if (MODE === "off" || !command || !MAYBE.test(command)) return;
  // The scanner is loaded only now: every other shell command pays for a regex, nothing more.
  const [{ guard, scanArchive, privateRegistries }, { vet }] = await Promise.all([import("./lib/guard.mjs"), import("./lib/index.mjs")]);
  const res = await guard(command, { cwd, config, mode: MODE, minAgeHours: +(process.env.VETCODE_GUARD_MIN_AGE_HOURS || 72), isPrivate: privateRegistries({ cwd }), scan: (eco, url, size) => scanArchive(eco, url, size, { vet }) });
  if (!hook) {
    console.log(`${res.decision}${res.checked ? ` (${res.checked} package${res.checked === 1 ? "" : "s"} checked)` : ""}`);
    if (res.message) console.log(res.message);
    for (const n of res.notes) console.log(`note: ${n}`);
    process.exitCode = res.decision === "deny" ? 2 : res.decision === "ask" ? 1 : 0;
    return;
  }
  if (res.decision === "allow") {
    // Say nothing unless there is something worth knowing; the agent sees it with the result.
    if (res.notes.length) console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", additionalContext: `vetcode checked this install. ${res.notes.join(" ")}` } }));
    return;
  }
  // The guard never approves a call and never changes its input: it denies, or it hands the
  // question to the person. "Allow" is silence, which leaves Claude Code's own permission flow as it is.
  const decision = res.decision === "deny" ? "deny" : "ask";
  console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: decision, permissionDecisionReason: config ? res.message.replace(/^vetcode: /, `vetcode: ${config} would make the agent start a program that needs a look. `) : res.message } }));
}

// A guard that fails must not stop the work: any error means "no opinion".
main().catch(() => {});
