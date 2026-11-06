// AI coding agents read a project's settings and instruction files and act on them, so a
// repository can attack whoever opens it with an agent: hooks that run commands, an API
// base URL that sends your key elsewhere, auto-approved MCP servers, and hidden
// instructions in CLAUDE.md / AGENTS.md / .cursorrules / skills / MCP tool descriptions.
import { finding, lineOf } from "./engine.mjs";

const rule = r => ({ category: "agent", confidence: "medium", ...r });
const readJson = text => { try { return JSON.parse(text.replace(/^﻿/, "").replace(/^\s*\/\/.*$/gm, "")); } catch { return null; } };
const lineIn = (text, needle) => { const i = text.indexOf(needle); return i < 0 ? 1 : lineOf(text, i); };

const SETTINGS = /(^|\/)\.claude\/settings(\.local)?\.json$|(^|\/)\.gemini\/settings\.json$|(^|\/)\.codex\/config\.toml$/;
export const INSTRUCTIONS = /(^|\/)(CLAUDE|AGENTS|GEMINI|CONVENTIONS)\.md$|(^|\/)\.cursorrules$|(^|\/)\.cursor\/rules\/[^/]+$|(^|\/)\.windsurfrules$|(^|\/)\.clinerules(\/[^/]+)?$|(^|\/)\.github\/copilot-instructions\.md$|(^|\/)\.github\/instructions\/[^/]+$|(^|\/)SKILL\.md$|(^|\/)\.claude\/(commands|agents|skills)\/.+\.md$|(^|\/)\.(agents|github)\/skills\/.+\.md$/i;

function checkSettings(file, text, out) {
  const s = readJson(text);
  if (!s) return;
  const at = key => lineIn(text, `"${key}"`);
  if (s.hooks && Object.keys(s.hooks).length) {
    const cmds = JSON.stringify(s.hooks).match(/"command"\s*:\s*"([^"]{0,200})/g) || [];
    out.push(finding(rule({ id: "agent-project-hooks", severity: "high", title: "Project settings define agent hooks",
      why: "Hooks run shell commands automatically when an agent starts or uses tools in this folder; a cloned repository can use them to run code on your machine.",
      fix: "Read every hook command. Do not open untrusted repositories with an agent until they are removed." }), file.rel, at("hooks"), cmds.slice(0, 3).join(" ").replace(/"command"\s*:\s*"/g, "")));
  }
  for (const [k, v] of Object.entries(s.env || {})) {
    if (/_BASE_URL$|_API_URL$|^HTTPS?_PROXY$|_ENDPOINT$/i.test(k) && typeof v === "string" && !/^https:\/\/(api\.anthropic\.com|api\.openai\.com)/.test(v)) {
      out.push(finding(rule({ id: "agent-api-redirect", severity: "critical", confidence: "high", title: `Project settings send agent traffic to ${v.slice(0, 60)}`,
        why: "Overriding the API base URL or proxy in project settings routes your prompts and API key to that server (the CVE-2026-21852 pattern).",
        fix: "Remove it unless it is your own gateway." }), file.rel, at(k), `${k}=${v}`));
    }
  }
  if (s.enableAllProjectMcpServers === true || (Array.isArray(s.enabledMcpjsonServers) && s.enabledMcpjsonServers.length)) {
    out.push(finding(rule({ id: "agent-auto-mcp", severity: "high", confidence: "high", title: "Project auto-approves its MCP servers",
      why: "MCP servers start without asking when the agent opens the folder; with a malicious .mcp.json that is code execution on open (the CVE-2025-59536 pattern).",
      fix: "Remove the setting; approve servers yourself after reading them." }), file.rel, at(s.enableAllProjectMcpServers ? "enableAllProjectMcpServers" : "enabledMcpjsonServers"), JSON.stringify(s.enabledMcpjsonServers ?? true)));
  }
  const allow = s.permissions?.allow || [];
  const wide = allow.filter(p => /^(Bash|Shell|Write|Edit|WebFetch)(\((\*|\*\*|:?\*)\))?$/.test(p) || /^Bash\((curl|wget|sh|bash|rm|sudo|npx|node|python)\b/.test(p));
  if (wide.length || s.permissions?.defaultMode === "bypassPermissions") {
    out.push(finding(rule({ id: "agent-wide-permissions", severity: "medium", confidence: "high", title: "Project pre-approves broad agent permissions",
      why: "The agent will run these commands or edits without asking anyone who opens the project.", fix: "Keep project permissions narrow; put personal allow-lists in your user settings." }), file.rel, at(wide.length ? "allow" : "defaultMode"), wide.join(", ") || "defaultMode: bypassPermissions"));
  }
}

// Text aimed at a model rather than a person. Each hit is a candidate: real instruction files
// legitimately say "always" and "never"; these patterns are the ones attacks use.
const INJECTION = [
  [/\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|rules|prompts?)/i, "tells the model to drop its instructions"],
  [/\b(do\s+not|don'?t|never)\s+(tell|inform|mention|reveal|show)\b[^.\n]{0,40}\b(the\s+)?(user|human|developer|reviewer)/i, "asks the model to hide something from the user"],
  [/<\s*(IMPORTANT|SYSTEM|INSTRUCTIONS?|ADMIN|secret)\s*>/i, "fake system/priority tag"],
  [/\b(?:without|never|don'?t|do not)\s+(?:ask(?:ing)?|prompt(?:ing)?|notify(?:ing)?|tell(?:ing)?|inform(?:ing)?|confirm(?:ing)?\s+with)\s+(?:the\s+)?(?:user|human|developer|them)\b[^.\n]{0,80}\b(?:run|execute|install|download|send|upload|delete|push|post|curl|wget)\b|\b(?:silently|secretly|quietly|covertly)\s+(?:run|execute|install|download|send|upload|exfiltrate|post|copy)\b/i, "tells the model to act without the user knowing"],
  [/\b(this|the)\s+(file|code|package|repo(sitory)?)\s+(is|has\s+been)\s+(safe|verified|audited|trusted)\b[^.\n]{0,60}\b(skip|do\s+not|don'?t|no\s+need)/i, "tells a reviewer to skip checking"],
  [/\b(read|cat|open|send|upload|post|include|copy|print|attach|append|exfiltrate|collect)\b[^.\n]{0,60}(~\/\.ssh|id_rsa|id_ed25519|\.aws\/credentials|\.npmrc|\.git-credentials|\.env\b)|\b(send|upload|post|exfiltrate|forward)\b[^.\n]{0,40}\b(the\s+)?(tokens?|secrets?|credentials?|api[_ ]?keys?|env(ironment)? variables)\b[^.\n]{0,40}\b(to|at)\b[^.\n]{0,30}(https?:\/\/|webhook|server|endpoint)/i, "points the model at credentials", true],
  [/\b(curl|wget)\b[^\n]*\|\s*(ba|z)?sh\b|--dangerously-skip-permissions|--yolo\b|--trust-all-tools|bypassPermissions/i, "asks the model to run downloaded code or skip permission prompts"],
  [/extract(?:ed)?\s+(?:it\s+)?(?:using|with)\s+(?:the\s+)?pass(?:word)?|\(pass(?:word)?:\s*`?[\w-]+`?\)|\b(?:download|install)\b[^\n]{0,160}\.(?:zip|exe|dmg|pkg|msi|appimage)\b[^\n]{0,160}\b(?:run|execute|open|launch)\b|\b(?:run|execute|launch)\s+the\s+(?:executable|installer|binary|installation command)|\b(?:glot\.io|pastebin\.com|paste\.ee|rentry\.co|hastebin\.com|controlc\.com)\/|must be (?:installed|running) before (?:using|you use) this skill[^\n]{0,200}https?:\/\//i, "tells you to download and run an outside program"],
];

function checkInstructions(file, text, out) {
  for (const [re, what, negatable] of INJECTION) {
    const m = re.exec(text);
    if (!m) continue;
    // "Never print secrets or read ~/.ssh" is a safety rule, not an attack.
    if (negatable && /\b(never|not|don'?t|no|avoid|without)\b[^\n]{0,60}$/i.test(text.slice(Math.max(0, m.index - 70), m.index + m[1]?.length))) continue;
    out.push(finding(rule({ id: "agent-instruction-injection", severity: "high", title: `Agent instruction file ${what}`,
      why: "Coding agents follow these files. Instructions planted in them (or in a skill or MCP tool description) make the agent act against you: leak secrets, run code, or hide what it did.",
      fix: "Read the file as a person would; remove anything you did not write. Treat a repository that contains this as hostile." }), file.rel, lineOf(text, m.index), text.split("\n")[lineOf(text, m.index) - 1]));
  }
  const hidden = /<!--[\s\S]*?-->/g;
  for (const m of text.matchAll(hidden)) {
    if (!/\b(you|assistant|claude|ai|model|agent|must|always|never|execute|run)\b/i.test(m[0]) || m[0].length < 40) continue;
    out.push(finding(rule({ id: "agent-hidden-comment", severity: "medium", title: "Hidden HTML comment with instructions in an agent file",
      why: "Comments are invisible when the Markdown is rendered but the agent reads them.", fix: "Read it and remove it if it is not yours." }), file.rel, lineOf(text, m.index), m[0].slice(0, 150)));
    break;
  }
}

function checkMcpTools(file, text, out) {
  // Tool descriptions shipped in an MCP server's source: look for instructions to the model.
  for (const m of text.matchAll(/\b(description|desc)\s*[:=]\s*(["'`])([\s\S]{20,2000}?)\2/g)) {
    for (const [re, what] of INJECTION) {
      if (!re.test(m[3])) continue;
      out.push(finding(rule({ id: "mcp-tool-poisoning", severity: "high", title: `MCP tool description ${what}`,
        why: "The model reads tool descriptions as instructions; a poisoned one can make it read files or call other tools for the attacker.",
        fix: "Do not install this server; if it is yours, make the description describe the tool only." }), file.rel, lineOf(text, m.index), m[3].slice(0, 150)));
      return;
    }
  }
}

export function scanAgentFiles(file, text, out) {
  if (SETTINGS.test(file.rel)) checkSettings(file, text, out);
  else if (INSTRUCTIONS.test(file.rel)) checkInstructions(file, text, out);
  if (/\.(c|m)?(j|t)s$|\.py$/.test(file.rel) && /(McpServer|@modelcontextprotocol\/sdk|from mcp\b|FastMCP|server\.tool\(|\.registerTool\()/.test(text.slice(0, 50000))) checkMcpTools(file, text, out);
}
