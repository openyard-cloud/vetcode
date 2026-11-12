// AI coding agents read a project's settings and instruction files and act on them, so a
// repository can attack whoever opens it with an agent: hooks that run commands, an API
// base URL that sends your key elsewhere, auto-approved MCP servers, and hidden
// instructions in CLAUDE.md / AGENTS.md / .cursorrules / skills / MCP tool descriptions.
import fs from "node:fs";
import path from "node:path";
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
  // Not the phrase in quotation marks: a file that warns about "ignore previous instructions" is quoting it.
  [/(?<!["“‘'`]\s?)\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|rules|prompts?)/i, "tells the model to drop its instructions"],
  // Keeping something from the person: "do not tell the user", "never mention it to the user". Not advice about
  // what to ask of them ("never tell the user to run commands by hand"), about a kind of content
  // ("developer-only"), or about timing and chattiness ("until validation passes", "about each tool call").
  [/\b(do\s+not|don'?t|never)\s+(?:(?:tell|inform|show|notify|alert)\s+(?:the\s+)?(?:user|human|developer|reviewer)s?\b(?!-|\s+to\b|\s+about\s+(?:each|every)\b|[^.\n]{0,60}\b(?:until|unless|before|yet)\b)|(?:mention|reveal|disclose|report|show)\b[^.\n]{0,40}\bto\s+(?:the\s+)?(?:user|human|developer|reviewer)s?\b(?!-))/i, "asks the model to hide something from the user"],
  // Lying about itself: asked what it was told, the model is to answer as if nothing were unusual.
  [/\b(?:if|when)\s+(?:the\s+)?(?:user|human|developer|anyone|someone)\s+(?:asks?|tries|wants|requests?)\b[^.\n]{0,100}\b(?:system\s+prompt|instructions|skills|rules|this\s+(?:skill|file))\b[^.\n]{0,100}\b(?:as\s+if|as\s+though|pretend|deny|nothing\s+(?:is\s+)?(?:unusual|special|different)|just\s+a\s+(?:standard|normal|regular))/i, "tells the model to deny its instructions when asked"],
  // Tags that imitate the harness or shout priority. `<instructions>` in lower case is an ordinary
  // section of a prompt, and `<secret>` inside a code sample is a placeholder.
  [/<\s*(?:IMPORTANT|SYSTEM|INSTRUCTIONS?|ADMIN|SECRET)\s*>|^[ \t]*<\s*(?:system|system-reminder|important|secret)\s*>[ \t]*$/m, "fake system/priority tag"],
  // "Without asking the user, run…". Not "do not ask the user to run them": that is the agent doing the work itself.
  [/\b(?:without|never|don'?t|do not)\s+(?:ask(?:ing)?|prompt(?:ing)?|notify(?:ing)?|tell(?:ing)?|inform(?:ing)?|confirm(?:ing)?\s+with)\s+(?:the\s+)?(?:user|human|developer|them)\b(?!\s+to\b)[^.\n]{0,80}\b(?:run|execute|install|download|send|upload|delete|push|post|curl|wget)\b/i, "tells the model to act without the user knowing"],
  [/\b(silently|secretly|quietly|covertly)\s+(?:run|execute|install|download|send|upload|exfiltrate|post|copy)\b/i, "tells the model to act without the user knowing", true],
  [/\b(?:execute|run|act|operate|perform|make (?:changes|decisions))\b[^.\n]{0,40}\b(?:without (?:any )?(?:confirmation|permission|approval)|completely silently)\b/i, "tells the model to act without confirmation"],
  [/\b(this|the)\s+(file|code|package|repo(sitory)?)\s+(is|has\s+been)\s+(safe|verified|audited|trusted)\b[^.\n]{0,60}\b(skip|do\s+not|don'?t|no\s+need)/i, "tells a reviewer to skip checking"],
  // Reading a setting from .env is ordinary development; sending the file somewhere is not.
  [/\b(read|cat|open|send|upload|post|include|copy|print|attach|append|exfiltrate|collect)\b[^.\n]{0,60}(~\/\.ssh|id_rsa|id_ed25519|\.aws\/credentials|\.npmrc|\.git-credentials)|\b(send|upload|post|attach|append|exfiltrate|forward|copy)\b[^.\n]{0,60}(?<![\w/])\.env\b|\b(env|printenv)\s*\|\s*grep\b[^\n]{0,40}(?:TOKEN|PASSWORD|SECRET|CREDENTIAL)|\b(send|upload|post|exfiltrate|forward)\b[^.\n]{0,40}\b(the\s+)?(tokens?|secrets?|credentials?|api[_ ]?keys?|env(ironment)? variables)\b[^.\n]{0,40}\b(to|at)\b[^.\n]{0,30}(https?:\/\/|webhook|server|endpoint)/i, "points the model at credentials", true],
  [/\b(curl|wget)\b(?![^\n|]*https:\/\/(?:(?:deb|rpm)\.nodesource\.com|get\.docker\.com|sh\.rustup\.rs|install\.python-poetry\.org|bun\.sh\/install|get\.pnpm\.io|astral\.sh\/|deno\.land\/install|get\.helm\.sh|aspire\.dev\/install|aka\.ms\/|raw\.githubusercontent\.com\/(?:nvm-sh\/nvm|Homebrew\/install)\/|claude\.ai\/install))[^\n]*\|\s*(ba|z)?sh\b|--dangerously-skip-permissions|--yolo\b|--trust-all-tools|bypassPermissions/i, "asks the model to run downloaded code or skip permission prompts"],
  [/extract(?:ed)?\s+(?:it\s+)?(?:using|with)\s+(?:the\s+)?pass(?:word)?|\b(?:archive|zip|rar|7z)\s+pass(?:word|code)?\**\s*[:：]|\(pass(?:word)?:\s*`?[\w-]+`?\)|\b(?:download|install)\b[^\n]{0,160}\.(?:zip|exe|dmg|pkg|msi|appimage)\b[^\n]{0,160}\b(?:run|execute|open|launch)\b|\b(?:download|install|extract|unzip|unpack)\b[^\n]{0,200}\b(?:run|execute|launch)\s+the\s+(?:executable|installer|binary|installation command)|\b(?:run|execute|launch)\s+the\s+(?:installer|installation command)\b(?!\s+(?:from|in|shown in|given in|listed in)\s+(?:the\s+)?(?:[\w.-]+\s+){0,3}(?:docs?|documentation|README|guide)\b)|\b(?:glot\.io|pastebin\.com|paste\.ee|rentry\.co|hastebin\.com|controlc\.com)\/|must be (?:installed|running) before (?:using|you use) this skill[^\n]{0,200}https?:\/\//i, "tells you to download and run an outside program"],
];

// Hosts nobody ships real software from: free app hosting, throwaway domains, paste sites,
// link shorteners and bare addresses. A skill that sends its reader there to install a
// "required" tool is the fake-prerequisite trick (the ClawHavoc skills did exactly this).
const THROWAWAY = /(?:^|\.)(?:vercel\.app|netlify\.app|pages\.dev|workers\.dev|web\.app|firebaseapp\.com|onrender\.com|glitch\.me|repl\.co|replit\.app|herokuapp\.com|surge\.sh|carrd\.co|wixsite\.com|weebly\.com|000webhostapp\.com|glot\.io|rentry\.(?:co|org)|pastebin\.com|hastebin\.com|paste\.ee|bit\.ly|tinyurl\.com|is\.gd|cutt\.ly|rb\.gy)$|\.(?:forum|xyz|top|click|icu|cfd|sbs|cyou|monster|rest|quest|buzz|lol|zip|mov|tk|ml|ga|cf|gq)$|^\d{1,3}(?:\.\d{1,3}){3}$/i;
// Tunnels to somebody's own machine. Real services have a domain.
const TUNNEL = /https?:\/\/(?:bore\.pub:\d+|[a-z0-9-]+\.trycloudflare\.com|[a-z0-9-]{6,}\.ngrok(?:-free)?\.(?:io|app|dev)|[a-z0-9-]+\.loca\.lt|[a-z0-9-]+\.serveo\.net|[a-z0-9]+\.lhr\.life|[a-z0-9-]+\.playit\.gg|[a-z0-9-]+\.pinggy\.(?:io|link))[^\s)>\]"'`]*/i;

function checkDestinations(file, text, out) {
  for (const m of text.matchAll(/https?:\/\/([a-z0-9.-]+)(?::\d+)?[^\s)>\]"'`]*/gi)) {
    if (!THROWAWAY.test(m[1])) continue;
    const before = text.slice(Math.max(0, m.index - 160), m.index);
    if (!/\b(?:download|install|set\s?up|setup|get it|grab it)\b/i.test(before.split(/\n\s*\n/).pop())) continue; // the same paragraph as the link
    out.push(finding(rule({ id: "agent-fake-prerequisite", severity: "high", confidence: "high", title: `Agent instruction file sends you to install software from ${m[1]}`,
      why: "Malicious skills say a helper tool is required and link to an installer on a throwaway host. Whoever follows the instruction, the agent or you, runs the attacker's program.",
      fix: "Do not install it. Real tools are installed from their own domain or a package registry; remove the skill." }), file.rel, lineOf(text, m.index), text.split("\n")[lineOf(text, m.index) - 1]));
    break;
  }
  const t = TUNNEL.exec(text);
  if (t && !/\b(?:example|your[-_ ]|placeholder|<)/i.test(text.slice(Math.max(0, t.index - 40), t.index + t[0].length))) {
    out.push(finding(rule({ id: "agent-tunnel-endpoint", severity: "high", title: "Agent instruction file points at a tunnel to someone's own machine",
      why: "A tunnel address (bore, ngrok, trycloudflare…) leads to whatever computer opened it. An agent told to use it as an API or MCP server sends your prompts and data there.",
      fix: "Do not use it. A real service has its own domain; ask the author where the endpoint is hosted." }), file.rel, lineOf(text, t.index), t[0]));
  }
}

// Is this file part of a skill (a SKILL.md beside it or one folder up)? Its README is read by the same reader.
const skillDirs = new Map();
function inSkill(abs) {
  for (const dir of [path.dirname(abs), path.dirname(path.dirname(abs))]) {
    if (!skillDirs.has(dir)) skillDirs.set(dir, fs.existsSync(path.join(dir, "SKILL.md")));
    if (skillDirs.get(dir)) return true;
  }
  return false;
}

function checkInstructions(file, text, out) {
  checkDestinations(file, text, out);
  // An API the skill is told to use over plain HTTP, on a host that is neither this machine nor a
  // placeholder: the key and every prompt cross the network readable, to whoever runs that host.
  const plain = /\b(?:base[ _-]?url|endpoint|api[ _-]?url|api[ _-]?base|server[ _-]?url)\b[^a-z0-9\n]{0,20}(http:\/\/(?!localhost\b|127\.|0\.0\.0\.0|\[?::1|192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|host\.docker\.internal\b|example\.|your|my|<|\{|\$)[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?[^\s"'`)>]*)/i.exec(text);
  if (plain && /api[ _-]?key|token|secret|authorization|bearer/i.test(text)) {
    out.push(finding(rule({ id: "agent-plain-http-endpoint", severity: "high", title: "Agent instruction file points an API at a plain-HTTP address",
      why: "The skill sends a key and the content of requests to this address without encryption. A real service uses HTTPS; a bare HTTP host on a port is usually someone's own relay.",
      fix: "Do not use it with a real key. Ask who runs the host and why it has no HTTPS." }), file.rel, lineOf(text, plain.index), plain[1]));
  }
  // Front matter opened with `---js` is not data: the front-matter parser most tools use (gray-matter)
  // evaluates it as JavaScript the moment the file is loaded, before any agent reads a word.
  if (/^\uFEFF?---[ \t]*(?:js|javascript|coffee|coffeescript)[ \t]*\r?$/im.test(text)) {
    out.push(finding(rule({ id: "agent-frontmatter-code", severity: "critical", confidence: "high", title: "Front matter that is code, run when the file is parsed",
      why: "A file that opens with `---js` has its front matter executed by the parser that loads skills and instruction files. Nothing has to follow the instructions: listing or loading the skill is enough.",
      fix: "Do not load this file with any tool. Front matter is YAML; code there has no honest use." }), file.rel, lineOf(text, text.search(/^\uFEFF?---[ \t]*(?:js|javascript|coffee|coffeescript)[ \t]*\r?$/im)), text.split("\n").slice(0, 3).join(" ⏎ ")));
  }
  // A command that sends a local file to a server: `curl … --data-binary @notes https://…`.
  // Not a table row that lists the pattern, and not a server on this machine.
  for (const m of text.matchAll(/^(?![ \t]*\|)[^\n]*\bcurl\b[^|\n]*(?:--data-binary|--upload-file|\s-T|\s-F|--form|\s-d|--data)[ \t]+["']?[^"'\s]*@(?![{<])[~.\/$\w][^\s"']*[^|\n]*$/gm)) {
    const url = /https?:\/\/[^\s"'`)>]+/.exec(m[0]);
    if (!url || /^https?:\/\/(?:localhost|127\.0\.0\.1|\[?::1\]?|0\.0\.0\.0|\$|\{|<)/i.test(url[0])) continue;
    out.push(finding(rule({ id: "agent-upload-file", severity: "high", title: "Agent instruction file has a command that uploads a local file",
      why: "Following the instruction sends a file from this machine to someone's server. In a skill that is how notes, source code or credentials leave without anyone deciding to share them.",
      fix: "Find out which file it is and who runs the server. Remove the instruction unless sending that file there is the whole point of the skill and you chose it." }), file.rel, lineOf(text, m.index), m[0].trim()));
    break;
  }
  for (const [re, what, negatable] of INJECTION) {
    const m = re.exec(text);
    if (!m) continue;
    // "Never print secrets or read ~/.ssh" is a safety rule, not an attack.
    if (negatable && /\b(never|not|cannot|can'?t|won'?t|don'?t|no|avoid|without)\b[^\n]{0,60}$/i.test(text.slice(Math.max(0, m.index - 70), m.index + m[0].search(/\s|$/)))) continue;
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
  // The other Markdown of a skill (its README, its install notes): where it sends the reader to get software.
  else if (/\.md$/i.test(file.rel) && file.abs && inSkill(file.abs)) checkDestinations(file, text, out);
  if (/\.(c|m)?(j|t)s$|\.py$/.test(file.rel) && /(McpServer|@modelcontextprotocol\/sdk|from mcp\b|FastMCP|server\.tool\(|\.registerTool\()/.test(text.slice(0, 50000))) checkMcpTools(file, text, out);
}
