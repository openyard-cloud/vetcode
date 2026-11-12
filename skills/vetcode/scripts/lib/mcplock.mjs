// Rug-pull detection for MCP servers: remember what each configured server runs (command,
// arguments, URL, env names) and, for servers whose source is in the project, a hash of
// their tool descriptions. Later scans report anything that changed since you approved it.
import fs from "node:fs";
import crypto from "node:crypto";
import { finding } from "./engine.mjs";

const hash = s => crypto.createHash("sha256").update(s).digest("hex").slice(0, 16);
const readJson = t => { try { return JSON.parse(t); } catch { return null; } };
const CONFIG = /(^|\/)(\.mcp\.json|mcp\.json|claude_desktop_config\.json|mcp_config\.json|\.cursor\/mcp\.json|\.vscode\/mcp\.json)$/;

export function mcpSnapshot(files) {
  const snap = {};
  for (const f of files) {
    if (CONFIG.test(f.rel)) {
      const cfg = readJson(f.text);
      for (const [name, s] of Object.entries(cfg?.mcpServers || cfg?.servers || {})) {
        snap[`${f.rel}#${name}`] = hash(JSON.stringify({ command: s.command, args: s.args, url: s.url, env: Object.keys(s.env || {}).sort() }));
      }
    } else if (/\.(c|m)?(j|t)s$|\.py$/.test(f.rel) && /(McpServer|@modelcontextprotocol\/sdk|FastMCP|from mcp\b)/.test(f.text.slice(0, 50000))) {
      const descs = [...f.text.matchAll(/\b(?:description|desc)\s*[:=]\s*(["'`])([\s\S]{10,2000}?)\1/g)].map(m => m[2]).join("\n");
      if (descs) snap[`${f.rel}#tools`] = hash(descs);
    }
  }
  return snap;
}

/** Compare with the lock file; create it on first use. Returns a status line. */
export function checkMcpLock(lockPath, files, out) {
  const now = mcpSnapshot(files);
  if (!fs.existsSync(lockPath)) {
    fs.writeFileSync(lockPath, JSON.stringify({ note: "vetcode MCP lock: what each server ran when you approved it. Re-create after reviewing a change.", servers: now }, null, 2) + "\n");
    return `created (${Object.keys(now).length} entries)`;
  }
  const was = readJson(fs.readFileSync(lockPath, "utf8"))?.servers || {};
  let changed = 0;
  for (const [key, h] of Object.entries(now)) {
    if (was[key] === h) continue;
    changed++;
    const [file, name] = key.split("#");
    out.push(finding({ id: was[key] ? "mcp-changed" : "mcp-new-server", category: "agent", severity: was[key] ? "high" : "medium", confidence: "high",
      title: was[key] ? `MCP ${name === "tools" ? "tool descriptions" : `server "${name}"`} changed since you approved it` : `New MCP server "${name}" since the last approval`,
      why: "A server that changes after approval (a \"rug pull\") can start running different code or steering the model with new instructions.",
      fix: "Review what changed; then delete the lock file and re-run with --mcp-lock to approve the new state." }, file, 1, key));
  }
  for (const key of Object.keys(was)) if (!(key in now)) changed++;
  return changed ? `${changed} change(s)` : "unchanged";
}
