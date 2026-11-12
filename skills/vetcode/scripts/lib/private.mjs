// Which packages come from a private registry, so that the guard never looks their names up
// anywhere. This file reads settings and makes no request; nothing it reads is passed on.
//
// What it reads: the registry lines of the project's and the user's .npmrc, the index lines of
// pip.conf, and the environment variables named below. Tokens that sit in the same files are
// never read into a variable: a line is used only if it is a registry or index line.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const NPM_PUBLIC = new Set(["registry.npmjs.org", "registry.yarnpkg.com"]);
const PY_PUBLIC = new Set(["pypi.org", "files.pythonhosted.org"]);
const PY_INDEX = ["PIP_INDEX_URL", "UV_INDEX_URL", "UV_DEFAULT_INDEX", "PIP_EXTRA_INDEX_URL", "UV_EXTRA_INDEX_URL"];

const parse = text => { try { return new URL(String(text).trim()); } catch { return null; } };
// The public npm registry at its root, the public Python index at any path, with no login in the address.
const publicNpm = text => { const u = parse(text); return !!u && /^https?:$/.test(u.protocol) && !u.username && NPM_PUBLIC.has(u.hostname) && u.pathname === "/" && !u.search; };
const publicPy = text => { const u = parse(text); return !!u && u.protocol === "https:" && !u.username && PY_PUBLIC.has(u.hostname); };

/** The settings that matter, by name. The rest of the environment is not looked at. */
function settings() {
  const e = process.env;
  return {
    npm_config_registry: e.npm_config_registry, GOPRIVATE: e.GOPRIVATE, GONOPROXY: e.GONOPROXY,
    PIP_INDEX_URL: e.PIP_INDEX_URL, UV_INDEX_URL: e.UV_INDEX_URL, UV_DEFAULT_INDEX: e.UV_DEFAULT_INDEX,
    PIP_EXTRA_INDEX_URL: e.PIP_EXTRA_INDEX_URL, UV_EXTRA_INDEX_URL: e.UV_EXTRA_INDEX_URL,
  };
}

/** Returns a function that says whether a package ({ eco, name }) comes from a private registry. */
export function privateRegistries({ cwd = process.cwd(), home = os.homedir(), env = settings(), read = f => { try { return fs.readFileSync(f, "utf8"); } catch { return ""; } } } = {}) {
  const scopes = new Set(); let allNpm = false, allPy = false;
  for (const f of [path.join(cwd, ".npmrc"), path.join(home, ".npmrc")]) for (const line of read(f).split(/\r?\n/)) {
    const m = /^\s*(?:(@[\w.-]+):)?registry\s*=\s*(\S+)/.exec(line);
    if (!m || publicNpm(m[2])) continue;
    if (m[1]) scopes.add(m[1].toLowerCase()); else allNpm = true;
  }
  if (env.npm_config_registry && !publicNpm(env.npm_config_registry)) allNpm = true;
  for (const k of PY_INDEX) if (env[k] && !publicPy(env[k])) allPy = true;
  for (const f of [path.join(cwd, "pip.conf"), path.join(home, ".pip", "pip.conf"), path.join(home, ".config", "pip", "pip.conf")]) {
    for (const m of read(f).matchAll(/^\s*(?:extra-)?index-url\s*=\s*(\S+)/gm)) if (!publicPy(m[1])) allPy = true;
  }
  // GOPRIVATE / GONOPROXY: comma-separated path prefixes (globs) that never go to the public proxy.
  const goPrivate = `${env.GOPRIVATE || ""},${env.GONOPROXY || ""}`.split(",").map(x => x.trim()).filter(Boolean).map(g => new RegExp("^" + g.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*") + "(?:/|$)"));
  return pkg => pkg.eco === "npm" ? allNpm || scopes.has((pkg.name.match(/^(@[^/]+)\//) || [])[1]) : pkg.eco === "go" ? goPrivate.some(r => r.test(pkg.name)) : pkg.eco === "cargo" ? false : allPy;
}
