// Finds the files worth reading in a project: skips dependencies, build output, binaries
// and anything too big to be hand-written source. Honours .vetcodeignore.
import fs from "node:fs";
import path from "node:path";

export const SKIP_DIRS = new Set([
  ".git", "node_modules", "bower_components", "jspm_packages", "vendor", "dist", "build", "out",
  ".next", ".nuxt", ".svelte-kit", ".output", ".vercel", ".netlify", ".wrangler", ".turbo", ".cache",
  ".parcel-cache", "coverage", ".nyc_output", "__pycache__", ".venv", "venv", "env", ".tox", ".mypy_cache",
  ".pytest_cache", ".ruff_cache", "site-packages", "target", ".gradle", ".idea", "Pods", "DerivedData",
  ".terraform", ".serverless", ".expo", ".dart_tool", "playwright-report", "test-results", "storybook-static",
]);
// Without git there is no .gitignore to tell build output from source, and a downloaded package
// ships its code in dist/ or build/ (the rand-user-agent RAT lived in dist/index.js), so only
// dependency and tool-cache folders are skipped then.
export const SKIP_DIRS_NO_GIT = new Set([...SKIP_DIRS].filter(d => !["dist", "build", "out", "target", "lib"].includes(d)));

export const BINARY = /\.(png|jpe?g|gif|webp|avif|ico|icns|bmp|tiff?|psd|heic|mp[34]|m4a|mov|avi|mkv|webm|wav|ogg|flac|pdf|docx?|xlsx?|pptx?|zip|gz|tgz|bz2|xz|7z|rar|jar|war|ear|class|so|dylib|dll|exe|bin|o|a|wasm|woff2?|ttf|otf|eot|sqlite3?|db|pyc|pyo|node|dat|keystore|jks|p12|pfx|der|crt|cer)$/i;
export const MAX_BYTES = 1_000_000;

// A tiny gitignore-style matcher: `*`, `**`, `?`, a leading `/` anchors, a trailing `/` means a folder.
export function globToRegExp(pattern) {
  let p = pattern.trim();
  const anchored = p.startsWith("/");
  if (anchored) p = p.slice(1);
  const dirOnly = p.endsWith("/");
  if (dirOnly) p = p.slice(0, -1);
  let re = "";
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === "*" && p[i + 1] === "*") { re += ".*"; i++; if (p[i + 1] === "/") i++; }
    else if (c === "*") re += "[^/]*";
    else if (c === "?") re += "[^/]";
    else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  const start = anchored || p.includes("/") ? "^" : "(^|/)";
  return new RegExp(`${start}${re}${dirOnly ? "(/|$)" : "($|/)"}`);
}

export function loadIgnore(root) {
  const file = path.join(root, ".vetcodeignore");
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, "utf8").split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith("#")).map(globToRegExp);
}

export const ignored = (rel, matchers) => matchers.some(m => m.test(rel));

const PART = 256 * 1024;
/** First and last 256 KB of a big text file: payloads are usually at one end of a bundle. */
export function readPartial(abs) {
  try {
    const fd = fs.openSync(abs, "r"), size = fs.fstatSync(fd).size;
    const head = Buffer.alloc(PART), tail = Buffer.alloc(PART);
    fs.readSync(fd, head, 0, PART, 0); fs.readSync(fd, tail, 0, PART, Math.max(0, size - PART)); fs.closeSync(fd);
    if (head.subarray(0, 8000).includes(0)) return null;
    return head.toString("utf8") + "\n" + tail.toString("utf8");
  } catch { return null; }
}

/** Text of a file, or null when it is binary, too big or unreadable. */
function utf16Of(buf) {
  if (buf.length < 2) return null;
  if (buf[0] === 0xff && buf[1] === 0xfe) return new TextDecoder("utf-16le").decode(buf.subarray(2));
  if (buf[0] === 0xfe && buf[1] === 0xff) return new TextDecoder("utf-16be").decode(buf.subarray(2));
  return null;
}

export function readText(abs) {
  try {
    const st = fs.statSync(abs);
    if (!st.isFile() || st.size > MAX_BYTES) return null;
    const buf = fs.readFileSync(abs);
    // UTF-16 text is full of zero bytes but is not binary; reading it as binary would let a
    // file hide from every rule just by being saved in another encoding.
    const utf16 = utf16Of(buf);
    if (utf16 != null) return utf16;
    if (buf.subarray(0, 8000).includes(0)) return null;
    return buf.toString("utf8");
  } catch { return null; }
}

/**
 * Every readable file under `root`, as { abs, rel, text }.
 * `only` limits the walk to a list of relative paths (diff mode).
 */
export function* walk(root, { ignore = [], only = null, skipDirs = SKIP_DIRS } = {}) {
  if (only) {
    for (const rel of only) {
      if (ignored(rel, ignore) || BINARY.test(rel)) continue;
      yield* read(path.join(root, rel), rel);
    }
    return;
  }
  const stack = [""];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try { entries = fs.readdirSync(path.join(root, dir), { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const rel = dir ? `${dir}/${e.name}` : e.name;
      if (ignored(rel, ignore)) continue;
      if (e.isDirectory()) { if (!skipDirs.has(e.name)) stack.push(rel); continue; }
      if (!e.isFile() || BINARY.test(e.name)) continue;
      yield* read(path.join(root, rel), rel);
    }
  }
}

function* read(abs, rel) {
  const text = readText(abs);
  if (text != null) { yield { abs, rel, text }; return; }
  let size = 0; try { size = fs.statSync(abs).size; } catch {}
  if (size > MAX_BYTES) { const part = readPartial(abs); if (part != null) yield { abs, rel, text: part, partial: size }; }
}

/** Installed packages under node_modules (one level of scopes), for --deps. */
export function* installedPackages(root) {
  const nm = path.join(root, "node_modules");
  const visit = function* (dir, depth) {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (!e.isDirectory() || e.name.startsWith(".")) continue;
      const abs = path.join(dir, e.name);
      if (e.name.startsWith("@")) { yield* visit(abs, depth); continue; }
      if (fs.existsSync(path.join(abs, "package.json"))) yield abs;
      if (depth < 3) yield* visit(path.join(abs, "node_modules"), depth + 1);
    }
  };
  yield* visit(nm, 0);
}
