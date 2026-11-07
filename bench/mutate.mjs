#!/usr/bin/env node
// Evasion benchmark: rewrites malicious samples the way attackers do to slip past scanners,
// then the usual scorers (run.mjs for vetcode, rivals.mjs for others) measure how much is
// still caught. Text is rewritten only; nothing is installed or run.
//
//   node bench/mutate.mjs --cache <dir> --out <dir> [--only npm,pypi] [--n 150]
//
// Writes <out>/<mutation>/<eco>/malicious/<id>.tgz for each mutation, plus <out>/none with
// the untouched samples, so every mutated set can be compared with its own baseline. The same
// clean packages (unchanged) go into every set, so tools with several possible verdicts are
// judged on the one with the best F1, as in the main benchmark, not on "flag everything".
//
//   split     string literals cut in two and glued with +      ("child_" + "process")
//   hex       string literals written as \xNN escapes          ("\x63\x68\x69...")
//   pack      the whole file base64-encoded and run by eval/exec
//   zpack     the same, compressed first (gzip / zlib)
//   charcode  string literals built from character codes       (String.fromCharCode(99, …), "".join(map(chr, […])))
//   reverse   string literals written backwards                 ("ssecorp_dlihc".split("").reverse().join(""), "…"[::-1])
//   offscreen JavaScript lines pushed 400 spaces to the right  (rand-user-agent style)
//   dist      code moved under dist/, where bundles live
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import zlib from "node:zlib";

const arg = (k, d) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : d; };
const CACHE = path.resolve(arg("--cache", path.join(os.tmpdir(), "vetcode-bench")));
const OUT = path.resolve(arg("--out", path.join(os.tmpdir(), "vetcode-mutated")));
const ONLY = arg("--only", "npm,pypi").split(",");
const N = +arg("--n", 150);

const JS = /\.(c|m)?js$/i, PY = /\.pyw?$/i;
// Plain one-line literals without escapes or quotes inside, not on import lines (an ES import
// specifier cannot be an expression) and not prefixed (f"", b"", r"" in Python, tagged templates).
const LITERAL = /(?<![\w$`\\])(["'])([^"'\\\n]{6,200})\1/g;
const IMPORT_LINE = /^\s*(?:import\b|from\s+\S+\s+import\b|export\s[^\n]*\bfrom\b)/;
const eachLiteral = (text, fn) => text.split("\n").map(line => IMPORT_LINE.test(line) || line.includes('"""') || line.includes("'''") ? line : line.replace(LITERAL, (m, q, s) => fn(q, s, m))).join("\n");

const MUTATIONS = {
  none: null,
  split: (text) => eachLiteral(text, (q, s) => { const h = s.length >> 1; return `(${q}${s.slice(0, h)}${q} + ${q}${s.slice(h)}${q})`; }),
  hex: (text) => eachLiteral(text, (q, s, m) => /^[\x20-\x7e]+$/.test(s) ? q + [...s].map(c => "\\x" + c.charCodeAt(0).toString(16).padStart(2, "0")).join("") + q : m),
  charcode: (text, rel) => eachLiteral(text, (q, s, m) => {
    if (!/^[\x20-\x7e]+$/.test(s)) return m;
    const codes = [...s].map(c => c.charCodeAt(0)).join(", ");
    return JS.test(rel) ? `String.fromCharCode(${codes})` : `"".join(map(chr, [${codes}]))`;
  }),
  reverse: (text, rel) => eachLiteral(text, (q, s) => {
    const r = q + [...s].reverse().join("") + q;
    return JS.test(rel) ? `${r}.split("").reverse().join("")` : `${r}[::-1]`;
  }),
  pack: (text, rel) => {
    const b64 = Buffer.from(text).toString("base64");
    if (JS.test(rel)) return `eval(Buffer.from("${b64}", "base64").toString());\n`;
    return `exec(__import__("base64").b64decode("${b64}"))\n`;
  },
  zpack: (text, rel) => {
    const gz = zlib.gzipSync(Buffer.from(text)).toString("base64");
    if (JS.test(rel)) return `eval(require("zlib").gunzipSync(Buffer.from("${gz}", "base64")).toString());\n`;
    return `exec(__import__("zlib").decompress(__import__("base64").b64decode("${zlib.deflateSync(Buffer.from(text)).toString("base64")}")))\n`;
  },
  offscreen: (text, rel) => JS.test(rel) ? text.split("\n").map(l => l.trim() ? " ".repeat(400) + l : l).join("\n") : text,
  dist: "move",
};

function remove(dir) { spawnSync("chmod", ["-R", "u+rwX", dir]); spawnSync("rm", ["-rf", dir]); }
function unpack(file, into) {
  fs.mkdirSync(into, { recursive: true });
  const r = file.endsWith(".zip") ? spawnSync("unzip", ["-qq", "-o", "-P", "infected", file, "-d", into]) : spawnSync("tar", ["-xzf", file, "-C", into]);
  spawnSync("chmod", ["-R", "u+rwX", into]);
  return r.status === 0 || fs.readdirSync(into).length > 0;
}
// Python samples often arrive as an sdist or wheel inside the zip; open those too so the code is reachable.
function unpackInner(dir) {
  for (const f of walk(dir)) {
    if (/\.(tar\.gz|tgz)$/.test(f)) spawnSync("tar", ["-xzf", f, "-C", path.dirname(f)]);
    else if (/\.whl$/.test(f)) spawnSync("unzip", ["-qq", "-o", f, "-d", path.dirname(f)]);
    else continue;
    fs.rmSync(f, { force: true });
  }
  spawnSync("chmod", ["-R", "u+rwX", dir]);
}
function walk(dir, out = []) {
  let es; try { es = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of es) { const p = path.join(dir, e.name); if (e.isDirectory()) walk(p, out); else if (e.isFile()) out.push(p); }
  return out;
}

function mutate(dir, name) {
  const files = walk(dir).filter(f => JS.test(f) || PY.test(f));
  if (name === "dist") {
    // Move every code file under dist/ next to its package root and point package.json at it.
    // Relative to the package root (the folder with package.json, setup.py or pyproject.toml),
    // so install scripts still point at the moved files and the package would still work.
    const root = f => { for (let d = path.dirname(f); d.startsWith(dir); d = path.dirname(d)) if (["package.json", "setup.py", "pyproject.toml"].some(m => fs.existsSync(path.join(d, m)))) return d; return dir; };
    for (const f of files) {
      const base = root(f), to = path.join(base, "dist", path.relative(base, f));
      fs.mkdirSync(path.dirname(to), { recursive: true });
      fs.renameSync(f, to);
    }
    for (const pj of walk(dir).filter(f => path.basename(f) === "package.json")) {
      try {
        const p = JSON.parse(fs.readFileSync(pj, "utf8"));
        const fix = s => typeof s === "string" ? s.replace(/(\bnode\s+(?:-\S+\s+)*)(?:\.\/)?([\w./-]+\.(?:c|m)?js)/g, "$1dist/$2") : s;
        for (const k of Object.keys(p.scripts || {})) p.scripts[k] = fix(p.scripts[k]);
        if (typeof p.main === "string") p.main = "dist/" + p.main.replace(/^\.\//, "");
        fs.writeFileSync(pj, JSON.stringify(p, null, 2));
      } catch {}
    }
    return files.length;
  }
  let changed = 0;
  for (const f of files) {
    let text; try { if (fs.statSync(f).size > 2e6) continue; text = fs.readFileSync(f, "utf8"); } catch { continue; }
    const next = MUTATIONS[name](text, f);
    if (next !== text) { fs.writeFileSync(f, next); changed++; }
  }
  return changed;
}

const work = fs.mkdtempSync(path.join(os.tmpdir(), "vetcode-mutate-"));
process.on("exit", () => remove(work));
const summary = {};
for (const eco of ONLY) {
  const clean = path.join(CACHE, eco, "benign");
  if (fs.existsSync(clean)) for (const name of Object.keys(MUTATIONS)) {
    const dest = path.join(OUT, name, eco, "benign");
    fs.mkdirSync(dest, { recursive: true });
    for (const f of fs.readdirSync(clean).sort().slice(0, N)) fs.copyFileSync(path.join(clean, f), path.join(dest, f));
  }
  const src = path.join(CACHE, eco, "malicious");
  if (!fs.existsSync(src)) continue;
  const picked = fs.readdirSync(src).sort().slice(0, N);
  for (const [i, f] of picked.entries()) {
    const base = path.join(work, `base-${i}`);
    if (!unpack(path.join(src, f), base)) { remove(base); continue; }
    unpackInner(base);
    for (const name of Object.keys(MUTATIONS)) {
      const dir = path.join(work, `${name}-${i}`);
      spawnSync("cp", ["-R", base, dir]);
      let changed = 0;
      try { changed = MUTATIONS[name] ? mutate(dir, name) : 1; } catch (e) { console.error(`${eco}/${f} ${name}: ${e.message}`); }
      const dest = path.join(OUT, name, eco, "malicious");
      fs.mkdirSync(dest, { recursive: true });
      // A sample the mutation could not touch would only repeat the baseline; leave it out.
      if (changed) spawnSync("tar", ["-czf", path.join(dest, f.replace(/\.(zip|tgz|tar\.gz)$/, "") + ".tgz"), "-C", dir, "."]);
      (summary[`${eco}/${name}`] ||= { samples: 0 }).samples += changed ? 1 : 0;
      remove(dir);
    }
    remove(base);
  }
}
remove(work);
console.log(JSON.stringify(summary, null, 1));
