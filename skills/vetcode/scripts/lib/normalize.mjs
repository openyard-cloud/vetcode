// Cheap, static undoing of the tricks that hide code from pattern scanners: string literals
// split into pieces, characters written as \xNN or \uNNNN escapes, and a payload packed into
// base64 and handed to eval/exec. Nothing is run; the decoded text is only read.
//
// decoded(text) returns the same text with literals joined and escapes decoded, line for line
// (escapes that would add a line break are left alone, so line numbers still match), or null
// when there was nothing to undo. payloads(text) returns base64 blobs given to eval/exec,
// decoded, with the line they sit on.

const LIT = String.raw`(["'])((?:[^"'\\\n]|\\.)*?)\1`;
const JOIN = new RegExp(String.raw`${LIT}[ \t]*\+[ \t]*${LIT.replace(/\\1/g, "\\3")}`, "g");
const ESC = /\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\u\{[0-9a-fA-F]{1,6}\}/;

function unescapeLiteral(s) {
  return s.replace(/\\x([0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})|\\u\{([0-9a-fA-F]{1,6})\}/g, (m, x, u, cp) => {
    const n = parseInt(x || u || cp, 16);
    // Only printable ASCII: hidden code is ASCII, while libraries escape Unicode on purpose
    // (bidi marks in a sanitiser, glyph tables). Line breaks stay escaped so lines still match.
    return n >= 0x20 && n <= 0x7e ? String.fromCharCode(n) : m;
  });
}

// Strings built at run time from character codes or written backwards:
//   String.fromCharCode(99, 104, 105)          "".join(map(chr, [99, 104, 105]))
//   bytes([99, 104, 105]).decode()              chr(99) + chr(104) + chr(105)
//   "ssecorp".split("").reverse().join("")      "ssecorp"[::-1]
const NUM = String.raw`(?:0x[0-9a-fA-F]{1,4}|\d{1,5})`, NUMS = String.raw`${NUM}(?:\s*,\s*${NUM})*`;
const BUILT = new RegExp([
  String.raw`String\.fromCharCode\(\s*(${NUMS})\s*,?\s*\)`,
  String.raw`(["'])\2\.join\(\s*map\(\s*chr\s*,\s*[\[(]\s*(${NUMS})\s*,?\s*[\])]\s*\)\s*\)`,
  String.raw`(["'])\4\.join\(\s*\[?\s*chr\(\s*(\w+)\s*\)\s*for\s+\5\s+in\s+[\[(]\s*(${NUMS})\s*,?\s*[\])]\s*\]?\s*\)`,
  String.raw`\bbytes(?:array)?\(\s*\[\s*(${NUMS})\s*,?\s*\]\s*\)\.decode\(\s*(?:["'][\w-]*["']\s*)?\)`,
  String.raw`\bchr\(\s*${NUM}\s*\)(?:\s*\+\s*chr\(\s*${NUM}\s*\))+`,
].join("|"), "g");
const BACKWARDS = new RegExp(String.raw`${LIT}(?:\.split\(\s*(["'])\3\s*\)\.reverse\(\)\.join\(\s*(["'])\4\s*\)|\[\s*::\s*-1\s*\])`, "g");
const HINT = /fromCharCode|\bchr\b|\bbytes(?:array)?\(\s*\[|\.reverse\(\)|\[\s*::\s*-1\s*\]/;

function fromCodes(list) {
  const codes = list.match(/0x[0-9a-fA-F]+|\d+/g).map(n => Number(n));
  // Printable ASCII only, as for escapes; anything else is data (a glyph table, a checksum).
  if (!codes.every(n => n >= 0x20 && n <= 0x7e)) return null;
  const s = String.fromCharCode(...codes);
  return s.includes('"') ? (s.includes("'") ? null : `'${s}'`) : `"${s}"`;
}
function rebuilt(text) {
  if (!HINT.test(text)) return text;
  let out = text.replace(BUILT, (m, js, q1, py1, q2, v, py2, by) => fromCodes(js || py1 || py2 || by || m.replace(/chr\(|\)|\+/g, ",").replace(/^[\s,]+|[\s,]+$/g, "")) ?? m);
  out = out.replace(BACKWARDS, (m, q, body) => /\\/.test(body) ? m : q + [...body].reverse().join("") + q);
  return out;
}

export function decoded(text) {
  const built = rebuilt(text);
  if (!built.includes("+") && !ESC.test(built)) return built === text ? null : built;
  let out = built;
  // "a" + "b" + "c" -> "abc" on the same line (twice covers the pieces each pass leaves).
  for (let pass = 0; pass < 4; pass++) {
    const next = out.replace(JOIN, (m, q1, a, q2, b) => q1 === q2 || (!a.includes(q1) && !b.includes(q1)) ? `${q1}${a}${b}${q1}` : m);
    if (next === out) break;
    out = next;
  }
  if (ESC.test(out)) out = out.replace(new RegExp(LIT, "g"), (m, q, body) => ESC.test(body) ? q + unescapeLiteral(body) + q : m);
  return out === text ? null : out;
}

// eval(Buffer.from("…", "base64").toString()), eval(atob("…")), exec(base64.b64decode("…")),
// exec(__import__("base64").b64decode("…")), exec(codecs.decode("…", "base64")).
const PACKED = /\b(?:eval|exec|Function|execSync)\s*\(\s*(?:Buffer\.from\(\s*|atob\(\s*|(?:__import__\(\s*["']base64["']\s*\)|base64)\.b64decode\(\s*|codecs\.decode\(\s*|(?:zlib|lzma|bz2|gzip)\.(?:decompress|inflateSync|gunzipSync|brotliDecompressSync|unzipSync|inflateRawSync)\(\s*(?:base64\.b64decode\(\s*|Buffer\.from\(\s*))(["'])([A-Za-z0-9+/=\s\\]{40,}?)\1/g;

export function payloads(text, depth = 0) {
  const out = [];
  for (const m of text.matchAll(PACKED)) {
    const b64 = m[2].replace(/\\n|\s/g, "");
    let body;
    try { const bytes = Buffer.from(b64, "base64"); body = bytes.toString("utf8"); if (!printable(body)) body = inflate(bytes) || body; } catch { continue; }
    // Only text that looks like code: mostly printable, not a binary blob.
    if (!body || /[\x00-\x08\x0e-\x1f]/.test(body.slice(0, 2000))) continue;
    const line = text.slice(0, m.index).split("\n").length;
    out.push({ line, text: body });
    // A payload packed twice is still one payload.
    if (depth < 2) for (const inner of payloads(body, depth + 1)) out.push({ line, text: inner.text });
  }
  return out;
}

import zlib from "node:zlib";

// Compressed bytes (gzip, zlib, raw deflate, brotli) inflated with a hard cap, so a crafted
// "bomb" cannot use up memory. Returns text or null.
const CAP = 2 << 20;
function inflate(buf) {
  for (const fn of [b => zlib.gunzipSync(b, { maxOutputLength: CAP }), b => zlib.inflateSync(b, { maxOutputLength: CAP }), b => zlib.brotliDecompressSync(b, { maxOutputLength: CAP }), b => zlib.inflateRawSync(b, { maxOutputLength: CAP })]) {
    try { const out = fn(buf).toString("utf8"); if (printable(out)) return out; } catch {}
  }
  return null;
}

// Long hex or base64 literals that decode (one or two layers) to something that reads like
// code: a payload kept aside to be run later, even when no eval sits next to it. Images,
// fonts and wasm decode to binary and are skipped.
const CODELIKE = /\brequire\s*\(|\bimport\s+[\w{*]|child_process|\bexec(?:Sync)?\s*\(|\beval\s*\(|\bsubprocess\b|\bos\.system\b|https?:\/\/|process\.env|\bsocket\b/;
const printable = s => { if (!s) return false; let bad = 0; for (let i = 0; i < Math.min(s.length, 4000); i++) { const c = s.charCodeAt(i); if (c < 9 || (c > 13 && c < 32) || c === 0xfffd) bad++; } return bad / Math.min(s.length, 4000) < 0.02; };
function unwrap(lit) {
  let v = lit;
  for (let layer = 0; layer < 2; layer++) {
    const hex = /^(?:[0-9a-fA-F]{2})+$/.test(v), b64 = !hex && /^[A-Za-z0-9+/]+={0,2}$/.test(v) && v.length % 4 === 0;
    if (!hex && !b64) return null;
    const bytes = Buffer.from(v, hex ? "hex" : "base64");
    v = bytes.toString("utf8");
    if (!printable(v)) { v = inflate(bytes); if (v == null) return null; }
    if (CODELIKE.test(v)) return v;
    v = v.trim();
  }
  return null;
}
export function stashed(text) {
  const out = [];
  let tries = 0;
  // Compressed payloads are short, so the floor is low; the number of attempts per file is capped.
  for (const m of text.matchAll(/(["'`])([0-9a-fA-F]{100,}|[A-Za-z0-9+/]{100,}={0,2})\1/g)) {
    if (++tries > 200) break;
    const body = unwrap(m[2]);
    if (body) out.push({ line: text.slice(0, m.index).split("\n").length, text: body });
    if (out.length >= 5) break;
  }
  return out;
}

/** The text plus its decoded view and any packed payloads, for checks that ask what a file can do. */
export function expanded(text) {
  const alt = decoded(text), packed = [...payloads(text), ...stashed(text)];
  return alt || packed.length ? [text, alt || "", ...packed.map(p => p.text)].join("\n") : text;
}
