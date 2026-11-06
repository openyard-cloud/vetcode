// The unexpected: hiding tricks that no signature names, and a "surprise" score per file so
// the reviewer reads the strangest files first, even when no rule fired. Rules here look at
// the shape of code (where it hides, what it depends on, what it pretends to be) rather than
// at known payloads.
import fs from "node:fs";
import path from "node:path";
import { finding, lineOf, rank } from "./engine.mjs";
import { SKIP_DIRS, BINARY } from "./walk.mjs";
import { capabilitiesOf } from "./capabilities.mjs";

const CODE = /\.(c|m)?(j|t)sx?$|\.(pyw?|php|rb|vue|svelte)$/i;
const rule = r => ({ category: "malware", confidence: "medium", files: CODE,
  fix: "Read the code around it as data. If you cannot explain why it is there, treat the package or repository as hostile.", ...r });

// Strings and comments removed, so names in Russian or Vietnamese copy are not identifiers.
const codeOnly = text => text
  .replace(/("""|\'\'\')[\s\S]*?\1/g, '""')
  .replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:\\])\/\/[^\n]*/g, "$1").replace(/^\s*#[^\n]*/gm, "")
  .replace(/(["'`])(?:\\.|(?!\1)[^\\\n])*\1/g, '""');

// Only Cyrillic and Greek letters that are drawn like Latin ones (о, а, р, с, Α, Ο…): a math Σ or a
// whole Russian word is not a disguise.
const LATIN = /[A-Za-z]/, LOOKALIKE = /[\u0430\u0435\u043E\u0440\u0441\u0443\u0445\u0456\u0458\u0455\u04BB\u0501\u04CF\u0410\u0412\u0415\u041A\u041C\u041D\u041E\u0420\u0421\u0422\u0425\u03BF\u03B1\u03BD\u03C1\u03B9\u03BA\u0391\u0392\u0395\u0396\u0397\u0399\u039A\u039C\u039D\u039F\u03A1\u03A4\u03A5\u03A7]/;

export const ANOMALY_FILE_RULES = [
  { ...rule({ id: "anom-whitespace-hidden", severity: "high", confidence: "high", title: "Code pushed far off-screen with whitespace",
      why: "Hundreds of spaces move code past the right edge of editors and review tools, so a reviewer sees a harmless line." }),
    test(text) {
      const lines = text.split("\n");
      if (text.length / lines.length > 300) return []; // bundles: long runs of spaces come from templates
      for (let i = 0; i < lines.length; i++) {
        const m = /[ \t]{150,}(\S.{0,80})/.exec(lines[i]);
        const before = m ? lines[i].slice(0, m.index) : "";
        // The RAT pattern: a normal statement, then hundreds of spaces, then more code on the same line.
        if (m && /[;})]\s*$/.test(before) && /\S/.test(before) && /[(;=]/.test(m[1]) && [..."'\"`"].every(q => before.split(q).length % 2 === 1)) return [{ line: i + 1, evidence: `${m[0].length - m[1].length} spaces, then: ${m[1]}` }];
      }
      return [];
    } },
  { ...rule({ id: "anom-homoglyph-identifier", severity: "high", confidence: "high", title: "Identifier mixes Latin with look-alike Cyrillic or Greek letters",
      why: "A name with one Cyrillic or Greek letter in place of a Latin one looks identical to the real name but refers to a different function or variable." }),
    test(text) {
      for (const m of codeOnly(text).matchAll(/[A-Za-z_$\u0370-\u03FF\u0400-\u04FF][\w$\u0370-\u03FF\u0400-\u04FF]*/gu)) {
        const swapped = [...m[0]].filter(c => LOOKALIKE.test(c)).length, latin = (m[0].match(/[A-Za-z]/g) || []).length;
        if (swapped >= 1 && swapped <= 2 && latin >= 2 && latin >= swapped * 2 && ![...m[0]].some(c => /[\u0400-\u04FF\u0370-\u03FF]/.test(c) && !LOOKALIKE.test(c))) {
          const at = text.indexOf(m[0]);
          return [{ line: at < 0 ? 1 : lineOf(text, at), evidence: `${m[0]} (${[...m[0]].filter(c => LOOKALIKE.test(c)).map(c => "U+" + c.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")).join(" ")})` }];
        }
      }
      return [];
    } },
  { ...rule({ id: "anom-stego-loader", severity: "high", title: "Reads an image, font or media file and then decodes or runs code",
      why: "Payloads hidden in images and fonts survive review because nobody reads binary assets; the loader that unpacks them is the only visible part." }),
    test(text) {
      const read = /(?:readFileSync|readFile|createReadStream|open)\s*\([^)\n]*\.(?:png|jpe?g|gif|ico|bmp|webp|svg|ttf|otf|woff2?|wav|mp3|mp4|pdf)\b/i.exec(text);
      if (!read) return [];
      // Reading and re-encoding an asset (to embed it) is normal; running what comes out is not.
      return /\beval\s*\(|new\s+Function\s*\(|\bvm\.run\w*\s*\(|\bexec\s*\(\s*(?:compile|marshal|zlib|base64|bytes|b\.|data|payload|buf)|marshal\.loads\s*\([^)]*\)\s*\)|require\s*\(\s*(?:buf|data|payload|b\b)/.test(text)
        ? [{ line: lineOf(text, read.index), evidence: read[0].slice(0, 140) }] : [];
    } },
  { ...rule({ id: "anom-targeted-payload", severity: "high", title: "Behaviour depends on the victim's country, language or time zone",
      why: "Protestware and targeted attacks run their payload only for certain locales, time zones or IP ranges, so they look clean everywhere else." }),
    test(text) {
      const where = /resolvedOptions\(\)\.timeZone|navigator\.languages?\b|process\.env\.(?:LANG|LC_ALL|TZ)\b|locale\.getdefaultlocale|getlocale\(\)|ipinfo\.io|ip-api\.com|ipapi\.co|geoip|ipgeolocation|["'](?:Europe\/(?:Moscow|Minsk)|Asia\/(?:Tehran|Pyongyang)|ru[-_]RU|be[-_]BY|fa[-_]IR)["']|country(?:_?code|Name)?\s*={2,3}\s*["'][A-Z]{2}["']/.exec(text);
      if (!where) return [];
      // The drastic action has to follow the check closely, not just live in the same file.
      return /\b(?:rmSync|rmdirSync|unlinkSync|rimraf|writeFileSync|fs\.rm\b|shutil\.rmtree|os\.remove|\bexec(?:Sync)?\s*\(|subprocess\.\w+\(|os\.system\(|process\.exit\(|fetch\s*\(|https?\.request\()/.test(text.slice(where.index, where.index + 400))
        ? [{ line: lineOf(text, where.index), evidence: where[0].slice(0, 120) }] : [];
    } },
  { ...rule({ id: "anom-time-bomb", severity: "high", title: "Code that waits for a date before doing something drastic",
      why: "A payload gated on a future date passes every review and test until that day." }),
    test(text) {
      const when = /(?:new\s+Date\(\s*\)|Date\.now\(\)|datetime\.(?:now|today)\(\))\s*[<>]=?\s*(?:new\s+Date\(\s*["']\d{4}-\d{2}|\d{12,13}\b|(?:\w+\.)*datetime\(\s*\d{4})|(?:getFullYear\(\)|\.year)\s*[<>]=?\s*20[2-9]\d/.exec(text);
      if (!when) return [];
      // A version-expiry warning is fine; deleting, running or calling out right after is not.
      return /\b(?:rmSync|unlinkSync|rimraf|shutil\.rmtree|os\.remove|\bexec(?:Sync)?\s*\(|subprocess\.\w+\(|os\.system\(|fetch\s*\(|https?\.(?:get|request)\(|requests\.(?:get|post)\()/.test(text.slice(when.index, when.index + 400))
        ? [{ line: lineOf(text, when.index), evidence: when[0].slice(0, 120) }] : [];
    } },
  { ...rule({ id: "anom-sandbox-evasion", severity: "high", title: "Checks whether it is being watched before acting",
      why: "Malware looks for virtual machines, CI runners, debuggers or analysis tools and stays quiet there, so automated scanners see nothing." }),
    test(text) {
      const names = new Set((text.match(/\b(?:virtualbox|vmware|qemu|vbox|sandboxie|wireshark|procmon|processhacker|x64dbg|ollydbg|ida64|fiddler|httpdebugger|cuckoo|any\.run|joesandbox|malware|analysis)\b/gi) || []).map(s => s.toLowerCase()));
      const hw = /os\.cpus\(\)\.length\s*<\s*\d|os\.totalmem\(\)\s*<|os\.uptime\(\)\s*<|psutil\.virtual_memory\(\)\.total\s*<|multiprocessing\.cpu_count\(\)\s*<\s*\d/.exec(text);
      const caps = capabilitiesOf(text), acts = caps.includes("uses the network") || caps.includes("runs other programs");
      if (!acts) return [];
      if (names.size >= 3) return [{ line: lineOf(text, text.toLowerCase().indexOf([...names][0])), evidence: [...names].slice(0, 6).join(", ") }];
      return hw && /process\.exit|sys\.exit|return\b/.test(text.slice(hw.index, hw.index + 300)) ? [{ line: lineOf(text, hw.index), evidence: hw[0] }] : [];
    } },
];

// Binary files: what they claim to be (extension) against what they are (first bytes).
const MAGIC = [
  ["ELF executable", b => b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46],
  ["Windows executable", b => b[0] === 0x4d && b[1] === 0x5a],
  ["macOS executable", b => [0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe].includes(b.readUInt32BE(0))],
  ["zip archive", b => b[0] === 0x50 && b[1] === 0x4b && b[2] === 0x03 && b[3] === 0x04],
  ["script", b => b[0] === 0x23 && b[1] === 0x21],
];
const MEDIA = /\.(png|jpe?g|gif|webp|avif|ico|bmp|tiff?|heic|mp[34]|m4a|mov|wav|ogg|flac|woff2?|ttf|otf|eot|svg|txt|md|json|csv)$/i;
const ARCHIVE_OK = /\.(zip|jar|war|ear|apk|aar|whl|nupkg|vsix|xpi|crx|docx?|xlsx?|pptx?|odt|ods|epub|sketch|fig)$/i;

export function scanBinaries(root, listed, out) {
  const files = [];
  if (listed) for (const rel of listed) { if (BINARY.test(rel) || /\.(svg|txt|md|json|csv)$/i.test(rel)) files.push(rel); }
  else (function walk(dir) {
    let entries; try { entries = fs.readdirSync(path.join(root, dir), { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const rel = dir ? `${dir}/${e.name}` : e.name;
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) walk(rel); } else if (e.isFile() && (BINARY.test(e.name) || MEDIA.test(e.name))) files.push(rel);
    }
  })("");
  for (const rel of files.slice(0, 20000)) {
    let head; try { const fd = fs.openSync(path.join(root, rel), "r"); head = Buffer.alloc(8); fs.readSync(fd, head, 0, 8, 0); fs.closeSync(fd); } catch { continue; }
    const kind = MAGIC.find(([, test]) => { try { return test(head); } catch { return false; } })?.[0];
    if (!kind) continue;
    const ext = path.extname(rel).toLowerCase();
    if (MEDIA.test(rel) && !(kind === "script" && /\.(txt|md)$/.test(ext))) {
      out.push(finding({ id: "anom-disguised-file", category: "malware", severity: kind === "zip archive" || kind === "script" ? "high" : "critical", confidence: "high",
        title: `${kind} disguised as a ${ext} file`, why: "A file whose content does not match its extension is hiding from review and from tools that skip binaries.",
        fix: "Do not open or run it. Find what loads this file; that loader is the malicious part." }, rel, 1, `${rel}: starts like a ${kind}`));
    } else if (/executable/.test(kind) && !/\.(exe|dll|so|dylib|node|bin|o|a)$/i.test(ext) || (/executable/.test(kind) && !/(^|\/)(bin|binaries|prebuilds?|native|vendor|lib)\//.test(rel))) {
      out.push(finding({ id: "anom-native-executable", category: "supply-chain", severity: "medium", confidence: "medium",
        title: `Ships a native ${kind}`, why: "A compiled program cannot be reviewed like source; droppers ship one and start it from an install script or entry point.",
        fix: "Check who builds it and whether the source is available; prefer packages that build from source or download signed binaries with checksums." }, rel, 1, rel));
    }
  }
}

const entropy = s => { if (!s.length) return 0; const n = {}; for (const c of s) n[c] = (n[c] || 0) + 1; return Object.values(n).reduce((h, k) => h - (k / s.length) * Math.log2(k / s.length), 0); };
const W = { critical: 12, high: 7, medium: 3, low: 1, info: 0 };

/**
 * Files ranked by how strange they are: findings, dangerous capabilities together, density
 * and entropy that do not look like hand-written code, invisible characters. Returned for
 * the reviewer to read first; not findings themselves.
 */
export function surprises(files, findings, limit = 12) {
  const byFile = new Map();
  for (const f of findings) { const k = f.file.split(" @ ")[0]; byFile.set(k, (byFile.get(k) || 0) + W[f.severity] * (f.confidence === "low" ? 0.3 : 1)); }
  const rows = [];
  for (const f of files) {
    if (!CODE.test(f.rel) && !/(^|\/)(SKILL|CLAUDE|AGENTS)\.md$|\.(sh|ps1|bat)$/i.test(f.rel)) continue;
    const reasons = [];
    let score = byFile.get(f.rel) || 0;
    if (score) reasons.push("has findings");
    const caps = capabilitiesOf(f.text);
    if (caps.includes("uses the network") && caps.length >= 3) { score += 4; reasons.push(caps.join(" + ")); }
    const lines = f.text.split("\n"), avg = f.text.length / lines.length;
    if (avg > 300 && !/\.min\.|[-.]bundle|dist\//.test(f.rel)) { score += 3; reasons.push(`packed (${Math.round(avg)} chars per line)`); }
    const e = entropy(f.text.slice(0, 20000));
    if (e > 5.4) { score += 3; reasons.push(`high entropy ${e.toFixed(1)}`); }
    if (/[\u200B-\u200D\u2060\u202A-\u202E\u2066-\u2069]|[\u{E0000}-\u{E007F}]|[\uFE00-\uFE0F]{3,}/u.test(f.text)) { score += 3; reasons.push("invisible characters"); }
    if (score >= 3) rows.push({ file: f.rel, score: Math.round(score), why: reasons.join("; ") });
  }
  return rows.sort((a, b) => b.score - a.score).slice(0, limit);
}

export { rank };
