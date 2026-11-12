// What a file can do, GuardDog-style: one capability is normal, but code that runs at
// install time and both reads secrets and talks to the network (or runs programs, or
// decodes hidden code) is how most package malware is built.
import fs from "node:fs";
import path from "node:path";
import { finding } from "./engine.mjs";
import { decoded, expanded } from "./normalize.mjs";

const CAPS = {
  "reads environment or credential files": /process\.env\b|os\.environ|os\.getenv|\.ssh[\\/]|\.npmrc|\.aws[\\/]|\.git-credentials|homedir\(\)|expanduser\(["']~/,
  "uses the network": /(?:exec|execSync|spawn|spawnSync|system|popen|run)\s*\([^)\n]*\b(?:curl|wget|nslookup|dig|nc|Invoke-WebRequest)\b|\bfetch\s*\(|https?\.(?:get|request)\s*\(|require\(["'](?:node:)?(?:https?|net|dgram|dns)["']\)|from\s+["'](?:node:)?(?:https?|net|dgram|dns)["']|\baxios\b|\bXMLHttpRequest\b|\bWebSocket\b|requests\.(?:get|post)|urllib\.request|urlopen|\bsocket\.socket|httpx\.|(?:require\(|from\s+)["'](?:node-fetch|got|undici|request|superagent|needle|phin|discord\.js|discord-webhook-node|telegraf|node-telegram-bot-api|ws|socket\.io-client|ftp|basic-ftp|nodemailer)["']/,
  "collects user and host details": /os\.(?:hostname|userInfo|networkInterfaces)\(|getpass\.getuser|socket\.gethostname|platform\.node\(|\bwhoami\b|(?:require\(|from\s+)["'](?:systeminformation|public-ip|internal-ip|node-machine-id|getmac|macaddress|username|os-name)["']/,
  "writes into home or startup folders": /(?:writeFile|writeFileSync|createWriteStream|copyFile|open)\s*\([^)\n]*(?:homedir\(\)|\.vscode|\.ssh|LaunchAgents|AppData|Startup|\.bashrc|\.zshrc|expanduser)/,
  "runs other programs": /child_process|\bexecSync\b|\bspawnSync?\b|subprocess\.|os\.system|os\.popen/,
  "decodes or builds code at runtime": /\batob\s*\(|Buffer\.from\([^)]*["']base64["']|base64\.b64decode|String\.fromCharCode|\beval\s*\(|new\s+Function\s*\(|\bexec\s*\(\s*(?:compile|base64|zlib|marshal)/,
};

export function capabilitiesOf(text) {
  return Object.entries(CAPS).filter(([, re]) => re.test(text)).map(([name]) => name);
}

// Files a package runs at install: "node scripts/x.js", "python setup.py", "sh ./install.sh".
// What a published library runs when imported: its main/bin/module entry points.
export function libraryEntryFiles(dir, pkg) {
  if (!pkg || pkg.private || !pkg.name || !pkg.version) return [];
  const names = [pkg.main, pkg.module, ...(typeof pkg.bin === "string" ? [pkg.bin] : Object.values(pkg.bin || {})), "index.js"].filter(x => typeof x === "string");
  return [...new Set(names.map(n => path.join(dir, n.endsWith(".js") || n.endsWith(".mjs") || n.endsWith(".cjs") ? n : n + ".js")))].filter(f => f.startsWith(dir) && fs.existsSync(f) && fs.statSync(f).isFile());
}

export function installEntryFiles(dir, scripts, pkg) {
  const files = new Set();
  const main = () => { const m = pkg && typeof pkg.main === "string" ? pkg.main : "index.js"; return path.join(dir, /\.(c|m)?js$/.test(m) ? m : m + ".js"); };
  for (const cmd of Object.values(scripts || {})) {
    if (/(?:^|[\s;&|])node\s+(?:-\S+\s+)*\.\/?(?=$|[\s;&|])/.test(String(cmd))) files.add(main());
    for (const m of String(cmd).matchAll(/(?:^|[\s;&|])(?:node|nodejs|bun|deno\s+run(?:\s+-\S+)*|python\d?|sh|bash)\s+(?:-\S+\s+)*["']?([\w./@-]+\.(?:c?m?js|ts|py|sh))/g)) files.add(path.join(dir, m[1]));
  }
  if (fs.existsSync(path.join(dir, "setup.py"))) files.add(path.join(dir, "setup.py"));
  return [...files].filter(f => f.startsWith(dir) && fs.existsSync(f));
}

// An install script that only says require("./lib/setup") or exec("node x.js") moves the
// interesting part into another file; read those too (two levels, local files only).
const pkgRoot = abs => { for (let d = path.dirname(abs); d !== path.dirname(d); d = path.dirname(d)) if (fs.existsSync(path.join(d, "package.json")) || fs.existsSync(path.join(d, "setup.py"))) return d; return path.dirname(abs); };

// Libraries require their own modules all the time, so for a library entry only the files it
// starts as separate processes (fork, spawn node, exec node) are followed.
const LAUNCH = /\bfork\s*\(\s*["'`]([\w./-]+)["'`]|\bspawn(?:Sync)?\s*\(\s*["'`](?:node|process\.execPath)["'`]\s*,\s*\[\s*["'`]([\w./-]+)["'`]|\bnode\s+([\w./-]+\.(?:c|m)?js)\b/g;
const IMPORTS = /(?:require\(\s*|import\s*\(\s*|from\s+)["'](\.{1,2}\/[^"'\n]+)["']/g;

function withLocalDeps(abs, depth = 2, seen = new Set(), launchesOnly = false) {
  if (seen.has(abs) || seen.size > 12) return "";
  seen.add(abs);
  const root = seen.root ||= pkgRoot(abs);
  let text; try { if (fs.statSync(abs).size > 10e6) return ""; text = fs.readFileSync(abs, "utf8"); } catch { return ""; }
  if (depth === 0) return text;
  const dir = path.dirname(abs), deps = [];
  // File names can be hidden too: fork("sj.tini/stpircs".split("").reverse().join("")).
  const view = decoded(text) ?? text;
  const specs = [...view.matchAll(LAUNCH)].map(m => m[1] || m[2] || m[3]);
  if (!launchesOnly) specs.push(...[...view.matchAll(IMPORTS)].map(m => m[1]));
  for (const spec of specs) {
    // fork("scripts/x.js") resolves from the working directory, which at install is the package.
    for (const base of [dir, root]) for (const cand of [spec, spec + ".js", spec + ".cjs", spec + ".mjs", path.join(spec, "index.js")]) {
      const f = path.resolve(base, cand);
      if (f.startsWith(root) && fs.existsSync(f) && fs.statSync(f).isFile() && !deps.includes(f)) { deps.push(f); break; }
    }
  }
  return [text, ...deps.map(f => withLocalDeps(f, depth - 1, seen, launchesOnly))].join("\n");
}

// A file an install hook runs is run, even when it sits in test/ or fixtures/: keep its confidence.
const RUN = { confidence: "medium" };

export function checkInstallEntry(abs, rel, out, installed, where = "install", { popular = false, ownApp = false } = {}) {
  let text = withLocalDeps(abs, 2, new Set(), where === "library");
  try { text = expanded(text ?? fs.readFileSync(abs, "utf8")); } catch { return; }
  if (!text) return;
  // Obfuscated code that runs at install. Obfuscators turn every constant into hex arithmetic
  // (-0x49, 0x1f*-0x3); hand-written or minified install scripts do not look like that.
  if (where !== "library") {
    const hexOps = (text.match(/[-+*/<>=?:,(\[]\s*-?0x[0-9a-f]{1,8}\b/gi) || []).length;
    if (hexOps >= 60 && hexOps * 1000 / text.length >= 4) out.push(finding({ id: "install-runs-obfuscated-code", category: "supply-chain", severity: "high", confidence: "high", title: "Install script is obfuscated",
      why: "Code that runs on install has been put through an obfuscator (hex arithmetic everywhere, names that mean nothing). There is no honest reason to hide what an install step does.",
      fix: "Do not install it. If it was installed, treat the machine as exposed." }, rel, 1, `${hexOps} hex expressions in ${Math.round(text.length / 1024)} KB`, RUN));
  }
  // An install script that starts a Windows program shipped inside the package.
  const exe = where !== "library" && /(?:spawn|spawnSync|execFile|execFileSync|exec|execSync|startfile|Popen|call|run)\s*\([^\n;]{0,200}?["'][^"'\n]*\.(?:exe|scr|msi|com)["']/i.exec(text);
  if (exe) out.push(finding({ id: "install-runs-bundled-program", category: "supply-chain", severity: "critical", confidence: "high", title: "Install script starts a Windows program",
    why: "Installing a library should not launch an executable. This is how packages drop and run malware on Windows machines the moment they are installed.",
    fix: "Do not install it. If it was installed on Windows, treat that machine as compromised." }, rel, 1, exe[0].slice(0, 140), RUN));
  const caps = capabilitiesOf(text);
  const net = caps.includes("uses the network");
  const risky = caps.filter(c => c !== "uses the network");
  const lib = where === "library";
  // Calling out at install time with nothing else is how dependency-confusion probes report a
  // hit. Popular binary downloaders (esbuild, puppeteer, chromedriver) do it too, so they are left out.
  if (net && !risky.length && !lib && !popular && !ownApp) {
    out.push(finding({ id: "install-time-network", category: "supply-chain", severity: "high", confidence: "medium", title: "Install-time code contacts a server",
      why: "This file runs during install and makes a network request. Ordinary packages build or do nothing at install; probes and beacons call home from here.",
      fix: "Read the file and see where it connects. If it is not downloading a documented binary from the project's own releases, do not install it." }, rel, 1, caps.join(" + "), RUN));
    return;
  }
  if (!net || !risky.length) return;
  // A bundled library (tens of kilobytes of other people's code) nearly always has fetch next to
  // eval or process.env somewhere; only the stealer-specific capabilities say anything there.
  const bundle = lib && text.length > 40_000 && !risky.some(c => c === "collects user and host details" || c === "writes into home or startup folders");
  out.push(finding({ id: lib ? "library-entry-capabilities" : "install-time-capabilities", category: "supply-chain", severity: bundle ? "medium" : risky.length >= 2 || installed ? "critical" : "high", confidence: "medium",
    title: lib ? "Library entry point combines network access with secrets, programs or hidden code" : "Install-time code combines network access with secrets, programs or hidden code",
    why: `This file runs ${lib ? "as soon as the library is imported" : "during install"} and ${caps.join(", ")}. That combination is the shape of nearly every credential-stealing package.`,
    fix: "Read the whole file before installing. If it is a dependency, install with --ignore-scripts until it is explained." }, rel, 1, caps.join(" + "), lib ? {} : RUN));
}
