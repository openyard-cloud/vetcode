// What a file can do, GuardDog-style: one capability is normal, but code that runs at
// install time and both reads secrets and talks to the network (or runs programs, or
// decodes hidden code) is how most package malware is built.
import fs from "node:fs";
import path from "node:path";
import { finding } from "./engine.mjs";

const CAPS = {
  "reads environment or credential files": /process\.env\b|os\.environ|os\.getenv|\.ssh[\\/]|\.npmrc|\.aws[\\/]|\.git-credentials|homedir\(\)|expanduser\(["']~/,
  "uses the network": /(?:exec|execSync|spawn|spawnSync|system|popen|run)\s*\([^)\n]*\b(?:curl|wget|nslookup|dig|nc|Invoke-WebRequest)\b|\bfetch\s*\(|https?\.(?:get|request)\s*\(|require\(["'](?:node:)?(?:https?|net|dgram|dns)["']\)|from\s+["'](?:node:)?(?:https?|net|dgram|dns)["']|\baxios\b|\bXMLHttpRequest\b|\bWebSocket\b|requests\.(?:get|post)|urllib\.request|urlopen|\bsocket\.socket|httpx\./,
  "collects user and host details": /os\.(?:hostname|userInfo|networkInterfaces)\(|getpass\.getuser|socket\.gethostname|platform\.node\(|\bwhoami\b/,
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

export function installEntryFiles(dir, scripts) {
  const files = new Set();
  for (const cmd of Object.values(scripts || {})) {
    for (const m of String(cmd).matchAll(/(?:^|[\s;&|])(?:node|nodejs|bun|deno\s+run(?:\s+-\S+)*|python\d?|sh|bash)\s+(?:-\S+\s+)*["']?([\w./@-]+\.(?:c?m?js|ts|py|sh))/g)) files.add(path.join(dir, m[1]));
  }
  if (fs.existsSync(path.join(dir, "setup.py"))) files.add(path.join(dir, "setup.py"));
  return [...files].filter(f => f.startsWith(dir) && fs.existsSync(f));
}

export function checkInstallEntry(abs, rel, out, installed, where = "install", { popular = false, ownApp = false } = {}) {
  let text; try { text = fs.readFileSync(abs, "utf8"); } catch { return; }
  const caps = capabilitiesOf(text);
  const net = caps.includes("uses the network");
  const risky = caps.filter(c => c !== "uses the network");
  const lib = where === "library";
  // Calling out at install time with nothing else is how dependency-confusion probes report a
  // hit. Popular binary downloaders (esbuild, puppeteer, chromedriver) do it too, so they are left out.
  if (net && !risky.length && !lib && !popular && !ownApp) {
    out.push(finding({ id: "install-time-network", category: "supply-chain", severity: "high", confidence: "medium", title: "Install-time code contacts a server",
      why: "This file runs during install and makes a network request. Ordinary packages build or do nothing at install; probes and beacons call home from here.",
      fix: "Read the file and see where it connects. If it is not downloading a documented binary from the project's own releases, do not install it." }, rel, 1, caps.join(" + ")));
    return;
  }
  if (!net || !risky.length) return;
  // A bundled library (tens of kilobytes of other people's code) nearly always has fetch next to
  // eval or process.env somewhere; only the stealer-specific capabilities say anything there.
  const bundle = lib && text.length > 40_000 && !risky.some(c => c === "collects user and host details" || c === "writes into home or startup folders");
  out.push(finding({ id: lib ? "library-entry-capabilities" : "install-time-capabilities", category: "supply-chain", severity: bundle ? "medium" : risky.length >= 2 || installed ? "critical" : "high", confidence: "medium",
    title: lib ? "Library entry point combines network access with secrets, programs or hidden code" : "Install-time code combines network access with secrets, programs or hidden code",
    why: `This file runs ${lib ? "as soon as the library is imported" : "during install"} and ${caps.join(", ")}. That combination is the shape of nearly every credential-stealing package.`,
    fix: "Read the whole file before installing. If it is a dependency, install with --ignore-scripts until it is explained." }, rel, 1, caps.join(" + ")));
}
