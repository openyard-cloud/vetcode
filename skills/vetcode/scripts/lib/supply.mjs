// Supply chain: code that runs when you install or open a project (install scripts, setup.py,
// VS Code tasks, git hooks), dependencies that are not what they seem (typosquats, git/http
// sources, unpinned versions, extra package indexes), CI workflows that can be hijacked,
// and MCP servers / browser extensions that ask for too much.
import fs from "node:fs";
import path from "node:path";
import { finding, lineOf } from "./engine.mjs";
import { POPULAR_SCOPES, KNOWN_SCOPES, KNOWN_NPM, KNOWN_PYPI, TARGET_NPM, TARGET_PYPI } from "./popular.mjs";
import { installEntryFiles, checkInstallEntry, libraryEntryFiles, capabilitiesOf } from "./capabilities.mjs";
import { expanded } from "./normalize.mjs";
import { weeklyDownloads } from "./registry.mjs";

const rule = r => ({ category: "supply-chain", confidence: "medium", ...r });
const readJson = text => { try { return JSON.parse(text.replace(/^\uFEFF/, "")); } catch { return null; } };
const lineIn = (text, needle) => { const i = text.indexOf(needle); return i < 0 ? 1 : lineOf(text, i); };

// Install hooks worth a second look: they fetch, decode, or start another program.
export const SUSPICIOUS_SCRIPT = /\b(?:curl|wget|Invoke-WebRequest|iwr|irm|certutil|bitsadmin)\b|\bnode\s+(?:-e|--eval|-p)\b|\bpython\d?\s+-c\b|\bbase64\b|\beval\b|https?:\/\/|\|\s*(?:ba|z)?sh\b|\.(?:sh|ps1|bat|cmd|exe|vbs)\b|\bpowershell\b|\bchmod\s+\+x\b|\/dev\/tcp|\bnc\s/i;
const INSTALL_HOOKS = ["preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare", "prepublish", "preuninstall", "uninstall", "postuninstall"];

// Damerau-Levenshtein distance, capped: we only care about 1 and 2.
function distance(a, b) {
  if (Math.abs(a.length - b.length) > 2) return 3;
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) {
    const cost = a[i - 1] === b[j - 1] ? 0 : 1;
    d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
    if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
  }
  return d[a.length][b.length];
}
const norm = n => n.toLowerCase().replace(/[-_.]+/g, "-");
const sameButOneDigit = (a, b) => { const diff = [...a].map((c, i) => i).filter(i => a[i] !== b[i]); return diff.length === 1 && /\d/.test(a[diff[0]]) && /\d/.test(b[diff[0]]); };

/** The popular package (or npm scope) a name imitates, if any. */
export function lookalike(name, popular, scopes = POPULAR_SCOPES, known = popular) {
  const n = norm(name);
  if (popular.has(n) || known.has(n)) return null;
  const scoped = n.match(/^@([^/]+)\/(.+)$/);
  if (scoped) {
    if (scopes.has(scoped[1]) || KNOWN_SCOPES.has(scoped[1])) return null;
    for (const s of scopes) if (s.length >= 4 && distance(scoped[1], s) === 1) return `@${s}/${scoped[2]}`;
    return null;
  }
  const core = n.replace(/(?:[-.]?js)$/, "").replace(/^node-/, "");
  for (const p of popular) {
    if (p.startsWith("@") || p.length < 5) continue;
    if (core !== n && core.length >= 4 && popular.has(core)) return null;
    if (n.startsWith(p) && /^\d+$/.test(n.slice(p.length))) continue; // httpx2, boto3: versioned names
    if (n.length === p.length && sameButOneDigit(n, p)) continue; // es6-shim / es7-shim: a numbered series
    if (distance(n, p) === 1 || (core !== n && core !== p && distance(core, p) === 1) || n === p + "s" || n === p + "-js" || n === p + "js" || n === "node-" + p || (p.includes("-") && n === p.replace(/-/g, ""))) return p;
  }
  return null;
}

// A name installed tens of thousands of times a week is a package in its own right; one installed
// a few hundred times next to a name installed millions of times is what a typosquat looks like.
export const WIDELY_USED = 20000, BARELY_USED = 2000;

/** With --online: settle each look-alike dependency by asking the registry how much the name is used. */
export async function settleLookalikes(findings, log = () => {}, fetchFn = fetch) {
  const drop = new Set();
  for (const f of findings.filter(x => x.rule === "dep-typosquat").slice(0, 25)) {
    const name = ((f.evidence || "").match(/^"([^"]+)"/) || [])[1];
    if (!name) continue;
    const n = await weeklyDownloads(fetchFn, /\.json$/.test(f.file) ? "npm" : "pypi", name);
    if (n === null) continue;
    if (n >= WIDELY_USED) { drop.add(f); log(`${name}: ${n} installs last week, a package of its own`); }
    else if (n < BARELY_USED) { f.severity = "high"; f.confidence = "high"; f.title = "Dependency name is one letter from a popular package, and almost nobody installs it"; f.evidence += ` · ${n} installs last week`; }
  }
  for (let i = findings.length - 1; i >= 0; i--) if (drop.has(findings[i])) findings.splice(i, 1);
}

// `node -e "console.log('Thanks for installing, see https://…')"`: a notice, nothing runs.
const PRINT_ONLY = /^\s*node\s+-e\s+(["'])\s*console\.(?:log|info|warn)\((?:(?!require|import|process|eval|Function|fetch|child_process|Buffer|\$\{).)*\)\s*;?\s*\1\s*$/s;
const isKnownNpm = name => KNOWN_NPM.has(String(name).toLowerCase().replace(/[_.]+/g, "-"));
const INSTALL_ODDITIES = [
  { id: "install-runs-non-code", re: /\b(?:node|nodejs)\s+(?:--?(?!e\b|p\b|eval\b|print\b)[\w-]+(?:=\S+)?\s+)*["']?[\w./-]+\.(?:md|txt|json|png|jpe?g|gif|css|html?|log|cfg|ini|ya?ml|lock)(?=["']?(?:\s|$|&|;|\|))/i,
    title: "Install script runs a non-code file as a program", why: "Running README.md or an image with node only works when code is hidden inside it, which is done to get past reviewers." },
  { id: "install-self-delete", re: /(?:&&|;)\s*(?:del|rm|rimraf|erase)\s+(?:-\w+\s+)*["']?[\w./\\-]+\.(?:c|m)?js\b/i,
    title: "Install script deletes the file it ran", why: "Removing the script right after running it leaves nothing to inspect; malware does this to cover its tracks." },
  { id: "install-fetches-packages", re: /\b(?:npm|yarn|pnpm)\s+(?:i|install|add)\s+(?!-)[@\w]/,
    title: "Install script installs other packages", why: "Dependencies belong in package.json, where they are visible and locked. Installing extra packages from a script hides what ends up on the machine." },
  { id: "install-runs-test-file", re: /\b(?:node|nodejs|python\d?|sh|bash)\s+(?:-\S+\s+)*["']?(?:\.\/)?(?:[\w.-]+\/)*(?:tests?|__tests__|spec|fixtures?|__fixtures__|__mocks__)\/[\w./-]+/i,
    title: "Install script runs a file from the tests or fixtures", why: "Tests and fixtures are not part of installing a package. Pointing an install hook at them hides the code that runs where reviewers and scanners treat it as test material." },
  { id: "install-hook-exfil", re: /\b(?:ping|nslookup|dig|host|curl|wget|nc|ncat|Invoke-WebRequest|iwr)\b[^\n]*(?:\$\{?(?:USER|USERNAME|HOSTNAME|HOME|LOGNAME|PWD|npm_package_name)\}?|\$\((?:whoami|hostname|pwd|id|uname[^)]*)\)|`(?:whoami|hostname|pwd)`|%(?:USERNAME|COMPUTERNAME|USERDOMAIN)%)|\b(?:ping|nslookup|dig|host|curl|wget)\b[^\n]*\b(?:burpcollaborator\.net|oast\.\w+|interact\.sh|dnslog\.cn|ceye\.io|requestbin|pipedream\.net|webhook\.site|canarytokens)/i,
    title: "Install script sends who you are to a server", why: "Putting the user name, host name or working folder into a ping, DNS lookup or web request at install time is how dependency-confusion probes report which machine installed them." },
  { id: "install-background", re: /\bnode\s[^&|;]*\s&\s*(?:$|;)|\bstart\s+\/B\b/i,
    title: "Install script keeps running in the background", why: "Detaching a process from the install lets it outlive the install and keep working unnoticed." },
];

// Medium: among the dependencies of real projects this is right about as often as it is wrong
// (react-rnd, graphiql and list.js are packages of their own), and only the registry can tell: how
// old the name is and how many people install it. The guard asks exactly that before an install.
const TYPO = rule({ id: "dep-typosquat", severity: "medium", title: "Dependency name is one letter from a popular package: check it on the registry",
  why: "Typosquats copy a popular name with one letter changed so a typo installs malware. Many real packages also sit one letter from a popular one.",
  fix: "Check the exact name on the registry (owner, downloads, age, repository link). If it was a typo, remove it and treat the machine as exposed if it was installed." });

const LOCKS = ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"];

function checkPackageJson(file, text, out, { installed = false, root } = {}) {
  const pkg = readJson(text);
  if (!pkg || typeof pkg !== "object") return;
  // A published package being vetted (npm never ships its lockfile) rather than a project
  // someone works in: its devDependencies never reach the people who install it.
  const published = !!root && !pkg.private && !!pkg.name && !!pkg.version && !LOCKS.some(l => fs.existsSync(path.join(root, path.dirname(file.rel), l)));
  for (const hook of INSTALL_HOOKS) {
    const cmd = pkg.scripts?.[hook];
    // prepare and prepublish run in the author's checkout, never when a package is installed from a registry.
    if (typeof cmd !== "string" || (installed && /prepare|prepublish/.test(hook))) continue;
    if (SUSPICIOUS_SCRIPT.test(cmd) && !PRINT_ONLY.test(cmd)) {
      out.push(finding(rule({ id: "install-script-suspicious", severity: installed || hook === "preinstall" ? "critical" : "high", confidence: "high",
        title: `${installed ? `Installed package ${pkg.name}` : "Package"} runs a suspicious "${hook}" script`,
        why: "Install scripts run with your user's rights the moment the package is installed; this one downloads, decodes or launches something.",
        fix: "Read the script and every file it starts before installing. Install with `--ignore-scripts` until you trust it." }), file.rel, lineIn(text, `"${hook}"`), `"${hook}": "${cmd}"`));
    } else if (installed && hook !== "prepare") {
      out.push(finding(rule({ id: "install-script", severity: "info", confidence: "high", title: `Installed package ${pkg.name} runs a "${hook}" script`,
        why: "Install scripts are where most npm malware lives; this one looks ordinary but runs on every install.", fix: "Know why it needs to; consider `npm config set ignore-scripts true` and allow-listing." }), file.rel, lineIn(text, `"${hook}"`), `"${hook}": "${cmd}"`));
    }
  }
  // Install commands shaped only the way attacks shape them.
  const hooks = INSTALL_HOOKS.filter(h => h !== "prepare" && typeof pkg.scripts?.[h] === "string");
  for (const hook of hooks) {
    const cmd = pkg.scripts[hook], odd = INSTALL_ODDITIES.find(o => o.re.test(cmd));
    if (odd) out.push(finding(rule({ id: odd.id, severity: "high", confidence: "high", title: odd.title, why: odd.why,
      fix: "Do not install it. If it is already installed, read every file the script ran and treat the machine as exposed." }), file.rel, lineIn(text, `"${hook}"`), `"${hook}": "${cmd}"`));
  }
  // Dependency confusion: an internal-sounding name published with a huge version number so it
  // outranks the company's private package, plus an install script to report the hit.
  if (hooks.length && !pkg.private && typeof pkg.name === "string" && parseInt(pkg.version, 10) >= 90 && !isKnownNpm(pkg.name)) {
    out.push(finding(rule({ id: "dep-confusion-version", severity: "high", title: `Version ${pkg.version} with an install script`,
      why: "Dependency-confusion packages use version numbers like 99.x so they win over a private package of the same name, and an install script to call home.",
      fix: "Check that this package really comes from the registry you expect; pin private packages to their scope and registry." }), file.rel, lineIn(text, `"version"`), `"version": "${pkg.version}"`));
  }
  // When vetting a package, its own name imitating a popular one is a strong signal.
  if (!pkg.private && typeof pkg.name === "string" && pkg.version) {
    const like = lookalike(pkg.name, TARGET_NPM, POPULAR_SCOPES, KNOWN_NPM);
    if (like) out.push(finding(rule({ id: "package-name-typosquat", severity: "high", title: "This package's name imitates a popular package",
      why: "Typosquats borrow a popular name with a small change so people install them by mistake.", fix: "Install the real package instead; treat this one as hostile." }), file.rel, lineIn(text, `"name"`), `"${pkg.name}" looks like "${like}"`));
  }
  if (installed) return;
  for (const section of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
    for (const [name, spec] of Object.entries(pkg[section] || {})) {
      if (typeof spec !== "string") continue;
      const at = lineIn(text, `"${name}"`);
      const like = lookalike(name, TARGET_NPM, POPULAR_SCOPES, KNOWN_NPM);
      if (like) out.push(finding(published && section !== "dependencies" && section !== "optionalDependencies" ? { ...TYPO, severity: "medium" } : TYPO, file.rel, at, `"${name}" looks like "${like}"`));
      if (spec === "*" || spec === "latest" || spec === "x" || spec === "") {
        out.push(finding(rule({ id: "dep-unpinned", severity: "low", title: "Dependency accepts any version",
          why: "Any future version, including a hijacked one, installs without review.", fix: "Pin a version range and commit the lockfile." }), file.rel, at, `"${name}": "${spec}"`));
      } else if (/^(?:git\+|git:|github:|gitlab:|bitbucket:|https?:\/\/)|^[\w-]+\/[\w.-]+(?:#.*)?$/.test(spec)) {
        out.push(finding(rule({ id: "dep-remote-source", severity: "medium", title: "Dependency installed from a URL or git repository",
          why: "It skips the registry: no integrity pin by default, the content can change under you, and its prepare script runs at install.", fix: "Use a published version, or pin to a full commit SHA you have reviewed." }), file.rel, at, `"${name}": "${spec}"`));
      }
    }
  }
}

function checkNpmLock(file, text, out) {
  const lock = readJson(text);
  if (!lock) return;
  const entries = lock.packages ? Object.entries(lock.packages) : Object.entries(lock.dependencies || {});
  const scripts = [];
  for (const [key, meta] of entries) {
    if (!key || !meta || meta.link) continue;
    const name = meta.name || key.replace(/^.*node_modules\//, "");
    if (meta.resolved && !/^https:\/\/registry\.(?:npmjs\.org|yarnpkg\.com)\//.test(meta.resolved) && !meta.resolved.startsWith("file:")) {
      out.push(finding(rule({ id: "lock-foreign-source", severity: /^http:/.test(meta.resolved) ? "high" : "medium", title: "Locked package comes from outside the npm registry",
        why: "A git URL, tarball URL or other registry can serve different code than the package you reviewed; plain http can be tampered with in transit.",
        fix: "Make sure the source is yours or trusted; prefer registry packages pinned with integrity hashes." }), file.rel, lineIn(text, meta.resolved), `${name} ← ${meta.resolved}`));
    }
    if (meta.hasInstallScript) scripts.push(name);
  }
  if (scripts.length) {
    out.push(finding(rule({ id: "lock-install-scripts", severity: "info", confidence: "high", title: `${scripts.length} locked package(s) run install scripts`,
      why: "These packages execute code on every `npm install`; they are the first place to look for supply-chain malware.",
      fix: "Review them (or run with --deps to scan node_modules); consider `ignore-scripts` with an allow-list." }), file.rel, 1, scripts.slice(0, 25).join(", ") + (scripts.length > 25 ? ` … +${scripts.length - 25}` : "")));
  }
}

function checkOtherLocks(file, text, out) {
  const re = /(?:resolved\s+"|resolution:\s*"[^"]*@|tarball:\s*)(https?:\/\/[^"\s]+)/g;
  for (const m of text.matchAll(re)) {
    if (/^https:\/\/registry\.(?:npmjs\.org|yarnpkg\.com)\//.test(m[1])) continue;
    out.push(finding(rule({ id: "lock-foreign-source", severity: m[1].startsWith("http:") ? "high" : "medium", title: "Locked package comes from outside the npm registry",
      why: "Code from an unexpected source can differ from the package you reviewed.", fix: "Check that the source is trusted." }), file.rel, lineOf(text, m.index), m[1]));
  }
}

function checkRequirements(file, text, out) {
  stealerKit(file, text, out);
  text.split(/\r?\n/).forEach((raw, i) => {
    const line = raw.replace(/#.*/, "").trim();
    if (!line) return;
    if (/^--?(?:extra-index-url|index-url|i|f|find-links|trusted-host)\b/.test(line)) {
      const extra = /extra-index-url|find-links/.test(line);
      out.push(finding(rule({ id: extra ? "pip-extra-index" : "pip-custom-index", severity: extra ? "high" : /http:\/\//.test(line) || /trusted-host/.test(line) ? "high" : "low",
        title: extra ? "Extra package index (dependency confusion)" : "Custom package index",
        why: extra ? "pip picks the highest version from all indexes: anyone can publish your private package name on PyPI with a bigger version and it wins." : "Packages come from a non-default server; over http or with trusted-host they can be tampered with.",
        fix: extra ? "Use a single index that proxies PyPI, or pin with `--require-hashes`." : "Use https and avoid --trusted-host." }), file.rel, i + 1, line));
      return;
    }
    if (/^-/.test(line)) return;
    if (/^(?:git\+|https?:\/\/|svn\+|hg\+)/.test(line) || /@\s*(?:git\+|https?:)/.test(line)) {
      out.push(finding(rule({ id: "dep-remote-source", severity: "medium", title: "Python dependency installed from a URL or repository",
        why: "It skips PyPI and its content can change.", fix: "Pin to a commit hash or use a published release." }), file.rel, i + 1, line));
      return;
    }
    // A requirement is a name, optional extras, version specifiers and markers; prose is not.
    const spec = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:(?:[<>=!~]=?|===)\s*[^\s;,]+(?:\s*,\s*(?:[<>=!~]=?|===)\s*[^\s;,]+)*)?\s*(?:;.*)?$/);
    const name = spec?.[1];
    if (!name) return;
    const like = lookalike(name, TARGET_PYPI, POPULAR_SCOPES, KNOWN_PYPI);
    if (like) out.push(finding(TYPO, file.rel, i + 1, `"${name}" looks like "${like}"`));
  });
}

function checkPyproject(file, text, out) {
  stealerKit(file, text, out);
  const names = new Set();
  for (const m of text.matchAll(/^\s*(?:dependencies|[\w-]+)\s*=\s*\[([\s\S]*?)\]/gm)) {
    if (!/^\s*dependencies|optional-dependencies/.test(text.slice(Math.max(0, m.index - 200), m.index + 20)) && !/^\s*dependencies/.test(m[0])) continue;
    for (const d of m[1].matchAll(/"([^"]*)"|'([^']*)'/g)) { const name = (d[1] ?? d[2]).match(/^\s*([A-Za-z0-9][A-Za-z0-9._-]*)/)?.[1]; if (name) names.add(name); }
  }
  for (const m of text.matchAll(/^\[tool\.poetry\.(?:dev-)?dependencies\]([\s\S]*?)(?=^\[)/gm)) for (const d of m[1].matchAll(/^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=/gm)) names.add(d[1]);
  for (const n of names) { const like = lookalike(n, TARGET_PYPI, POPULAR_SCOPES, KNOWN_PYPI); if (like && n.toLowerCase() !== "python") out.push(finding(TYPO, file.rel, lineIn(text, n), `"${n}" looks like "${like}"`)); }
}

const INSTALL_CMD = /class\s+\w+\s*\(\s*(?:\w+\.)?(?:install|develop|egg_info|build_py|build_ext|sdist|bdist_\w+)\s*\)/;
// Libraries that turn up in stealers' dependency lists far more than anywhere else.
const STEALER_KIT = /\b(?:browser[_-]?cookie3?|discord[_-]?webhook|discordwebhook|dhooks|robloxpy|pyautogui|pynput|pycryptodomex?|win32crypt|pypiwin32|pywin32|getmac|psutil|pyperclip)\b/gi;

function stealerKit(file, text, out) {
  const names = new Set((text.match(STEALER_KIT) || []).map(n => n.toLowerCase().replace(/[_-]/g, "")));
  const core = [...names].filter(n => /browsercookie|discordwebhook|dhooks|robloxpy/.test(n));
  if (!core.length || names.size < 2 && !/browsercookie/.test(core[0])) return;
  const at = text.search(STEALER_KIT);
  out.push(finding(rule({ id: "dep-stealer-kit", severity: "high", confidence: "high", title: "Depends on a credential-stealer toolkit",
    why: `It pulls in ${[...names].join(", ")}: browser-cookie and chat-webhook libraries together are the building blocks of token and password stealers.`,
    fix: "Unless the project is plainly a tool for your own browser data, do not install it." }), file.rel, lineOf(text, at), [...names].join(", ")));
}

function checkSetupPy(file, text, out) {
  stealerKit(file, text, out);
  // The package being vetted: a name one letter from a popular one, or a version number chosen
  // to outrank a private package of the same name, with code that runs on install.
  const name = text.match(/\bname\s*=\s*["']([A-Za-z0-9][\w.-]*)["']/), version = text.match(/\bversion\s*=\s*["'](\d+)[\w.]*["']/);
  const like = name && lookalike(name[1], TARGET_PYPI, POPULAR_SCOPES, KNOWN_PYPI);
  if (like) out.push(finding(rule({ id: "package-name-typosquat", severity: "high", title: "This package's name imitates a popular package",
    why: "Typosquats borrow a popular name with a small change so people install them by mistake.", fix: "Install the real package instead; treat this one as hostile." }), file.rel, lineOf(text, name.index), `"${name[1]}" looks like "${like}"`));
  if (version && +version[1] >= 90 && (/cmdclass/.test(text) || /\b(?:subprocess\.|os\.system|urlopen|requests\.|exec\s*\(|eval\s*\()/.test(text)) && !(name && KNOWN_PYPI.has(name[1].toLowerCase().replace(/[-_.]+/g, "-"))))
    out.push(finding(rule({ id: "dep-confusion-version", severity: "high", title: `Version ${version[0].replace(/^version\s*=\s*/, "")} with code that runs on install`,
      why: "Dependency-confusion packages use version numbers like 99.x so they win over a private package of the same name, and install-time code to call home.",
      fix: "Check that this package really comes from the index you expect; pin private packages to your own index." }), file.rel, lineOf(text, version.index), version[0]));
  if (INSTALL_CMD.test(text) && /cmdclass/.test(text)) {
    // Compiling extensions with subprocess is normal; an install-time command that talks to the
    // network, runs decoded code, posts to a webhook or starts an .exe is not.
    const onInstall = /class\s+\w+\s*\(\s*(?:\w+\.)?(?:install|develop|egg_info)\s*\)/.test(text);
    const acts = onInstall && text.match(/\b(?:requests\.|urllib|urlopen|urlretrieve|socket\.|exec\s*\(|eval\s*\(|startfile|Webhook|webhook|curl|wget|\.exe\b|powershell|Fernet|b64decode|whoami|hostname|getpass\.getuser|os\.getlogin|platform\.node)/);
    out.push(finding(rule({ id: "setup-py-install-command", severity: acts ? "high" : "medium", confidence: acts ? "high" : "medium",
      title: acts ? "setup.py overrides the install command to run code" : "setup.py overrides the install command",
      why: "A custom install command runs during `pip install` with your rights; malicious packages use it to download, beacon or start a payload before any code is imported.",
      fix: "Read the overridden run() method; install from a wheel or with --no-build-isolation in a throwaway environment if you must." }), file.rel, lineOf(text, text.search(INSTALL_CMD)), acts ? `install command + ${acts[0]}` : text.match(INSTALL_CMD)[0]));
  }
  const m = text.match(/\b(?:urllib\.request|urlopen|requests\.(?:get|post)|httpx\.|subprocess\.|os\.system|os\.popen|exec\s*\(|eval\s*\(|socket\.|base64\.b64decode|__import__\()/);
  // A module that happens to be called setup.py (an app's setup endpoint) is not run by pip.
  // pip runs the setup.py at the root of a distribution: the top of what is being read, a file that calls setup(), or one beside packaging metadata.
  const packaging = !file.rel.includes("/") || /\b(?:setuptools|distutils)\b|^\s*setup\s*\(/m.test(text) || (file.abs && ["PKG-INFO", "pyproject.toml", "setup.cfg", "MANIFEST.in"].some(f => fs.existsSync(path.join(path.dirname(file.abs), f))));
  if (!m || !packaging) return;
  // Building C extensions or reading git tags needs subprocess; fetching or decoding code does not.
  // Running the text of a file the package opens itself (pkg/version.py, to read the version) is fine.
  const runsDecoded = /\b(?:exec|eval)\s*\((?!\s*(?:compile\s*\()?\s*open\s*\()(?![^)\n]*\.read\(\))[^\n]*/.test(text) && /b64decode|decompress|marshal|fromhex|unhexlify|__import__/.test(text);
  const strong = /\b(?:urllib\.request|urlopen|requests\.(?:get|post)|httpx\.(?:get|post)|socket\.socket|socket\.connect)\b|\b(?:curl|wget|powershell)\b/.test(text) || runsDecoded;
  out.push(finding(rule({ id: "setup-py-runs-code", severity: strong ? "high" : "low", title: strong ? "setup.py fetches, decodes or evaluates code" : "setup.py runs shell commands",
    why: "setup.py executes during `pip install`; downloading or launching programs there is a classic way to ship malware.",
    fix: "Read exactly what it runs. Prefer packages that ship wheels; install untrusted ones in a throwaway container." }), file.rel, lineOf(text, m.index), text.split("\n")[lineOf(text, m.index) - 1]));
}

const GH_INPUT = /\$\{\{\s*github\.(?:event\.(?:issue|pull_request|comment|review|review_comment|discussion|discussion_comment|head_commit|pages|commits|workflow_run)\b[\w.[\]*'"-]*\.(?:title|body|head_ref|ref|label|message|name|email|default_branch|page_name)|head_ref)\s*\}\}/;

// Actions that were compromised in the past: pin them by SHA to a version you have checked.
const ONCE_COMPROMISED = /^(?:tj-actions\/(?:changed-files|eslint-changed-files|verify-changed-files)|reviewdog\/action-[\w-]+|ultralytics\/actions)$/i;

// Who owns the repository being read, from its git remote (lower case), or "" when it cannot be told.
const owners = new Map();
function repoOwner(abs) {
  let dir = abs ? path.dirname(abs) : "";
  for (let i = 0; dir && i < 8; i++, dir = path.dirname(dir)) {
    if (owners.has(dir)) return owners.get(dir);
    const cfg = path.join(dir, ".git", "config");
    if (fs.existsSync(cfg)) {
      let text = ""; try { text = fs.readFileSync(cfg, "utf8"); } catch { /* unreadable: unknown */ }
      const owner = ((text.match(/url\s*=\s*\S*github\.com[:/]([\w.-]+)\//i) || [])[1] || "").toLowerCase();
      owners.set(dir, owner);
      return owner;
    }
    if (path.dirname(dir) === dir) break;
  }
  return "";
}

function checkWorkflow(file, text, out) {
  const lines = text.split(/\r?\n/);
  const w = rule => out.push(finding(rule.r, file.rel, rule.line, rule.ev));
  // Whole-workflow checks (zizmor's artipacked, excessive-permissions, self-hosted-runner, dangerous-triggers).
  const uploads = /uses:\s*actions\/upload-artifact/.test(text);
  for (const m of text.matchAll(/uses:\s*actions\/checkout@[^\n]*((?:\n\s+[^\n-][^\n]*)*)/g)) {
    if (uploads && !/persist-credentials:\s*false/.test(m[1])) w({ r: rule({ id: "gha-persisted-credentials", severity: "low", confidence: "medium", title: "Checkout keeps the token on disk in a job that uploads artifacts",
      why: "actions/checkout writes the GITHUB_TOKEN into .git/config; uploading the workspace publishes it (\"artipacked\").", fix: "Add `persist-credentials: false` to the checkout step." }), line: lineOf(text, m.index), ev: "actions/checkout without persist-credentials: false" });
  }
  if (!/^permissions\s*:/m.test(text) && !/^\s{2,}permissions\s*:/m.test(text)) w({ r: rule({ id: "gha-default-permissions", severity: "low", confidence: "high", title: "Workflow does not limit its token",
    why: "Without a permissions block the token gets the repository default, which is often write access.", fix: "Add `permissions: { contents: read }` at the top and widen per job." }), line: 1, ev: "no permissions: block" });
  const pub = /\bon\s*:[\s\S]{0,200}?\b(pull_request|pull_request_target|issue_comment|workflow_run)\b/.test(text);
  const selfHosted = text.match(/runs-on\s*:\s*\[?[^\n]*self-hosted/);
  if (pub && selfHosted) w({ r: rule({ id: "gha-self-hosted-untrusted", severity: "high", confidence: "medium", title: "Self-hosted runner used for events outsiders can trigger",
    why: "On a public repository, a pull request or comment can run code on your own machine.", fix: "Use GitHub-hosted runners for untrusted events, or ephemeral isolated runners." }), line: lineOf(text, selfHosted.index), ev: selfHosted[0].trim() });
  for (const m of text.matchAll(/credentials\s*:\s*\n\s+username\s*:[^\n]*\n\s+password\s*:\s*(?!\$\{\{)(\S+)/g)) w({ r: rule({ id: "gha-hardcoded-registry-password", severity: "high", confidence: "high", title: "Container registry password written in the workflow",
    why: "Anyone who can read the repository has it.", fix: "Use `${{ secrets.NAME }}`." }), line: lineOf(text, m.index), ev: "credentials.password: " + m[1].slice(0, 3) + "…" });
  if (/\bnpm\s+publish\b|\btwine\s+upload\b|pypa\/gh-action-pypi-publish/.test(text) && /NODE_AUTH_TOKEN|NPM_TOKEN|PYPI_(?:API_)?TOKEN|TWINE_PASSWORD|password\s*:\s*\$\{\{\s*secrets/.test(text) && !/id-token\s*:\s*write/.test(text))
    w({ r: rule({ id: "gha-long-lived-publish-token", severity: "low", confidence: "medium", title: "Publishes with a long-lived registry token",
      why: "A stolen token publishes malicious versions of your package; worms like Shai-Hulud spread exactly this way.", fix: "Use trusted publishing (OIDC: `permissions: id-token: write`) on npm and PyPI, and remove the token secret." }), line: lineOf(text, text.search(/npm\s+publish|twine\s+upload|gh-action-pypi-publish/)), ev: "registry token in a publish workflow" });
  const prt = /^\s*(?:pull_request_target|workflow_run|issue_comment)\s*:|on:\s*\[?[^\]\n]*(?:pull_request_target|workflow_run|issue_comment)/m.test(text);
  let inRun = false, runIndent = -1;
  lines.forEach((line, i) => {
    const indent = line.search(/\S/);
    // A script is the text under `run: |`; a one-line `run: cmd` has none below it, and the keys
    // beside it (`env:`, `with:`) are where untrusted text is supposed to go.
    const runKey = line.match(/^(\s*)(-\s+)?run\s*:\s*(.*)$/);
    if (runKey) { inRun = /^[|>][+-]?\d*\s*(?:#.*)?$/.test(runKey[3].trim()); runIndent = runKey[1].length + (runKey[2]?.length || 0); }
    else if (inRun && indent >= 0 && indent <= runIndent && line.trim()) inRun = false;
    // The base of a pull request (its ref, sha, label) is a branch of this repository, not the author's text.
    if ((inRun || /^\s*-?\s*run\s*:/.test(line) || /script\s*:/.test(line)) && GH_INPUT.test(line.replace(/\$\{\{[^}]*\.base\.(?:ref|sha|label)[^}]*\}\}/g, ""))) {
      out.push(finding(rule({ id: "gha-script-injection", severity: "high", confidence: "high", title: "Untrusted event text inside a workflow script",
        why: "A PR title, branch name or comment becomes shell code: anyone opening a PR or issue can run commands with the workflow's token and secrets.",
        fix: "Pass it through `env:` (e.g. `TITLE: ${{ github.event.pull_request.title }}`) and use \"$TITLE\" in the script." }), file.rel, i + 1, line));
    }
    // The PR's code has to be fetched: a `ref:` for the checkout, or a git/gh command. Reading
    // the branch name in an `if:` runs nothing of the attacker's.
    if (prt && /\bref\s*:[^\n]*(?:github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|refs\/pull\/|workflow_run\.head_(?:sha|branch))|\bgit\s+(?:fetch|checkout|pull|merge)\b[^\n]*(?:refs\/pull\/|\bpull\/|github\.head_ref|pull_request\.head)|\bgh\s+pr\s+checkout\b/.test(line)) {
      out.push(finding(rule({ id: "gha-pwn-request", severity: "critical", confidence: "high", title: "Privileged workflow checks out the PR's code",
        why: "pull_request_target, workflow_run and issue_comment run with write tokens and secrets; building or running the attacker's PR code there hands them over.",
        fix: "Use `pull_request` for building untrusted code, or never run the checked-out code in the privileged job." }), file.rel, i + 1, line));
    }
    // Text an outsider writes (a title, a branch name, a comment), not a number or the maintainers' own tag.
    if (GH_INPUT.test(line) && />>\s*"?\$\{?GITHUB_(?:ENV|PATH)\b/.test(line)) {
      out.push(finding(rule({ id: "gha-github-env-injection", severity: "high", confidence: "high", title: "Event data written to GITHUB_ENV / GITHUB_PATH",
        why: "An attacker-controlled value can set environment variables (LD_PRELOAD, NODE_OPTIONS) or PATH for every later step.", fix: "Never write event data there; pass it through step outputs or env." }), file.rel, i + 1, line));
    }
    if (/\bsecrets\s*:\s*inherit\b|toJSON\(\s*secrets\s*\)|ACTIONS_ALLOW_UNSECURE_COMMANDS/.test(line)) {
      // Handing every secret to a workflow in the same repository keeps them where they already are;
      // a workflow from another repository is the case to read.
      const depth = l => l.search(/\S/), mine = depth(line);
      // The job's own `uses:`: the nearest one at the same depth, without leaving the job.
      let uses = null;
      for (const step of [-1, 1]) for (let k = i + step; !uses && k >= 0 && k < lines.length && (depth(lines[k]) < 0 || depth(lines[k]) >= mine); k += step) if (depth(lines[k]) === mine && /^\s*uses\s*:/.test(lines[k])) uses = lines[k];
      const own = ((uses || "").match(/^\s*uses\s*:\s*["']?([\w.-]+)\//) || [])[1];
      const local = /\bsecrets\s*:\s*inherit\b/.test(line) && (/^\s*uses\s*:\s*["']?\.\//.test(uses || "") || (!!own && own.toLowerCase() === repoOwner(file.abs)));
      out.push(finding(rule({ id: "gha-secrets-overexposed", severity: local ? "low" : "medium", confidence: "high", title: local ? "Workflow passes all its secrets to another workflow in this repository" : "Workflow hands out all secrets or re-enables unsafe commands",
        why: "Every secret becomes available to the called workflow or step, or old `set-env` commands can be injected through logs.", fix: "Pass only the secrets a job needs; remove ACTIONS_ALLOW_UNSECURE_COMMANDS." }), file.rel, i + 1, line.trim()));
    }
    if (/github\.actor\s*==\s*['"](?:dependabot|renovate|github-actions)\[bot\]['"]/.test(line)) {
      out.push(finding(rule({ id: "gha-spoofable-bot-check", severity: "medium", title: "Trust decided by github.actor",
        why: "github.actor is whoever triggered the latest event; it can be the bot while the code came from someone else.", fix: "Check `github.event.pull_request.user.login` and the event type instead." }), file.rel, i + 1, line.trim()));
    }
    if (/^\s*permissions\s*:\s*write-all\b/.test(line)) {
      out.push(finding(rule({ id: "gha-write-all", severity: "medium", confidence: "high", title: "Workflow token has write access to everything",
        why: "Any compromised step can push code, create releases or change settings.", fix: "Grant only what the job needs (`contents: read`, ...)." }), file.rel, i + 1, line));
    }
    if (/\becho\b[^\n]*\$\{\{\s*secrets\./.test(line) && !/\$\{\{\s*secrets\.[^}]*\}\}[^\n|>]*["']?\s*(?:\||>)/.test(line)) {
      out.push(finding(rule({ id: "gha-secret-echo", severity: "high", confidence: "high", title: "Secret printed in a workflow",
        why: "Masking is easy to bypass (encoding, splitting); printed secrets end up in logs.", fix: "Never print secrets; pass them via env to the tool that needs them." }), file.rel, i + 1, line));
    }
    const uses = line.match(/^\s*-?\s*uses\s*:\s*([\w.-]+\/[\w./-]+)@([\w.-]+)/);
    if (uses && ONCE_COMPROMISED.test(uses[1]) && !/^[0-9a-f]{40}$/.test(uses[2])) {
      out.push(finding(rule({ id: "gha-once-compromised-action", severity: "medium", confidence: "high", title: `${uses[1]} was compromised before and is not pinned`,
        why: "Its tags were moved to malicious code in a past incident; a tag reference would pick that up again.", fix: "Pin to a reviewed commit SHA, or replace it." }), file.rel, i + 1, line.trim()));
    }
    // Once per action in a workflow: ten steps using the same action are one thing to fix.
    // Actions from the organisation that owns this repository are its own code on its own branch.
    if (uses && !/^(?:actions|github)\//.test(uses[1]) && uses[1].split("/")[0].toLowerCase() !== repoOwner(file.abs) && !/^[0-9a-f]{40}$/.test(uses[2]) && !out.some(f => f.rule === "gha-unpinned-action" && f.file === file.rel && f.evidence.includes(`${uses[1]}@${uses[2]}`))) {
      out.push(finding(rule({ id: "gha-unpinned-action", severity: /^(main|master|dev|develop|latest|HEAD)$/.test(uses[2]) ? "medium" : "low", confidence: "high", title: "Third-party action pinned to a tag, not a commit",
        why: "Tags can be moved: a compromised action repository can change what runs in your CI (as in the tj-actions incident).", fix: `Pin to the full commit SHA: uses: ${uses[1]}@<sha> # ${uses[2]}` }), file.rel, i + 1, line.trim()));
    }
  });
  const trig = text.match(/^\s*(pull_request_target|workflow_run)\s*:|^on\s*:\s*\[?[^\n]*(pull_request_target|workflow_run)/m);
  if (trig && !out.some(f => f.rule === "gha-pwn-request" && f.file === file.rel)) w({ r: rule({ id: "gha-dangerous-trigger", severity: "low", confidence: "medium", title: `Workflow uses ${trig[1] || trig[2]}`,
    why: "This trigger runs with secrets and a write token even for outside contributors; it is safe only if no step touches their code or text.", fix: "Prefer pull_request; if you need this trigger, never check out or interpolate PR content." }), line: lineOf(text, trig.index), ev: trig[0].trim() });
}

function checkVscode(file, text, out) {
  const m = text.match(/"runOn"\s*:\s*"folderOpen"/);
  if (m) out.push(finding(rule({ id: "vscode-autorun-task", severity: "high", confidence: "high", title: "VS Code task runs automatically when the folder opens",
    why: "Malicious repositories (fake job interviews, 'test projects') use this to run code the moment you open them.",
    fix: "Read the task's command before trusting the workspace; remove runOn if it is not yours." }), file.rel, lineOf(text, m.index), text.split("\n")[lineOf(text, m.index) - 1]));
}

function checkMcp(file, text, out) {
  const cfg = readJson(text);
  const servers = cfg?.mcpServers || cfg?.servers || cfg?.mcp?.servers;
  if (!servers || typeof servers !== "object") return;
  for (const [name, s] of Object.entries(servers)) {
    if (!s || typeof s !== "object") continue;
    const cmd = [s.command, ...(s.args || [])].filter(Boolean).join(" ");
    const at = lineIn(text, `"${name}"`);
    if (SUSPICIOUS_SCRIPT.test(cmd) && /curl|wget|\|\s*sh|powershell|base64|eval/i.test(cmd)) {
      out.push(finding(rule({ id: "mcp-suspicious-command", severity: "critical", confidence: "high", title: `MCP server "${name}" downloads or decodes code to run`,
        why: "MCP servers run on your machine with your rights.", fix: "Remove it unless you know exactly what it runs." }), file.rel, at, cmd));
    }
    if (typeof s.url === "string" && /^http:\/\/(?!localhost|127\.0\.0\.1|\[::1\])/.test(s.url)) {
      out.push(finding(rule({ id: "mcp-plain-http", severity: "high", confidence: "high", title: `MCP server "${name}" is reached over plain HTTP`,
        why: "Anyone on the network path can read the traffic and inject tool results.", fix: "Use https." }), file.rel, at, s.url));
    }
    const pkg = /^(?:npx|bunx|pnpm\s+dlx|uvx|pipx\s+run)$/.test(String(s.command)) ? (s.args || []).find(a => !String(a).startsWith("-")) : null;
    if (pkg && !/@\d|==\d|#v?\d|#[0-9a-f]{7,40}\b/.test(String(pkg).replace(/^@[^/]+\//, ""))) {
      out.push(finding(rule({ id: "mcp-unpinned", severity: "medium", confidence: "high", title: `MCP server "${name}" runs the latest version of ${pkg}`,
        why: "Every start fetches whatever is newest; a hijacked release runs on your machine without review.", fix: `Pin a version you reviewed, e.g. ${pkg}@1.2.3.` }), file.rel, at, cmd));
    }
  }
}

function checkExtensionManifest(file, text, out) {
  const m = readJson(text);
  if (!m || !m.manifest_version) return;
  const perms = [...(m.permissions || []), ...(m.host_permissions || []), ...(m.optional_permissions || [])].map(String);
  const risky = perms.filter(p => /^(?:<all_urls>|\*:\/\/\*\/\*|https?:\/\/\*\/\*|debugger|nativeMessaging|proxy|webRequestBlocking|cookies|history|management|clipboardRead|desktopCapture|declarativeNetRequestWithHostAccess)$/.test(p));
  if (risky.length) out.push(finding(rule({ id: "ext-broad-permissions", severity: "medium", title: "Browser extension asks for powerful permissions",
    why: "With these it can read or change every page, cookies or traffic; a malicious update would inherit them.", fix: "Keep only what the features need; prefer activeTab and specific host patterns." }), file.rel, lineIn(text, risky[0]), risky.join(", ")));
  const csp = JSON.stringify(m.content_security_policy || "");
  if (/unsafe-eval/.test(csp)) out.push(finding(rule({ id: "ext-unsafe-eval", severity: "high", title: "Extension CSP allows unsafe-eval",
    why: "Remote or injected strings can run as code inside the extension.", fix: "Remove unsafe-eval." }), file.rel, lineIn(text, "unsafe-eval"), "content_security_policy: unsafe-eval"));
  if ((m.externally_connectable?.matches || []).some(x => /^\*|:\/\/\*\//.test(x))) out.push(finding(rule({ id: "ext-externally-connectable", severity: "medium", title: "Any website can message the extension",
    why: "Pages can send it commands.", fix: "List the exact origins." }), file.rel, lineIn(text, "externally_connectable"), JSON.stringify(m.externally_connectable)));
}

const HOOKS = /(^|\/)(\.husky\/[^/_][^/]*|\.githooks\/[^/]+)$/;

export function scanSupplyChain(file, text, out, root) {
  const base = path.basename(file.rel);
  if (base === "package.json") checkPackageJson(file, text, out, { root });
  else if (base === "package-lock.json" || base === "npm-shrinkwrap.json") checkNpmLock(file, text, out);
  else if (base === "yarn.lock" || base === "pnpm-lock.yaml" || base === "bun.lock") checkOtherLocks(file, text, out);
  else if (/^requirements[\w.-]*\.(txt|in)$/.test(base) || (base === "constraints.txt" && /^(?:[^/]+\/)?(?:requirements\/)?constraints\.txt$/.test(file.rel) && !/(^|\/)(docs?|contrib|tests?)\//.test(file.rel))) checkRequirements(file, text, out);
  else if (base === "pyproject.toml") checkPyproject(file, text, out);
  else if (base === "setup.py") checkSetupPy(file, text, out);
  else if (/\.github\/workflows\/[^/]+\.ya?ml$/.test(file.rel)) checkWorkflow(file, text, out);
  else if (/\.vscode\/tasks\.json$/.test(file.rel)) checkVscode(file, text, out);
  else if (/(^|\/)(\.mcp\.json|mcp\.json|claude_desktop_config\.json|mcp_config\.json|\.cursor\/mcp\.json)$/.test(file.rel)) checkMcp(file, text, out);
  else if (base === "manifest.json") checkExtensionManifest(file, text, out);
  if (HOOKS.test(file.rel) && SUSPICIOUS_SCRIPT.test(text) && /curl|wget|\|\s*sh|base64|eval|powershell/i.test(text)) {
    out.push(finding(rule({ id: "git-hook-suspicious", severity: "high", title: "Git hook downloads or decodes something",
      why: "Hooks run on commit/checkout without asking.", fix: "Read the hook before installing hooks from this repository." }), file.rel, 1, text.split("\n").find(l => SUSPICIOUS_SCRIPT.test(l)) || ""));
  }
}

const relTo = (root, abs) => path.relative(root, abs).split(path.sep).join("/");
const hookScripts = pkg => Object.fromEntries(INSTALL_HOOKS.filter(h => typeof pkg?.scripts?.[h] === "string").map(h => [h, pkg.scripts[h]]));

/** Installed npm packages: install scripts and malware rules on their files (--deps). */
export function scanInstalledPackage(dir, root, out) {
  const text = fs.readFileSync(path.join(dir, "package.json"), "utf8");
  checkPackageJson({ rel: relTo(root, path.join(dir, "package.json")) }, text, out, { installed: true });
  const pkg = readJson(text), hooks = Object.fromEntries(Object.entries(hookScripts(pkg)).filter(([h]) => !/prepare|prepublish/.test(h)));
  for (const f of installEntryFiles(dir, hooks, pkg)) checkInstallEntry(f, relTo(root, f), out, true, "install", { popular: isKnownNpm(pkg?.name) });
  return Object.keys(hooks).length > 0;
}

/** Python code that runs on import: a package __init__.py that phones home with system details. */
export function scanPythonImportTime(files, out) {
  for (const f of files) {
    if (!/(^|\/)__init__\.py$/.test(f.rel) || f.text.length > 40_000 || /(^|\/)(tests?|docs?|examples?)\//.test(f.rel)) continue;
    const caps = capabilitiesOf(expanded(f.text));
    // Running programs alone is common (setuptools, build helpers); a beacon collects identity or hides code.
    const risky = caps.filter(c => ["collects user and host details", "decodes or builds code at runtime", "writes into home or startup folders"].includes(c));
    if (!caps.includes("uses the network") || !risky.length) continue;
    out.push(finding(rule({ id: "import-time-capabilities", severity: risky.length >= 2 ? "critical" : "high", title: "Package __init__.py reaches out on import",
      why: `This runs as soon as anyone imports the package, and it ${caps.join(", ")}. Libraries rarely need that at import time; beacons and stealers do.`,
      fix: "Read the whole file; pin a version you reviewed or remove the package." }), f.rel, 1, caps.join(" + ")));
  }
}

/** The project's own install-time files (package.json hooks, setup.py). */
export function scanProjectInstallEntries(root, files, out) {
  const atInstall = new Set(); // the files an install script starts: what runs before anyone decides to run anything
  for (const f of files) {
    if (!/(^|\/)package\.json$/.test(f.rel)) continue;
    const dir = path.join(root, path.dirname(f.rel)), pkg = readJson(f.text);
    const install = installEntryFiles(dir, hookScripts(pkg), pkg);
    // A private package is the user's own app; its setup scripts are theirs to know.
    for (const abs of install) { atInstall.add(relTo(root, abs)); checkInstallEntry(abs, relTo(root, abs), out, false, "install", { popular: isKnownNpm(pkg?.name), ownApp: !!pkg?.private }); }
    for (const abs of libraryEntryFiles(dir, pkg)) if (!install.includes(abs)) checkInstallEntry(abs, relTo(root, abs), out, false, "library");
  }
  return atInstall;
}

// Install-script defences a project may already have: lower the noise and say what is missing.
export function installHardening(root, files) {
  const read = rel => files.find(f => f.rel === rel)?.text ?? "";
  const pkg = readJson(read("package.json")) || {};
  return {
    ignoreScripts: /^\s*ignore-scripts\s*=\s*true/m.test(read(".npmrc")) || /enableScripts:\s*false/.test(read(".yarnrc.yml")),
    allowList: !!(pkg.lavamoat?.allowScripts || pkg.pnpm?.onlyBuiltDependencies || pkg.trustedDependencies || /onlyBuiltDependencies|allowBuilds/.test(read("pnpm-workspace.yaml"))),
    releaseAge: /minimumReleaseAge|minimum-release-age|npmMinimalAgeGate|min-release-age/.test(read("pnpm-workspace.yaml") + read(".npmrc") + read(".yarnrc.yml") + read("bunfig.toml")),
  };
}

export function hardeningAdvice(root, files, out) {
  const lock = files.find(f => /^(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?)$/.test(f.rel));
  if (!lock) return;
  const h = installHardening(root, files);
  if (h.ignoreScripts || h.allowList) for (const f of out) if (f.rule === "lock-install-scripts") f.why += " The project already limits install scripts (ignore-scripts or an allow-list), so check that these are the allowed ones.";
  const missing = [!h.ignoreScripts && !h.allowList && "install scripts run for every dependency", !h.releaseAge && "brand-new releases install immediately"].filter(Boolean);
  if (!missing.length) return;
  out.push(finding(rule({ id: "supply-hardening", severity: "low", confidence: "high", title: "Dependency installs are not hardened",
    why: `In this project ${missing.join(", and ")}. Most npm malware lives in install scripts and is caught within a day or two of publishing.`,
    fix: "pnpm: `onlyBuiltDependencies` (allow-list) and `minimumReleaseAge: 1440` in pnpm-workspace.yaml; npm: `ignore-scripts=true` in .npmrc plus @lavamoat/allow-scripts; yarn: `enableScripts: false` and `npmMinimalAgeGate`; bun: `trustedDependencies`." }), lock.rel, 1, missing.join("; ")));
}
