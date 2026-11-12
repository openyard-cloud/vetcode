// How a release came to exist, from npm registry metadata (no token needed, --online only):
// provenance or trusted publishing that disappears, a publisher never seen before, an install
// script that appears in this version, a brand-new or long-dormant release, a sudden jump in
// size. Compromised maintainers and stolen tokens (chalk/debug, Shai-Hulud) look like this
// before any code is read.
import { finding } from "./engine.mjs";

const HOOKS = ["preinstall", "install", "postinstall"];
const DAY = 86400000;
const rule = r => ({ category: "supply-chain", confidence: "medium", ...r });
const pre = v => /-/.test(v);

/** Pure analysis of one version against the versions published before it. */
export function analyzeHistory(doc, version, { now = Date.now(), file = "package.json" } = {}) {
  const out = [];
  const v = doc?.versions?.[version], t = doc?.time || {};
  if (!v || !t[version]) return out;
  const at = Date.parse(t[version]), id = `${doc.name}@${version}`;
  const earlier = Object.keys(doc.versions).filter(x => x !== version && t[x] && Date.parse(t[x]) < at && (pre(version) || !pre(x))).sort((a, b) => Date.parse(t[a]) - Date.parse(t[b]));
  const prev = earlier.at(-1) && doc.versions[earlier.at(-1)], recent = earlier.slice(-5).map(x => doc.versions[x]);
  const add = (r, evidence) => out.push(finding(rule(r), file, 1, `${id}: ${evidence}`));

  if (recent.some(x => x.dist?.attestations?.provenance) && !v.dist?.attestations?.provenance)
    add({ id: "npm-provenance-dropped", severity: "high", title: `${doc.name}: this release has no provenance, earlier ones did`,
      why: "Releases built by CI carry a signed provenance statement. One published without it usually came from a laptop or a stolen token.",
      fix: "Pin the previous version until the maintainers confirm this release." }, `previous ${earlier.at(-1)} had provenance`);
  if (recent.some(x => x._npmUser?.trustedPublisher) && !v._npmUser?.trustedPublisher)
    add({ id: "npm-trusted-publisher-dropped", severity: "high", title: `${doc.name}: published outside its usual trusted-publishing pipeline`,
      why: "Earlier releases came from the project's CI via trusted publishing; this one did not.", fix: "Pin the previous version until this is explained." }, `published by ${v._npmUser?.name || "unknown"}`);
  const seen = new Set(earlier.map(x => doc.versions[x]._npmUser?.name).filter(Boolean));
  if (earlier.length >= 3 && v._npmUser?.name && !seen.has(v._npmUser.name))
    add({ id: "npm-new-publisher", severity: "medium", title: `${doc.name}: published by an account that never published it before`,
      why: "New publishers are normal when a team grows, and also exactly what a hijacked or handed-over package looks like.", fix: "Check the maintainer change on the project's repository before upgrading." }, `${v._npmUser.name} (before: ${[...seen].slice(0, 3).join(", ")})`);
  const hooks = HOOKS.filter(h => v.scripts?.[h]);
  if (prev && hooks.length && !HOOKS.some(h => prev.scripts?.[h]))
    add({ id: "npm-install-script-added", severity: "high", title: `${doc.name}: this release adds an install script`,
      why: "A script that runs on install appearing in a routine release is the most common sign of a compromised package.", fix: "Read the script and the files it starts; pin the previous version meanwhile." }, `${hooks.map(h => `${h}: ${v.scripts[h]}`).join("; ").slice(0, 120)}`);
  if (prev && v.dist?.unpackedSize && prev.dist?.unpackedSize && v.dist.unpackedSize > 3 * prev.dist.unpackedSize && v.dist.unpackedSize - prev.dist.unpackedSize > 200_000)
    add({ id: "npm-size-jump", severity: "low", title: `${doc.name}: this release is much bigger than the last`,
      why: "Payloads (bundled binaries, obfuscated blobs) make packages jump in size.", fix: "Look at what files were added." }, `${prev.dist.unpackedSize} → ${v.dist.unpackedSize} bytes`);
  if (now - at < 3 * DAY)
    add({ id: "npm-fresh-release", severity: "medium", title: `${doc.name}: released ${Math.max(1, Math.round((now - at) / 3600000))} hours ago`,
      why: "Most malicious releases are caught and removed within a day or two; installing a release this new skips that safety window.", fix: "Wait a few days, or set a minimum release age (pnpm minimumReleaseAge)." }, t[version]);
  if (prev && at - Date.parse(t[earlier.at(-1)]) > 365 * DAY)
    add({ id: "npm-dormant-revival", severity: "low", title: `${doc.name}: first release after more than a year of silence`,
      why: "Abandoned packages are bought or taken over and then republished with a payload.", fix: "Check who published it and what changed." }, `previous release ${t[earlier.at(-1)].slice(0, 10)}`);
  return out;
}

async function registry(name) {
  const r = await fetch(`https://registry.npmjs.org/${name.replace("/", "%2F")}`, { headers: { "user-agent": "vetcode" }, signal: AbortSignal.timeout(30000) });
  return r.ok ? r.json() : null;
}

/** The package itself (when vetting one) and the project's direct dependencies at their locked versions. */
export async function npmHistory(files, out, log = () => {}, limit = 80) {
  const targets = new Map();
  const pkgFile = files.find(f => f.rel === "package.json"), lockFile = files.find(f => f.rel === "package-lock.json");
  const pkg = pkgFile && JSON.parse(pkgFile.text || "{}"), lock = lockFile && JSON.parse(lockFile.text || "{}");
  if (pkg?.name && pkg.version && !pkg.private) targets.set(pkg.name, { version: pkg.version, file: "package.json" });
  for (const name of Object.keys({ ...pkg?.dependencies, ...pkg?.devDependencies, ...pkg?.optionalDependencies })) {
    const version = lock?.packages?.[`node_modules/${name}`]?.version || lock?.dependencies?.[name]?.version;
    if (version && targets.size < limit) targets.set(name, { version, file: "package-lock.json" });
  }
  const queue = [...targets];
  let checked = 0;
  await Promise.all(Array.from({ length: 6 }, async () => {
    for (let item; (item = queue.shift()); ) {
      const [name, { version, file }] = item;
      try { const doc = await registry(name); if (doc) { out.push(...analyzeHistory(doc, version, { file })); checked++; } } catch {}
    }
  }));
  log(`npm history: ${checked} packages checked`);
  return checked;
}
