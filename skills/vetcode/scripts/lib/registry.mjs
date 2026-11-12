// The registries' public download counters. This file makes requests and reads nothing from the
// machine: no file, no environment variable. The only thing it sends is a package name.

/** How many times a package was installed last week, from the registry's public counters. null when unknown. */
export async function weeklyDownloads(fetchFn, eco, name) {
  try {
    const url = eco === "npm" ? `https://api.npmjs.org/downloads/point/last-week/${String(name).replace("/", "%2F")}` : `https://pypistats.org/api/packages/${String(name).toLowerCase()}/recent`;
    const r = await fetchFn(url, { headers: { "user-agent": "vetcode", accept: "application/json" }, signal: AbortSignal.timeout(8000) });
    if (!r.ok) return null;
    const j = await r.json(), n = eco === "npm" ? j.downloads : j.data?.last_week;
    return Number.isFinite(n) ? n : null;
  } catch { return null; }
}
