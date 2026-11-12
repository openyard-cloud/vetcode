// Leaked credentials: provider tokens with known shapes, private keys, connection strings
// with passwords, and secret-looking assignments. Values are always redacted in the report.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { DOC, TEST, LOCALE, DEVSTACK, finding, suppressedHere, presentIn } from "./engine.mjs";

const ROTATE = "Revoke and rotate it at the provider first (assume it is already copied), then move it to an environment variable or secret store and remove it from the code and git history.";

export const SECRET_RULES = [
  { id: "secret-private-key", severity: "critical", title: "Private key in the repository", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/,
    // A header named in docs, or matched against (`starts_with("-----BEGIN …-----")`), holds no key.
    // Nor does a pattern that looks for one (a scrubber's regular expression), or a header followed by dots, stars or a template field.
    unless: /^\s*(?:\/\/[/!]?|\*|#|--)\s|-----BEGIN[^"'`\n]*-----["'`]\s*[,;)\]]|\bplaceholder\s*=|\/[^\/\n]*-----BEGIN[^\n]*\/[gimsuy]*\s*[,;)}\]]|\b(?:regex|pattern|RegExp|re\.compile|Regex::new)\b[^\n]*-----BEGIN|-----BEGIN[^\n]{0,60}(?:\.\.\.|\*{3,}|\{\w+\}|\\n\.\.\.)/i },
  { id: "secret-aws-key", severity: "critical", title: "AWS access key", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/, unless: /EXAMPLE/ },
  { id: "secret-github-token", severity: "critical", title: "GitHub token", re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/ },
  { id: "secret-gitlab-token", severity: "critical", title: "GitLab token", re: /\bglpat-[A-Za-z0-9_-]{20,}\b/ },
  { id: "secret-npm-token", severity: "critical", title: "npm token", re: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { id: "secret-pypi-token", severity: "critical", title: "PyPI token", re: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}/ },
  { id: "secret-openai-key", severity: "critical", title: "OpenAI API key", re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}|\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}/ },
  { id: "secret-anthropic-key", severity: "critical", title: "Anthropic API key", re: /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{60,}/ },
  { id: "secret-stripe-live", severity: "critical", title: "Stripe live secret key", re: /\b[rs]k_live_[A-Za-z0-9]{20,}\b/ },
  { id: "secret-stripe-test", severity: "low", title: "Stripe test key", re: /\b[rs]k_test_[A-Za-z0-9]{20,}\b/, confidence: "high" },
  { id: "secret-supabase-secret", severity: "critical", title: "Supabase secret key", re: /\bsb_secret_[A-Za-z0-9_-]{20,}/ },
  { id: "secret-google-oauth", severity: "high", title: "Google OAuth client secret", re: /\bGOCSPX-[A-Za-z0-9_-]{28}\b/ },
  { id: "secret-google-api-key", severity: "medium", title: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/, fix: "Browser keys (Firebase, Maps) are public by design: restrict them to your domains and APIs in Google Cloud. Server keys must be rotated and moved out of the code." },
  { id: "secret-slack-token", severity: "high", title: "Slack token", re: /\bxox[abprs]-[A-Za-z0-9-]{10,}/ },
  { id: "secret-sendgrid", severity: "high", title: "SendGrid API key", re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/ },
  { id: "secret-discord-bot", severity: "high", title: "Discord bot token", re: /\b[MNO][A-Za-z\d_-]{23,25}\.[\w-]{6}\.[\w-]{27,38}\b/ },
  { id: "secret-telegram-bot", severity: "high", title: "Telegram bot token", re: /\b\d{8,10}:AA[0-9A-Za-z_-]{33}\b/ },
  { id: "secret-twilio", severity: "medium", title: "Twilio API key", re: /\bSK[0-9a-f]{32}\b/ },
  { id: "secret-ai-key", severity: "critical", title: "AI provider API key", re: /\b(?:hf_[A-Za-z0-9]{34,}|gsk_[A-Za-z0-9]{48,}|xai-[A-Za-z0-9]{70,}|r8_[A-Za-z0-9]{37}|pplx-[A-Za-z0-9]{48}|AIzaSy[A-Za-z0-9_-]{33}(?=[^\n]*(?:gemini|generativelanguage)))\b/ },
  { id: "secret-cloud-token", severity: "critical", title: "Cloud or infrastructure token", re: /\b(?:dop_v1_[a-f0-9]{64}|dp\.(?:pt|st|sa|ct)\.[A-Za-z0-9]{40,}|hvs\.[A-Za-z0-9_-]{90,}|atlasv1\.(?<=\b[A-Za-z0-9]{14}\.atlasv1\.)[A-Za-z0-9_=-]{60,}|pul-[a-f0-9]{40}|AGE-SECRET-KEY-1[0-9A-Z]{58}|sntrys_[A-Za-z0-9+/=_-]{60,}|glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}|glc_[A-Za-z0-9+/]{32,}={0,2}|dapi[a-f0-9]{32}(?:-\d)?)\b/ },
  { id: "secret-saas-token", severity: "high", title: "SaaS API token", re: /\b(?:shp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}|EAAA[A-Za-z0-9_-]{60}|sq0csp-[A-Za-z0-9_-]{43}|lin_api_[A-Za-z0-9]{40}|ntn_[A-Za-z0-9]{40,}|secret_[A-Za-z0-9]{43}(?=[^\n]*notion)|PMAK-[a-f0-9]{24}-[a-f0-9]{34}|re_[A-Za-z0-9]{8}_[A-Za-z0-9]{24}|key-[0-9a-z]{32}(?=[^\n]*mailgun))\b/i },
  { id: "secret-azure-storage", severity: "critical", title: "Azure storage account key", re: /AccountKey=[A-Za-z0-9+/]{86}==/ },
  { id: "secret-npmrc-token", severity: "critical", title: "Registry auth token in .npmrc", re: /_authToken\s*=\s*(?!\$\{)[A-Za-z0-9_\-.]{20,}/ },
  { id: "secret-slack-webhook", severity: "medium", title: "Slack incoming webhook URL", re: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{20,}/, unless: /\bplaceholder\s*=/i },
  { id: "secret-gcp-service-account", severity: "critical", title: "Google service account key", re: /"private_key_id"\s*:\s*"[a-f0-9]{40}"/ },
  // A database on this machine (a CI service container, a local stack) is not reachable by whoever reads the code.
  { id: "secret-db-url", severity: "low", title: "Database URL with a password, for a database on this machine", re: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql):\/\/[^\s:@/'"`]+:([^\s@/'"`]{3,})@(?:localhost|127\.0\.0\.1|\[?::1\]?|0\.0\.0\.0)(?=[:/?'"`\s]|$)[^\s'"`]*/i,
    unless: /:\/\/[^\s:@/]+:(?:\$\{?|<|\[|\{\{|%\(|[^@]*(?:passw(?:or)?d|secret|changeme|example)|pass|pwd|xxx+|\*{3,}|user|test|postgres|root|my[_-]?\w*|your[_-]?\w*|replace[\w-]*|invalid)[^@]*@|:\/\/(?<same>[^\s:@/]+):\k<same>@/i },
  { id: "secret-db-url", severity: "high", title: "Database URL with a password", re: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql):\/\/[^\s:@/'"`]+:([^\s@/'"`]{3,})@(?!(?:localhost|127\.0\.0\.1|\[?::1\]?|0\.0\.0\.0)(?=[:/?'"`\s]|$))[^\s'"`]+/i,
    // Not a placeholder in brackets, and not a password that says it is one (dbpassword, your-secret).
    unless: /:\/\/[^\s:@/]+:(?:\$\{?|<|\[|\{\{|%\(|[^@]*(?:passw(?:or)?d|secret|changeme|example)|passw(or)?d|pass|pwd|secret|changeme|example|xxx+|\*{3,}|user|test|postgres|root|my[_-]?\w*|your[_-]?\w*|replace[\w-]*|invalid)[^@]*@|:\/\/(?<same>[^\s:@/]+):\k<same>@/i },
].map(r => ({ category: "secrets", confidence: "high", why: "Anyone who can read this code (or a copy of it, a build, a log) can use the credential.", fix: ROTATE, ...r }));

// Values that are clearly not real secrets.
const PLACEHOLDER = /^(?:x+|\*+|\.+|-+|0+|1234\d*|changeme|change[_-]?me|example\w*|placeholder|dummy|test\w*|secret|password|your[_-].*|my[_-].*|<.*>|\{\{.*\}\}|\$\{.*\}|%\(.*\)s|todo|tbd|none|null|undefined|redacted|sample\w*|demo\w*|fake\w*)$/i;

function entropy(s) {
  const n = {}; for (const c of s) n[c] = (n[c] || 0) + 1;
  return Object.values(n).reduce((h, k) => h - (k / s.length) * Math.log2(k / s.length), 0);
}

const ASSIGN = /\b([A-Za-z0-9_]*?(?:secret|passw(?:or)?d|pwd|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret|signing[_-]?key|encryption[_-]?key|webhook[_-]?secret)[A-Za-z0-9_]*)["']?\s*[:=]\s*["'`]([^"'`\s]{8,200})["'`]/i;
const GENERIC = { id: "secret-assignment", category: "secrets", severity: "medium", title: "Hard-coded secret value", confidence: "medium",
  why: "A secret written into the code ships with every copy of the code.", fix: ROTATE };

// GitHub tokens end in a checksum (CRC32 of the 30 random characters, base 62, six digits).
// A string of the right shape that fails it was never issued: an example or a test value.
const CRC = new Int32Array(256).map((_, n) => { for (let k = 0; k < 8; k++) n = n & 1 ? (n >>> 1) ^ 0xEDB88320 : n >>> 1; return n; });
const B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
export function githubChecksum(random) {
  let c = -1; for (const ch of Buffer.from(random)) c = CRC[(c ^ ch) & 255] ^ (c >>> 8);
  let n = (c ^ -1) >>> 0, out = "";
  while (n > 0) { out = B62[n % 62] + out; n = Math.floor(n / 62); }
  return out.padStart(6, "0");
}
const neverIssued = (rule, value) => {
  const m = rule.id === "secret-github-token" && /^gh[pousr]_([A-Za-z0-9]{30})([A-Za-z0-9]{6})$/.exec(value);
  return !!m && githubChecksum(m[1]) !== m[2];
};

// Where a "secret-looking assignment" is not a secret. These files and names hold words about
// secrets (labels, column names, test values), which is most of what a real application has.
// The key says what a field is called or what state it is in, not what its value is.
const NAME_KEY = /(?:column|field|name|label|header|param(?:eter)?|path|prop|attr(?:ibute)?|selector|placeholder|title|type|status|state|hint|help|text|message|description|prefix|suffix|env|var(?:iable)?|regex|pattern|format|url|uri|endpoint|file(?:name)?|dir|length|size|count|ttl|expir\w*|algo(?:rithm)?|scheme|mode|kind|event|action|error|required|enabled|visible|strength|policy|rules?|min|max)$/i;
// A name, not a value: words joined by . _ - : or / (api_key_encrypted, backend-api-key).
// Also a session key or an error code (_totp_secret, profile-password-01).
const NAME_VALUE = /^[_-]?[A-Za-z]+(?:[._:\/-](?:[A-Za-z]+|\d{1,3}))+(?:,\s*[A-Za-z]+(?:[._:\/-](?:[A-Za-z]+|\d{1,3}))+)*$/;
// The pool characters are drawn from, a reference to a variable or a framework parameter, and
// an identifier-shaped value under a key that only says "password" (passwords are not UUIDs; keys and tokens can be).
// Also a command substitution, and a route written as METHOD:/path.
const NOT_A_VALUE = v => /abcdefgh|ABCDEFGH|01234567/.test(v) || /^\$[A-Za-z_]\w*$/.test(v) || /^%[\w.]+%/.test(v) || /^\$\(/.test(v) || /^(?:GET|POST|PUT|PATCH|DELETE|HEAD):\//.test(v);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const redact = v => v.length <= 8 ? "•".repeat(v.length) : `${v.slice(0, 4)}…${v.slice(-2)} (${v.length} chars)`;

// JWTs are only secrets when they grant something; a Supabase service_role key is a master key.
function jwtClaims(token) {
  try { return JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString()) || {}; } catch { return {}; }
}

const JWT = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;

export function scanSecrets(file, text, out) {
  const doc = DOC.test(file.rel), test = TEST.test(file.rel);
  // Most files hold no secret at all: find which rules can match before reading line by line.
  const rules = SECRET_RULES.filter(r => presentIn(text, r));
  JWT.lastIndex = 0;
  // Tests and translations are full of made-up and translated values next to these words.
  const jwt = JWT.test(text), assign = !doc && !test && !LOCALE.test(file.rel) && ASSIGN.test(text);
  JWT.lastIndex = 0; // matchAll copies lastIndex

  if (!rules.length && !jwt && !assign) return;
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > 5000) continue;
    let hit = false;
    for (const r of rules) {
      const m = r.re.exec(line);
      if (!m || (r.unless && r.unless.test(line)) || neverIssued(r, m[0]) || suppressedHere(lines, i, file.rel, r.id)) continue;
      hit = true;
      out.push(finding(r, file.rel, i + 1, line.replace(m[1] ?? m[0], redact(m[1] ?? m[0])), doc ? { confidence: "low" } : (test || /\b\w*(?:FAKE|DUMMY|EXAMPLE|SAMPLE|TEST)\w*\s*(?::[^=\n]*)?=/i.test(line)) && r.id === "secret-private-key" ? { severity: "low", title: "Private key that is a fixture by its place or its name (unless it is used anywhere real)" } : {}));
    }
    for (const m of jwt ? line.matchAll(JWT) : []) {
      hit = true;
      const claims = jwtClaims(m[0]), role = claims.role;
      // The keys `supabase start` prints are the same for everyone and only work locally.
      const localDemo = claims.iss === "supabase-demo";
      const r = localDemo
        ? { id: "secret-supabase-local", category: "secrets", severity: "info", title: `Supabase local development ${role || ""} key (public default)`, confidence: "high", why: "This is the well-known key of the local Supabase stack; it does not work against a hosted project.", fix: "Nothing to rotate. Make sure production keys come from the environment." }
        : role === "service_role"
        ? { id: "secret-supabase-service-role", category: "secrets", severity: "critical", title: `Supabase service_role key${claims.ref ? ` for project ${claims.ref}` : ""}`, confidence: "high", why: "The service_role key bypasses every Row Level Security policy: full read and write on the database.", fix: ROTATE }
        : { id: "secret-jwt", category: "secrets", severity: role === "anon" || test ? "info" : "medium", title: role === "anon" ? "Supabase anon key (public by design)" : "JSON Web Token in the code", confidence: "medium", why: role === "anon" ? "The anon key is meant for browsers; it is only safe if Row Level Security is on for every table." : "A signed token may still be valid and grant access.", fix: role === "anon" ? "Nothing to rotate; make sure RLS is enabled with real policies." : ROTATE };
      out.push(finding(r, file.rel, i + 1, line.replace(m[0], redact(m[0]))));
    }
    if (hit || !assign) continue;
    const m = ASSIGN.exec(line);
    if (!m || suppressedHere(lines, i, file.rel, GENERIC.id)) continue;
    const value = m[2];
    if (PLACEHOLDER.test(value) || /process\.env|os\.environ|getenv|import\.meta\.env|\$\{|\{\{|ENV\[|config\(|secrets\.|\benv\(/.test(line)) continue;
    if (entropy(value) < 3.2 || /^[a-z]+$/i.test(value) || /^(https?:|\/|\.\/)/.test(value)) continue;
    if (NAME_KEY.test(m[1]) || NAME_VALUE.test(value) || /[^\x00-\x7F]/.test(value)) continue;
    if (NOT_A_VALUE(value) || (UUID.test(value) && !/key|token|secret|credential|auth/i.test(m[1]))) continue;
    // A key that starts with digits names a record (a migration, a row of checksums), not a secret.
    if (/^\d{6,}/.test(m[1])) continue;
    // A commented-out example, a value built at run time, or the search-only key a docs site publishes on purpose.
    if (/^\s*(?:#|\/\/|\*|--|;)/.test(line) || /#\{|\$\{|%[sd]|\{\w*\}/.test(value) || (/^api_?key$/i.test(m[1]) && /algolia|docsearch|docusaurus|vitepress/i.test(file.rel + text.slice(0, 4000)))) continue;
    out.push(finding(GENERIC, file.rel, i + 1, line.replace(value, redact(value)), DEVSTACK.test(file.rel) ? { severity: "low", title: "Secret-looking value in a development or CI stack" } : {}));
  }
}

const SECRET_FILE = /(^|\/)(\.env(\.[\w-]+)?|id_(rsa|dsa|ecdsa|ed25519)|[^/]+\.(pem|key|p12|pfx|keystore|jks)|credentials(\.json)?|service[-_]?account[^/]*\.json|\.npmrc|\.pypirc|\.netrc|\.git-credentials)$/i;
const SAMPLE = /\.(example|sample|template|dist|defaults?)$|\.example\.|\.sample\./i;

/** Secret files committed to git (or sitting next to a .gitignore that does not cover them). */
export function scanSecretFiles(root, out) {
  const git = spawnSync("git", ["ls-files", "-z"], { cwd: root, encoding: "utf8", maxBuffer: 64 << 20 });
  if (git.status === 0) {
    for (const rel of git.stdout.split("\0").filter(Boolean)) {
      if (!SECRET_FILE.test(rel) || SAMPLE.test(rel)) continue;
      if (/\.npmrc$/.test(rel) && !/_authToken|_auth\s*=|_password/.test(safeRead(path.join(root, rel)))) continue;
      // An env file kept in git on purpose (CI, tests, public build settings) holds no secret when
      // none of its values looks like one; a key or certificate among the tests is a fixture.
      const body = /\.env/i.test(rel) ? safeRead(path.join(root, rel)) : null, inside = [];
      if (body !== null) scanSecrets({ rel: "env" }, body, inside);
      const plain = (body !== null && !inside.some(f => f.severity !== "info")) || TEST.test(rel);
      out.push(finding({ id: "secret-file-committed", category: "secrets", severity: plain ? "low" : "high", title: plain ? "Env or key file tracked by git (no secret-looking value found in it)" : "Secret file tracked by git", confidence: "high",
        why: "Everything in this file is in the repository and its history, for anyone with access to it.",
        fix: "Rotate what is inside, `git rm --cached` the file, add it to .gitignore, and purge it from history (git filter-repo) if the repository was ever shared." }, rel, 1, rel));
    }
  }
  const envs = fs.existsSync(root) ? fs.readdirSync(root).filter(f => /^\.env(\.[\w-]+)?$/.test(f) && !SAMPLE.test(f)) : [];
  if (envs.length) {
    const gi = safeRead(path.join(root, ".gitignore"));
    if (!/^\s*\/?\.env(\*|\.\*)?\s*$/m.test(gi) && !/^\s*\*\.env|^\s*\.env\*/m.test(gi)) {
      out.push(finding({ id: "secret-env-not-ignored", category: "secrets", severity: "medium", title: ".env is not in .gitignore", confidence: "high",
        why: "The next `git add .` will commit your secrets.", fix: "Add `.env*` (and `!.env.example`) to .gitignore." }, ".gitignore", 1, envs.join(", ")));
    }
  }
}

const safeRead = f => { try { return fs.readFileSync(f, "utf8"); } catch { return ""; } };

/** Secrets that were committed at some point, even if deleted since. */
export function scanHistory(root, out, maxCommits = 1000) {
  const r = spawnSync("git", ["log", "--all", "-p", "--no-color", "-U0", `--max-count=${maxCommits}`, "--format=commit %H"], { cwd: root, encoding: "utf8", maxBuffer: 512 << 20 });
  if (r.status !== 0) return;
  let commit = "", file = "";
  const seen = new Set();
  for (const line of r.stdout.split("\n")) {
    if (line.startsWith("commit ")) { commit = line.slice(7, 19); continue; }
    if (line.startsWith("+++ b/")) { file = line.slice(6); continue; }
    if (!line.startsWith("+") || line.startsWith("+++")) continue;
    const found = [];
    scanSecrets({ rel: file }, line.slice(1), found);
    for (const f of found) {
      if (f.rule === "secret-assignment" || f.severity === "info") continue;
      const key = f.rule + f.evidence;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ ...f, rule: f.rule, title: `${f.title} (in git history)`, line: 0, file: `${file} @ ${commit}`, fix: ROTATE + " Deleting it in a later commit does not remove it from history." });
    }
  }
}
