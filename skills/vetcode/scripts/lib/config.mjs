// Server and deployment configuration: containers, compose, nginx/Apache, Kubernetes,
// Terraform, Cloudflare Workers, Django settings, Supabase row level security, and CSP.
import path from "node:path";
import { finding, lineOf } from "./engine.mjs";

const rule = r => ({ category: "config", confidence: "medium", ...r });
const SECRETISH = /(?:SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIALS?|AUTH)/i;
const line = (text, i) => text.split("\n")[lineOf(text, i) - 1] ?? "";

const DOCKER = /(^|\/)(Dockerfile|Containerfile)(\.[\w.-]+)?$|\.dockerfile$/i;
const COMPOSE = /(^|\/)(docker-)?compose(\.[\w-]+)?\.ya?ml$/i;
const NGINX = /(^|\/)(nginx[\w.-]*\.conf|[\w.-]+\.nginx|sites-(available|enabled)\/[^/]+)$|nginx\/.*\.conf$/i;
const K8S = /\.ya?ml$/i;
const NOT_K8S = /(^|\/)(docker-)?compose(\.[\w-]+)?\.ya?ml$|\.github\/|\.gitlab-ci|pnpm-lock|\.pre-commit/i;
const TF = /\.tf$/i;

export const CONFIG_RULES = [
  rule({ id: "docker-download-exec", severity: "medium", title: "Image build pipes a download into a shell", files: DOCKER,
    re: /\b(?:curl|wget)\b[^|\n]*\|\s*(?:ba|z)?sh\b/,
    unless: /https:\/\/(?:(?:deb|rpm)\.nodesource\.com|get\.docker\.com|sh\.rustup\.rs|install\.python-poetry\.org|bun\.sh\/install|get\.pnpm\.io|astral\.sh\/|deno\.land\/install|get\.helm\.sh)/i,
    why: "Whatever that URL serves at build time ends up in your image.", fix: "Download a pinned version, check its checksum, then run it." }),
  rule({ id: "docker-add-url", severity: "low", title: "ADD from a URL", files: DOCKER,
    re: /^\s*ADD\s+https?:\/\//i, why: "The file is not checksum-pinned and can change.", fix: "Use `ADD --checksum=sha256:...` or download and verify in RUN." }),
  rule({ id: "docker-secret-env", severity: "high", title: "Secret baked into the image", files: DOCKER,
    re: /^\s*(?:ENV|ARG)\s+(\w*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)\w*)[\s=]+["']?(?!\$)[^\s"']{6,}/i,
    why: "ENV and ARG values are stored in the image layers; anyone who pulls the image can read them.", fix: "Pass secrets at runtime, or use BuildKit `--mount=type=secret` during the build." }),
  rule({ id: "compose-privileged", severity: "high", confidence: "high", title: "Container runs privileged", files: COMPOSE,
    re: /^\s*privileged\s*:\s*true\b/, why: "A privileged container can take over the host.", fix: "Remove it; add only the capabilities the service needs (`cap_add`)." }),
  rule({ id: "compose-docker-socket", severity: "high", confidence: "high", title: "Docker socket mounted into a container", files: /\.ya?ml$|Dockerfile/i,
    re: /\/var\/run\/docker\.sock/, unless: /^\s*#/, why: "Access to the socket is root on the host.", fix: "Avoid it, or put a filtering proxy (e.g. docker-socket-proxy) in front with read-only access." }),
  rule({ id: "compose-host-network", severity: "medium", title: "Container uses the host network", files: COMPOSE,
    re: /^\s*network_mode\s*:\s*["']?host\b/, why: "The container sees every port on the host and the host sees everything it opens.", fix: "Use a bridge network and publish only the ports needed." }),
  rule({ id: "compose-db-exposed", severity: "medium", title: "Database port published on all interfaces", files: COMPOSE,
    re: /^\s*-\s*["']?(?:0\.0\.0\.0:)?(?:5432|3306|6379|27017|9200|5984|11211|9042|8086|1433|5672|15672|2379)(?::\d+)?["']?\s*$/,
    why: "On a server with a public IP, the database is reachable from the internet (and Docker bypasses ufw).", fix: "Publish as `127.0.0.1:5432:5432`, or do not publish and use the internal network." }),
  rule({ id: "compose-literal-password", severity: "medium", title: "Password written into compose file", files: COMPOSE, perFile: true,
    re: /^\s*-?\s*["']?\w*(?:PASSWORD|SECRET|TOKEN|API_KEY)\w*["']?\s*[:=]\s*["']?(?!\$\{?)[^\s"'$]{4,}/i,
    unless: /[:=]\s*["']?(?:replace|change[-_]?me|example|your[-_]|<|(?:true|false|yes|no|on|off|[01])["']?\s*$)|RANDOM|ALLOW_EMPTY/i,
    why: "The file is committed and shared; the value leaks with it.", fix: "Use `${VAR}` from an untracked .env, or Docker secrets." }),
  rule({ id: "nginx-autoindex", severity: "medium", confidence: "high", title: "Directory listing on", files: NGINX, re: /^\s*autoindex\s+on\s*;/,
    why: "Anyone can browse every file in the folder, including backups and configs.", fix: "Turn it off." }),
  rule({ id: "nginx-old-tls", severity: "medium", confidence: "high", title: "Old TLS versions allowed", files: NGINX, re: /^\s*ssl_protocols\b[^;]*\b(?:SSLv[23]|TLSv1(?:\.1)?)\b(?!\.[23])/,
    why: "TLS 1.0/1.1 have known weaknesses.", fix: "`ssl_protocols TLSv1.2 TLSv1.3;`" }),
  rule({ id: "nginx-server-tokens", severity: "low", confidence: "high", title: "Server version shown", files: NGINX, re: /^\s*server_tokens\s+on\s*;/,
    why: "Tells attackers which exploits to try.", fix: "`server_tokens off;`" }),
  rule({ id: "apache-indexes", severity: "medium", confidence: "high", title: "Directory listing on", files: /(^|\/)(\.htaccess|httpd\.conf|apache2?\.conf|[\w.-]+\.conf)$/i,
    re: /^\s*Options\s+[^#\n]*(?<!-)\+?Indexes\b/, why: "Visitors can list files in folders without an index page.", fix: "`Options -Indexes`" }),
  rule({ id: "k8s-privileged", severity: "high", confidence: "high", title: "Pod runs privileged or with host access", files: K8S, skip: NOT_K8S,
    re: /^\s*(?:privileged|hostNetwork|hostPID|hostIPC|allowPrivilegeEscalation)\s*:\s*true\b/, why: "A compromised container can escape to the node.", fix: "Remove it; set `runAsNonRoot: true` and drop capabilities." }),
  rule({ id: "k8s-root", severity: "medium", title: "Container runs as root", files: K8S, skip: NOT_K8S, re: /^\s*runAsUser\s*:\s*0\s*$/,
    why: "Root inside the container makes escapes and damage easier.", fix: "Run as a non-root user id." }),
  rule({ id: "tf-public-acl", severity: "high", confidence: "high", title: "Storage bucket is public", files: TF,
    re: /\bacl\s*=\s*"public-read(?:-write)?"|block_public_(?:acls|policy)\s*=\s*false|\ballUsers\b|\ballAuthenticatedUsers\b/, why: "Anyone on the internet can list or download the files.", fix: "Keep buckets private; share through signed URLs or a CDN with origin access control." }),
  rule({ id: "tf-public-db", severity: "high", confidence: "high", title: "Database reachable from the internet", files: TF,
    re: /publicly_accessible\s*=\s*true/, why: "The database listens on a public address.", fix: "Keep it in a private subnet and connect through the app or a bastion." }),
  rule({ id: "tf-unencrypted", severity: "low", title: "Encryption at rest turned off", files: TF,
    re: /\b(?:encrypted|storage_encrypted|encryption)\s*=\s*false/, why: "Snapshots and disks are stored in clear.", fix: "Turn encryption on." }),
  rule({ id: "django-allowed-hosts", severity: "medium", title: "Django accepts any Host header", files: /settings[\w/]*\.py$/i,
    re: /^\s*ALLOWED_HOSTS\s*=\s*\[\s*["']\*["']\s*\]/, why: "Enables host-header attacks such as poisoned password-reset links.", fix: "List your real domains." }),
  rule({ id: "csp-unsafe", severity: "low", title: "Content Security Policy allows inline or eval'd scripts", files: /\.(html?|conf|json|toml|ya?ml|js|ts|mjs|py)$|_headers$/i,
    re: /(?:Content-Security-Policy|contentSecurityPolicy|script-src)[^\n]*'unsafe-(?:inline|eval)'/i, why: "These keywords cancel most of the XSS protection a CSP gives.", fix: "Use nonces or hashes for inline scripts and remove unsafe-eval." }),
];

// Whole-file checks.
export const CONFIG_FILE_RULES = [
  { ...rule({ id: "docker-latest", severity: "low", title: "Base image without a fixed version",
      why: "`latest` changes under you: builds stop being reproducible and can pull in a compromised image.",
      fix: "Pin a version tag, ideally with its digest (`image:1.2@sha256:...`)." }), files: DOCKER,
    test(text) {
      const stages = new Set([...text.matchAll(/^\s*FROM\s+\S+(?:\s+\S+)*?\s+AS\s+(\S+)/gim)].map(m => m[1].toLowerCase()));
      return [...text.matchAll(/^\s*FROM\s+(?:--\S+\s+)*(\S+)/gim)].filter(m => {
        const img = m[1].toLowerCase();
        if (img === "scratch" || stages.has(img) || img.includes("$") || img.includes("@sha256:")) return false;
        const tag = img.split("/").pop().split(":")[1];
        return !tag || tag === "latest";
      }).map(m => ({ line: lineOf(text, m.index), evidence: m[0].trim() }));
    } },
  { ...rule({ id: "docker-root-user", severity: "low", title: "Container runs as root",
      why: "If the app is compromised, the attacker is root inside the container, which makes escaping and tampering easier.",
      fix: "Add a user and switch to it at the end: `RUN adduser -D app` / `USER app`." }), files: DOCKER,
    test(text) {
      const users = [...text.matchAll(/^\s*USER\s+(\S+)/gim)];
      const last = users.at(-1)?.[1];
      if (!/^\s*FROM\b/im.test(text) || /^\s*FROM\s+[^\n]*(?:distroless|chainguard)[^\n]*nonroot/im.test(text)) return [];
      if (!last) return [{ line: 1, evidence: "no USER instruction" }];
      return /^(root|0)(:|$)/.test(last) ? [{ line: lineOf(text, users.at(-1).index), evidence: users.at(-1)[0].trim() }] : [];
    } },
  { ...rule({ id: "nginx-alias-traversal", severity: "high", confidence: "high", title: "nginx alias path traversal (off-by-slash)",
      why: "`location /files` with `alias /data/files/;` lets `/files../secret` read files next to the folder.",
      fix: "Make both end with a slash (`location /files/ { alias /data/files/; }`) or use `root`." }), files: NGINX,
    test(text) {
      const out = [];
      for (const m of text.matchAll(/location\s+([^\s{~=^]+)\s*\{([^}]*)\}/g)) {
        const alias = m[2].match(/\balias\s+([^;\s]+)\s*;/);
        if (alias && !m[1].endsWith("/") && alias[1].endsWith("/")) out.push({ line: lineOf(text, m.index), evidence: `location ${m[1]} { alias ${alias[1]}; }` });
      }
      return out;
    } },
  { ...rule({ id: "tf-open-admin-port", severity: "high", confidence: "high", title: "SSH/RDP/database open to the whole internet",
      why: "Every scanner on the internet will try to log in.", fix: "Allow only your IPs or a VPN; use SSM/bastion for admin access." }), files: TF,
    test(text) {
      const out = [];
      for (const m of text.matchAll(/(?:ingress|security_rule|resource\s+"aws_security_group_rule"|resource\s+"aws_vpc_security_group_ingress_rule")[^{]*\{([\s\S]*?)\n\s*\}/g)) {
        const b = m[1];
        if (!/0\.0\.0\.0\/0|::\/0|"\*"/.test(b)) continue;
        const ports = [...b.matchAll(/(?:from_port|to_port|destination_port_range)\s*=\s*"?(\d+)/g)].map(p => +p[1]);
        if (ports.some(p => [22, 3389, 5432, 3306, 6379, 27017, 9200, 2375, 2376, 5985, 5986].includes(p)) || (ports.length >= 2 && ports[0] === 0 && ports[1] >= 65535)) out.push({ line: lineOf(text, m.index), evidence: `ports ${ports.join("-")} open to 0.0.0.0/0` });
      }
      return out;
    } },
  { ...rule({ id: "wrangler-secret-var", severity: "high", confidence: "high", title: "Secret stored as a plain Cloudflare var",
      why: "`vars` are plain text in the config and visible in the dashboard and in the repository.",
      fix: "Use `wrangler secret put NAME` and remove it from vars." }), files: /(^|\/)wrangler\.(toml|jsonc?)$/i,
    test(text) {
      const out = [];
      const block = text.match(/"vars"\s*:\s*\{([\s\S]*?)\}/) || text.match(/^\[vars\]([\s\S]*?)(?=^\[|$(?![\s\S]))/m);
      if (!block) return out;
      for (const m of block[1].matchAll(/["']?(\w+)["']?\s*[:=]\s*["']([^"']{8,})["']/g)) {
        if (SECRETISH.test(m[1]) && !/SITE_KEY|PUBLIC|CLIENT_ID|_URL$/i.test(m[1])) out.push({ line: lineOf(text, text.indexOf(m[0])), evidence: `${m[1]} = "${m[2].slice(0, 4)}…"` });
      }
      return out;
    } },
  { ...rule({ id: "supabase-rls-disabled", severity: "high", confidence: "high", title: "Row Level Security turned off",
      why: "With RLS off, anyone holding the public anon key can read and write every row of the table.",
      fix: "Enable RLS and add policies that check `auth.uid()`." }), files: /\.sql$/i,
    test(text) { return [...text.matchAll(/alter\s+table\s+[^;]*\bdisable\s+row\s+level\s+security/gi)].map(m => ({ line: lineOf(text, m.index), evidence: line(text, m.index).trim() })); } },
  { ...rule({ id: "supabase-policy-true", severity: "high", title: "RLS policy that lets everyone through",
      why: "`using (true)` on update/delete/all means any visitor can change or delete any row.",
      fix: "Compare against the user, e.g. `using (auth.uid() = user_id)`." }), files: /\.sql$/i,
    test(text) {
      return [...text.matchAll(/create\s+policy[\s\S]{0,400}?;/gi)]
        .filter(m => /\bfor\s+(?:all|update|delete|insert)\b/i.test(m[0]) && /(?:using|with\s+check)\s*\(\s*true\s*\)/i.test(m[0]) && !/\bto\s+service_role\b/i.test(m[0]))
        .map(m => ({ line: lineOf(text, m.index), evidence: m[0].replace(/\s+/g, " ").slice(0, 150) }));
    } },
];

/** Tables created in Supabase migrations that never get RLS enabled (needs every migration). */
export function supabaseTablesWithoutRls(files, out) {
  const created = new Map(), enabled = new Set();
  for (const f of files) {
    if (!/(^|\/)supabase\/migrations\/[^/]+\.sql$|(^|\/)migrations\/[^/]+\.sql$/i.test(f.rel)) continue;
    for (const m of f.text.matchAll(/create\s+table\s+(?:if\s+not\s+exists\s+)?(?:"?public"?\.)?"?(\w+)"?\s*\(/gi)) {
      if (/\b(?:auth|storage|private|internal|extensions)\./i.test(m[0])) continue;
      if (!created.has(m[1])) created.set(m[1], { file: f.rel, line: lineOf(f.text, m.index) });
    }
    for (const m of f.text.matchAll(/alter\s+table\s+(?:only\s+)?(?:"?public"?\.)?"?(\w+)"?\s+enable\s+row\s+level\s+security/gi)) enabled.add(m[1]);
  }
  const isSupabase = files.some(f => /(^|\/)supabase\//.test(f.rel) || /@supabase\/|supabase_url|SUPABASE_URL/i.test(f.text.slice(0, 20000)));
  if (!isSupabase) return;
  for (const [table, at] of created) {
    if (enabled.has(table)) continue;
    out.push(finding({ id: "supabase-table-no-rls", category: "config", severity: "high", confidence: "medium", title: `Table "${table}" is created without Row Level Security`,
      why: "Supabase exposes public tables through its API; without RLS the anon key reads and writes everything.",
      fix: `\`alter table public.${table} enable row level security;\` plus policies for who may read and write.` }, at.file, at.line, `create table ${table}`));
  }
}

export const isConfigFile = rel => DOCKER.test(rel) || COMPOSE.test(rel) || NGINX.test(rel) || TF.test(rel) || /\.(ya?ml|sql|toml|jsonc?|conf|py|html?)$|_headers$|\.htaccess$/i.test(path.basename(rel));
