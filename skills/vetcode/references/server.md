# Servers, deployment and cloud

## Exposure

- Only the web ports face the internet. Databases, Redis, Elasticsearch, admin panels, Docker API (2375/2376), Kubernetes dashboards and debug ports bind to `127.0.0.1` or a private network. Remember Docker's published ports bypass `ufw`.
- SSH: keys only, no root login, not open to `0.0.0.0/0` (or behind a VPN/bastion); fail2ban or equivalent.
- Staging and preview deployments are protected (password, IP allow-list, or no real data) and not indexed.
- No `.git`, `.env`, backups (`*.sql`, `*.zip`, `*.bak`) or source maps with secrets served from the web root.

## Containers

- Non-root `USER`; minimal base image pinned by version (and digest for production); no secrets in `ENV`/`ARG`/layers (use runtime env or BuildKit secrets); `.dockerignore` excludes `.git`, `.env`, `node_modules`.
- Compose/Kubernetes: no `privileged`, no Docker socket mounts, no `hostNetwork`/`hostPID`; resource limits; read-only root filesystem where possible; secrets from a secret store.

## Web server and TLS

- TLS 1.2+ only, HSTS, HTTP → HTTPS redirect. Certificates renewed automatically.
- nginx: `server_tokens off`, no `autoindex`, `alias` and `location` both end in `/`, request size limits, proxy headers (`X-Forwarded-For`) trusted only from your proxy.
- Security headers set once (app or proxy) and consistent across routes, including error pages and static files.

## Platforms

- **Supabase:** RLS enabled on every table in exposed schemas with real policies; `service_role` key only on the server/edge functions, never with a `NEXT_PUBLIC_`/`VITE_`/`EXPO_PUBLIC_` prefix or in a mobile app; storage bucket policies; `security definer` functions set `search_path` and check the caller; database webhooks and cron functions authenticated.
- **Firebase:** Firestore/RTDB/Storage rules require auth and ownership; App Check for abuse; web API keys restricted by referrer and API (they are public by design).
- **Cloudflare Workers/Pages:** secrets via `wrangler secret put`, not `vars`; routes and preview URLs intended; D1/KV bindings not exposed through debug endpoints; Turnstile checked server-side.
- **Vercel/Netlify:** env vars scoped per environment; preview deployments protected; serverless functions check auth; no secrets in `NEXT_PUBLIC_*`.
- **AWS/GCP/Azure:** buckets private with public access block; IAM least privilege (no `*:*`, no long-lived admin keys on servers; use roles); security groups narrow; databases not publicly accessible; logging (CloudTrail) on.

## Operations

- Secrets in a manager or platform env, rotated when people leave; separate keys per environment.
- Dependencies updated (Dependabot/Renovate) and lockfiles committed; CI installs with `npm ci`/`--frozen-lockfile`, ideally with install scripts disabled for untrusted packages.
- CI: least-privilege `permissions`, actions pinned by SHA, no secrets for workflows triggered by forks, protected main branch, required reviews for workflow changes.
- Backups exist, are encrypted, and restoring has been tried. Logs keep security events (logins, permission changes) without secrets or personal data.
