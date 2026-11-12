# Web apps and APIs: what to review by hand

Patterns find dangerous calls; these checks find missing protections. Start by listing every entry point: HTTP routes, API handlers, server actions, RPC/tRPC procedures, GraphQL resolvers, webhooks, queue consumers, cron jobs, WebSocket messages.

## Authentication

- Every non-public entry point checks the session/token **on the server**. Middleware matchers actually cover the paths (Next.js `matcher`, Express router order, a route added after the auth middleware).
- Tokens: JWTs verified with a fixed algorithm and key, expiry checked, not just decoded. Refresh tokens rotated and revocable. Logout invalidates server-side sessions.
- Passwords hashed with argon2id/bcrypt/scrypt; login, reset and OTP endpoints rate-limited; reset tokens single-use, random, short-lived; responses do not reveal whether an email exists (if that matters to the product).
- OAuth: `state` checked, redirect URIs exact, tokens not put in URLs or logs, account linking does not trust unverified emails.

## Authorization (the bug scanners miss)

- **IDOR:** for every handler that takes an id (path, query, body), the query also filters by the current user or tenant (`where id = ? and owner_id = ?`), or ownership is checked before acting. Try mentally: change the id to someone else's.
- Role checks on the server for admin actions, not only hidden buttons. Server actions and API routes in Next.js are public endpoints even if no page links to them.
- Multi-tenant apps: every query is scoped by tenant; caches and storage paths include the tenant.
- Mass assignment: users cannot set `role`, `isAdmin`, `ownerId`, `price`, `balance`, `emailVerified` through update endpoints.
- Supabase/Firebase: the client talks to the database directly, so RLS policies / security rules **are** the authorization. Each table: RLS on; `select` limited to own rows; `insert` sets `user_id = auth.uid()` via `with check`; `update`/`delete` require ownership; no `using (true)` except truly public reads. Storage buckets have policies too.

## Input and output

- SQL/NoSQL: parameters everywhere; dynamic identifiers (table/column names, ORDER BY) come from an allow-list.
- XSS: frameworks escape by default; review every raw-HTML escape hatch, Markdown rendering (sanitised?), user content in `href`/`src` (block `javascript:`), JSON embedded in `<script>` (escape `<`), and SVG uploads served inline.
- SSRF: any server-side fetch of a user-given URL (link previews, webhooks, image import, PDF rendering, OpenGraph) blocks private ranges, metadata IPs, redirects to them, and non-http schemes.
- File upload: size limit, content-type and extension checked, stored outside the web root or on object storage with a generated name, served with `Content-Disposition: attachment` or from a separate domain.
- Path handling, archive extraction (zip slip), XML parsers with external entities off, YAML/pickle never on untrusted data.

## State-changing requests

- CSRF: cookie-authenticated POST/PUT/DELETE need SameSite cookies plus a token or Origin check; GET never changes state.
- Webhooks (Stripe, GitHub, payment gateways like VNPay/MoMo/ZaloPay): signature verified on the raw body with a constant-time compare; timestamp/replay checked; amount and order id re-checked against your database, not trusted from the callback.
- Payments and credits: prices computed on the server; idempotency keys; race conditions on balance/stock (use transactions or atomic updates).
- Rate limits on login, sign-up, OTP/SMS, email sending, expensive AI calls, and anything that costs money.

## Responses and errors

- No stack traces or SQL errors to clients in production; generic auth errors.
- Security headers: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `frame-ancestors` (or X-Frame-Options).
- CORS: explicit origins; never reflect `Origin` with credentials.
- APIs do not return more fields than the UI needs (password hashes, emails of other users, internal flags).

## LLM and agent features

- User or web content reaching a model can contain instructions (prompt injection): the model must not have tools that act with more rights than the user who triggered it, and outputs that drive actions (SQL, shell, URLs, emails) are validated like user input.
- Secrets and other users' data never go into prompts that untrusted users can read back.
- Model output rendered as HTML/Markdown is sanitised (links and images can exfiltrate data via URLs).
- Cost controls: per-user limits on tokens and requests.
