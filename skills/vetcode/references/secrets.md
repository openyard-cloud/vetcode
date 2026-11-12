# Secrets

## Where they leak

- Source files and config committed to git (and kept in history after deletion).
- `.env` files committed, or missing from `.gitignore`.
- Front-end bundles: anything read through `NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, `REACT_APP_`, `PUBLIC_` ends up in JavaScript every visitor downloads. Mobile apps can be unpacked the same way.
- Docker image layers (`ENV`, `ARG`, copied `.env`), CI logs (`echo`, `set -x`, verbose tools), error pages and logs, source maps, notebooks with outputs, screenshots and issue trackers.
- MCP and agent config (`.mcp.json`, `claude_desktop_config.json`) with tokens in `env`, often committed by accident.

## Is it real?

- Public by design (not a leak, but check restrictions): Supabase **anon/publishable** keys (only safe with RLS), Firebase web `apiKey` (restrict by referrer/API), Stripe **publishable** `pk_` keys, Google Maps browser keys (restrict by referrer), Turnstile/reCAPTCHA **site** keys, OAuth **client ids**.
- Always secret: Supabase `service_role`/`sb_secret_`, Stripe `sk_live_`/`rk_live_`, OAuth client secrets, any private key, database URLs with passwords, cloud access keys, GitHub/npm/PyPI tokens, AI provider keys (OpenAI, Anthropic), webhook signing secrets, JWT signing secrets.
- Local-development defaults (the Supabase `supabase-demo` keys, `postgres:postgres@localhost`) are not secrets, but make sure production does not use them.

## Responding to a leak

1. **Rotate first.** Revoke the key at the provider and issue a new one. Assume it was copied the moment it was pushed: bots scan public GitHub within minutes.
2. Check the provider's logs for use you do not recognise (cloud bills, API usage, new users, database queries).
3. Move the new value to the platform's secret store / environment variables; read it in code from the environment.
4. Remove it from the code. Purge history (`git filter-repo --replace-text`) only if the repository was never public or cloned widely; otherwise rotation is the fix and history cleanup is cosmetic.
5. Prevent repeats: `.gitignore` for `.env*` (keep `.env.example`), a pre-commit secret scanner (gitleaks), GitHub push protection.
