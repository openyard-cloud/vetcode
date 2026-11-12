# Code that decides who may do what: libraries, SDKs and servers

Web apps have routes to walk through; a broker, a database, an SDK, a sandbox or a memory store does not. Their access bugs hide in how a decision is built, not in a missing check on a route. Start by finding every **decision point**: ACL and permission checks, role and scope evaluation, tenant, namespace or session scoping, sandbox and path boundaries, and the code that builds the keys, topics, paths or queries those decisions are made on. Then ask four questions of each.

## 1. Can a value cross a boundary by its spelling?

Isolation often rests on a string: a cache key `tenant:user:item`, a storage path, a topic, a namespace prefix, an ACL pattern, a LIKE or glob query.

- Values a caller controls (names, ids, labels, topics) are escaped or rejected when they can contain the separator or a special character: `:` `/` `.` `..` `|` `\0`, wildcards (`*`, `?`, `+`, `#`, `%`, `_`), regex metacharacters, or Unicode that normalizes to one of them.
- A pattern filled with a caller's value (`user/%u/#`, `tenants/{id}/*`) cannot become wider than intended because the value itself contains a wildcard.
- Prefix checks compare whole segments: `startsWith("team1")` also matches `team10`, and a path check before normalization lets `a/../b` through.
- Two different inputs never produce the same key (missing delimiters, case folding, truncation), which would let one user read or overwrite another's entry.

## 2. Does every way in apply the same check?

- List every operation that reaches the same data or action: main API, legacy or v1 endpoints, batch and bulk calls, import and export, AJAX or partial handlers, admin UIs, CLI and RPC entry points, a second protocol (WebSocket next to HTTP, a binary protocol next to REST), background jobs acting on a request's behalf.
- Each one enforces the same permission on the same object. A check in the main handler does not protect a sibling that skips it.
- Granular permissions (export, resend, reorder, sign, download) are checked for that action, not only the broader "can view" or "is logged in".

## 3. Whose identity does the decision use?

- The identity used for the check is the authenticated one. An identity the caller merely claims (an `authzid` or "act as" field, a header, a parameter, a token field that was not verified) is not trusted unless the authenticated identity is allowed to assume it.
- Different kinds of principal (user, service account, API key, link share, guest, anonymous) are not mistaken for one another: an id from one kind is not looked up as another, and a share link's rights do not become its creator's.
- Objects stay bound to the session or user that created them (tasks, streams, uploads, temporary resources); another session cannot read or drive them by guessing or reusing an id.
- Ownership of a parent object is not taken as permission for a child that belongs to someone else (a project member editing another project's item through a shared id).

## 4. Is the check still true when the action happens?

- Allow-lists and boundary checks are applied again after anything that changes the target: HTTP redirects, DNS resolution, symlink and path resolution, module or plugin resolution, URL decoding, archive extraction.
- The checked value is the value used: no re-reading from the request, no second parse with a different parser, no time-of-check to time-of-use gap on files or records.
- Defaults fail closed: a request that matches no rule, an unknown path or an unexpected type is denied, not passed through.
- A sandbox or "safe mode" option holds for every way code or files are loaded (custom resolvers, `require` hooks, includes, templates), not only the main one.

## Reporting

Name the decision point, the input that crosses it and what the attacker gains (read, write, act as, escape). Severity follows the data or action reached: another tenant's data or an admin action is high; a boundary that only leaks names is medium.
