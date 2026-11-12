# Privacy

vetcode runs on your machine. There is no vetcode account, no vetcode server, no telemetry and no analytics. OpenYard, which publishes vetcode, receives nothing from it.

This page says what each part reads, what it sends and where. It applies to the Claude Code plugin, the Agent Skill, the MCP server, the command-line scanner and the GitHub Action.

## What is never sent

Your source code, the contents of your files, file paths, environment variables, tokens, the shell commands your agent runs, and the findings of a scan. Secrets found in a scan are redacted in every report.

## The guard (the Claude Code plugin's hooks, and the `vetcode_guard` MCP tool)

When a command would install a package, register an MCP server, or write an agent configuration file, the guard looks the packages up. Each lookup is a plain HTTPS request without cookies or credentials. It carries a package name, sometimes a version, and nothing about you beyond the IP address every request carries.

| Sent | To | When |
|---|---|---|
| package name; then a download of the package archive | `registry.npmjs.org` | an npm, pnpm, yarn, bun or npx command names the package, or a bare install would add it |
| package name and version; then a download of the archive from the address PyPI gives | `pypi.org` | the same for pip, uv, uvx, pipx and poetry |
| crate name; then a download of the archive | `crates.io` | `cargo add`, `cargo install` |
| module path and version; then a download of the archive | `proxy.golang.org` | `go get`, `go install`, `go run pkg@version` |
| package names and versions | `api.osv.dev` | every package checked, and for a bare install the names and versions pinned in the lockfile or requirements file |
| package name | `api.npmjs.org`, `pypistats.org` | only when a name is one letter away from a popular package, to see how many people install it |
| the version number of Yarn | `repo.yarnpkg.com` | only after a clone that carries its own copy of Yarn, to compare that copy with the one Yarn published |

Archives are unpacked in a temporary folder, read, and deleted. Nothing from them is run.

Packages that come from a private registry (a `registry=` line in `.npmrc`, `PIP_INDEX_URL`, `GOPRIVATE` and the like) are not looked up anywhere. The guard reads those settings to know which packages to leave alone; it does not read or send the credentials next to them.

`VETCODE_GUARD=off` turns the guard off, and with it every request above.

## The scanner (the skill, the CLI, the `vetcode_scan` MCP tool, the GitHub Action)

It reads files and makes no network request, unless you pass `--online`. Then the names and versions of the project's dependencies go to `api.osv.dev`, a committed copy of Yarn is compared with `repo.yarnpkg.com`, and semgrep, osv-scanner and trivy, if you have installed them, run with their own network access.

The GitHub Action runs in your own CI and writes its comments to your pull request with the token of that workflow.

## What is stored

Nothing outside the files you ask for (`--json`, `--sarif`, `--mcp-lock`). No cache, no log, no history.

## Your agent is a separate matter

When an agent reviews code with the skill, the agent reads that code, so it goes to the model provider the agent uses, under that provider's terms. vetcode has no part in that. For code that must not leave the machine, run the scanner alone.

## Children

vetcode is a tool for software developers. It is not directed at children and collects no personal data from anyone.

## Changes and contact

Changes to this page are in its [history](https://github.com/openyard-cloud/vetcode/commits/main/PRIVACY.md). Questions: [open an issue](https://github.com/openyard-cloud/vetcode/issues). Security reports: [private vulnerability reporting](https://github.com/openyard-cloud/vetcode/security/advisories/new).
