<p align="center"><img src="assets/logo.svg" width="112" alt="vetcode logo"></p>

<h1 align="center">vetcode</h1>

**A security check you can run before you trust code: your own app before it ships, or someone else's repo, package, extension or MCP server before you install it.**

vetcode is an [Agent Skill](https://agentskills.io), an MCP server and a CLI, for Claude, Codex, Gemini, Copilot, Cursor and any other AI coding agent. A zero-dependency scanner finds candidates in seconds; then your agent reads the code around each one, traces where the data comes from, throws out false positives, and looks for what patterns cannot see (missing authorization, IDOR, broken business logic). You get a short report with real findings, concrete attack scenarios and fixes.

Free and open source (MIT), from the [OpenYard](https://openyard.cloud) community.

## How it compares

Measured head to head: each tool scans exactly the same packages, drawn at random from public malware datasets, on samples that were never used to tune vetcode's rules. GuardDog is scored with each of its four verdicts (any issue, any threat rule, risk score ≥ 5, risk score ≥ 7) and credited with its best one.

**Malicious packages, vetcode vs [GuardDog](https://github.com/DataDog/guarddog)**

| | Samples | F1 | Precision | Recall | False alarms |
|---|---|---|---|---|---|
| **npm**, vetcode | 500 malicious + 500 clean | **94.4** | **97.6** | **91.4** | **2.2%** |
| npm, GuardDog | same | 93.3 | 95.4 | 91.2 | 4.4% |
| **PyPI**, vetcode | 300 malicious + 216 clean | **86.4** | **93.4** | **80.3** | **7.9%** |
| PyPI, GuardDog | same | 78.3 | 78.5 | 78.0 | 29.6% |

npm samples come from [NPMAnalysis](https://github.com/lxyeternal/NPMAnalysis), the dataset whose paper ranks GuardDog first among 13 detectors. PyPI malware comes from the [Datadog dataset](https://github.com/DataDog/malicious-software-packages-dataset); the clean side is popular packages from pypi.org. On npm the two are close: a one-point gap is within the variation between samples. On PyPI vetcode is clearly ahead, mostly because it raises a quarter as many false alarms.

**Malicious agent skills, vetcode vs [Cisco skill-scanner](https://github.com/cisco-ai-defense/skill-scanner)**, both without an LLM, on 204 malicious skills (Datadog) and 132 clean ones (Anthropic, Trail of Bits, obra/superpowers):

| At severity high | Caught | False alarms |
|---|---|---|
| **vetcode** | **29.9%** | **3.0%** |
| Cisco skill-scanner | 23.5% | 15.9% |

Rules alone catch a minority of malicious skills for every tool; most of them are ordinary-looking instructions that need reading. That reading is the agent's step in vetcode's `SKILL.md` and is not part of these numbers.

**Also measured**

- **Speed:** on the same 30 PyPI packages (659 MB), GuardDog took 1,104 s and vetcode 299 s; vetcode has since become another third faster.
- **Techniques the datasets barely contain:** 12 of 12 caught from 2025–2026 campaigns, each next to a clean look-alike that is not flagged (`bench/redteam.mjs`): code pushed off-screen in `dist/`, GlassWorm Unicode payloads, payloads in images, protestware, time bombs, sandbox evasion, homoglyphs, disguised executables, recon beacons, ClawHavoc-style skills.
- **Breadth:** one run covers malware, supply chain, secrets, web and API code, server and cloud configuration, CI/CD and AI agent setups. GuardDog covers malicious packages; Cisco skill-scanner covers skills.

**Caveats.** Samples are 336 to 1,000 items, so numbers move by one or two points between samples. Most malicious packages in these datasets were found by GuardDog itself, which favours it. The numbers are the scanner alone; in normal use the agent re-reads every finding, which removes more false alarms. Everything is reproducible with the scripts in [`bench/`](bench/README.md).

## What it checks

| Area | Examples |
|---|---|
| **Malware** | decode-then-`eval`, download-and-run, reverse shells, credential and wallet theft (`~/.ssh`, `~/.aws`, browser profiles), env-var exfiltration to webhooks, `_0x` obfuscation, hidden Unicode payloads (GlassWorm), Trojan Source bidi characters, AI CLIs started with permission prompts off, self-spreading `npm publish` worms, `.pth` autoruns, miners, beacons that report host, user and IP, `.exe` droppers |
| **Supply chain** | install-time code that combines network access with secrets, programs or hidden code; dependency-confusion probes (install scripts that call home, version 99.x, self-deleting or detached scripts); suspicious `preinstall`/`postinstall`, typosquats (`expresss`, `@angullar/core`, `reqeusts`), git/URL dependencies, lockfile packages from foreign hosts, `--extra-index-url` dependency confusion, `setup.py` that runs code, VS Code tasks that run on folder open, git hooks, known vulnerable and **known malicious** packages via [OSV.dev](https://osv.dev) |
| **AI agents** | project `.claude/settings.json` with hooks, API base-URL redirects or auto-approved MCP servers; prompt injection and hidden comments in `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, skills; poisoned MCP tool descriptions; unpinned or plain-HTTP MCP servers |
| **Secrets** | 40+ providers (cloud, AI, payment, SaaS, registries), private keys, database URLs, Supabase `service_role` keys (and not the public anon key), committed `.env`, secrets in git history, secrets behind `NEXT_PUBLIC_`/`VITE_` prefixes |
| **Web / API** | SQL/NoSQL/command injection, XSS, SSTI, path traversal, SSRF, open redirects, unsafe deserialisation, weak JWT handling, TLS checks off, permissive CORS, mass assignment, weak password hashing, insecure randomness, zip slip, XXE, prototype pollution, model output passed to `eval` |
| **Server & cloud** | root containers, secrets in image layers, privileged/socket-mounted containers, databases published on all interfaces, nginx alias traversal, public buckets, open SSH/RDP, Cloudflare secrets in `vars`, Supabase tables without RLS or with `using (true)` policies, Firebase rules open to everyone |
| **CI/CD** | `pull_request_target` / `workflow_run` running PR code, script injection from PR titles, `GITHUB_ENV` injection, `secrets: inherit`, persisted checkout credentials, self-hosted runners on public triggers, spoofable bot checks, once-compromised and tag-pinned actions, long-lived publish tokens instead of trusted publishing (and zizmor when installed) |
| **Hardening advice** | whether install scripts run for every dependency and brand-new releases install immediately, with the pnpm/npm/yarn/bun settings that fix it |

## Install

vetcode comes in three forms; pick what your agent supports.

| Your agent | Use |
|---|---|
| Claude Code | the plugin (below) or the skill |
| Codex, Gemini CLI, GitHub Copilot, Cursor, Amp, Goose, opencode, Windsurf, Cline, Roo… (anything that loads [Agent Skills](https://agentskills.io)) | the **skill** |
| Any agent or app that speaks **MCP** (Cursor, VS Code, Codex, Gemini CLI, Windsurf, Zed, Claude Desktop, ChatGPT…) | the **MCP server** |
| CI, scripts, or no agent at all | the **CLI** |

All of them need Node.js 18+.

### Skill (any agent that loads Agent Skills)

With the [skills CLI](https://vercel.com/docs/agent-resources/skills), which knows where each agent looks:

```bash
npx skills add openyard-cloud/vetcode
```

Or copy the folder yourself: `git clone https://github.com/openyard-cloud/vetcode`, then copy `vetcode/skills/vetcode` into your agent's skills folder: `.agents/skills/` (the shared location many agents read, e.g. Codex and Copilot), `.claude/skills/` (Claude Code), `.github/skills/` (Copilot), `.gemini/skills/` (Gemini CLI) or `.cursor/skills/` (Cursor), in the project or under your home folder.

**Claude Code plugin:** run both lines; the first adds the marketplace, without it the second says `Marketplace "openyard" not found`.

```
/plugin marketplace add openyard-cloud/vetcode
/plugin install vetcode@openyard
```

**claude.ai:** download `vetcode-skill.zip` from [Releases](https://github.com/openyard-cloud/vetcode/releases) and upload it under Settings → Capabilities → Skills.

### MCP server

The server runs `npx` straight from this repository, pinned to a release. It offers three tools (`vetcode_scan`, `vetcode_guide`, `vetcode_reference`) and a `security_review` prompt.

Most agents (`.cursor/mcp.json`, `.mcp.json`, Claude Desktop, Gemini CLI `settings.json`, Windsurf `mcp_config.json`):

```json
{
  "mcpServers": {
    "vetcode": { "command": "npx", "args": ["-y", "-p", "github:openyard-cloud/vetcode#v0.2.0", "vetcode-mcp"] }
  }
}
```

VS Code (`.vscode/mcp.json`):

```json
{ "servers": { "vetcode": { "type": "stdio", "command": "npx", "args": ["-y", "-p", "github:openyard-cloud/vetcode#v0.2.0", "vetcode-mcp"] } } }
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.vetcode]
command = "npx"
args = ["-y", "-p", "github:openyard-cloud/vetcode#v0.2.0", "vetcode-mcp"]
```

Then ask your agent to "use vetcode to review this project". The agent should call `vetcode_guide` once; the server also tells it to.

### Agents that only read an instructions file

For tools that read `AGENTS.md` (or `.cursorrules`, `CONVENTIONS.md`…) but neither skills nor MCP, clone this repository next to your project and add:

```markdown
## Security reviews
When asked to check code for security problems or malware, follow `../vetcode/skills/vetcode/SKILL.md`
and run its scanner: `node ../vetcode/skills/vetcode/scripts/vet.mjs <folder>`.
```

## Use

Just ask:

- "Check this repo for malware before I run it"
- "Security review before I deploy"
- "Is this MCP server safe to install?"
- "Review my changes for security issues"

or run `/vetcode` in Claude Code (`/vetcode:vetcode` when installed as a plugin).

### The scanner on its own

```bash
node skills/vetcode/scripts/vet.mjs [path] [options]
```

| Option | |
|---|---|
| `--online` | look up dependencies on OSV.dev (known vulnerabilities and malware); also runs semgrep, osv-scanner and trivy if installed |
| `--deps` | read installed `node_modules`: install scripts, and the full code of packages that have them |
| `--history` | search git history for secrets that were committed and later removed |
| `--diff [base]` | only files changed against `base` (default: uncommitted changes) |
| `--no-ignore` | ignore `.vetcodeignore` and inline suppressions (always use this on code you did not write) |
| `--json file` / `--sarif file` | full results as JSON, or SARIF 2.1.0 for GitHub code scanning |
| `--baseline old.json` | show only findings that are not in an earlier `--json` report |
| `--mcp-lock file` | record the project's MCP servers and tool descriptions; later runs report anything that changed (rug pulls) |
| `--fail-on <severity>` | exit 1 if a finding at that level or worse exists |
| `--no-tools` | do not run external tools (gitleaks and zizmor run automatically if installed) |

### In CI

```yaml
name: vetcode
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
        with: { repository: openyard-cloud/vetcode, path: .vetcode }
      - run: node .vetcode/skills/vetcode/scripts/vet.mjs . --sarif vetcode.sarif --fail-on high
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: vetcode.sarif }
```

### Suppressing a false positive

```js
const id = Math.random(); // vetcode-ignore[insecure-random] used for a UI animation, not a secret
```

Name the rule. Folders can go in `.vetcodeignore` (gitignore syntax). Every report shows how much was suppressed, and `--no-ignore` turns all of it off.

## How it works, and its limits

The scanner is regex and heuristics: fast, offline, explainable, and noisy on purpose. It produces candidates, not verdicts. The skill tells the agent to confirm each one with a concrete exploit scenario, drop what it cannot justify, and review what patterns cannot see. [Cisco's measurements on malicious agent skills](https://github.com/cisco-ai-defense/skill-scanner) found that rules alone catch a small share of them, while adding a model's judgement catches far more; vetcode is built around that combination.

It is not a guarantee. New malware, logic bugs and infrastructure outside the repository can still slip through. Treat a clean report as "nothing obvious found".

**Privacy:** everything runs locally. Only with `--online` are package names and versions sent to OSV.dev. Secrets are redacted in every report.

## Learning from others

vetcode borrows ideas (not code) from projects that do parts of this very well, and works alongside them: [GuardDog](https://github.com/DataDog/guarddog), [zizmor](https://github.com/zizmorcore/zizmor), [gitleaks](https://github.com/gitleaks/gitleaks), [trufflehog](https://github.com/trufflesecurity/trufflehog), [Snyk agent-scan (mcp-scan)](https://github.com/invariantlabs-ai/mcp-scan), [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages), [semgrep](https://github.com/semgrep/semgrep), [claude-code-security-review](https://github.com/anthropics/claude-code-security-review) and [Trail of Bits' skills](https://github.com/trailofbits/skills). If you need deep coverage in one area, use them too; vetcode will pick up gitleaks, semgrep, osv-scanner and trivy when they are installed.

## Contributing

New rules, fewer false positives and real-world samples are all welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Found a way to make vetcode miss malware? Please report it privately: [SECURITY.md](SECURITY.md).

