<p align="center"><img src="assets/logo.svg" width="112" alt="vetcode logo"></p>

<h1 align="center">vetcode</h1>

<p align="center"><b>The security check your AI coding agent runs before it acts.</b><br>Before it installs a package, after it clones a repository, before your code ships.<br>Zero dependencies. Reads, never runs. Works without an agent too.</p>

<p align="center"><a href="https://vetcode.openyard.cloud"><b>vetcode.openyard.cloud</b></a></p>

<p align="center">
  <a href="https://github.com/openyard-cloud/vetcode/releases"><img alt="release" src="https://img.shields.io/github/v/release/openyard-cloud/vetcode?color=14665f"></a>
  <a href="LICENSE"><img alt="MIT" src="https://img.shields.io/badge/license-MIT-14665f"></a>
  <img alt="zero dependencies" src="https://img.shields.io/badge/dependencies-0-14665f">
  <a href="bench/README.md"><img alt="npm F1 96.0 vs GuardDog 92.8 (signs); verdicts wrong on 0.5% of clean packages" src="https://img.shields.io/badge/npm%20malware%20F1-96.0%20(GuardDog%2092.8)-2dd4bf"></a>
  <a href="https://openyard.cloud/p/vetcode#check"><img alt="OpenYard code check" src="https://openyard.cloud/badge/vetcode.svg"></a>
</p>

<p align="center"><img src="assets/demo.svg" width="760" alt="vetcode scanning a credential-stealing npm package: 2 critical and 3 high findings"></p>

```bash
# Claude Code: the skill plus the guard that checks installs and clones
claude plugin marketplace add openyard-cloud/vetcode && claude plugin install vetcode@openyard

npx skills add openyard-cloud/vetcode            # any other agent, as a skill
npx github:openyard-cloud/vetcode#v0.8.6 .       # no agent: scan a project, a package or a cloned repo
```

An agent installs a package in a second and runs a cloned project without reading it. vetcode is the check in between. It is three things:

| | What it does | Where it runs |
|---|---|---|
| **The guard** | Answers allow, ask or deny before a package is installed or an MCP server is added, and reads a repository right after it is cloned | Claude Code, on its own; other agents call it as a tool |
| **The scanner** | Reads a folder for malware, supply-chain attacks, attacks on agents, leaked secrets, and server and CI problems, and lists the places in web code worth reading | Skill, MCP server, command line, GitHub Action |
| **The review procedure** | Tells your agent how to confirm each finding by reading the code, and what to report | Skill, MCP server |

Nothing from the code it looks at is installed, built or run. It needs Node.js 18 or newer and nothing else. Free and open source (MIT), from the [OpenYard](https://openyard.cloud) community.

**Contents:** [How good is it](#how-good-is-it) · [Install](#install) · [The guard](#the-guard) · [Use it](#use-it) · [What it checks](#what-it-checks) · [How it works, and its limits](#how-it-works-and-its-limits)

## How good is it

Every number here is measured, on samples the rules were not tuned on unless it says so. The scripts, the runs and the full history are in [`bench/`](bench/README.md).

| Question | vetcode | For comparison |
|---|---|---|
| Malicious **npm** packages caught, of 1,000 (false alarms on 1,000 clean ones) | **947** (26); verdicts 907 (**5**) | [GuardDog](https://github.com/DataDog/guarddog): 903 (43) |
| Malicious **PyPI** packages caught, of 300 (false alarms on 210 clean ones) | **262** (16); verdicts 234 (**1**) | GuardDog: 241 (48) |
| The same malware after 8 kinds of disguise | still catches 99–100% of what it caught | GuardDog: 90–92% on several |
| Malicious **agent skills** it had never seen, of 157 (false alarms on 1,029 clean ones) | 91 (**1**) | [Cisco skill-scanner](https://github.com/cisco-ai-defense/skill-scanner): 101 (56) |
| The guard, shown malware as if nobody had reported it yet | blocks or questions 95% of npm, 88% of PyPI, and 3% of clean npm packages | |
| A package whose newest release is hours old, asked for 3 times | the agent installs the previous, settled version 3 times | the agent alone installs the new release 3 times |
| Wrong "this is malicious" verdicts on 72 real applications (228,000 files) | **1** | |
| Findings an agent has to read on those applications | about 4 per 1,000 files, plus 8 places to read | |
| Real injection bugs the scanner points at, of 480 advisories | 55 (11%); 6% on the half no rule was tuned on | |
| Real authorization bugs found by Claude Code with vetcode, of 49 advisories | 41% | Claude Code alone does as well |

**A sign and a verdict are different things.** A scanner of several hundred rules that lets any one of them call code malicious is wrong somewhere on almost every large project. vetcode reports every sign, which is what your agent is told to read, and gives a verdict, which is what stops an install without asking, only when a rule with a measured record fires, when two rules agree on one file, or when the sign sits in code an install script starts.

**What it is good at.** Malware and supply-chain attacks in packages and repositories, attacks aimed at coding agents (poisoned `CLAUDE.md` and skills, hooks and auto-approved MCP servers in project settings, tool descriptions that give orders), leaked secrets, and stepping in before the install, not after.

**What it is not.** It does not find web bugs by itself: it lists the dangerous calls as places to read, and those stand at about one real injection bug in ten, so they are where to start, not coverage. It does not make your agent better at logic bugs such as missing authorization; that is the agent's own ability. And a clean report means "nothing obvious found", not "safe".

**Read the numbers with care.** Samples are 157 to 1,000 items, so they move by a point or two between samples. Most malicious packages in the public datasets were found by GuardDog itself, which favours it. Cisco's scanner catches ten more skills by flagging 56 clean ones, a trade vetcode does not make. All numbers are the scanner alone; in normal use your agent reads every finding again.

## Install

All forms need Node.js 18+. **vetcode is not on npm**: every command here runs it from this repository, pinned to a release. A package called `vetcode` on npm or PyPI is not this project.

| Your agent | Use |
|---|---|
| Claude Code | the [plugin](#claude-code-plugin) (skill and guard), or the [skill](#skill) alone |
| Codex, Gemini CLI, GitHub Copilot, Cursor, Amp, Goose, opencode, Windsurf, Cline, Roo… | the [skill](#skill) |
| Anything that speaks MCP (Cursor, VS Code, Codex, Gemini CLI, Windsurf, Zed, Claude Desktop, ChatGPT…) | the [MCP server](#mcp-server) |
| claude.ai | the [skill zip](#claudeai) |
| CI, scripts, or no agent at all | the [command line](#the-scanner-on-its-own) or the [GitHub Action](#pull-request-review-on-github) |

### Claude Code plugin

```bash
claude plugin marketplace add openyard-cloud/vetcode && claude plugin install vetcode@openyard
```

Inside a session the same is two commands, because Claude Code only installs from marketplaces it already knows:

```
/plugin marketplace add openyard-cloud/vetcode
/plugin install vetcode@openyard
```

<details>
<summary>For a whole team</summary>

Commit this to the project's `.claude/settings.json`. Everyone who opens the project and trusts the folder gets the marketplace registered, so each person only runs `/plugin install vetcode@openyard` once:

```json
{
  "extraKnownMarketplaces": {
    "openyard": { "source": { "source": "github", "repo": "openyard-cloud/vetcode" } }
  },
  "enabledPlugins": { "vetcode@openyard": true }
}
```

</details>

### Skill

For any agent that loads [Agent Skills](https://agentskills.io). The [skills CLI](https://vercel.com/docs/agent-resources/skills) knows where each agent keeps them ([vetcode on skills.sh](https://skills.sh/openyard-cloud/vetcode/vetcode)):

```bash
npx skills add openyard-cloud/vetcode
```

<details>
<summary>Or copy the folder yourself</summary>

`git clone https://github.com/openyard-cloud/vetcode`, then copy `vetcode/skills/vetcode` into your agent's skills folder, in the project or under your home folder: `.agents/skills/` (shared by many agents, such as Codex and Copilot), `.claude/skills/` (Claude Code), `.github/skills/` (Copilot), `.gemini/skills/` (Gemini CLI) or `.cursor/skills/` (Cursor).

</details>

### MCP server

Four tools (`vetcode_scan`, `vetcode_guard`, `vetcode_guide`, `vetcode_reference`) and a `security_review` prompt. Most agents (`.cursor/mcp.json`, `.mcp.json`, Gemini CLI `settings.json`, Windsurf `mcp_config.json`):

```json
{
  "mcpServers": {
    "vetcode": { "command": "npx", "args": ["-y", "-p", "github:openyard-cloud/vetcode#v0.8.6", "vetcode-mcp"] }
  }
}
```

**Claude Desktop:** download `vetcode.mcpb` from [Releases](https://github.com/openyard-cloud/vetcode/releases) and open it. The server is also in the [MCP Registry](https://registry.modelcontextprotocol.io) as `io.github.openyard-cloud/vetcode`.

<details>
<summary>VS Code and Codex</summary>

VS Code (`.vscode/mcp.json`):

```json
{ "servers": { "vetcode": { "type": "stdio", "command": "npx", "args": ["-y", "-p", "github:openyard-cloud/vetcode#v0.8.6", "vetcode-mcp"] } } }
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.vetcode]
command = "npx"
args = ["-y", "-p", "github:openyard-cloud/vetcode#v0.8.6", "vetcode-mcp"]
```

</details>

Then ask your agent to "use vetcode to review this project". The agent should call `vetcode_guide` once; the server also tells it to.

### claude.ai

Download `vetcode-skill.zip` from [Releases](https://github.com/openyard-cloud/vetcode/releases) and upload it under Settings → Capabilities → Skills.

### Agents that only read an instructions file

For tools that read `AGENTS.md` (or `.cursorrules`, `CONVENTIONS.md`…) but neither skills nor MCP, clone this repository next to your project and add:

```markdown
## Security reviews
When asked to check code for security problems or malware, follow `../vetcode/skills/vetcode/SKILL.md`
and run its scanner: `node ../vetcode/skills/vetcode/scripts/vet.mjs <folder>`.
```

## The guard

An agent decides to install a package in a second: a name it remembered wrong, a name a web page suggested, a release published an hour ago. Installing runs that package's code with your rights. With the Claude Code plugin, vetcode looks at every install command **before** it runs, and at every MCP server before it is registered, and answers allow, ask or deny:

| The command would… | Answer |
|---|---|
| install a package that does not exist (a made-up name is one an attacker can register) | deny |
| install a package with a malware advisory on [OSV.dev](https://osv.dev) | deny |
| install a package whose code gets a malware verdict at critical (the archive is downloaded and read, never run) | deny |
| install a package whose code shows signs of malware short of that | ask |
| install a name one letter from a popular package (`expres`, `reqeusts`) that few people install | ask |
| install a release less than 72 hours old, or one that lost its provenance or gained an install script | ask |
| pipe a download into a shell, or install from another index, a repository or a URL | ask |
| add an MCP server at a tunnel address (ngrok, trycloudflare…) or over plain HTTP to another machine | ask |
| install well-known packages at settled versions | allow, silently |

"Ask" shows you the reason and waits for your answer. In a run with nobody to ask (`claude -p`) it stops the command and tells the agent why.

```bash
node skills/vetcode/scripts/guard.mjs "npm install expres"     # try it by hand
# ask (1 package checked)
# vetcode: expres looks like the popular package express. If express was meant, install that instead.
```

**It checks wherever a package is about to be fetched**, not only when the command names it:

| Where | What is checked |
|---|---|
| `npm install x`, `npx x`, `pip install x`, `uvx x`, `cargo add x`, `cargo install x`, `go get x`, `go install x@v`, also inside `bash -c "…"` | the packages named |
| `npm install`, `npm ci`, `pnpm install`, `yarn`, `bun install`, `pip install -r requirements.txt` | the dependencies added since the lockfile was written, one by one; and everything the lockfile or requirements file pins, against malware advisories |
| `claude mcp add … -- npx x`, `codex mcp add`, `gemini mcp add` | the package the server would run, and the server's address |
| writing `.mcp.json`, `claude_desktop_config.json`, agent `settings.json` or Codex `config.toml` | the same, for every server or hook command in the text being written |

**After a clone.** When the agent runs `git clone`, `gh repo clone` or `npx degit`, the guard reads the folder that arrived and, if it holds signs of malware or of an attack on coding agents, tells the agent before it installs, builds or runs anything from it. A clean clone gets no message.

**Other agents.** Agents without hooks can call the same check as the MCP tool `vetcode_guard`, or run the script above before installing.

**Settings** (environment variables): `VETCODE_GUARD=off` turns it off, `VETCODE_GUARD=strict` turns every ask into deny, `VETCODE_GUARD_MIN_AGE_HOURS=72` sets how old a release must be.

**What it sends.** The names and versions of the packages in the command, to the registry the install would contact anyway (npm, PyPI, crates.io or the Go proxy) and to OSV.dev, plus a download of the package archive, which is read and deleted. Packages from a private registry are not looked up anywhere. Every destination is listed in [PRIVACY.md](PRIVACY.md).

<details>
<summary>Limits of the guard</summary>

- If the network is down or a check fails, the command is allowed: the guard never blocks on its own errors.
- The clone check tells the agent what the scanner sees at high or critical; it does not stop the agent by force.
- It reads the code of the packages named and of new direct dependencies, up to 12 per command. What those depend on in turn is checked against malware advisories once it is in a lockfile, but its code is not read; scan the project for that.
- `bun.lock` is used to tell which dependencies are new, but its pins are not checked against advisories; `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` and requirements files are.
- For crates and Go modules there is no list of popular names to compare with, so look-alikes are not checked there; existence, malware advisories, the age of the release and the code are.
- A server started through `npx` or `uvx` without a version is fetched again at every start, long after the check; the guard says so and names the version to pin.
- Made-up names, removed malware and typos were already avoided by Claude Code itself in our runs, so the guard changed nothing there. Where it changed the outcome was the release hours old ([details](bench/README.md#the-guard-what-an-agent-installs-with-and-without-it)).

</details>

## Use it

Just ask your agent:

- "Check this repo for malware before I run it"
- "Security review before I deploy"
- "Is this MCP server safe to install?"
- "Review my changes for security issues"

or run `/vetcode` in Claude Code (`/vetcode:vetcode` when installed as a plugin).

### The scanner on its own

```bash
npx github:openyard-cloud/vetcode#v0.8.6 [path] [options]   # straight from a release
node skills/vetcode/scripts/vet.mjs [path] [options]         # from a clone
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
| `--mcp-lock file` | record the project's MCP servers and tool descriptions; later runs report anything that changed |
| `--fail-on <severity>` | exit 1 if a finding at that level or worse exists |
| `--no-tools` | do not run external tools (gitleaks and zizmor run automatically if installed) |

### Pull request review on GitHub

The action is on [GitHub Marketplace](https://github.com/marketplace/actions/vetcode-security-review). It scans only the files a pull request changes, comments on the exact lines it adds, lists what was already there, and fails the check only for problems on changed lines.

```yaml
# .github/workflows/vetcode.yml
name: vetcode
on: pull_request
permissions:
  contents: read
  pull-requests: write    # inline review comments
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { persist-credentials: false }
      - uses: openyard-cloud/vetcode@v0.8.6   # a release tag, or its commit SHA
        with:
          fail-on: high        # critical, high, medium, low, or empty to never fail
```

Comments are not repeated on later pushes, and a thread is resolved once its finding is gone. Pull requests from forks get a read-only token, so their results go to the job summary, and their `vetcode-ignore` comments are not honoured. Inputs: `path`, `fail-on`, `comment`, `sarif`, `online`, `github-token`.

<details>
<summary>With an AI agent, the Security tab, and other CI</summary>

**With an AI agent.** The action is the scanner on its own, so a file that builds malware-shaped strings on purpose is flagged like real malware. To have an agent confirm each finding and look for what patterns cannot see, run your agent in the same workflow and point it at the skill, for example with [Claude Code Action](https://github.com/anthropics/claude-code-action):

```yaml
      - uses: actions/checkout@v4
        with: { repository: openyard-cloud/vetcode, path: .vetcode, persist-credentials: false }
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          prompt: |
            Review this pull request for security problems. Follow .vetcode/skills/vetcode/SKILL.md
            and run its scanner with --diff origin/${{ github.base_ref }}. Comment only on confirmed findings.
```

**The Security tab.** The review comments already annotate the pull request, so do not also upload the SARIF file from the same run: code scanning would show every finding twice. Upload it from pushes to your default branch instead, with `github/codeql-action/upload-sarif@v3` and `sarif_file: vetcode.sarif` (needs `security-events: write`).

**Other CI.** Anything with Node.js 18+ can run the scanner and fail the build:

```bash
git clone --depth 1 https://github.com/openyard-cloud/vetcode .vetcode
node .vetcode/skills/vetcode/scripts/vet.mjs . --sarif vetcode.sarif --fail-on high
```

</details>

### Suppressing a false positive

```js
const id = Math.random(); // vetcode-ignore[insecure-random] used for a UI animation, not a secret
```

Name the rule. Folders can go in `.vetcodeignore` (gitignore syntax). Every report shows how much was suppressed, and `--no-ignore` turns all of it off.

## What it checks

| Area | Examples |
|---|---|
| **Malware** | decode-then-`eval`, download-and-run, reverse shells, credential and wallet theft (`~/.ssh`, `~/.aws`, browser profiles), a file that gathers the keys of several unrelated services, env-var exfiltration to webhooks, `_0x` obfuscation, hidden Unicode payloads (GlassWorm), Trojan Source bidi characters, AI CLIs started with permission prompts off, self-spreading `npm publish` worms, `.pth` autoruns, miners, beacons that report host, user and IP, `.exe` droppers |
| **Supply chain** | install-time code that combines network access with secrets, programs or hidden code; dependency-confusion probes; suspicious `preinstall`/`postinstall`; typosquats (`expresss`, `@angullar/core`, `reqeusts`); git and URL dependencies; lockfile packages from foreign hosts; `setup.py` that runs code; VS Code tasks that run on folder open; git hooks; known vulnerable and **known malicious** packages via [OSV.dev](https://osv.dev) |
| **Build and install time, beyond npm and PyPI** | Rust `build.rs` and proc macros, `go:generate` lines and Go `init()`, `go.mod` replace directives, Ruby gem extensions, Composer scripts, MSBuild `Exec` tasks and build events, NuGet `install.ps1`, Gradle builds and wrappers, Maven exec plugins, package repositories over plain HTTP |
| **AI agents** | project `.claude/settings.json` with hooks, API base-URL redirects or auto-approved MCP servers; prompt injection and hidden comments in `CLAUDE.md`, `AGENTS.md`, `.cursorrules` and skills; poisoned MCP tool descriptions; unpinned or plain-HTTP MCP servers |
| **Secrets** | 40+ providers (cloud, AI, payment, SaaS, registries), private keys, database URLs, Supabase `service_role` keys, committed `.env`, secrets in git history, secrets behind `NEXT_PUBLIC_`/`VITE_` prefixes |
| **Web and API**, as places to read (JavaScript/TypeScript, Python, PHP, Java/Kotlin, C#, Go, Ruby, Rust) | SQL, NoSQL and command injection, XSS, SSTI, path traversal, SSRF, open redirects, unsafe deserialisation, weak JWT handling, TLS checks off, permissive CORS, mass assignment, weak password hashing, zip slip, XXE, prototype pollution, model output passed to `eval` |
| **Server and cloud** | root containers, secrets in image layers, privileged or socket-mounted containers, databases published on all interfaces, nginx alias traversal, public buckets, open SSH/RDP, Supabase tables without RLS, Firebase rules open to everyone |
| **CI/CD** | `pull_request_target` and `workflow_run` running PR code, script injection from PR titles, `GITHUB_ENV` injection, `secrets: inherit`, persisted checkout credentials, self-hosted runners on public triggers, once-compromised and tag-pinned actions, long-lived publish tokens (and zizmor when installed) |
| **Hardening advice** | whether install scripts run for every dependency and brand-new releases install immediately, with the pnpm/npm/yarn/bun settings that fix it |

## How it works, and its limits

**Two steps.** A scanner of patterns and heuristics finds candidates in seconds: fast, offline and explainable. Then your agent (Claude, Codex, Gemini, Copilot, Cursor…) reads the code around each one, drops what it cannot back with a concrete exploit scenario, and looks for what patterns cannot see. For malware the scanner also gives a verdict, by rules whose record on real malicious and clean code is measured ([how](bench/README.md#signs-and-verdicts)). A rule added tomorrow is a sign until it has a record.

**What vetcode adds to an agent** is what the agent does not have by itself: every file read, not a sample; patterns for malware, supply-chain tricks and leaked secrets with measured accuracy; registry and advisory data newer than the model; a check that runs whether or not the model remembers to ask; and a procedure for looking at untrusted code without running it.

**What it does not add.**

- *Web bugs.* A dangerous call whose argument is not fixed text (a program started, text run as code, HTML written without escaping, SQL built from parts) is listed as a **place to read**, apart from the findings: most are fine, and the report says what to ask of each kind. On 480 real injection advisories a finding or a place of the right kind stood on the lines the fix later changed in 55 of them, and in 6% of the half no rule was tuned on ([how](bench/README.md#the-scanner-on-real-injection-bugs)). No place does not mean no injection bug.
- *Logic bugs.* On 49 real authorization and business-logic advisories published after the model's training cutoff, Claude Code with vetcode found the bug in 41%, and on a 15-case control Claude Code alone did as well ([how](bench/README.md#the-agent-step-on-real-advisories)).
- *Instructions hidden in what your agent reads.* The guard looks at commands, not at web pages or tool answers. The patterns that catch a poisoned `CLAUDE.md` flag under 1% of a public set of injected prompts, so a guard for fetched text was measured and not built ([why](bench/README.md#instructions-injected-into-what-an-agent-reads-a-guard-that-was-not-built)).
- *A guarantee.* New malware, logic bugs and infrastructure outside the repository can still slip through.

**Privacy** ([the full policy](PRIVACY.md)). There is no account, no server of ours and no telemetry. The scanner runs locally and sends no code anywhere; with `--online`, package names and versions go to OSV.dev, and semgrep, osv-scanner and trivy, if installed, run with their own network access. The guard sends package names to the registry and OSV.dev ([above](#the-guard)). Secrets are redacted in every report. The review step is different: your agent reads the code, so that code goes to whichever model provider the agent uses. For code that must not leave the machine, run the scanner alone, or use an agent backed by a local model.

**What runs when.** Always: every built-in check. When installed: gitleaks and zizmor (`--no-tools` turns them off). Only with `--online`: OSV.dev, semgrep, osv-scanner and trivy.

## Learning from others

vetcode borrows ideas (not code) from projects that do parts of this very well, and works alongside them: [GuardDog](https://github.com/DataDog/guarddog), [zizmor](https://github.com/zizmorcore/zizmor), [gitleaks](https://github.com/gitleaks/gitleaks), [trufflehog](https://github.com/trufflesecurity/trufflehog), [Snyk agent-scan (mcp-scan)](https://github.com/invariantlabs-ai/mcp-scan), [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages), [semgrep](https://github.com/semgrep/semgrep), [claude-code-security-review](https://github.com/anthropics/claude-code-security-review) and [Trail of Bits' skills](https://github.com/trailofbits/skills). If you need deep coverage in one area, use them too.

## Support and contributing

Questions, false alarms and missed detections: [open an issue](https://github.com/openyard-cloud/vetcode/issues). New rules, fewer false positives and real-world samples are welcome: [CONTRIBUTING.md](CONTRIBUTING.md). A security problem in vetcode itself, or a way to make it miss malware: report it privately, see [SECURITY.md](SECURITY.md). What vetcode sends and where: [PRIVACY.md](PRIVACY.md).
