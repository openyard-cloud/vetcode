<p align="center"><img src="assets/logo.svg" width="112" alt="vetcode logo"></p>

<h1 align="center">vetcode</h1>

<p align="center"><b>The security check your AI coding agent runs before it acts.</b><br>Before it installs a package, after it clones a repository, before your code ships.<br>Zero dependencies. Reads, never runs. Works without an agent too.</p>

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
npx github:openyard-cloud/vetcode#v0.8.1 .       # no agent: scan a project, a package or a cloned repo
```

An agent installs a package in a second and runs a cloned project without reading it. vetcode is the check in between, and every claim below is measured ([how](bench/README.md)):

- **It steps in before the damage.** In Claude Code a [guard](#the-guard-checked-before-your-agent-installs) looks at every install command before it runs and at every repository right after it is cloned. Asked for a package whose newest release was hours old, the agent alone installed it 3 times out of 3; with the guard it installed the previous settled version every time. Shown malware as if nobody had reported it yet, the guard blocked or questioned 95% of 1,000 malicious npm packages and 88% of 300 PyPI ones.
- **It tells a sign from a verdict.** A scanner of several hundred rules that lets any one of them call code malicious is wrong somewhere on almost every large project. vetcode reports every sign, and gives a verdict only when a rule with a measured record fires, when two rules agree on one file, or when the sign sits in code an install script starts. On 72 open-source apps (228,000 files) that leaves one verdict, on an app that ships agent hooks; on clean npm packages the verdict is wrong 5 times in 1,000, where GuardDog flags 43.
- **Catches more malware than the best open-source detector, and is harder to fool.** Both tools on the same 2,000 npm packages: vetcode's signs catch 947 of 1,000 with 26 false alarms and its verdicts 907 with 5; GuardDog catches 903 with 43. On PyPI: 262 of 300 with 16, verdicts 234 with 1; GuardDog 241 with 48. After 8 kinds of disguise (split strings, hex escapes, character codes, reversed strings, base64 and gzip packing, code pushed off screen or into `dist/`) it still catches 99–100% of what it caught; GuardDog loses up to 10%.
- **Knows what attacks on agents look like.** Poisoned `CLAUDE.md` and skills, hooks and auto-approved MCP servers in project settings, tool descriptions that give orders, a "required" tool to install from a throwaway host. On 157 malicious skills from marketplaces it had never seen, rules alone catch 58% and wrongly flag 1 of 1,029 clean ones.
- **One run, everything else too.** Malware, supply chain, secrets, web and API bugs, cloud and server config, CI/CD, in 8 languages.
- **Reads, never runs.** Nothing from the target is installed, built or executed. Node 18+ and nothing else.

vetcode is an [Agent Skill](https://agentskills.io), an MCP server, a CLI, a GitHub Action and, in Claude Code, the guard. A zero-dependency scanner finds candidates in seconds; then your agent (Claude, Codex, Gemini, Copilot, Cursor…) reads the code around each one and throws out false positives. Finding logic bugs such as missing authorization is your agent's own ability, and we measured that vetcode [does not raise it](#how-it-works-and-its-limits); what it adds is what an agent does not have by itself: every file read, measured patterns, registry and advisory data newer than the model, and a check that runs whether or not the model remembers to ask.

Free and open source (MIT), from the [OpenYard](https://openyard.cloud) community.

## How it compares

Measured head to head: each tool scans exactly the same packages, drawn at random from public malware datasets, on samples that were never used to tune vetcode's rules. GuardDog is scored with each of its four verdicts (any issue, any threat rule, risk score ≥ 5, risk score ≥ 7) and credited with its best one.

**Malicious packages, vetcode vs [GuardDog](https://github.com/DataDog/guarddog)**

| | Samples | F1 | Precision | Recall | False alarms |
|---|---|---|---|---|---|
| **npm**, vetcode 0.8.0, any sign | 1,000 malicious + 1,000 clean | **96.0** | 97.3 | **94.7** | 2.6% |
| **npm**, vetcode 0.8.0, verdict | same | 94.9 | **99.5** | 90.7 | **0.5%** |
| npm, GuardDog 3.2.0 | same | 92.8 | 95.5 | 90.3 | 4.3% |
| **PyPI**, vetcode 0.8.0, any sign | 300 malicious + 210 clean | **90.7** | 94.2 | **87.3** | 7.6% |
| **PyPI**, vetcode 0.8.0, verdict | same | 87.5 | **99.6** | 78.0 | **0.5%** |
| PyPI, GuardDog 3.2.0 | same | 81.8 | 83.4 | 80.3 | 22.9% |

"Any sign" is what an agent is told to read; "verdict" is what stops an install without asking. The table of rules trusted to give a verdict alone was computed from another sample (seed 7), so these rows are a check, not a fit.

Both tools ran on GitHub Actions on the same sample (seed 31), whose malicious packages nobody looked at while 0.6.0's rules were written. npm samples come from [NPMAnalysis](https://github.com/lxyeternal/NPMAnalysis), the dataset whose paper ranks GuardDog first among 13 detectors. PyPI malware comes from the [Datadog dataset](https://github.com/DataDog/malicious-software-packages-dataset); the clean side is popular packages from pypi.org. Earlier versions were closer on npm: over eight older samples vetcode led on five and GuardDog on three, by up to 1.1 F1 points. The [full history](bench/README.md) lists every run, including those.

**Malicious agent skills, vetcode vs [Cisco skill-scanner](https://github.com/cisco-ai-defense/skill-scanner)**, both without an LLM, on 204 malicious skills (Datadog) and 132 clean ones (Anthropic, Trail of Bits, obra/superpowers):

| At severity high | Caught | False alarms |
|---|---|---|
| **vetcode** | **29.9%** | **3.0%** |
| Cisco skill-scanner | 23.5% | 15.9% |

Those numbers were measured before any rule was written from this dataset. Version 0.4.1 adds rules for what the misses had in common (a "required" tool to install from a throwaway host, an MCP or API endpoint on a tunnel, orders to act without confirmation) and catches **48.5%** of the same 204 with the same 3.0% false alarms. That figure is in-sample: the rules were written from descriptions of these samples, so it does not count as evidence. 0.7.1 stands at 50.5% (103 of 204) with 0.8% false alarms on this set.

**On skills it had never seen.** Because that figure is in-sample, 0.7.0 was also run on a second set that no rule was written from and whose misses are never described to anyone (the benchmark refuses to): 157 skills found malicious on two skill marketplaces ([MaliciousAgentSkillsBench](https://github.com/protectskills/MaliciousSkillBench)), against 1,029 skills from four public collections (GitHub's awesome-copilot, Microsoft's, wshobson/agents and K-Dense's scientific skills).

| Held-out skills | Caught | False alarms | F1 |
|---|---|---|---|
| **vetcode 0.7.0** | 58.0% (91 of 157) | **0.1%** (1 of 1,029) | **73.1** |
| vetcode 0.7.0 at first look, before its false alarms on the clean side were read | 59.9% (94) | 2.6% (27) | 67.6 |
| Cisco skill-scanner 2.3.2, its best verdict | **64.3%** (101 of 157) | 5.4% (56 of 1,029) | 64.3 |

Cisco's scanner catches a few more of these; vetcode wrongly flags far fewer clean skills, which is what an agent pays for on every skill it loads. The clean collections are public, so their false alarms were read and fixed (that cost three catches, and it means vetcode's 0.1% is a tuned number where Cisco's 5.4% is not; the first-look row is the like-for-like one); the malicious side stays unread.

Rules alone catch a minority of malicious skills for every tool; most of them are ordinary-looking instructions that need reading. That reading is the agent's step in vetcode's `SKILL.md` and is not part of these numbers.

**Also measured**

- **Disguised malware:** once samples are rewritten the way attackers dodge scanners (split strings, `\xNN` escapes, `String.fromCharCode`/`chr()` building, reversed strings, base64- or gzip-packed `eval`/`exec`, code pushed off screen or moved into `dist/`), vetcode still catches 99–100% of what it caught before; GuardDog drops to 90–92% on several of them (`bench/mutate.mjs`).
- **Speed:** on the same 30 PyPI packages (659 MB), GuardDog took 1,104 s and vetcode 299 s; vetcode has since become another third faster.
- **Techniques the datasets barely contain:** 15 of 15 caught from 2021–2026 campaigns, each next to a clean look-alike that is not flagged (`bench/redteam.mjs`): code pushed off-screen in `dist/`, GlassWorm Unicode payloads, payloads in images, protestware, time bombs, sandbox evasion, homoglyphs, disguised executables, recon beacons, ClawHavoc-style skills, a Visual Studio project that runs encoded PowerShell at build, a Rust build script that steals SSH keys, a Go module whose init() opens a shell.
- **Breadth:** one run covers malware, supply chain, secrets, web and API code, server and cloud configuration, CI/CD and AI agent setups. GuardDog covers malicious packages; Cisco skill-scanner covers skills.

**On real applications.** A scanner that cries wolf costs an agent tokens on every run, so false alarms are measured too: twelve well-known open-source apps (about 14,000 files, pinned to a commit) that handle tokens, passwords and API keys all day.

| Twelve apps at a time | Findings at first look | Findings now | Wrong verdicts at first look | Wrong verdicts now |
|---|---|---|---|---|
| First set (14,000 files) | 2,024 (0.3.1) | **76** | 3 | **0** |
| Second (33,000 files) | 477 (0.5.0) | **247** | 5 | **0** |
| Third (37,000 files) | 340 (0.6.0) | **210** | 2 | **0** |
| Fourth (40,000 files) | 380 (0.7.0) | **180** | 4 | **0** |
| Fifth (58,000 files) | 1,423 (0.7.1) | **818** | 5 | **0** |
| Sixth (45,000 files), first scanned with 0.8.0 | 554 | 554 | **1** (2 by the old rule) | 1 |

Findings are at medium or above; from 0.8.0 several raw-HTML sinks in one file count once (counted line by line the "now" column reads 96, 285, 241, 293 and 1,181). A wrong verdict used to mean any high sign of malware, supply-chain attack or agent attack; five sets of apps in a row produced two to five of them at first look, each from one rule matching one or two lines, and fixing the rules for one set did not help the next. From 0.8.0 a verdict needs a rule with a record or corroboration. The sixth set is the first met with that mechanism: one verdict, on an app (Ghost) that does ship agent hooks and install instructions for agents.

The report itself got shorter too, which is what an agent pays for: on the first twelve apps the text an agent has to read went from 131 KB to 45 KB in total (median per app 11 KB to 4 KB), and on the third twelve from 147 KB to 79 KB. Fewer findings account for most of it; low and informational findings are now one line per rule, with the detail in the JSON report.

"First look" is the version that met the apps before any rule was changed because of them. On new code the scanner still reports 9 to 24 findings per thousand files; that part has not improved from one set to the next, and the candidates are for a reader to check.

Detection did not pay for this: on a malware sample no rule was written from, 0.6.0 catches slightly more than 0.5.0 (npm 944 → 949 of 1,000, PyPI 247 → 262 of 300) with the same false alarms. Run the noise check yourself with `node bench/noise.mjs` (no model, no cost); details in [`bench/README.md`](bench/README.md#false-alarms-on-real-applications).

**Caveats.** Samples are 336 to 1,000 items, so numbers move by one or two points between samples. Most malicious packages in these datasets were found by GuardDog itself, which favours it. The numbers are the scanner alone; in normal use the agent re-reads every finding, which removes more false alarms. Everything is reproducible with the scripts in [`bench/`](bench/README.md).

## What it checks

| Area | Examples |
|---|---|
| **Malware** | decode-then-`eval`, download-and-run, reverse shells, credential and wallet theft (`~/.ssh`, `~/.aws`, browser profiles), env-var exfiltration to webhooks, `_0x` obfuscation, hidden Unicode payloads (GlassWorm), Trojan Source bidi characters, AI CLIs started with permission prompts off, self-spreading `npm publish` worms, `.pth` autoruns, miners, beacons that report host, user and IP, `.exe` droppers |
| **Supply chain** | install-time code that combines network access with secrets, programs or hidden code; dependency-confusion probes (install scripts that call home, version 99.x, self-deleting or detached scripts); suspicious `preinstall`/`postinstall`, typosquats (`expresss`, `@angullar/core`, `reqeusts`), git/URL dependencies, lockfile packages from foreign hosts, `--extra-index-url` dependency confusion, `setup.py` that runs code, VS Code tasks that run on folder open, git hooks, known vulnerable and **known malicious** packages via [OSV.dev](https://osv.dev) |
| **Build and install time, beyond npm and PyPI** | Rust `build.rs` and proc macros that download, run shells or read `~/.ssh`; `go:generate` lines that fetch and pipe to a shell, Go `init()` that starts programs or phones home, `go.mod` replace directives pointing at another repository; Ruby gem extensions (`extconf.rb`) that download; Composer scripts; MSBuild `Exec` tasks, pre/post-build events and inline tasks in `.csproj`/`.vcxproj`/`.targets`, NuGet `install.ps1`; Gradle builds that download and run shells, a Gradle wrapper pointing away from services.gradle.org, Maven exec/antrun plugins; package repositories over plain HTTP |
| **AI agents** | project `.claude/settings.json` with hooks, API base-URL redirects or auto-approved MCP servers; prompt injection and hidden comments in `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, skills; poisoned MCP tool descriptions; unpinned or plain-HTTP MCP servers |
| **Secrets** | 40+ providers (cloud, AI, payment, SaaS, registries), private keys, database URLs, Supabase `service_role` keys (and not the public anon key), committed `.env`, secrets in git history, secrets behind `NEXT_PUBLIC_`/`VITE_` prefixes |
| **Web / API** (JavaScript/TypeScript, Python, PHP, Java/Kotlin, C#, Go, Ruby, Rust) | SQL/NoSQL/command injection, XSS, SSTI, path traversal, SSRF, open redirects, unsafe deserialisation, weak JWT handling, TLS checks off, permissive CORS, mass assignment, weak password hashing, insecure randomness, zip slip, XXE, prototype pollution, model output passed to `eval` |
| **Server & cloud** | root containers, secrets in image layers, privileged/socket-mounted containers, databases published on all interfaces, nginx alias traversal, public buckets, open SSH/RDP, Cloudflare secrets in `vars`, Supabase tables without RLS or with `using (true)` policies, Firebase rules open to everyone |
| **CI/CD** | `pull_request_target` / `workflow_run` running PR code, script injection from PR titles, `GITHUB_ENV` injection, `secrets: inherit`, persisted checkout credentials, self-hosted runners on public triggers, spoofable bot checks, once-compromised and tag-pinned actions, long-lived publish tokens instead of trusted publishing (and zizmor when installed) |
| **Hardening advice** | whether install scripts run for every dependency and brand-new releases install immediately, with the pnpm/npm/yarn/bun settings that fix it |

## Install

**One command, any agent that loads [Agent Skills](https://agentskills.io)** (Claude Code, Codex, Gemini CLI, GitHub Copilot, Cursor, Amp, Goose, opencode…):

```bash
npx skills add openyard-cloud/vetcode
```

**One command, Claude Code as a plugin** (run in your terminal):

```bash
claude plugin marketplace add openyard-cloud/vetcode && claude plugin install vetcode@openyard
```

Everything else (MCP, claude.ai, CI, a whole team) is below. All forms need Node.js 18+.

**vetcode is not on npm.** Every command on this page runs it from this repository, pinned to a release. If you come across a package called `vetcode` on npm or PyPI, it is not this project.

| Your agent | Use |
|---|---|
| Claude Code | the [plugin](#claude-code) or the [skill](#skill-any-agent-that-loads-agent-skills) |
| Codex, Gemini CLI, GitHub Copilot, Cursor, Amp, Goose, opencode, Windsurf, Cline, Roo… | the [skill](#skill-any-agent-that-loads-agent-skills) |
| Any agent or app that speaks MCP (Cursor, VS Code, Codex, Gemini CLI, Windsurf, Zed, Claude Desktop, ChatGPT…) | the [MCP server](#mcp-server) |
| claude.ai | the [skill zip](#claudeai) |
| CI, scripts, or no agent at all | the [CLI](#the-scanner-on-its-own) |

### Skill (any agent that loads Agent Skills)

The [skills CLI](https://vercel.com/docs/agent-resources/skills) knows where each agent looks for skills:

```bash
npx skills add openyard-cloud/vetcode
```

Or copy the folder yourself: `git clone https://github.com/openyard-cloud/vetcode`, then copy `vetcode/skills/vetcode` into your agent's skills folder: `.agents/skills/` (the shared location many agents read, e.g. Codex and Copilot), `.claude/skills/` (Claude Code), `.github/skills/` (Copilot), `.gemini/skills/` (Gemini CLI) or `.cursor/skills/` (Cursor), in the project or under your home folder.

### Claude Code

As a plugin, from inside a session it takes two commands, because Claude Code only installs from marketplaces it already knows. The first line is needed once per machine; without it the second says `Marketplace "openyard" not found`.

```
/plugin marketplace add openyard-cloud/vetcode
/plugin install vetcode@openyard
```

From the terminal the same is one line: `claude plugin marketplace add openyard-cloud/vetcode && claude plugin install vetcode@openyard`.

**For a whole team**, commit this to the project's `.claude/settings.json`. Everyone who opens the project and trusts the folder gets the OpenYard marketplace registered, so each person only runs `/plugin install vetcode@openyard` once:

```json
{
  "extraKnownMarketplaces": {
    "openyard": { "source": { "source": "github", "repo": "openyard-cloud/vetcode" } }
  },
  "enabledPlugins": { "vetcode@openyard": true }
}
```

### claude.ai

Download `vetcode-skill.zip` from [Releases](https://github.com/openyard-cloud/vetcode/releases) and upload it under Settings → Capabilities → Skills.

### MCP server

The server runs `npx` straight from this repository, pinned to a release. It offers four tools (`vetcode_scan`, `vetcode_guard`, `vetcode_guide`, `vetcode_reference`) and a `security_review` prompt.

Most agents (`.cursor/mcp.json`, `.mcp.json`, Claude Desktop, Gemini CLI `settings.json`, Windsurf `mcp_config.json`):

```json
{
  "mcpServers": {
    "vetcode": { "command": "npx", "args": ["-y", "-p", "github:openyard-cloud/vetcode#v0.8.1", "vetcode-mcp"] }
  }
}
```

VS Code (`.vscode/mcp.json`):

```json
{ "servers": { "vetcode": { "type": "stdio", "command": "npx", "args": ["-y", "-p", "github:openyard-cloud/vetcode#v0.8.1", "vetcode-mcp"] } } }
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.vetcode]
command = "npx"
args = ["-y", "-p", "github:openyard-cloud/vetcode#v0.8.1", "vetcode-mcp"]
```

Then ask your agent to "use vetcode to review this project". The agent should call `vetcode_guide` once; the server also tells it to.

### Agents that only read an instructions file

For tools that read `AGENTS.md` (or `.cursorrules`, `CONVENTIONS.md`…) but neither skills nor MCP, clone this repository next to your project and add:

```markdown
## The guard: checked before your agent installs

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

The same answers apply wherever a package is about to be fetched, not only when the command names it:

| Where | What is checked |
|---|---|
| `npm install x`, `npx x`, `pip install x`, `uvx x`, `cargo add x`, `cargo install x`, `go get x`, `go install x@v`, also inside `bash -c "…"` | the packages named |
| `npm install`, `npm ci`, `pnpm install`, `yarn`, `bun install`, `pip install -r requirements.txt` | the dependencies added since the lockfile was written (what an agent just put into `package.json`), one by one; and everything the lockfile or requirements file pins, against malware advisories in one request |
| `claude mcp add … -- npx x`, `codex mcp add`, `gemini mcp add` | the package the server would run, and the server's address |
| writing `.mcp.json`, `claude_desktop_config.json`, agent `settings.json` or Codex `config.toml` | the same, for every server or hook command in the text being written |

A server started through `npx` or `uvx` without a version is fetched again at every start, long after the check; the guard says so and names the version to pin.

**After a clone.** When the agent runs `git clone`, `gh repo clone` or `npx degit`, the guard reads the folder that arrived (nothing is run) and, if it holds signs of malware or of an attack on coding agents (a poisoned `CLAUDE.md`, hooks in project settings, an install script that decodes and runs code), tells the agent before it installs, builds or runs anything from it. A clean clone gets no message.

It reads `npm`, `pnpm`, `yarn` and `bun` installs, `npx` and friends, `pip`, `uv`, `uvx`, `pipx`, `poetry`, `cargo` and `go`. For crates and Go modules there is no list of popular names to compare with, so look-alikes are not checked there; existence (crates.io), malware advisories, the age of the release and the code are. Other shell commands and other files cost one regex. "Ask" shows you the reason and waits for your answer; in a run with nobody to ask (`claude -p`) it stops the command and tells the agent why.

```bash
node skills/vetcode/scripts/guard.mjs "npm install expres"     # try it by hand
# ask (1 package checked)
# vetcode: expres looks like the popular package express. If express was meant, install that instead.
```

Agents without hooks can call the same check as the MCP tool `vetcode_guard`, or run the script above before installing.

**Settings** (environment variables): `VETCODE_GUARD=off` turns it off, `VETCODE_GUARD=strict` turns every ask into deny, `VETCODE_GUARD_MIN_AGE_HOURS=72` sets how old a release must be.

**What it sends:** the names and versions of the packages in the command, to the package registry (the one the install would contact anyway: npm, PyPI, crates.io or the Go proxy) and to OSV.dev, plus a download of the package archive, which is read and deleted. A name that looks like a popular package also goes to the download counters (api.npmjs.org, pypistats.org), to see how many people install it. Every destination is listed in [PRIVACY.md](PRIVACY.md). For an install that names no package, the names and versions in the lockfile or requirements file go to OSV.dev. Packages that come from a private registry (a `registry=` line in `.npmrc`, `PIP_INDEX_URL` and the like) are not looked up anywhere. If the network is down or a check fails, the command is allowed: the guard never blocks on its own errors.

**Limits:** the clone check reports what the scanner sees at high or critical; it does not stop the agent by force, it tells it. For packages, it reads the code of the packages named and of new direct dependencies, up to 12 per command; what those packages depend on in turn is checked against malware advisories once it is in a lockfile, but its code is not read (scan the project for that). `bun.lock` is used to tell which dependencies are new, but its pins are not checked against advisories; `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` and requirements files are. Measured against Claude Code without it ([details](bench/README.md#the-guard-what-an-agent-installs-with-and-without-it)): asked for a package whose newest release was hours old, the agent alone installed it 3 times out of 3, and with the guard it installed the previous settled version every time. Made-up names, removed malware and typos the agent already avoided by itself, so the guard changed nothing there. Malware that is still downloadable cannot be tested live; on the malware datasets, put to the guard as if no advisory existed yet, it blocks or questions about 95% of malicious npm packages and 88% of PyPI ones, and 3% of clean npm packages ([details](bench/README.md#the-guard-what-an-agent-installs-with-and-without-it)).

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
npx github:openyard-cloud/vetcode#v0.8.1 [path] [options]   # straight from a release
node skills/vetcode/scripts/vet.mjs [path] [options] # from a clone
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

### Pull request review on GitHub

vetcode can review every pull request: it scans only the files the pull request changes, comments on the exact lines it adds, lists what was already there, and fails the check only for problems on changed lines.

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
      - uses: openyard-cloud/vetcode@main   # pin a release tag or commit SHA
        with:
          fail-on: high        # critical, high, medium, low, or empty to never fail
```

Comments are not repeated on later pushes, and once a finding is gone (fixed or removed) its thread is resolved automatically. Pull requests from forks get a read-only token, so for them the results go to the job summary; their `vetcode-ignore` comments are also ignored, so a contributor cannot hide what they add. Inputs: `path`, `fail-on`, `comment`, `sarif`, `online`, `github-token`.

The review comments already annotate the pull request, so do not also upload the SARIF file from the same pull request run: GitHub code scanning would show every finding a second time. For the Security tab, upload it from pushes to your default branch instead (see Other CI below). These comments come from the scanner alone, with no AI: patterns, so a benchmark file that builds malware-shaped strings on purpose gets flagged like real malware. The agent step below reads each finding in context and drops the ones it cannot justify.

**With an AI agent.** The action is the scanner on its own. To have an agent confirm each finding and look for what patterns cannot see (authorization, business logic), run your agent in the same workflow and point it at the skill, for example with [Claude Code Action](https://github.com/anthropics/claude-code-action):

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

### Other CI

Any CI that has Node.js 18+ can run the scanner and fail the build:

```bash
git clone --depth 1 https://github.com/openyard-cloud/vetcode .vetcode
node .vetcode/skills/vetcode/scripts/vet.mjs . --sarif vetcode.sarif --fail-on high
```

On GitHub, a push to the default branch can feed the Security tab with the same SARIF file: run the line above, then `github/codeql-action/upload-sarif@v3` with `sarif_file: vetcode.sarif` (needs `security-events: write`).

### Suppressing a false positive

```js
const id = Math.random(); // vetcode-ignore[insecure-random] used for a UI animation, not a secret
```

Name the rule. Folders can go in `.vetcodeignore` (gitignore syntax). Every report shows how much was suppressed, and `--no-ignore` turns all of it off.

## How it works, and its limits

The scanner is regex and heuristics: fast, offline and explainable. It produces candidates, and for malware one more thing: a verdict, given only by rules whose record on real malicious and clean code is measured ([how](bench/README.md#signs-and-verdicts)), by two rules agreeing on one file, or by a sign in code that an install script starts. A rule added tomorrow is a sign until it has a record. The skill tells the agent to confirm each one with a concrete exploit scenario, drop what it cannot justify, and review what patterns cannot see. [Cisco's measurements on malicious agent skills](https://github.com/cisco-ai-defense/skill-scanner) found that rules alone catch a small share of them, while adding a model's judgement catches far more; vetcode is built around that combination.

It is not a guarantee. New malware, logic bugs and infrastructure outside the repository can still slip through. Treat a clean report as "nothing obvious found".

**What vetcode adds, and what it does not.** We measured the review step on 49 real authorization and business-logic advisories published after the model's training cutoff. Claude Code with vetcode found the bug in 41% of them, and on a 15-case control Claude Code alone did as well (7 against 8). Finding logic bugs is your agent's own ability; the skill does not raise it. What vetcode gives an agent is what it does not have by itself: every file read, not a sample; patterns for malware, supply-chain tricks and leaked secrets with measured accuracy; registry and advisory data newer than the model; and a procedure for looking at untrusted code without running it. The numbers and their limits are in [`bench/README.md`](bench/README.md#the-agent-step-on-real-advisories).

**Privacy** ([the full policy](PRIVACY.md)): there is no account, no server of ours and no telemetry. The scanner runs locally and sends no code anywhere. The guard, when the plugin's hook is on, sends the package names in an install command to the registry and OSV.dev ([details](#the-guard-checked-before-your-agent-installs)). The scanner itself reaches the network only with `--online`: package names and versions go to OSV.dev, and installed semgrep, osv-scanner and trivy run with their own network access (semgrep downloads its rules). Secrets are redacted in every report. The review step is different: your agent reads the code, so that code goes to whichever model provider the agent uses (Anthropic, OpenAI, Google…), under that provider's terms. For code that must not leave the machine, run the scanner alone, or use an agent backed by a local model.

**What runs when.** Built in, always: every check listed above, including secrets, containers and infrastructure files. Automatically when installed: gitleaks and zizmor (`--no-tools` turns them off). Only with `--online`: OSV.dev, semgrep, osv-scanner and trivy.

## Learning from others

vetcode borrows ideas (not code) from projects that do parts of this very well, and works alongside them: [GuardDog](https://github.com/DataDog/guarddog), [zizmor](https://github.com/zizmorcore/zizmor), [gitleaks](https://github.com/gitleaks/gitleaks), [trufflehog](https://github.com/trufflesecurity/trufflehog), [Snyk agent-scan (mcp-scan)](https://github.com/invariantlabs-ai/mcp-scan), [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages), [semgrep](https://github.com/semgrep/semgrep), [claude-code-security-review](https://github.com/anthropics/claude-code-security-review) and [Trail of Bits' skills](https://github.com/trailofbits/skills). If you need deep coverage in one area, use them too; vetcode will pick up gitleaks, semgrep, osv-scanner and trivy when they are installed.

## Support

Questions, false alarms and missed detections: [open an issue](https://github.com/openyard-cloud/vetcode/issues). A security problem in vetcode itself: [SECURITY.md](SECURITY.md). What vetcode sends and where: [PRIVACY.md](PRIVACY.md).

## Contributing

New rules, fewer false positives and real-world samples are all welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Found a way to make vetcode miss malware? Please report it privately: [SECURITY.md](SECURITY.md).
