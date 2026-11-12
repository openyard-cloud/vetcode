# vetcode

The security check Claude Code runs before it acts: before it installs a package, before it registers an MCP server, right after it clones a repository, and when you ask for a security review.

An agent installs a package in a second and runs a cloned project without reading it. Installing runs that package's code with your rights. vetcode is the check in between. It reads code and never runs it, has no dependencies, and needs only Node.js 18 or newer.

Free and open source (MIT), from the [OpenYard](https://openyard.cloud) community. Source, benchmarks and tests: [github.com/openyard-cloud/vetcode](https://github.com/openyard-cloud/vetcode).

## Install

```
/plugin install vetcode --marketplace openyard-cloud/vetcode
```

One step on Claude Code 2.1.275 or later. Needs Node.js 18 or newer on your machine; nothing else is installed.

## What you get

**A guard.** Three hooks look at what Claude is about to do and answer allow, ask or deny:

| Claude is about to… | Answer |
|---|---|
| install a package that does not exist (a made-up name is one an attacker can register) | deny |
| install a package with a malware advisory on [OSV.dev](https://osv.dev) | deny |
| install a package whose code gets a malware verdict (the archive is downloaded and read, never run) | deny |
| install a package whose code shows signs of malware short of a verdict | ask |
| install a name one letter from a popular package (`expres`, `reqeusts`) that few people install | ask |
| install a release less than 72 hours old, or one that lost its provenance or gained an install script | ask |
| pipe a download into a shell, or install from another index, a repository or a URL | ask |
| add an MCP server at a tunnel address or over plain HTTP to another machine | ask |
| install well-known packages at settled versions | allow, silently |

It reads `npm`, `pnpm`, `yarn`, `bun`, `npx`, `pip`, `uv`, `uvx`, `pipx`, `poetry`, `cargo` and `go` commands, bare installs (`npm install`, `pip install -r requirements.txt`), `claude mcp add`, and MCP servers written into `.mcp.json` or agent settings. After `git clone` it reads the folder that arrived and tells Claude if it holds signs of malware or of an attack on coding agents (a poisoned `CLAUDE.md`, hooks in project settings, an install script that decodes and runs code) before anything from it is run.

**A review skill.** `/vetcode:vetcode`, or just ask. A scanner finds candidates in seconds: malware, supply-chain tricks, leaked secrets, web and API vulnerabilities, cloud, server and CI configuration, in 8 languages. Claude then reads the code around each one, drops false positives and reports what it confirmed.

## Try it

1. "Install the expres package with npm." The guard stops and asks: the name is one letter from `express`.
2. "Clone https://github.com/expressjs/cors and tell me whether it is safe to run." The clone is read before anything from it runs (a clean one gets no message), and Claude reviews it with the skill.
3. "Use vetcode to review this project for security problems before I deploy." Claude runs the scanner, reads the code behind each finding and reports the confirmed ones with a fix.

## Everything this plugin runs, sends and fetches

**What runs.** The plugin has one program, `skills/vetcode/scripts/guard.mjs`, started with `node` by three hooks:

- before every Bash command (`PreToolUse`), to see whether it installs something or registers an MCP server;
- before every `Write`, `Edit` or `MultiEdit` (`PreToolUse`), to see whether the file is an MCP or agent configuration file that would start a program;
- after every Bash command (`PostToolUse`), to see whether it cloned a repository.

A command or file that is none of these is let through after one pattern match. The guard starts no other program except `tar` or `unzip` (to unpack a downloaded package archive into a temporary folder), `chmod` (to be able to delete that folder) and `git` (to list a folder's files). When you ask for a review, Claude runs the scanner, `skills/vetcode/scripts/vet.mjs`, on the folder you name; it uses gitleaks and zizmor if you have installed them. Nothing from a package, an archive or a cloned repository is ever installed, built or executed.

**What it sends.** Package names and versions, and nothing else: to the registry the install would contact anyway (`registry.npmjs.org`, `pypi.org`, `crates.io`, `proxy.golang.org`), to `api.osv.dev` for malware advisories, and, for a name that looks like a popular package, to the download counters `api.npmjs.org` and `pypistats.org`. No source code, file contents, paths, environment variables, tokens or commands leave your machine, and there is no telemetry. Packages from a private registry are not looked up anywhere. To know which those are, `skills/vetcode/scripts/lib/private.mjs` reads the registry lines of `.npmrc` and `pip.conf` and a few environment variables it names (`PIP_INDEX_URL`, `GOPRIVATE` and the like); that file makes no request, and tokens in the same files are not read.

**What it fetches.** The archive of each package it checks (up to 12 per command), which is unpacked, read and deleted; and, after a clone that carries its own copy of Yarn, the same release from `repo.yarnpkg.com` to compare. It fetches no code to run and no instructions.

**What it stores.** Nothing.

**What it does not touch.** It does not change Claude's permission settings or any configuration, and it does not write to your project. It only answers the hook. If the network is down or a check fails, the command is allowed: the guard never blocks on its own errors.

Full details: [privacy policy](https://github.com/openyard-cloud/vetcode/blob/main/PRIVACY.md).

## Settings

Environment variables: `VETCODE_GUARD=off` turns the guard off, `VETCODE_GUARD=strict` turns every ask into deny, `VETCODE_GUARD_MIN_AGE_HOURS=72` sets how old a release must be before it installs without a question.

## Limits

vetcode is patterns and heuristics plus your agent's reading. It is not a guarantee: new malware and logic bugs can slip through, so treat a clean result as "nothing obvious found". The guard reads the code of the packages a command names and of new direct dependencies; what those depend on in turn is checked against malware advisories, not read. The hooks run in Claude Code; the skill works in any agent that loads Agent Skills.

How it is measured, on which samples and against which other tools: [benchmarks](https://github.com/openyard-cloud/vetcode/blob/main/bench/README.md).

## This plugin contains attack patterns, as data

A scanner has to know what it looks for. The files under `skills/vetcode/scripts/lib/` hold patterns that match malware and text written to steer an agent, and the files under `skills/vetcode/references/` describe such attacks so that Claude can recognise them. They are data the scanner matches against, not instructions to Claude and not code that runs.

## Support

- Questions, false alarms, missed detections: [issues](https://github.com/openyard-cloud/vetcode/issues)
- A security problem in vetcode itself: [private vulnerability reporting](https://github.com/openyard-cloud/vetcode/security/advisories/new)
- Troubleshooting: run the guard by hand to see its answer and reasons, `node skills/vetcode/scripts/guard.mjs "npm install expres"`, from the plugin's folder.
