# Benchmark

Measures how many real malicious packages the vetcode scanner flags, and how many clean
packages it flags by mistake. Scanner only: the agent's verification step is not part of
these numbers.

| Dataset | Malicious | Benign |
|---|---|---|
| npm | [NPMAnalysis](https://github.com/lxyeternal/NPMAnalysis) (its paper scores GuardDog and 12 other tools on the same data) | NPMAnalysis |
| PyPI | [Datadog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) | source distributions of popular packages from pypi.org |
| AI skills | Datadog dataset | skills from Anthropic, Trail of Bits and obra/superpowers |

A package is flagged when vetcode reports a high or critical finding in the malware,
supply-chain or agent categories, ignoring low-confidence findings (tests, docs).

## Run it online (recommended)

Actions → **Benchmark** → Run workflow. Samples are downloaded and scanned on a throwaway
GitHub runner; the results are attached to the run and summarised on its page. No
malicious sample touches your machine.

## Run it locally

Only if you need to: the samples are real malware. Nothing is installed or executed (archives
are unpacked into empty folders, read, and deleted), but antivirus may react.

```bash
node bench/fetch.mjs --cache /tmp/vetcode-bench --npm 1000 --pypi 300 --seed 7
node bench/run.mjs --cache /tmp/vetcode-bench --out bench/results
node bench/summary.mjs bench/results
rm -rf /tmp/vetcode-bench
```

`fetch.mjs` refuses to start with less than 5 GB free. Score in parallel with
`--shard i/n` (one process per shard) and combine with `node bench/merge.mjs <out>`.

## Advanced techniques (red team)

```bash
node bench/redteam.mjs            # this build
node bench/redteam.mjs --lib <path to another build>/skills/vetcode/scripts/lib/index.mjs
```

Twelve techniques from 2025–2026 campaigns that the public datasets barely contain (code
pushed off-screen in dist/, GlassWorm Unicode payloads, payloads in images, protestware,
time bombs, sandbox evasion, homoglyphs, disguised executables, purpose mismatch, recon
beacons, ClawHavoc-style skills, skills that hide actions), each next to a clean look-alike.
Samples are generated at run time and carry no working payload. The set was built
alongside the rules, so it measures coverage, not an independent detection rate.
