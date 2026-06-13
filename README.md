# @westbayberry/dg

[![npm version](https://img.shields.io/npm/v/@westbayberry/dg)](https://www.npmjs.com/package/@westbayberry/dg)
[![CI](https://github.com/WestBayBerry/DG_CLI/actions/workflows/ci.yml/badge.svg)](https://github.com/WestBayBerry/DG_CLI/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)

Dependency Guardian is a supply-chain firewall for npm and PyPI. The `dg` CLI
checks a package against the scanner before its code can run, so a malicious
install is blocked before its install scripts execute, not flagged afterward.
It scans published package artifacts from the registry; your source code stays
on your machine.

## Install

```bash
npm install -g @westbayberry/dg
```

Requires Node.js >= 22.14. Installing the package adds only the `dg` binary and
runs no install lifecycle scripts of its own. The published tarball ships an
`npm-shrinkwrap.json`, so every install resolves the exact dependency tree the
release was audited with. Nothing touches your shell until you run `dg setup`.

## Quickstart

Audit the project in the current directory:

```bash
dg scan
```

`dg scan` reads your lockfiles, asks the scanner for a verdict on each
dependency, and opens a full-screen results browser in an interactive terminal
(plain text or machine output otherwise). It installs nothing and runs no
package scripts. Exit code 0 means the project is clean, 2 means a block-level
package was found.

## Verdicts

Every result is one of three states the scanner returns: **PASS** (verified),
**WARN** (flagged, review advised), or **BLOCK** (refused). The exit code
follows the verdict.

**The server is the verdict source.** For registry checks and the install
firewall the scanner returns the verdict and the CLI displays it; the CLI never
derives a verdict from a local score. If the scanner is unreachable, `dg scan`
falls back to local heuristics and marks the report (`scannerUnavailable` in
JSON output) rather than passing silently.

## The install firewall

Prefix any install command with `dg` and the package is checked before its
bytes reach your package manager:

```bash
dg npm install lodash
dg pnpm add react
dg pip install requests
dg cargo add serde
```

The prefix starts a local proxy for just that command, hashes each artifact as
it downloads, asks the scanner for a verdict, and refuses a blocked package
before delivery. Supported prefixes include npm, npx, pnpm, pnpx, Yarn classic,
pip, pipx, uv, uvx, and cargo. A block exits 2 and prints the override command;
a warn prompts `Proceed? [y/N]` (default No) in a terminal.

To protect bare commands too, run `dg setup`. It shows one consent screen
listing exactly what it writes, then installs reversible, user-local shims so
plain `npm install` and `pip install` are scanned automatically, plus a native
hook in each AI coding agent it detects. Undo all of it with `dg uninstall`.

## Command reference

Run `dg <command> --help` for full flags and examples, or `dg --help-all` for
the complete list. The exhaustive reference lives at
[westbayberry.com/docs/cli-reference](https://westbayberry.com/docs/cli-reference).

### dg scan [path]

Audits the project's lockfiles for the path (current directory by default).
Read-only: it never installs, runs package scripts, or changes setup state.
Reads `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`,
`pnpm-lock.yaml`, `requirements.txt`, `poetry.lock`, `Pipfile.lock`, and
`uv.lock`, including nested projects in a monorepo.

- Flags: `--staged`, `--json`, `--sarif`, `--output <file>`, `--no-decisions`.
- Exit codes: 0 pass, 1 warn (strict mode upgrades warn to 2), 2 block,
  4 analysis incomplete, 10 nothing to scan. JSON output carries a
  `schemaVersion` field and sets `scannerUnavailable` when the scanner could
  not be reached.

### dg sbom [path]

Inventories the resolved dependency tree as a CycloneDX 1.5 software bill of
materials, with purl, license, and integrity hash per component. Reads the same
lockfiles as `dg scan` plus `Cargo.lock`. In a terminal it streams
BLOCK/WARN/PASS verdicts for npm and PyPI components when signed in; cargo stays
inventory only. Piped, with `--output` (alias `-o`), or with `--json` it stays
offline and prints the raw CycloneDX document.

- Flags: `--output <path>` / `-o`, `--json`, `--reproducible` (byte-stable
  output; honors `SOURCE_DATE_EPOCH`).

### dg verify &lt;registry:package[@version] | path | lockfile&gt;

Runs a real scanner check on a published package before you install it. Name
the registry, `npm:react` or `pypi:requests`, with an optional `@version`
(latest by default). Works signed out with a free verdict summary (the verdict,
top reasons, provenance, and the package page link); signing in unlocks the
full reason list, license info, `--json`, and `--output`. Verifying a local
path, lockfile, or tarball stays free and offline.

### dg licenses [path]

SPDX license report for the dependency tree, grouped by risk. Use `--csv` or
`--markdown` for CI artifacts and `--fail-on <risk>[,<risk>]` to exit non-zero
when a dependency carries a named license-risk tier.

### dg audit [path]

Pre-publish check of a package of your own.
Inspects exactly the resolved publish set of one package, never the whole repo.
Basic checks run 100% locally and upload nothing: leaked secrets and keys,
credential files, source maps, `.git`, terraform state, risky lifecycle
scripts, and a missing `files` allowlist. On a paid plan, and if your org allows
it, it also runs a deep behavioral scan: a packed copy is uploaded with no
lifecycle scripts run, raw bytes are never retained, and only the verdict and
redacted findings reach your dashboard.

- Flags: `--local` (skip the upload), `--require-deep` (fail when deep can't
  run), `--fail-on warn`.
- Exit codes: 0 clean, 1 warn (with `--fail-on warn`), 2 block, 3 deep required
  but unavailable, 4 analysis incomplete.

### dg setup

Installs the shell shims so bare `npm install` / `pip install` are scanned, and
the agent hooks, behind one consent screen. `--print` previews the exact write
plan and changes nothing; `--yes` applies just the shell shims non-interactively
(add `--agents` or `--guard-commit` for the others). Everything it writes is
dg-owned and reversible with `dg uninstall`.

### dg guard-commit

Installs a per-repo git pre-commit hook that scans the staged lockfile changes
and blocks a commit that would add a malicious dependency. It chains any
existing pre-commit hook and self-checks that git will fire it. Reverse with
`dg guard-commit off`. `git commit --no-verify` is the override.

### dg agents

Routes AI coding agents' installs through the firewall with a native
pre-command hook in each agent's own config, so a malicious or unresolvable
package is blocked before it is fetched. Supported: Claude Code, Codex CLI,
Cursor, Gemini CLI, GitHub Copilot CLI, and Windsurf. Bare `dg agents` lists
each agent and whether it is protected; `dg agents on` hooks every detected
agent (or one, `dg agents on claude-code`); `dg agents --check` verifies the
wiring; `dg agents off` removes it. `dg hook claude-code` keeps working as an
alias.

### dg decisions &lt;list | revoke&gt;

Warn-level findings you accept at an install prompt or commit guard can be
remembered in a committable `dg.json` at the project root, so repeat runs only
surface new problems. A new finding category, a severity escalation, or a block
always resurfaces; blocks can never be acknowledged away. `dg decisions list`
shows what the project accepted; `dg decisions revoke` removes an entry.

### dg cooldown [&lt;age&gt; | off]

Quarantines new installs of a registry release younger than `cooldown.age`
(default `24h`), since most malicious releases are caught within their first
day. Change it with `dg cooldown 7d` or disable it with `dg cooldown off`.
Lockfile scans are never failed by cooldown; packages you already depend on get
a display annotation only. `dg cooldown exempt <name>` records a shareable
exemption in `dg.json`.

### dg config &lt;get | set | unset | list&gt;

Views or edits user-global configuration in `~/.dg/config.json`. The everyday
key is `policy.mode` (`off`, `warn`, `block` the default, or `strict`), which
sets how a flagged package is handled. There is no detection-tuning knob;
`policy.mode` changes only how a flagged package is handled, not what the
scanner looks for.

### dg login / dg logout --yes

`dg login` signs in via your browser and links this machine to your account;
`dg login --token dg_live_...` authenticates CI without the browser flow.
Scanning works without an account. `dg logout --yes` removes the saved token
from this machine (the token stays valid until you revoke it from the
dashboard).

### dg doctor

Checks runtime, auth, API, policy, setup shims, PATH precedence, real-binary
resolution, stale state, and service state. Every non-pass line ends with the
exact fix command. `--json` for machine output.

### dg service

Service mode runs a persistent local proxy plus a managed certificate authority
so installs are scanned continuously, for CI runners and private registries
where a per-command proxy is not enough. A paid feature; run `dg login` first,
then `dg service start`. Fully reversible with `dg uninstall --service`.

### dg update

Checks whether a newer CLI version is published and prints the exact
`npm install -g` command to run. It never installs anything and never mutates
the installed package; you run the printed command yourself. Alias: `dg upgrade`.

### dg uninstall

Removes registered dg-owned setup and service writes, state, cache, sessions,
shims, and shell-rc sentinel blocks while preserving unrelated user content.
Run it before `npm uninstall -g @westbayberry/dg`.

## Exit codes

Stable, so CI and shells can read them directly:

| Code | Meaning |
| --- | --- |
| `0` | Clean. The requested action is allowed. |
| `1` | Warn-level result (strict policy upgrades this to `2`). |
| `2` | Block: a block-level package, a denied install, or an unknown command. |
| `3` | `dg audit --require-deep` ran but the deep scan was unavailable. |
| `4` | Analysis incomplete; not a clean pass. |
| `10` | `dg scan` found nothing to scan. |
| `64` | A usage error (bad flags or arguments). |
| `69` | A command unavailable or gated on this platform, or a signed-out `dg verify` asking for `--json`/`--output`. |
| `70` | Internal tool error (for example, a report file could not be written). |
| `130` / `143` | Interrupted by SIGINT (Ctrl-C) or SIGTERM. |

## What dg sends to the API

The CLI sends no telemetry: no crash reporter and no analytics endpoint. It
talks to the network only when a command needs it.

- **Scanning** sends package names and pinned versions from your lockfiles to
  the scan API, which pulls the actual package artifacts from the public
  registry on its side. Your source never leaves your machine.
- **The install firewall** asks the server for a verdict on each artifact as it
  downloads: name, version, ecosystem, registry host, download URL, and the
  artifact's SHA-256.
- **Deep audit** (`dg audit`, opt-in, paid) uploads a packed copy of your own
  package to `/v1/scan-tarball`; raw bytes are never retained.
- **Version check** queries the public npm registry for `@westbayberry/dg` at
  most once a day in an interactive terminal. Set `CI=1` to skip it.

Authenticate CI with `DG_API_KEY` (a `dg_live_*` or `dg_test_*` key;
`DG_API_TOKEN` is an accepted alias). Full detail:
[westbayberry.com/docs/telemetry](https://westbayberry.com/docs/telemetry).

## Use in CI

```bash
npm install -g @westbayberry/dg
export DG_API_KEY="dg_live_..."   # from Settings -> CI keys
dg scan
```

A non-zero exit means a block-level finding; wire that into your pipeline's
pass/fail. The CLI auto-detects CI and switches to non-interactive output; pass
`--json` or `--sarif` when a parser reads stdout. On GitHub, the
[GitHub App](https://westbayberry.com/docs#github-app) is the simpler path and
posts a required PR status check.

## Documentation

- [Getting started](https://westbayberry.com/docs)
- [CLI reference](https://westbayberry.com/docs/cli-reference)
- [Blocking behavior](https://westbayberry.com/docs/blocking)
- [Integrations](https://westbayberry.com/docs/integrations)
- [Telemetry](https://westbayberry.com/docs/telemetry)

## Reporting a vulnerability

Please report security issues privately through GitHub's
[private vulnerability reporting](https://github.com/WestBayBerry/DG_CLI/security/advisories/new)
rather than a public issue.

## License

Apache-2.0. See [LICENSE](./LICENSE). Issues and pull requests are welcome at
[github.com/WestBayBerry/DG_CLI](https://github.com/WestBayBerry/DG_CLI).
