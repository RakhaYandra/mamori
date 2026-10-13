# Mamori 守 — Local Security Auditor

Read-only, local-first security hygiene for Linux developer machines:
secret hints, Git exposure, file permissions, SSH config. No network,
no raw secrets in output.

> Status: **v0.1.0** — full audit + custom rules + baseline + pre-commit hook.

## Requirements

* Linux, Go 1.27+
* Git CLI (for Git inspection and the pre-commit hook)

## Quick Start

```bash
git clone https://github.com/RakhaYandra/mamori
cd mamori
make build
./bin/mamori audit ~/Projects
./bin/mamori audit . --history
./bin/mamori git . --staged
```

Or grab a release binary (`mamori-linux-amd64`, `mamori-linux-arm64`,
verify with `SHA256SUMS`) and put it on `PATH`.

## Commands

`audit` · `secrets` · `permissions` · `ssh` · `git` · `report` ·
`rules list|explain` · `config init` · `hook install` · `version`

Global flags: `--config --severity --format --exclude --no-color --quiet --verbose`
(`--format terminal|json|sarif`).
`audit`/`secrets`/`git` add `--history --limit`; `audit` adds
`--baseline PATH --update-baseline`.

Exit codes: `0` clean · `1` findings meet the threshold ·
`2` invalid usage/config · `3` incomplete audit.

## Custom rules

Drop YAML files in `~/.config/mamori/rules/`:

```yaml
- id: custom.internal-token
  title: Internal token format
  severity: high
  category: secret
  pattern: 'INT-[A-Za-z0-9]{16}'
  recommendation: Rotate it.
  enabled: true
```

IDs must start with `custom.`; patterns are RE2, capped at 4KB, gated by
the same entropy filter as bundled rules.

## Baseline

```bash
./bin/mamori audit . --update-baseline --baseline .mamori-baseline
./bin/mamori audit . --baseline .mamori-baseline   # known findings hidden
```

The file stores fingerprints (hashes), never evidence or secrets.

## Pre-commit hook

```bash
./bin/mamori hook install   # installs .git/hooks/pre-commit
```

Blocks commits when staged secrets are found. Bypass only with explicit
`git commit --no-verify`.

## CI (SARIF)

```bash
./bin/mamori audit . --format sarif > results.sarif
```

Upload to GitHub code scanning (see `.github/workflows/mamori.yml`).
SARIF carries rule IDs, titles, and relative paths only — never evidence
fragments. Severity maps to `error` (high/critical), `warning` (medium),
`note` (low/info).

## Shell completions & man pages

```bash
./bin/mamori completion bash | sudo tee /usr/share/bash-completion/completions/mamori
./bin/mamori completion zsh > ~/.zfunc/_mamori
man -l docs/man/mamori.1   # or install docs/man/*.1 to a mandir
```

`completion` supports bash, zsh, fish, powershell. Regenerate pages
with `make man`.

## Limitations

* Pattern-based detection: unknown credential formats are missed
  (false negatives); odd-looking strings can match (false positives).
  Findings are hints, not verdicts.
* Entropy is a supporting gate, not a detector on its own.
* History scan defaults to 100 commits; deeper history needs `--limit`.
* JSON reports contain paths and rule metadata — never raw secrets —
  but review them before sharing.
* v0.1 never modifies files, permissions, or Git state (except the files
  `hook install` and `config init` explicitly create).

## Security

* Read-only by default; the audit modifies nothing.
* One redaction layer for every output sink (terminal, JSON, errors);
  verbose mode never bypasses it.
* Structured `os/exec` arg lists only — `make audit` bans shell patterns.
* See [docs/SECURITY.md](docs/SECURITY.md).

## Development

```bash
make build   # ./bin/mamori
make test    # go test ./...
make check   # vet + test + audit + lint
```

## License

MIT — see [LICENSE](LICENSE). Full spec lives in the private `mamori-internal` repo.
