# Mamori 守 — Local Security Auditor

Read-only, local-first security hygiene for Linux developer machines:
secret hints, Git exposure, file permissions, SSH config. No network,
no raw secrets in output.

> Status: **P1 core** — `audit`/`secrets`/`permissions` jalan (secret patterns + entropy gate, permission audit, terminal/JSON report, exit codes). `ssh`/`git`/`report` masih stub (P1-integration).

## Requirements

* Linux, Go 1.27+
* Git CLI (used later for Git inspection)

## Quick Start

```bash
git clone https://github.com/RakhaYandra/mamori
cd mamori
make build
./bin/mamori --help
./bin/mamori version
```

## Commands

`audit` · `secrets` · `permissions` · `ssh` · `git` · `report` ·
`rules list|explain` · `config init` · `version`

Global flags: `--config --severity --format --exclude --no-color --quiet --verbose`.

Exit codes: `0` clean · `1` findings at/above threshold (P1) ·
`2` invalid usage/config · `3` incomplete audit.

## Security

* Read-only by default; never modifies files, permissions, or Git state.
* One redaction layer for every output sink (terminal, JSON, errors).
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
