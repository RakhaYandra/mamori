# Architecture (v0.1.0)

```
CLI (cobra) → auditor.Run → scanner | gitinspect | sshaudit
                          → rules (+ custom) → redact → report
                          → baseline (suppress / update)
```

* `cmd/mamori`: Cobra wiring only, no scan logic.
* `internal/config`: YAML load + strict schema validation.
* `internal/audit`: safe finding model (random ID, stable fingerprint).
* `internal/auditor`: orchestration, severity filter, exit codes.
* `internal/scanner`: walker, secrets (patterns + entropy gate), permissions.
* `internal/gitinspect`: tracked/staged/history via Git CLI allowlist.
* `internal/sshaudit`: Host-aware client config parser + rules.
* `internal/rules`: bundled metadata + user `custom.*` regex (RE2, capped).
* `internal/baseline`: fingerprint-keyed acknowledgements, no evidence stored.
* `internal/hook`: static pre-commit script installer.
* `internal/redact`: single path to every sink. `internal/report`: terminal + JSON.
* Invariants: read-only, no network, no shell interpolation, redaction before render.
