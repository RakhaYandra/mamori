# Architecture (v0.1 bootstrap)

```
CLI (cobra) → audit.Orchestrator → scanner | gitinspect | sshaudit
                                        → rules.Engine → redact → report
```

* `cmd/mamori`: Cobra wiring only, no scan logic.
* `internal/config`: YAML load + strict schema validation.
* P1 adds: `internal/audit`, `internal/scanner`, `internal/gitinspect`,
  `internal/sshaudit`, `internal/rules`, `internal/redact`, `internal/report`.
* Rules: domain logic dependency-free; renderers consume redacted findings only.
* Invariants: read-only, no network, no shell interpolation, redaction before render.
