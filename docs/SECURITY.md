# Security

* Local-first: no telemetry, no uploads, no external connections.
* Read-only: audit never writes files, permissions, or Git state.
* Redaction: raw credential values never enter findings, output, logs, or errors.
  Verbose mode does not bypass redaction.
* Execution: Git via `os/exec` with separate args; `make audit` rejects
  `sh -c`, `/bin/sh`, `os.system`, `eval(` patterns.
* Symlinks are not followed outside the audit target by default.
* JSON reports may contain paths and rule metadata — never raw secrets.
