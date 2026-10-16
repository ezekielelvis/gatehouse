# Intentionally vulnerable fixtures

These repositories contain **deliberately planted** security issues (hard-coded
secrets, and in later phases known-vulnerable dependencies and insecure code).
They exist solely as the end-to-end test suite for Gatehouse — a scan must have
something real to find.

**Do not "fix" these findings and do not reuse this code.** The secrets here are
fake/example values.

- `go-vuln/` — a Go module with a hard-coded credential map that Gitleaks'
  `generic-api-key` rule detects.
