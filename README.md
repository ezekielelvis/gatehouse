# Gatehouse

**Local, self-hosted pre-push assurance.** Point Gatehouse at a repository and
get a security, quality, QA and governance verdict *before* code leaves your
machine. Everything runs locally, offline-capable, inside throwaway sandboxes,
and every run leaves a tamper-evident evidence record.

> Status: **Phase 1–3 core complete.** The working engine end to end:
> normalised finding model; diff-aware new/existing/fixed classification; an
> embedded OPA policy gate (baseline + strict-release packs); a SQLite history
> store; a hardened container sandbox; per-repo `gatehouse.yaml`;
> secrets/SAST/SCA tool manifests (Gitleaks, Opengrep, OSV-Scanner, gosec);
> JUnit + lcov adapters (tests and changed-lines coverage feed the gate);
> **CycloneDX SBOM** (Syft) with licence data feeding policy; **compliance
> mapping** (OWASP Top 10, CWE Top 25, ISO 27001, SOC 2, PCI DSS by weakness;
> NIST SSDF & SLSA by process/activity evidence) with Met/Not-met/Manual
> control status; **flaky-test detection and quarantine** from run history; a
> signed evidence trail (Ed25519 attestations, hash-chained audit log, portable
> `.tar.gz` bundle); **SBOM export** in CycloneDX 1.6 and SPDX 2.3; the
> **pre-commit/pre-push git-hook installer**; a CLI; a **local web UI**
> (server-side rendered + htmx, served offline from the binary); and a signed,
> multi-arch **release pipeline** (images + binaries + SBOM + SLSA provenance).
> The roadmap's core is now implemented end to end: 15 scanner/tool manifests
> (secrets, SAST, SCA, SBOM, IaC, containers, CI/CD, lint, mutation); risk
> enrichment from local CVSS/EPSS/KEV mirrors; 7 compliance standards; combined
> SARIF + HTML + SPDX/CycloneDX export; the YAML policy DSL + repo policy layer;
> git-notes attestation with `verify`; retention `gc`; the e2e/services sandbox
> model; and the full local web UI (dashboard, run detail, history, waivers,
> policies, settings). Remaining is polish and the out-of-module VS Code /
> JetBrains extension (plan §12 phase 2).

## Why

- **One binary.** The core is a single static Go binary — daemon, CLI and git
  hook — with no runtime to install.
- **Orchestrator, not monolith.** Each check is a plugin declared by a YAML
  manifest. Adding a tool means adding a manifest, not core code.
- **Everything is a finding.** Lint errors, CVEs, failing tests and policy
  violations share one normalised model, so policies reason across all of them.
- **Policy as code.** Gates are declarative, versioned, testable Rego evaluated
  by embedded [OPA](https://openpolicyagent.org) — no sidecar.
- **Diff-aware.** Findings are classified `new` / `existing` / `fixed` against
  the last run, so the default gate blocks only on *new* issues and stays
  usable on legacy code.
- **Sandboxed by default.** Every check runs against a read-only source snapshot
  with no network, all capabilities dropped and strict resource limits.

## Quick start

```bash
go build -o bin/gatehouse ./cmd/gatehouse

# Scan the working tree (requires Docker or Podman running):
bin/gatehouse scan /path/to/repo

# Only gate on what changed vs a base ref:
bin/gatehouse scan /path/to/repo --diff origin/main

# Validate the built-in policy packs:
bin/gatehouse policy test

# Install the pre-commit + pre-push git hooks (the local gate):
bin/gatehouse hook install

# Map a run onto a compliance standard:
bin/gatehouse compliance <run-id> --standard owasp-top10

# Export the SBOM in either standard:
bin/gatehouse report <run-id> --format spdx       # or: cyclonedx

# Export a signed, portable evidence bundle for a run:
bin/gatehouse report <run-id> --format bundle --out run.tar.gz

# Re-check the tamper-evident audit chain:
bin/gatehouse audit verify

# Browse runs, findings, SBOM and compliance in the local web UI
# (server-side rendered, htmx, binds to 127.0.0.1 only):
bin/gatehouse serve   # http://127.0.0.1:7420
```

### Per-repo configuration

Drop a `gatehouse.yaml` at the repo root to select policy packs, enable/disable
or re-image tools, and declare QA services:

```yaml
policy_packs: [baseline, strict-release]
plugins:
  gosec:   { enabled: false }
  gitleaks: { image: ghcr.io/you/gitleaks@sha256:... }
```

Waive a specific finding (reviewed like any code change) in
`.gatehouse/waivers.yaml` — an expiry date is mandatory:

```yaml
waivers:
  - id: W-1
    fingerprint: 08c9e7d2...        # or: rule + path glob
    reason: accepted risk, tracked in TICKET-42
    owner: you@example.com
    expires: 2026-11-30
```

Docker and Podman are equal citizens — point `DOCKER_HOST` at either engine's
Docker-compatible socket (e.g. rootless Podman:
`DOCKER_HOST=unix:///var/run/docker.sock`). Use your own tool images (or try one
out) with `--plugins <dir>`, a directory of extra manifests appended to the
built-in set.

No container runtime handy? For local development only, add
`--unsafe-host-exec` to run a tool's `host_command` directly on the host with
**no sandbox isolation**. This is never the default and must never be used on
untrusted code.

### Verifying the sandbox (live tests)

The container sandbox is exercised against a real daemon by tests gated on
`GATEHOUSE_LIVE=1`; they confirm read-only `/src`, no network, non-root
execution, and the internal-network services model. Verified on rootless
Podman 6.x:

```bash
GATEHOUSE_LIVE=1 DOCKER_HOST=unix:///var/run/docker.sock \
  go test ./internal/sandbox -run TestPodmanLive -v
```

### Commands

```
gatehouse scan <path> [flags]   Scan a repo and apply the policy gate
gatehouse hook install          Install pre-commit + pre-push git hooks
gatehouse policy test           Validate the built-in policy packs
gatehouse report <run-id>       Render a run: json|sarif|html|bundle|cyclonedx|spdx
gatehouse compliance <run-id>   Map a run onto a standard (--standard)
gatehouse verify <commit>       Verify the signed git-notes attestation
gatehouse audit verify          Re-check the hash-chained evidence log
gatehouse db update --from DIR  Import CVSS/EPSS/KEV mirror feeds
gatehouse gc [--keep N]         Apply run-history retention
gatehouse serve [flags]         Start the local web UI / API
```

### Exit codes

`0` pass · `1` fail (policy denied) · `2` warn-only · `3` tool/infra error —
suitable for a `pre-push` hook.

## Architecture

Gatehouse is one Go process that plans runs, starts hardened containers through
the user's Docker or Podman, collects their outputs and decides. A run is a DAG:

```
detect → snapshot → run plugins (parallel sandboxes) → normalise → diff → policy → persist
```

| Package | Responsibility |
| --- | --- |
| `internal/model` | Normalised data model (Finding, Metric, Run, …) |
| `internal/findings` | SARIF ingest, stable fingerprinting, new/existing/fixed diff |
| `internal/detect` | Language & manifest detection → repo profile |
| `internal/plugins` | Tool manifest loading and selection |
| `internal/sandbox` | Runtime abstraction: hardened Docker/Podman + dev-only host executor |
| `internal/orchestrator` | The run pipeline |
| `internal/policy` | Embedded OPA engine, run-input document |
| `internal/store` | SQLite (pure-Go, WAL) history store |
| `internal/gitx` | Read-only snapshotting and diffing |
| `internal/config` | Per-repo `gatehouse.yaml` (packs, plugin overrides, QA) |
| `internal/adapters` | JUnit → test results, lcov → coverage metrics |
| `internal/waivers` | `.gatehouse/waivers.yaml` with mandatory expiry |
| `internal/evidence` | Ed25519 signing, in-toto/DSSE attestations, audit chain, bundle |
| `internal/standards` | CWE/check → control mapping, Met/Not-met/Manual status |
| `internal/sbom` | CycloneDX 1.6 + SPDX 2.3 SBOM writers (export) |
| `internal/qa` | Flaky-test detection and quarantine from run history |
| `internal/ui` | Server-side-rendered web UI (html/template + htmx, embedded) |
| `policies/packs` | Built-in Rego packs (baseline, strict-release) |
| `plugins/manifests` | Built-in tool manifests (gitleaks, opengrep, osv-scanner, gosec, syft) |
| `standards/` | Mapping data: owasp-top10, cwe-top25, nist-ssdf, slsa, iso-27001, soc2, pci-dss |
| `images/` | Dockerfiles for the core + tool/runner images |

## License

[Apache-2.0](LICENSE). Third-party tools keep their own licenses inside their
own images. Contributions are under the [DCO](https://developercertificate.org/).
