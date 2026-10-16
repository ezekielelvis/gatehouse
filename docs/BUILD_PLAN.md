# Local Code Assurance Platform — Build Plan

Oct 15, 2026 · @Amartey Ezekiel

## 1. Vision, goals and principles

Build an open-source, self-hosted "pre-push assurance" platform — working name **Gatehouse** — that a developer installs with one `docker compose up` or `podman play kube`, points at a local repository or branch, and gets a full security, quality, QA and governance verdict before code ever leaves their machine. Everything runs locally, offline-capable, inside throwaway sandboxes, and every run leaves a tamper-evident evidence record.

**Goals**

- One command to install; one click (web UI) or one command (CLI / git hook) to scan.
- Scan a working tree, a branch, a commit range, or just the diff against a base branch.
- Cover four layers in one run: code quality, security, QA testing, governance/policy.
- Run every third-party scanner and every test suite inside an isolated, network-restricted container.
- Let users write their own policies (and import shared policy packs) without recompiling anything.
- Keep a durable, queryable history of runs, findings, test results, SBOMs and policy decisions.
- Map findings to recognised standards (OWASP, CWE, NIST SSDF, SLSA, etc.) so output is audit-usable.
- Be fast and light: a single static binary for the core, sub-second UI, idle memory under \~50 MB.

**Non-goals (v1)**

- No cloud service, no telemetry by default, no account system, no SaaS backend.
- Not a replacement for a CI server; it is the local gate that runs *before* CI.
- No dynamic scanning of production systems — only the code and what can be built and run locally.
- Not reinventing scanners: Gatehouse orchestrates proven open-source tools and normalises their output.

**Design principles**

1. **Local-first, zero egress by default.** Network is off inside scan sandboxes unless a step explicitly needs it (e.g. dependency install) and the user allows it.
2. **Read-only source.** The user's repo is never modified; scans work on a snapshot.
3. **Orchestrator, not monolith.** Each check is a plugin defined by a manifest; adding a tool means adding a manifest, not core code.
4. **Everything is a finding.** Lint errors, CVEs, failing tests and policy violations share one normalised model, so policies can reason across all of them.
5. **Policy as code.** Gates are declarative, versioned, testable files that live in the repo or a shared pack.
6. **Evidence by default.** Every run is reproducible and signed: inputs, tool versions, outputs, verdict.
7. **Docker and Podman are equal citizens**, including rootless Podman.

## 2. Language and tech stack

**Write the core in Go.** It compiles to one static binary with no runtime, starts in milliseconds, idles at tens of MB, cross-compiles to Linux/macOS/Windows on amd64 and arm64, and has first-class concurrency for running many scanners in parallel. Decisively, most of the tools you will orchestrate are themselves Go (Gitleaks, TruffleHog, OSV-Scanner, Syft, Grype, Trivy, gosec), and the policy engine you want — Open Policy Agent — is a Go library you can embed directly with no sidecar. Rust is the faster-at-the-limit alternative, but the bottleneck here is the scanners, not the orchestrator, so Go's ecosystem fit and build speed win.

On "polyglot": the *app* should be one language; the *scanning* is polyglot. Gatehouse detects every language in a repo and runs the right toolchain for each inside its own container image, so Go, Python, JS/TS, Java, C#, Rust, PHP, Ruby, C/C++ and IaC are all covered without the core knowing their details.

| Layer | Choice | Why |
| --- | --- | --- |
| Core daemon + CLI | Go 1.26+, single binary `gatehouse` (subcommands `serve`, `scan`, `hook`, `policy`) | Static, tiny, fast, same code for UI and CLI |
| HTTP API | Go `net/http` + chi router, OpenAPI 3.1 spec, JSON | Standard library first; the spec generates clients |
| Live progress | Server-Sent Events (SSE) | Simpler than WebSockets, one-way log/progress streaming |
| Web UI | templ (Go-typed HTML) + htmx + a little Alpine.js, embedded with `go:embed` | No Node runtime, no SPA build in the hot path, whole UI ships inside the binary |
| Charts in UI | Apache ECharts or uPlot (vendored, served locally) | Works offline |
| Database | SQLite in WAL mode via `modernc.org/sqlite` (pure Go, no cgo) | Zero-ops, single file, fast enough for millions of findings |
| Artifact store | Content-addressed blobs on disk (`sha256/ab/cd…`) | Dedupes SBOMs, logs and reports; easy to export |
| Container runtime | Docker Engine API, used against Docker *or* Podman's Docker-compatible socket | One code path for both runtimes |
| Policy engine | OPA embedded via `github.com/open-policy-agent/opa/v1/rego` (Rego v1) | Industry-standard policy-as-code, testable, no extra process |
| Simple rules | YAML rule DSL compiled to Rego | Lets non-experts write gates without learning Rego |
| Finding format | SARIF 2.1.0 in, normalised internal model, SARIF/JSON/HTML/PDF out | SARIF is what IDEs, GitHub and most scanners speak |
| SBOM | CycloneDX 1.6 (primary), SPDX 2.3/3.0 export | Both are the recognised standards |
| Vulnerability data | OSV database, mirrored locally | Offline, open, multi-ecosystem |
| Signing / attestations | in-toto attestations, signed with a local key via sigstore-go | Tamper-evident evidence without a server |
| Config | One `gatehouse.yaml` per repo + a global config | Repo-level policy travels with the code |
| Logging | `log/slog` structured JSON | Standard library |

OPA is actively maintained and its Go SDK and `v1/rego` package are the documented way to embed it as a library ([OPA integration docs](https://openpolicyagent.org/docs/integration)).

## 3. System architecture

Gatehouse is one Go process that plans runs, starts hardened containers through the user's Docker or Podman, collects their outputs, and decides. No scanner, build or test ever runs inside the core process.

&#91;embedded content: system architecture · core, runtime, sandboxes\]

**A run, end to end**

1. The UI, CLI or a git hook calls the API with a repo, a ref (or diff base) and a gate profile.
2. The orchestrator snapshots the code, detects languages and manifests, and builds a DAG of steps from the matching plugin manifests.
3. An optional *prepare* step installs dependencies through the egress proxy; every other step runs with no network.
4. Steps run in parallel sandboxes; each writes results to its own `/out` volume.
5. Adapters normalise outputs into findings, metrics and test results; findings are fingerprinted and diffed against the base branch's last run.
6. Enrichment adds CVSS, EPSS, KEV and standards mappings from local mirrors.
7. The policy engine evaluates the run document and returns pass, warn or fail with messages.
8. Evidence is signed and stored; the UI updates live over SSE and the hook exits with the right code.

## 4. Sandboxed execution model

Every check runs in a fresh, locked-down container against a read-only snapshot of the code; nothing a scanner or a test does can touch the user's repo, home directory, network or container runtime. The sandbox is the product's core promise, so build it first and test it hardest.

**Step 1 — Snapshot the code**

- *Branch / commit / range:* `git worktree add --detach` (or `git archive <ref>`) into `~/.gatehouse/runs/<run-id>/src`.
- *Working tree incl. uncommitted changes:* copy tracked + untracked-but-not-ignored files (`git ls-files -co --exclude-standard`).
- *Diff mode:* also record the changed file list and hunks so scanners can be told to report only on changed lines.
- Record the snapshot's tree hash; it becomes part of the run's evidence.

**Step 2 — Run each check in its own container**

| Control | Setting | Purpose |
| --- | --- | --- |
| Source mount | `/src` read-only bind mount | Scanners cannot modify code |
| Output mount | `/out` per-step writable volume | Only place results can be written |
| Root filesystem | `--read-only`, `/tmp` as tmpfs | No persistence inside the image |
| Network | `--network=none` by default | No exfiltration, no surprise downloads |
| Privileges | `--cap-drop=ALL`, `--security-opt no-new-privileges`, non-root UID | Least privilege |
| Syscalls | Runtime default seccomp + AppArmor/SELinux label | Kernel attack-surface reduction |
| Resources | `--memory`, `--cpus`, `--pids-limit`, wall-clock timeout | Stops runaway tests, fork bombs, crypto-miners |
| Runtime socket | Never mounted into scanner containers | A scanned repo can never control the host runtime |
| Stronger isolation | Use gVisor (`runsc`) or Kata if installed | Optional VM-grade isolation for untrusted repos |
| Images | Pinned by digest, signature verified before first use | Supply-chain safety (see section 14) |

**Step 3 — Controlled network only when needed**

Tests and builds often need dependencies. Split them into two phases:

1. **Prepare** (opt-in network): install dependencies through Gatehouse's own egress proxy, which allows only the registries the user approves (npmjs, PyPI, Maven Central, proxy.golang.org, crates.io, a private mirror). Dependencies land in a per-repo cache volume.
2. **Execute** (no network): run builds, tests and scanners with the cache mounted read-only and the network off. Integration tests that need a database get a private internal network with only the service containers attached.

The prepare step's lockfile hash is recorded, so a reused cache is provably the same dependency set.

**Step 4 — Collect and tear down**

Copy `/out`, stdout/stderr and exit codes into the artifact store, then remove containers, the worktree and scratch volumes. Keep the dependency cache (keyed by lockfile hash) for speed.

**Where the core itself runs**

- *Recommended:* the `gatehouse` binary runs on the host and talks to the user's Docker or rootless-Podman socket. Simplest and most transparent.
- *Containerised:* the core runs in a container with the runtime socket mounted. Convenient, but that socket is host-root-equivalent on rootful Docker, so document it clearly and recommend rootless Podman or Docker rootless mode for this setup.

## 5. Code quality pipeline

Gatehouse first fingerprints the repo, then runs only the analyzers that apply, preferring the repo's own configuration (an existing `.eslintrc`, `ruff.toml`, `.golangci.yml`) over Gatehouse defaults so results match what the team already expects.

**Detection.** Use `go-enry` (a Go port of GitHub Linguist) for languages, plus manifest detection (`go.mod`, `package.json`, `pyproject.toml`, `pom.xml`, `Cargo.toml`, `*.csproj`, `Dockerfile`, `*.tf`, Helm charts, k8s YAML, GitHub/GitLab CI files). The result is a *repo profile* stored with the run and used to pick plugins.

**Analyzer matrix (defaults, all swappable)**

| Ecosystem | Lint | Format check | Type / build check | Tests + coverage |
| --- | --- | --- | --- | --- |
| Go | golangci-lint | gofmt / gofumpt | `go vet`, `go build` | `go test -race -coverprofile` |
| Python | Ruff | Ruff format / Black | mypy or Pyright | pytest + coverage.py |
| JS / TS | ESLint, Biome | Prettier / Biome | `tsc --noEmit` | Jest / Vitest + Istanbul (lcov) |
| Java / Kotlin | Checkstyle, PMD, SpotBugs, detekt | google-java-format, ktlint | Maven / Gradle compile | JUnit + JaCoCo |
| C# / .NET | Roslyn analyzers | `dotnet format --verify-no-changes` | `dotnet build` | `dotnet test` + Coverlet |
| Rust | Clippy | `cargo fmt --check` | `cargo check` | `cargo test` + cargo-llvm-cov |
| PHP | PHPStan / Psalm, PHP\_CodeSniffer | PHP-CS-Fixer | — | PHPUnit |
| Ruby | RuboCop | RuboCop | Sorbet (optional) | RSpec + SimpleCov |
| C / C++ | clang-tidy, cppcheck | clang-format | build via CMake | CTest + gcov/llvm-cov |
| Shell | ShellCheck | shfmt | — | bats (optional) |
| Dockerfile | Hadolint | — | — | — |
| YAML / JSON / Markdown | yamllint, markdownlint | Prettier | schema validation | — |

**Cross-language quality checks**

- Cyclomatic complexity and long functions: Lizard (supports \~20 languages).
- Duplication: PMD CPD.
- Dead code / unused dependencies: language-specific (knip for JS, deadcode for Go, vulture for Python).
- Commit hygiene: commitlint (Conventional Commits), signed-commit check, large-file and binary-blob detection.
- Repo hygiene: README, LICENSE, CODEOWNERS, SECURITY.md, `.editorconfig` presence.

**Normalisation.** Every tool's output (SARIF where supported, otherwise JSON/XML/lcov/Cobertura/JaCoCo) is converted by a small adapter into the common Finding and Metric models (section 15). Coverage from any format becomes one metric set: line, branch, and changed-lines coverage.

**Plugin manifest.** Each analyzer is declared, not coded:

```yaml
id: ruff
version: "0.x"
image: ghcr.io/gatehouse/ruff@sha256:<digest>
applies_when: { languages: [Python] }
category: [lint, format]
network: none
command: ["ruff", "check", "/src", "--output-format=sarif", "-o", "/out/ruff.sarif"]
outputs: [{ path: /out/ruff.sarif, format: sarif }]
timeout: 5m
respects_repo_config: [ruff.toml, pyproject.toml]
```

New tools are added by contributing a manifest and, if the tool lacks SARIF, an adapter.

## 6. Security scanning catalogue

A full security run covers 12 check families, all of which can run locally and offline once the vulnerability databases are mirrored. Each family is a set of plugins; users can disable, swap or add tools per repo.

| # | Check family | What it finds | Default tools (open source) |
| --- | --- | --- | --- |
| 1 | SAST (pattern + taint) | Injection, XSS, path traversal, SSRF, insecure deserialisation, weak crypto, hard-coded config | [Opengrep](https://github.com/opengrep/opengrep) with Semgrep-format rules |
| 2 | Language-specific SAST | Deeper idiomatic issues per language | gosec, Bandit, Brakeman, SpotBugs + FindSecBugs, ESLint security plugins, Roslyn security analyzers, cppcheck/Flawfinder |
| 3 | Secrets — working tree | API keys, tokens, private keys, passwords, `.env` files | Gitleaks, TruffleHog (verification off by default — it calls providers) |
| 4 | Secrets — git history | Secrets committed then "deleted" in older commits on the branch | Gitleaks `git` mode over the scanned range |
| 5 | Dependency vulnerabilities (SCA) | Known CVEs/GHSAs in direct and transitive dependencies | OSV-Scanner (offline DB), Grype; govulncheck for Go reachability |
| 6 | Malicious packages | Typosquats and known-malicious package versions | OSV `MAL-` advisories, GuardDog heuristics for npm/PyPI |
| 7 | SBOM | Full inventory of components, versions, hashes, licences | Syft → CycloneDX 1.6 and SPDX |
| 8 | Licence compliance | Copyleft or forbidden licences, missing licence info | SBOM licence data + policy; ScanCode Toolkit for deep scans (optional, slow) |
| 9 | Infrastructure as Code | Misconfigured Terraform, CloudFormation, Kubernetes, Helm, Ansible, Docker Compose | Checkov, Trivy `config`, kube-linter, Kubescape |
| 10 | Containers | Dockerfile anti-patterns; CVEs and CIS issues in images built from the repo | Hadolint; build in sandbox with BuildKit/Buildah rootless, then Grype/Trivy + Dockle |
| 11 | CI/CD pipeline security | Script injection in workflows, unpinned actions, over-broad tokens, dangerous triggers | zizmor, actionlint, poutine |
| 12 | Repo posture & commit integrity | Unsigned commits, missing branch-protection files, no SECURITY.md, binaries in repo | Built-in checks modelled on OpenSSF Scorecard's local checks |

**Optional, heavier checks** (off by default, enabled per repo):

- **CodeQL** for deep semantic analysis — the CLI's licence limits free use to open-source and research code, so Gatehouse must ask users to supply it themselves rather than bundle it.
- **Local DAST:** start the app in the sandbox on an internal network and run an OWASP ZAP baseline scan against it. Nothing leaves the machine.
- **Fuzzing** (see section 8).

**Prioritisation.** Every vulnerability finding is enriched from locally mirrored feeds: CVSS v3.1/v4.0 base score, EPSS exploit probability, CISA KEV "known exploited" flag, fix version availability, and reachability where the tool provides it (govulncheck, OSV-Scanner call analysis). The UI sorts by *risk*, not raw count.

**Diff-aware results.** In branch or pre-push mode, each finding is tagged `new`, `existing` or `fixed` by comparing to the base branch's last run (matched by a stable fingerprint: rule + file + normalised code snippet). Default gates only block on *new* issues, which is what makes the tool usable on legacy code.

**Licensing note.** Opengrep is an LGPL-2.1 community fork of Semgrep CE that restores features Semgrep moved to its commercial tier and stays compatible with Semgrep rules, JSON and SARIF ([AppSec Santa](https://appsecsanta.com/opengrep-vs-semgrep)). Run every third-party tool as a separate container image rather than linking it into the Gatehouse binary; that keeps Gatehouse's own licence (Apache-2.0 recommended) clean. Check each rule pack's licence before bundling it — some vendor rule registries restrict redistribution.

## 7. Cybersecurity standards mapping

Gatehouse cannot make a team "compliant", but it can produce mapped, signed evidence for the code-level controls in each standard. The mechanism is simple: every finding carries CWE IDs (most scanners emit them in SARIF), and versioned mapping files translate CWE and check IDs into standard controls.

| Standard | What Gatehouse maps to it | Evidence produced |
| --- | --- | --- |
| OWASP Top 10 (current edition) | SAST, SCA, secrets, IaC findings via CWE → category mapping | Findings grouped by category, trend per run |
| OWASP ASVS 5.0 | Code-verifiable requirements (input validation, crypto, secrets, error handling) | Per-requirement pass/fail where automatable; "manual" flag otherwise |
| CWE Top 25 | Direct CWE match on findings | Count and list per weakness |
| NIST SSDF (SP 800-218) | PW.7 code review/analysis, PW.8 testing, PS.3 provenance, RV.1 vulnerability identification | Practice-level checklist with linked runs |
| SLSA (build track) | Local build provenance for artifacts built in the sandbox | in-toto/SLSA provenance attestation |
| OpenSSF Scorecard | Locally checkable items: pinned dependencies, dangerous workflows, binary artifacts, security policy, signed commits | Scorecard-style score card |
| CIS Benchmarks (Docker, Kubernetes) | Dockle, Kubescape and Checkov checks | Benchmark item pass/fail |
| ISO/IEC 27001:2022 Annex A | 8.25 secure development lifecycle, 8.28 secure coding, 8.29 security testing | Control → run evidence report |
| SOC 2 (TSC) | CC7.1 vulnerability detection, CC8.1 change management | Per-change evidence that gates ran and passed |
| PCI DSS v4.0.1 | Req. 6.2.x secure software development, 6.3.x vulnerability identification | Evidence pack per release branch |
| EU Cyber Resilience Act | SBOM and known-vulnerability handling for products sold in the EU | CycloneDX SBOM + vulnerability report per release |
| Privacy laws (GDPR, Ghana Data Protection Act 2012) | PII patterns in code, fixtures, logs and test data | PII findings with file locations |

**Implementation**

- Ship mappings as data in `standards/<name>/<version>.yaml` so they can be updated without a code release and reviewed by the community.
- Each mapping lists control ID, title, automatable (yes/partial/no), and the check IDs or CWE IDs that provide evidence.
- The UI's *Compliance* view shows each control as Met / Not met / Manual / Not applicable, with links to the exact findings and runs behind it.
- Exported compliance reports state plainly which controls need human attestation — overstating automated coverage is the fastest way to lose auditor trust.

## 8. QA testing layer

QA in Gatehouse means three things: run the project's own test suites reliably in the sandbox, add test types teams usually skip (contract, mutation, fuzz, accessibility, performance smoke), and measure the *quality of the tests themselves* over time. JUnit XML is the common result format; almost every framework can emit it.

**Test types and how each runs**

| QA type | How Gatehouse runs it | Default tools | Default mode |
| --- | --- | --- | --- |
| Unit tests | Detected framework, run in execute phase, JUnit XML + coverage parsed | Framework-native (section 5) | On every scan |
| Integration tests | `services:` block in `gatehouse.yaml` starts Postgres/Redis/etc. on a private network | Official service images | On every scan if declared |
| End-to-end / UI | App started in sandbox, browser tests run against it; traces, screenshots, videos stored | Playwright, Cypress | On demand / pre-release |
| API contract | Property-based tests generated from the OpenAPI/GraphQL schema; consumer contracts verified | Schemathesis, Pact | On demand |
| Mutation testing | Mutates changed code only, reports mutation score | Stryker (JS/TS, C#), PIT (Java), mutmut (Python), cargo-mutants (Rust), Gremlins (Go) | Weekly / pre-release |
| Fuzzing | Time-boxed (e.g. 60 s per target) native fuzz targets; crashes saved as artifacts | Go fuzzing, cargo-fuzz, Atheris, Jazzer | Opt-in |
| Performance smoke | Benchmarks and a short load test vs. stored baseline; fail on regression above a threshold | `go test -bench` + benchstat, k6, hyperfine | Opt-in |
| Accessibility | Pages from e2e runs checked against WCAG 2.2 AA rules | axe-core via Playwright, Pa11y | With e2e |
| Manual / exploratory | Release checklists with named sign-off stored as evidence | Built-in checklist feature | Pre-release |

**Making tests trustworthy**

- **Flaky-test detection:** failing tests are retried up to N times; a test that passes on retry is marked *flaky*. Per-test pass history gives a flakiness score, and policies can quarantine known-flaky tests instead of blocking pushes.
- **Test impact analysis:** per-test coverage from earlier runs maps files to tests, so pre-push mode runs only tests touching changed files, with a full run on demand or nightly.
- **Changed-lines coverage:** the gate that matters is "new code is tested" (e.g. ≥ 80% of changed lines), not total coverage.
- **Test suite health metrics** per run: count, duration, slowest tests, flake rate, mutation score, coverage trend.

**Integration tests and Testcontainers.** Libraries like Testcontainers need a container runtime socket inside the test container, which breaks the sandbox model. Default: declared `services:` only. Advanced: a "trusted repo" mode that gives tests a nested rootless Podman, never the host socket.

**Example `gatehouse.yaml` QA block**

```yaml
qa:
  services:
    postgres: { image: postgres:17, env: { POSTGRES_PASSWORD: test } }
  e2e:
    start: "npm run start"
    wait_for: http://app:3000/health
    run: "npx playwright test --reporter=junit"
  mutation: { enabled: true, scope: changed }
  flaky: { retries: 2, quarantine_after: 3 }
```

## 9. Governance and custom policy engine

Every run ends with a policy decision — **pass**, **warn** or **fail** — computed by embedded OPA over one JSON document describing the whole run. Policies are files: versioned, reviewable in pull requests, unit-testable, and shareable as packs.

**The policy input** (one document per run): repo profile, branch and base, git metadata (authors, signatures, changed files), all normalised findings with `new/existing/fixed` status, metrics (coverage, complexity, duplication), test results, SBOM components and licences, active waivers, and the gate context (`pre-commit`, `pre-push`, `release`).

**Policy layers (later layers can tighten; loosening requires the earlier layer to allow it)**

1. *Built-in baseline* shipped with Gatehouse.
2. *Shared / organisation packs* from a git URL or folder, optionally signed bundles.
3. *Repo policies* in `.gatehouse/policies/` — travel with the code.
4. *Local user overrides* — only for rules not marked `locked: true` upstream.

**Shipped packs:** `baseline` (no secrets, no critical CVEs, tests pass), `owasp-top10`, `strict-release`, `oss-library` (licence + SBOM + signed commits), `pci-ready`, `iac-hardening`.

**Two ways to write custom policies**

*Simple rules (YAML DSL, compiled to Rego):*

```yaml
rules:
  - id: no-new-high-vulns
    when: { context: [pre-push, release] }
    deny_if: findings.where(type == "vulnerability" and status == "new" and severity >= "high").count > 0
    message: "New high/critical vulnerable dependency: fix or waive with expiry"
  - id: changed-lines-coverage
    warn_if: metrics.coverage.changed_lines < 80
  - id: forbidden-licences
    deny_if: sbom.components.any(licence in ["AGPL-3.0-only", "SSPL-1.0"])
```

*Full Rego for anything complex:*

```rego
package gatehouse.gates

import rego.v1

deny contains msg if {
  input.context == "release"
  some f in input.findings
  f.type == "secret"
  msg := sprintf("Secret %s in %s:%d blocks release", [f.rule_id, f.path, f.line])
}

deny contains msg if {
  some t in input.tests.failed
  not t.quarantined
  msg := sprintf("Test failing: %s", [t.name])
}
```

**Policy authoring in the UI:** editor with syntax checking, "dry-run against last run" to preview the decision, policy unit tests (`opa test`) run on save, and a library view of all active rules with their source layer.

**Waivers (exceptions)**

- A waiver targets one finding fingerprint (or a rule + path glob), with a reason, owner, and **mandatory expiry date**.
- Stored in `.gatehouse/waivers.yaml` inside the repo, so they go through normal code review.
- Expired waivers automatically stop applying; policies can cap waiver duration by severity (e.g. critical ≤ 14 days).
- Optional: require waivers to be added in a commit signed by someone listed in CODEOWNERS — verifiable locally.

**Remediation SLAs:** policies can turn age into a gate, e.g. an *existing* critical finding older than 7 days becomes blocking. This is how governance handles legacy debt without blocking every push on day one.

**Gate profiles**

| Context | Target time | What runs | Typical blocking rules |
| --- | --- | --- | --- |
| pre-commit | < 10 s | Secrets, format, fast lint on staged files | Any secret |
| pre-push | < 2–3 min | Diff-scoped SAST, SCA, IaC, affected tests | New high/critical findings, failing tests |
| release | No limit | Everything incl. SBOM, mutation, e2e, checklists | Full pack + signed evidence bundle |

**Audit trail:** each decision records the policy bundle hash, the input hash, and the result, appended to a hash-chained local audit log (section 10).

## 10. Results, evidence and records

Each run produces an immutable, signed **evidence bundle** that can prove later exactly what was scanned, with which tools and policies, and what was decided. The database is for fast querying; the bundle is the record of truth.

**What is stored per run**

| Record | Format | Kept in |
| --- | --- | --- |
| Run manifest: repo path, ref, tree hash, diff base, context, timestamps, host OS, runtime | JSON | SQLite + bundle |
| Tool inventory: each plugin's name, version, image digest, command, exit code, duration | JSON | SQLite + bundle |
| Raw tool outputs | Native (SARIF, JUnit XML, lcov, JSON) | Blob store |
| Normalised findings and metrics | Internal schema | SQLite |
| Combined report | SARIF 2.1.0 | Blob store + bundle |
| SBOM | CycloneDX 1.6 JSON (+ SPDX on export) | Blob store + bundle |
| Test artifacts | JUnit XML, coverage, Playwright traces, screenshots, fuzz crashers | Blob store |
| Logs | stdout/stderr per step, compressed | Blob store |
| Policy decision: bundle hash, input hash, deny/warn messages, waivers applied | JSON | SQLite + bundle |
| Attestation | in-toto Statement (DSSE envelope) signed with the local key | Bundle |

**Integrity**

- On first start, Gatehouse generates a local signing key (Ed25519) stored in the OS keychain where available, otherwise an encrypted file. Teams can import a shared key or use a hardware key.
- Every run's manifest, report digest, SBOM digest and decision are wrapped in an in-toto attestation and signed.
- An append-only, hash-chained audit log (each entry contains the previous entry's hash) records runs, policy changes, waiver changes and deletions. `gatehouse audit verify` re-checks the chain.

**Retention and size**

- Default retention: keep all decisions and findings forever (small), keep raw outputs and logs for the last 50 runs per branch, keep everything for runs tagged `release`.
- Content-addressed storage deduplicates identical SBOMs and reports.
- `gatehouse gc` applies retention; deletions are themselves logged.

**Export and sharing**

- One-click export of a run as a `.tar.zst` evidence bundle, an HTML report, a PDF summary for auditors, or SARIF for upload to GitHub/GitLab code scanning.
- Optional `git notes` mode writes a compact signed summary of the decision onto the commit, so CI can verify a pre-push scan really ran.
- History views: risk trend, findings opened/closed over time, mean time to remediate, waiver count, coverage trend.

## 11. Local web UI

The UI is served by the same binary at `http://127.0.0.1:7420`, renders server-side with htmx for interactivity, and should ship under \~100 KB of JavaScript. Everything the UI can do is also an API call and a CLI command.

**Pages**

| Page | What the user does there |
| --- | --- |
| Dashboard | See every registered repo, its last verdict per branch, open critical issues, and recent runs |
| Repositories | Add a local repo folder, view its detected profile, set default gate profile and policy packs |
| New scan | Pick repo → ref (working tree, branch, commit, range, or diff vs. base) → profile (pre-push / release / custom) → toggle check families → Run |
| Live run | Pipeline graph with each step's status, streaming logs (SSE), elapsed time, cancel button |
| Run report | Verdict banner with the exact policy messages; findings table filterable by family, severity, new/existing, file; code viewer with the offending lines; fix version / remediation; Waive button; compare with any previous run |
| Tests | Pass/fail/flaky per test, duration, coverage by file and on changed lines, mutation score |
| SBOM & licences | Component tree, licences, vulnerable components, export CycloneDX/SPDX |
| Compliance | Control-by-control view per standard with linked evidence |
| Policies | Active rules by layer, YAML/Rego editor with validation, dry-run against a past run, import packs |
| Waivers | All waivers with owner, reason, expiry; expiring-soon list |
| History | Trends: risk score, findings opened/closed, MTTR, coverage, run duration |
| Settings | Runtime (Docker/Podman), resource limits, network allowlist, tool versions, DB mirror updates, signing key, retention |

**UI security (it is a local server, so treat it like one)**

- Bind to `127.0.0.1` only; listening on other interfaces needs an explicit flag and a password.
- A random access token is generated at startup and opened in the browser via URL (Jupyter-style), then kept in an HttpOnly cookie.
- Validate the `Host` and `Origin` headers to block DNS-rebinding and cross-site requests from malicious web pages; CSRF tokens on every state-changing request.
- Strict Content-Security-Policy; no third-party assets — everything is embedded, which also makes it work offline.

**UX details that make it pleasant**

- "Scan before push" from the UI shows only *new* issues by default, with a toggle for all.
- Every finding has a copyable CLI command to reproduce it locally.
- Keyboard navigation, dark mode, and WCAG 2.2 AA for the UI itself.

## 12. Developer workflow

The web UI is the cockpit, but most daily use will be the git hook and CLI, so both talk to the same running daemon and reuse its caches.

**CLI**

```bash
gatehouse serve                         # start daemon + web UI
gatehouse repo add ~/code/payments-api  # register a repo
gatehouse scan .                        # full scan of working tree
gatehouse scan . --diff origin/main     # only what changed vs main
gatehouse scan . --ref feature/login --profile release
gatehouse hook install                  # install pre-commit + pre-push hooks
gatehouse policy test                   # run policy unit tests
gatehouse waive <fingerprint> --reason "..." --expires 2026-11-30
gatehouse report <run-id> --format sarif|html|pdf|bundle
gatehouse db update                     # refresh OSV/EPSS/KEV mirrors
gatehouse audit verify                  # check evidence chain
```

Exit codes: `0` pass, `1` fail (policy denied), `2` warn-only (configurable to pass), `3` tool/infra error. Output modes: human (coloured), `--json`, `--sarif`.

**Git hooks**

- `pre-commit`: staged files only — secrets, formatting, fast lint. Target under 10 seconds.
- `pre-push`: computes the commit range being pushed, runs the pre-push profile on the diff, prints a short summary and a link to the full report in the UI.
- Works alongside existing hook managers: provide ready-made entries for the `pre-commit` framework, Lefthook and Husky instead of overwriting their hooks.
- If the daemon is not running, the hook starts a one-shot scan in standalone mode.

**Handling `--no-verify`.** Hooks can always be bypassed. To make the gate meaningful for teams, the optional `git notes` attestation (section 10) lets CI run `gatehouse verify <commit>` and flag pushes that skipped the local scan — or simply rerun the same scan, since the binary runs identically in CI.

**IDE integration**

- Phase 1: exported SARIF opens in the VS Code SARIF Viewer and JetBrains Qodana/SARIF plugins.
- Phase 2: a thin VS Code extension that calls the daemon API, shows findings inline, and offers "waive" and "rescan file".

**CI parity.** The same `gatehouse scan` command and the same `gatehouse.yaml` run in GitHub Actions, GitLab CI or Jenkins, so local and CI verdicts match. CI usage is a bonus, not the main product.

## 13. Packaging and distribution

Ship one small core image plus a family of tool and language-runner images that are pulled lazily, only when a repo needs them. A Python-only repo should never download the JVM image.

**Images (all multi-arch: linux/amd64 + linux/arm64)**

| Image | Contents | Approx. role |
| --- | --- | --- |
| `gatehouse` | Core binary on a distroless/static base | Daemon, UI, CLI |
| `gatehouse-tools-core` | Opengrep, Gitleaks, OSV-Scanner, Syft, Grype, Hadolint, zizmor, actionlint, Lizard | Language-agnostic scanners |
| `gatehouse-tools-iac` | Checkov, Kubescape, kube-linter, Trivy (config mode) | IaC and container config |
| `gatehouse-run-go`, `-python`, `-node`, `-jvm`, `-dotnet`, `-rust`, `-php`, `-ruby`, `-cpp` | Toolchain + that ecosystem's linters, test runners, coverage, mutation tools | Build, lint, test per language |
| `gatehouse-run-browser` | Playwright + browsers, axe-core | E2E and accessibility |
| `gatehouse-dast` | OWASP ZAP | Optional local DAST |

Users can override any runner image (e.g. the exact Node version their project uses) in `gatehouse.yaml`.

**Install options**

1. **Host binary (recommended):** install script, Homebrew, Scoop/winget, `.deb`/`.rpm`; uses whichever Docker or Podman is already installed.
2. **Docker Compose:**

```yaml
services:
  gatehouse:
    image: ghcr.io/gatehouse/gatehouse@sha256:<digest>
    ports: ["127.0.0.1:7420:7420"]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock   # prefer rootless socket
      - ${HOME}/code:/repos:ro                      # folders you allow it to scan
      - gatehouse-data:/data
volumes:
  gatehouse-data: {}
```

3. **Podman (rootless):** `podman kube play gatehouse-pod.yaml`, or a Quadlet `.container` unit so it starts with the user session via systemd. Mount `$XDG_RUNTIME_DIR/podman/podman.sock`.

**macOS and Windows:** both need a Linux VM (Docker Desktop, Podman Desktop/`podman machine`, Rancher Desktop, Colima or WSL2). Bind-mount performance through the VM can be slow for large repos, so snapshot into a named volume first rather than scanning across the mount.

**Offline / air-gapped use**

- `gatehouse db update` refreshes the OSV, EPSS and KEV mirrors; `--from <dir>` loads them from a USB/drive copy.
- `gatehouse bundle export` writes every needed image plus databases into one archive for machines without internet; `bundle import` loads it.

**Updates**

- The core self-updates only to signed releases.
- Tool versions are governed by a signed **tool lockfile** (image name → digest) released on a regular cadence; users accept updates explicitly, and the lockfile hash is recorded in every run's evidence.

## 14. Securing the tool itself

A security scanner runs with high trust on developer machines, which makes it an attractive target; in March 2026 attackers used stolen credentials to publish a malicious Trivy 0.69.4 release and force-push most `trivy-action` tags to credential-stealing code ([CVE-2026-33634](https://cve.cert.hr/cve/CVE-2026-33634)), and Docker's guidance afterwards was that mutable tags are not a security boundary ([Docker](https://www.docker.com/blog/trivy-supply-chain-compromise-what-docker-hub-users-should-know/)). Gatehouse must be designed assuming any upstream tool can be compromised.

**Threat model and controls**

| Threat | Control |
| --- | --- |
| Malicious repo runs code during build/tests (postinstall scripts, test code, build plugins) | Sandbox: no network, no runtime socket, read-only source, resource limits, optional gVisor (section 4) |
| Crafted files exploit a scanner's parser | Same sandbox; scanners never run in the core process |
| Compromised upstream tool or image | Pin every image by digest; verify Sigstore/cosign signatures; build tool images from source in Gatehouse's own CI; hold new upstream versions for a cooling-off period (e.g. 7 days) before the tool lockfile adopts them |
| Malicious web page attacks the local UI | Localhost bind, startup token, Host/Origin checks, CSRF, CSP (section 11) |
| Discovered secrets leak through Gatehouse | Store only a hash plus masked preview (first/last 4 chars); redact secrets from stored logs and reports |
| Tampering with evidence or history | Signed attestations, hash-chained audit log, `audit verify` |
| Malicious shared policy pack | Policies are sandboxed Rego (no network or file builtins enabled); packs can require a trusted signer |
| Gatehouse's own supply chain | Release builds on hardened CI with actions pinned to full commit SHAs, SLSA provenance, signed binaries and images, SBOM per release, reproducible builds as a goal |

**Engineering practices for the Gatehouse repo**

- Gatehouse scans itself on every PR ("dogfooding") with the `strict-release` pack.
- `govulncheck`, fuzz tests for every parser/adapter, and race-detector test runs in CI.
- Two-maintainer review for anything touching the sandbox, signing or policy evaluation.
- `SECURITY.md` with a private disclosure channel (GitHub Security Advisories) and a 90-day disclosure window.
- Disable OPA builtins that reach the network (`http.send`) or environment when evaluating user and shared policies.

## 15. Repository layout and data model

One Go module for the core, with plugin manifests, policies, standards mappings and runner images as plain data folders that the community can contribute to without touching Go.

```text
gatehouse/
├── cmd/gatehouse/            # main: serve, scan, hook, policy, report, db, audit
├── internal/
│   ├── api/                  # HTTP handlers, OpenAPI spec, SSE
│   ├── ui/                   # templ components, htmx pages, embedded static assets
│   ├── orchestrator/         # run planner, DAG scheduler, worker pool, cancellation
│   ├── sandbox/              # runtime client (Docker API / Podman compat), snapshotting, egress proxy
│   ├── detect/               # language + manifest detection, repo profile
│   ├── plugins/              # manifest loader, version/digest resolution
│   ├── adapters/             # SARIF, JUnit, lcov, Cobertura, JaCoCo, tool-specific JSON → model
│   ├── findings/             # normalisation, fingerprinting, dedupe, new/existing/fixed diffing
│   ├── enrich/               # CVSS, EPSS, KEV, OSV mirror, CWE → standards mapping
│   ├── policy/               # OPA embedding, YAML DSL compiler, layering, waivers
│   ├── evidence/             # attestations, signing, audit log, bundle export
│   ├── store/                # SQLite schema + migrations, blob store, retention
│   └── gitx/                 # worktrees, diffs, hooks, git notes
├── plugins/                  # one YAML manifest per tool
├── policies/packs/           # baseline, owasp-top10, strict-release, …
├── standards/                # CWE/control mappings per standard + version
├── images/                   # Dockerfiles for tools-core, tools-iac, run-* images
├── deploy/                   # compose.yaml, podman kube YAML, Quadlet units
├── testdata/vulnerable-repos # intentionally vulnerable fixture repos for e2e tests
└── docs/
```

**Core data model (SQLite)**

| Table | Key fields |
| --- | --- |
| `repos` | id, path, name, default\_profile, policy\_packs, created\_at |
| `runs` | id, repo\_id, ref, tree\_hash, base\_ref, context, status, verdict, started\_at, finished\_at, tool\_lock\_hash, policy\_hash, attestation\_digest |
| `steps` | id, run\_id, plugin\_id, image\_digest, exit\_code, duration\_ms, log\_blob, output\_blobs |
| `findings` | id, run\_id, fingerprint, family, rule\_id, tool, severity, cvss, epss, kev, cwe\_ids, path, start\_line, end\_line, message, fix\_version, status (new/existing/fixed), waiver\_id |
| `metrics` | run\_id, key (coverage.line, coverage.changed\_lines, complexity.max, …), value |
| `test_results` | run\_id, suite, name, status, duration\_ms, retries, flaky, quarantined |
| `components` | run\_id, purl, name, version, licence, hashes, direct (bool) |
| `waivers` | id, fingerprint\_or\_scope, reason, owner, created\_at, expires\_at, source (repo file / UI) |
| `decisions` | run\_id, verdict, deny\_msgs, warn\_msgs, input\_hash, policy\_hash |
| `audit_log` | seq, ts, actor, action, payload\_hash, prev\_hash, entry\_hash |

**The fingerprint** is the key to diffing across runs: `sha256(rule_id + normalised path + normalised snippet ± 2 lines)`, so a finding keeps its identity when unrelated lines above it move.

**Orchestrator behaviour.** A run is a DAG: detect → snapshot → prepare (deps) → parallel scanners and tests → enrich → policy → evidence. A worker pool sized to CPU count runs independent steps concurrently; any step can be cancelled; a failed tool marks its family as *errored* (policies decide whether that blocks) rather than silently passing.

## 16. Phased roadmap

Ship a genuinely useful pre-push gate for three languages by about week 10, then widen. Each phase ends with a gate that is a test you can run, not a feeling.

&#91;embedded content: roadmap · 6 phases, 6 gates\]

Phase 1 is the one to protect: secrets, SAST, dependency CVEs, tests and one baseline policy, scoped to the diff, is already more than most teams run before pushing. Everything after it is breadth and depth on a working core.

**Start this week**

- [ ] Create the repo with Apache-2.0, DCO, `SECURITY.md`, and CI running `go test -race` and `govulncheck`.
- [ ] Write the sandbox runner: run one container with `/src:ro`, `--network=none`, `--cap-drop=ALL`, collect `/out`; test it on both Docker and rootless Podman.
- [ ] Define the Finding schema and the SARIF adapter, then wire Gitleaks end to end as the first plugin.
- [ ] Build three small intentionally vulnerable fixture repos (Go, Python, JS) to act as the e2e test suite.
- [ ] Embed OPA and evaluate a one-rule `baseline` policy against a real run.

## 17. Open-source setup, risks and open decisions

**Project setup**

- Licence: **Apache-2.0** for Gatehouse (permissive, includes a patent grant, friendly to companies adopting it). Third-party tools keep their own licences inside their own images; list them all in `THIRD_PARTY.md`.
- Contributions: Developer Certificate of Origin (DCO) sign-off instead of a CLA; `CONTRIBUTING.md` with three easy on-ramps — add a plugin manifest, add a policy rule, add a standards mapping.
- Governance: `GOVERNANCE.md` and `MAINTAINERS.md` from day one; decisions by maintainer consensus; aim for an OpenSSF or CNCF sandbox application once there are maintainers from more than one organisation.
- Community: Code of Conduct, GitHub Discussions, a docs site (Hugo or Docusaurus) with a 5-minute quickstart, and a public roadmap board.
- Releases: SemVer; monthly minor releases; signed binaries, images and SBOMs; tool lockfile updates on their own cadence.

**Key risks**

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Scope is very large | Never ships a usable v1 | Strict phases (section 16); MVP is secrets + SAST + SCA + tests + policy for 3 languages |
| Noise / false positives | Developers disable the hook | Diff-only gates, new-issues-only default, easy waivers, tuned default rule sets |
| Slow scans on large repos | Pre-push becomes painful | Diff scoping, test impact analysis, dependency caches, parallel DAG, incremental SBOM |
| Upstream licence changes (as with Semgrep) | Forced tool swap | Plugin abstraction; every family has at least two candidate tools |
| Upstream tool compromise | Attack via Gatehouse | Digest pinning, signature checks, cooling-off period, self-built images (section 14) |
| macOS/Windows VM file performance | Poor experience for many users | Snapshot into a volume; document recommended VM settings |
| Maintainer burnout | Project stalls | Data-driven extensibility so contributors add value without core changes; clear ownership areas |

**Open decisions to settle early**

- [ ] Final project name (check trademark and package-name availability).
- [ ] UI approach: templ + htmx (lightest, one language) vs. SvelteKit static build (richer interactivity).
- [ ] Whether v1 supports Testcontainers via nested rootless Podman or only declared `services:`.
- [ ] Whether CodeQL is supported as a bring-your-own plugin in v1.
- [ ] Single-user only for v1, or a shared-team mode with a central policy repo from the start.
- [ ] Which three languages the MVP covers (suggested: Go, Python, JS/TS).

## Sources

- [Opengrep repository](https://github.com/opengrep/opengrep)
- [OpenGrep vs Semgrep — AppSec Santa](https://appsecsanta.com/opengrep-vs-semgrep)
- [OPA integration docs (Go SDK and v1/rego)](https://openpolicyagent.org/docs/integration)
- [CVE-2026-33634 — Trivy supply chain compromise](https://cve.cert.hr/cve/CVE-2026-33634)
- [Trivy supply chain compromise: what Docker Hub users should know — Docker](https://www.docker.com/blog/trivy-supply-chain-compromise-what-docker-hub-users-should-know/)
