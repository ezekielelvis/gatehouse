# Security Policy

Gatehouse is a security tool that runs with high trust on developer machines,
which makes it an attractive target. We take its security seriously and design
it assuming any upstream tool it orchestrates can be compromised (see the threat
model in the build plan, §14).

## Reporting a vulnerability

Please report security vulnerabilities privately via
**GitHub Security Advisories** on this repository (Security → Advisories →
Report a vulnerability). Do not open a public issue for a suspected
vulnerability.

We aim to acknowledge reports within 3 business days and follow a **90-day
coordinated disclosure** window.

## Scope

In scope:

- The `gatehouse` core (orchestrator, sandbox, policy evaluation, evidence
  signing, local web UI/API).
- The built-in plugin manifests and policy packs shipped in this repository.

Out of scope:

- Vulnerabilities in third-party scanner tools themselves (report those
  upstream). Gatehouse mitigates compromised tools via digest pinning,
  signature verification and a cooling-off period on the tool lockfile.

## Hardening guarantees

- Every check runs in a locked-down container: read-only source, `--network=none`
  by default, `--cap-drop=ALL`, `no-new-privileges`, non-root, resource limits,
  and no host runtime socket mounted into scanner containers.
- Discovered secrets are stored only as a hash plus a masked preview; they are
  redacted from stored logs and reports.
- User and shared policies evaluate with network- and environment-reaching Rego
  builtins (e.g. `http.send`) disabled.
- The local web UI binds to `127.0.0.1`, validates `Host`/`Origin`, and ships a
  strict CSP with no third-party assets.
