# Tool & runtime images

Gatehouse ships one small core image plus a family of tool and language-runner
images pulled lazily, only when a repo needs them (plan §13). A Python-only repo
never downloads the JVM image.

| Image | Dockerfile | Contents |
| --- | --- | --- |
| `gatehouse` | `gatehouse.Dockerfile` | Core static binary (daemon, UI, CLI) |
| `gatehouse-tools-core` | `tools-core.Dockerfile` | Gitleaks, Opengrep, OSV-Scanner (+ offline OSV DB) |
| `gatehouse-run-go` | `run-go.Dockerfile` | Go toolchain, golangci-lint, gosec, govulncheck, gotestsum |
| `gatehouse-run-python` | `run-python.Dockerfile` | Ruff, Bandit, mypy, pytest + coverage |
| `gatehouse-run-node` | `run-node.Dockerfile` | ESLint, Biome, TypeScript, Vitest |

## Building (multi-arch)

```bash
# Core
docker buildx build --platform linux/amd64,linux/arm64 \
  -f images/gatehouse.Dockerfile -t ghcr.io/gatehouse/gatehouse:dev .

# A tool image
docker buildx build --platform linux/amd64,linux/arm64 \
  -f images/tools-core.Dockerfile -t ghcr.io/gatehouse/tools-core:dev images/
```

## Supply-chain rules (plan §14)

- **Pin every upstream image by digest, never a mutable tag.** The placeholder
  `@sha256:000…` digests in these Dockerfiles are resolved and pinned by release
  CI into the signed **tool lockfile** (image name → digest).
- Verify Sigstore/cosign signatures before first use.
- Hold new upstream versions for a cooling-off period before the lockfile adopts
  them.
- Final stages are non-root distroless so a compromised scanner has minimal
  surface; the sandbox additionally enforces `--network=none`, read-only source,
  dropped capabilities and resource limits at run time.
