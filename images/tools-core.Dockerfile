# gatehouse-tools-core: the language-agnostic scanner image (plan §13).
#
# Bundles the tools that run on any repo regardless of language: secrets
# (Gitleaks), SAST (Opengrep), SCA (OSV-Scanner). Each is copied from its
# upstream image pinned by digest — never a mutable tag, which the Trivy
# supply-chain compromise (CVE-2026-33634) showed is not a security boundary.
#
# The final stage is a static, non-root distroless base with none of the build
# tooling, so a compromised scanner has minimal surface. Scanners run with
# --network=none, /src read-only and /out as the only writable mount.
#
# NOTE: digests below are placeholders. Gatehouse's release CI resolves and
# pins the real digests into the signed tool lockfile.

# --- Gitleaks ---------------------------------------------------------------
FROM zricethezav/gitleaks@sha256:0000000000000000000000000000000000000000000000000000000000000000 AS gitleaks

# --- Opengrep ---------------------------------------------------------------
FROM ghcr.io/opengrep/opengrep@sha256:0000000000000000000000000000000000000000000000000000000000000000 AS opengrep

# --- OSV-Scanner (+ offline OSV DB staged by release CI) --------------------
FROM ghcr.io/google/osv-scanner@sha256:0000000000000000000000000000000000000000000000000000000000000000 AS osv

# --- Final: distroless static, non-root ------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=gitleaks /usr/bin/gitleaks   /usr/bin/gitleaks
COPY --from=opengrep  /usr/local/bin/opengrep /usr/bin/opengrep
COPY --from=osv       /osv-scanner         /usr/bin/osv-scanner

# A locally mirrored OSV database baked in so the execute phase stays offline.
COPY --from=osv /osv-db /opt/osv-db
ENV OSV_SCANNER_LOCAL_DB_DIR=/opt/osv-db

USER nonroot:nonroot
WORKDIR /src
ENTRYPOINT []
