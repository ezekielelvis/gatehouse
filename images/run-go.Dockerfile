# gatehouse-run-go: the Go ecosystem runner (plan §13).
#
# Contains the Go toolchain plus Go's linters, security scanner, test runner and
# coverage/mutation tooling, so build/lint/test for a Go repo happens entirely
# inside the sandbox. Pulled lazily, only when a repo has Go.
FROM golang:1.27-bookworm

# Pin tool versions; Gatehouse's release CI records exact versions in the lockfile.
RUN go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.0 \
 && go install github.com/securego/gosec/v2/cmd/gosec@v2.21.4 \
 && go install golang.org/x/vuln/cmd/govulncheck@latest \
 && go install gotest.tools/gotestsum@latest \
 && go install github.com/boumenot/gocover-cobertura@latest

# Run as a non-root user; the sandbox also enforces this.
RUN useradd -m -u 65532 runner
USER 65532:65532
WORKDIR /src
ENV GOFLAGS=-mod=mod GOCACHE=/tmp/go-build GOPATH=/tmp/go
ENTRYPOINT []
