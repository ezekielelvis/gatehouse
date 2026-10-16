# Gatehouse developer tasks.
BINARY := bin/gatehouse
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test race vet fmt lint ci clean run scan serve

build: ## Build the gatehouse binary
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/gatehouse

test: ## Run the test suite
	go test ./...

race: ## Run tests with the race detector
	go test -race ./...

vet: ## go vet
	go vet ./...

fmt: ## Format all Go code
	gofmt -w cmd internal plugins policies standards

lint: ## Check formatting (fails if unformatted)
	test -z "$$(gofmt -l cmd internal plugins policies standards)"

ci: lint vet race ## Everything CI runs

clean:
	rm -rf bin

# Convenience: scan the bundled vulnerable fixture with the host executor.
scan: build
	$(BINARY) scan testdata/vulnerable-repos/go-vuln --unsafe-host-exec

serve: build
	$(BINARY) serve
