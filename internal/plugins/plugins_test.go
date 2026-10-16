package plugins

import (
	"testing"

	"github.com/gatehouse/gatehouse/internal/model"
)

func TestLoadAndApplies(t *testing.T) {
	m, err := Load([]byte(`
id: ruff
image: ghcr.io/gatehouse/ruff@sha256:abc
family: quality
network: none
applies_when: { languages: [Python] }
command: ["ruff", "check", "/src"]
outputs: [{ path: /out/ruff.sarif, format: sarif }]
`))
	if err != nil {
		t.Fatal(err)
	}
	if !m.Applies(model.RepoProfile{Languages: []string{"Python"}}) {
		t.Error("ruff should apply to a Python repo")
	}
	if m.Applies(model.RepoProfile{Languages: []string{"Go"}}) {
		t.Error("ruff should not apply to a Go-only repo")
	}
}

func TestAlwaysApplies(t *testing.T) {
	m, _ := Load([]byte(`
id: gitleaks
image: ghcr.io/gatehouse/gitleaks@sha256:abc
family: secret
network: none
applies_when: { always: true }
command: ["gitleaks", "detect"]
`))
	if !m.Applies(model.RepoProfile{}) {
		t.Error("always-on plugin should apply to any profile")
	}
}

func TestValidateRejectsIncomplete(t *testing.T) {
	if _, err := Load([]byte(`id: x`)); err == nil {
		t.Error("expected validation error for manifest missing image/command/network")
	}
}
