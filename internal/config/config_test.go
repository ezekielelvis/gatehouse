package config

import (
	"testing"

	"github.com/gatehouse/gatehouse/internal/plugins"
)

func man(id string) plugins.Manifest {
	return plugins.Manifest{ID: id, Image: "img", Network: "none", Command: []string{"x"}}
}

func TestDefaultPacks(t *testing.T) {
	c, err := Parse([]byte(``))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Packs) != 1 || c.Packs[0] != "baseline" {
		t.Fatalf("empty config should default to baseline, got %v", c.Packs)
	}
}

func TestApplyDisablesPlugin(t *testing.T) {
	c, _ := Parse([]byte(`
plugins:
  gosec:
    enabled: false
`))
	all := []plugins.Manifest{man("gitleaks"), man("gosec")}
	selected := all // pretend both were selected
	got := c.Apply(all, selected)
	for _, m := range got {
		if m.ID == "gosec" {
			t.Fatal("gosec should be force-disabled")
		}
	}
	if len(got) != 1 {
		t.Fatalf("want 1 plugin after disable, got %d", len(got))
	}
}

func TestApplyEnablesSkippedPlugin(t *testing.T) {
	c, _ := Parse([]byte(`
plugins:
  gosec:
    enabled: true
`))
	all := []plugins.Manifest{man("gitleaks"), man("gosec")}
	selected := []plugins.Manifest{man("gitleaks")} // gosec not selected by profile
	got := c.Apply(all, selected)
	ids := map[string]bool{}
	for _, m := range got {
		ids[m.ID] = true
	}
	if !ids["gosec"] {
		t.Fatal("gosec should be force-enabled even though selection skipped it")
	}
}

func TestApplyImageOverride(t *testing.T) {
	c, _ := Parse([]byte(`
plugins:
  gitleaks:
    image: ghcr.io/me/custom@sha256:abc
`))
	all := []plugins.Manifest{man("gitleaks")}
	got := c.Apply(all, all)
	if got[0].Image != "ghcr.io/me/custom@sha256:abc" {
		t.Fatalf("image override not applied: %s", got[0].Image)
	}
}

// Ensure Apply is a no-op passthrough (sorted) without overrides.
func TestApplyPassthrough(t *testing.T) {
	c := Default()
	all := []plugins.Manifest{man("b"), man("a")}
	got := c.Apply(all, all)
	if len(got) != 2 || got[0].ID != "a" || got[1].ID != "b" {
		t.Fatalf("expected sorted passthrough, got %v", []string{got[0].ID, got[1].ID})
	}
}
