// Package config loads the per-repo gatehouse.yaml (plan §2/§5). Repo-level
// configuration travels with the code: it selects policy packs, enables or
// disables individual plugins, overrides tool images (e.g. pin the exact Node
// version a project uses), and declares QA services. Everything has a sane
// default so a repo with no gatehouse.yaml still scans.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/gatehouse/gatehouse/internal/plugins"
	"gopkg.in/yaml.v3"
)

// Config is the parsed gatehouse.yaml.
type Config struct {
	// Packs selects which built-in/shared policy packs apply. Empty = baseline.
	Packs []string `yaml:"policy_packs"`

	// Plugins tunes individual tools by id.
	Plugins map[string]PluginOverride `yaml:"plugins"`

	// QA declares services and test behaviour (consumed in a later phase; parsed
	// here so the schema is stable and forward-compatible).
	QA QA `yaml:"qa"`
}

// PluginOverride adjusts one plugin without editing its manifest.
type PluginOverride struct {
	// Enabled, when non-nil, force-enables (true) or disables (false) the plugin
	// regardless of its applies_when. nil means "use default selection".
	Enabled *bool `yaml:"enabled"`
	// Image overrides the manifest image (e.g. a specific toolchain version).
	Image string `yaml:"image"`
}

// QA mirrors the plan's gatehouse.yaml QA block.
type QA struct {
	Services map[string]Service `yaml:"services"`
	E2E      *E2E               `yaml:"e2e"`
	Mutation struct {
		Enabled bool   `yaml:"enabled"`
		Scope   string `yaml:"scope"`
	} `yaml:"mutation"`
	Flaky struct {
		Retries         int `yaml:"retries"`
		QuarantineAfter int `yaml:"quarantine_after"`
	} `yaml:"flaky"`
	// Quarantine explicitly quarantines named tests ("name" or "suite/name"),
	// so a known-bad test can be excluded from the gate via code review.
	Quarantine []string `yaml:"quarantine"`
}

// Service is one dependency container for integration tests.
type Service struct {
	Image string            `yaml:"image"`
	Env   map[string]string `yaml:"env"`
}

// E2E declares how to start the app and run end-to-end tests against it (plan
// §8). The app and the test runner share a private internal network with the
// declared services; nothing has egress.
type E2E struct {
	// Image is the runner image (browsers etc.); defaults to run-browser.
	Image string `yaml:"image"`
	// Start launches the app in the background inside the sandbox.
	Start string `yaml:"start"`
	// WaitFor is a URL polled until the app is healthy before tests run.
	WaitFor string `yaml:"wait_for"`
	// Run executes the e2e suite; it should emit JUnit to /out.
	Run string `yaml:"run"`
}

// Default is the configuration used when a repo has no gatehouse.yaml.
func Default() Config {
	return Config{Packs: []string{"baseline"}}
}

// Load reads gatehouse.yaml from repoDir, falling back to Default() when the
// file is absent. A present-but-invalid file is an error (fail loud, so a typo
// in a gate config can't silently weaken the gate).
func Load(repoDir string) (Config, error) {
	path := filepath.Join(repoDir, "gatehouse.yaml")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Default(), nil
	}
	if err != nil {
		return Config{}, err
	}
	return Parse(data)
}

// Parse decodes a gatehouse.yaml document, applying defaults for empty fields.
func Parse(data []byte) (Config, error) {
	cfg := Config{}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse gatehouse.yaml: %w", err)
	}
	if len(cfg.Packs) == 0 {
		cfg.Packs = []string{"baseline"}
	}
	return cfg, nil
}

// Apply resolves the effective plugin set for a profile by taking the manifests
// that selection chose, adding any force-enabled plugins, dropping any
// force-disabled ones, and applying image overrides. selected is the result of
// plugins.Select; all is every available manifest (needed to honour an
// enable override for a plugin that selection skipped).
func (c Config) Apply(all, selected []plugins.Manifest) []plugins.Manifest {
	byID := func(ms []plugins.Manifest) map[string]plugins.Manifest {
		m := make(map[string]plugins.Manifest, len(ms))
		for _, x := range ms {
			m[x.ID] = x
		}
		return m
	}
	allByID := byID(all)
	chosen := byID(selected)

	// Force-enable plugins that selection didn't pick.
	for id, ov := range c.Plugins {
		if ov.Enabled != nil && *ov.Enabled {
			if m, ok := allByID[id]; ok {
				chosen[id] = m
			}
		}
	}

	out := make([]plugins.Manifest, 0, len(chosen))
	for id, m := range chosen {
		ov, ok := c.Plugins[id]
		if ok {
			if ov.Enabled != nil && !*ov.Enabled {
				continue // force-disabled
			}
			if ov.Image != "" {
				m.Image = ov.Image
			}
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
