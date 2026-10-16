// Package plugins loads tool manifests. A plugin is declared, not coded: adding
// a scanner means adding a YAML manifest (and, if the tool lacks SARIF, an
// adapter), never touching core Go.
package plugins

import (
	"fmt"
	"io/fs"
	"path"
	"strings"

	"github.com/gatehouse/gatehouse/internal/model"
	"gopkg.in/yaml.v3"
)

// OutputFormat names the shape of a result file a plugin writes to /out.
type OutputFormat string

const (
	FormatSARIF     OutputFormat = "sarif"
	FormatJUnit     OutputFormat = "junit"
	FormatLCOV      OutputFormat = "lcov"
	FormatCycloneDX OutputFormat = "cyclonedx"
	FormatMutation  OutputFormat = "mutation"
	FormatJSON      OutputFormat = "json"
)

// Output declares one result file a plugin produces.
type Output struct {
	Path   string       `yaml:"path"`
	Format OutputFormat `yaml:"format"`
}

// AppliesWhen is the selector matched against a repo profile.
type AppliesWhen struct {
	Languages []string `yaml:"languages"`
	Manifests []string `yaml:"manifests"`
	// Always, when true, makes the plugin run regardless of profile (e.g. a
	// secrets scanner is language-agnostic).
	Always bool `yaml:"always"`
}

// NetworkMode mirrors the sandbox network policy.
type NetworkMode string

const (
	NetworkNone     NetworkMode = "none"
	NetworkPrepare  NetworkMode = "prepare" // allowed only during the opt-in prepare phase
	NetworkInternal NetworkMode = "internal"
)

// Manifest is the on-disk declaration of one analyzer.
type Manifest struct {
	ID             string       `yaml:"id"`
	Version        string       `yaml:"version"`
	Image          string       `yaml:"image"`
	AppliesWhen    AppliesWhen  `yaml:"applies_when"`
	Category       []string     `yaml:"category"`
	Family         model.Family `yaml:"family"`
	Network        NetworkMode  `yaml:"network"`
	Command        []string     `yaml:"command"`
	Outputs        []Output     `yaml:"outputs"`
	Timeout        string       `yaml:"timeout"`
	RespectsConfig []string     `yaml:"respects_repo_config"`
	// DefaultOff plugins never run via automatic selection; they must be
	// explicitly enabled in gatehouse.yaml (e.g. slow mutation/e2e/fuzz tools).
	DefaultOff bool `yaml:"default_off"`
	// HostCommand is an optional command used by the dev-only host executor when
	// no container runtime is available. It must never be used in production.
	HostCommand []string `yaml:"host_command"`
}

// Validate checks a manifest for the fields the orchestrator relies on.
func (m Manifest) Validate() error {
	if m.ID == "" {
		return fmt.Errorf("manifest: id is required")
	}
	if m.Image == "" {
		return fmt.Errorf("manifest %s: image is required", m.ID)
	}
	if len(m.Command) == 0 {
		return fmt.Errorf("manifest %s: command is required", m.ID)
	}
	if m.Network == "" {
		return fmt.Errorf("manifest %s: network is required (use 'none' to be explicit)", m.ID)
	}
	return nil
}

// Applies reports whether the plugin should run against the given profile.
// Default-off plugins never match automatic selection (they are opt-in via
// gatehouse.yaml, which goes through config.Apply, not Select).
func (m Manifest) Applies(p model.RepoProfile) bool {
	if m.DefaultOff {
		return false
	}
	if m.AppliesWhen.Always {
		return true
	}
	for _, l := range m.AppliesWhen.Languages {
		if p.HasLanguage(l) {
			return true
		}
	}
	for _, want := range m.AppliesWhen.Manifests {
		for _, got := range p.Manifests {
			if strings.EqualFold(want, got) {
				return true
			}
		}
	}
	return len(m.AppliesWhen.Languages) == 0 && len(m.AppliesWhen.Manifests) == 0
}

// Load reads and validates a single manifest.
func Load(data []byte) (Manifest, error) {
	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("parse manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// LoadDir reads every *.yaml/*.yml manifest from fsys rooted at dir.
func LoadDir(fsys fs.FS, dir string) ([]Manifest, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("read plugins dir: %w", err)
	}
	var out []Manifest
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(path.Ext(e.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		data, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		m, err := Load(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out = append(out, m)
	}
	return out, nil
}

// Select returns the subset of manifests that apply to the profile.
func Select(all []Manifest, p model.RepoProfile) []Manifest {
	var out []Manifest
	for _, m := range all {
		if m.Applies(p) {
			out = append(out, m)
		}
	}
	return out
}
