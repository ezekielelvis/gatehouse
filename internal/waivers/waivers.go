// Package waivers loads and applies exceptions declared in
// .gatehouse/waivers.yaml (plan §9). A waiver suppresses a specific finding (by
// fingerprint) or a class of findings (by rule id + path glob) until a
// mandatory expiry date. Because waivers live in the repo, they go through
// normal code review; expired waivers automatically stop applying.
package waivers

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gatehouse/gatehouse/internal/model"
	"gopkg.in/yaml.v3"
)

// Waiver is one exception.
type Waiver struct {
	ID string `yaml:"id"`
	// Fingerprint targets exactly one finding. Mutually usable with Rule/Path.
	Fingerprint string `yaml:"fingerprint"`
	// Rule + Path target a class of findings; Path is a glob matched against the
	// finding's repo-relative path.
	Rule string `yaml:"rule"`
	Path string `yaml:"path"`

	Reason  string `yaml:"reason"`
	Owner   string `yaml:"owner"`
	Expires string `yaml:"expires"` // RFC3339 date (YYYY-MM-DD) — mandatory
}

// Set is a loaded collection of waivers.
type Set struct {
	Waivers []Waiver `yaml:"waivers"`
}

// Load reads .gatehouse/waivers.yaml from repoDir. An absent file yields an
// empty set. A present-but-invalid file is an error.
func Load(repoDir string) (*Set, error) {
	path := filepath.Join(repoDir, ".gatehouse", "waivers.yaml")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Set{}, nil
	}
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse decodes and validates a waivers document.
func Parse(data []byte) (*Set, error) {
	var s Set
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse waivers: %w", err)
	}
	for i, w := range s.Waivers {
		if w.ID == "" {
			return nil, fmt.Errorf("waiver %d: id is required", i)
		}
		if w.Fingerprint == "" && w.Rule == "" {
			return nil, fmt.Errorf("waiver %s: must target a fingerprint or a rule", w.ID)
		}
		if w.Expires == "" {
			return nil, fmt.Errorf("waiver %s: a mandatory expiry date is missing", w.ID)
		}
		if _, err := parseExpiry(w.Expires); err != nil {
			return nil, fmt.Errorf("waiver %s: bad expiry %q: %w", w.ID, w.Expires, err)
		}
	}
	return &s, nil
}

// Apply stamps WaiverID onto every finding matched by a non-expired waiver, as
// of time now. It returns the findings (mutated in place) and the set of waiver
// IDs that actually applied, so the UI can show which waivers are in use.
func (s *Set) Apply(findings []model.Finding, now time.Time) ([]model.Finding, []string) {
	appliedSet := map[string]struct{}{}
	for i := range findings {
		for _, w := range s.Waivers {
			if w.expired(now) {
				continue
			}
			if w.matches(findings[i]) {
				findings[i].WaiverID = w.ID
				appliedSet[w.ID] = struct{}{}
				break
			}
		}
	}
	applied := make([]string, 0, len(appliedSet))
	for id := range appliedSet {
		applied = append(applied, id)
	}
	return findings, applied
}

func (w Waiver) matches(f model.Finding) bool {
	if w.Fingerprint != "" {
		return w.Fingerprint == f.Fingerprint
	}
	if w.Rule != f.RuleID {
		return false
	}
	if w.Path == "" {
		return true
	}
	ok, err := filepath.Match(w.Path, f.Path)
	return err == nil && ok
}

func (w Waiver) expired(now time.Time) bool {
	exp, err := parseExpiry(w.Expires)
	if err != nil {
		return true // a waiver we can't parse is treated as not applying
	}
	// A waiver is valid through the end of its expiry day.
	return now.After(exp.Add(24 * time.Hour))
}

func parseExpiry(s string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}
