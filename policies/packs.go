// Package policies embeds the built-in policy packs shipped with Gatehouse so
// they travel inside the single binary (plan §2/§9). The baseline pack is the
// default gate; additional packs (owasp-top10, strict-release, …) are added as
// sibling .rego files and exposed here.
package policies

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/gatehouse/gatehouse/internal/policy"
)

//go:embed packs/*.rego
var packsFS embed.FS

// Pack returns the modules that make up a named built-in pack. A pack is any
// set of .rego files whose base name starts with the pack name (so a pack may
// span several files, e.g. baseline.rego, baseline_tests.rego).
func Pack(name string) ([]policy.Module, error) {
	entries, err := packsFS.ReadDir("packs")
	if err != nil {
		return nil, err
	}
	var mods []policy.Module
	for _, e := range entries {
		base := strings.TrimSuffix(e.Name(), ".rego")
		if base != name && !strings.HasPrefix(base, name+"_") {
			continue
		}
		data, err := fs.ReadFile(packsFS, "packs/"+e.Name())
		if err != nil {
			return nil, err
		}
		mods = append(mods, policy.Module{Name: e.Name(), Source: string(data)})
	}
	if len(mods) == 0 {
		return nil, fmt.Errorf("unknown policy pack %q", name)
	}
	return mods, nil
}

// Baseline is the default shipped gate.
func Baseline() ([]policy.Module, error) { return Pack("baseline") }

// List returns the names of all built-in packs (one per .rego file base name,
// de-duplicated), for the UI's policies view.
func List() ([]string, error) {
	entries, err := packsFS.ReadDir("packs")
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var names []string
	for _, e := range entries {
		base := strings.TrimSuffix(e.Name(), ".rego")
		if i := strings.IndexByte(base, '_'); i > 0 {
			base = base[:i] // fold baseline_tests.rego into "baseline"
		}
		if !seen[base] {
			seen[base] = true
			names = append(names, base)
		}
	}
	sort.Strings(names)
	return names, nil
}
