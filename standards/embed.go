// Package standardsdata embeds the built-in standard mapping files so they ship
// inside the single binary and can be updated as data without a code release
// (plan §7). Community contributions add a <name>/<version>.yaml file here.
package standardsdata

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/gatehouse/gatehouse/internal/standards"
)

//go:embed */*.yaml
var dataFS embed.FS

// Load returns the latest-version mapping for a named standard (e.g.
// "owasp-top10"). When multiple versions exist, the lexically greatest file
// name wins, which matches year/semver ordering for our files.
func Load(name string) (*standards.Standard, error) {
	entries, err := fs.ReadDir(dataFS, name)
	if err != nil {
		return nil, fmt.Errorf("unknown standard %q", name)
	}
	var files []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".yaml") {
			files = append(files, e.Name())
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("standard %q has no mapping files", name)
	}
	sort.Strings(files)
	latest := files[len(files)-1]
	data, err := fs.ReadFile(dataFS, path.Join(name, latest))
	if err != nil {
		return nil, err
	}
	return standards.Parse(data)
}

// List returns the names of all embedded standards.
func List() ([]string, error) {
	entries, err := dataFS.ReadDir(".")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}
