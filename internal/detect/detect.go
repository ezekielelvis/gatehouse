// Package detect fingerprints a snapshot into a model.RepoProfile: which
// languages are present and which build/CI manifests exist. The profile drives
// plugin selection (a plugin's applies_when is matched against it).
//
// v1 uses a lightweight extension- and filename-based heuristic rather than
// pulling in go-enry, which keeps the core binary small; the plan allows
// swapping in go-enry later behind this same package boundary.
package detect

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gatehouse/gatehouse/internal/model"
)

// extLang maps file extensions to a canonical language name.
var extLang = map[string]string{
	".go":   "Go",
	".py":   "Python",
	".js":   "JavaScript",
	".jsx":  "JavaScript",
	".mjs":  "JavaScript",
	".cjs":  "JavaScript",
	".ts":   "TypeScript",
	".tsx":  "TypeScript",
	".java": "Java",
	".kt":   "Kotlin",
	".cs":   "C#",
	".rs":   "Rust",
	".php":  "PHP",
	".rb":   "Ruby",
	".c":    "C",
	".h":    "C",
	".cc":   "C++",
	".cpp":  "C++",
	".hpp":  "C++",
	".sh":   "Shell",
	".bash": "Shell",
	".tf":   "Terraform",
	".yaml": "YAML",
	".yml":  "YAML",
	".json": "JSON",
	".md":   "Markdown",
}

// manifestFiles maps well-known filenames to a canonical manifest label. The
// value is the label recorded in the profile; the key is matched case-sensitively
// against the base filename.
var manifestFiles = map[string]string{
	"go.mod":           "go.mod",
	"package.json":     "package.json",
	"pyproject.toml":   "pyproject.toml",
	"requirements.txt": "requirements.txt",
	"pom.xml":          "pom.xml",
	"build.gradle":     "build.gradle",
	"Cargo.toml":       "Cargo.toml",
	"Gemfile":          "Gemfile",
	"composer.json":    "composer.json",
	"Dockerfile":       "Dockerfile",
	"CMakeLists.txt":   "CMakeLists.txt",
}

// manifestSuffix matches manifests identified by suffix rather than exact name.
var manifestSuffix = map[string]string{
	".csproj": "csproj",
	".tf":     "terraform",
}

// skipDirs are never descended into during detection.
var skipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	"dist":         true,
	"build":        true,
	"target":       true,
	".venv":        true,
	"__pycache__":  true,
}

// Profile walks root and returns the detected repo profile. It is tolerant of
// read errors on individual entries (a scan must not fail because one file is
// unreadable).
func Profile(fsys fs.FS, root string) (model.RepoProfile, error) {
	langs := map[string]bool{}
	manifests := map[string]bool{}

	walkRoot := root
	if walkRoot == "" {
		walkRoot = "."
	}

	err := fs.WalkDir(fsys, walkRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		name := d.Name()
		if label, ok := manifestFiles[name]; ok {
			manifests[label] = true
		}
		for suf, label := range manifestSuffix {
			if strings.HasSuffix(name, suf) {
				manifests[label] = true
			}
		}
		if lang, ok := extLang[strings.ToLower(filepath.Ext(name))]; ok {
			langs[lang] = true
		}
		// Helm/k8s heuristic: a chart has Chart.yaml.
		if name == "Chart.yaml" {
			manifests["helm"] = true
		}
		// GitHub Actions: any workflow file under .github/workflows.
		if strings.Contains(filepath.ToSlash(path), ".github/workflows/") &&
			(strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")) {
			manifests["github-actions"] = true
		}
		return nil
	})
	if err != nil {
		return model.RepoProfile{}, err
	}

	return model.RepoProfile{
		Languages: sortedKeys(langs),
		Manifests: sortedKeys(manifests),
	}, nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
