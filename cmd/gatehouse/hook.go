package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gatehouse/gatehouse/internal/gitx"
)

// cmdHook implements "gatehouse hook install" (plan §12): it wires Gatehouse
// into git's pre-commit and pre-push hooks so the gate runs before code leaves
// the machine. It refuses to clobber another tool's hooks — if a hook manager
// (pre-commit, Lefthook, Husky) is detected it prints the integration snippet
// instead; and it backs up any existing plain hook before replacing it.
func cmdHook(args []string) int {
	if len(args) == 0 || args[0] != "install" {
		fmt.Fprintln(os.Stderr, "usage: gatehouse hook install [--path <repo>]")
		return exitError
	}
	fs := flag.NewFlagSet("hook install", flag.ExitOnError)
	path := fs.String("path", ".", "repository path")
	fs.Parse(args[1:])

	if !gitx.IsRepo(*path) {
		fmt.Fprintf(os.Stderr, "not a git repository: %s\n", *path)
		return exitError
	}
	top, err := gitx.TopLevel(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitError
	}

	if mgr := detectHookManager(top); mgr != "" {
		printManagerGuidance(mgr)
		return exitPass
	}

	hooksDir, err := gitx.HooksDir(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "locate hooks dir:", err)
		return exitError
	}
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitError
	}

	for name, script := range map[string]string{
		"pre-commit": preCommitHook,
		"pre-push":   prePushHook,
	} {
		if err := writeHook(filepath.Join(hooksDir, name), script); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", name, err)
			return exitError
		}
		fmt.Printf("✓ installed %s hook\n", name)
	}
	fmt.Println("\nGatehouse will now run before every commit and push.")
	fmt.Println("Bypass once with `git push --no-verify` (CI can re-run the same scan to catch bypasses).")
	return exitPass
}

const hookMarker = "# gatehouse-managed-hook"

const preCommitHook = `#!/bin/sh
` + hookMarker + `
# Fast, staged-scope checks (secrets, format). Target < 10s.
exec gatehouse scan . --profile pre-commit
`

const prePushHook = `#!/bin/sh
` + hookMarker + `
# Scan only what is being pushed, diffed against what the remote already has.
zero=0000000000000000000000000000000000000000
status=0
while read -r local_ref local_oid remote_ref remote_oid; do
  if [ "$remote_oid" = "$zero" ] || [ -z "$remote_oid" ]; then
    gatehouse scan . --profile pre-push || status=1
  else
    gatehouse scan . --profile pre-push --diff "$remote_oid" || status=1
  fi
done
exit $status
`

// writeHook installs a hook script, backing up any pre-existing non-Gatehouse
// hook so a user's own hook is never silently destroyed.
func writeHook(path, script string) error {
	if existing, err := os.ReadFile(path); err == nil {
		if !strings.Contains(string(existing), hookMarker) {
			backup := path + ".pre-gatehouse"
			if err := os.Rename(path, backup); err != nil {
				return fmt.Errorf("back up existing hook: %w", err)
			}
			fmt.Printf("  (backed up your existing %s → %s)\n", filepath.Base(path), filepath.Base(backup))
		}
	}
	return os.WriteFile(path, []byte(script), 0o755)
}

// detectHookManager returns the name of a hook manager in use, if any.
func detectHookManager(top string) string {
	candidates := map[string]string{
		".pre-commit-config.yaml": "pre-commit",
		"lefthook.yml":            "Lefthook",
		"lefthook.yaml":           "Lefthook",
		".husky":                  "Husky",
	}
	for file, name := range candidates {
		if _, err := os.Stat(filepath.Join(top, file)); err == nil {
			return name
		}
	}
	return ""
}

func printManagerGuidance(mgr string) {
	fmt.Printf("Detected %s — not overwriting its hooks. Add these entries instead:\n\n", mgr)
	switch mgr {
	case "pre-commit":
		fmt.Print(`  # .pre-commit-config.yaml
  - repo: local
    hooks:
      - id: gatehouse-pre-commit
        name: gatehouse
        entry: gatehouse scan . --profile pre-commit
        language: system
        pass_filenames: false
        stages: [commit]
      - id: gatehouse-pre-push
        name: gatehouse
        entry: gatehouse scan . --profile pre-push
        language: system
        pass_filenames: false
        stages: [push]
`)
	case "Lefthook":
		fmt.Print(`  # lefthook.yml
  pre-commit:
    commands:
      gatehouse: { run: gatehouse scan . --profile pre-commit }
  pre-push:
    commands:
      gatehouse: { run: gatehouse scan . --profile pre-push }
`)
	case "Husky":
		fmt.Print(`  # .husky/pre-commit
  gatehouse scan . --profile pre-commit

  # .husky/pre-push
  gatehouse scan . --profile pre-push
`)
	}
}
