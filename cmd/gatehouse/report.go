package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/gatehouse/gatehouse/internal/evidence"
	"github.com/gatehouse/gatehouse/internal/report"
	"github.com/gatehouse/gatehouse/internal/sbom"
	"github.com/gatehouse/gatehouse/internal/store"
)

// cmdReport renders a stored run in a chosen format (plan §10/§12):
//
//	gatehouse report <run-id> --format json|bundle
//
// The signed .tar.gz evidence bundle is the portable record of truth.
func cmdReport(args []string) int {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	format := fs.String("format", "json", "output format: json|sarif|html|bundle|cyclonedx|spdx")
	out := fs.String("out", "", "output file (default: stdout for json, <run-id>.tar.gz for bundle)")
	dbPath := fs.String("db", defaultDBPath(), "SQLite database path")

	runID := ""
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		runID = args[0]
		args = args[1:]
	}
	fs.Parse(args)
	if runID == "" {
		fmt.Fprintln(os.Stderr, "usage: gatehouse report <run-id> [--format json|bundle]")
		return exitError
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open db:", err)
		return exitError
	}
	defer st.Close()

	run, deny, warn, err := st.GetRun(runID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load run:", err)
		return exitError
	}
	if run == nil {
		fmt.Fprintf(os.Stderr, "no such run: %s\n", runID)
		return exitError
	}

	switch *format {
	case "json":
		w := os.Stdout
		if *out != "" {
			f, err := os.Create(*out)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return exitError
			}
			defer f.Close()
			w = f
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(run)
	case "bundle":
		signer, err := evidence.LoadOrCreateKey(defaultKeyPath())
		if err != nil {
			fmt.Fprintln(os.Stderr, "signing key:", err)
			return exitError
		}
		path := *out
		if path == "" {
			path = runID + ".tar.gz"
		}
		digest, err := evidence.ExportFile(path, *run, deny, warn, signer)
		if err != nil {
			fmt.Fprintln(os.Stderr, "export bundle:", err)
			return exitError
		}
		fmt.Printf("wrote signed evidence bundle %s\n  attestation sha256: %s\n  signer key id: %s\n", path, digest, signer.KeyID())
	case "cyclonedx", "spdx":
		var doc any
		if *format == "spdx" {
			doc = sbom.SPDX(*run)
		} else {
			doc = sbom.CycloneDX(*run)
		}
		w := os.Stdout
		if *out != "" {
			f, err := os.Create(*out)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return exitError
			}
			defer f.Close()
			w = f
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(doc)
	case "sarif", "html":
		w, closeFn, err := openOut(*out)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitError
		}
		defer closeFn()
		if *format == "sarif" {
			err = report.SARIF(w, *run)
		} else {
			err = report.HTML(w, *run, deny, warn)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "render:", err)
			return exitError
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown format %q (want json|sarif|html|bundle|cyclonedx|spdx)\n", *format)
		return exitError
	}
	return exitPass
}

// openOut returns a writer for the output path, or stdout when empty.
func openOut(path string) (io.Writer, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { f.Close() }, nil
}

func defaultKeyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "gatehouse-key.json"
	}
	return filepath.Join(home, ".gatehouse", "signing-key.json")
}

func defaultAuditPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "gatehouse-audit.log"
	}
	return filepath.Join(home, ".gatehouse", "audit.log")
}
