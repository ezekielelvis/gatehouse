// Command gatehouse is the single-binary core: daemon, CLI and git-hook entry
// point for the local code-assurance platform (plan §12). Subcommands:
//
//	gatehouse version
//	gatehouse scan <path> [--diff <base>] [--profile <ctx>] [--unsafe-host-exec]
//	gatehouse policy test
//	gatehouse serve [--addr]
//
// Exit codes (plan §12): 0 pass, 1 fail (policy denied), 2 warn-only, 3
// tool/infra error.
package main

import (
	"fmt"
	"os"
)

// Build metadata, overridable via -ldflags "-X main.version=...".
var version = "0.1.0-dev"

const (
	exitPass  = 0
	exitFail  = 1
	exitWarn  = 2
	exitError = 3
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(exitError)
	}
	var code int
	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Printf("gatehouse %s\n", version)
	case "scan":
		code = cmdScan(os.Args[2:])
	case "policy":
		code = cmdPolicy(os.Args[2:])
	case "hook":
		code = cmdHook(os.Args[2:])
	case "db":
		code = cmdDB(os.Args[2:])
	case "verify":
		code = cmdVerify(os.Args[2:])
	case "gc":
		code = cmdGC(os.Args[2:])
	case "report":
		code = cmdReport(os.Args[2:])
	case "compliance":
		code = cmdCompliance(os.Args[2:])
	case "audit":
		code = cmdAudit(os.Args[2:])
	case "serve":
		code = cmdServe(os.Args[2:])
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		code = exitError
	}
	os.Exit(code)
}

func usage() {
	fmt.Fprint(os.Stderr, `gatehouse — local code assurance platform

Usage:
  gatehouse scan <path> [flags]   Scan a repo and apply the policy gate
  gatehouse policy test           Validate the built-in policy packs
  gatehouse hook install          Install pre-commit + pre-push git hooks
  gatehouse report <run-id>       Render a stored run (--format json|bundle)
  gatehouse compliance <run-id>   Map a run onto a standard (--standard)
  gatehouse audit verify          Re-check the hash-chained evidence log
  gatehouse db update --from DIR  Import CVSS/EPSS/KEV mirror feeds
  gatehouse verify <commit>       Verify the signed git-notes attestation
  gatehouse gc [--keep N]         Apply run-history retention
  gatehouse serve [flags]         Start the local web UI / API
  gatehouse version               Print version

Run "gatehouse <command> -h" for command flags.
`)
}
