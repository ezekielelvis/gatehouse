package main

import (
	"fmt"
	"os"

	"github.com/gatehouse/gatehouse/internal/evidence"
)

// cmdAudit implements "gatehouse audit verify", which re-checks the hash-chained
// audit log end to end (plan §10). A broken chain means the local evidence
// history was tampered with.
func cmdAudit(args []string) int {
	if len(args) == 0 || args[0] != "verify" {
		fmt.Fprintln(os.Stderr, "usage: gatehouse audit verify")
		return exitError
	}
	log, err := evidence.OpenAuditLog(defaultAuditPath())
	if err != nil {
		fmt.Fprintln(os.Stderr, "open audit log:", err)
		return exitError
	}
	n, err := log.Verify()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ audit chain INVALID after %d entries: %v\n", n, err)
		return exitFail
	}
	fmt.Printf("✓ audit chain verified: %d entries intact\n", n)
	return exitPass
}
