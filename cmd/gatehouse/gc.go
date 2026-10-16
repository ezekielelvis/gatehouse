package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/gatehouse/gatehouse/internal/store"
)

// cmdGC applies retention (plan §10): keep the most recent N completed runs per
// repo+branch, but never prune runs tagged with the release context. Decisions
// and findings for pruned runs are removed via cascade; the small
// finding/decision history for kept runs stays.
func cmdGC(args []string) int {
	fs := flag.NewFlagSet("gc", flag.ExitOnError)
	keep := fs.Int("keep", 50, "runs to keep per repo+branch (release runs are always kept)")
	dbPath := fs.String("db", defaultDBPath(), "SQLite database path")
	fs.Parse(args)

	st, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open db:", err)
		return exitError
	}
	defer st.Close()

	n, err := st.GC(*keep)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gc:", err)
		return exitError
	}
	fmt.Printf("pruned %d run(s); kept the newest %d per branch plus all release runs\n", n, *keep)
	return exitPass
}
