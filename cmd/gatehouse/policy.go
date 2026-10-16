package main

import (
	"context"
	"fmt"
	"os"

	"github.com/gatehouse/gatehouse/internal/policy"
	"github.com/gatehouse/gatehouse/policies"
)

// cmdPolicy currently supports "policy test", which compiles every built-in
// pack to confirm it is valid Rego and evaluatable. In later phases this grows
// into `opa test` of the packs' unit tests (plan §9).
func cmdPolicy(args []string) int {
	if len(args) == 0 || args[0] != "test" {
		fmt.Fprintln(os.Stderr, "usage: gatehouse policy test")
		return exitError
	}
	ctx := context.Background()
	packs := []string{"baseline", "strict-release", "owasp-top10", "oss-library", "iac-hardening"}
	ok := true
	for _, name := range packs {
		mods, err := policies.Pack(name)
		if err != nil {
			fmt.Printf("✗ %s: %v\n", name, err)
			ok = false
			continue
		}
		if _, err := policy.New(ctx, mods...); err != nil {
			fmt.Printf("✗ %s: %v\n", name, err)
			ok = false
			continue
		}
		fmt.Printf("✓ %s (%d modules) compiles\n", name, len(mods))
	}
	if !ok {
		return exitError
	}
	return exitPass
}
