// Package qa holds test-quality logic that makes a test suite trustworthy
// enough to gate on (plan §8): flaky-test detection and quarantine. It is pure
// (model + plain inputs) so it is easy to test and reason about.
package qa

import (
	"strings"

	"github.com/gatehouse/gatehouse/internal/model"
)

// Outcome is a test's historical pass/fail tally from prior runs.
type Outcome struct {
	Pass int
	Fail int
}

// FlakyConfig controls quarantine behaviour.
type FlakyConfig struct {
	// QuarantineAfter: a flaky test with at least this many failing runs
	// (including the current one) is auto-quarantined. 0 disables auto-quarantine.
	QuarantineAfter int
	// Manual lists tests to quarantine unconditionally, as "name" or "suite/name".
	Manual []string
}

// Apply annotates each test with Flaky and Quarantined, combining its current
// result with its history. A test is flaky when it has both passed and failed
// across the observed window; a flaky test is auto-quarantined once it has
// failed in at least QuarantineAfter runs, and any test in the manual list is
// quarantined outright. Quarantined failing tests do not block the gate (the
// baseline policy skips them), which keeps a known-bad test from wedging every
// push while it is being fixed.
func Apply(tests []model.TestResult, history map[string]Outcome, cfg FlakyConfig) []model.TestResult {
	manual := manualSet(cfg.Manual)
	out := make([]model.TestResult, len(tests))
	for i, t := range tests {
		key := t.Suite + "\x00" + t.Name
		h := history[key]
		pass := h.Pass
		fail := h.Fail
		switch t.Status {
		case "passed":
			pass++
		case "failed":
			fail++
		}

		t.Flaky = pass > 0 && fail > 0
		switch {
		case manual[t.Name] || manual[t.Suite+"/"+t.Name]:
			t.Quarantined = true
		case t.Flaky && cfg.QuarantineAfter > 0 && fail >= cfg.QuarantineAfter:
			t.Quarantined = true
		}
		out[i] = t
	}
	return out
}

func manualSet(list []string) map[string]bool {
	m := make(map[string]bool, len(list))
	for _, s := range list {
		m[strings.TrimSpace(s)] = true
	}
	return m
}
