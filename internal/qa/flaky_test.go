package qa

import (
	"testing"

	"github.com/gatehouse/gatehouse/internal/model"
)

func key(suite, name string) string { return suite + "\x00" + name }

func TestFlakyWhenHistoryHasBothOutcomes(t *testing.T) {
	tests := []model.TestResult{{Suite: "unit", Name: "TestA", Status: "failed"}}
	history := map[string]Outcome{key("unit", "TestA"): {Pass: 5, Fail: 1}}
	out := Apply(tests, history, FlakyConfig{})
	if !out[0].Flaky {
		t.Fatal("a test that has both passed and failed should be flaky")
	}
}

func TestNotFlakyWhenAlwaysPassedThenFailsFirstTime(t *testing.T) {
	tests := []model.TestResult{{Suite: "unit", Name: "TestB", Status: "failed"}}
	history := map[string]Outcome{key("unit", "TestB"): {Pass: 10, Fail: 0}}
	out := Apply(tests, history, FlakyConfig{})
	if !out[0].Flaky {
		t.Fatal("pass history + a current fail means both outcomes seen → flaky")
	}
}

func TestStablePassingTestNotFlaky(t *testing.T) {
	tests := []model.TestResult{{Suite: "unit", Name: "TestC", Status: "passed"}}
	history := map[string]Outcome{key("unit", "TestC"): {Pass: 10, Fail: 0}}
	out := Apply(tests, history, FlakyConfig{})
	if out[0].Flaky {
		t.Fatal("a consistently passing test must not be flaky")
	}
}

func TestAutoQuarantineAfterThreshold(t *testing.T) {
	tests := []model.TestResult{{Suite: "unit", Name: "TestD", Status: "failed"}}
	history := map[string]Outcome{key("unit", "TestD"): {Pass: 2, Fail: 2}}
	// 2 historical fails + 1 current = 3 >= quarantine_after.
	out := Apply(tests, history, FlakyConfig{QuarantineAfter: 3})
	if !out[0].Quarantined {
		t.Fatal("flaky test at/over the fail threshold should be quarantined")
	}
}

func TestNoAutoQuarantineBelowThreshold(t *testing.T) {
	tests := []model.TestResult{{Suite: "unit", Name: "TestE", Status: "failed"}}
	history := map[string]Outcome{key("unit", "TestE"): {Pass: 5, Fail: 0}}
	out := Apply(tests, history, FlakyConfig{QuarantineAfter: 3})
	if out[0].Quarantined {
		t.Fatal("below threshold should not auto-quarantine")
	}
}

func TestManualQuarantine(t *testing.T) {
	tests := []model.TestResult{
		{Suite: "e2e", Name: "TestFlaky", Status: "failed"},
		{Suite: "e2e", Name: "TestOther", Status: "failed"},
	}
	out := Apply(tests, nil, FlakyConfig{Manual: []string{"e2e/TestFlaky"}})
	if !out[0].Quarantined {
		t.Error("manually listed test should be quarantined")
	}
	if out[1].Quarantined {
		t.Error("unlisted test should not be quarantined")
	}
}
