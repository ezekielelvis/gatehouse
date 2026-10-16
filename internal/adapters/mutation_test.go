package adapters

import (
	"strings"
	"testing"
)

func TestParseMutationScoreDirect(t *testing.T) {
	ms, err := ParseMutation(strings.NewReader(`{"score": 84.0}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].Key != "mutation.score" || ms[0].Value != 84.0 {
		t.Fatalf("unexpected metric: %+v", ms)
	}
}

func TestParseMutationFromKilledTotal(t *testing.T) {
	ms, err := ParseMutation(strings.NewReader(`{"killed": 42, "total": 50}`))
	if err != nil {
		t.Fatal(err)
	}
	if ms[0].Value != 84.0 {
		t.Fatalf("want 84%% (42/50), got %v", ms[0].Value)
	}
}

func TestParseMutationZeroTotalIsZero(t *testing.T) {
	ms, _ := ParseMutation(strings.NewReader(`{"killed": 0, "total": 0}`))
	if ms[0].Value != 0 {
		t.Fatalf("empty mutation run should score 0, got %v", ms[0].Value)
	}
}
