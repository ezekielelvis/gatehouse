package waivers

import (
	"testing"
	"time"

	"github.com/gatehouse/gatehouse/internal/model"
)

func mustParse(t *testing.T, doc string) *Set {
	t.Helper()
	s, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestWaiverByFingerprint(t *testing.T) {
	s := mustParse(t, `
waivers:
  - id: W-1
    fingerprint: abc123
    reason: accepted risk
    owner: alice
    expires: 2999-01-01
`)
	fs := []model.Finding{{Fingerprint: "abc123", RuleID: "r"}, {Fingerprint: "other"}}
	fs, applied := s.Apply(fs, time.Now())
	if fs[0].WaiverID != "W-1" {
		t.Errorf("fingerprint waiver not applied: %q", fs[0].WaiverID)
	}
	if fs[1].WaiverID != "" {
		t.Errorf("unrelated finding should not be waived")
	}
	if len(applied) != 1 || applied[0] != "W-1" {
		t.Errorf("applied set wrong: %v", applied)
	}
}

func TestWaiverByRuleAndGlob(t *testing.T) {
	s := mustParse(t, `
waivers:
  - id: W-2
    rule: generic-api-key
    path: "testdata/*"
    reason: fixtures
    owner: bob
    expires: 2999-01-01
`)
	fs := []model.Finding{
		{RuleID: "generic-api-key", Path: "testdata/a.go"},
		{RuleID: "generic-api-key", Path: "src/a.go"},
	}
	fs, _ = s.Apply(fs, time.Now())
	if fs[0].WaiverID != "W-2" {
		t.Error("glob should match testdata/a.go")
	}
	if fs[1].WaiverID != "" {
		t.Error("glob should not match src/a.go")
	}
}

func TestExpiredWaiverDoesNotApply(t *testing.T) {
	s := mustParse(t, `
waivers:
  - id: W-3
    fingerprint: abc
    reason: temporary
    owner: carol
    expires: 2020-01-01
`)
	fs := []model.Finding{{Fingerprint: "abc"}}
	fs, applied := s.Apply(fs, time.Now())
	if fs[0].WaiverID != "" {
		t.Error("expired waiver must not apply")
	}
	if len(applied) != 0 {
		t.Error("no waivers should be reported applied")
	}
}

func TestWaiverRequiresExpiry(t *testing.T) {
	if _, err := Parse([]byte(`
waivers:
  - id: W-4
    fingerprint: abc
    reason: no expiry
    owner: dave
`)); err == nil {
		t.Fatal("expected error: waivers must have a mandatory expiry")
	}
}

func TestLoadMissingFileIsEmpty(t *testing.T) {
	s, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Waivers) != 0 {
		t.Fatal("absent waivers file should yield an empty set")
	}
}
