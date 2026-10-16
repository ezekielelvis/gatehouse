package policy_test

import (
	"context"
	"testing"

	"github.com/gatehouse/gatehouse/internal/model"
	"github.com/gatehouse/gatehouse/internal/policy"
	"github.com/gatehouse/gatehouse/policies"
)

func TestBaselineWarnsOnErroredCheck(t *testing.T) {
	mods, _ := policies.Baseline()
	eng, err := policy.New(context.Background(), mods...)
	if err != nil {
		t.Fatal(err)
	}
	run := model.Run{
		Context: model.ContextPrePush,
		Steps:   []model.Step{{PluginID: "opengrep", Errored: true, Error: "image pull failed"}},
	}
	d, err := eng.Evaluate(context.Background(), run)
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != model.VerdictWarn {
		t.Fatalf("an errored security check should warn, got %s (warn=%v)", d.Verdict, d.Warn)
	}
}
