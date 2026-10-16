package findings

import "github.com/gatehouse/gatehouse/internal/model"

// Diff classifies each finding in cur against the base run's findings, setting
// Status to new/existing, and returns any base findings absent from cur as
// "fixed". Matching is purely by fingerprint, which is why the fingerprint must
// be stable across unrelated code movement (see Fingerprint).
//
// Default gates block only on "new" findings, which is what makes Gatehouse
// usable on a large legacy codebase: pre-existing issues are reported but do
// not fail the push until a remediation-SLA policy promotes them.
func Diff(cur []model.Finding, base []model.Finding) (classified []model.Finding, fixed []model.Finding) {
	baseSet := make(map[string]model.Finding, len(base))
	for _, f := range base {
		baseSet[f.Fingerprint] = f
	}
	curSet := make(map[string]struct{}, len(cur))

	classified = make([]model.Finding, len(cur))
	for i, f := range cur {
		curSet[f.Fingerprint] = struct{}{}
		if _, ok := baseSet[f.Fingerprint]; ok {
			f.Status = model.StatusExisting
		} else {
			f.Status = model.StatusNew
		}
		classified[i] = f
	}

	for fp, f := range baseSet {
		if _, ok := curSet[fp]; !ok {
			f.Status = model.StatusFixed
			fixed = append(fixed, f)
		}
	}
	return classified, fixed
}
