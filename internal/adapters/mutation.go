package adapters

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/gatehouse/gatehouse/internal/model"
)

// Mutation tools (Gremlins, Stryker, PIT, mutmut, cargo-mutants) each have their
// own report format, so a plugin wraps its tool to emit a tiny normalised JSON:
//
//	{"killed": 42, "total": 50}   or   {"score": 84.0}
//
// ParseMutation reads that and returns the mutation-score metric (0-100), the
// single number the gate and trend views care about (plan §8).
type mutationReport struct {
	Killed  int     `json:"killed"`
	Total   int     `json:"total"`
	Score   float64 `json:"score"`
	Timeout int     `json:"timeout"`
}

// ParseMutation returns the mutation.score metric from a normalised report.
func ParseMutation(r io.Reader) ([]model.Metric, error) {
	var rep mutationReport
	if err := json.NewDecoder(r).Decode(&rep); err != nil {
		return nil, fmt.Errorf("decode mutation report: %w", err)
	}
	score := rep.Score
	if score == 0 && rep.Total > 0 {
		score = float64(rep.Killed) / float64(rep.Total) * 100
	}
	return []model.Metric{{Key: "mutation.score", Value: score}}, nil
}
