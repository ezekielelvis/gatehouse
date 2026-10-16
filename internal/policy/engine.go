package policy

import (
	"context"
	"fmt"
	"sort"

	"github.com/gatehouse/gatehouse/internal/model"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

// Decision is the outcome of evaluating all policy layers against a run.
type Decision struct {
	Verdict model.Verdict `json:"verdict"`
	Deny    []string      `json:"deny"`
	Warn    []string      `json:"warn"`
}

// Module is one named Rego source file (a policy layer or pack member).
type Module struct {
	Name   string
	Source string
}

// Engine evaluates Rego policies. Gatehouse convention: policies live in
// package gatehouse.gates and contribute to two string sets, deny and warn.
// Any deny message fails the run; otherwise any warn message warns; otherwise
// the run passes.
type Engine struct {
	deny prepared
	warn prepared
}

type prepared struct {
	q rego.PreparedEvalQuery
}

// New compiles the given modules into an evaluatable engine. Network- and
// environment-reaching builtins (http.send, opa.runtime, …) are stripped from
// the capabilities so a malicious shared policy pack cannot exfiltrate or probe
// the host (plan §14).
func New(ctx context.Context, modules ...Module) (*Engine, error) {
	caps := restrictedCapabilities()

	build := func(query string) (prepared, error) {
		opts := []func(*rego.Rego){
			rego.Query(query),
			rego.Capabilities(caps),
		}
		for _, m := range modules {
			opts = append(opts, rego.Module(m.Name, m.Source))
		}
		r := rego.New(opts...)
		pq, err := r.PrepareForEval(ctx)
		if err != nil {
			return prepared{}, fmt.Errorf("compile policy (%s): %w", query, err)
		}
		return prepared{q: pq}, nil
	}

	deny, err := build("data.gatehouse.gates.deny")
	if err != nil {
		return nil, err
	}
	warn, err := build("data.gatehouse.gates.warn")
	if err != nil {
		return nil, err
	}
	return &Engine{deny: deny, warn: warn}, nil
}

// Evaluate runs the policies against a run and returns the decision.
func (e *Engine) Evaluate(ctx context.Context, run model.Run) (Decision, error) {
	input := BuildInput(run)

	deny, err := e.deny.eval(ctx, input)
	if err != nil {
		return Decision{}, err
	}
	warn, err := e.warn.eval(ctx, input)
	if err != nil {
		return Decision{}, err
	}

	d := Decision{Deny: deny, Warn: warn, Verdict: model.VerdictPass}
	switch {
	case len(deny) > 0:
		d.Verdict = model.VerdictFail
	case len(warn) > 0:
		d.Verdict = model.VerdictWarn
	}
	return d, nil
}

func (p prepared) eval(ctx context.Context, input map[string]any) ([]string, error) {
	rs, err := p.q.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("evaluate policy: %w", err)
	}
	set := map[string]struct{}{}
	for _, r := range rs {
		for _, expr := range r.Expressions {
			// The query evaluates a set of strings; OPA returns it as a []any.
			items, ok := expr.Value.([]any)
			if !ok {
				continue
			}
			for _, it := range items {
				if s, ok := it.(string); ok {
					set[s] = struct{}{}
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out, nil
}

// restrictedCapabilities returns the default builtin set with any builtin that
// reaches the network or the host environment removed, so user and shared
// policies are pure functions of their input.
func restrictedCapabilities() *ast.Capabilities {
	caps := ast.CapabilitiesForThisVersion()
	blocked := map[string]bool{
		"http.send":          true,
		"net.lookup_ip_addr": true,
		"opa.runtime":        true,
		"rego.parse_module":  true,
		"trace":              true,
		"time.now_ns":        false, // allowed: deterministic enough and useful
	}
	filtered := caps.Builtins[:0]
	for _, b := range caps.Builtins {
		if blocked[b.Name] {
			continue
		}
		filtered = append(filtered, b)
	}
	caps.Builtins = filtered
	return caps
}
