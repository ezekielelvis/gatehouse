package sandbox

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

// HostRuntime runs a plugin's host_command directly on the host with NO
// isolation whatsoever. It exists only so the end-to-end pipeline can be
// exercised on machines without a container runtime (e.g. CI for Gatehouse
// itself, or local dev). It provides none of the sandbox's guarantees — no
// read-only source, no network lockdown, no resource limits — so it must only
// ever be selected explicitly via an "unsafe host exec" flag and never be the
// default.
type HostRuntime struct{}

func NewHostRuntime() *HostRuntime { return &HostRuntime{} }

func (h *HostRuntime) Name() string { return "host (UNSAFE, no isolation)" }

func (h *HostRuntime) Available(ctx context.Context) error { return nil }

func (h *HostRuntime) Close() error { return nil }

func (h *HostRuntime) Run(ctx context.Context, spec Spec) (*Result, error) {
	argv := spec.HostCommand
	if len(argv) == 0 {
		return nil, errors.New("host runtime requires a host_command in the plugin manifest")
	}
	// Substitute the sandbox mount points with real host paths so the same
	// manifest command shape works in both runtimes.
	rep := strings.NewReplacer("/src", spec.SrcDir, "/out", spec.OutDir)
	resolved := make([]string, len(argv))
	for i, a := range argv {
		resolved[i] = rep.Replace(a)
	}

	runCtx := ctx
	var cancel context.CancelFunc
	if spec.Limits.Timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, spec.Limits.Timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(runCtx, resolved[0], resolved[1:]...)
	cmd.Dir = spec.SrcDir
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb

	start := time.Now()
	err := cmd.Run()
	res := &Result{
		Stdout:   out.Bytes(),
		Stderr:   errb.Bytes(),
		Duration: time.Since(start),
	}
	if runCtx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
		return res, nil
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.ExitCode = ee.ExitCode()
			return res, nil
		}
		return nil, err // couldn't even start the command
	}
	return res, nil
}
