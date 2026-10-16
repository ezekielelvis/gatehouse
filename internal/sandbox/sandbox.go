// Package sandbox executes one plugin against a read-only source snapshot in a
// locked-down environment and collects the files it wrote to /out. The sandbox
// is the product's core security promise (see plan §4): nothing a scanner or
// test does can touch the user's repo, home directory, network or the host
// container runtime.
//
// Two Runtime implementations exist:
//
//   - DockerRuntime  — the real sandbox, driving Docker or Podman's
//     Docker-compatible API with the hardened flags below. Used in production.
//   - HostRuntime    — a DEV-ONLY fallback that runs a plugin's host_command
//     directly on the host with NO isolation. It exists so the pipeline can be
//     exercised where no container runtime is available; it must never be the
//     default and loudly advertises that it is unsafe.
package sandbox

import (
	"context"
	"time"
)

// Limits caps a step's resource use to stop runaway tests, fork bombs and
// crypto-miners.
type Limits struct {
	Memory   int64         // bytes; 0 = runtime default
	CPUs     float64       // fractional CPUs; 0 = unlimited
	PidLimit int64         // max processes; 0 = runtime default
	Timeout  time.Duration // wall-clock; 0 = no timeout
}

// Network is the network policy for a step.
type Network string

const (
	NetworkNone     Network = "none"     // --network=none; the default
	NetworkInternal Network = "internal" // private internal net (service containers only)
	NetworkPrepare  Network = "prepare"  // egress via the approved-registry proxy
)

// Spec fully describes one sandboxed execution.
type Spec struct {
	// StepID is a unique, filesystem-safe identifier for this step (used to
	// name the container and the /out directory).
	StepID string
	// Image is the fully-pinned image reference (digest form expected in prod).
	Image string
	// Command is argv executed in the container.
	Command []string
	// SrcDir is the host path mounted read-only at /src.
	SrcDir string
	// OutDir is the host path mounted writable at /out; results are read back
	// from here after the run.
	OutDir string
	// Network policy. Defaults to NetworkNone when empty.
	Network Network
	// Limits caps resources.
	Limits Limits
	// Env passes additional environment variables (never secrets).
	Env map[string]string
	// HostCommand is the dev-only command for HostRuntime (ignored by Docker).
	HostCommand []string
	// NetworkName, when set, attaches the container to this pre-created network
	// instead of the default for Network (used for the e2e/services phase so the
	// test runner can reach the service containers). Implies an internal network.
	NetworkName string
}

// ServiceSpec is one dependency container (Postgres, Redis, …) brought up on a
// private internal network for integration/e2e tests (plan §8).
type ServiceSpec struct {
	Name  string // network alias the app uses to reach it
	Image string
	Env   map[string]string
}

// ServiceRunner is implemented by runtimes that can bring up a private network
// with service containers for the e2e phase. Only the real container runtime
// implements it; the orchestrator skips the e2e phase otherwise.
type ServiceRunner interface {
	// StartServices creates an internal network named for runID, starts each
	// service attached to it, and returns the network name plus a cleanup func
	// that tears everything down. The network has no egress.
	StartServices(ctx context.Context, runID string, services []ServiceSpec) (network string, cleanup func(), err error)
}

// Result is the outcome of a sandboxed execution.
type Result struct {
	ExitCode int
	Stdout   []byte
	Stderr   []byte
	Duration time.Duration
	// TimedOut is true if the step was killed by the wall-clock timeout.
	TimedOut bool
}

// Runtime runs sandboxed steps. Implementations must honour Spec's isolation
// contract (or, for HostRuntime, loudly document that they do not).
type Runtime interface {
	// Name identifies the backend (e.g. "docker", "podman", "host").
	Name() string
	// Available reports whether the backend can be used right now.
	Available(ctx context.Context) error
	// Run executes one step to completion (or timeout) and returns its result.
	Run(ctx context.Context, spec Spec) (*Result, error)
	// Close releases any backend resources.
	Close() error
}
