package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

// DockerRuntime drives the Docker Engine API. It targets Docker or Podman's
// Docker-compatible socket identically — the plan treats both as equal
// citizens — so DOCKER_HOST may point at either (e.g.
// unix://$XDG_RUNTIME_DIR/podman/podman.sock for rootless Podman).
type DockerRuntime struct {
	cli *client.Client
}

// NewDockerRuntime connects using the environment (DOCKER_HOST, etc.).
func NewDockerRuntime() (*DockerRuntime, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("connect to container runtime: %w", err)
	}
	return &DockerRuntime{cli: cli}, nil
}

func (d *DockerRuntime) Name() string { return "docker" }

func (d *DockerRuntime) Available(ctx context.Context) error {
	_, err := d.cli.Ping(ctx)
	if err != nil {
		return fmt.Errorf("container runtime not reachable: %w", err)
	}
	return nil
}

func (d *DockerRuntime) Close() error { return d.cli.Close() }

func (d *DockerRuntime) Run(ctx context.Context, spec Spec) (*Result, error) {
	if err := d.ensureImage(ctx, spec.Image); err != nil {
		return nil, err
	}

	runCtx := ctx
	if spec.Limits.Timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, spec.Limits.Timeout)
		defer cancel()
	}

	cfg, hostCfg := d.buildConfig(spec)

	created, err := d.cli.ContainerCreate(runCtx, cfg, hostCfg, nil, nil, "gatehouse-"+spec.StepID)
	if err != nil {
		return nil, fmt.Errorf("create container: %w", err)
	}
	// Always remove the container, even on timeout/cancel: use a fresh context
	// because runCtx may already be done.
	defer func() {
		rmCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = d.cli.ContainerRemove(rmCtx, created.ID, container.RemoveOptions{Force: true})
	}()

	start := time.Now()
	if err := d.cli.ContainerStart(runCtx, created.ID, container.StartOptions{}); err != nil {
		return nil, fmt.Errorf("start container: %w", err)
	}

	statusCh, errCh := d.cli.ContainerWait(runCtx, created.ID, container.WaitConditionNotRunning)
	res := &Result{}
	select {
	case err := <-errCh:
		if err != nil {
			if runCtx.Err() == context.DeadlineExceeded {
				res.TimedOut = true
				res.Duration = time.Since(start)
				return res, nil
			}
			return nil, fmt.Errorf("wait container: %w", err)
		}
	case st := <-statusCh:
		res.ExitCode = int(st.StatusCode)
	}
	res.Duration = time.Since(start)

	res.Stdout, res.Stderr = d.logs(context.Background(), created.ID)
	return res, nil
}

// buildConfig translates a Spec into the hardened container configuration from
// plan §4: read-only source, writable /out only, read-only rootfs with a tmpfs
// /tmp, no network by default, all capabilities dropped, no privilege
// escalation, non-root, and resource caps.
func (d *DockerRuntime) buildConfig(spec Spec) (*container.Config, *container.HostConfig) {
	env := make([]string, 0, len(spec.Env))
	for k, v := range spec.Env {
		env = append(env, k+"="+v)
	}

	cfg := &container.Config{
		Image:      spec.Image,
		Cmd:        spec.Command,
		Env:        env,
		WorkingDir: "/src",
		User:       "65532:65532", // nonroot (distroless convention)
	}

	netMode := "none"
	switch {
	case spec.NetworkName != "":
		netMode = spec.NetworkName // pre-created internal network for e2e/services
	case spec.Network == NetworkInternal:
		netMode = "gatehouse-internal"
	case spec.Network == NetworkPrepare:
		netMode = "gatehouse-egress" // routed through the approved-registry proxy
	}

	hostCfg := &container.HostConfig{
		Mounts: []mount.Mount{
			{Type: mount.TypeBind, Source: spec.SrcDir, Target: "/src", ReadOnly: true},
			{Type: mount.TypeBind, Source: spec.OutDir, Target: "/out"},
		},
		ReadonlyRootfs: true,
		Tmpfs:          map[string]string{"/tmp": "rw,noexec,nosuid,size=256m"},
		NetworkMode:    container.NetworkMode(netMode),
		CapDrop:        []string{"ALL"},
		SecurityOpt:    []string{"no-new-privileges"},
		AutoRemove:     false, // we remove explicitly to read logs first
		Resources:      d.resources(spec.Limits),
	}
	return cfg, hostCfg
}

func (d *DockerRuntime) resources(l Limits) container.Resources {
	r := container.Resources{}
	if l.Memory > 0 {
		r.Memory = l.Memory
	}
	if l.CPUs > 0 {
		r.NanoCPUs = int64(l.CPUs * 1e9)
	}
	if l.PidLimit > 0 {
		pl := l.PidLimit
		r.PidsLimit = &pl
	}
	return r
}

// ensureImage pulls the image if it is not already present. In production the
// orchestrator verifies digests and signatures before this point (plan §14);
// here we only guarantee the image exists locally.
func (d *DockerRuntime) ensureImage(ctx context.Context, ref string) error {
	if _, err := d.cli.ImageInspect(ctx, ref); err == nil {
		return nil
	}
	rc, err := d.cli.ImagePull(ctx, ref, image.PullOptions{})
	if err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}
	defer rc.Close()
	_, _ = io.Copy(io.Discard, rc) // drain so the pull completes
	return nil
}

func (d *DockerRuntime) logs(ctx context.Context, id string) (stdout, stderr []byte) {
	rc, err := d.cli.ContainerLogs(ctx, id, container.LogsOptions{ShowStdout: true, ShowStderr: true})
	if err != nil {
		return nil, nil
	}
	defer rc.Close()
	var out, errb bytes.Buffer
	_, _ = stdcopy.StdCopy(&out, &errb, rc)
	return out.Bytes(), errb.Bytes()
}
