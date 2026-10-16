package sandbox

import (
	"context"
	"fmt"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
)

// StartServices brings up the declared service containers on a fresh internal
// (no-egress) network, so integration/e2e tests can reach them by name while
// nothing can call out (plan §8). It returns the network name and a cleanup
// func that removes the services and the network. DockerRuntime satisfies
// sandbox.ServiceRunner.
func (d *DockerRuntime) StartServices(ctx context.Context, runID string, services []ServiceSpec) (string, func(), error) {
	netName := "gatehouse-net-" + runID
	if _, err := d.cli.NetworkCreate(ctx, netName, network.CreateOptions{Driver: "bridge", Internal: true}); err != nil {
		return "", nil, fmt.Errorf("create internal network: %w", err)
	}

	var started []string
	cleanup := func() {
		rmCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, id := range started {
			_ = d.cli.ContainerRemove(rmCtx, id, container.RemoveOptions{Force: true})
		}
		_ = d.cli.NetworkRemove(rmCtx, netName)
	}

	for _, svc := range services {
		if err := d.ensureImage(ctx, svc.Image); err != nil {
			cleanup()
			return "", nil, err
		}
		env := make([]string, 0, len(svc.Env))
		for k, v := range svc.Env {
			env = append(env, k+"="+v)
		}
		cfg := &container.Config{Image: svc.Image, Env: env}
		hostCfg := &container.HostConfig{
			NetworkMode: container.NetworkMode(netName),
			// Services get least privilege too, but they are trusted official
			// images, so we don't force read-only rootfs (DBs need to write).
			CapDrop:     []string{"ALL"},
			SecurityOpt: []string{"no-new-privileges"},
		}
		netCfg := &network.NetworkingConfig{
			EndpointsConfig: map[string]*network.EndpointSettings{
				netName: {Aliases: []string{svc.Name}},
			},
		}
		created, err := d.cli.ContainerCreate(ctx, cfg, hostCfg, netCfg, nil, "gatehouse-svc-"+runID+"-"+svc.Name)
		if err != nil {
			cleanup()
			return "", nil, fmt.Errorf("create service %s: %w", svc.Name, err)
		}
		started = append(started, created.ID)
		if err := d.cli.ContainerStart(ctx, created.ID, container.StartOptions{}); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("start service %s: %w", svc.Name, err)
		}
	}
	return netName, cleanup, nil
}
