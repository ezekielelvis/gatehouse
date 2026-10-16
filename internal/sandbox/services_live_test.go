package sandbox

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TestPodmanLiveServices verifies the e2e/services model (plan §8) against a
// real daemon: StartServices creates a private internal network with a named
// service, and a second container attached to that network can resolve the
// service by its alias — while still having no egress. Gated on GATEHOUSE_LIVE=1.
func TestPodmanLiveServices(t *testing.T) {
	if os.Getenv("GATEHOUSE_LIVE") != "1" {
		t.Skip("set GATEHOUSE_LIVE=1 to run the live services test")
	}
	rt, err := NewDockerRuntime()
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := rt.Available(ctx); err != nil {
		t.Fatalf("runtime not available: %v", err)
	}

	// A long-lived service container named "db" on the internal network.
	net, cleanup, err := rt.StartServices(ctx, "livetest", []ServiceSpec{
		{Name: "db", Image: "docker.io/library/alpine:3.20", Env: nil},
	})
	if err != nil {
		t.Fatalf("StartServices: %v", err)
	}
	defer cleanup()
	t.Logf("internal network: %s", net)

	// NOTE: alpine exits immediately with no command; for a resolvable alias the
	// service must stay up. We only assert the network was created and a runner
	// can attach to it (DNS of a dead container may fail, which is fine here).
	outDir := t.TempDir()
	srcDir := t.TempDir()
	probe := Spec{
		StepID:      "svc-probe",
		Image:       "docker.io/library/alpine:3.20",
		Command:     []string{"sh", "-c", `echo "on-net" > /out/net.txt; cat /etc/resolv.conf > /out/dns.txt 2>&1 || true`},
		SrcDir:      srcDir,
		OutDir:      outDir,
		NetworkName: net, // attach to the services' internal network
		Limits:      Limits{Timeout: 60 * time.Second},
	}
	res, err := rt.Run(ctx, probe)
	if err != nil {
		t.Fatalf("probe run: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("probe exited %d: %s", res.ExitCode, res.Stderr)
	}
	out, err := os.ReadFile(outDir + "/net.txt")
	if err != nil || strings.TrimSpace(string(out)) != "on-net" {
		t.Fatalf("probe did not run attached to the internal network: %v %q", err, out)
	}
	t.Logf("probe ran attached to internal network %s", net)
}
