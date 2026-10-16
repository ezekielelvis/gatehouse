package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestPodmanLiveSandbox exercises the real DockerRuntime against a running
// Docker-compatible daemon (Docker or Podman). It is gated on GATEHOUSE_LIVE=1
// so the normal suite stays hermetic. It asserts the sandbox's core promises
// from plan §4: read-only /src, writable /out, and no network by default.
//
//	GATEHOUSE_LIVE=1 DOCKER_HOST=unix:///var/run/docker.sock \
//	  go test ./internal/sandbox -run TestPodmanLive -v
func TestPodmanLiveSandbox(t *testing.T) {
	if os.Getenv("GATEHOUSE_LIVE") != "1" {
		t.Skip("set GATEHOUSE_LIVE=1 to run the live container sandbox test")
	}
	rt, err := NewDockerRuntime()
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := rt.Available(ctx); err != nil {
		t.Fatalf("runtime not available: %v", err)
	}
	t.Logf("runtime backend reachable")

	srcDir := t.TempDir()
	outDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "hello.txt"), []byte("SOURCE-OK"), 0o644); err != nil {
		t.Fatal(err)
	}

	// The command probes each guarantee and records the result in /out.
	script := `
set +e
cat /src/hello.txt > /out/read.txt
touch /src/evil 2>/dev/null && echo "WROTE-SRC" > /out/write.txt || echo "SRC-READONLY" > /out/write.txt
( wget -T 3 -q -O- http://1.1.1.1 >/dev/null 2>&1 && echo "HAS-NET" || echo "NO-NET" ) > /out/net.txt
id -u > /out/uid.txt
echo done
`
	spec := Spec{
		StepID:  "live-probe",
		Image:   "docker.io/library/alpine:3.20",
		Command: []string{"sh", "-c", script},
		SrcDir:  srcDir,
		OutDir:  outDir,
		Network: NetworkNone,
		Limits:  Limits{Timeout: 90 * time.Second, Memory: 256 << 20, PidLimit: 128},
	}

	res, err := rt.Run(ctx, spec)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	t.Logf("exit=%d timedOut=%v stdout=%q", res.ExitCode, res.TimedOut, strings.TrimSpace(string(res.Stdout)))

	read := readOut(t, outDir, "read.txt")
	if read != "SOURCE-OK" {
		t.Errorf("/src not readable as expected: %q", read)
	}
	if w := readOut(t, outDir, "write.txt"); w != "SRC-READONLY" {
		t.Errorf("/src must be read-only, probe said: %q", w)
	}
	if n := readOut(t, outDir, "net.txt"); n != "NO-NET" {
		t.Errorf("network must be off by default, probe said: %q", n)
	}
	if uid := readOut(t, outDir, "uid.txt"); uid == "0" {
		t.Errorf("container should run non-root, uid=%s", uid)
	} else {
		t.Logf("container uid=%s (non-root)", uid)
	}
}

func readOut(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("missing /out/%s: %v", name, err)
	}
	return strings.TrimSpace(string(b))
}
