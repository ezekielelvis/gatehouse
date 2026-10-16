package evidence

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gatehouse/gatehouse/internal/model"
)

func testRun() model.Run {
	return model.Run{
		ID: "r1", RepoPath: "/repo", Ref: "working-tree", TreeHash: "deadbeef",
		Context: model.ContextPrePush, Verdict: model.VerdictFail, Status: "done",
		FinishedAt: time.Now().UTC(),
		Findings:   []model.Finding{{Fingerprint: "fp", Status: model.StatusNew}},
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	key, err := LoadOrCreateKey(filepath.Join(t.TempDir(), "k.json"))
	if err != nil {
		t.Fatal(err)
	}
	env, err := Attest(testRun(), []string{"blocked"}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := Verify(env, key.Public())
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if stmt.Predicate.RunID != "r1" || stmt.Predicate.Verdict != model.VerdictFail {
		t.Fatalf("predicate not round-tripped: %+v", stmt.Predicate)
	}
	if stmt.Predicate.NewFindings != 1 {
		t.Errorf("new findings count wrong: %d", stmt.Predicate.NewFindings)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	key, _ := LoadOrCreateKey(filepath.Join(t.TempDir(), "k.json"))
	env, _ := Attest(testRun(), nil, nil, key)
	// Flip the payload after signing.
	env.Payload = env.Payload[:len(env.Payload)-4] + "AAAA"
	if _, err := Verify(env, key.Public()); err == nil {
		t.Fatal("verify must reject a tampered payload")
	}
}

func TestKeyPersistsAcrossLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.json")
	k1, _ := LoadOrCreateKey(path)
	k2, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if k1.KeyID() != k2.KeyID() {
		t.Fatal("reloading the key should yield the same key id")
	}
}

func TestAuditChainVerifies(t *testing.T) {
	log, err := OpenAuditLog(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := log.Append("alice", "run", []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	n, err := log.Verify()
	if err != nil {
		t.Fatalf("chain should verify: %v", err)
	}
	if n != 3 {
		t.Fatalf("want 3 entries, got %d", n)
	}
}

func TestAuditChainDetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	log, _ := OpenAuditLog(path)
	_, _ = log.Append("alice", "run", []byte("one"))
	_, _ = log.Append("alice", "run", []byte("two"))

	// Tamper with the first line's actor.
	data, _ := os.ReadFile(path)
	tampered := bytes.Replace(data, []byte(`"actor":"alice"`), []byte(`"actor":"mallory"`), 1)
	_ = os.WriteFile(path, tampered, 0o600)

	if _, err := log.Verify(); err == nil {
		t.Fatal("tampering with an entry must break the chain")
	}
}

func TestBundleExportContainsExpectedFiles(t *testing.T) {
	key, _ := LoadOrCreateKey(filepath.Join(t.TempDir(), "k.json"))
	var buf bytes.Buffer
	if _, err := Export(&buf, testRun(), []string{"blocked"}, nil, key); err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	found := map[string]bool{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		found[h.Name] = true
	}
	for _, want := range []string{"run.json", "attestation.dsse.json", "SUMMARY.txt"} {
		if !found[want] {
			t.Errorf("bundle missing %s (have %v)", want, found)
		}
	}
}
