package evidence

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/gatehouse/gatehouse/internal/model"
)

// Bundle is a self-contained, signed evidence archive for one run (plan §10):
// the run manifest, the combined report, and the signed attestation, so the run
// can later be proven exactly as it happened. v1 writes a .tar.gz; the plan's
// .tar.zst is a drop-in once a zstd writer is vendored.
type Bundle struct {
	Run         model.Run `json:"run"`
	Attestation *Envelope `json:"attestation"`
}

// Export writes the bundle for run (with its decision messages) to w, signing
// an attestation with signer. It returns the attestation digest recorded on the
// run.
func Export(w io.Writer, run model.Run, deny, warn []string, signer Signer) (string, error) {
	env, err := Attest(run, deny, warn, signer)
	if err != nil {
		return "", err
	}

	gz := gzip.NewWriter(w)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	runJSON, _ := json.MarshalIndent(run, "", "  ")
	if err := writeFile(tw, "run.json", runJSON); err != nil {
		return "", err
	}
	envJSON, _ := json.MarshalIndent(env, "", "  ")
	if err := writeFile(tw, "attestation.dsse.json", envJSON); err != nil {
		return "", err
	}
	// A compact human-readable summary for auditors opening the archive.
	summary := fmt.Sprintf("Gatehouse evidence bundle\nrun: %s\nrepo: %s\nref: %s\nverdict: %s\ntree: %s\n",
		run.ID, run.RepoPath, run.Ref, run.Verdict, run.TreeHash)
	if err := writeFile(tw, "SUMMARY.txt", []byte(summary)); err != nil {
		return "", err
	}

	return DigestBytes(envJSON), nil
}

// ExportFile writes the bundle to a file path.
func ExportFile(path string, run model.Run, deny, warn []string, signer Signer) (string, error) {
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return Export(f, run, deny, warn, signer)
}

func writeFile(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}
