package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/gatehouse/gatehouse/internal/evidence"
	"github.com/gatehouse/gatehouse/internal/gitx"
	"github.com/gatehouse/gatehouse/internal/model"
)

// gitNoteRef is the notes ref Gatehouse writes its signed run summary under.
const gitNoteRef = "gatehouse"

// writeGitNote signs a DSSE attestation of the run and stores it (base64) as a
// git note on HEAD, so a later `gatehouse verify <commit>` — or CI — can prove
// a local scan ran and with what verdict.
func writeGitNote(repoDir string, run model.Run, deny, warn []string) error {
	commit, err := gitx.HeadCommit(repoDir)
	if err != nil {
		return err
	}
	signer, err := evidence.LoadOrCreateKey(defaultKeyPath())
	if err != nil {
		return err
	}
	env, err := evidence.Attest(run, deny, warn, signer)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(env)
	return gitx.WriteNote(repoDir, gitNoteRef, commit, base64.StdEncoding.EncodeToString(raw))
}

// cmdVerify reads and verifies the signed git-notes attestation on a commit.
func cmdVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	path := fs.String("path", ".", "repository path")

	commit := "HEAD"
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		commit = args[0]
		args = args[1:]
	}
	fs.Parse(args)

	if !gitx.IsRepo(*path) {
		fmt.Fprintf(os.Stderr, "not a git repository: %s\n", *path)
		return exitError
	}
	note, err := gitx.ReadNote(*path, gitNoteRef, commit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "no Gatehouse attestation on %s (was it scanned locally?)\n", commit)
		return exitFail
	}
	raw, err := base64.StdEncoding.DecodeString(note)
	if err != nil {
		fmt.Fprintln(os.Stderr, "corrupt attestation note:", err)
		return exitError
	}
	var env evidence.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		fmt.Fprintln(os.Stderr, "corrupt attestation note:", err)
		return exitError
	}
	signer, err := evidence.LoadOrCreateKey(defaultKeyPath())
	if err != nil {
		fmt.Fprintln(os.Stderr, "signing key:", err)
		return exitError
	}
	stmt, err := evidence.Verify(&env, signer.Public())
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ attestation signature INVALID: %v\n", err)
		return exitFail
	}
	fmt.Printf("✓ verified Gatehouse attestation for %s\n", commit)
	fmt.Printf("  run:     %s\n  verdict: %s\n  context: %s\n  new findings: %d\n",
		stmt.Predicate.RunID, stmt.Predicate.Verdict, stmt.Predicate.Context, stmt.Predicate.NewFindings)
	if stmt.Predicate.Verdict == model.VerdictFail {
		return exitFail
	}
	return exitPass
}
