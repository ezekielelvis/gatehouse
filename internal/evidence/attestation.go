package evidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gatehouse/gatehouse/internal/model"
)

// in-toto / DSSE constants.
const (
	intotoPayloadType = "application/vnd.in-toto+json"
	statementType     = "https://in-toto.io/Statement/v1"
	predicateType     = "https://gatehouse.dev/RunVerdict/v1"
)

// Statement is a minimal in-toto v1 Statement: what was scanned (subject) and
// the verdict/evidence about it (predicate).
type Statement struct {
	Type          string     `json:"_type"`
	Subject       []Subject  `json:"subject"`
	PredicateType string     `json:"predicateType"`
	Predicate     RunVerdict `json:"predicate"`
}

// Subject names the artifact the attestation is about: the snapshot tree hash.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// RunVerdict is the predicate: the signed summary of a run.
type RunVerdict struct {
	RunID        string         `json:"run_id"`
	Repo         string         `json:"repo"`
	Ref          string         `json:"ref"`
	Context      model.Context  `json:"context"`
	Verdict      model.Verdict  `json:"verdict"`
	FindingCount int            `json:"finding_count"`
	NewFindings  int            `json:"new_findings"`
	Deny         []string       `json:"deny,omitempty"`
	Warn         []string       `json:"warn,omitempty"`
	ReportDigest string         `json:"report_digest,omitempty"`
	ToolVersions map[string]int `json:"-"`
	FinishedAt   time.Time      `json:"finished_at"`
}

// Envelope is a DSSE (Dead Simple Signing Envelope) wrapping the statement.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"` // base64 of the statement JSON
	Signatures  []Signature `json:"signatures"`
}

// Signature is one DSSE signature.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"` // base64
}

// Attest builds a signed DSSE envelope attesting to a run's verdict.
func Attest(run model.Run, deny, warn []string, signer Signer) (*Envelope, error) {
	stmt := Statement{
		Type:          statementType,
		PredicateType: predicateType,
		Subject: []Subject{{
			Name:   run.RepoPath,
			Digest: map[string]string{"sha256": run.TreeHash},
		}},
		Predicate: RunVerdict{
			RunID:        run.ID,
			Repo:         run.RepoPath,
			Ref:          run.Ref,
			Context:      run.Context,
			Verdict:      run.Verdict,
			FindingCount: len(run.Findings),
			NewFindings:  countNew(run.Findings),
			Deny:         deny,
			Warn:         warn,
			FinishedAt:   run.FinishedAt,
		},
	}
	payload, err := json.Marshal(stmt)
	if err != nil {
		return nil, err
	}
	return &Envelope{
		PayloadType: intotoPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []Signature{{
			KeyID: signer.KeyID(),
			Sig:   base64.StdEncoding.EncodeToString(signer.Sign(pae(intotoPayloadType, payload))),
		}},
	}, nil
}

// Verify checks a DSSE envelope's signature against pub and returns the decoded
// statement.
func Verify(env *Envelope, pub ed25519.PublicKey) (*Statement, error) {
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	if len(env.Signatures) == 0 {
		return nil, fmt.Errorf("envelope has no signatures")
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(pub, pae(env.PayloadType, payload), sig) {
		return nil, fmt.Errorf("signature verification failed")
	}
	var stmt Statement
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return nil, err
	}
	return &stmt, nil
}

// pae is the DSSE Pre-Authentication Encoding, which binds the payload type
// into the signed bytes so a payload can't be reinterpreted under another type.
func pae(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s",
		len(payloadType), payloadType, len(payload), payload))
}

// DigestBytes returns the hex sha256 of data, used for report/SBOM digests.
func DigestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func countNew(fs []model.Finding) int {
	n := 0
	for _, f := range fs {
		if f.Status == model.StatusNew {
			n++
		}
	}
	return n
}
