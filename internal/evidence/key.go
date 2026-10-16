// Package evidence makes every run reproducible and tamper-evident (plan §10):
// a local Ed25519 signing key, in-toto attestations wrapped in a DSSE envelope,
// an append-only hash-chained audit log, and a self-contained evidence bundle.
//
// v1 stores the key as a file under ~/.gatehouse (0600). The plan's OS-keychain
// and hardware-key options slot in behind the Signer interface later; sigstore
// interop is deferred to keep the core dependency-light.
package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Signer signs evidence. The concrete local implementation is a file-backed
// Ed25519 key.
type Signer interface {
	Sign(data []byte) []byte
	// KeyID identifies the signing key (here, base64 of the public key).
	KeyID() string
	Public() ed25519.PublicKey
}

// LocalKey is a file-backed Ed25519 signer.
type LocalKey struct {
	priv ed25519.PrivateKey
}

type storedKey struct {
	Algorithm  string `json:"algorithm"`
	PrivateKey string `json:"private_key"` // base64 seed
}

// LoadOrCreateKey loads the signing key at path, generating and persisting a new
// one (0600) if it does not exist.
func LoadOrCreateKey(path string) (*LocalKey, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return generateKey(path)
	}
	if err != nil {
		return nil, err
	}
	var sk storedKey
	if err := json.Unmarshal(data, &sk); err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}
	seed, err := base64.StdEncoding.DecodeString(sk.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode signing key: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("signing key: bad seed size %d", len(seed))
	}
	return &LocalKey{priv: ed25519.NewKeyFromSeed(seed)}, nil
}

func generateKey(path string) (*LocalKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sk := storedKey{
		Algorithm:  "ed25519",
		PrivateKey: base64.StdEncoding.EncodeToString(priv.Seed()),
	}
	data, _ := json.MarshalIndent(sk, "", "  ")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return nil, err
	}
	return &LocalKey{priv: priv}, nil
}

func (k *LocalKey) Sign(data []byte) []byte { return ed25519.Sign(k.priv, data) }

func (k *LocalKey) Public() ed25519.PublicKey { return k.priv.Public().(ed25519.PublicKey) }

func (k *LocalKey) KeyID() string {
	return base64.StdEncoding.EncodeToString(k.Public())
}
