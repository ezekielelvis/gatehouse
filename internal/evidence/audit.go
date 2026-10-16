package evidence

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// AuditEntry is one record in the append-only, hash-chained audit log (plan
// §10). Each entry commits to the previous entry's hash, so any insertion,
// deletion or edit anywhere in the history breaks the chain from that point on.
type AuditEntry struct {
	Seq         int       `json:"seq"`
	Timestamp   time.Time `json:"ts"`
	Actor       string    `json:"actor"`
	Action      string    `json:"action"` // e.g. "run", "waiver.add", "policy.change"
	PayloadHash string    `json:"payload_hash"`
	PrevHash    string    `json:"prev_hash"`
	EntryHash   string    `json:"entry_hash"`
}

// AuditLog is a file-backed hash chain (one JSON object per line).
type AuditLog struct {
	path string
}

// OpenAuditLog opens (creating the parent dir if needed) the audit log at path.
func OpenAuditLog(path string) (*AuditLog, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	return &AuditLog{path: path}, nil
}

// Append adds an entry committing to the given payload, chaining it to the
// current tail. It returns the stored entry.
func (l *AuditLog) Append(actor, action string, payload []byte) (*AuditEntry, error) {
	entries, err := l.read()
	if err != nil {
		return nil, err
	}
	prevHash := ""
	seq := 1
	if n := len(entries); n > 0 {
		prevHash = entries[n-1].EntryHash
		seq = entries[n-1].Seq + 1
	}

	e := AuditEntry{
		Seq:         seq,
		Timestamp:   time.Now().UTC(),
		Actor:       actor,
		Action:      action,
		PayloadHash: hashHex(payload),
		PrevHash:    prevHash,
	}
	e.EntryHash = e.computeHash()

	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	line, _ := json.Marshal(e)
	if _, err := f.Write(append(line, '\n')); err != nil {
		return nil, err
	}
	return &e, nil
}

// Verify re-checks the whole chain and returns the number of entries verified.
// It fails at the first entry whose recomputed hash or prev-hash link is wrong.
func (l *AuditLog) Verify() (int, error) {
	entries, err := l.read()
	if err != nil {
		return 0, err
	}
	prev := ""
	for i, e := range entries {
		if e.PrevHash != prev {
			return i, fmt.Errorf("entry %d: broken chain (prev_hash mismatch)", e.Seq)
		}
		if e.computeHash() != e.EntryHash {
			return i, fmt.Errorf("entry %d: tampered (entry_hash mismatch)", e.Seq)
		}
		prev = e.EntryHash
	}
	return len(entries), nil
}

func (l *AuditLog) read() ([]AuditEntry, error) {
	f, err := os.Open(l.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []AuditEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var e AuditEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("corrupt audit log line: %w", err)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// computeHash hashes the chain-relevant fields (everything except EntryHash
// itself) so the hash commits to the entry's content and its predecessor.
func (e AuditEntry) computeHash() string {
	h := sha256.New()
	fmt.Fprintf(h, "%d\n%s\n%s\n%s\n%s\n%s\n",
		e.Seq, e.Timestamp.Format(time.RFC3339Nano), e.Actor, e.Action, e.PayloadHash, e.PrevHash)
	return hex.EncodeToString(h.Sum(nil))
}

func hashHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
