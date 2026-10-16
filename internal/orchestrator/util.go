package orchestrator

import (
	"crypto/rand"
	"encoding/hex"
)

// randHex returns n random bytes hex-encoded (2n chars), for run-id suffixes.
func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
