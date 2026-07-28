package sandbox

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// NamePrefix marks every container detonate creates.
//
// A stable prefix is what makes orphan cleanup possible: if a scan dies hard
// (power loss, SIGKILL, a crash in our own code), the containers it left
// behind are still identifiable afterwards by name alone.
const NamePrefix = "detonate-"

// NewName returns a unique container name.
//
// Random rather than sequential or PID-based, because two detonate processes
// scanning at once must never collide: docker rejects a duplicate name, so a
// collision would turn a concurrent scan into a confusing failure. Eight bytes
// is far more than enough for that.
func NewName() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating sandbox name: %w", err)
	}
	return NamePrefix + hex.EncodeToString(b[:]), nil
}
