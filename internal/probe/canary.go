package probe

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// Canary represents a unique token generated for a specific probe execution.
type Canary struct {
	Token    string
	Filename string
	HostPath string
	HostDir  string
}

// GenerateCanary creates a canary in scanner-owned staging.
//
// The canary must never be written into the target directory. Even if it is
// removed later, doing so mutates the artifact being measured and makes a
// failed cleanup leave scanner-generated content in the user's source tree.
// Callers mount HostDir at the desired in-sandbox location instead.
func GenerateCanary() (*Canary, error) {
	hostDir, err := os.MkdirTemp("", "detonate-canary-")
	if err != nil {
		return nil, fmt.Errorf("creating canary staging directory: %w", err)
	}
	cleanup := func(err error) (*Canary, error) {
		_ = os.RemoveAll(hostDir)
		return nil, err
	}

	// Generate a random 16-byte token. The collision check against the target
	// corpus belongs to the seeding layer, which has both the token and corpus;
	// this helper deliberately owns only isolated creation and cleanup.
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return cleanup(fmt.Errorf("generating canary token: %w", err))
	}
	token := hex.EncodeToString(bytes)
	filename := fmt.Sprintf("detonate-canary-%s.txt", token[:8])
	hostPath := filepath.Join(hostDir, filename)

	// Write token to canary file
	content := fmt.Sprintf("DETONATE_CANARY_TOKEN:%s", token)
	if err := os.WriteFile(hostPath, []byte(content), 0o600); err != nil {
		return cleanup(fmt.Errorf("writing canary: %w", err))
	}

	return &Canary{
		Token:    token,
		Filename: filename,
		HostPath: hostPath,
		HostDir:  hostDir,
	}, nil
}

// Cleanup removes all scanner-owned canary staging. Safe to call more than
// once. The error is part of the scan outcome: silently leaving a secret-like
// artifact behind would violate the production lifecycle contract.
func (c *Canary) Cleanup() error {
	if c == nil || c.HostDir == "" {
		return nil
	}
	dir := c.HostDir
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("removing canary staging directory %q: %w", dir, err)
	}
	c.HostDir = ""
	c.HostPath = ""
	return nil
}
