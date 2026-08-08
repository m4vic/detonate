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
}

// TargetDirProvider is implemented by Callers that expose a local path mounted as /target in the container.
type TargetDirProvider interface {
	TargetDir() string
}

// GenerateCanary creates a temporary canary file in the host target directory.
func GenerateCanary(hostDir string) (*Canary, error) {
	if hostDir == "" {
		return nil, fmt.Errorf("empty host directory")
	}

	// Generate random 16-byte hex token
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}
	token := hex.EncodeToString(bytes)
	filename := fmt.Sprintf("detonate-canary-%s.txt", token[:8])
	hostPath := filepath.Join(hostDir, filename)

	// Write token to canary file
	content := fmt.Sprintf("DETONATE_CANARY_TOKEN:%s", token)
	if err := os.WriteFile(hostPath, []byte(content), 0644); err != nil {
		return nil, err
	}

	return &Canary{
		Token:    token,
		Filename: filename,
		HostPath: hostPath,
	}, nil
}

// Cleanup removes the canary file from the host.
func (c *Canary) Cleanup() {
	if c.HostPath != "" {
		_ = os.Remove(c.HostPath)
	}
}
