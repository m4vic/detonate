//go:build unix

package decoy

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// os.WriteFile and os.MkdirAll mask the mode they are given by the process
// umask, so asking for 0644 under `umask 077` still produces 0600. Requesting
// the mode is not the same as having it.
func TestPlantingSurvivesARestrictiveUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)

	dir := t.TempDir()
	if _, err := Plant(dir, "/home/detonate"); err != nil {
		t.Fatal(err)
	}

	key := filepath.Join(dir, ".ssh", "id_rsa")
	info, err := os.Stat(key)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o004 == 0 {
		t.Errorf("under umask 077 the SSH decoy is %04o; the umask silently won",
			info.Mode().Perm())
	}

	sshDir, err := os.Stat(filepath.Join(dir, ".ssh"))
	if err != nil {
		t.Fatal(err)
	}
	if sshDir.Mode().Perm()&0o005 != 0o005 {
		t.Errorf(".ssh is %04o under umask 077; the key inside it is unreachable",
			sshDir.Mode().Perm())
	}
}
