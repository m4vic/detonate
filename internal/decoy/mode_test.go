package decoy

import (
	"io/fs"
	"path/filepath"
	"runtime"
	"testing"
)

// The decoy is planted by detonate and read inside the sandbox, and those are
// two different users: the sandbox runs as uid 1000, the files are created by
// whoever ran detonate. Ownership therefore never matches, so anything the
// group and other bits do not permit is unreadable from inside the container.
//
// Every decoy was written 0600. On Linux — CI, and most real users — the entire
// evidence mechanism was planted, mounted, and invisible: a thieving server
// could not open the key it was being tempted with, so nothing leaked and the
// scan reported a clean result it had not earned.
//
// It survived because Docker Desktop on Windows and macOS serves bind mounts
// through a VM that ignores POSIX ownership, so every local run passed. This
// test states the requirement on every platform rather than only where it bites.
func TestPlantedFilesAreReadableByAnotherUser(t *testing.T) {
	dir := t.TempDir()
	env, err := Plant(dir, "/home/detonate")
	if err != nil {
		t.Fatal(err)
	}
	if len(env.Tokens) == 0 {
		t.Fatal("nothing was planted")
	}

	if runtime.GOOS == "windows" {
		// Windows has no POSIX modes to assert. The requirement still holds and
		// is checked wherever it can actually be violated.
		t.Skip("POSIX modes are not meaningful on Windows")
	}

	err = filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		mode := info.Mode().Perm()
		if info.IsDir() {
			// Without o+x the directory cannot be traversed, and a readable
			// file inside it is still unreachable.
			if mode&0o005 != 0o005 {
				t.Errorf("directory %s is %04o; the sandbox user cannot traverse it",
					rel(dir, path), mode)
			}
			return nil
		}
		if mode&0o004 == 0 {
			t.Errorf("file %s is %04o; the sandbox user cannot read it, so a target that "+
				"stole it would leave no evidence", rel(dir, path), mode)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func rel(base, path string) string {
	r, err := filepath.Rel(base, path)
	if err != nil {
		return path
	}
	return r
}
