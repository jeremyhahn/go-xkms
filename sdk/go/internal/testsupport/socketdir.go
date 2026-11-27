// Package testsupport holds helpers shared by the sdk/go module's tests.
package testsupport

import (
	"os"
	"testing"
)

// SocketDir returns a fresh mode-0700 directory directly under os.TempDir for
// a test that binds or dials a Unix socket inside it, and removes it when the
// test ends.
//
// t.TempDir nests the test name and two more levels in its path, so under a
// long TMPDIR (a CI runner's work directory) a socket path beneath it passes
// AF_UNIX's sun_path limit (108 bytes on Linux, 104 on macOS) and bind or
// connect fails with "invalid argument". os.MkdirTemp creates the directory
// 0700, which the ssh agent's socket-directory checks require of a parent.
func SocketDir(t testing.TB) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "sg")
	if err != nil {
		t.Fatalf("testsupport.SocketDir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("testsupport.SocketDir: remove %s: %v", dir, err)
		}
	})
	return dir
}
