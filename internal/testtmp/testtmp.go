// Package testtmp keeps the temporary directories of a test binary short.
//
// A unix socket path must fit in sun_path (108 bytes on Linux). Runners whose
// TMPDIR is deep (for example /home/runner/_work/_temp) make t.TempDir()
// return paths that, with a long test name and a socket file name, exceed it.
// Short points TMPDIR at a short directory for the whole test run.
//
// Use it from a package's TestMain:
//
//	func TestMain(m *testing.M) { os.Exit(testtmp.Short(m.Run)) }
package testtmp

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// shortRoot is the preferred parent of the short directory.
const shortRoot = "/tmp"

// tmpVars are the variables Short points at the short directory for the run.
var tmpVars = []string{"TMPDIR", "GOTMPDIR"}

// Short makes one short directory (under /tmp, or under os.TempDir() when
// /tmp is unusable), sets TMPDIR to it while run executes, then restores
// TMPDIR and removes the directory. It returns run's exit code.
func Short(run func() int) int {
	dir, err := mkdirShort(shortRoot)
	if err != nil {
		dir, err = os.MkdirTemp(os.TempDir(), "xk")
		if err != nil {
			fmt.Fprintf(os.Stderr, "testtmp: creating a short temporary directory: %v\n", err)
			return run()
		}
	}

	// t.TempDir prefers GOTMPDIR over TMPDIR, so both point at dir.
	restore := make([]func(), 0, len(tmpVars))
	for _, key := range tmpVars {
		prev, had := os.LookupEnv(key)
		if err := os.Setenv(key, dir); err != nil {
			fmt.Fprintf(os.Stderr, "testtmp: setting %s: %v\n", key, err)
		}
		restore = append(restore, func() {
			if had {
				_ = os.Setenv(key, prev)
			} else {
				_ = os.Unsetenv(key)
			}
		})
	}
	defer func() {
		for _, r := range restore {
			r()
		}
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintf(os.Stderr, "testtmp: removing %s: %v\n", dir, err)
		}
	}()

	return run()
}

// mkdirShort creates root/xkNNNN with 4 random base-36 characters: 6 bytes
// shorter than os.MkdirTemp's suffix, which some socket paths need.
func mkdirShort(root string) (string, error) {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
	var lastErr error
	for range 1000 {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		name := []byte("xk")
		for _, c := range b {
			name = append(name, alphabet[int(c)%len(alphabet)])
		}
		dir := filepath.Join(root, string(name))
		err := os.Mkdir(dir, 0o700)
		if err == nil {
			return dir, nil
		}
		lastErr = err
		if !errors.Is(err, fs.ErrExist) {
			return "", err
		}
	}
	return "", lastErr
}
