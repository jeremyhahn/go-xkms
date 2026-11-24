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

// Short makes one short directory (under /tmp, or under os.TempDir() when
// /tmp is unusable), sets TMPDIR and GOTMPDIR to it while run executes, then
// restores both and removes the directory. It returns run's exit code.
func Short(run func() int) int {
	dir, err := mkdirShort(shortRoot)
	if err != nil {
		dir, err = os.MkdirTemp(os.TempDir(), "xk")
		if err != nil {
			fmt.Fprintf(os.Stderr, "testtmp: creating a short temporary directory: %v\n", err)
			return run()
		}
	}

	// t.TempDir() makes its directories under GOTMPDIR when it is set
	// (testing.go: os.MkdirTemp(os.Getenv("GOTMPDIR"), ...)), so both
	// variables point at the short directory.
	restore := setEnv(map[string]string{"TMPDIR": dir, "GOTMPDIR": dir})
	defer func() {
		restore()
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintf(os.Stderr, "testtmp: removing %s: %v\n", dir, err)
		}
	}()

	return run()
}

// setEnv sets each variable in vars and returns a func that restores the
// previous values (unsetting those that were unset).
func setEnv(vars map[string]string) func() {
	type saved struct {
		val string
		had bool
	}
	prev := make(map[string]saved, len(vars))
	for k, v := range vars {
		old, had := os.LookupEnv(k)
		prev[k] = saved{old, had}
		if err := os.Setenv(k, v); err != nil {
			fmt.Fprintf(os.Stderr, "testtmp: setting %s: %v\n", k, err)
		}
	}
	return func() {
		for k, s := range prev {
			if s.had {
				_ = os.Setenv(k, s.val)
			} else {
				_ = os.Unsetenv(k)
			}
		}
	}
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
