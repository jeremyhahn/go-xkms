// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

// Package testsupport holds helpers shared by the root module's tests.
package testsupport

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// SocketDir returns a fresh mode-0700 directory directly under os.TempDir for
// a test that binds or dials a Unix socket inside it, and removes it when the
// test ends.
//
// t.TempDir nests the test name and two more levels in its path, so under a
// long TMPDIR (a CI runner's work directory) a socket path beneath it passes
// AF_UNIX's sun_path limit (108 bytes on Linux, 104 on macOS) and bind or
// connect fails with "invalid argument". The server's socket directory checks
// also refuse a directory with group or other permission bits, which
// os.MkdirTemp never sets.
func SocketDir(t testing.TB) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "xs")
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

// RunWithShortTempDir runs m with TMPDIR and GOTMPDIR pointed at a fresh
// mode-0700 directory directly under /tmp, removes it and restores both
// variables afterwards, and returns
// m.Run's exit code; call it from TestMain as
// os.Exit(testsupport.RunWithShortTempDir(m)).
//
// It is for a package whose code under test binds its own Unix socket
// beneath os.TempDir (ssh/agent's default session directory), where a test
// cannot pass a SocketDir path in: under a long runner TMPDIR that socket's
// path passes sun_path. GOTMPDIR is set too because t.TempDir prefers it over
// TMPDIR (Go 1.27), and the self-hosted pool sets it to the runner's long
// _work/_temp. On Windows, which has no /tmp, m runs unchanged.
func RunWithShortTempDir(m *testing.M) int {
	return runWithShortTempDir(m.Run)
}

// runWithShortTempDir is RunWithShortTempDir for any run function, so its own
// test can drive it without a TestMain.
func runWithShortTempDir(run func() int) int {
	if runtime.GOOS == "windows" {
		return run()
	}
	dir, err := mkdirShort(shortRoot)
	if err != nil {
		dir, err = os.MkdirTemp(os.TempDir(), "xk")
		if err != nil {
			fmt.Fprintf(os.Stderr, "testsupport.RunWithShortTempDir: %v\n", err)
			return run()
		}
	}

	// t.TempDir() makes its directories under GOTMPDIR when it is set
	// (testing.go: os.MkdirTemp(os.Getenv("GOTMPDIR"), ...)), so both
	// variables point at the short directory, and both are restored after.
	restore := setEnv(map[string]string{"TMPDIR": dir, "GOTMPDIR": dir})
	defer func() {
		restore()
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintf(os.Stderr, "testsupport.RunWithShortTempDir: remove %s: %v\n", dir, err)
		}
	}()

	return run()
}

// shortRoot is where runWithShortTempDir makes its directory.
const shortRoot = "/tmp"

// setEnv sets vars and returns a function that restores their earlier values
// (unsetting the ones that were unset).
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
			fmt.Fprintf(os.Stderr, "testsupport: setting %s: %v\n", k, err)
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

// mkdirShort makes a mode-0700 directory root/xkNNNN (11 bytes under /tmp),
// shorter than os.MkdirTemp's 10-digit suffix allows.
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
