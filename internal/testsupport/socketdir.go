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
	"fmt"
	"os"
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

// RunWithShortTempDir runs m with TMPDIR pointed at a fresh mode-0700
// directory directly under /tmp, removes it afterwards and returns m.Run's
// exit code; call it from TestMain as os.Exit(testsupport.RunWithShortTempDir(m)).
//
// It is for a package whose code under test binds its own Unix socket
// beneath os.TempDir (ssh/agent's default session directory), where a test
// cannot pass a SocketDir path in: under a long runner TMPDIR that socket's
// path passes sun_path. On Windows, which has no /tmp, m runs unchanged.
func RunWithShortTempDir(m *testing.M) int {
	if runtime.GOOS == "windows" {
		return m.Run()
	}
	dir, err := os.MkdirTemp("/tmp", "xt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "testsupport.RunWithShortTempDir: %v\n", err)
		return 1
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintf(os.Stderr, "testsupport.RunWithShortTempDir: remove %s: %v\n", dir, err)
		}
	}()
	if err := os.Setenv("TMPDIR", dir); err != nil {
		fmt.Fprintf(os.Stderr, "testsupport.RunWithShortTempDir: %v\n", err)
		return 1
	}
	return m.Run()
}
