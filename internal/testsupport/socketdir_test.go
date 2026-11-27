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

package testsupport

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestRunWithShortTempDirShortensTDotTempDirUnderALongGOTMPDIR is the
// self-hosted pool's shape: GOTMPDIR is the runner's long _work/_temp, which
// t.TempDir prefers over TMPDIR, so a t.TempDir created under
// RunWithShortTempDir must still land under its short /tmp directory.
func TestRunWithShortTempDirShortensTDotTempDirUnderALongGOTMPDIR(t *testing.T) {
	if runtime.GOOS == "windows" {
		return // RunWithShortTempDir runs m unchanged on Windows.
	}
	long := filepath.Join(t.TempDir(), strings.Repeat("x", 70))
	if err := os.MkdirAll(long, 0o700); err != nil {
		t.Fatal(err)
	}
	// t.Setenv restores both variables when the test ends.
	t.Setenv("GOTMPDIR", long)
	t.Setenv("TMPDIR", long)

	var short, got string
	code := runWithShortTempDir(func() int {
		short = os.Getenv("GOTMPDIR")
		t.Run("tempdir", func(st *testing.T) {
			got = st.TempDir()
		})
		return 0
	})
	if code != 0 {
		t.Fatalf("runWithShortTempDir returned %d", code)
	}
	if !strings.HasPrefix(short, "/tmp/") || short == long {
		t.Fatalf("GOTMPDIR under RunWithShortTempDir = %q, want a fresh directory under /tmp", short)
	}
	if !strings.HasPrefix(got, short+string(filepath.Separator)) {
		t.Fatalf("t.TempDir() = %q, want it under the short directory %q", got, short)
	}
	if _, err := os.Stat(short); !os.IsNotExist(err) {
		t.Errorf("short directory %q not removed afterwards: %v", short, err)
	}
}
