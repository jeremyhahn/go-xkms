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

package ssh_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestShortTMPDIR_socket_path_fits_under_a_deep_TMPDIR mirrors
// internal/testtmp's test for this module, which cannot import it (#2248).
func TestShortTMPDIR_socket_path_fits_under_a_deep_TMPDIR(t *testing.T) {
	deep := filepath.Join(os.TempDir(), "a-deep-runner-work-directory-like-home-runner-_work-_temp-"+strings.Repeat("x", 40))
	if len(deep) <= 90 {
		t.Fatalf("deep TMPDIR %q is only %d bytes", deep, len(deep))
	}
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatalf("creating deep TMPDIR: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(deep) })
	t.Setenv("TMPDIR", deep)

	var short, sock string
	code := shortTMPDIR(func() int {
		short = os.TempDir()
		sock = filepath.Join(t.TempDir(), "x/agent.sock")
		return 0
	})

	if code != 0 {
		t.Fatalf("shortTMPDIR returned %d, want 0", code)
	}
	if len(sock) >= 104 {
		t.Fatalf("socket path %q is %d bytes, want under 104", sock, len(sock))
	}
	if got := os.Getenv("TMPDIR"); got != deep {
		t.Fatalf("TMPDIR after shortTMPDIR = %q, want %q restored", got, deep)
	}
	if short == deep {
		t.Fatalf("shortTMPDIR kept the deep TMPDIR %q for the run", deep)
	}
	if _, err := os.Stat(short); !os.IsNotExist(err) {
		t.Fatalf("short directory %q still exists after shortTMPDIR (stat err %v)", short, err)
	}
}

// TestShortTMPDIR_TempDir_is_short_under_a_deep_GOTMPDIR: t.TempDir prefers
// GOTMPDIR, so a deep GOTMPDIR must not leak into the run.
func TestShortTMPDIR_TempDir_is_short_under_a_deep_GOTMPDIR(t *testing.T) {
	deep := filepath.Join(os.TempDir(), "a-deep-runner-work-directory-like-home-runner-_work-_temp-"+strings.Repeat("g", 40))
	if len(deep) <= 90 {
		t.Fatalf("deep GOTMPDIR %q is only %d bytes", deep, len(deep))
	}
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatalf("creating deep GOTMPDIR: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(deep) })
	t.Setenv("TMPDIR", deep)
	t.Setenv("GOTMPDIR", deep)

	var sock string
	code := shortTMPDIR(func() int {
		sock = filepath.Join(t.TempDir(), "x/agent.sock")
		return 0
	})

	if code != 0 {
		t.Fatalf("shortTMPDIR returned %d, want 0", code)
	}
	if strings.HasPrefix(sock, deep) || len(sock) >= 104 {
		t.Fatalf("socket path %q (%d bytes) is under the deep GOTMPDIR", sock, len(sock))
	}
	for _, key := range []string{"TMPDIR", "GOTMPDIR"} {
		if got := os.Getenv(key); got != deep {
			t.Fatalf("%s after shortTMPDIR = %q, want %q restored", key, got, deep)
		}
	}
}

func TestShortTMPDIR_returns_the_run_exit_code(t *testing.T) {
	if got := shortTMPDIR(func() int { return 3 }); got != 3 {
		t.Fatalf("shortTMPDIR returned %d, want 3", got)
	}
}
