package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestShortTMPDIR_socket_path_fits_under_a_deep_TMPDIR mirrors
// go-xkms internal/testsupport's short_test.go for this module, which cannot import it (#2248).
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

// t.TempDir() uses GOTMPDIR before TMPDIR, so a deep GOTMPDIR must not
// survive into the run either.
func TestShortTMPDIR_t_TempDir_is_short_under_a_deep_GOTMPDIR(t *testing.T) {
	deep := filepath.Join(os.TempDir(), "a-deep-runner-go-tmp-directory-like-home-runner-_work-_temp-gotmp-"+strings.Repeat("x", 40))
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
	shortTMPDIR(func() int {
		sock = filepath.Join(t.TempDir(), "x/agent.sock")
		return 0
	})

	if len(sock) >= 104 {
		t.Fatalf("socket path %q is %d bytes, want under 104", sock, len(sock))
	}
	for _, name := range []string{"TMPDIR", "GOTMPDIR"} {
		if got := os.Getenv(name); got != deep {
			t.Fatalf("%s after shortTMPDIR = %q, want %q restored", name, got, deep)
		}
	}
}

func TestShortTMPDIR_returns_the_run_exit_code(t *testing.T) {
	if got := shortTMPDIR(func() int { return 3 }); got != 3 {
		t.Fatalf("shortTMPDIR returned %d, want 3", got)
	}
}
