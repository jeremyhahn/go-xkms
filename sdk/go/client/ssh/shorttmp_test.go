package ssh_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// deepTempDir makes a directory longer than 90 bytes, like the self-hosted
// runner's /home/runner/_work/_temp, and removes it when t ends.
func deepTempDir(t *testing.T) string {
	t.Helper()
	deep := filepath.Join(os.TempDir(), "a-deep-runner-work-directory-like-home-runner-_work-_temp-"+strings.Repeat("x", 40))
	if len(deep) <= 90 {
		t.Fatalf("deep directory %q is only %d bytes", deep, len(deep))
	}
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatalf("creating deep directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(deep) })
	return deep
}

func TestShortTMPDIR_socket_path_fits_under_a_deep_TMPDIR_and_GOTMPDIR(t *testing.T) {
	deep := deepTempDir(t)
	t.Setenv("TMPDIR", deep)
	t.Setenv("GOTMPDIR", deep)

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
	for _, name := range []string{"TMPDIR", "GOTMPDIR"} {
		if got := os.Getenv(name); got != deep {
			t.Fatalf("%s after shortTMPDIR = %q, want %q restored", name, got, deep)
		}
	}
	if short == deep {
		t.Fatalf("shortTMPDIR kept the deep TMPDIR %q for the run", deep)
	}
	if _, err := os.Stat(short); !os.IsNotExist(err) {
		t.Fatalf("short directory %q still exists after shortTMPDIR (stat err %v)", short, err)
	}
}

func TestShortTMPDIR_unsets_variables_that_were_unset(t *testing.T) {
	t.Setenv("GOTMPDIR", "")
	if err := os.Unsetenv("GOTMPDIR"); err != nil {
		t.Fatalf("unsetting GOTMPDIR: %v", err)
	}

	var during string
	shortTMPDIR(func() int {
		during = os.Getenv("GOTMPDIR")
		return 0
	})

	if during == "" {
		t.Fatal("GOTMPDIR was not set during the run")
	}
	if _, had := os.LookupEnv("GOTMPDIR"); had {
		t.Fatal("GOTMPDIR is set after shortTMPDIR, want it unset again")
	}
}

func TestShortTMPDIR_returns_the_run_exit_code(t *testing.T) {
	if code := shortTMPDIR(func() int { return 3 }); code != 3 {
		t.Fatalf("shortTMPDIR returned %d, want 3", code)
	}
}
