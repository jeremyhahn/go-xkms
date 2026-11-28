package ssh

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sunPathMax is the size of sun_path on Linux, including the trailing NUL.
const sunPathMax = 108

// TestShortTMPDIR_DeepTMPDIRAndGOTMPDIR shows that shortTMPDIR points both
// TMPDIR and GOTMPDIR (which t.TempDir() uses) at a short directory, and
// restores both afterwards (#2248).
func TestShortTMPDIR_DeepTMPDIRAndGOTMPDIR(t *testing.T) {
	base := "/tmp"
	if _, err := os.Stat(base); err != nil {
		base = os.TempDir()
	}
	deep, err := os.MkdirTemp(base, "deep")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(deep)
	long := filepath.Join(deep, strings.Repeat("d", 100))
	longTMP, longGO := filepath.Join(long, "t"), filepath.Join(long, "g")
	for _, d := range []string{longTMP, longGO} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
	}
	t.Setenv("TMPDIR", longTMP)
	t.Setenv("GOTMPDIR", longGO)

	var inTMP, inGO string
	code := shortTMPDIR(func() int {
		inTMP, inGO = os.Getenv("TMPDIR"), os.Getenv("GOTMPDIR")
		d, err := os.MkdirTemp(os.Getenv("GOTMPDIR"), "TestStartAgent_SocketDirServesAnotherWorkingDirectory")
		if err != nil {
			t.Errorf("MkdirTemp under GOTMPDIR: %v", err)
			return 1
		}
		sock := filepath.Join(d, "001", "agent", "agent.sock")
		if len(sock) >= sunPathMax {
			t.Errorf("socket path %d bytes, must be < %d: %s", len(sock), sunPathMax, sock)
		}
		return 7
	})
	if code != 7 {
		t.Fatalf("exit code = %d, want 7", code)
	}
	if inTMP != inGO {
		t.Fatalf("TMPDIR %q and GOTMPDIR %q must be the same short dir", inTMP, inGO)
	}
	if len(inTMP) >= 90 {
		t.Fatalf("short dir %q is %d bytes", inTMP, len(inTMP))
	}
	if got := os.Getenv("TMPDIR"); got != longTMP {
		t.Fatalf("TMPDIR not restored: %q", got)
	}
	if got := os.Getenv("GOTMPDIR"); got != longGO {
		t.Fatalf("GOTMPDIR not restored: %q", got)
	}
	if _, err := os.Stat(inTMP); !os.IsNotExist(err) {
		t.Fatalf("short dir %q not removed: %v", inTMP, err)
	}
}

// TestShortTMPDIR_UnsetsVariablesThatWereUnset checks that a variable unset
// before the run is set during it and unset again after it.
func TestShortTMPDIR_UnsetsVariablesThatWereUnset(t *testing.T) {
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

// TestTempDir_FitsAgentSocket shows the package's t.TempDir() leaves room for
// the agent socket under a deep TMPDIR or GOTMPDIR, which needs the TestMain.
func TestTempDir_FitsAgentSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "agent", "agent.sock")
	if len(sock) >= sunPathMax {
		t.Fatalf("socket path %d bytes, must be < %d: %s", len(sock), sunPathMax, sock)
	}
}
