package testsupport

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// failingSocketDir is a directory name as long as the ones t.TempDir() makes
// for the tests that failed on the self-hosted race pool.
// os.MkdirTemp appends the random suffix t.TempDir() appends.
const failingSocketDir = "TestNewQRDBControlTransport_PlaintextBearerTLS_carries_the_token"

// TestShort_dir_name_is_short pins the length of the short directory: a
// pkg/api/unix test needs it at most 11 bytes ("/tmp/xk" plus 4).
func TestShort_dir_name_is_short(t *testing.T) {
	var dir string
	runWithShortTempDir(func() int { dir = os.TempDir(); return 0 })
	if filepath.Dir(dir) == "/tmp" && len(dir) > 11 {
		t.Fatalf("short directory %q is %d bytes, want at most 11", dir, len(dir))
	}
}

func TestShort_unix_socket_binds_under_a_deep_TMPDIR(t *testing.T) {
	deep := filepath.Join(os.TempDir(), "a-deep-runner-work-directory-like-home-runner-_work-_temp-"+strings.Repeat("x", 40))
	if len(deep) <= 80 {
		t.Fatalf("deep TMPDIR %q is only %d bytes", deep, len(deep))
	}
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatalf("creating deep TMPDIR: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(deep) })
	t.Setenv("TMPDIR", deep)

	var short string
	var bindErr error
	code := runWithShortTempDir(func() int {
		short = os.TempDir()
		dir, err := os.MkdirTemp(short, failingSocketDir)
		if err != nil {
			bindErr = err
			return 1
		}
		sock := filepath.Join(dir, "001", "xkms.sock")
		if err := os.MkdirAll(filepath.Dir(sock), 0o700); err != nil {
			bindErr = err
			return 1
		}
		ln, err := net.Listen("unix", sock)
		if err != nil {
			bindErr = err
			return 1
		}
		_ = ln.Close()
		return 0
	})

	if bindErr != nil {
		t.Fatalf("binding a unix socket under the run's TMPDIR %q: %v", short, bindErr)
	}
	if code != 0 {
		t.Fatalf("Short returned %d, want 0", code)
	}
	if got := os.Getenv("TMPDIR"); got != deep {
		t.Fatalf("TMPDIR after Short = %q, want %q restored", got, deep)
	}
	if short == deep {
		t.Fatalf("Short kept the deep TMPDIR %q for the run", deep)
	}
	if _, err := os.Stat(short); !os.IsNotExist(err) {
		t.Fatalf("short directory %q still exists after Short (stat err %v)", short, err)
	}
}

// t.TempDir() uses GOTMPDIR before TMPDIR, so a deep GOTMPDIR must not
// survive into the run either.
func TestShort_t_TempDir_is_short_under_a_deep_GOTMPDIR(t *testing.T) {
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
	runWithShortTempDir(func() int {
		sock = filepath.Join(t.TempDir(), "x/agent.sock")
		return 0
	})

	if len(sock) >= 104 {
		t.Fatalf("socket path %q is %d bytes, want under 104", sock, len(sock))
	}
	for _, name := range []string{"TMPDIR", "GOTMPDIR"} {
		if got := os.Getenv(name); got != deep {
			t.Fatalf("%s after Short = %q, want %q restored", name, got, deep)
		}
	}
}

func TestShort_returns_the_run_exit_code(t *testing.T) {
	if got := runWithShortTempDir(func() int { return 3 }); got != 3 {
		t.Fatalf("Short returned %d, want 3", got)
	}
}
