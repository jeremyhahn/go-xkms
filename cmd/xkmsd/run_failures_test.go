package main

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// setRunArgs points os.Args at args for the duration of the test.
func setRunArgs(t *testing.T, args ...string) {
	t.Helper()
	origArgs := os.Args
	os.Args = append([]string{"xkmsd"}, args...)
	t.Cleanup(func() { os.Args = origArgs })
}

func TestRun_UndefinedFlagReturnsTwo(t *testing.T) {
	restoreFlags := swapFlagCommandLine(t)
	defer restoreFlags()
	setRunArgs(t, "--no-such-flag")

	if code := run(); code != 2 {
		t.Fatalf("run() with an undefined flag = %d, want 2", code)
	}
}

// TestRun_ShortFlagsSelectConfig proves -c replaces the --config default:
// the named file does not exist, so the load fails and run returns 1 rather
// than reading /etc/xkms/xkmsd.yaml.
func TestRun_ShortFlagsSelectConfig(t *testing.T) {
	restoreFlags := swapFlagCommandLine(t)
	defer restoreFlags()
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	setRunArgs(t, "-c", missing, "-d")

	if code := run(); code != 1 {
		t.Fatalf("run() with -c naming a missing file = %d, want 1", code)
	}
	if got := flagValue(t, "config"); got != missing {
		t.Errorf("--config after -c = %q, want %q", got, missing)
	}
	if got := flagValue(t, "daemon"); got != "true" {
		t.Errorf("--daemon after -d = %q, want true", got)
	}
}

// TestRun_EnvConfigOverridesFlag proves XKMS_CONFIG wins over --config: the
// flag names a valid, compliant file, the environment a missing one, and the
// load of the environment's path fails.
func TestRun_EnvConfigOverridesFlag(t *testing.T) {
	restoreFlags := swapFlagCommandLine(t)
	defer restoreFlags()
	setRunArgs(t, "--config", writeRunLifecycleConfig(t))
	t.Setenv("XKMS_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))

	if code := run(); code != 1 {
		t.Fatalf("run() with XKMS_CONFIG naming a missing file = %d, want 1", code)
	}
}

func TestRun_PIDFileWriteFailureReturnsOne(t *testing.T) {
	restoreFlags := swapFlagCommandLine(t)
	defer restoreFlags()
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}
	setRunArgs(t, "--config", writeRunLifecycleConfig(t), "--pid-file", filepath.Join(blocker, "xkmsd.pid"))

	if code := run(); code != 1 {
		t.Fatalf("run() with an unwritable PID file = %d, want 1", code)
	}
}

// TestRun_ServerConstructionFailureRemovesPIDFile makes server.New fail (the
// datastore path is a regular file) after the PID file is written, and checks
// run returns 1 and removes the PID file on the way out.
func TestRun_ServerConstructionFailureRemovesPIDFile(t *testing.T) {
	restoreFlags := swapFlagCommandLine(t)
	defer restoreFlags()
	path := writeRunLifecycleConfig(t)
	storage := filepath.Join(filepath.Dir(path), "storage")
	if err := os.WriteFile(storage, []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("write storage blocker: %v", err)
	}
	pidFile := filepath.Join(t.TempDir(), "xkmsd.pid")
	setRunArgs(t, "--config", path, "--pid-file", pidFile)

	if code := run(); code != 1 {
		t.Fatalf("run() with an unopenable datastore = %d, want 1", code)
	}
	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Fatalf("PID file still present after run() returned: stat err = %v", err)
	}
}

func TestServe_ACMEStartFailureShutsDownAndReturnsOne(t *testing.T) {
	srv, cfg := newServeTestServer(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}
	cfg.ACME = &config.ACMEConfig{Enabled: true, DataDir: filepath.Join(blocker, "acme")}

	// shutdownCtx is never canceled: serve must return on the ACME error
	// without reaching its shutdown wait.
	done := make(chan int, 1)
	go func() { done <- serve(context.Background(), srv, cfg, logger) }()

	select {
	case code := <-done:
		if code != 1 {
			t.Fatalf("serve() = %d, want 1 when the ACME server fails to start", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve() did not return promptly on an ACME start failure")
	}

	// serve shut the server down on the failure, so a second Shutdown has
	// nothing left to stop.
	if err := srv.Shutdown(); err != nil {
		t.Fatalf("Shutdown after serve's own shutdown: %v", err)
	}
}

// flagValue reads a flag's current value from the swapped flag set.
func flagValue(t *testing.T, name string) string {
	t.Helper()
	f := flag.CommandLine.Lookup(name)
	if f == nil {
		t.Fatalf("flag %q not registered", name)
	}
	return f.Value.String()
}
