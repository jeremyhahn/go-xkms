// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package main

// Tests for main.go: PID file handling, the signal handler, and run()'s
// flag/command wiring. run() itself is otherwise reached only through
// os.Exit (main()) or a live server.New/srv.Start, which this batch's scope
// (#705 batch D) excludes; the cases here are the branches reachable without
// either.

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ============================================================================
// writePIDFile / removePIDFile
// ============================================================================

func TestWritePIDFile_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "xkmsd.pid")

	if err := writePIDFile(path); err != nil {
		t.Fatalf("writePIDFile: %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	got := strings.TrimSpace(string(content))
	want := strconv.Itoa(os.Getpid())
	if got != want {
		t.Errorf("PID file contains %q, want the current process ID %q", got, want)
	}
}

// TestWritePIDFile_DirectoryCreateFails uses ENOTDIR rather than a
// permission bit: CI runs these tests as root, which ignores file-mode
// permissions entirely, but a *file* standing where a *directory* is
// required fails MkdirAll no matter who is asking.
func TestWritePIDFile_DirectoryCreateFails(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}
	// "blocker" is a plain file; asking to create a directory under it can
	// never succeed, root or not.
	path := filepath.Join(blocker, "subdir", "xkmsd.pid")

	err := writePIDFile(path)
	if !errors.Is(err, ErrPIDDirCreate) {
		t.Fatalf("writePIDFile(blocked dir) = %v, want ErrPIDDirCreate", err)
	}
}

// TestWritePIDFile_WriteFails uses the same ENOTDIR shape for the write step:
// the target path itself is a directory, so os.WriteFile can never succeed
// there regardless of the caller's privileges.
func TestWritePIDFile_WriteFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "xkmsd.pid")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	err := writePIDFile(path)
	if !errors.Is(err, ErrPIDFileWrite) {
		t.Fatalf("writePIDFile(path is a directory) = %v, want ErrPIDFileWrite", err)
	}
}

func TestRemovePIDFile_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "xkmsd.pid")
	if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
		t.Fatalf("write PID file: %v", err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	removePIDFile(path, logger)

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("PID file still exists after removePIDFile: stat error = %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("removePIDFile logged on a clean removal: %s", buf.String())
	}
}

// TestRemovePIDFile_MissingFileIsLogged proves the failure path logs a
// warning rather than panicking or silently ignoring a PID file that is
// already gone.
func TestRemovePIDFile_MissingFileIsLogged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.pid")

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	removePIDFile(path, logger)

	if !strings.Contains(buf.String(), "Failed to remove PID file") {
		t.Errorf("removePIDFile(missing file) did not log a warning; got:\n%s", buf.String())
	}
}

// ============================================================================
// setupSignalHandler
// ============================================================================

// TestSetupSignalHandler_SIGTERMCancelsContext mirrors
// cmd/acme-client's TestServiceStartCmd_SignalShutdown: it delivers a real
// SIGTERM to this test process and proves the returned context is canceled
// as a result, exactly as run()'s shutdown-wait (`<-shutdownCtx.Done()`)
// depends on.
func TestSetupSignalHandler_SIGTERMCancelsContext(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, reloadCh := setupSignalHandler(logger)
	_ = reloadCh

	// Give the goroutine time to reach signal.Notify before delivering
	// SIGTERM.
	time.Sleep(150 * time.Millisecond)
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("failed to send SIGTERM to self: %v", err)
	}

	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("context was not canceled after SIGTERM was delivered")
	}
}

// TestSetupSignalHandler_SIGHUPReachesReloadChannel proves the second half of
// setupSignalHandler's contract: SIGHUP is forwarded on reloadCh rather than
// canceling the shutdown context, so a running daemon can distinguish
// "reload configuration" from "shut down".
func TestSetupSignalHandler_SIGHUPReachesReloadChannel(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, reloadCh := setupSignalHandler(logger)

	time.Sleep(150 * time.Millisecond)
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("failed to send SIGHUP to self: %v", err)
	}

	select {
	case <-reloadCh:
	case <-time.After(5 * time.Second):
		t.Fatal("SIGHUP was not delivered on reloadCh")
	}

	select {
	case <-ctx.Done():
		t.Fatal("SIGHUP must not cancel the shutdown context")
	default:
	}
}

// ============================================================================
// run(): the branches reachable without a live server.New / srv.Start.
// ============================================================================

// TestRun_DispatchesRegisteredSubcommand pins the map-based dispatch itself
// (CLAUDE.md's O(1)-lookup convention): os.Args[1] naming a registered
// subcommand runs its handler and returns 0 without ever reaching the
// flag-parsing / server-construction path below it. The real "init" entry is
// swapped out for the duration of the test because runInit calls os.Exit,
// which would terminate the test binary.
func TestRun_DispatchesRegisteredSubcommand(t *testing.T) {
	original := subcommands
	t.Cleanup(func() { subcommands = original })

	called := false
	var gotArgs []string
	subcommands = map[string]func([]string){
		"init": func(args []string) {
			called = true
			gotArgs = args
		},
	}

	origArgs := os.Args
	os.Args = []string{"xkmsd", "init", "--so-pin", "1234"}
	t.Cleanup(func() { os.Args = origArgs })

	if code := run(); code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
	if !called {
		t.Fatal("run() did not dispatch to the registered \"init\" subcommand")
	}
	if len(gotArgs) != 2 || gotArgs[0] != "--so-pin" || gotArgs[1] != "1234" {
		t.Fatalf("run() dispatched with args %v, want the arguments following the subcommand name", gotArgs)
	}
}

// TestRun_UnknownArgFallsThroughToFlagParsing proves the dispatch table does
// not swallow ordinary flags: an os.Args[1] that names no subcommand (an
// ordinary flag like --version) falls through to flag.Parse rather than
// being treated as an unrecognized subcommand.
func TestRun_UnknownArgFallsThroughToFlagParsing(t *testing.T) {
	restoreFlags := swapFlagCommandLine(t)
	defer restoreFlags()

	origArgs := os.Args
	os.Args = []string{"xkmsd", "--version"}
	t.Cleanup(func() { os.Args = origArgs })

	stdout := captureStdout(t, func() {
		if code := run(); code != 0 {
			t.Fatalf("run() = %d, want 0", code)
		}
	})

	if !strings.Contains(stdout, "xKMS Daemon") {
		t.Fatalf("run() --version output = %q, want it to identify the daemon", stdout)
	}
}

// TestRun_ConfigLoadFailureReturnsOne proves a config path that cannot be
// loaded fails start-up with exit code 1 rather than panicking or silently
// falling back to defaults.
func TestRun_ConfigLoadFailureReturnsOne(t *testing.T) {
	restoreFlags := swapFlagCommandLine(t)
	defer restoreFlags()

	origArgs := os.Args
	os.Args = []string{"xkmsd", "--config", filepath.Join(t.TempDir(), "does-not-exist.yaml")}
	t.Cleanup(func() { os.Args = origArgs })

	if code := run(); code != 1 {
		t.Fatalf("run() with an unreadable --config = %d, want 1", code)
	}
}

// TestRun_InsecureConfigRefusesToStart proves the secure-by-default gate
// (main.go's cfg.ComplianceGaps() check) refuses a structurally valid but
// non-compliant configuration and returns 1 before ever reaching
// server.New -- the one branch of run() past config loading that this
// batch's scope (no live server) can still reach deterministically.
func TestRun_InsecureConfigRefusesToStart(t *testing.T) {
	restoreFlags := swapFlagCommandLine(t)
	defer restoreFlags()

	path := filepath.Join(t.TempDir(), "xkmsd.yaml")
	if err := os.WriteFile(path, []byte(insecureReloadConfig), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	origArgs := os.Args
	os.Args = []string{"xkmsd", "--config", path}
	t.Cleanup(func() { os.Args = origArgs })

	if code := run(); code != 1 {
		t.Fatalf("run() with an insecure config = %d, want 1", code)
	}
}

// swapFlagCommandLine points the package-level flag.CommandLine at a fresh
// FlagSet for the duration of a test, restoring the original afterwards.
// run() registers its flags directly on flag.CommandLine on every call, and
// the flag package panics ("flag redefined") on a second registration of the
// same name against one FlagSet -- exactly what calling run() from more than
// one test in this binary would otherwise do. flag.ContinueOnError (rather
// than the default ExitOnError) keeps a parse failure from calling os.Exit
// out from under the test.
func swapFlagCommandLine(t *testing.T) func() {
	t.Helper()
	original := flag.CommandLine
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	flag.CommandLine = fs
	return func() { flag.CommandLine = original }
}
