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

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
)

// swapRunSeams points run at the given fakes for the duration of one test.
func swapRunSeams(t *testing.T,
	resolve func(context.Context, *slog.Logger) (Connection, func(), error),
	gui func(Connection, *slog.Logger) error,
) {
	t.Helper()
	oldResolve, oldGUI := resolveConnectionFn, runGUIFn
	resolveConnectionFn, runGUIFn = resolve, gui
	t.Cleanup(func() { resolveConnectionFn, runGUIFn = oldResolve, oldGUI })
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestRun_CleanupRunsWhenGUIFails is the regression this extraction exists
// for.
//
// main used to call os.Exit(1) on the GUI error path with `defer cleanup()`
// already registered. os.Exit does not run deferred functions, so in
// standalone mode the in-process loopback engine was never stopped when the
// GUI returned an error -- the one path where stopping it matters most,
// because the process is going down unexpectedly.
//
// The exit therefore moved to main and the work moved here, and this asserts
// the property that move was for: cleanup runs even when the GUI fails.
func TestRun_CleanupRunsWhenGUIFails(t *testing.T) {
	cleanups := 0
	guiErr := errors.New("gui exploded")

	swapRunSeams(t,
		func(context.Context, *slog.Logger) (Connection, func(), error) {
			return Connection{}, func() { cleanups++ }, nil
		},
		func(Connection, *slog.Logger) error { return guiErr },
	)

	err := run(quietLogger())

	if !errors.Is(err, guiErr) {
		t.Errorf("run returned %v, want the GUI's error so main can set the exit status", err)
	}
	if cleanups != 1 {
		t.Errorf("cleanup ran %d times on the GUI error path, want exactly 1: "+
			"the standalone engine must be stopped even when the GUI fails", cleanups)
	}
}

func TestRun_CleanupRunsOnce_WhenGUISucceeds(t *testing.T) {
	cleanups := 0

	swapRunSeams(t,
		func(context.Context, *slog.Logger) (Connection, func(), error) {
			return Connection{}, func() { cleanups++ }, nil
		},
		func(Connection, *slog.Logger) error { return nil },
	)

	if err := run(quietLogger()); err != nil {
		t.Fatalf("run returned %v, want nil on the success path", err)
	}
	if cleanups != 1 {
		t.Errorf("cleanup ran %d times, want exactly 1", cleanups)
	}
}

// TestRun_NoCleanupWhenResolveFails pins the other half: there is nothing to
// clean up if the connection was never established, and run must not invoke a
// cleanup func it was never handed.
func TestRun_NoCleanupWhenResolveFails(t *testing.T) {
	cleanups := 0
	resolveErr := errors.New("no engine")
	guiRuns := 0

	swapRunSeams(t,
		func(context.Context, *slog.Logger) (Connection, func(), error) {
			// A non-nil cleanup alongside an error: run must ignore it rather
			// than call it, and must not depend on resolveConnection
			// returning nil here.
			return Connection{}, func() { cleanups++ }, resolveErr
		},
		func(Connection, *slog.Logger) error { guiRuns++; return nil },
	)

	err := run(quietLogger())

	if !errors.Is(err, resolveErr) {
		t.Errorf("run returned %v, want the resolver's error", err)
	}
	if cleanups != 0 {
		t.Errorf("cleanup ran %d times after resolution failed, want 0", cleanups)
	}
	if guiRuns != 0 {
		t.Errorf("the GUI ran %d times after resolution failed, want 0", guiRuns)
	}
}
