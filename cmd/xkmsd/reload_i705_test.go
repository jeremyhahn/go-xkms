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

// go-xkms#705: reloadConfiguration's own config.Load failure path
// (main.go) was reached only through resolveReloadConfig directly
// (TestResolveReloadConfig_ReappliesFlags), never through reloadConfiguration
// itself -- the wrapper that a SIGHUP actually calls.

import (
	"errors"
	"flag"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
)

// TestReloadConfiguration_ConfigLoadFailure proves a SIGHUP naming a config
// file that no longer exists (deleted or renamed since start-up) fails the
// reload with a *WrappedError around ErrConfigLoad, and never reaches
// srv.Reload -- proven here by passing a nil *server.Server, which a reload
// that tried to dereference it would panic on.
func TestReloadConfiguration_ConfigLoadFailure(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.yaml")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	err := reloadConfiguration(nil, missing, registerServerFlags(flag.NewFlagSet("xkmsd", flag.ContinueOnError)), flag.NewFlagSet("xkmsd", flag.ContinueOnError), logger)
	if err == nil {
		t.Fatal("reloadConfiguration with a missing config file = nil error, want a refusal")
	}
	if !errors.Is(err, ErrConfigLoad) {
		t.Fatalf("reloadConfiguration error = %v, want errors.Is(err, ErrConfigLoad)", err)
	}
	var wrapped *WrappedError
	if !errors.As(err, &wrapped) {
		t.Fatalf("reloadConfiguration error = %T, want *WrappedError", err)
	}
}
