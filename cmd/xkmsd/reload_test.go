// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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
	"errors"
	"flag"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// insecureReloadConfig is a valid configuration (config.Load accepts it) that is
// nonetheless non-compliant: encryption-at-rest (barrier), authentication, and a
// CA are all absent, so ComplianceGaps reports gaps.
const insecureReloadConfig = `
server:
  host: "localhost"
  rest_port: 8443
  grpc_port: 9443

protocols:
  rest: true
  grpc: true

logging:
  level: "info"
  format: "json"

tls:
  enabled: true
  cert_file: "/path/to/cert.pem"
  key_file: "/path/to/key.pem"

auth:
  enabled: false

storage:
  backend: "qrdb"
  path: "/data/xkms"

default_backend: "pkcs8"

backends:
  pkcs8:
    enabled: true
    path: "/data/xkms/pkcs8"
`

// TestReloadConfiguration_RefusesInsecureConfig verifies that a SIGHUP-triggered
// reload re-applies the secure-by-default gate: an insecure configuration is
// refused, unconditionally. Without this gate a SIGHUP could quietly drop a
// running daemon to a non-compliant posture. The gate short-circuits before
// srv.Reload, so the nil *server.Server is never dereferenced on the refuse
// path.
func TestReloadConfiguration_RefusesInsecureConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "xkmsd.yaml")
	if err := os.WriteFile(path, []byte(insecureReloadConfig), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	err := reloadConfiguration(nil, path, registerServerFlags(flag.NewFlagSet("xkmsd", flag.ContinueOnError)), flag.NewFlagSet("xkmsd", flag.ContinueOnError), logger)
	if err == nil {
		t.Fatal("expected reload to be refused for an insecure configuration")
	}
	if !strings.Contains(err.Error(), "refusing to reload an insecure configuration") {
		t.Fatalf("expected refuse-insecure error, got: %v", err)
	}

	// The refusal must hold no matter how the daemon was started: there is no
	// development override to fall back to.
	var insecureErr *InsecureReloadError
	if !errors.As(err, &insecureErr) {
		t.Fatalf("expected *InsecureReloadError, got %T", err)
	}
	if len(insecureErr.Gaps) == 0 {
		t.Error("refusal must name the compliance gaps that caused it")
	}
}

// TestResolveReloadConfig_ReappliesFlags proves a SIGHUP resolves the
// configuration through the same layers as start-up, flags included: a
// daemon started with --host keeps that host across a reload even when the
// file never mentions it. Before this the reload path called config.Load
// alone, so the flag was dropped and the next planned restart bound every
// interface.
func TestResolveReloadConfig_ReappliesFlags(t *testing.T) {
	path := writeHostConfig(t, "10.0.0.1")

	t.Run("set flag survives the reload", func(t *testing.T) {
		fs := flag.NewFlagSet("xkmsd", flag.ContinueOnError)
		flags := registerServerFlags(fs)
		if err := fs.Parse([]string{"-host", "10.0.0.5"}); err != nil {
			t.Fatalf("Parse: %v", err)
		}

		cfg, err := resolveReloadConfig(path, flags, fs)
		if err != nil {
			t.Fatalf("resolveReloadConfig: %v", err)
		}
		if cfg.Server.Host != "10.0.0.5" {
			t.Fatalf("Server.Host = %q after reload, want the --host value 10.0.0.5", cfg.Server.Host)
		}
	})

	t.Run("unset flag leaves the file value", func(t *testing.T) {
		fs := flag.NewFlagSet("xkmsd", flag.ContinueOnError)
		flags := registerServerFlags(fs)
		if err := fs.Parse(nil); err != nil {
			t.Fatalf("Parse: %v", err)
		}

		cfg, err := resolveReloadConfig(path, flags, fs)
		if err != nil {
			t.Fatalf("resolveReloadConfig: %v", err)
		}
		if cfg.Server.Host != "10.0.0.1" {
			t.Fatalf("Server.Host = %q after reload, want the file value 10.0.0.1", cfg.Server.Host)
		}
	})

	t.Run("unreadable file is ErrConfigLoad", func(t *testing.T) {
		fs := flag.NewFlagSet("xkmsd", flag.ContinueOnError)
		flags := registerServerFlags(fs)
		if _, err := resolveReloadConfig(filepath.Join(t.TempDir(), "missing.yaml"), flags, fs); !errors.Is(err, ErrConfigLoad) {
			t.Fatalf("expected ErrConfigLoad, got %v", err)
		}
	})
}
