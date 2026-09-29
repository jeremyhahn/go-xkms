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
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// writeHostConfig writes a minimal valid daemon configuration with the given
// server.host and returns its path.
func writeHostConfig(t *testing.T, host string) string {
	t.Helper()

	content := `
server:
  host: "` + host + `"
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
auth:
  enabled: false
datastore:
  engine: "pebble"
  path: "/data"
default_backend: "pkcs8"
backends:
  pkcs8:
    enabled: true
    path: "/data/pkcs8"
`
	path := filepath.Join(t.TempDir(), "xkmsd.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// loadWithServerFlags runs the daemon's resolution order end to end: Load
// (defaults, file, env) followed by the flags parsed from args.
func loadWithServerFlags(t *testing.T, path string, args []string) *config.Config {
	t.Helper()

	fs := flag.NewFlagSet("xkmsd", flag.ContinueOnError)
	flags := registerServerFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("Parse(%v) error = %v", args, err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	flags.apply(cfg, fs)
	return cfg
}

// TestServerHost_Precedence proves the full order for server.host, one layer
// at a time: defaults, then the file over the defaults, then the environment
// over the file, then the flag over the environment (go-xkms#140, items 1-3).
func TestServerHost_Precedence(t *testing.T) {
	t.Run("file over defaults", func(t *testing.T) {
		cfg := loadWithServerFlags(t, writeHostConfig(t, "10.0.0.1"), nil)
		if cfg.Server.Host != "10.0.0.1" {
			t.Fatalf("Server.Host = %q, want file value 10.0.0.1", cfg.Server.Host)
		}
	})

	t.Run("env over file", func(t *testing.T) {
		t.Setenv("XKMS_SERVER_HOST", "10.0.0.2")
		cfg := loadWithServerFlags(t, writeHostConfig(t, "10.0.0.1"), nil)
		if cfg.Server.Host != "10.0.0.2" {
			t.Fatalf("Server.Host = %q, want env value 10.0.0.2", cfg.Server.Host)
		}
	})

	t.Run("flag over env and file", func(t *testing.T) {
		t.Setenv("XKMS_SERVER_HOST", "10.0.0.2")
		cfg := loadWithServerFlags(t, writeHostConfig(t, "10.0.0.1"), []string{"-host", "10.0.0.3"})
		if cfg.Server.Host != "10.0.0.3" {
			t.Fatalf("Server.Host = %q, want flag value 10.0.0.3", cfg.Server.Host)
		}
	})
}

// TestServerHost_UnsetFlagDoesNotClobber proves the flag layer is applied
// only when set: an absent --host leaves the resolved host alone, while an
// explicit empty --host is honoured as "every interface" because it was set.
func TestServerHost_UnsetFlagDoesNotClobber(t *testing.T) {
	t.Run("absent flag keeps the env value", func(t *testing.T) {
		t.Setenv("XKMS_SERVER_HOST", "10.0.0.2")
		cfg := loadWithServerFlags(t, writeHostConfig(t, "10.0.0.1"), []string{})
		if cfg.Server.Host != "10.0.0.2" {
			t.Fatalf("Server.Host = %q, want env value 10.0.0.2 untouched by an unset flag", cfg.Server.Host)
		}
	})

	t.Run("explicit empty flag wins", func(t *testing.T) {
		t.Setenv("XKMS_SERVER_HOST", "10.0.0.2")
		cfg := loadWithServerFlags(t, writeHostConfig(t, "10.0.0.1"), []string{"-host", ""})
		if cfg.Server.Host != config.DefaultServerHost {
			t.Fatalf("Server.Host = %q, want the explicit empty flag value", cfg.Server.Host)
		}
	})
}

// TestFlagWasSet covers the Changed() equivalent for the standard flag set.
func TestFlagWasSet(t *testing.T) {
	fs := flag.NewFlagSet("xkmsd", flag.ContinueOnError)
	registerServerFlags(fs)
	if err := fs.Parse([]string{"-host", "10.0.0.3"}); err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !flagWasSet(fs, "host") {
		t.Fatal("flagWasSet(host) = false after -host was parsed")
	}
	if flagWasSet(fs, "missing") {
		t.Fatal("flagWasSet(missing) = true for a flag that does not exist")
	}
}
