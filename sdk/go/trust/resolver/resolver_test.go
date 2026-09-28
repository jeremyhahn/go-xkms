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

package resolver

import (
	"os"
	"path/filepath"
	"testing"
)

// baseConfigBody is a minimal daemon configuration that satisfies
// (*pkgconfig.Config).Validate on its own, mirroring pkg/config's own
// load_test.go fixture. trustLines is inserted verbatim so callers can
// append (or omit) a trust: section.
func baseConfigBody(trustLines string) string {
	return `
server:
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

storage:
  backend: "qrdb"
  path: "/data"

default_backend: "pkcs8"

backends:
  pkcs8:
    enabled: true
    path: "/data/pkcs8"
` + trustLines
}

// writeConfig writes body to a temp xkmsd.yaml and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "xkmsd.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// TestLoadTrustConfig_NoTrustSection proves that a valid daemon config
// with no trust: section resolves to a nil *Config and a nil error --
// Trust is optional (yaml:",omitempty") and LoadTrustConfig must not
// synthesize a default in its place.
func TestLoadTrustConfig_NoTrustSection(t *testing.T) {
	path := writeConfig(t, baseConfigBody(""))

	cfg, err := LoadTrustConfig(path)
	if err != nil {
		t.Fatalf("LoadTrustConfig() error = %v", err)
	}
	if cfg != nil {
		t.Fatalf("LoadTrustConfig() = %+v, want nil (no trust: section in the file)", cfg)
	}
}

// TestLoadTrustConfig_WithTrustSection proves the trust: section round
// trips through pkgconfig.Load into the returned *Config, i.e. that
// LoadTrustConfig reaches the same field the daemon does rather than a
// re-parsed copy.
func TestLoadTrustConfig_WithTrustSection(t *testing.T) {
	trustSection := `
trust:
  scopes:
    default:
      strategies: ["embedded"]
      server-url: "https://kms.example.com:8443"
`
	path := writeConfig(t, baseConfigBody(trustSection))

	cfg, err := LoadTrustConfig(path)
	if err != nil {
		t.Fatalf("LoadTrustConfig() error = %v", err)
	}
	if cfg == nil {
		t.Fatal("LoadTrustConfig() = nil, want a populated trust config")
	}
	scope, ok := cfg.Scopes["default"]
	if !ok {
		t.Fatalf("cfg.Scopes = %+v, want a \"default\" scope", cfg.Scopes)
	}
	if len(scope.Strategies) != 1 || scope.Strategies[0] != StrategyEmbedded {
		t.Errorf("scope.Strategies = %v, want [%q]", scope.Strategies, StrategyEmbedded)
	}
	if scope.ServerURL != "https://kms.example.com:8443" {
		t.Errorf("scope.ServerURL = %q, want the configured URL", scope.ServerURL)
	}
}

// TestLoadTrustConfig_MissingFile proves a nonexistent path surfaces as an
// error instead of a nil, nil success -- a caller that ignores the error
// and dereferences the Config would otherwise nil-panic on a typo'd path.
func TestLoadTrustConfig_MissingFile(t *testing.T) {
	cfg, err := LoadTrustConfig(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("LoadTrustConfig() error = nil, want an error for a missing file")
	}
	if cfg != nil {
		t.Errorf("LoadTrustConfig() = %+v, want nil on error", cfg)
	}
}

// TestLoadTrustConfig_InvalidConfig proves a file that fails
// pkgconfig.Config.Validate (here: no protocol enabled) propagates that
// error rather than being swallowed.
func TestLoadTrustConfig_InvalidConfig(t *testing.T) {
	body := `
protocols:
  rest: false
  grpc: false

logging:
  level: "info"
  format: "json"

storage:
  backend: "qrdb"
  path: "/data"

default_backend: "pkcs8"

backends:
  pkcs8:
    enabled: true
    path: "/data/pkcs8"
`
	path := writeConfig(t, body)

	cfg, err := LoadTrustConfig(path)
	if err == nil {
		t.Fatal("LoadTrustConfig() error = nil, want a validation error")
	}
	if cfg != nil {
		t.Errorf("LoadTrustConfig() = %+v, want nil on error", cfg)
	}
}
