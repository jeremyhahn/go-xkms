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
  backend: "filesystem"
  path: "/data/xkms"

default_backend: "pkcs8"

backends:
  pkcs8:
    enabled: true
    path: "/data/xkms/pkcs8"
`

// TestReloadConfiguration_RefusesInsecureConfig verifies that a SIGHUP-triggered
// reload re-applies the secure-by-default gate: an insecure configuration is
// refused unless the daemon was started in insecure (development) mode. Without
// this gate a SIGHUP could quietly drop a running daemon to a non-compliant
// posture. The gate short-circuits before srv.Reload, so the nil *server.Server
// is never dereferenced on the refuse path.
func TestReloadConfiguration_RefusesInsecureConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "xkmsd.yaml")
	if err := os.WriteFile(path, []byte(insecureReloadConfig), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	err := reloadConfiguration(nil, path, false, logger)
	if err == nil {
		t.Fatal("expected reload to be refused for an insecure configuration")
	}
	if !strings.Contains(err.Error(), "refusing to reload an insecure configuration") {
		t.Fatalf("expected refuse-insecure error, got: %v", err)
	}
}
