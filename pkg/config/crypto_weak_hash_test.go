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

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// loadableConfig is the smallest configuration Load accepts (validation
// requires at least one protocol), so a test can add one section and attribute
// the result to it.
const loadableConfig = `
protocols:
  rest: true

server:
  host: "localhost"
  rest_port: 8443

logging:
  level: info
  format: json

storage:
  backend: file
  path: /tmp/xkms-config-test

default_backend: software

backends:
  software:
    enabled: true
    path: /tmp/xkms-config-test/keys
`

// writeConfig writes loadableConfig plus body to a temporary xkmsd.yaml and
// returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "xkmsd.yaml")
	if err := os.WriteFile(path, []byte(loadableConfig+body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// TestLoad_CryptoAllowWeakHashes covers the operator-facing half of the
// weak-hash policy: the YAML key has to reach the field server.New passes to
// types.SetAllowWeakHashes. A key that parses into nothing would leave the
// daemon refusing SHA-1 while the operator's file says otherwise, with no
// error to explain it.
//
// The absent case is the one that matters most — the secure default has to
// survive a configuration that never mentions the setting.
func TestLoad_CryptoAllowWeakHashes(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{
			name: "opt-in is parsed",
			body: "crypto:\n  allow_weak_hashes: true\n",
			want: true,
		},
		{
			name: "explicit refusal is parsed",
			body: "crypto:\n  allow_weak_hashes: false\n",
			want: false,
		},
		{
			name: "absent crypto section refuses",
			body: "",
			want: false,
		},
		{
			name: "empty crypto section refuses",
			body: "crypto: {}\n",
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(writeConfig(t, tc.body))
			if err != nil {
				t.Fatalf("Load() error = %v, want nil", err)
			}
			if got := cfg.Crypto.AllowWeakHashes; got != tc.want {
				t.Errorf("Crypto.AllowWeakHashes = %t, want %t", got, tc.want)
			}
		})
	}
}

// TestLoad_CryptoAllowWeakHashes_RejectsNonBoolean is the bad-input case. A
// non-boolean value must fail the load rather than be coerced or ignored:
// silently reading it as false would strand an operator who needs the legacy
// digests, and silently reading it as true would admit forgeable signatures
// on a typo.
func TestLoad_CryptoAllowWeakHashes_RejectsNonBoolean(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"string value", "crypto:\n  allow_weak_hashes: \"sure\"\n"},
		{"mapping value", "crypto:\n  allow_weak_hashes:\n    enabled: true\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(writeConfig(t, tc.body))
			if err == nil {
				t.Fatalf("Load() error = nil, want a type error; AllowWeakHashes = %t",
					cfg.Crypto.AllowWeakHashes)
			}
		})
	}
}
