//go:build integration

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

package integration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/test/integration/api/commands"
)

// TestSecretsRunnerIdentity checks the secrets matrix refuses to run a remote
// transport whose runner carries no usable credential, and accepts one with a
// client certificate and key or a token.
func TestSecretsRunnerIdentity(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key")
	for _, f := range []string{cert, key} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	missing := filepath.Join(dir, "absent.pem")

	cases := []struct {
		name   string
		runner commands.TestRunner
		ok     bool
	}{
		{"none", commands.TestRunner{}, false},
		{"cert-without-key", commands.TestRunner{ClientCert: cert}, false},
		{"key-without-cert", commands.TestRunner{ClientKey: key}, false},
		{"cert-file-missing", commands.TestRunner{ClientCert: missing, ClientKey: key}, false},
		{"key-file-missing", commands.TestRunner{ClientCert: cert, ClientKey: missing}, false},
		{"cert-and-key", commands.TestRunner{ClientCert: cert, ClientKey: key}, true},
		{"token", commands.TestRunner{Token: "set"}, true},
	}
	for _, protocol := range commands.CLIProtocols() {
		for _, tc := range cases {
			gap := runnerIdentityGap(&tc.runner, protocol)
			want := tc.ok || protocol == commands.ProtocolEmbedded
			if (gap == "") != want {
				t.Errorf("%s/%s: gap %q, want ok=%v", protocol, tc.name, gap, want)
			}
		}
	}
}

// TestSecretsAuthRefusal checks the outputs of a refused, unauthenticated call
// are told apart from other failures.
func TestSecretsAuthRefusal(t *testing.T) {
	refused := []string{
		"Error: rpc error: code = Unauthenticated desc = authentication required",
		"Error: HTTP 401 Unauthorized",
		"Error: rpc error: code = PermissionDenied desc = permission denied",
		"Error: HTTP 403 Forbidden",
	}
	for _, out := range refused {
		if !authRefusal(out) {
			t.Errorf("authRefusal(%q) = false, want true", out)
		}
	}
	other := []string{
		"",
		`{"id":"e1"}`,
		"Error: vault is locked",
		"Error: the backend needs a physical PIV token",
	}
	for _, out := range other {
		if authRefusal(out) {
			t.Errorf("authRefusal(%q) = true, want false", out)
		}
	}
}
