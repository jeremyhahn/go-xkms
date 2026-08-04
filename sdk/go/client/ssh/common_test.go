// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// TestBuildTLSConfig_ErrorMapping pins the ProtocolError mapping every TLS
// scheme (https/grpcs/quic/mcps) shares: the shared transport helper's typed
// errors must surface with the exact messages the per-transport forks used
// before the dedup.
func TestBuildTLSConfig_ErrorMapping(t *testing.T) {
	dir := t.TempDir()
	junk := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(junk, []byte("not a certificate"), 0600); err != nil {
		t.Fatalf("write junk: %v", err)
	}

	tests := []struct {
		name    string
		opts    transport.TLSOptions
		wantMsg string
	}{
		{
			name:    "unreadable ca file",
			opts:    transport.TLSOptions{CAFile: filepath.Join(dir, "missing.pem")},
			wantMsg: "read tls ca",
		},
		{
			name:    "unparseable ca file",
			opts:    transport.TLSOptions{CAFile: junk},
			wantMsg: "parse tls ca: no certificates found",
		},
		{
			name:    "bad client keypair",
			opts:    transport.TLSOptions{CertFile: junk, KeyFile: junk},
			wantMsg: "load client certificate",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildTLSConfig(tc.opts)
			var perr *ProtocolError
			if !errors.As(err, &perr) {
				t.Fatalf("expected *ProtocolError, got %T: %v", err, err)
			}
			if !strings.HasPrefix(perr.Message, tc.wantMsg) {
				t.Fatalf("expected message prefix %q, got %q", tc.wantMsg, perr.Message)
			}
		})
	}
}

// TestBuildTLSConfig_Success verifies the pass-through: a valid option set
// yields the shared helper's TLS 1.3 config unchanged.
func TestBuildTLSConfig_Success(t *testing.T) {
	cfg, err := buildTLSConfig(transport.TLSOptions{ServerName: "xkms.example.com"})
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("expected TLS 1.3 minimum, got %#x", cfg.MinVersion)
	}
	if cfg.ServerName != "xkms.example.com" {
		t.Fatalf("expected server name override, got %q", cfg.ServerName)
	}
}

// TestTLSConfigFromCA_Empty verifies the system-roots path: an empty caFile
// returns a minimal TLS 1.3 config with a nil root pool.
func TestTLSConfigFromCA_Empty(t *testing.T) {
	cfg, err := tlsConfigFromCA("")
	if err != nil {
		t.Fatalf("tlsConfigFromCA: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 || cfg.RootCAs != nil {
		t.Fatal("expected minimal TLS 1.3 config with system roots")
	}
}

// TestParseExportedPublicKey covers the shared remote-signer parse helper
// used by the REST, gRPC, and MCP Signer constructors.
func TestParseExportedPublicKey(t *testing.T) {
	t.Run("valid authorized_keys line", func(t *testing.T) {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		sshPub, err := gossh.NewPublicKey(pub)
		if err != nil {
			t.Fatalf("new public key: %v", err)
		}
		line := string(gossh.MarshalAuthorizedKey(sshPub))

		parsed, err := parseExportedPublicKey(line)
		if err != nil {
			t.Fatalf("parseExportedPublicKey: %v", err)
		}
		if parsed.Type() != sshPub.Type() {
			t.Fatalf("expected type %q, got %q", sshPub.Type(), parsed.Type())
		}
	})

	t.Run("invalid line", func(t *testing.T) {
		_, err := parseExportedPublicKey("not an authorized_keys line")
		var perr *ProtocolError
		if !errors.As(err, &perr) {
			t.Fatalf("expected *ProtocolError, got %T: %v", err, err)
		}
		if perr.Message != "parse exported public key" {
			t.Fatalf("unexpected message %q", perr.Message)
		}
	})
}

// TestStripCallbackPort covers the shared HostKeyCallback hostname
// normalization used by the REST, gRPC, and MCP KnownHosts callbacks.
func TestStripCallbackPort(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"example.com:22", "example.com"},
		{"example.com", "example.com"},
		{"[::1]:22", "::1"},
		{"10.0.0.1:2222", "10.0.0.1"},
	}
	for _, tc := range tests {
		if got := stripCallbackPort(tc.in); got != tc.want {
			t.Errorf("stripCallbackPort(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
