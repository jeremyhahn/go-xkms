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
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// TestParseACMETLSVersion covers every recognized spelling
// buildACMETLSConfig accepts for acme.tls.min_version / max_version, plus
// the unrecognized-value fallback that leaves the caller's default alone.
func TestParseACMETLSVersion(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want uint16
	}{
		{"TLS1.2 canonical", "TLS1.2", tls.VersionTLS12},
		{"tls1.2 lowercase", "tls1.2", tls.VersionTLS12},
		{"1.2 bare", "1.2", tls.VersionTLS12},
		{"TLS1.3 canonical", "TLS1.3", tls.VersionTLS13},
		{"tls1.3 lowercase", "tls1.3", tls.VersionTLS13},
		{"1.3 bare", "1.3", tls.VersionTLS13},
		{"unrecognized", "TLS1.1", 0},
		{"empty", "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseACMETLSVersion(tt.in); got != tt.want {
				t.Errorf("parseACMETLSVersion(%q) = %#x, want %#x", tt.in, got, tt.want)
			}
		})
	}
}

// TestBuildACMETLSConfig_MaxVersion proves acme.tls.max_version is applied
// through the same parseACMETLSVersion path as MinVersion, exercised
// separately by TestBuildACMETLSConfig_Success.
func TestBuildACMETLSConfig_MaxVersion(t *testing.T) {
	certPath, keyPath := writeACMETestCertAndKey(t, t.TempDir())

	tlsCfg, err := buildACMETLSConfig(&config.ACMEConfig{
		TLS: config.ACMETLSConfig{
			CertFile:   certPath,
			KeyFile:    keyPath,
			MaxVersion: "1.3",
		},
	})
	if err != nil {
		t.Fatalf("buildACMETLSConfig() error = %v", err)
	}
	if tlsCfg.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("tlsCfg.MaxVersion = %#x, want TLS1.3", tlsCfg.MaxVersion)
	}
}

// TestBuildACMETLSConfig_UnrecognizedVersionLeavesDefault proves an
// unrecognized min/max version string is ignored rather than zeroing out
// tls.Config's version field (parseACMETLSVersion returns 0, and
// buildACMETLSConfig only assigns when v > 0).
func TestBuildACMETLSConfig_UnrecognizedVersionLeavesDefault(t *testing.T) {
	certPath, keyPath := writeACMETestCertAndKey(t, t.TempDir())

	tlsCfg, err := buildACMETLSConfig(&config.ACMEConfig{
		TLS: config.ACMETLSConfig{
			CertFile:   certPath,
			KeyFile:    keyPath,
			MinVersion: "not-a-version",
		},
	})
	if err != nil {
		t.Fatalf("buildACMETLSConfig() error = %v", err)
	}
	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("tlsCfg.MinVersion = %#x, want the untouched default TLS1.3", tlsCfg.MinVersion)
	}
}

// TestBuildACMETLSConfig_ClientAuth covers every acme.tls.client_auth value
// buildACMETLSConfig maps to a tls.ClientAuthType.
func TestBuildACMETLSConfig_ClientAuth(t *testing.T) {
	tests := []struct {
		value string
		want  tls.ClientAuthType
	}{
		{"request", tls.RequestClientCert},
		{"require", tls.RequireAnyClientCert},
		{"verify", tls.VerifyClientCertIfGiven},
		{"require_and_verify", tls.RequireAndVerifyClientCert},
		{"", tls.NoClientCert},
		{"none", tls.NoClientCert},
	}
	for _, tt := range tests {
		t.Run("client_auth="+tt.value, func(t *testing.T) {
			certPath, keyPath := writeACMETestCertAndKey(t, t.TempDir())
			tlsCfg, err := buildACMETLSConfig(&config.ACMEConfig{
				TLS: config.ACMETLSConfig{
					CertFile:   certPath,
					KeyFile:    keyPath,
					ClientAuth: tt.value,
				},
			})
			if err != nil {
				t.Fatalf("buildACMETLSConfig() error = %v", err)
			}
			if tlsCfg.ClientAuth != tt.want {
				t.Errorf("ClientAuth = %v, want %v", tlsCfg.ClientAuth, tt.want)
			}
		})
	}
}

// TestBuildACMETLSConfig_ClientCAsLoaded proves a valid client CA bundle is
// parsed into tlsCfg.ClientCAs rather than only exercising the failure
// paths (TestBuildACMETLSConfig_RejectsUnparseableClientCA).
func TestBuildACMETLSConfig_ClientCAsLoaded(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeACMETestCertAndKey(t, dir)

	tlsCfg, err := buildACMETLSConfig(&config.ACMEConfig{
		TLS: config.ACMETLSConfig{
			CertFile:   certPath,
			KeyFile:    keyPath,
			ClientAuth: "require_and_verify",
			// The server's own certificate is a valid, unrelated PEM
			// certificate; buildACMETLSConfig only requires it parse.
			ClientCAs: []string{certPath},
		},
	})
	if err != nil {
		t.Fatalf("buildACMETLSConfig() error = %v", err)
	}
	if tlsCfg.ClientCAs == nil {
		t.Fatal("tlsCfg.ClientCAs = nil, want a populated cert pool")
	}
	if len(tlsCfg.ClientCAs.Subjects()) != 1 { //nolint:staticcheck // Subjects() is deprecated but still the simplest count here.
		t.Errorf("tlsCfg.ClientCAs contains %d subject(s), want 1", len(tlsCfg.ClientCAs.Subjects())) //nolint:staticcheck
	}
}

// TestBuildACMETLSConfig_ClientCAsUnreadable proves a client CA path that
// cannot be read (as opposed to one that reads but fails to parse, covered
// by TestBuildACMETLSConfig_RejectsUnparseableClientCA) fails with the same
// ErrACMEClientCALoad sentinel.
func TestBuildACMETLSConfig_ClientCAsUnreadable(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeACMETestCertAndKey(t, dir)

	_, err := buildACMETLSConfig(&config.ACMEConfig{
		TLS: config.ACMETLSConfig{
			CertFile:   certPath,
			KeyFile:    keyPath,
			ClientAuth: "require_and_verify",
			ClientCAs:  []string{filepath.Join(dir, "does-not-exist.pem")},
		},
	})
	if err == nil {
		t.Fatal("expected error for an unreadable client CA path")
	}
	if !errors.Is(err, ErrACMEClientCALoad) {
		t.Errorf("err = %v, want errors.Is match against ErrACMEClientCALoad", err)
	}
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) {
		t.Errorf("err = %v, want the underlying *os.PathError reachable via errors.As", err)
	}
}
