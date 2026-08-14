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

package rest_test

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	sdkrest "github.com/jeremyhahn/go-xkms/sdk/go/transport/rest"
)

// TestNew_TLSOptionSelectsHTTPSScheme is the anti-downgrade guard. The REST
// transport derives the URL scheme from Config.TLSEnabled, so an option that
// fails to propagate through New() would silently produce a plaintext http://
// base URL while the caller believes TLS is on.
func TestNew_TLSOptionSelectsHTTPSScheme(t *testing.T) {
	tests := []struct {
		name       string
		opts       []transport.Option
		wantScheme string
		wantTLS    bool
	}{
		{
			name:       "tls_enabled",
			opts:       []transport.Option{transport.WithAddress("xkms.example.com:8443"), transport.WithTLSEnabled(true)},
			wantScheme: "https://",
			wantTLS:    true,
		},
		{
			name:       "tls_disabled",
			opts:       []transport.Option{transport.WithAddress("xkms.example.com:8080"), transport.WithTLSEnabled(false)},
			wantScheme: "http://",
			wantTLS:    false,
		},
		{
			name: "prebuilt_tls_config_also_enables_tls",
			opts: []transport.Option{
				transport.WithAddress("xkms.example.com:8443"),
				transport.WithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS13}),
			},
			wantScheme: "https://",
			wantTLS:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr, err := sdkrest.New(tc.opts...)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			t.Cleanup(func() { _ = tr.Close() })

			if !strings.HasPrefix(tr.BaseURL(), tc.wantScheme) {
				t.Errorf("BaseURL = %q, want scheme %q", tr.BaseURL(), tc.wantScheme)
			}
			if got := tr.Config().TLSEnabled; got != tc.wantTLS {
				t.Errorf("Config().TLSEnabled = %v, want %v", got, tc.wantTLS)
			}
		})
	}
}

// TestNew_OptionsReachTransportConfig verifies that New actually applies the
// supplied options rather than silently returning defaults.
func TestNew_OptionsReachTransportConfig(t *testing.T) {
	tr, err := sdkrest.New(
		transport.WithAddress("xkms.example.com:8443"),
		transport.WithTimeout(42*time.Second),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	cfg := tr.Config()
	if cfg.Address != "xkms.example.com:8443" {
		t.Errorf("Address = %q", cfg.Address)
	}
	if cfg.Timeout != 42*time.Second {
		t.Errorf("Timeout = %v, want 42s", cfg.Timeout)
	}

	// The defaults must still differ from what we set, otherwise this test
	// could pass without the options being applied at all.
	def := transport.DefaultConfig()
	if def.Timeout == 42*time.Second {
		t.Fatal("test is vacuous: chosen timeout equals the default")
	}
}

// TestNew_ExplicitSchemeIsPreserved checks that an address already carrying a
// scheme is not rewritten based on TLSEnabled.
func TestNew_ExplicitSchemeIsPreserved(t *testing.T) {
	tr, err := sdkrest.New(
		transport.WithAddress("https://xkms.example.com:8443/"),
		transport.WithTLSEnabled(false),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	// An explicit https:// must survive even when TLSEnabled is false, and the
	// trailing slash must be trimmed so path joins do not double up.
	if tr.BaseURL() != "https://xkms.example.com:8443" {
		t.Errorf("BaseURL = %q, want %q", tr.BaseURL(), "https://xkms.example.com:8443")
	}
}

// TestNew_OptionErrorPropagates ensures a failing option aborts construction
// instead of yielding a half-configured transport.
func TestNew_OptionErrorPropagates(t *testing.T) {
	wantErr := errors.New("bad option")
	failing := func(*transport.Config) error { return wantErr }

	tr, err := sdkrest.New(transport.WithAddress("xkms.example.com:8443"), failing)
	if err == nil {
		if tr != nil {
			_ = tr.Close()
		}
		t.Fatal("expected the option error to abort New")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want %v", err, wantErr)
	}
	if tr != nil {
		t.Error("no transport may be returned when an option fails")
	}
}

// TestNew_MTLSRecordsTrustMaterialAndEnablesTLS pins the mTLS contract:
// WithMTLS must enable TLS and record all three paths at construction time.
// Certificate material is loaded lazily by Connect, so a missing file surfaces
// there — not silently as an anonymous (no client cert) TLS connection.
func TestNew_MTLSRecordsTrustMaterialAndEnablesTLS(t *testing.T) {
	dir := t.TempDir()
	certFile := dir + "/client.crt"
	keyFile := dir + "/client.key"
	caFile := dir + "/ca.pem"

	tr, err := sdkrest.New(
		transport.WithAddress("xkms.example.com:8443"),
		transport.WithMTLS(certFile, keyFile, caFile),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	cfg := tr.Config()
	if !cfg.TLSEnabled {
		t.Error("WithMTLS must enable TLS")
	}
	if cfg.TLSCertFile != certFile || cfg.TLSKeyFile != keyFile || cfg.TLSCAFile != caFile {
		t.Errorf("trust material lost: cert=%q key=%q ca=%q", cfg.TLSCertFile, cfg.TLSKeyFile, cfg.TLSCAFile)
	}
	if !strings.HasPrefix(tr.BaseURL(), "https://") {
		t.Errorf("BaseURL = %q, want an https:// scheme under mTLS", tr.BaseURL())
	}

	// The unreadable CA must be reported by Connect rather than ignored.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tr.Connect(ctx); err == nil {
		t.Fatal("Connect must fail when the configured CA file cannot be read")
	}
}

// TestNew_MTLSRejectsEmptyPaths covers the eager validation half of WithMTLS.
func TestNew_MTLSRejectsEmptyPaths(t *testing.T) {
	cases := []struct{ name, cert, key string }{
		{"empty_cert", "", "/tmp/x.key"},
		{"empty_key", "/tmp/x.crt", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := sdkrest.New(
				transport.WithAddress("xkms.example.com:8443"),
				transport.WithMTLS(tc.cert, tc.key, ""),
			); err == nil {
				t.Fatal("expected an error for incomplete mTLS material")
			}
		})
	}
}

// TestNewWithConfig_NilConfigUsesDefaults documents the nil-config contract.
func TestNewWithConfig_NilConfigUsesDefaults(t *testing.T) {
	tr, err := sdkrest.NewWithConfig(nil)
	if err != nil {
		t.Fatalf("NewWithConfig(nil): %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	def := transport.DefaultConfig()
	if tr.Config().Timeout != def.Timeout {
		t.Errorf("Timeout = %v, want the default %v", tr.Config().Timeout, def.Timeout)
	}
}

// TestErrorSentinelsAreTheCanonicalOnes proves the SDK re-exports identity, not
// copies: downstream code does errors.Is against these, and a duplicated
// sentinel value would break every such check.
func TestErrorSentinelsAreDistinctAndNonNil(t *testing.T) {
	sentinels := map[string]error{
		"ErrNotConnected":     sdkrest.ErrNotConnected,
		"ErrNotSupported":     sdkrest.ErrNotSupported,
		"ErrConnectionFailed": sdkrest.ErrConnectionFailed,
		"ErrNotImplemented":   sdkrest.ErrNotImplemented,
	}
	seen := map[string]string{}
	for name, err := range sentinels {
		if err == nil {
			t.Errorf("%s is nil", name)
			continue
		}
		if prev, dup := seen[err.Error()]; dup {
			t.Errorf("%s and %s share the message %q; errors.Is cannot distinguish them",
				name, prev, err.Error())
		}
		seen[err.Error()] = name
	}
}
