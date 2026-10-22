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

//go:build gui

package main

import (
	"errors"
	"strings"
	"testing"

	acmegui "github.com/jeremyhahn/go-xkms/sdk/go/acme/gui"
)

// acmeGUIIdentity is a complete mTLS identity for the resolution tests; the
// files are never opened before the window starts.
func acmeGUIIdentity() *Config {
	return &Config{TLSCert: "admin.crt", TLSKey: "admin.key", TLSCACert: "ca.crt"}
}

func TestACMEGUIConfig_Resolution(t *testing.T) {
	cases := []struct {
		name          string
		server        string
		transport     string
		wantTransport string
		wantAddress   string
	}{
		{"https scheme", "https://ca.example.com:8443", "", "rest", "https://ca.example.com:8443"},
		{"grpcs scheme", "grpcs://ca.example.com:9443", "", "grpc", "ca.example.com:9443"},
		{"quic scheme", "quic://ca.example.com:9444", "", "quic", "ca.example.com:9444"},
		{"mcps scheme", "mcps://ca.example.com:9444", "", "mcp", "ca.example.com:9444"},
		{"bare address, transport flag", "ca.example.com:8443", "rest", "rest", "ca.example.com:8443"},
		{"bare address, sdk default", "ca.example.com:9443", "", "grpc", "ca.example.com:9443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetACMEConnectionFlags(t)
			acmeServerFlag = tc.server
			acmeTransportFlag = tc.transport

			got, err := acmeGUIConfig(acmeGUIIdentity())
			if err != nil {
				t.Fatalf("acmeGUIConfig: %v", err)
			}
			if got.Transport != tc.wantTransport {
				t.Errorf("Transport = %q, want %q", got.Transport, tc.wantTransport)
			}
			if got.Address != tc.wantAddress {
				t.Errorf("Address = %q, want %q", got.Address, tc.wantAddress)
			}
			if got.TLSCert != "admin.crt" || got.TLSKey != "admin.key" || got.TLSCA != "ca.crt" {
				t.Errorf("identity = %q/%q/%q, want admin.crt/admin.key/ca.crt",
					got.TLSCert, got.TLSKey, got.TLSCA)
			}

			defaults := acmegui.DefaultAdminGUIConfig()
			if got.Title != defaults.Title || got.Width != defaults.Width || got.Height != defaults.Height {
				t.Errorf("window = %q %dx%d, want the admin GUI defaults", got.Title, got.Width, got.Height)
			}
		})
	}
}

func TestACMEGUIConfig_AddressRequired(t *testing.T) {
	resetACMEConnectionFlags(t)

	_, err := acmeGUIConfig(acmeGUIIdentity())
	var required *ACMEAdminAddressRequiredError
	if !errors.As(err, &required) {
		t.Fatalf("expected ACMEAdminAddressRequiredError, got %v", err)
	}
}

func TestACMEGUIConfig_UnsupportedTransport(t *testing.T) {
	resetACMEConnectionFlags(t)
	acmeServerFlag = "unix:///run/xkms.sock"

	_, err := acmeGUIConfig(acmeGUIIdentity())
	var unsupported *ACMEAdminUnsupportedTransportError
	if !errors.As(err, &unsupported) {
		t.Fatalf("expected ACMEAdminUnsupportedTransportError, got %v", err)
	}
}

func TestACMEGUIConfig_IdentityRequired(t *testing.T) {
	cases := map[string]*Config{
		"no identity":      {},
		"certificate only": {TLSCert: "admin.crt"},
		"key only":         {TLSKey: "admin.key"},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			resetACMEConnectionFlags(t)
			acmeServerFlag = "grpcs://ca.example.com:9443"

			_, err := acmeGUIConfig(cfg)
			var required *ACMEGUIIdentityRequiredError
			if !errors.As(err, &required) {
				t.Fatalf("expected ACMEGUIIdentityRequiredError, got %v", err)
			}
		})
	}
}

// TestACMEGUI_RefusesBeforeConnecting proves acmeGUI returns the typed
// refusal before it builds a client or opens a window.
func TestACMEGUI_RefusesBeforeConnecting(t *testing.T) {
	resetACMEConnectionFlags(t)
	if err := acmeGUI(acmeGUIIdentity()); !errors.As(err, new(*ACMEAdminAddressRequiredError)) {
		t.Fatalf("missing server: expected ACMEAdminAddressRequiredError, got %v", err)
	}

	acmeServerFlag = "grpcs://ca.example.com:9443"
	if err := acmeGUI(&Config{}); !errors.As(err, new(*ACMEGUIIdentityRequiredError)) {
		t.Fatalf("missing identity: expected ACMEGUIIdentityRequiredError, got %v", err)
	}
}

func TestACMEGUICmd_Registered(t *testing.T) {
	cmd, _, err := acmeCmd.Find([]string{"gui"})
	if err != nil || cmd != acmeGUICmd {
		t.Fatalf("acme gui is not registered: cmd=%v err=%v", cmd, err)
	}
}

func TestACMEGUITypedErrors(t *testing.T) {
	if msg := (&ACMEGUIIdentityRequiredError{}).Error(); !strings.Contains(msg, "--tls-cert") {
		t.Errorf("identity error does not name --tls-cert: %q", msg)
	}

	cause := errors.New("open dist: file does not exist")
	assetsErr := &ACMEGUIAssetsError{Cause: cause}
	if !errors.Is(assetsErr, cause) {
		t.Error("ACMEGUIAssetsError does not unwrap to its cause")
	}
	if !strings.Contains(assetsErr.Error(), cause.Error()) {
		t.Errorf("assets error drops its cause: %q", assetsErr.Error())
	}
}
