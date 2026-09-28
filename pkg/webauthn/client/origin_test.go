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

package client

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/fido2"
)

func TestOriginFromURL(t *testing.T) {
	tests := []struct {
		name      string
		serverURL string
		want      string
	}{
		{"https with port", "https://xkms.example.com:8443", "https://xkms.example.com:8443"},
		{"https without port", "https://xkms.example.com", "https://xkms.example.com"},
		{"trailing path is dropped", "https://xkms.example.com:8443/api/v1", "https://xkms.example.com:8443"},
		{"surrounding whitespace", "  https://xkms.example.com  ", "https://xkms.example.com"},
		{"http", "http://localhost:8080", "http://localhost:8080"},
		{"no scheme", "xkms.example.com:8443", ""},
		{"empty", "", ""},
		{"unparsable", "://nope", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := OriginFromURL(tc.serverURL); got != tc.want {
				t.Errorf("OriginFromURL(%q) = %q, want %q", tc.serverURL, got, tc.want)
			}
		})
	}
}

// TestNewClient_RefusesUnderivableOrigin proves a client with a directly
// supplied RelyingParty and neither Origin nor ServerURL is refused at
// construction, rather than falling back to an origin built from whatever
// rpId the server later supplies.
func TestNewClient_RefusesUnderivableOrigin(t *testing.T) {
	_, err := NewClient(&Config{
		RelyingParty:         &HTTPRelyingParty{},
		AuthenticatorAdapter: &mockAdapter{available: true},
	})
	if !errors.Is(err, fido2.ErrOriginRequired) {
		t.Fatalf("NewClient error = %v, want fido2.ErrOriginRequired", err)
	}
}

// TestSoftwareAdapter_RPIDOriginBinding proves both SoftwareAdapter
// ceremonies refuse a server-supplied rpId the caller's origin does not
// cover, refuse an empty origin outright, and accept an rpId that is a
// registrable suffix of the origin's host.
func TestSoftwareAdapter_RPIDOriginBinding(t *testing.T) {
	challenge := "dGVzdC1jaGFsbGVuZ2UtMzItYnl0ZXMtbG9uZyEh"
	tests := []struct {
		name    string
		rpID    string
		origin  string
		wantErr error
	}{
		{"mismatched rpId", "attacker.example", "https://example.com", fido2.ErrRPIDOriginMismatch},
		{"public suffix rpId", "com", "https://example.com", fido2.ErrRPIDOriginMismatch},
		{"sibling subdomain rpId", "evil.example.com", "https://example.com", fido2.ErrRPIDOriginMismatch},
		{"empty origin", "example.com", "", fido2.ErrOriginRequired},
		{"registrable suffix rpId", "example.com", "https://login.example.com", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			adapter := NewSoftwareAdapter()
			_, err := adapter.MakeCredential(context.Background(), &CeremonyOptions{
				OptionsJSON: buildCreationOptionsWithAuthenticatorSelection(tc.rpID, challenge,
					map[string]interface{}{"residentKey": "required"}),
				Origin: tc.origin,
			})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("MakeCredential error = %v, want %v", err, tc.wantErr)
			}

			_, err = adapter.GetAssertion(context.Background(), &CeremonyOptions{
				OptionsJSON: buildTestAssertionOptionsNoAllowList(tc.rpID, challenge),
				Origin:      tc.origin,
			})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("GetAssertion error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
