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

package fido2

import (
	"errors"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
)

func TestValidateRPID(t *testing.T) {
	tests := []struct {
		name    string
		rpID    string
		origin  string
		wantErr error
	}{
		{"rpId equals host", "example.com", "https://example.com", nil},
		{"rpId equals host with port", "example.com", "https://example.com:8443", nil},
		{"rpId is registrable suffix", "example.com", "https://login.example.com", nil},
		{"rpId is deep registrable suffix", "example.co.uk", "https://a.b.example.co.uk", nil},
		{"case-insensitive", "Example.COM", "https://LOGIN.example.com", nil},
		{"localhost", "localhost", "http://localhost:8080", nil},
		{"IP literal equal", "127.0.0.1", "https://127.0.0.1:8443", nil},
		{"empty origin", "example.com", "", ErrOriginRequired},
		{"origin without scheme", "example.com", "example.com", ErrInvalidOrigin},
		{"unparsable origin", "example.com", "://nope", ErrInvalidOrigin},
		{"mismatched rpId", "attacker.example", "https://example.com", ErrRPIDOriginMismatch},
		{"sibling subdomain rpId", "evil.example.com", "https://example.com", ErrRPIDOriginMismatch},
		{"label-boundary lookalike", "ample.com", "https://example.com", ErrRPIDOriginMismatch},
		{"public suffix rpId", "com", "https://example.com", ErrRPIDOriginMismatch},
		{"multi-label public suffix rpId", "co.uk", "https://example.co.uk", ErrRPIDOriginMismatch},
		{"private public suffix rpId", "github.io", "https://alice.github.io", ErrRPIDOriginMismatch},
		{"IP literal suffix", "0.0.1", "https://127.0.0.1", ErrRPIDOriginMismatch},
		{"empty rpId", "", "https://example.com", ErrRPIDOriginMismatch},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRPID(tc.rpID, tc.origin)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ValidateRPID(%q, %q) = %v, want %v", tc.rpID, tc.origin, err, tc.wantErr)
			}
		})
	}
}

// TestParseOptions_RPIDOriginBinding proves both server-options parsers
// refuse an rpId the origin does not cover and an empty origin, before any
// device is touched, and never synthesise an origin from the rpId.
func TestParseOptions_RPIDOriginBinding(t *testing.T) {
	challenge := []byte("server-issued-challenge-value-32")
	tests := []struct {
		name    string
		rpID    string
		origin  string
		wantErr error
	}{
		{"mismatched rpId", "attacker.example", "https://example.com", ErrRPIDOriginMismatch},
		{"public suffix rpId", "com", "https://example.com", ErrRPIDOriginMismatch},
		{"sibling subdomain rpId", "evil.example.com", "https://example.com", ErrRPIDOriginMismatch},
		{"empty origin", "example.com", "", ErrOriginRequired},
		{"registrable suffix rpId", "example.com", "https://login.example.com", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reqOpts, err := parseRequestOptions(
				buildRequestOptionsJSON(t, challenge, tc.rpID, nil, protocol.VerificationPreferred), tc.origin)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("parseRequestOptions error = %v, want %v", err, tc.wantErr)
			}
			if err == nil && reqOpts.Origin != tc.origin {
				t.Errorf("request origin = %q, want %q", reqOpts.Origin, tc.origin)
			}

			regOpts, err := ParseWebAuthnRegistrationOptions(
				buildCreationOptionsJSON(challenge, []byte("user-handle"), tc.rpID, "RP", "alice", "Alice", "preferred"), tc.origin)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ParseWebAuthnRegistrationOptions error = %v, want %v", err, tc.wantErr)
			}
			if err == nil && regOpts.Origin != tc.origin {
				t.Errorf("registration origin = %q, want %q", regOpts.Origin, tc.origin)
			}
		})
	}
}

// TestCeremonyEntryPoints_RPIDOriginBinding proves the direct ceremony entry
// points enforce the same binding for callers that build the options
// themselves, before any device is touched.
func TestCeremonyEntryPoints_RPIDOriginBinding(t *testing.T) {
	handler := newMockAssertHandler(t)
	t.Cleanup(func() {
		if err := handler.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	_, err := handler.AuthenticateWebAuthn(WebAuthnAuthenticationOptions{
		Challenge: []byte{0x01}, RPID: "evil.example.com", Origin: "https://example.com",
	})
	if !errors.Is(err, ErrRPIDOriginMismatch) {
		t.Errorf("AuthenticateWebAuthn error = %v, want ErrRPIDOriginMismatch", err)
	}

	_, err = handler.RegisterWebAuthn(WebAuthnRegistrationOptions{
		Challenge: []byte{0x01}, RPID: "example.com",
	})
	if !errors.Is(err, ErrOriginRequired) {
		t.Errorf("RegisterWebAuthn error = %v, want ErrOriginRequired", err)
	}
}
