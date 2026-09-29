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
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

// buildCreationOptionsJSON builds a browser-shaped ({"publicKey": {...}})
// PublicKeyCredentialCreationOptions document, textually, so the encoding of
// every base64url field is exactly what a relying party serves — including
// User.ID, which go-webauthn types `any` and which a real server emits as a
// base64url string, not the []byte-as-standard-base64 form encoding/json
// would produce from a Go struct literal.
func buildCreationOptionsJSON(challenge, userID []byte, rpID, rpName, userName, userDisplayName string, uv string) []byte {
	return []byte(`{"publicKey":{` +
		`"challenge":"` + base64.RawURLEncoding.EncodeToString(challenge) + `",` +
		`"rp":{"id":"` + rpID + `","name":"` + rpName + `"},` +
		`"user":{"id":"` + base64.RawURLEncoding.EncodeToString(userID) + `","name":"` + userName + `","displayName":"` + userDisplayName + `"},` +
		`"authenticatorSelection":{"userVerification":"` + uv + `"},` +
		`"timeout":90000` +
		`}}`)
}

// TestParseWebAuthnRegistrationOptions_MapsFields proves every server field
// is mapped into the device-driver options: challenge, rp id/name, user
// id/name/displayName, the caller's origin, user-verification, and timeout.
func TestParseWebAuthnRegistrationOptions_MapsFields(t *testing.T) {
	challenge := []byte("registration-challenge-value")
	userID := []byte("user-handle-1")

	optionsJSON := buildCreationOptionsJSON(challenge, userID, "xkms.example.com", "xKMS", "alice", "Alice Example", "required")

	opts, err := ParseWebAuthnRegistrationOptions(optionsJSON, "https://xkms.example.com")
	if err != nil {
		t.Fatalf("ParseWebAuthnRegistrationOptions: %v", err)
	}

	if !bytes.Equal(opts.Challenge, challenge) {
		t.Errorf("Challenge: got %q want %q", opts.Challenge, challenge)
	}
	if opts.RPID != "xkms.example.com" {
		t.Errorf("RPID: got %q want %q", opts.RPID, "xkms.example.com")
	}
	if opts.RPName != "xKMS" {
		t.Errorf("RPName: got %q want %q", opts.RPName, "xKMS")
	}
	if !bytes.Equal(opts.UserID, userID) {
		t.Errorf("UserID: got %q want %q", opts.UserID, userID)
	}
	if opts.UserName != "alice" {
		t.Errorf("UserName: got %q want %q", opts.UserName, "alice")
	}
	if opts.UserDisplayName != "Alice Example" {
		t.Errorf("UserDisplayName: got %q want %q", opts.UserDisplayName, "Alice Example")
	}
	if !opts.RequireUserVerification {
		t.Error("RequireUserVerification: got false, want true for userVerification=required")
	}
	if opts.Timeout != 90*time.Second {
		t.Errorf("Timeout: got %v want %v", opts.Timeout, 90*time.Second)
	}
	// Origin defaults to the WebAuthn same-origin form when the caller
	// supplies none.
	if opts.Origin != "https://xkms.example.com" {
		t.Errorf("Origin: got %q want %q", opts.Origin, "https://xkms.example.com")
	}
}

// TestParseWebAuthnRegistrationOptions_ExplicitOrigin proves an explicit
// origin (e.g. a registrable-suffix RP ID whose origin host differs) is
// bound instead of the derived same-origin default.
func TestParseWebAuthnRegistrationOptions_ExplicitOrigin(t *testing.T) {
	optionsJSON := buildCreationOptionsJSON([]byte("challenge-bytes"), []byte("user-1"), "example.com", "Example", "bob", "Bob", "preferred")

	opts, err := ParseWebAuthnRegistrationOptions(optionsJSON, "https://app.example.com")
	if err != nil {
		t.Fatalf("ParseWebAuthnRegistrationOptions: %v", err)
	}
	if opts.Origin != "https://app.example.com" {
		t.Errorf("Origin: got %q want %q", opts.Origin, "https://app.example.com")
	}
	if opts.RequireUserVerification {
		t.Error("RequireUserVerification: got true, want false for userVerification=preferred")
	}
}

// TestParseWebAuthnRegistrationOptions_AcceptsBareDocument proves the
// unwrapped PublicKeyCredentialCreationOptions shape (no {"publicKey": ...}
// wrapper) is also accepted, since servers serve either shape.
func TestParseWebAuthnRegistrationOptions_AcceptsBareDocument(t *testing.T) {
	challenge := []byte("bare-challenge")
	bare := []byte(`{"challenge":"` + base64.RawURLEncoding.EncodeToString(challenge) + `",` +
		`"rp":{"id":"bare.example.org"},` +
		`"user":{"name":"carol"}}`)

	opts, err := ParseWebAuthnRegistrationOptions(bare, "https://bare.example.org")
	if err != nil {
		t.Fatalf("ParseWebAuthnRegistrationOptions (bare): %v", err)
	}
	if !bytes.Equal(opts.Challenge, challenge) {
		t.Errorf("Challenge: got %q want %q", opts.Challenge, challenge)
	}
	if opts.RPID != "bare.example.org" {
		t.Errorf("RPID: got %q want %q", opts.RPID, "bare.example.org")
	}
	if opts.UserName != "carol" {
		t.Errorf("UserName: got %q want %q", opts.UserName, "carol")
	}
}

// TestParseWebAuthnRegistrationOptions_PaddedChallenge proves a padded
// base64url challenge (relying parties have been observed emitting it) is
// tolerated: go-webauthn's URLEncodedBase64 trims trailing "=".
func TestParseWebAuthnRegistrationOptions_PaddedChallenge(t *testing.T) {
	optionsJSON := []byte(`{"publicKey":{"challenge":"Y2hhbGxlbmdlLTE=","rp":{"id":"rp.example"}}}`)

	opts, err := ParseWebAuthnRegistrationOptions(optionsJSON, "https://rp.example")
	if err != nil {
		t.Fatalf("ParseWebAuthnRegistrationOptions: %v", err)
	}
	if !bytes.Equal(opts.Challenge, []byte("challenge-1")) {
		t.Errorf("Challenge: got %q want %q", opts.Challenge, "challenge-1")
	}
}

// TestParseWebAuthnRegistrationOptions_Errors proves every malformed or
// incomplete options document is rejected with the documented typed error,
// before any device is touched.
func TestParseWebAuthnRegistrationOptions_Errors(t *testing.T) {
	tests := []struct {
		name        string
		optionsJSON []byte
		wantErr     error
	}{
		{
			name:        "empty options",
			optionsJSON: nil,
			wantErr:     ErrRegistrationOptionsRequired,
		},
		{
			name:        "malformed JSON",
			optionsJSON: []byte("{not json"),
			wantErr:     nil, // any error; no sentinel for a JSON syntax failure
		},
		{
			name:        "missing challenge",
			optionsJSON: []byte(`{"publicKey":{"rp":{"id":"rp.example"}}}`),
			wantErr:     ErrRegistrationChallengeMissing,
		},
		{
			name:        "missing rp.id",
			optionsJSON: []byte(`{"publicKey":{"challenge":"Y2hhbGxlbmdl","rp":{"name":"rp"}}}`),
			wantErr:     ErrRegistrationRPIDMissing,
		},
		{
			name:        "bad challenge encoding",
			optionsJSON: []byte(`{"publicKey":{"challenge":"!!!!","rp":{"id":"rp.example"}}}`),
			wantErr:     nil,
		},
		{
			name:        "bad user id encoding",
			optionsJSON: []byte(`{"publicKey":{"challenge":"Y2hhbGxlbmdl","rp":{"id":"rp.example"},"user":{"id":"!!!!"}}}`),
			wantErr:     nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseWebAuthnRegistrationOptions(tc.optionsJSON, "")
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("error = %v, want to wrap %v", err, tc.wantErr)
			}
		})
	}
}

// TestParseWebAuthnRegistrationOptions_NoUserID proves a creation options
// document with no user id at all (User.ID nil) parses to a nil UserID
// rather than failing — a caller may omit it deliberately.
func TestParseWebAuthnRegistrationOptions_NoUserID(t *testing.T) {
	optionsJSON := []byte(`{"publicKey":{"challenge":"Y2hhbGxlbmdl","rp":{"id":"rp.example"},"user":{"name":"dave"}}}`)

	opts, err := ParseWebAuthnRegistrationOptions(optionsJSON, "https://rp.example")
	if err != nil {
		t.Fatalf("ParseWebAuthnRegistrationOptions: %v", err)
	}
	if opts.UserID != nil {
		t.Errorf("UserID: got %x, want nil", opts.UserID)
	}
}
