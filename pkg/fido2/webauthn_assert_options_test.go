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
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
)

// buildRequestOptionsJSON marshals a server-issued WebAuthn assertion options
// document in the wrapped (browser) shape: a protocol.CredentialAssertion whose
// publicKey member carries the challenge, rpId, allowCredentials, and
// userVerification — exactly the BeginLogin output a relying party serves.
func buildRequestOptionsJSON(t *testing.T, challenge []byte, rpID string, allow [][]byte, uv protocol.UserVerificationRequirement) []byte {
	t.Helper()

	descriptors := make([]protocol.CredentialDescriptor, 0, len(allow))
	for _, id := range allow {
		descriptors = append(descriptors, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: id,
		})
	}

	ca := protocol.CredentialAssertion{
		Response: protocol.PublicKeyCredentialRequestOptions{
			Challenge:          challenge,
			RelyingPartyID:     rpID,
			AllowedCredentials: descriptors,
			UserVerification:   uv,
			Timeout:            30000,
		},
	}

	raw, err := json.Marshal(ca)
	if err != nil {
		t.Fatalf("marshal CredentialAssertion: %v", err)
	}
	return raw
}

// newMockAssertHandler builds a FIDO2 handler backed by the in-package mock CTAP2
// HID device, the same harness the CTAP2 unit tests drive. The mock answers
// authenticatorGetAssertion with a well-formed assertion (credential id, authData,
// signature), so the full options -> CTAP2 -> WebAuthn-assertion path is exercised.
func newMockAssertHandler(t *testing.T) *FIDO2Handler {
	t.Helper()

	config := DefaultConfig
	mockDev := NewMockHIDDevice("/dev/hidraw0")

	enum := NewMockHIDDeviceEnumerator()
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return handler
}

// TestAssertWithOptions_DrivesAuthenticatorAndProducesAssertion is the load-bearing
// proof: given a realistic server-issued options JSON, AssertWithOptionsAndOrigin parses it,
// drives the (mock) CTAP2 authenticator, and produces a well-formed WebAuthn
// PublicKeyCredential assertion JSON. The decisive check is that the server's own
// parser (protocol.ParseCredentialRequestResponseBody, the parser
// FinishAuthentication uses) accepts the output, and that the embedded
// clientDataJSON binds the supplied challenge + the caller's origin + type
// "webauthn.get".
func TestAssertWithOptions_DrivesAuthenticatorAndProducesAssertion(t *testing.T) {
	handler := newMockAssertHandler(t)
	defer func() { _ = handler.Close() }()

	// A realistic 32-byte server challenge whose length is not a multiple of 3,
	// to exercise the no-padding base64url binding in clientDataJSON.
	challenge := make([]byte, 32)
	for i := range challenge {
		challenge[i] = byte(0x10 + i)
	}
	rpID := "login.example.com"
	// The mock authenticator answers with a credential id of 32 zero bytes; the
	// allow-list credential id is independent of which credential the device picks.
	allow := [][]byte{{0xAB, 0xCD, 0xEF, 0x01}}

	optionsJSON := buildRequestOptionsJSON(t, challenge, rpID, allow, protocol.VerificationPreferred)

	assertionJSON, err := handler.AssertWithOptionsAndOrigin(context.Background(), optionsJSON, "https://"+rpID)
	if err != nil {
		t.Fatalf("AssertWithOptionsAndOrigin: %v", err)
	}
	if len(assertionJSON) == 0 {
		t.Fatal("AssertWithOptionsAndOrigin returned empty assertion JSON")
	}

	// The server's parser must accept the assertion document.
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(assertionJSON))
	if err != nil {
		t.Fatalf("ParseCredentialRequestResponseBody rejected assertion: %v", err)
	}

	// The navigator.credentials.get() response shape must be present.
	if parsed.Type != "public-key" {
		t.Errorf("credential type: got %q want public-key", parsed.Type)
	}
	if len(parsed.RawID) == 0 {
		t.Error("assertion missing rawId")
	}
	if len(parsed.Raw.AssertionResponse.AuthenticatorData) == 0 {
		t.Error("assertion missing authenticatorData")
	}
	if len(parsed.Response.Signature) == 0 {
		t.Error("assertion missing signature")
	}

	// The clientDataJSON must bind the assertion type, the caller's origin,
	// and the exact server challenge (base64url, no padding).
	cd := parsed.Response.CollectedClientData
	if cd.Type != "webauthn.get" {
		t.Errorf("clientData type: got %q want webauthn.get", cd.Type)
	}
	if cd.Origin != "https://"+rpID {
		t.Errorf("clientData origin: got %q want %q", cd.Origin, "https://"+rpID)
	}
	wantChallenge := base64.RawURLEncoding.EncodeToString(challenge)
	if cd.Challenge != wantChallenge {
		t.Errorf("clientData challenge: got %q want %q", cd.Challenge, wantChallenge)
	}
}

// TestAssertWithOptionsAndOrigin_ExplicitOrigin proves an origin whose host
// differs from the rpId (a registrable-suffix RP ID) is accepted and bound into
// the clientDataJSON.
func TestAssertWithOptionsAndOrigin_ExplicitOrigin(t *testing.T) {
	handler := newMockAssertHandler(t)
	defer func() { _ = handler.Close() }()

	challenge := []byte("server-supplied-challenge-value!")
	rpID := "example.com"
	origin := "https://app.example.com"

	optionsJSON := buildRequestOptionsJSON(t, challenge, rpID, [][]byte{{0x01}}, protocol.VerificationRequired)

	assertionJSON, err := handler.AssertWithOptionsAndOrigin(context.Background(), optionsJSON, origin)
	if err != nil {
		t.Fatalf("AssertWithOptionsAndOrigin: %v", err)
	}

	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(assertionJSON))
	if err != nil {
		t.Fatalf("ParseCredentialRequestResponseBody rejected assertion: %v", err)
	}
	if parsed.Response.CollectedClientData.Origin != origin {
		t.Errorf("clientData origin: got %q want %q", parsed.Response.CollectedClientData.Origin, origin)
	}
}

// TestAssertWithOptions_AcceptsBareRequestOptions proves the bare
// PublicKeyCredentialRequestOptions shape (no {"publicKey": ...} wrapper) is also
// accepted, since servers serve either shape.
func TestAssertWithOptions_AcceptsBareRequestOptions(t *testing.T) {
	handler := newMockAssertHandler(t)
	defer func() { _ = handler.Close() }()

	challenge := make([]byte, 32)
	for i := range challenge {
		challenge[i] = byte(i)
	}
	rpID := "bare.example.org"

	bare := protocol.PublicKeyCredentialRequestOptions{
		Challenge:        challenge,
		RelyingPartyID:   rpID,
		UserVerification: protocol.VerificationDiscouraged,
		Timeout:          15000,
	}
	optionsJSON, err := json.Marshal(bare)
	if err != nil {
		t.Fatalf("marshal bare options: %v", err)
	}

	assertionJSON, err := handler.AssertWithOptionsAndOrigin(context.Background(), optionsJSON, "https://"+rpID)
	if err != nil {
		t.Fatalf("AssertWithOptionsAndOrigin (bare): %v", err)
	}

	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(assertionJSON))
	if err != nil {
		t.Fatalf("ParseCredentialRequestResponseBody rejected assertion: %v", err)
	}
	wantChallenge := base64.RawURLEncoding.EncodeToString(challenge)
	if parsed.Response.CollectedClientData.Challenge != wantChallenge {
		t.Errorf("clientData challenge: got %q want %q",
			parsed.Response.CollectedClientData.Challenge, wantChallenge)
	}
	if parsed.Response.CollectedClientData.Origin != "https://"+rpID {
		t.Errorf("clientData origin: got %q want %q",
			parsed.Response.CollectedClientData.Origin, "https://"+rpID)
	}
}

// TestParseRequestOptions_Errors proves the options parser rejects malformed and
// incomplete server options with the documented typed errors, before any device
// is touched.
func TestParseRequestOptions_Errors(t *testing.T) {
	// Empty options.
	if _, err := parseRequestOptions(nil, ""); !errors.Is(err, ErrAssertionOptionsRequired) {
		t.Errorf("empty options: got %v want ErrAssertionOptionsRequired", err)
	}

	// Malformed JSON.
	if _, err := parseRequestOptions([]byte("{not json"), ""); err == nil {
		t.Error("expected error for malformed options JSON")
	}

	// Missing challenge.
	noChallenge, err := json.Marshal(protocol.CredentialAssertion{
		Response: protocol.PublicKeyCredentialRequestOptions{RelyingPartyID: "rp"},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := parseRequestOptions(noChallenge, ""); !errors.Is(err, ErrAssertionChallengeMissing) {
		t.Errorf("missing challenge: got %v want ErrAssertionChallengeMissing", err)
	}

	// Missing rpId.
	noRPID, err := json.Marshal(protocol.CredentialAssertion{
		Response: protocol.PublicKeyCredentialRequestOptions{Challenge: []byte{0x01, 0x02}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := parseRequestOptions(noRPID, ""); !errors.Is(err, ErrAssertionRPIDMissing) {
		t.Errorf("missing rpId: got %v want ErrAssertionRPIDMissing", err)
	}
}

// TestParseRequestOptions_MapsFields proves the parser maps every server field
// into the device-driver options: challenge, rpId, the caller's origin, the
// allow-list, the user-verification requirement, and the timeout.
func TestParseRequestOptions_MapsFields(t *testing.T) {
	challenge := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	rpID := "rp.example.net"
	allow := [][]byte{{0x01, 0x02}, {0x03, 0x04}}

	optionsJSON := buildRequestOptionsJSON(t, challenge, rpID, allow, protocol.VerificationRequired)

	opts, err := parseRequestOptions(optionsJSON, "https://"+rpID)
	if err != nil {
		t.Fatalf("parseRequestOptions: %v", err)
	}

	if !bytes.Equal(opts.Challenge, challenge) {
		t.Errorf("challenge: got %x want %x", opts.Challenge, challenge)
	}
	if opts.RPID != rpID {
		t.Errorf("rpID: got %q want %q", opts.RPID, rpID)
	}
	if opts.Origin != "https://"+rpID {
		t.Errorf("origin: got %q want %q", opts.Origin, "https://"+rpID)
	}
	if !opts.RequireUserVerification {
		t.Error("expected RequireUserVerification true for VerificationRequired")
	}
	if len(opts.AllowCredentialIDs) != 2 {
		t.Fatalf("allow list: got %d want 2", len(opts.AllowCredentialIDs))
	}
	for i, id := range allow {
		if !bytes.Equal(opts.AllowCredentialIDs[i], id) {
			t.Errorf("allow[%d]: got %x want %x", i, opts.AllowCredentialIDs[i], id)
		}
	}
	if opts.Timeout == 0 {
		t.Error("expected non-zero timeout mapped from options")
	}
}

// TestAssertWithOptions_ContextCancelled proves a cancelled context is honored
// before any device work begins.
func TestAssertWithOptions_ContextCancelled(t *testing.T) {
	handler := newMockAssertHandler(t)
	defer func() { _ = handler.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	optionsJSON := buildRequestOptionsJSON(t, []byte{0x01, 0x02, 0x03}, "rp", [][]byte{{0x01}}, protocol.VerificationPreferred)

	if _, err := handler.AssertWithOptionsAndOrigin(ctx, optionsJSON, "https://rp"); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled context: got %v want context.Canceled", err)
	}
}
