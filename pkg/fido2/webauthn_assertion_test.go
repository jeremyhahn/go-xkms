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
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
)

// buildAssertionAuthData hand-builds WebAuthn authenticator data for an
// assertion. Unlike registration authData, an assertion carries no attested
// credential data — only the fixed 37-byte header:
//
//	rpIdHash[32] | flags[1] | signCount[4]
func buildAssertionAuthData(signCount uint32) []byte {
	authData := make([]byte, 0, 37)

	// rpIdHash: 32 bytes (arbitrary but fixed).
	rpIDHash := make([]byte, 32)
	for i := range rpIDHash {
		rpIDHash[i] = byte(i)
	}
	authData = append(authData, rpIDHash...)

	// flags: UP (0x01) + UV (0x04) set, AT (0x40) unset (no attested cred data).
	authData = append(authData, 0x01|0x04)

	// signCount: 4 bytes big-endian.
	sc := make([]byte, 4)
	binary.BigEndian.PutUint32(sc, signCount)
	authData = append(authData, sc...)

	return authData
}

// syntheticGetAssertionResponse returns a well-formed GetAssertion response with
// the supplied credential id, user handle, and a non-empty signature.
func syntheticGetAssertionResponse(credID, userHandle []byte) *GetAssertionResponse {
	return &GetAssertionResponse{
		Credential: PublicKeyCredentialDescriptor{
			Type: "public-key",
			ID:   credID,
		},
		AuthData:  buildAssertionAuthData(7),
		Signature: []byte{0x30, 0x44, 0x02, 0x20, 0xAA, 0xBB, 0xCC, 0xDD},
		User:      &User{ID: userHandle},
	}
}

// TestBuildWebAuthnAssertionParsesViaServerParser proves the generated
// PublicKeyCredential assertion JSON is server-acceptable: it parses with no
// error via protocol.ParseCredentialRequestResponseBody (the exact parser
// XKMSService.FinishAuthentication uses) and the parsed RawID, signature,
// userHandle, and clientData round-trip correctly.
func TestBuildWebAuthnAssertionParsesViaServerParser(t *testing.T) {
	credID := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	userHandle := []byte("user-handle-42")
	challenge := make([]byte, 32)
	for i := range challenge {
		challenge[i] = byte(0x40 + i)
	}
	origin := "https://login.example.com"

	resp := syntheticGetAssertionResponse(credID, userHandle)

	assertion, err := buildWebAuthnAssertion(resp, challenge, origin)
	if err != nil {
		t.Fatalf("buildWebAuthnAssertion: %v", err)
	}

	if !bytes.Equal(assertion.CredentialID, credID) {
		t.Fatalf("credential id mismatch: got %x want %x", assertion.CredentialID, credID)
	}

	// The decisive assertion: the server's parser must accept the JSON.
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(assertion.PublicKeyCredentialJSON))
	if err != nil {
		t.Fatalf("ParseCredentialRequestResponseBody rejected assertion: %v", err)
	}

	// RawID must equal our input credential id.
	if !bytes.Equal(parsed.RawID, credID) {
		t.Fatalf("parsed RawID mismatch: got %x want %x", []byte(parsed.RawID), credID)
	}

	// The parsed credential id (base64url) must equal our encoding.
	wantID := base64.RawURLEncoding.EncodeToString(credID)
	if parsed.ID != wantID {
		t.Fatalf("parsed credential ID mismatch: got %q want %q", parsed.ID, wantID)
	}

	// The signature must round-trip.
	if !bytes.Equal(parsed.Response.Signature, resp.Signature) {
		t.Fatalf("parsed signature mismatch: got %x want %x", []byte(parsed.Response.Signature), resp.Signature)
	}

	// The user handle must round-trip.
	if !bytes.Equal(parsed.Response.UserHandle, userHandle) {
		t.Fatalf("parsed userHandle mismatch: got %x want %x", []byte(parsed.Response.UserHandle), userHandle)
	}

	// The collected client data must carry the assertion type and challenge.
	if parsed.Response.CollectedClientData.Type != "webauthn.get" {
		t.Fatalf("parsed clientData type: got %q want %q",
			parsed.Response.CollectedClientData.Type, "webauthn.get")
	}
	if parsed.Response.CollectedClientData.Origin != origin {
		t.Fatalf("parsed clientData origin: got %q want %q",
			parsed.Response.CollectedClientData.Origin, origin)
	}
	wantChallenge := base64.RawURLEncoding.EncodeToString(challenge)
	if parsed.Response.CollectedClientData.Challenge != wantChallenge {
		t.Fatalf("parsed clientData challenge: got %q want %q",
			parsed.Response.CollectedClientData.Challenge, wantChallenge)
	}
}

// TestBuildAssertionClientDataJSONShape verifies the clientDataJSON has the
// correct WebAuthn authentication shape: type "webauthn.get",
// base64url(challenge) with no padding, and the supplied origin.
func TestBuildAssertionClientDataJSONShape(t *testing.T) {
	challenge := []byte("a-non-multiple-of-3-challenge!!")
	origin := "https://rp.example.org"

	raw, err := buildAssertionClientDataJSON(challenge, origin)
	if err != nil {
		t.Fatalf("buildAssertionClientDataJSON: %v", err)
	}

	var cd collectedClientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		t.Fatalf("unmarshal clientDataJSON: %v", err)
	}

	if cd.Type != "webauthn.get" {
		t.Errorf("type: got %q want %q", cd.Type, "webauthn.get")
	}
	if cd.Origin != origin {
		t.Errorf("origin: got %q want %q", cd.Origin, origin)
	}
	wantChallenge := base64.RawURLEncoding.EncodeToString(challenge)
	if cd.Challenge != wantChallenge {
		t.Errorf("challenge: got %q want %q", cd.Challenge, wantChallenge)
	}
}

// TestBuildPublicKeyAssertionJSONErrors verifies error handling for malformed
// GetAssertion responses: nil response, missing authData, missing signature, and
// missing credential id.
func TestBuildPublicKeyAssertionJSONErrors(t *testing.T) {
	clientDataJSON := []byte(`{"type":"webauthn.get"}`)

	if _, _, err := buildPublicKeyAssertionJSON(nil, clientDataJSON); err == nil {
		t.Error("expected error for nil GetAssertionResponse")
	}

	// Missing authData.
	noAuthData := &GetAssertionResponse{
		Credential: PublicKeyCredentialDescriptor{ID: []byte{0x01}},
		Signature:  []byte{0x02},
	}
	if _, _, err := buildPublicKeyAssertionJSON(noAuthData, clientDataJSON); err == nil {
		t.Error("expected error for missing authData")
	}

	// Missing signature.
	noSig := &GetAssertionResponse{
		Credential: PublicKeyCredentialDescriptor{ID: []byte{0x01}},
		AuthData:   buildAssertionAuthData(1),
	}
	if _, _, err := buildPublicKeyAssertionJSON(noSig, clientDataJSON); err == nil {
		t.Error("expected error for missing signature")
	}

	// Missing credential id.
	noCredID := &GetAssertionResponse{
		AuthData:  buildAssertionAuthData(1),
		Signature: []byte{0x02},
	}
	if _, _, err := buildPublicKeyAssertionJSON(noCredID, clientDataJSON); err == nil {
		t.Error("expected error for missing credential id")
	}
}

// TestAssertionAllowList verifies raw credential IDs convert into
// public-key descriptors, and that an empty input yields a nil allow list.
func TestAssertionAllowList(t *testing.T) {
	if got := assertionAllowList(nil); got != nil {
		t.Errorf("expected nil allow list for nil input, got %v", got)
	}

	ids := [][]byte{{0x01, 0x02}, {0x03, 0x04}}
	got := assertionAllowList(ids)
	if len(got) != 2 {
		t.Fatalf("expected 2 descriptors, got %d", len(got))
	}
	for i, d := range got {
		if d.Type != "public-key" {
			t.Errorf("descriptor %d type: got %q want public-key", i, d.Type)
		}
		if !bytes.Equal(d.ID, ids[i]) {
			t.Errorf("descriptor %d id: got %x want %x", i, d.ID, ids[i])
		}
	}
}

// TestAuthenticateWebAuthnValidation verifies AuthenticateWebAuthn rejects
// missing challenge and origin before touching any device.
func TestAuthenticateWebAuthnValidation(t *testing.T) {
	h := &FIDO2Handler{}

	if _, err := h.AuthenticateWebAuthn(WebAuthnAuthenticationOptions{Origin: "https://x"}); err == nil {
		t.Error("expected error for missing challenge")
	}
	if _, err := h.AuthenticateWebAuthn(WebAuthnAuthenticationOptions{Challenge: []byte{0x01}}); err == nil {
		t.Error("expected error for missing origin")
	}
}
