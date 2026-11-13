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
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestSoftwareAdapter_MakeCredential_Success(t *testing.T) {
	adapter := NewSoftwareAdapter()

	challenge := base64.RawURLEncoding.EncodeToString([]byte("test-challenge-1234567890123456"))
	options := buildTestCreationOptions("localhost", challenge)

	result, err := adapter.MakeCredential(context.Background(), ceremonyFor(options))
	if err != nil {
		t.Fatalf("MakeCredential() error: %v", err)
	}

	if result == nil {
		t.Fatal("MakeCredential() returned nil result")
	}

	// Verify the response is valid JSON
	var response map[string]interface{}
	if err := json.Unmarshal(result, &response); err != nil {
		t.Fatalf("MakeCredential() returned invalid JSON: %v", err)
	}

	// Verify required fields
	if _, ok := response["id"]; !ok {
		t.Error("response missing 'id' field")
	}
	if _, ok := response["rawId"]; !ok {
		t.Error("response missing 'rawId' field")
	}
	if response["type"] != "public-key" {
		t.Errorf("type = %v, want 'public-key'", response["type"])
	}

	respObj, ok := response["response"].(map[string]interface{})
	if !ok {
		t.Fatal("response missing 'response' object")
	}
	if _, ok := respObj["clientDataJSON"]; !ok {
		t.Error("response.response missing 'clientDataJSON'")
	}
	if _, ok := respObj["attestationObject"]; !ok {
		t.Error("response.response missing 'attestationObject'")
	}

	// Verify a credential was stored
	if adapter.CredentialCount() != 1 {
		t.Errorf("CredentialCount() = %d, want 1", adapter.CredentialCount())
	}
}

func TestSoftwareAdapter_MakeCredential_InvalidJSON(t *testing.T) {
	adapter := NewSoftwareAdapter()

	_, err := adapter.MakeCredential(context.Background(), ceremonyFor([]byte("not json")))
	if err == nil {
		t.Fatal("MakeCredential() should return error for invalid JSON")
	}
	if !errors.Is(err, ErrCTAPOperationFailed) {
		t.Errorf("error should wrap ErrCTAPOperationFailed, got: %v", err)
	}
}

func TestSoftwareAdapter_MakeCredential_MissingRPID(t *testing.T) {
	adapter := NewSoftwareAdapter()

	challenge := base64.RawURLEncoding.EncodeToString([]byte("test-challenge"))
	options := buildTestCreationOptions("", challenge)

	_, err := adapter.MakeCredential(context.Background(), ceremonyFor(options))
	if err == nil {
		t.Fatal("MakeCredential() should return error for missing RP ID")
	}
	if !errors.Is(err, ErrCTAPOperationFailed) {
		t.Errorf("error should wrap ErrCTAPOperationFailed, got: %v", err)
	}
}

func TestSoftwareAdapter_MakeCredential_InvalidChallenge(t *testing.T) {
	adapter := NewSoftwareAdapter()

	// Use invalid base64 as challenge
	options := buildTestCreationOptions("localhost", "!!!invalid-base64!!!")

	_, err := adapter.MakeCredential(context.Background(), ceremonyFor(options))
	if err == nil {
		t.Fatal("MakeCredential() should return error for invalid challenge")
	}
	if !errors.Is(err, ErrInvalidChallenge) {
		t.Errorf("error should wrap ErrInvalidChallenge, got: %v", err)
	}
}

func TestSoftwareAdapter_GetAssertion_Success(t *testing.T) {
	adapter := NewSoftwareAdapter()

	// First, create a credential
	challenge1 := base64.RawURLEncoding.EncodeToString([]byte("registration-challenge-12345678"))
	creationOpts := buildTestCreationOptions("localhost", challenge1)

	attestation, err := adapter.MakeCredential(context.Background(), ceremonyFor(creationOpts))
	if err != nil {
		t.Fatalf("MakeCredential() error: %v", err)
	}

	// Parse the attestation to get the credential ID
	var attestResp map[string]interface{}
	if err := json.Unmarshal(attestation, &attestResp); err != nil {
		t.Fatalf("failed to parse attestation response: %v", err)
	}
	credID := attestResp["id"].(string)

	// Now get an assertion
	challenge2 := base64.RawURLEncoding.EncodeToString([]byte("assertion-challenge-123456789"))
	assertionOpts := buildTestAssertionOptions("localhost", challenge2, credID)

	result, err := adapter.GetAssertion(context.Background(), ceremonyFor(assertionOpts))
	if err != nil {
		t.Fatalf("GetAssertion() error: %v", err)
	}

	// Verify the response is valid JSON
	var response map[string]interface{}
	if err := json.Unmarshal(result, &response); err != nil {
		t.Fatalf("GetAssertion() returned invalid JSON: %v", err)
	}

	// Verify required fields
	if response["id"] != credID {
		t.Errorf("id = %v, want %v", response["id"], credID)
	}
	if response["type"] != "public-key" {
		t.Errorf("type = %v, want 'public-key'", response["type"])
	}

	respObj, ok := response["response"].(map[string]interface{})
	if !ok {
		t.Fatal("response missing 'response' object")
	}
	if _, ok := respObj["clientDataJSON"]; !ok {
		t.Error("response.response missing 'clientDataJSON'")
	}
	if _, ok := respObj["authenticatorData"]; !ok {
		t.Error("response.response missing 'authenticatorData'")
	}
	if _, ok := respObj["signature"]; !ok {
		t.Error("response.response missing 'signature'")
	}
}

func TestSoftwareAdapter_GetAssertion_NoCredential(t *testing.T) {
	adapter := NewSoftwareAdapter()

	challenge := base64.RawURLEncoding.EncodeToString([]byte("assertion-challenge"))
	assertionOpts := buildTestAssertionOptions("localhost", challenge, "nonexistent-cred-id")

	_, err := adapter.GetAssertion(context.Background(), ceremonyFor(assertionOpts))
	if err == nil {
		t.Fatal("GetAssertion() should return error when no credential is found")
	}
	if !errors.Is(err, ErrCTAPOperationFailed) {
		t.Errorf("error should wrap ErrCTAPOperationFailed, got: %v", err)
	}
}

func TestSoftwareAdapter_GetAssertion_InvalidJSON(t *testing.T) {
	adapter := NewSoftwareAdapter()

	_, err := adapter.GetAssertion(context.Background(), ceremonyFor([]byte("invalid")))
	if err == nil {
		t.Fatal("GetAssertion() should return error for invalid JSON")
	}
	if !errors.Is(err, ErrCTAPOperationFailed) {
		t.Errorf("error should wrap ErrCTAPOperationFailed, got: %v", err)
	}
}

func TestSoftwareAdapter_GetAssertion_MissingRPID(t *testing.T) {
	adapter := NewSoftwareAdapter()

	challenge := base64.RawURLEncoding.EncodeToString([]byte("test-challenge"))
	assertionOpts := buildTestAssertionOptions("", challenge, "some-id")

	_, err := adapter.GetAssertion(context.Background(), ceremonyFor(assertionOpts))
	if err == nil {
		t.Fatal("GetAssertion() should return error for missing RP ID")
	}
	if !errors.Is(err, ErrCTAPOperationFailed) {
		t.Errorf("error should wrap ErrCTAPOperationFailed, got: %v", err)
	}
}

func TestSoftwareAdapter_GetAssertion_InvalidChallenge(t *testing.T) {
	adapter := NewSoftwareAdapter()

	assertionOpts := buildTestAssertionOptions("localhost", "!!!invalid!!!", "some-id")

	_, err := adapter.GetAssertion(context.Background(), ceremonyFor(assertionOpts))
	if err == nil {
		t.Fatal("GetAssertion() should return error for invalid challenge")
	}
	if !errors.Is(err, ErrInvalidChallenge) {
		t.Errorf("error should wrap ErrInvalidChallenge, got: %v", err)
	}
}

func TestSoftwareAdapter_MultipleCredentials(t *testing.T) {
	adapter := NewSoftwareAdapter()

	// Create discoverable credentials for two different RPs so they can
	// be located without an allowList, as required by the CTAP2 spec.
	challenge1 := base64.RawURLEncoding.EncodeToString([]byte("challenge-rp1-12345678901234567"))
	challenge2 := base64.RawURLEncoding.EncodeToString([]byte("challenge-rp2-12345678901234567"))

	rkRequired := map[string]interface{}{"residentKey": "required"}
	opts1 := buildCreationOptionsWithAuthenticatorSelection("rp1.example.com", challenge1, rkRequired)
	opts2 := buildCreationOptionsWithAuthenticatorSelection("rp2.example.com", challenge2, rkRequired)

	_, err := adapter.MakeCredential(context.Background(), ceremonyFor(opts1))
	if err != nil {
		t.Fatalf("MakeCredential(rp1) error: %v", err)
	}
	_, err = adapter.MakeCredential(context.Background(), ceremonyFor(opts2))
	if err != nil {
		t.Fatalf("MakeCredential(rp2) error: %v", err)
	}

	if adapter.CredentialCount() != 2 {
		t.Errorf("CredentialCount() = %d, want 2", adapter.CredentialCount())
	}

	// Assert for rp1 (no allow list, should find the rp1 discoverable credential)
	assertChallenge := base64.RawURLEncoding.EncodeToString([]byte("assert-challenge-12345678901234"))
	assertOpts := buildTestAssertionOptionsNoAllowList("rp1.example.com", assertChallenge)

	result, err := adapter.GetAssertion(context.Background(), ceremonyFor(assertOpts))
	if err != nil {
		t.Fatalf("GetAssertion(rp1) error: %v", err)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(result, &response); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if response["type"] != "public-key" {
		t.Errorf("type = %v, want 'public-key'", response["type"])
	}
}

func TestSoftwareAdapter_WrongRPID(t *testing.T) {
	adapter := NewSoftwareAdapter()

	// Create a discoverable credential for rp1
	challenge := base64.RawURLEncoding.EncodeToString([]byte("challenge-1234567890123456789012"))
	opts := buildCreationOptionsWithAuthenticatorSelection("rp1.example.com", challenge,
		map[string]interface{}{"residentKey": "required"})
	_, err := adapter.MakeCredential(context.Background(), ceremonyFor(opts))
	if err != nil {
		t.Fatalf("MakeCredential() error: %v", err)
	}

	// Try to assert for rp2 (should fail -- no discoverable credential for rp2)
	assertChallenge := base64.RawURLEncoding.EncodeToString([]byte("assert-challenge-12345678901234"))
	assertOpts := buildTestAssertionOptionsNoAllowList("rp2.example.com", assertChallenge)

	_, err = adapter.GetAssertion(context.Background(), ceremonyFor(assertOpts))
	if err == nil {
		t.Fatal("GetAssertion() should fail for wrong RP ID")
	}
	if !errors.Is(err, ErrCTAPOperationFailed) {
		t.Errorf("error should wrap ErrCTAPOperationFailed, got: %v", err)
	}
}

// Helper functions for building test options JSON.

func buildTestCreationOptions(rpID, challenge string) []byte {
	opts := map[string]interface{}{
		"publicKey": map[string]interface{}{
			"challenge": challenge,
			"rp": map[string]interface{}{
				"id":   rpID,
				"name": "Test RP",
			},
			"user": map[string]interface{}{
				"id":          base64.RawURLEncoding.EncodeToString([]byte("user-123")),
				"name":        "test@example.com",
				"displayName": "Test User",
			},
			"pubKeyCredParams": []map[string]interface{}{
				{"type": "public-key", "alg": -7},
			},
		},
	}
	data, _ := json.Marshal(opts)
	return data
}

func buildTestAssertionOptions(rpID, challenge, credID string) []byte {
	opts := map[string]interface{}{
		"publicKey": map[string]interface{}{
			"challenge": challenge,
			"rpId":      rpID,
			"allowCredentials": []map[string]interface{}{
				{"type": "public-key", "id": credID},
			},
		},
	}
	data, _ := json.Marshal(opts)
	return data
}

func buildTestAssertionOptionsNoAllowList(rpID, challenge string) []byte {
	opts := map[string]interface{}{
		"publicKey": map[string]interface{}{
			"challenge": challenge,
			"rpId":      rpID,
		},
	}
	data, _ := json.Marshal(opts)
	return data
}

// extractAuthDataFlagsFromAttestation decodes the attestation response to extract
// the flags byte from the authenticator data embedded in the attestation object.
// The authData structure is: rpIdHash(32) || flags(1) || signCount(4) || ...
// The flags byte is at offset 32.
func extractAuthDataFlagsFromAttestation(t *testing.T, result []byte) byte {
	t.Helper()

	var response map[string]interface{}
	if err := json.Unmarshal(result, &response); err != nil {
		t.Fatalf("failed to parse response JSON: %v", err)
	}

	respObj, ok := response["response"].(map[string]interface{})
	if !ok {
		t.Fatal("response missing 'response' object")
	}

	attObjB64, ok := respObj["attestationObject"].(string)
	if !ok {
		t.Fatal("response missing 'attestationObject'")
	}

	attObjBytes, err := base64.RawURLEncoding.DecodeString(attObjB64)
	if err != nil {
		t.Fatalf("failed to decode attestationObject: %v", err)
	}

	// Decode the CBOR attestation object using fxamacker/cbor
	var attObj map[string]interface{}
	if err := cbor.Unmarshal(attObjBytes, &attObj); err != nil {
		t.Fatalf("failed to decode CBOR attestation object: %v", err)
	}

	authData, ok := attObj["authData"].([]byte)
	if !ok {
		t.Fatal("attestation object missing 'authData' field")
	}

	if len(authData) < 33 {
		t.Fatalf("authData too short: %d bytes, need at least 33", len(authData))
	}

	return authData[32] // flags byte
}

// extractAuthDataFlagsFromAssertion decodes the assertion response to extract
// the flags byte from the authenticator data.
func extractAuthDataFlagsFromAssertion(t *testing.T, result []byte) byte {
	t.Helper()

	var response map[string]interface{}
	if err := json.Unmarshal(result, &response); err != nil {
		t.Fatalf("failed to parse response JSON: %v", err)
	}

	respObj, ok := response["response"].(map[string]interface{})
	if !ok {
		t.Fatal("response missing 'response' object")
	}

	authDataB64, ok := respObj["authenticatorData"].(string)
	if !ok {
		t.Fatal("response missing 'authenticatorData'")
	}

	authData, err := base64.RawURLEncoding.DecodeString(authDataB64)
	if err != nil {
		t.Fatalf("failed to decode authenticatorData: %v", err)
	}

	if len(authData) < 33 {
		t.Fatalf("authData too short: %d bytes, need at least 33", len(authData))
	}

	return authData[32] // flags byte
}

// buildCreationOptionsWithAuthenticatorSelection creates creation options JSON with
// the given authenticatorSelection parameters.
func buildCreationOptionsWithAuthenticatorSelection(rpID, challenge string, authSel map[string]interface{}) []byte {
	pubKey := map[string]interface{}{
		"challenge": challenge,
		"rp": map[string]interface{}{
			"id":   rpID,
			"name": "Test RP",
		},
		"user": map[string]interface{}{
			"id":          base64.RawURLEncoding.EncodeToString([]byte("user-123")),
			"name":        "test@example.com",
			"displayName": "Test User",
		},
		"pubKeyCredParams": []map[string]interface{}{
			{"type": "public-key", "alg": -7},
		},
	}
	if authSel != nil {
		pubKey["authenticatorSelection"] = authSel
	}

	opts := map[string]interface{}{
		"publicKey": pubKey,
	}
	data, _ := json.Marshal(opts)
	return data
}

// buildAssertionOptionsWithUV creates assertion options JSON with
// the given userVerification value and allow list credential ID.
func buildAssertionOptionsWithUV(rpID, challenge, credID, uv string) []byte {
	pubKey := map[string]interface{}{
		"challenge": challenge,
		"rpId":      rpID,
	}
	if credID != "" {
		pubKey["allowCredentials"] = []map[string]interface{}{
			{"type": "public-key", "id": credID},
		}
	}
	if uv != "" {
		pubKey["userVerification"] = uv
	}

	opts := map[string]interface{}{
		"publicKey": pubKey,
	}
	data, _ := json.Marshal(opts)
	return data
}

// getCredentialIDFromAttestation extracts the credential ID (base64url string)
// from a MakeCredential attestation response.
func getCredentialIDFromAttestation(t *testing.T, result []byte) string {
	t.Helper()

	var response map[string]interface{}
	if err := json.Unmarshal(result, &response); err != nil {
		t.Fatalf("failed to parse attestation response: %v", err)
	}
	credID, ok := response["id"].(string)
	if !ok {
		t.Fatal("attestation response missing 'id' field")
	}
	return credID
}

func TestSoftwareAdapter_MakeCredential_WithAuthenticatorSelection(t *testing.T) {
	challenge := base64.RawURLEncoding.EncodeToString([]byte("auth-sel-challenge-123456789012"))

	// With EnablePIN: false, the authenticator has no UV mechanism, so the UV
	// flag will never be set in authData. This is correct CTAP2 behavior:
	// you cannot claim user verification without a verification mechanism.
	tests := []struct {
		name    string
		authSel map[string]interface{}
		wantUP  bool
		wantUV  bool
	}{
		{
			name: "uv_required_no_uv_without_pin",
			authSel: map[string]interface{}{
				"userVerification": "required",
			},
			wantUP: true,
			wantUV: false, // No PIN configured, so UV cannot be set
		},
		{
			name: "uv_preferred_no_uv_without_pin",
			authSel: map[string]interface{}{
				"userVerification": "preferred",
			},
			wantUP: true,
			wantUV: false, // No PIN configured, so UV cannot be set
		},
		{
			name: "uv_discouraged_clears_UV_flag",
			authSel: map[string]interface{}{
				"userVerification": "discouraged",
			},
			wantUP: true,
			wantUV: false,
		},
		{
			name: "residentKey_required",
			authSel: map[string]interface{}{
				"residentKey":      "required",
				"userVerification": "required",
			},
			wantUP: true,
			wantUV: false, // No PIN configured
		},
		{
			name: "residentKey_preferred",
			authSel: map[string]interface{}{
				"residentKey":      "preferred",
				"userVerification": "preferred",
			},
			wantUP: true,
			wantUV: false, // No PIN configured
		},
		{
			name: "residentKey_discouraged",
			authSel: map[string]interface{}{
				"residentKey":      "discouraged",
				"userVerification": "required",
			},
			wantUP: true,
			wantUV: false, // No PIN configured
		},
		{
			name: "requireResidentKey_true",
			authSel: map[string]interface{}{
				"requireResidentKey": true,
				"userVerification":   "required",
			},
			wantUP: true,
			wantUV: false, // No PIN configured
		},
		{
			name: "requireResidentKey_false",
			authSel: map[string]interface{}{
				"requireResidentKey": false,
				"userVerification":   "required",
			},
			wantUP: true,
			wantUV: false, // No PIN configured
		},
		{
			name: "authenticatorAttachment_platform",
			authSel: map[string]interface{}{
				"authenticatorAttachment": "platform",
				"userVerification":        "required",
			},
			wantUP: true,
			wantUV: false, // No PIN configured
		},
		{
			name: "authenticatorAttachment_cross_platform_discouraged",
			authSel: map[string]interface{}{
				"authenticatorAttachment": "cross-platform",
				"userVerification":        "discouraged",
			},
			wantUP: true,
			wantUV: false,
		},
		{
			name:    "no_authenticatorSelection_defaults",
			authSel: nil,
			wantUP:  true,
			wantUV:  false, // No PIN configured
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			adapter := NewSoftwareAdapter()

			opts := buildCreationOptionsWithAuthenticatorSelection("localhost", challenge, tc.authSel)
			result, err := adapter.MakeCredential(context.Background(), ceremonyFor(opts))
			if err != nil {
				t.Fatalf("MakeCredential() error: %v", err)
			}

			// Extract flags from the authData in the attestation object
			flags := extractAuthDataFlagsFromAttestation(t, result)

			gotUP := flags&0x01 != 0
			gotUV := flags&0x04 != 0

			if gotUP != tc.wantUP {
				t.Errorf("UP flag = %v, want %v (flags=0x%02x)", gotUP, tc.wantUP, flags)
			}
			if gotUV != tc.wantUV {
				t.Errorf("UV flag = %v, want %v (flags=0x%02x)", gotUV, tc.wantUV, flags)
			}

			// Verify credential was stored
			if adapter.CredentialCount() != 1 {
				t.Errorf("CredentialCount() = %d, want 1", adapter.CredentialCount())
			}
		})
	}
}

func TestSoftwareAdapter_GetAssertion_WithUserVerification(t *testing.T) {
	// With EnablePIN: false, the authenticator has no UV mechanism. The UV flag
	// will never be set regardless of the RP's userVerification requirement.
	// This is correct CTAP2 behavior for a headless authenticator without PIN.
	tests := []struct {
		name        string
		creationUV  string // userVerification used during MakeCredential
		assertionUV string // userVerification in assertion options ("" means omitted)
		wantUP      bool
		wantUV      bool
	}{
		{
			name:        "assertion_uv_required_no_uv_without_pin",
			creationUV:  "required",
			assertionUV: "required",
			wantUP:      true,
			wantUV:      false, // No PIN mechanism
		},
		{
			name:        "assertion_uv_preferred_no_uv_without_pin",
			creationUV:  "preferred",
			assertionUV: "preferred",
			wantUP:      true,
			wantUV:      false, // No PIN mechanism
		},
		{
			name:        "assertion_uv_discouraged_clears_UV",
			creationUV:  "required",
			assertionUV: "discouraged",
			wantUP:      true,
			wantUV:      false,
		},
		{
			name:        "assertion_uv_empty_with_credential_uv_discouraged_clears_UV",
			creationUV:  "discouraged",
			assertionUV: "",
			wantUP:      true,
			wantUV:      false,
		},
		{
			name:        "assertion_uv_empty_with_credential_uv_required_no_uv",
			creationUV:  "required",
			assertionUV: "",
			wantUP:      true,
			wantUV:      false, // No PIN mechanism
		},
		{
			name:        "assertion_uv_required_overrides_credential_uv_discouraged",
			creationUV:  "discouraged",
			assertionUV: "required",
			wantUP:      true,
			wantUV:      false, // No PIN mechanism
		},
		{
			name:        "assertion_uv_preferred_overrides_credential_uv_discouraged",
			creationUV:  "discouraged",
			assertionUV: "preferred",
			wantUP:      true,
			wantUV:      false, // No PIN mechanism
		},
		{
			name:        "assertion_uv_empty_with_credential_uv_preferred_no_uv",
			creationUV:  "preferred",
			assertionUV: "",
			wantUP:      true,
			wantUV:      false, // No PIN mechanism
		},
		{
			name:        "assertion_uv_empty_with_no_creation_uv_no_uv",
			creationUV:  "",
			assertionUV: "",
			wantUP:      true,
			wantUV:      false, // No PIN mechanism
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			adapter := NewSoftwareAdapter()

			// Step 1: Create a credential with the specified UV policy
			regChallenge := base64.RawURLEncoding.EncodeToString([]byte("reg-challenge-uv-test-123456789"))

			var authSel map[string]interface{}
			if tc.creationUV != "" {
				authSel = map[string]interface{}{
					"userVerification": tc.creationUV,
				}
			}
			creationOpts := buildCreationOptionsWithAuthenticatorSelection("localhost", regChallenge, authSel)

			attestation, err := adapter.MakeCredential(context.Background(), ceremonyFor(creationOpts))
			if err != nil {
				t.Fatalf("MakeCredential() error: %v", err)
			}

			credID := getCredentialIDFromAttestation(t, attestation)

			// Step 2: Get assertion with the specified UV requirement
			assertChallenge := base64.RawURLEncoding.EncodeToString([]byte("assert-challenge-uv-test-12345"))
			assertionOpts := buildAssertionOptionsWithUV("localhost", assertChallenge, credID, tc.assertionUV)

			result, err := adapter.GetAssertion(context.Background(), ceremonyFor(assertionOpts))
			if err != nil {
				t.Fatalf("GetAssertion() error: %v", err)
			}

			// Step 3: Verify UP/UV flags in the assertion authData
			flags := extractAuthDataFlagsFromAssertion(t, result)

			gotUP := flags&0x01 != 0
			gotUV := flags&0x04 != 0

			if gotUP != tc.wantUP {
				t.Errorf("UP flag = %v, want %v (flags=0x%02x)", gotUP, tc.wantUP, flags)
			}
			if gotUV != tc.wantUV {
				t.Errorf("UV flag = %v, want %v (flags=0x%02x)", gotUV, tc.wantUV, flags)
			}
		})
	}
}

func TestSoftwareAdapter_AttestationObjectIsCBOR(t *testing.T) {
	// Verify the attestation object is valid CBOR with string keys as
	// required by the WebAuthn specification.
	adapter := NewSoftwareAdapter()

	challenge := base64.RawURLEncoding.EncodeToString([]byte("cbor-verify-challenge-123456789"))
	opts := buildTestCreationOptions("localhost", challenge)

	result, err := adapter.MakeCredential(context.Background(), ceremonyFor(opts))
	if err != nil {
		t.Fatalf("MakeCredential() error: %v", err)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(result, &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	respObj := response["response"].(map[string]interface{})
	attObjB64 := respObj["attestationObject"].(string)
	attObjBytes, err := base64.RawURLEncoding.DecodeString(attObjB64)
	if err != nil {
		t.Fatalf("failed to decode attestation object: %v", err)
	}

	// Decode with fxamacker/cbor - should succeed with string keys
	var attObj map[string]interface{}
	if err := cbor.Unmarshal(attObjBytes, &attObj); err != nil {
		t.Fatalf("attestation object is not valid CBOR: %v", err)
	}

	// Verify expected string-keyed fields
	if _, ok := attObj["fmt"]; !ok {
		t.Error("attestation object missing 'fmt' field")
	}
	if _, ok := attObj["authData"]; !ok {
		t.Error("attestation object missing 'authData' field")
	}
	if _, ok := attObj["attStmt"]; !ok {
		t.Error("attestation object missing 'attStmt' field")
	}

	// Verify fmt is "none"
	fmtVal, ok := attObj["fmt"].(string)
	if !ok || fmtVal != "none" {
		t.Errorf("fmt = %v, want 'none'", attObj["fmt"])
	}
}

func TestExtractCredentialIDFromAuthData_TooShort(t *testing.T) {
	// authData must be at least 37 bytes
	_, err := extractCredentialIDFromAuthData(make([]byte, 20))
	if err == nil {
		t.Fatal("expected error for authData shorter than 37 bytes")
	}
	if !strings.Contains(err.Error(), "authData too short") {
		t.Errorf("error = %v, want error containing 'authData too short'", err)
	}
}

func TestExtractCredentialIDFromAuthData_ATFlagNotSet(t *testing.T) {
	// 37 bytes with flags byte (offset 32) having AT flag (0x40) not set
	authData := make([]byte, 37)
	authData[32] = 0x01 // UP flag only, no AT flag
	_, err := extractCredentialIDFromAuthData(authData)
	if err == nil {
		t.Fatal("expected error when AT flag is not set")
	}
	if !strings.Contains(err.Error(), "AT flag not set") {
		t.Errorf("error = %v, want error containing 'AT flag not set'", err)
	}
}

func TestExtractCredentialIDFromAuthData_TooShortForAttestedData(t *testing.T) {
	// authData with AT flag set but not enough bytes for aaguid + credIDLen
	authData := make([]byte, 40) // 37 + 3 bytes (not enough for 16 + 2)
	authData[32] = 0x41          // UP + AT flags
	_, err := extractCredentialIDFromAuthData(authData)
	if err == nil {
		t.Fatal("expected error when authData is too short for attested credential data")
	}
	if !strings.Contains(err.Error(), "too short for attested credential data") {
		t.Errorf("error = %v, want error containing 'too short for attested credential data'", err)
	}
}

func TestExtractCredentialIDFromAuthData_TooShortForCredentialID(t *testing.T) {
	// authData with AT flag, aaguid, credIDLen=10 but only 5 bytes of credential ID
	authData := make([]byte, 37+16+2+5) // header + aaguid + len + 5 bytes (short)
	authData[32] = 0x41                 // UP + AT flags
	// Set credIDLen to 10 (big-endian)
	authData[37+16] = 0
	authData[37+16+1] = 10
	_, err := extractCredentialIDFromAuthData(authData)
	if err == nil {
		t.Fatal("expected error when authData is too short for credential ID")
	}
	if !strings.Contains(err.Error(), "too short for credential ID") {
		t.Errorf("error = %v, want error containing 'too short for credential ID'", err)
	}
}

func TestExtractCredentialIDFromAuthData_Success(t *testing.T) {
	// Build valid authData: rpIdHash(32) + flags(1) + signCount(4) + aaguid(16) + credIDLen(2) + credID(4)
	authData := make([]byte, 37+16+2+4)
	authData[32] = 0x41 // UP + AT flags
	// credIDLen = 4 (big-endian)
	authData[37+16] = 0
	authData[37+16+1] = 4
	// credential ID bytes
	copy(authData[37+16+2:], []byte{0xCA, 0xFE, 0xBA, 0xBE})

	credID, err := extractCredentialIDFromAuthData(authData)
	if err != nil {
		t.Fatalf("extractCredentialIDFromAuthData() error: %v", err)
	}
	if len(credID) != 4 {
		t.Errorf("credentialID length = %d, want 4", len(credID))
	}
	expected := []byte{0xCA, 0xFE, 0xBA, 0xBE}
	for i, b := range credID {
		if b != expected[i] {
			t.Errorf("credentialID[%d] = 0x%02x, want 0x%02x", i, b, expected[i])
		}
	}
}

func TestNormalizeAttStmt_StringKeyedMap(t *testing.T) {
	input := map[string]interface{}{
		"alg": -7,
		"sig": []byte{0x01, 0x02},
	}
	result := normalizeAttStmt(input)
	if result == nil {
		t.Fatal("normalizeAttStmt returned nil for map[string]interface{}")
	}
	if result["alg"] != -7 {
		t.Errorf("alg = %v, want -7", result["alg"])
	}
}

func TestNormalizeAttStmt_InterfaceKeyedMap(t *testing.T) {
	input := map[interface{}]interface{}{
		"alg": -7,
		"sig": []byte{0x01, 0x02},
		42:    "non-string key is dropped",
	}
	result := normalizeAttStmt(input)
	if result == nil {
		t.Fatal("normalizeAttStmt returned nil for map[interface{}]interface{}")
	}
	if result["alg"] != -7 {
		t.Errorf("alg = %v, want -7", result["alg"])
	}
	if _, ok := result["sig"]; !ok {
		t.Error("sig key should be present")
	}
	// Non-string key (42) should be dropped
	if len(result) != 2 {
		t.Errorf("result length = %d, want 2 (non-string keys should be dropped)", len(result))
	}
}

func TestNormalizeAttStmt_DefaultBranch(t *testing.T) {
	// Test with a value that is neither map type -- triggers the default branch
	result := normalizeAttStmt("not a map")
	if result == nil {
		t.Fatal("normalizeAttStmt returned nil for default branch")
	}
	if len(result) != 0 {
		t.Errorf("result should be empty map for non-map input, got %v", result)
	}
}

func TestBuildCBORPubKeyCredParams_EmptyParams(t *testing.T) {
	result := buildCBORPubKeyCredParams(nil)
	if len(result) != 1 {
		t.Fatalf("expected 1 default param, got %d", len(result))
	}
	if result[0]["alg"] != -7 {
		t.Errorf("default alg = %v, want -7 (ES256)", result[0]["alg"])
	}
}

func TestBuildCBORPubKeyCredParams_CustomParams(t *testing.T) {
	params := []pubKeyCredParam{
		{Type: "public-key", Alg: -7},
		{Type: "public-key", Alg: -257},
	}
	result := buildCBORPubKeyCredParams(params)
	if len(result) != 2 {
		t.Fatalf("expected 2 params, got %d", len(result))
	}
	if result[1]["alg"] != -257 {
		t.Errorf("second alg = %v, want -257", result[1]["alg"])
	}
}

func TestBuildCollectedClientData(t *testing.T) {
	challenge := []byte("test-challenge")
	cd := buildCollectedClientData("webauthn.create", challenge, "https://example.com")
	if cd.Type != "webauthn.create" {
		t.Errorf("Type = %q, want %q", cd.Type, "webauthn.create")
	}
	if cd.Origin != "https://example.com" {
		t.Errorf("Origin = %q, want %q", cd.Origin, "https://example.com")
	}
	// Challenge should be base64url encoded
	decoded, err := base64.RawURLEncoding.DecodeString(cd.Challenge)
	if err != nil {
		t.Fatalf("Challenge is not valid base64url: %v", err)
	}
	if string(decoded) != "test-challenge" {
		t.Errorf("decoded challenge = %q, want %q", string(decoded), "test-challenge")
	}
}

func TestSoftwareAdapter_MakeCredential_InvalidUserID(t *testing.T) {
	adapter := NewSoftwareAdapter()

	// Invalid base64url in user ID
	opts, _ := json.Marshal(map[string]interface{}{
		"publicKey": map[string]interface{}{
			"challenge": base64.RawURLEncoding.EncodeToString([]byte("test-challenge-12345678")),
			"rp":        map[string]interface{}{"id": "localhost", "name": "Test"},
			"user": map[string]interface{}{
				"id":          "!!!not-valid-base64!!!",
				"name":        "test@example.com",
				"displayName": "Test",
			},
		},
	})

	_, err := adapter.MakeCredential(context.Background(), ceremonyFor(opts))
	if err == nil {
		t.Fatal("MakeCredential() should return error for invalid user ID encoding")
	}
	if !errors.Is(err, ErrCTAPOperationFailed) {
		t.Errorf("error should wrap ErrCTAPOperationFailed, got: %v", err)
	}
}

func TestSoftwareAdapter_GetAssertion_InvalidAllowCredentialID(t *testing.T) {
	adapter := NewSoftwareAdapter()

	// First register a credential
	regChallenge := base64.RawURLEncoding.EncodeToString([]byte("inv-allow-reg-challenge-12345678"))
	creationOpts := buildTestCreationOptions("localhost", regChallenge)
	_, err := adapter.MakeCredential(context.Background(), ceremonyFor(creationOpts))
	if err != nil {
		t.Fatalf("MakeCredential() error: %v", err)
	}

	// Use an allow credential with non-base64url ID -- should fall back to raw bytes
	assertChallenge := base64.RawURLEncoding.EncodeToString([]byte("inv-allow-assert-challenge-12345"))
	opts, _ := json.Marshal(map[string]interface{}{
		"publicKey": map[string]interface{}{
			"challenge": assertChallenge,
			"rpId":      "localhost",
			"allowCredentials": []map[string]interface{}{
				{"type": "public-key", "id": "!!!not-base64!!!"},
			},
		},
	})

	// This should not panic -- the code falls back to using raw bytes
	_, err = adapter.GetAssertion(context.Background(), ceremonyFor(opts))
	// It will likely fail because the credential ID doesn't match, which is expected
	if err == nil {
		// If it doesn't fail, that's OK too -- we just wanted to exercise the fallback path
		return
	}
	if !errors.Is(err, ErrCTAPOperationFailed) {
		t.Errorf("error should wrap ErrCTAPOperationFailed, got: %v", err)
	}
}

// ceremonyFor wraps optionsJSON in CeremonyOptions carrying the origin a
// browser on the relying party's own host reports: https://<rp id>, read from
// the options' rp.id (creation) or rpId (request). Options with no RP ID, or
// that are not JSON, get no origin, so the parse and missing-RP-ID failures
// they exercise are the ones reported.
func ceremonyFor(optionsJSON []byte) *CeremonyOptions {
	var doc struct {
		PublicKey struct {
			RP struct {
				ID string `json:"id"`
			} `json:"rp"`
			RPID string `json:"rpId"`
		} `json:"publicKey"`
	}
	opts := &CeremonyOptions{OptionsJSON: optionsJSON}
	if err := json.Unmarshal(optionsJSON, &doc); err != nil {
		return opts
	}
	rpID := doc.PublicKey.RP.ID
	if rpID == "" {
		rpID = doc.PublicKey.RPID
	}
	if rpID != "" {
		opts.Origin = "https://" + rpID
	}
	return opts
}
