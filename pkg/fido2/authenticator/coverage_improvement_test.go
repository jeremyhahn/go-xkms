// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package authenticator

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// handleChangePIN edge case tests (cmd_clientpin.go)
// =============================================================================

// TestChangePINWithPINBlocked tests that ChangePIN fails when PIN retries are exhausted.
func TestChangePINWithPINBlocked(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set initial PIN.
	initialPIN := "1234"
	if err := auth.SetPINForTesting(initialPIN); err != nil {
		t.Fatalf("Failed to set initial PIN: %v", err)
	}

	// Exhaust all PIN retries.
	auth.state.SetPINRetries(0)

	// Get key agreement.
	_, err := getKeyAgreement(t, auth)
	if err != nil {
		t.Fatalf("Failed to get key agreement: %v", err)
	}

	// Generate platform key and get shared secret.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	if err != nil {
		t.Fatalf("Failed to generate platform key: %v", err)
	}

	// Prepare ChangePIN request.
	newPIN := "5678"
	newPinEnc, _, err := encryptNewPIN(sharedSecret, newPIN)
	if err != nil {
		t.Fatalf("Failed to encrypt new PIN: %v", err)
	}

	pinHashEnc, err := encryptPINHash(sharedSecret, initialPIN)
	if err != nil {
		t.Fatalf("Failed to encrypt PIN hash: %v", err)
	}

	// Generate authParam.
	authData := append(newPinEnc, pinHashEnc...)
	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write(authData)
	authParam := mac.Sum(nil)[:16]

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdChangePIN,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinUvAuthParam:    authParam,
		clientPINKeyNewPinEnc:         newPinEnc,
		clientPINKeyPinHashEnc:        pinHashEnc,
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err == nil {
		t.Fatal("Expected error when PIN is blocked")
	}

	if resp[0] != StatusPINBlocked {
		t.Errorf("Expected StatusPINBlocked (0x%02x), got 0x%02x", StatusPINBlocked, resp[0])
	}
}

// TestChangePINMissingKeyAgreement tests ChangePIN without key agreement.
func TestChangePINMissingKeyAgreement(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set initial PIN.
	if err := auth.SetPINForTesting("1234"); err != nil {
		t.Fatalf("Failed to set initial PIN: %v", err)
	}

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdChangePIN,
		// Missing keyAgreement
		clientPINKeyPinUvAuthParam: make([]byte, 16),
		clientPINKeyNewPinEnc:      make([]byte, 64),
		clientPINKeyPinHashEnc:     make([]byte, 16),
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	// First init PIN protocol.
	_, err = getKeyAgreement(t, auth)
	if err != nil {
		t.Fatalf("Failed to get key agreement: %v", err)
	}

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err == nil {
		t.Fatal("Expected error when key agreement is missing")
	}

	if resp[0] != StatusInvalidParameter && resp[0] != StatusOtherError {
		t.Errorf("Expected error status, got 0x%02x", resp[0])
	}
}

// TestChangePINMissingPinUvAuthParam tests ChangePIN without pinUvAuthParam.
func TestChangePINMissingPinUvAuthParam(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set initial PIN.
	if err := auth.SetPINForTesting("1234"); err != nil {
		t.Fatalf("Failed to set initial PIN: %v", err)
	}

	// Get key agreement.
	_, err := getKeyAgreement(t, auth)
	if err != nil {
		t.Fatalf("Failed to get key agreement: %v", err)
	}

	// Generate platform key and get shared secret.
	auth.mu.Lock()
	platformCOSE, _, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	if err != nil {
		t.Fatalf("Failed to generate platform key: %v", err)
	}

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdChangePIN,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		// Missing pinUvAuthParam, newPinEnc, and pinHashEnc
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err == nil {
		t.Fatal("Expected error when required parameters are missing")
	}

	if resp[0] != StatusInvalidParameter {
		t.Errorf("Expected StatusInvalidParameter, got 0x%02x", resp[0])
	}
}

// TestChangePINInvalidAuthParam tests ChangePIN with invalid auth param.
func TestChangePINInvalidAuthParam(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set initial PIN.
	if err := auth.SetPINForTesting("1234"); err != nil {
		t.Fatalf("Failed to set initial PIN: %v", err)
	}

	// Get key agreement.
	_, err := getKeyAgreement(t, auth)
	if err != nil {
		t.Fatalf("Failed to get key agreement: %v", err)
	}

	// Generate platform key and get shared secret.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	if err != nil {
		t.Fatalf("Failed to generate platform key: %v", err)
	}

	// Prepare ChangePIN request with wrong auth param.
	newPinEnc, _, err := encryptNewPIN(sharedSecret, "5678")
	if err != nil {
		t.Fatalf("Failed to encrypt new PIN: %v", err)
	}

	pinHashEnc, err := encryptPINHash(sharedSecret, "1234")
	if err != nil {
		t.Fatalf("Failed to encrypt PIN hash: %v", err)
	}

	// Use wrong auth param.
	wrongAuthParam := make([]byte, 16)

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdChangePIN,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinUvAuthParam:    wrongAuthParam,
		clientPINKeyNewPinEnc:         newPinEnc,
		clientPINKeyPinHashEnc:        pinHashEnc,
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err == nil {
		t.Fatal("Expected error when auth param is invalid")
	}

	if resp[0] != StatusPINAuthInvalid {
		t.Errorf("Expected StatusPINAuthInvalid, got 0x%02x", resp[0])
	}
}

// TestChangePINNewPINTooShort tests ChangePIN with new PIN that's too short.
func TestChangePINNewPINTooShort(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set initial PIN.
	initialPIN := "1234"
	if err := auth.SetPINForTesting(initialPIN); err != nil {
		t.Fatalf("Failed to set initial PIN: %v", err)
	}

	// Get key agreement.
	_, err := getKeyAgreement(t, auth)
	if err != nil {
		t.Fatalf("Failed to get key agreement: %v", err)
	}

	// Generate platform key and get shared secret.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	if err != nil {
		t.Fatalf("Failed to generate platform key: %v", err)
	}

	// Prepare ChangePIN request with short new PIN.
	newPIN := "123" // Too short (less than 4)
	newPinEnc, _, err := encryptNewPIN(sharedSecret, newPIN)
	if err != nil {
		t.Fatalf("Failed to encrypt new PIN: %v", err)
	}

	pinHashEnc, err := encryptPINHash(sharedSecret, initialPIN)
	if err != nil {
		t.Fatalf("Failed to encrypt PIN hash: %v", err)
	}

	// Generate correct authParam.
	authData := append(newPinEnc, pinHashEnc...)
	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write(authData)
	authParam := mac.Sum(nil)[:16]

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdChangePIN,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinUvAuthParam:    authParam,
		clientPINKeyNewPinEnc:         newPinEnc,
		clientPINKeyPinHashEnc:        pinHashEnc,
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err == nil {
		t.Fatal("Expected error when new PIN is too short")
	}

	if resp[0] != StatusPINPolicyViolation {
		t.Errorf("Expected StatusPINPolicyViolation, got 0x%02x", resp[0])
	}
}

// TestChangePINDecryptBlockFails tests ChangePIN when PIN hash decryption fails.
func TestChangePINDecryptBlockFails(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set initial PIN.
	initialPIN := "1234"
	if err := auth.SetPINForTesting(initialPIN); err != nil {
		t.Fatalf("Failed to set initial PIN: %v", err)
	}

	// Get key agreement.
	_, err := getKeyAgreement(t, auth)
	if err != nil {
		t.Fatalf("Failed to get key agreement: %v", err)
	}

	// Generate platform key and get shared secret.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	if err != nil {
		t.Fatalf("Failed to generate platform key: %v", err)
	}

	// Prepare request with wrong length pinHashEnc (should be 16 bytes).
	newPinEnc, _, err := encryptNewPIN(sharedSecret, "5678")
	if err != nil {
		t.Fatalf("Failed to encrypt new PIN: %v", err)
	}

	// Wrong length pinHashEnc (not 16 bytes).
	wrongPinHashEnc := make([]byte, 32) // Wrong size

	// Generate authParam (still valid HMAC, but pinHashEnc has wrong length).
	authData := append(newPinEnc, wrongPinHashEnc...)
	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write(authData)
	authParam := mac.Sum(nil)[:16]

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdChangePIN,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinUvAuthParam:    authParam,
		clientPINKeyNewPinEnc:         newPinEnc,
		clientPINKeyPinHashEnc:        wrongPinHashEnc,
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	// Record initial retries.
	initialRetries := auth.PINRetries()

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err == nil {
		t.Fatal("Expected error when decryption fails")
	}

	// Verify retries were decremented.
	if auth.PINRetries() >= initialRetries {
		t.Error("PIN retries should have been decremented")
	}

	if resp[0] != StatusPINInvalid {
		t.Errorf("Expected StatusPINInvalid, got 0x%02x", resp[0])
	}
}

// TestChangePINDecryptBlockFailsUntilBlocked tests ChangePIN decryption failure until blocked.
func TestChangePINDecryptBlockFailsUntilBlocked(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set initial PIN with only 1 retry left.
	if err := auth.SetPINForTesting("1234"); err != nil {
		t.Fatalf("Failed to set initial PIN: %v", err)
	}
	auth.state.SetPINRetries(1)

	// Get key agreement.
	_, err := getKeyAgreement(t, auth)
	if err != nil {
		t.Fatalf("Failed to get key agreement: %v", err)
	}

	// Generate platform key and get shared secret.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	if err != nil {
		t.Fatalf("Failed to generate platform key: %v", err)
	}

	// Prepare request with wrong length pinHashEnc.
	newPinEnc, _, err := encryptNewPIN(sharedSecret, "5678")
	if err != nil {
		t.Fatalf("Failed to encrypt new PIN: %v", err)
	}

	wrongPinHashEnc := make([]byte, 32) // Wrong size

	authData := append(newPinEnc, wrongPinHashEnc...)
	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write(authData)
	authParam := mac.Sum(nil)[:16]

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdChangePIN,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinUvAuthParam:    authParam,
		clientPINKeyNewPinEnc:         newPinEnc,
		clientPINKeyPinHashEnc:        wrongPinHashEnc,
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err == nil {
		t.Fatal("Expected error when decryption fails")
	}

	if resp[0] != StatusPINBlocked {
		t.Errorf("Expected StatusPINBlocked, got 0x%02x", resp[0])
	}
}

// TestChangePINWrongPINUntilBlocked tests ChangePIN with wrong PIN until blocked.
func TestChangePINWrongPINUntilBlocked(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set initial PIN with only 1 retry left.
	if err := auth.SetPINForTesting("1234"); err != nil {
		t.Fatalf("Failed to set initial PIN: %v", err)
	}
	auth.state.SetPINRetries(1)

	// Get key agreement.
	_, err := getKeyAgreement(t, auth)
	if err != nil {
		t.Fatalf("Failed to get key agreement: %v", err)
	}

	// Generate platform key and get shared secret.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	if err != nil {
		t.Fatalf("Failed to generate platform key: %v", err)
	}

	// Prepare request with wrong current PIN.
	newPinEnc, _, err := encryptNewPIN(sharedSecret, "5678")
	if err != nil {
		t.Fatalf("Failed to encrypt new PIN: %v", err)
	}

	// Wrong current PIN hash.
	pinHashEnc, err := encryptPINHash(sharedSecret, "9999")
	if err != nil {
		t.Fatalf("Failed to encrypt PIN hash: %v", err)
	}

	authData := append(newPinEnc, pinHashEnc...)
	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write(authData)
	authParam := mac.Sum(nil)[:16]

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdChangePIN,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinUvAuthParam:    authParam,
		clientPINKeyNewPinEnc:         newPinEnc,
		clientPINKeyPinHashEnc:        pinHashEnc,
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err == nil {
		t.Fatal("Expected error for wrong PIN")
	}

	// Should return PIN blocked since we had only 1 retry.
	if resp[0] != StatusPINBlocked {
		t.Errorf("Expected StatusPINBlocked, got 0x%02x", resp[0])
	}
}

// =============================================================================
// handleGetPinUvAuthTokenUsingPinWithPermissions edge case tests
// =============================================================================

// TestGetPinUvAuthTokenWithPermissionsMissingPermissions tests missing permissions.
func TestGetPinUvAuthTokenWithPermissionsMissingPermissions(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set PIN.
	if err := auth.SetPINForTesting("1234"); err != nil {
		t.Fatalf("Failed to set PIN: %v", err)
	}

	// Get key agreement.
	_, err := getKeyAgreement(t, auth)
	if err != nil {
		t.Fatalf("Failed to get key agreement: %v", err)
	}

	// Generate platform key.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	if err != nil {
		t.Fatalf("Failed to generate platform key: %v", err)
	}

	pinHashEnc, err := encryptPINHash(sharedSecret, "1234")
	if err != nil {
		t.Fatalf("Failed to encrypt PIN hash: %v", err)
	}

	// Request without permissions (or permissions = 0).
	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdGetPinUvAuthTokenUsingPinWithPermissions,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        pinHashEnc,
		clientPINKeyPermissions:       0, // Zero permissions
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err == nil {
		t.Fatal("Expected error for missing permissions")
	}

	if resp[0] != StatusInvalidParameter {
		t.Errorf("Expected StatusInvalidParameter, got 0x%02x", resp[0])
	}
}

// TestGetPinUvAuthTokenWithPermissionsBlocked tests when PIN is blocked.
func TestGetPinUvAuthTokenWithPermissionsBlocked(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set PIN and exhaust retries.
	if err := auth.SetPINForTesting("1234"); err != nil {
		t.Fatalf("Failed to set PIN: %v", err)
	}
	auth.state.SetPINRetries(0)

	// Get key agreement.
	_, err := getKeyAgreement(t, auth)
	if err != nil {
		t.Fatalf("Failed to get key agreement: %v", err)
	}

	// Generate platform key.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	if err != nil {
		t.Fatalf("Failed to generate platform key: %v", err)
	}

	pinHashEnc, err := encryptPINHash(sharedSecret, "1234")
	if err != nil {
		t.Fatalf("Failed to encrypt PIN hash: %v", err)
	}

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdGetPinUvAuthTokenUsingPinWithPermissions,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        pinHashEnc,
		clientPINKeyPermissions:       PINPermissionMakeCredential,
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err == nil {
		t.Fatal("Expected error when PIN is blocked")
	}

	if resp[0] != StatusPINBlocked {
		t.Errorf("Expected StatusPINBlocked, got 0x%02x", resp[0])
	}
}

// TestGetPinUvAuthTokenWithPermissionsWrongPIN tests wrong PIN.
func TestGetPinUvAuthTokenWithPermissionsWrongPIN(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set PIN.
	if err := auth.SetPINForTesting("1234"); err != nil {
		t.Fatalf("Failed to set PIN: %v", err)
	}

	initialRetries := auth.PINRetries()

	// Get key agreement.
	_, err := getKeyAgreement(t, auth)
	if err != nil {
		t.Fatalf("Failed to get key agreement: %v", err)
	}

	// Generate platform key.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	if err != nil {
		t.Fatalf("Failed to generate platform key: %v", err)
	}

	// Wrong PIN.
	pinHashEnc, err := encryptPINHash(sharedSecret, "9999")
	if err != nil {
		t.Fatalf("Failed to encrypt PIN hash: %v", err)
	}

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdGetPinUvAuthTokenUsingPinWithPermissions,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        pinHashEnc,
		clientPINKeyPermissions:       PINPermissionMakeCredential,
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err == nil {
		t.Fatal("Expected error for wrong PIN")
	}

	if resp[0] != StatusPINInvalid {
		t.Errorf("Expected StatusPINInvalid, got 0x%02x", resp[0])
	}

	// Verify retries decremented.
	if auth.PINRetries() >= initialRetries {
		t.Error("PIN retries should have been decremented")
	}
}

// TestGetPinUvAuthTokenWithPermissionsDecryptFails tests decryption failure.
func TestGetPinUvAuthTokenWithPermissionsDecryptFails(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set PIN.
	if err := auth.SetPINForTesting("1234"); err != nil {
		t.Fatalf("Failed to set PIN: %v", err)
	}

	// Get key agreement.
	_, err := getKeyAgreement(t, auth)
	if err != nil {
		t.Fatalf("Failed to get key agreement: %v", err)
	}

	// Generate platform key.
	auth.mu.Lock()
	platformCOSE, _, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	if err != nil {
		t.Fatalf("Failed to generate platform key: %v", err)
	}

	// Wrong length pinHashEnc.
	wrongPinHashEnc := make([]byte, 32)

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdGetPinUvAuthTokenUsingPinWithPermissions,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        wrongPinHashEnc,
		clientPINKeyPermissions:       PINPermissionMakeCredential,
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err == nil {
		t.Fatal("Expected error for decryption failure")
	}

	if resp[0] != StatusPINInvalid {
		t.Errorf("Expected StatusPINInvalid, got 0x%02x", resp[0])
	}
}

// TestGetPinUvAuthTokenWithPermissionsDecryptFailsUntilBlocked tests decryption failure until blocked.
func TestGetPinUvAuthTokenWithPermissionsDecryptFailsUntilBlocked(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set PIN with only 1 retry.
	if err := auth.SetPINForTesting("1234"); err != nil {
		t.Fatalf("Failed to set PIN: %v", err)
	}
	auth.state.SetPINRetries(1)

	// Get key agreement.
	_, err := getKeyAgreement(t, auth)
	if err != nil {
		t.Fatalf("Failed to get key agreement: %v", err)
	}

	// Generate platform key.
	auth.mu.Lock()
	platformCOSE, _, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	if err != nil {
		t.Fatalf("Failed to generate platform key: %v", err)
	}

	// Wrong length pinHashEnc.
	wrongPinHashEnc := make([]byte, 32)

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdGetPinUvAuthTokenUsingPinWithPermissions,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        wrongPinHashEnc,
		clientPINKeyPermissions:       PINPermissionMakeCredential,
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err == nil {
		t.Fatal("Expected error for decryption failure")
	}

	if resp[0] != StatusPINBlocked {
		t.Errorf("Expected StatusPINBlocked, got 0x%02x", resp[0])
	}
}

// TestGetPinUvAuthTokenWithPermissionsWrongPINUntilBlocked tests wrong PIN until blocked.
func TestGetPinUvAuthTokenWithPermissionsWrongPINUntilBlocked(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set PIN with only 1 retry.
	if err := auth.SetPINForTesting("1234"); err != nil {
		t.Fatalf("Failed to set PIN: %v", err)
	}
	auth.state.SetPINRetries(1)

	// Get key agreement.
	_, err := getKeyAgreement(t, auth)
	if err != nil {
		t.Fatalf("Failed to get key agreement: %v", err)
	}

	// Generate platform key.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	if err != nil {
		t.Fatalf("Failed to generate platform key: %v", err)
	}

	// Wrong PIN.
	pinHashEnc, err := encryptPINHash(sharedSecret, "9999")
	if err != nil {
		t.Fatalf("Failed to encrypt PIN hash: %v", err)
	}

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdGetPinUvAuthTokenUsingPinWithPermissions,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        pinHashEnc,
		clientPINKeyPermissions:       PINPermissionMakeCredential,
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err == nil {
		t.Fatal("Expected error for wrong PIN")
	}

	if resp[0] != StatusPINBlocked {
		t.Errorf("Expected StatusPINBlocked, got 0x%02x", resp[0])
	}
}

// =============================================================================
// decodeGetAssertionOptions edge case tests (cmd_getassertion.go)
// =============================================================================

// TestDecodeGetAssertionOptionsStringKeyedMap tests string-keyed map decoding.
func TestDecodeGetAssertionOptionsStringKeyedMap(t *testing.T) {
	stringKeyedMap := map[string]interface{}{
		"up": true,
		"uv": false,
	}

	options, err := decodeGetAssertionOptions(stringKeyedMap)
	require.NoError(t, err)
	require.True(t, options["up"])
	require.False(t, options["uv"])
}

// TestDecodeGetAssertionOptionsInterfaceKeyedMap tests interface-keyed map decoding.
func TestDecodeGetAssertionOptionsInterfaceKeyedMap(t *testing.T) {
	interfaceKeyedMap := map[interface{}]interface{}{
		"up": true,
		"uv": false,
		123:  true,         // Non-string key should be skipped
		"rk": "not-a-bool", // Non-bool value should be skipped
	}

	options, err := decodeGetAssertionOptions(interfaceKeyedMap)
	require.NoError(t, err)
	require.True(t, options["up"])
	require.False(t, options["uv"])
	require.Len(t, options, 2) // Only up and uv should be present
}

// TestDecodeGetAssertionOptionsNonBoolValues tests handling of non-bool values.
func TestDecodeGetAssertionOptionsNonBoolValues(t *testing.T) {
	stringKeyedMap := map[string]interface{}{
		"up":    true,
		"other": "string-value", // Should be skipped
	}

	options, err := decodeGetAssertionOptions(stringKeyedMap)
	require.NoError(t, err)
	require.True(t, options["up"])
	_, exists := options["other"]
	require.False(t, exists)
}

// =============================================================================
// decodeGetAssertionCredentialDescriptor edge case tests (cmd_getassertion.go)
// =============================================================================

// TestDecodeGetAssertionCredentialDescriptorStringKeyedMap tests string-keyed map.
func TestDecodeGetAssertionCredentialDescriptorStringKeyedMap(t *testing.T) {
	credID := make([]byte, 32)
	_, _ = rand.Read(credID)

	stringKeyedMap := map[string]interface{}{
		"type":       "public-key",
		"id":         credID,
		"transports": []interface{}{"internal", "usb"},
	}

	desc, err := decodeGetAssertionCredentialDescriptor(stringKeyedMap)
	require.NoError(t, err)
	require.Equal(t, "public-key", desc.Type)
	require.Equal(t, credID, desc.ID)
	require.Contains(t, desc.Transports, "internal")
	require.Contains(t, desc.Transports, "usb")
}

// TestDecodeGetAssertionCredentialDescriptorInterfaceKeyedMap tests interface-keyed map.
func TestDecodeGetAssertionCredentialDescriptorInterfaceKeyedMap(t *testing.T) {
	credID := make([]byte, 32)
	_, _ = rand.Read(credID)

	interfaceKeyedMap := map[interface{}]interface{}{
		"type":       "public-key",
		"id":         credID,
		"transports": []interface{}{"nfc"},
	}

	desc, err := decodeGetAssertionCredentialDescriptor(interfaceKeyedMap)
	require.NoError(t, err)
	require.Equal(t, "public-key", desc.Type)
	require.Equal(t, credID, desc.ID)
	require.Contains(t, desc.Transports, "nfc")
}

// TestDecodeGetAssertionCredentialDescriptorInvalidType tests invalid raw type.
func TestDecodeGetAssertionCredentialDescriptorInvalidType(t *testing.T) {
	_, err := decodeGetAssertionCredentialDescriptor("not-a-map")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrGetAssertionInvalidCredentialDescriptor)
}

// TestDecodeGetAssertionCredentialDescriptorMissingType tests missing type field.
func TestDecodeGetAssertionCredentialDescriptorMissingType(t *testing.T) {
	credID := make([]byte, 32)
	m := map[string]interface{}{
		"id": credID,
	}

	_, err := decodeGetAssertionCredentialDescriptor(m)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrGetAssertionInvalidCredentialDescriptor)
}

// TestDecodeGetAssertionCredentialDescriptorMissingID tests missing id field.
func TestDecodeGetAssertionCredentialDescriptorMissingID(t *testing.T) {
	m := map[string]interface{}{
		"type": "public-key",
	}

	_, err := decodeGetAssertionCredentialDescriptor(m)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrGetAssertionInvalidCredentialDescriptor)
}

// TestDecodeGetAssertionCredentialDescriptorEmptyType tests empty type.
func TestDecodeGetAssertionCredentialDescriptorEmptyType(t *testing.T) {
	credID := make([]byte, 32)
	m := map[string]interface{}{
		"type": "",
		"id":   credID,
	}

	_, err := decodeGetAssertionCredentialDescriptor(m)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrGetAssertionInvalidCredentialDescriptor)
}

// TestDecodeGetAssertionCredentialDescriptorEmptyID tests empty ID.
func TestDecodeGetAssertionCredentialDescriptorEmptyID(t *testing.T) {
	m := map[string]interface{}{
		"type": "public-key",
		"id":   []byte{},
	}

	_, err := decodeGetAssertionCredentialDescriptor(m)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrGetAssertionInvalidCredentialDescriptor)
}

// TestDecodeGetAssertionCredentialDescriptorNonStringTransports tests non-string transports.
func TestDecodeGetAssertionCredentialDescriptorNonStringTransports(t *testing.T) {
	credID := make([]byte, 32)
	_, _ = rand.Read(credID)

	m := map[string]interface{}{
		"type":       "public-key",
		"id":         credID,
		"transports": []interface{}{123, "usb", nil}, // Mixed types
	}

	desc, err := decodeGetAssertionCredentialDescriptor(m)
	require.NoError(t, err)
	require.Equal(t, "public-key", desc.Type)
	// Only "usb" should be included
	require.Contains(t, desc.Transports, "usb")
	require.Len(t, desc.Transports, 1)
}

// =============================================================================
// processHMACSecretExtension edge case tests (cmd_getassertion.go)
// =============================================================================

// TestProcessHMACSecretExtensionNoKey tests when credential has no HMAC secret key.
func TestProcessHMACSecretExtensionNoKey(t *testing.T) {
	auth := createTestAuthenticator(t)
	rpID := "example.com"

	// Create credential WITHOUT HMAC secret key.
	credID, err := GenerateCredentialID()
	require.NoError(t, err)

	privateKey, publicKeyCOSE, err := GenerateCredentialKey(COSEAlgES256)
	require.NoError(t, err)

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)

	cred := &StoredCredential{
		CredentialID:    credID,
		RPID:            rpID,
		RPName:          "Test RP",
		UserID:          []byte("user-123"),
		UserName:        "testuser@example.com",
		UserDisplayName: "Test User",
		PrivateKey:      privateKeyBytes,
		PublicKeyCOSE:   publicKeyCOSE,
		Algorithm:       COSEAlgES256,
		SignCount:       0,
		Discoverable:    false,
		HMACSecretKey:   nil, // No HMAC secret key
		CreatedAt:       time.Now().Unix(),
	}

	err = auth.storage.Store(cred)
	require.NoError(t, err)

	clientDataHash := generateTestClientDataHash()
	salt1 := make([]byte, 32)
	_, _ = rand.Read(salt1)

	request := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: clientDataHash,
		getAssertionParamAllowList: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   cred.CredentialID,
			},
		},
		getAssertionParamExtensions: map[string]interface{}{
			"hmac-secret": map[string]interface{}{
				"salt1": salt1,
			},
		},
	}

	reqBytes, err := cbor.Marshal(request)
	require.NoError(t, err)

	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, reqBytes)
	require.Error(t, err)
	require.NotEqual(t, byte(StatusOK), respBytes[0])
}

// TestProcessHMACSecretExtensionInvalidInputType tests invalid input type.
func TestProcessHMACSecretExtensionInvalidInputType(t *testing.T) {
	auth := createTestAuthenticator(t)
	rpID := "example.com"
	cred := createAssertionTestCredential(t, auth, rpID, false)

	clientDataHash := generateTestClientDataHash()

	request := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: clientDataHash,
		getAssertionParamAllowList: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   cred.CredentialID,
			},
		},
		getAssertionParamExtensions: map[string]interface{}{
			"hmac-secret": "not-a-map", // Invalid type
		},
	}

	reqBytes, err := cbor.Marshal(request)
	require.NoError(t, err)

	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, reqBytes)
	require.Error(t, err)
	require.NotEqual(t, byte(StatusOK), respBytes[0])
}

// TestProcessHMACSecretExtensionInvalidSalt2Length tests invalid salt2 length.
func TestProcessHMACSecretExtensionInvalidSalt2Length(t *testing.T) {
	auth := createTestAuthenticator(t)
	rpID := "example.com"
	cred := createAssertionTestCredential(t, auth, rpID, false)

	clientDataHash := generateTestClientDataHash()
	salt1 := make([]byte, 32)
	_, _ = rand.Read(salt1)
	salt2 := make([]byte, 16) // Wrong size (should be 32)
	_, _ = rand.Read(salt2)

	request := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: clientDataHash,
		getAssertionParamAllowList: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   cred.CredentialID,
			},
		},
		getAssertionParamExtensions: map[string]interface{}{
			"hmac-secret": map[string]interface{}{
				"salt1": salt1,
				"salt2": salt2,
			},
		},
	}

	reqBytes, err := cbor.Marshal(request)
	require.NoError(t, err)

	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, reqBytes)
	require.Error(t, err)
	require.NotEqual(t, byte(StatusOK), respBytes[0])
}

// TestProcessHMACSecretExtensionInterfaceKeyedMap tests interface-keyed map input.
func TestProcessHMACSecretExtensionInterfaceKeyedMap(t *testing.T) {
	auth := createTestAuthenticator(t)
	rpID := "example.com"
	cred := createAssertionTestCredential(t, auth, rpID, false)

	clientDataHash := generateTestClientDataHash()
	salt1 := make([]byte, 32)
	_, _ = rand.Read(salt1)

	// Build request with interface-keyed extension map.
	request := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: clientDataHash,
		getAssertionParamAllowList: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   cred.CredentialID,
			},
		},
		getAssertionParamExtensions: map[interface{}]interface{}{
			"hmac-secret": map[interface{}]interface{}{
				"salt1": salt1,
			},
		},
	}

	reqBytes, err := cbor.Marshal(request)
	require.NoError(t, err)

	respBytes, err := auth.ProcessCBOR(CmdGetAssertion, reqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), respBytes[0])
}

// =============================================================================
// HID adapter edge case tests (hid_adapter.go)
// =============================================================================

// TestCTAPHIDHandler_CBOREmptyPayload tests CBOR with empty payload.
func TestCTAPHIDHandler_CBOREmptyPayload(t *testing.T) {
	handler, collector := createTestHandler(t)
	defer func() { _ = handler.Close() }()

	// Initialize channel.
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	initPacket := createInitPacket(CIDBroadcast, nonce)
	handler.HandleMessage(initPacket)

	responses := collector.getResponses()
	_, cid := parseInitResponse(t, responses[0])
	collector.clear()

	// Send CBOR with zero-length payload.
	cborPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(cborPacket[0:4], cid)
	cborPacket[4] = CTAPHIDCBOR
	binary.BigEndian.PutUint16(cborPacket[5:7], 0) // Zero length

	handler.HandleMessage(cborPacket)

	responses = collector.getResponses()
	require.Equal(t, 1, len(responses))
	require.Equal(t, byte(CTAPHIDError), responses[0][4])
	require.Equal(t, byte(CTAPHIDErrInvalidLen), responses[0][7])
}

// TestCTAPHIDHandler_CBORBroadcastChannel tests CBOR on broadcast channel.
func TestCTAPHIDHandler_CBORBroadcastChannel(t *testing.T) {
	handler, collector := createTestHandler(t)
	defer func() { _ = handler.Close() }()

	// Send CBOR to broadcast channel (should fail).
	cborPayload := []byte{CmdGetInfo}
	cborPacket := createCBORPacket(CIDBroadcast, cborPayload)
	handler.HandleMessage(cborPacket)

	responses := collector.getResponses()
	require.Equal(t, 1, len(responses))
	require.Equal(t, byte(CTAPHIDError), responses[0][4])
}

// TestCTAPHIDHandler_ContPacketInvalidChannel tests continuation on invalid channel.
func TestCTAPHIDHandler_ContPacketInvalidChannel(t *testing.T) {
	handler, collector := createTestHandler(t)
	defer func() { _ = handler.Close() }()

	// Send continuation packet to non-existent channel.
	contPacket := createContPacket(0x12345678, 0, make([]byte, 50))
	handler.HandleMessage(contPacket)

	responses := collector.getResponses()
	require.Equal(t, 1, len(responses))
	require.Equal(t, byte(CTAPHIDError), responses[0][4])
	require.Equal(t, byte(CTAPHIDErrInvalidChannel), responses[0][7])
}

// TestCTAPHIDHandler_ContPacketTooMuchData tests continuation with excess data.
func TestCTAPHIDHandler_ContPacketTooMuchData(t *testing.T) {
	handler, collector := createTestHandler(t)
	defer func() { _ = handler.Close() }()

	// Initialize channel.
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	initPacket := createInitPacket(CIDBroadcast, nonce)
	handler.HandleMessage(initPacket)

	responses := collector.getResponses()
	_, cid := parseInitResponse(t, responses[0])
	collector.clear()

	// Start a multi-packet message with small declared length.
	pingData := make([]byte, 60) // Just 3 bytes over init payload size
	initPing := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(initPing[0:4], cid)
	initPing[4] = CTAPHIDPing
	binary.BigEndian.PutUint16(initPing[5:7], uint16(len(pingData)))
	copy(initPing[7:], pingData[:InitPacketPayloadSize])
	handler.HandleMessage(initPing)

	// Now send two continuation packets (more than needed).
	contPacket1 := createContPacket(cid, 0, pingData[InitPacketPayloadSize:])
	handler.HandleMessage(contPacket1)

	// First continuation should complete the message and return response.
	responses = collector.getResponses()
	require.GreaterOrEqual(t, len(responses), 1)

	collector.clear()

	// Second continuation should fail because state was cleared.
	contPacket2 := createContPacket(cid, 1, make([]byte, 50))
	handler.HandleMessage(contPacket2)

	responses = collector.getResponses()
	if len(responses) > 0 {
		require.Equal(t, byte(CTAPHIDError), responses[0][4])
	}
}

// TestCTAPHIDHandler_MultiPacketCBOR tests multi-packet CBOR command.
func TestCTAPHIDHandler_MultiPacketCBOR(t *testing.T) {
	handler, collector := createTestHandler(t)
	defer func() { _ = handler.Close() }()

	// Initialize channel.
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	initPacket := createInitPacket(CIDBroadcast, nonce)
	handler.HandleMessage(initPacket)

	responses := collector.getResponses()
	_, cid := parseInitResponse(t, responses[0])
	collector.clear()

	// Create a large CBOR payload (MakeCredential with lots of data).
	// For simplicity, we'll use GetInfo which has a small payload.
	largePayload := make([]byte, 100)
	largePayload[0] = CmdGetInfo

	// Send init packet.
	initCBOR := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(initCBOR[0:4], cid)
	initCBOR[4] = CTAPHIDCBOR
	binary.BigEndian.PutUint16(initCBOR[5:7], uint16(len(largePayload)))
	copy(initCBOR[7:], largePayload[:InitPacketPayloadSize])
	handler.HandleMessage(initCBOR)

	// Send continuation packet.
	contPacket := createContPacket(cid, 0, largePayload[InitPacketPayloadSize:])
	handler.HandleMessage(contPacket)

	// Should get a response.
	responses = collector.getResponses()
	require.GreaterOrEqual(t, len(responses), 1)
	require.Equal(t, byte(CTAPHIDCBOR), responses[0][4])
}

// TestCTAPHIDHandler_ContPacketUnknownCommand tests continuation for unknown command.
func TestCTAPHIDHandler_ContPacketUnknownCommand(t *testing.T) {
	handler, collector := createTestHandler(t)
	defer func() { _ = handler.Close() }()

	// Initialize channel.
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	initPacket := createInitPacket(CIDBroadcast, nonce)
	handler.HandleMessage(initPacket)

	responses := collector.getResponses()
	_, cid := parseInitResponse(t, responses[0])
	collector.clear()

	// Manually set up channel state for an unknown command.
	handler.mu.Lock()
	handler.channels[cid] = &channelState{
		cid:      cid,
		sequence: 0,
		incoming: make([]byte, 50),
		expected: 60,
		command:  0xFE | 0x80, // Unknown command
	}
	handler.mu.Unlock()

	// Send continuation to complete the message.
	contPacket := createContPacket(cid, 0, make([]byte, 10))
	handler.HandleMessage(contPacket)

	responses = collector.getResponses()
	require.Equal(t, 1, len(responses))
	require.Equal(t, byte(CTAPHIDError), responses[0][4])
	require.Equal(t, byte(CTAPHIDErrInvalidCmd), responses[0][7])
}

// TestCTAPHIDHandler_CIDWraparound tests CID allocation wraparound.
func TestCTAPHIDHandler_CIDWraparound(t *testing.T) {
	handler, collector := createTestHandler(t)
	defer func() { _ = handler.Close() }()

	// Set nextCID close to broadcast.
	handler.mu.Lock()
	handler.nextCID = CIDBroadcast - 1
	handler.mu.Unlock()

	// Allocate first channel.
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	initPacket := createInitPacket(CIDBroadcast, nonce)
	handler.HandleMessage(initPacket)

	responses := collector.getResponses()
	_, cid1 := parseInitResponse(t, responses[0])
	require.Equal(t, uint32(CIDBroadcast-1), cid1)
	collector.clear()

	// Allocate second channel (should wrap around).
	handler.HandleMessage(initPacket)
	responses = collector.getResponses()
	_, cid2 := parseInitResponse(t, responses[0])

	// Should have wrapped around to avoid broadcast CID.
	require.NotEqual(t, CIDBroadcast, cid2)
	require.Equal(t, uint32(0x01000000), cid2)
}

// TestCTAPHIDHandler_LargeResponseFragmentation tests response fragmentation using multi-packet ping.
func TestCTAPHIDHandler_LargeResponseFragmentation(t *testing.T) {
	handler, collector := createTestHandler(t)
	defer func() { _ = handler.Close() }()

	// Initialize channel.
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	initPacket := createInitPacket(CIDBroadcast, nonce)
	handler.HandleMessage(initPacket)

	responses := collector.getResponses()
	_, cid := parseInitResponse(t, responses[0])
	collector.clear()

	// Create a large ping payload that will require multiple response packets.
	// 200 bytes: init packet carries 57 bytes, then we need continuation packets.
	largeData := make([]byte, 200)
	for i := range largeData {
		largeData[i] = byte(i)
	}

	// Send init packet with full length declared.
	initPing := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(initPing[0:4], cid)
	initPing[4] = CTAPHIDPing
	binary.BigEndian.PutUint16(initPing[5:7], uint16(len(largeData)))
	copy(initPing[7:], largeData[:InitPacketPayloadSize])
	handler.HandleMessage(initPing)

	// Send continuation packets with remaining data.
	// After init packet: 200 - 57 = 143 bytes remaining.
	// Each cont packet holds 59 bytes.
	// Cont 0: 59 bytes (143 - 59 = 84 remaining)
	// Cont 1: 59 bytes (84 - 59 = 25 remaining)
	// Cont 2: 25 bytes (done)
	remaining := largeData[InitPacketPayloadSize:]
	seq := byte(0)
	for len(remaining) > 0 {
		copyLen := ContPacketPayloadSize
		if len(remaining) < copyLen {
			copyLen = len(remaining)
		}
		contPacket := createContPacket(cid, seq, remaining[:copyLen])
		handler.HandleMessage(contPacket)
		remaining = remaining[copyLen:]
		seq++
	}

	responses = collector.getResponses()

	// Should have multiple response packets.
	// Response: 200 bytes = 57 in init + 143 remaining = 3 cont packets (59 + 59 + 25).
	// Total: 1 init + 3 cont = 4 packets.
	require.GreaterOrEqual(t, len(responses), 3)

	// Verify first packet is init with correct command.
	require.Equal(t, byte(CTAPHIDPing), responses[0][4])
	respLen := int(binary.BigEndian.Uint16(responses[0][5:7]))
	require.Equal(t, 200, respLen)

	// Verify continuation packets have correct sequences.
	for i := 1; i < len(responses); i++ {
		seq := responses[i][4]
		require.Equal(t, byte(i-1), seq)
	}
}

// =============================================================================
// Additional helper for testing decryptPIN edge cases
// =============================================================================

// TestDecryptPINNoNullTerminator tests PIN without null terminator.
func TestDecryptPINNoNullTerminator(t *testing.T) {
	sharedSecret := make([]byte, 32)
	_, _ = rand.Read(sharedSecret)

	// Create PIN that fills entire block without null terminator.
	pin := make([]byte, 64)
	for i := range pin {
		pin[i] = 'A' // No null bytes
	}

	// Encrypt.
	block, err := aes.NewCipher(sharedSecret)
	require.NoError(t, err)

	iv := make([]byte, AESBlockSize)
	mode := cipher.NewCBCEncrypter(block, iv)

	encryptedPIN := make([]byte, len(pin))
	mode.CryptBlocks(encryptedPIN, pin)

	// Create authenticator and test decryption.
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	decrypted, err := auth.decryptPIN(sharedSecret, encryptedPIN)
	require.NoError(t, err)
	require.Equal(t, 64, len(decrypted)) // Should use entire length
}

// TestDecryptPINTooShort tests PIN that's too short.
func TestDecryptPINTooShort(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	sharedSecret := make([]byte, 32)
	shortPIN := make([]byte, 32) // Less than 64 bytes

	_, err := auth.decryptPIN(sharedSecret, shortPIN)
	require.Error(t, err)
}

// TestDecryptBlockWrongSize tests block decryption with wrong size.
func TestDecryptBlockWrongSize(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	sharedSecret := make([]byte, 32)
	wrongSizeBlock := make([]byte, 32) // Should be 16 bytes

	_, err := auth.decryptBlock(sharedSecret, wrongSizeBlock)
	require.Error(t, err)
}

// TestClientPINToUint8InvalidTypes tests clientPINToUint8 with invalid types.
func TestClientPINToUint8InvalidTypes(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
	}{
		{"string", "invalid"},
		{"float32", float32(42)},
		{"float64", float64(42)},
		{"nil", nil},
		{"slice", []byte{1, 2, 3}},
		{"map", map[string]int{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := clientPINToUint8(tt.input)
			require.Error(t, err)
		})
	}
}

// TestClientPINToUint8ValidTypes tests clientPINToUint8 with all valid types.
func TestClientPINToUint8ValidTypes(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		want  uint8
	}{
		{"int", int(42), 42},
		{"int8", int8(42), 42},
		{"int16", int16(42), 42},
		{"int32", int32(42), 42},
		{"int64", int64(42), 42},
		{"uint", uint(42), 42},
		{"uint8", uint8(42), 42},
		{"uint16", uint16(42), 42},
		{"uint32", uint32(42), 42},
		{"uint64", uint64(42), 42},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := clientPINToUint8(tt.input)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// TestDecodeClientPINRequestInvalidCBOR tests decoding invalid CBOR.
func TestDecodeClientPINRequestInvalidCBOR(t *testing.T) {
	_, err := decodeClientPINRequest([]byte{0xFF, 0xFF, 0xFF})
	require.Error(t, err)
}

// TestDecodeClientPINRequestInvalidSubCommandType tests invalid subcommand type.
func TestDecodeClientPINRequestInvalidSubCommandType(t *testing.T) {
	req := map[int]interface{}{
		clientPINKeySubCommand: "not-an-int",
	}

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	_, err = decodeClientPINRequest(reqBytes)
	require.Error(t, err)
}

// TestVerifyPinUvAuthTokenNoProtocol tests token verification without protocol state.
func TestVerifyPinUvAuthTokenNoProtocol(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Don't initialize PIN protocol.
	clientDataHash := make([]byte, 32)
	authParam := make([]byte, 16)

	result := auth.VerifyPinUvAuthToken(clientDataHash, authParam)
	require.False(t, result)
}

// TestGetPinUvAuthTokenNoProtocol tests getting token without protocol state.
func TestGetPinUvAuthTokenNoProtocol(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Don't initialize PIN protocol.
	token := auth.GetPinUvAuthToken()
	require.Nil(t, token)
}
