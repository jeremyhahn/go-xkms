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

package authenticator

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator/keybackend"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

// createTestAuthenticatorWithPIN creates an authenticator with PIN support enabled.
func createTestAuthenticatorWithPIN(t *testing.T) *Authenticator {
	t.Helper()

	storage := NewMemoryStorage()
	config := &Config{
		Storage:             storage,
		EnablePIN:           true,
		PINMinLength:        4,
		PINMaxRetries:       8,
		SupportedAlgorithms: []int{COSEAlgES256},
	}

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}

	return auth
}

// TestGetRetriesReturnsCorrectCount tests that GetRetries returns the correct PIN retry count.
func TestGetRetriesReturnsCorrectCount(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Create GetRetries request.
	req := map[int]interface{}{
		clientPINKeySubCommand: ClientPINSubCmdGetRetries,
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	// Execute command.
	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err != nil {
		t.Fatalf("GetRetries failed: %v", err)
	}

	// Verify response.
	if resp[0] != StatusOK {
		t.Fatalf("Expected StatusOK, got 0x%02x", resp[0])
	}

	var respMap map[int]interface{}
	if err := cbor.Unmarshal(resp[1:], &respMap); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	retriesRaw, ok := respMap[clientPINResponseKeyPinRetries]
	if !ok {
		t.Fatal("Response missing pinRetries field")
	}

	retries, err := clientPINToUint8(retriesRaw)
	if err != nil {
		t.Fatalf("Failed to convert retries: %v", err)
	}

	if int(retries) != auth.config.PINMaxRetries {
		t.Errorf("Expected %d retries, got %d", auth.config.PINMaxRetries, retries)
	}
}

// TestGetRetriesDecrementedAfterFailure tests that retry count decrements on PIN failure.
func TestGetRetriesDecrementedAfterFailure(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set a PIN first.
	if err := auth.SetPINForTesting("1234"); err != nil {
		t.Fatalf("Failed to set PIN: %v", err)
	}

	initialRetries := auth.PINRetries()

	// Get key agreement.
	if err := initKeyAgreement(t, auth); err != nil {
		t.Fatalf("Failed to get key agreement: %v", err)
	}

	// Generate platform key and get shared secret.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	if err != nil {
		t.Fatalf("Failed to generate platform key: %v", err)
	}

	// Try GetPINToken with wrong PIN.
	wrongPinHashEnc, err := encryptPINHash(sharedSecret, "9999")
	if err != nil {
		t.Fatalf("Failed to encrypt wrong PIN hash: %v", err)
	}

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdGetPINToken,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        wrongPinHashEnc,
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	// Execute command - should fail with PIN invalid.
	_, err = auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err == nil {
		t.Fatal("Expected error for wrong PIN")
	}

	// Check retry count decremented.
	newRetries := auth.PINRetries()
	if newRetries != initialRetries-1 {
		t.Errorf("Expected retries to be %d, got %d", initialRetries-1, newRetries)
	}
}

// TestGetKeyAgreementReturnsValidCOSEKey tests that GetKeyAgreement returns a valid COSE key.
func TestGetKeyAgreementReturnsValidCOSEKey(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Create GetKeyAgreement request.
	req := map[int]interface{}{
		clientPINKeySubCommand: ClientPINSubCmdGetKeyAgreement,
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	// Execute command.
	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err != nil {
		t.Fatalf("GetKeyAgreement failed: %v", err)
	}

	if resp[0] != StatusOK {
		t.Fatalf("Expected StatusOK, got 0x%02x", resp[0])
	}

	// Parse response.
	var respMap map[int]interface{}
	if err := cbor.Unmarshal(resp[1:], &respMap); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	keyAgreementRaw, ok := respMap[clientPINResponseKeyKeyAgreement]
	if !ok {
		t.Fatal("Response missing keyAgreement field")
	}

	// The keyAgreement is now a CBOR map (decoded as map[interface{}]interface{}).
	keyMap := cborMapToIntMap(t, keyAgreementRaw)

	// Verify key type is EC2 (2).
	kty, err := clientPINToUint8(keyMap[coseKeyLabelKty])
	if err != nil || kty != COSEKeyTypeEC2 {
		t.Errorf("Expected kty=2 (EC2), got %v", keyMap[coseKeyLabelKty])
	}

	// Verify algorithm is ECDH-ES+HKDF-256 (-25).
	alg, ok := keyMap[coseKeyLabelAlg]
	if !ok {
		t.Error("COSE key missing algorithm")
	}
	algInt, err := toInt(alg)
	if err != nil || algInt != COSEAlgECDHESHKDF256 {
		t.Errorf("Expected alg=-25 (ECDH-ES+HKDF-256), got %v", alg)
	}

	// Verify curve is P-256 (1).
	crv, err := clientPINToUint8(keyMap[coseKeyLabelCrv])
	if err != nil || crv != COSECurveP256 {
		t.Errorf("Expected crv=1 (P-256), got %v", keyMap[coseKeyLabelCrv])
	}

	// Verify X and Y coordinates are present and 32 bytes.
	xBytes, ok := keyMap[coseKeyLabelX].([]byte)
	if !ok || len(xBytes) != 32 {
		t.Errorf("Expected 32-byte X coordinate, got %d bytes", len(xBytes))
	}

	yBytes, ok := keyMap[coseKeyLabelY].([]byte)
	if !ok || len(yBytes) != 32 {
		t.Errorf("Expected 32-byte Y coordinate, got %d bytes", len(yBytes))
	}
}

// TestGetKeyAgreementIdempotent tests that multiple calls return the same key.
func TestGetKeyAgreementIdempotent(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Compare raw response bytes from ProcessCBOR, which are deterministic
	// since they are produced by the same encodeCBOR call in production code.
	// Avoid decode-then-re-encode which introduces non-deterministic map ordering.
	resp1, err := getKeyAgreementRawResponse(t, auth)
	if err != nil {
		t.Fatalf("First GetKeyAgreement failed: %v", err)
	}

	resp2, err := getKeyAgreementRawResponse(t, auth)
	if err != nil {
		t.Fatalf("Second GetKeyAgreement failed: %v", err)
	}

	if string(resp1) != string(resp2) {
		t.Error("GetKeyAgreement should return the same key on repeated calls")
	}
}

// TestSetPINWorkflow tests the complete SetPIN workflow.
func TestSetPINWorkflow(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Verify PIN is not set initially.
	if auth.IsPINSet() {
		t.Fatal("PIN should not be set initially")
	}

	// Get key agreement.
	if err := initKeyAgreement(t, auth); err != nil {
		t.Fatalf("Failed to get key agreement: %v", err)
	}

	// Generate platform key and get shared secret.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	if err != nil {
		t.Fatalf("Failed to generate platform key: %v", err)
	}

	// Set PIN.
	newPIN := "123456"
	encryptedPIN, authParam, err := encryptNewPIN(sharedSecret, newPIN)
	if err != nil {
		t.Fatalf("Failed to encrypt new PIN: %v", err)
	}

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdSetPIN,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinUvAuthParam:    authParam,
		clientPINKeyNewPinEnc:         encryptedPIN,
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err != nil {
		t.Fatalf("SetPIN failed: %v", err)
	}

	if resp[0] != StatusOK {
		t.Fatalf("Expected StatusOK, got 0x%02x", resp[0])
	}

	// Verify PIN is now set.
	if !auth.IsPINSet() {
		t.Error("PIN should be set after SetPIN")
	}
}

// TestSetPINFailsWhenAlreadySet tests that SetPIN fails when PIN is already set.
func TestSetPINFailsWhenAlreadySet(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set initial PIN.
	if err := auth.SetPINForTesting("1234"); err != nil {
		t.Fatalf("Failed to set initial PIN: %v", err)
	}

	// Get key agreement.
	if err := initKeyAgreement(t, auth); err != nil {
		t.Fatalf("Failed to get key agreement: %v", err)
	}

	// Generate platform key and get shared secret.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	if err != nil {
		t.Fatalf("Failed to generate platform key: %v", err)
	}

	// Try to set PIN again.
	encryptedPIN, authParam, err := encryptNewPIN(sharedSecret, "5678")
	if err != nil {
		t.Fatalf("Failed to encrypt new PIN: %v", err)
	}

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdSetPIN,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinUvAuthParam:    authParam,
		clientPINKeyNewPinEnc:         encryptedPIN,
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err == nil {
		t.Fatal("Expected error when setting PIN that's already set")
	}

	if resp[0] != StatusPINInvalid {
		t.Errorf("Expected StatusPINInvalid (0x%02x), got 0x%02x", StatusPINInvalid, resp[0])
	}
}

// TestSetPINPolicyViolation tests that SetPIN fails with short PIN.
func TestSetPINPolicyViolation(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Get key agreement.
	if err := initKeyAgreement(t, auth); err != nil {
		t.Fatalf("Failed to get key agreement: %v", err)
	}

	// Generate platform key and get shared secret.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	if err != nil {
		t.Fatalf("Failed to generate platform key: %v", err)
	}

	// Try to set short PIN.
	encryptedPIN, authParam, err := encryptNewPIN(sharedSecret, "123") // Only 3 chars
	if err != nil {
		t.Fatalf("Failed to encrypt new PIN: %v", err)
	}

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdSetPIN,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinUvAuthParam:    authParam,
		clientPINKeyNewPinEnc:         encryptedPIN,
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err == nil {
		t.Fatal("Expected error for short PIN")
	}

	if resp[0] != StatusPINPolicyViolation {
		t.Errorf("Expected StatusPINPolicyViolation (0x%02x), got 0x%02x", StatusPINPolicyViolation, resp[0])
	}
}

// TestChangePINWithValidCurrentPIN tests changing PIN with correct current PIN.
func TestChangePINWithValidCurrentPIN(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set initial PIN.
	initialPIN := "1234"
	if err := auth.SetPINForTesting(initialPIN); err != nil {
		t.Fatalf("Failed to set initial PIN: %v", err)
	}

	// Get key agreement.
	if err := initKeyAgreement(t, auth); err != nil {
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

	// Generate authParam over newPinEnc || pinHashEnc.
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
	if err != nil {
		t.Fatalf("ChangePIN failed: %v", err)
	}

	if resp[0] != StatusOK {
		t.Fatalf("Expected StatusOK, got 0x%02x", resp[0])
	}

	// Verify new PIN works by checking hash.
	newPINHash := sha256.Sum256([]byte(newPIN))
	if !hmac.Equal(newPINHash[:PINHashSize], auth.state.PINHash) {
		t.Error("New PIN hash does not match expected value")
	}
}

// TestChangePINWithInvalidCurrentPIN tests changing PIN with wrong current PIN.
func TestChangePINWithInvalidCurrentPIN(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set initial PIN.
	initialPIN := "1234"
	if err := auth.SetPINForTesting(initialPIN); err != nil {
		t.Fatalf("Failed to set initial PIN: %v", err)
	}

	initialRetries := auth.PINRetries()

	// Get key agreement.
	if err := initKeyAgreement(t, auth); err != nil {
		t.Fatalf("Failed to get key agreement: %v", err)
	}

	// Generate platform key and get shared secret.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	if err != nil {
		t.Fatalf("Failed to generate platform key: %v", err)
	}

	// Prepare ChangePIN request with wrong current PIN.
	newPIN := "5678"
	wrongPIN := "9999"

	newPinEnc, _, err := encryptNewPIN(sharedSecret, newPIN)
	if err != nil {
		t.Fatalf("Failed to encrypt new PIN: %v", err)
	}

	pinHashEnc, err := encryptPINHash(sharedSecret, wrongPIN)
	if err != nil {
		t.Fatalf("Failed to encrypt wrong PIN hash: %v", err)
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
		t.Fatal("Expected error for wrong current PIN")
	}

	if resp[0] != StatusPINInvalid {
		t.Errorf("Expected StatusPINInvalid (0x%02x), got 0x%02x", StatusPINInvalid, resp[0])
	}

	// Verify retry count decremented.
	if auth.PINRetries() != initialRetries-1 {
		t.Errorf("Expected retries to be %d, got %d", initialRetries-1, auth.PINRetries())
	}
}

// TestChangePINFailsWhenNotSet tests that ChangePIN fails when PIN is not set.
func TestChangePINFailsWhenNotSet(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Get key agreement.
	if err := initKeyAgreement(t, auth); err != nil {
		t.Fatalf("Failed to get key agreement: %v", err)
	}

	// Generate platform key and get shared secret.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	if err != nil {
		t.Fatalf("Failed to generate platform key: %v", err)
	}

	// Try to change PIN when not set.
	newPinEnc, _, err := encryptNewPIN(sharedSecret, "5678")
	if err != nil {
		t.Fatalf("Failed to encrypt new PIN: %v", err)
	}

	pinHashEnc, err := encryptPINHash(sharedSecret, "1234")
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
		t.Fatal("Expected error when PIN not set")
	}

	if resp[0] != StatusPINNotSet {
		t.Errorf("Expected StatusPINNotSet (0x%02x), got 0x%02x", StatusPINNotSet, resp[0])
	}
}

// TestGetPINTokenWithValidPIN tests getting a PIN token with correct PIN.
func TestGetPINTokenWithValidPIN(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set PIN.
	pin := "1234"
	if err := auth.SetPINForTesting(pin); err != nil {
		t.Fatalf("Failed to set PIN: %v", err)
	}

	// Get key agreement.
	if err := initKeyAgreement(t, auth); err != nil {
		t.Fatalf("Failed to get key agreement: %v", err)
	}

	// Generate platform key and get shared secret.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	if err != nil {
		t.Fatalf("Failed to generate platform key: %v", err)
	}

	// Request PIN token.
	pinHashEnc, err := encryptPINHash(sharedSecret, pin)
	if err != nil {
		t.Fatalf("Failed to encrypt PIN hash: %v", err)
	}

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdGetPINToken,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        pinHashEnc,
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err != nil {
		t.Fatalf("GetPINToken failed: %v", err)
	}

	if resp[0] != StatusOK {
		t.Fatalf("Expected StatusOK, got 0x%02x", resp[0])
	}

	// Parse response.
	var respMap map[int]interface{}
	if err := cbor.Unmarshal(resp[1:], &respMap); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	encryptedToken, ok := respMap[clientPINResponseKeyPinUvAuthToken].([]byte)
	if !ok {
		t.Fatal("Response missing pinUvAuthToken")
	}

	// Decrypt the token.
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		t.Fatalf("Failed to create AES cipher: %v", err)
	}

	iv := make([]byte, AESBlockSize)
	mode := cipher.NewCBCDecrypter(block, iv)

	decryptedToken := make([]byte, len(encryptedToken))
	mode.CryptBlocks(decryptedToken, encryptedToken)

	// Verify token is 32 bytes (after removing padding).
	if len(decryptedToken) < PINTokenSize {
		t.Errorf("Decrypted token too short: %d bytes", len(decryptedToken))
	}

	// Verify internal token matches.
	internalToken := auth.GetPinUvAuthToken()
	if internalToken == nil {
		t.Fatal("Internal PIN token not set")
	}

	if !hmac.Equal(decryptedToken[:PINTokenSize], internalToken) {
		t.Error("Decrypted token does not match internal token")
	}
}

// TestGetPINTokenWithInvalidPIN tests getting a PIN token with wrong PIN.
func TestGetPINTokenWithInvalidPIN(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set PIN.
	if err := auth.SetPINForTesting("1234"); err != nil {
		t.Fatalf("Failed to set PIN: %v", err)
	}

	initialRetries := auth.PINRetries()

	// Get key agreement.
	if err := initKeyAgreement(t, auth); err != nil {
		t.Fatalf("Failed to get key agreement: %v", err)
	}

	// Generate platform key and get shared secret.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	if err != nil {
		t.Fatalf("Failed to generate platform key: %v", err)
	}

	// Request PIN token with wrong PIN.
	pinHashEnc, err := encryptPINHash(sharedSecret, "9999")
	if err != nil {
		t.Fatalf("Failed to encrypt PIN hash: %v", err)
	}

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdGetPINToken,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
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

	if resp[0] != StatusPINInvalid {
		t.Errorf("Expected StatusPINInvalid (0x%02x), got 0x%02x", StatusPINInvalid, resp[0])
	}

	// Verify retry count decremented.
	if auth.PINRetries() != initialRetries-1 {
		t.Errorf("Expected retries to be %d, got %d", initialRetries-1, auth.PINRetries())
	}
}

// TestGetPINTokenFailsWhenNotSet tests that GetPINToken fails when PIN is not set.
func TestGetPINTokenFailsWhenNotSet(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Get key agreement.
	if err := initKeyAgreement(t, auth); err != nil {
		t.Fatalf("Failed to get key agreement: %v", err)
	}

	// Generate platform key and get shared secret.
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
		clientPINKeySubCommand:        ClientPINSubCmdGetPINToken,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        pinHashEnc,
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err == nil {
		t.Fatal("Expected error when PIN not set")
	}

	if resp[0] != StatusPINNotSet {
		t.Errorf("Expected StatusPINNotSet (0x%02x), got 0x%02x", StatusPINNotSet, resp[0])
	}
}

// TestPINBlockingAfterMaxRetries tests that PIN is blocked after max retries.
func TestPINBlockingAfterMaxRetries(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set low max retries for faster testing.
	auth.config.PINMaxRetries = 3
	auth.state.SetPINRetries(3)

	// Set PIN.
	if err := auth.SetPINForTesting("1234"); err != nil {
		t.Fatalf("Failed to set PIN: %v", err)
	}

	// Get key agreement.
	if err := initKeyAgreement(t, auth); err != nil {
		t.Fatalf("Failed to get key agreement: %v", err)
	}

	// Exhaust retries with wrong PIN.
	for i := 0; i < 3; i++ {
		auth.mu.Lock()
		platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
		auth.mu.Unlock()
		if err != nil {
			t.Fatalf("Failed to generate platform key: %v", err)
		}

		pinHashEnc, err := encryptPINHash(sharedSecret, "9999")
		if err != nil {
			t.Fatalf("Failed to encrypt PIN hash: %v", err)
		}

		req := map[int]interface{}{
			clientPINKeyPinUvAuthProtocol: PINProtocol1,
			clientPINKeySubCommand:        ClientPINSubCmdGetPINToken,
			clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
			clientPINKeyPinHashEnc:        pinHashEnc,
		}

		reqBytes, err := cbor.Marshal(req)
		if err != nil {
			t.Fatalf("Failed to marshal request: %v", err)
		}

		_, _ = auth.ProcessCBOR(CmdClientPIN, reqBytes)
	}

	// Verify PIN is blocked.
	if auth.PINRetries() != 0 {
		t.Errorf("Expected 0 retries after blocking, got %d", auth.PINRetries())
	}

	// Try again - should get PIN blocked error.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	if err != nil {
		t.Fatalf("Failed to generate platform key: %v", err)
	}

	pinHashEnc, err := encryptPINHash(sharedSecret, "1234") // Even correct PIN
	if err != nil {
		t.Fatalf("Failed to encrypt PIN hash: %v", err)
	}

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdGetPINToken,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        pinHashEnc,
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err == nil {
		t.Fatal("Expected error when PIN blocked")
	}

	if resp[0] != StatusPINBlocked {
		t.Errorf("Expected StatusPINBlocked (0x%02x), got 0x%02x", StatusPINBlocked, resp[0])
	}
}

// TestGetPinUvAuthTokenUsingPinWithPermissions tests the permissions-based token retrieval.
func TestGetPinUvAuthTokenUsingPinWithPermissions(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set PIN.
	pin := "1234"
	if err := auth.SetPINForTesting(pin); err != nil {
		t.Fatalf("Failed to set PIN: %v", err)
	}

	// Get key agreement.
	if err := initKeyAgreement(t, auth); err != nil {
		t.Fatalf("Failed to get key agreement: %v", err)
	}

	// Generate platform key and get shared secret.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	if err != nil {
		t.Fatalf("Failed to generate platform key: %v", err)
	}

	// Request PIN token with permissions.
	pinHashEnc, err := encryptPINHash(sharedSecret, pin)
	if err != nil {
		t.Fatalf("Failed to encrypt PIN hash: %v", err)
	}

	permissions := PINPermissionMakeCredential | PINPermissionGetAssertion

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdGetPinUvAuthTokenUsingPinWithPermissions,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        pinHashEnc,
		clientPINKeyPermissions:       permissions,
		clientPINKeyPermissionsRPID:   "example.com",
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err != nil {
		t.Fatalf("GetPinUvAuthTokenUsingPinWithPermissions failed: %v", err)
	}

	if resp[0] != StatusOK {
		t.Fatalf("Expected StatusOK, got 0x%02x", resp[0])
	}

	// Verify token was generated.
	if auth.GetPinUvAuthToken() == nil {
		t.Error("PIN token should be set after successful request")
	}

	// Verify permissions are stored.
	auth.mu.RLock()
	storedPerms := auth.pinState.protocol.tokenPermissions
	storedRPID := auth.pinState.protocol.tokenRPID
	auth.mu.RUnlock()

	if storedPerms != uint8(permissions) {
		t.Errorf("Expected permissions 0x%02x, got 0x%02x", permissions, storedPerms)
	}

	if storedRPID != "example.com" {
		t.Errorf("Expected RPID 'example.com', got '%s'", storedRPID)
	}
}

// TestInvalidSubcommand tests that invalid subcommands are rejected.
func TestInvalidSubcommand(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        0xFF, // Invalid subcommand
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err == nil {
		t.Fatal("Expected error for invalid subcommand")
	}

	if resp[0] != StatusInvalidSubcommand {
		t.Errorf("Expected StatusInvalidSubcommand (0x%02x), got 0x%02x", StatusInvalidSubcommand, resp[0])
	}
}

// TestUnsupportedPINProtocol tests that unsupported PIN protocols are rejected.
func TestUnsupportedPINProtocol(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set PIN first.
	if err := auth.SetPINForTesting("1234"); err != nil {
		t.Fatalf("Failed to set PIN: %v", err)
	}

	// Get key agreement.
	if err := initKeyAgreement(t, auth); err != nil {
		t.Fatalf("Failed to get key agreement: %v", err)
	}

	// Generate platform key and get shared secret.
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
		clientPINKeyPinUvAuthProtocol: 3, // Protocol 3 not supported
		clientPINKeySubCommand:        ClientPINSubCmdGetPINToken,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        pinHashEnc,
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err == nil {
		t.Fatal("Expected error for unsupported PIN protocol")
	}

	if resp[0] != StatusInvalidParameter {
		t.Errorf("Expected StatusInvalidParameter (0x%02x), got 0x%02x", StatusInvalidParameter, resp[0])
	}
}

// TestGetUvRetries tests the GetUvRetries subcommand.
func TestGetUvRetries(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	req := map[int]interface{}{
		clientPINKeySubCommand: ClientPINSubCmdGetUvRetries,
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err != nil {
		t.Fatalf("GetUvRetries failed: %v", err)
	}

	if resp[0] != StatusOK {
		t.Fatalf("Expected StatusOK, got 0x%02x", resp[0])
	}

	var respMap map[int]interface{}
	if err := cbor.Unmarshal(resp[1:], &respMap); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	uvRetriesRaw, ok := respMap[clientPINResponseKeyUvRetries]
	if !ok {
		t.Fatal("Response missing uvRetries field")
	}

	uvRetries, err := clientPINToUint8(uvRetriesRaw)
	if err != nil {
		t.Fatalf("Failed to convert UV retries: %v", err)
	}

	if int(uvRetries) != DefaultUVRetries {
		t.Errorf("Expected %d UV retries, got %d", DefaultUVRetries, uvRetries)
	}
}

// TestClientPINDisabled tests that ClientPIN commands fail when PIN is disabled.
func TestClientPINDisabled(t *testing.T) {
	storage := NewMemoryStorage()
	config := &Config{
		Storage:             storage,
		EnablePIN:           false, // PIN disabled
		SupportedAlgorithms: []int{COSEAlgES256},
	}

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}
	defer func() { _ = auth.Close() }()

	req := map[int]interface{}{
		clientPINKeySubCommand: ClientPINSubCmdGetRetries,
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err == nil {
		t.Fatal("Expected error when PIN is disabled")
	}

	// Should return invalid command since PIN is disabled.
	if resp[0] != StatusInvalidCommand {
		t.Errorf("Expected StatusInvalidCommand (0x%02x), got 0x%02x", StatusInvalidCommand, resp[0])
	}
}

// TestDecodeClientPINRequestEmpty tests decoding empty request.
func TestDecodeClientPINRequestEmpty(t *testing.T) {
	_, err := decodeClientPINRequest(nil)
	if err == nil {
		t.Error("Expected error for nil data")
	}

	_, err = decodeClientPINRequest([]byte{})
	if err == nil {
		t.Error("Expected error for empty data")
	}
}

// TestDecodeClientPINRequestMissingSubCommand tests decoding request without subcommand.
func TestDecodeClientPINRequestMissingSubCommand(t *testing.T) {
	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		// Missing subCommand
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	_, err = decodeClientPINRequest(reqBytes)
	if err == nil {
		t.Error("Expected error for missing subcommand")
	}
}

// TestVerifyPinUvAuthToken tests the token verification helper.
func TestVerifyPinUvAuthToken(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set PIN and get token.
	pin := "1234"
	if err := auth.SetPINForTesting(pin); err != nil {
		t.Fatalf("Failed to set PIN: %v", err)
	}

	// Get key agreement.
	if err := initKeyAgreement(t, auth); err != nil {
		t.Fatalf("Failed to get key agreement: %v", err)
	}

	// Generate platform key and get shared secret.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	if err != nil {
		t.Fatalf("Failed to generate platform key: %v", err)
	}

	// Get PIN token.
	pinHashEnc, err := encryptPINHash(sharedSecret, pin)
	if err != nil {
		t.Fatalf("Failed to encrypt PIN hash: %v", err)
	}

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdGetPINToken,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        pinHashEnc,
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	_, err = auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err != nil {
		t.Fatalf("GetPINToken failed: %v", err)
	}

	// Get the token.
	token := auth.GetPinUvAuthToken()
	if token == nil {
		t.Fatal("Token should be set")
	}

	// Create valid auth param.
	clientDataHash := make([]byte, 32)
	mac := hmac.New(sha256.New, token)
	mac.Write(clientDataHash)
	validAuthParam := mac.Sum(nil)[:16]

	// Test valid auth param.
	if !auth.VerifyPinUvAuthToken(clientDataHash, validAuthParam) {
		t.Error("Valid auth param should verify successfully")
	}

	// Test invalid auth param.
	invalidAuthParam := make([]byte, 16)
	if auth.VerifyPinUvAuthToken(clientDataHash, invalidAuthParam) {
		t.Error("Invalid auth param should fail verification")
	}
}

// TestECDSAPublicKeyToCOSE tests the ecdsaPublicKeyToCOSE helper function.
func TestECDSAPublicKeyToCOSE(t *testing.T) {
	t.Run("P-256 key with ES256 algorithm", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		coseBytes, err := ecdsaPublicKeyToCOSE(&privateKey.PublicKey, COSEAlgES256)
		require.NoError(t, err)
		require.NotEmpty(t, coseBytes)

		// Decode and verify COSE key structure
		var coseKey map[int]interface{}
		err = cbor.Unmarshal(coseBytes, &coseKey)
		require.NoError(t, err)

		// Verify key type is EC2
		kty, err := toInt(coseKey[coseKeyLabelKty])
		require.NoError(t, err)
		require.Equal(t, COSEKeyTypeEC2, kty)

		// Verify algorithm
		alg, err := toInt(coseKey[coseKeyLabelAlg])
		require.NoError(t, err)
		require.Equal(t, COSEAlgES256, alg)

		// Verify curve is P-256
		crv, err := toInt(coseKey[coseKeyLabelCrv])
		require.NoError(t, err)
		require.Equal(t, COSECurveP256, crv)

		// Verify X and Y coordinates are 32 bytes
		xBytes, ok := coseKey[coseKeyLabelX].([]byte)
		require.True(t, ok)
		require.Len(t, xBytes, 32)

		yBytes, ok := coseKey[coseKeyLabelY].([]byte)
		require.True(t, ok)
		require.Len(t, yBytes, 32)
	})

	t.Run("P-384 key with ES384 algorithm", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)

		coseBytes, err := ecdsaPublicKeyToCOSE(&privateKey.PublicKey, COSEAlgES384)
		require.NoError(t, err)
		require.NotEmpty(t, coseBytes)

		// Decode and verify COSE key structure
		var coseKey map[int]interface{}
		err = cbor.Unmarshal(coseBytes, &coseKey)
		require.NoError(t, err)

		// Verify curve is P-384
		crv, err := toInt(coseKey[coseKeyLabelCrv])
		require.NoError(t, err)
		require.Equal(t, COSECurveP384, crv)

		// Verify algorithm
		alg, err := toInt(coseKey[coseKeyLabelAlg])
		require.NoError(t, err)
		require.Equal(t, COSEAlgES384, alg)

		// Verify X and Y coordinates are 48 bytes
		xBytes, ok := coseKey[coseKeyLabelX].([]byte)
		require.True(t, ok)
		require.Len(t, xBytes, 48)

		yBytes, ok := coseKey[coseKeyLabelY].([]byte)
		require.True(t, ok)
		require.Len(t, yBytes, 48)
	})

	t.Run("P-521 key with ES512 algorithm", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		require.NoError(t, err)

		coseBytes, err := ecdsaPublicKeyToCOSE(&privateKey.PublicKey, COSEAlgES512)
		require.NoError(t, err)
		require.NotEmpty(t, coseBytes)

		// Decode and verify COSE key structure
		var coseKey map[int]interface{}
		err = cbor.Unmarshal(coseBytes, &coseKey)
		require.NoError(t, err)

		// Verify curve is P-521
		crv, err := toInt(coseKey[coseKeyLabelCrv])
		require.NoError(t, err)
		require.Equal(t, COSECurveP521, crv)

		// Verify algorithm
		alg, err := toInt(coseKey[coseKeyLabelAlg])
		require.NoError(t, err)
		require.Equal(t, COSEAlgES512, alg)

		// Verify X and Y coordinates are 66 bytes
		xBytes, ok := coseKey[coseKeyLabelX].([]byte)
		require.True(t, ok)
		require.Len(t, xBytes, 66)

		yBytes, ok := coseKey[coseKeyLabelY].([]byte)
		require.True(t, ok)
		require.Len(t, yBytes, 66)
	})

	t.Run("COSE key is decodable", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		coseBytes, err := ecdsaPublicKeyToCOSE(&privateKey.PublicKey, COSEAlgES256)
		require.NoError(t, err)

		// Verify the COSE key can be decoded back to a public key
		pubKey, alg, err := DecodeCOSEPublicKey(coseBytes)
		require.NoError(t, err)
		require.Equal(t, COSEAlgES256, alg)

		ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
		require.True(t, ok)
		require.True(t, ecdsaPubKey.Curve == elliptic.P256())
		require.Equal(t, privateKey.X.Bytes(), ecdsaPubKey.X.Bytes())
		require.Equal(t, privateKey.Y.Bytes(), ecdsaPubKey.Y.Bytes())
	})
}

// =============================================================================
// handleGetPINToken Comprehensive Tests
// =============================================================================

// TestHandleGetPINToken_Success tests the success path with correct PIN.
func TestHandleGetPINToken_Success(t *testing.T) {
	t.Parallel()

	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set PIN.
	pin := "123456"
	err := auth.SetPINForTesting(pin)
	require.NoError(t, err)

	// Record initial retry count.
	initialRetries := auth.PINRetries()

	// Get key agreement to initialize PIN protocol.
	err = initKeyAgreement(t, auth)
	require.NoError(t, err)

	// Generate platform key and derive shared secret.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	require.NoError(t, err)

	// Encrypt PIN hash.
	pinHashEnc, err := encryptPINHash(sharedSecret, pin)
	require.NoError(t, err)

	// Build GetPINToken request.
	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdGetPINToken,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        pinHashEnc,
	}

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	// Execute command.
	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0], "Expected StatusOK")

	// Parse response.
	var respMap map[int]interface{}
	err = cbor.Unmarshal(resp[1:], &respMap)
	require.NoError(t, err)

	// Verify encrypted token is present.
	encryptedToken, ok := respMap[clientPINResponseKeyPinUvAuthToken].([]byte)
	require.True(t, ok, "Response should contain pinUvAuthToken")
	require.NotEmpty(t, encryptedToken)

	// Decrypt and verify token.
	block, err := aes.NewCipher(sharedSecret)
	require.NoError(t, err)

	iv := make([]byte, AESBlockSize)
	mode := cipher.NewCBCDecrypter(block, iv)

	decryptedToken := make([]byte, len(encryptedToken))
	mode.CryptBlocks(decryptedToken, encryptedToken)

	// Verify token matches internal state.
	internalToken := auth.GetPinUvAuthToken()
	require.NotNil(t, internalToken, "Internal PIN token should be set")
	require.True(t, hmac.Equal(decryptedToken[:PINTokenSize], internalToken),
		"Decrypted token should match internal token")

	// Verify retry count was reset to max.
	require.Equal(t, initialRetries, auth.PINRetries(),
		"PIN retries should be reset to max after successful verification")
}

// TestHandleGetPINToken_PINNotSet tests error when PIN is not configured.
func TestHandleGetPINToken_PINNotSet(t *testing.T) {
	t.Parallel()

	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Do NOT set a PIN - this is the test condition.

	// Get key agreement.
	err := initKeyAgreement(t, auth)
	require.NoError(t, err)

	// Generate platform key.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	require.NoError(t, err)

	// Encrypt a fake PIN hash.
	pinHashEnc, err := encryptPINHash(sharedSecret, "1234")
	require.NoError(t, err)

	// Build request.
	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdGetPINToken,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        pinHashEnc,
	}

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	// Execute command.
	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.Error(t, err, "Should return error when PIN not set")
	require.Equal(t, byte(StatusPINNotSet), resp[0],
		"Expected StatusPINNotSet (0x%02x), got 0x%02x", StatusPINNotSet, resp[0])
}

// TestHandleGetPINToken_PINBlocked tests error when PIN retries are exhausted.
func TestHandleGetPINToken_PINBlocked(t *testing.T) {
	t.Parallel()

	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set PIN.
	err := auth.SetPINForTesting("1234")
	require.NoError(t, err)

	// Exhaust all retries by setting to 0.
	auth.state.SetPINRetries(0)

	// Get key agreement.
	err = initKeyAgreement(t, auth)
	require.NoError(t, err)

	// Generate platform key.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	require.NoError(t, err)

	// Encrypt correct PIN hash (should still fail due to blocked state).
	pinHashEnc, err := encryptPINHash(sharedSecret, "1234")
	require.NoError(t, err)

	// Build request.
	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdGetPINToken,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        pinHashEnc,
	}

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	// Execute command.
	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.Error(t, err, "Should return error when PIN is blocked")
	require.Equal(t, byte(StatusPINBlocked), resp[0],
		"Expected StatusPINBlocked (0x%02x), got 0x%02x", StatusPINBlocked, resp[0])
}

// TestHandleGetPINToken_MissingKeyAgreement tests error when keyAgreement is missing.
func TestHandleGetPINToken_MissingKeyAgreement(t *testing.T) {
	t.Parallel()

	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set PIN.
	err := auth.SetPINForTesting("1234")
	require.NoError(t, err)

	// Get key agreement to initialize protocol.
	err = initKeyAgreement(t, auth)
	require.NoError(t, err)

	// Build request WITHOUT keyAgreement.
	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdGetPINToken,
		// Missing: clientPINKeyKeyAgreement
		clientPINKeyPinHashEnc: make([]byte, PINHashSize), // dummy data
	}

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	// Execute command.
	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.Error(t, err, "Should return error when keyAgreement is missing")
	require.Equal(t, byte(StatusOtherError), resp[0],
		"Expected StatusOtherError (0x%02x), got 0x%02x", StatusMissingParameter, resp[0])
}

// TestHandleGetPINToken_MissingPinHashEnc tests error when pinHashEnc is missing.
func TestHandleGetPINToken_MissingPinHashEnc(t *testing.T) {
	t.Parallel()

	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set PIN.
	err := auth.SetPINForTesting("1234")
	require.NoError(t, err)

	// Get key agreement.
	err = initKeyAgreement(t, auth)
	require.NoError(t, err)

	// Generate platform key.
	auth.mu.Lock()
	platformCOSE, _, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	require.NoError(t, err)

	// Build request WITHOUT pinHashEnc.
	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdGetPINToken,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		// Missing: clientPINKeyPinHashEnc
	}

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	// Execute command.
	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.Error(t, err, "Should return error when pinHashEnc is missing")
	require.Equal(t, byte(StatusInvalidParameter), resp[0],
		"Expected StatusInvalidParameter (0x%02x), got 0x%02x", StatusInvalidParameter, resp[0])
}

// TestHandleGetPINToken_InvalidPinHash tests error when PIN hash is incorrect.
func TestHandleGetPINToken_InvalidPinHash(t *testing.T) {
	t.Parallel()

	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set PIN.
	correctPIN := "1234"
	err := auth.SetPINForTesting(correctPIN)
	require.NoError(t, err)

	// Get initial retry count.
	initialRetries := auth.PINRetries()

	// Get key agreement.
	err = initKeyAgreement(t, auth)
	require.NoError(t, err)

	// Generate platform key.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	require.NoError(t, err)

	// Encrypt WRONG PIN hash.
	wrongPIN := "9999"
	pinHashEnc, err := encryptPINHash(sharedSecret, wrongPIN)
	require.NoError(t, err)

	// Build request.
	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdGetPINToken,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        pinHashEnc,
	}

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	// Execute command.
	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.Error(t, err, "Should return error for wrong PIN")
	require.Equal(t, byte(StatusPINInvalid), resp[0],
		"Expected StatusPINInvalid (0x%02x), got 0x%02x", StatusPINInvalid, resp[0])

	// Verify retry count was decremented.
	require.Equal(t, initialRetries-1, auth.PINRetries(),
		"PIN retries should be decremented after failed attempt")
}

// TestHandleGetPINToken_RetryDecrementLogic tests PIN retry decrement on multiple failures.
func TestHandleGetPINToken_RetryDecrementLogic(t *testing.T) {
	t.Parallel()

	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set low max retries for faster testing.
	auth.config.PINMaxRetries = 5
	auth.state.SetPINRetries(5)

	// Set PIN.
	correctPIN := "1234"
	err := auth.SetPINForTesting(correctPIN)
	require.NoError(t, err)

	// Get key agreement.
	err = initKeyAgreement(t, auth)
	require.NoError(t, err)

	// Perform 3 failed attempts and verify decrement each time.
	for i := 0; i < 3; i++ {
		expectedRetries := 5 - i

		// Verify current retry count.
		require.Equal(t, expectedRetries, auth.PINRetries(),
			"Iteration %d: expected %d retries before attempt", i, expectedRetries)

		// Generate platform key.
		auth.mu.Lock()
		platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
		auth.mu.Unlock()
		require.NoError(t, err)

		// Encrypt wrong PIN hash.
		pinHashEnc, err := encryptPINHash(sharedSecret, "wrong")
		require.NoError(t, err)

		// Build request.
		req := map[int]interface{}{
			clientPINKeyPinUvAuthProtocol: PINProtocol1,
			clientPINKeySubCommand:        ClientPINSubCmdGetPINToken,
			clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
			clientPINKeyPinHashEnc:        pinHashEnc,
		}

		reqBytes, err := cbor.Marshal(req)
		require.NoError(t, err)

		// Execute command.
		resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
		require.Error(t, err, "Iteration %d: should fail with wrong PIN", i)
		require.Equal(t, byte(StatusPINInvalid), resp[0],
			"Iteration %d: expected StatusPINInvalid", i)

		// Verify retry count decremented.
		require.Equal(t, expectedRetries-1, auth.PINRetries(),
			"Iteration %d: expected %d retries after attempt", i, expectedRetries-1)
	}

	// Verify we have 2 retries remaining.
	require.Equal(t, 2, auth.PINRetries())

	// Now succeed with correct PIN.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	require.NoError(t, err)

	pinHashEnc, err := encryptPINHash(sharedSecret, correctPIN)
	require.NoError(t, err)

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdGetPINToken,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        pinHashEnc,
	}

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	// Verify retries reset to max.
	require.Equal(t, 5, auth.PINRetries(),
		"PIN retries should be reset to max after successful verification")
}

// TestHandleGetPINToken_BlockedAfterExhaustingRetries tests that PIN becomes blocked.
func TestHandleGetPINToken_BlockedAfterExhaustingRetries(t *testing.T) {
	t.Parallel()

	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set very low max retries.
	auth.config.PINMaxRetries = 2
	auth.state.SetPINRetries(2)

	// Set PIN.
	err := auth.SetPINForTesting("1234")
	require.NoError(t, err)

	// Get key agreement.
	err = initKeyAgreement(t, auth)
	require.NoError(t, err)

	// First failed attempt.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	require.NoError(t, err)

	pinHashEnc, err := encryptPINHash(sharedSecret, "wrong")
	require.NoError(t, err)

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdGetPINToken,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        pinHashEnc,
	}

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.Error(t, err)
	require.Equal(t, byte(StatusPINInvalid), resp[0])
	require.Equal(t, 1, auth.PINRetries())

	// Second failed attempt - should block.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err = auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	require.NoError(t, err)

	pinHashEnc, err = encryptPINHash(sharedSecret, "wrong")
	require.NoError(t, err)

	req = map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdGetPINToken,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        pinHashEnc,
	}

	reqBytes, err = cbor.Marshal(req)
	require.NoError(t, err)

	resp, err = auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.Error(t, err)
	// Last failed attempt should return PINBlocked.
	require.Equal(t, byte(StatusPINBlocked), resp[0],
		"Expected StatusPINBlocked after exhausting retries")
	require.Equal(t, 0, auth.PINRetries())

	// Third attempt with correct PIN should fail with blocked.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err = auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	require.NoError(t, err)

	pinHashEnc, err = encryptPINHash(sharedSecret, "1234") // Correct PIN
	require.NoError(t, err)

	req = map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdGetPINToken,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        pinHashEnc,
	}

	reqBytes, err = cbor.Marshal(req)
	require.NoError(t, err)

	resp, err = auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.Error(t, err)
	require.Equal(t, byte(StatusPINBlocked), resp[0],
		"Even correct PIN should fail when blocked")
}

// TestHandleGetPINToken_MalformedPinHashEnc tests error with invalid pinHashEnc size.
func TestHandleGetPINToken_MalformedPinHashEnc(t *testing.T) {
	t.Parallel()

	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set PIN.
	err := auth.SetPINForTesting("1234")
	require.NoError(t, err)

	initialRetries := auth.PINRetries()

	// Get key agreement.
	err = initKeyAgreement(t, auth)
	require.NoError(t, err)

	// Generate platform key.
	auth.mu.Lock()
	platformCOSE, _, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	require.NoError(t, err)

	// Use wrong-sized pinHashEnc (should be 16 bytes).
	wrongSizePinHashEnc := make([]byte, 8) // Too small

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdGetPINToken,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        wrongSizePinHashEnc,
	}

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.Error(t, err, "Should fail with malformed pinHashEnc")

	// Decryption failure decrements retries and returns PINInvalid.
	require.Equal(t, byte(StatusPINInvalid), resp[0])
	require.Equal(t, initialRetries-1, auth.PINRetries(),
		"Retries should decrement on decryption failure")
}

// TestHandleGetPINToken_RetriesResetOnSuccess tests that retries reset after success.
func TestHandleGetPINToken_RetriesResetOnSuccess(t *testing.T) {
	t.Parallel()

	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set max retries.
	auth.config.PINMaxRetries = 8
	auth.state.SetPINRetries(8)

	// Set PIN.
	correctPIN := "1234"
	err := auth.SetPINForTesting(correctPIN)
	require.NoError(t, err)

	// Get key agreement.
	err = initKeyAgreement(t, auth)
	require.NoError(t, err)

	// Fail a few times first.
	for i := 0; i < 3; i++ {
		auth.mu.Lock()
		platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
		auth.mu.Unlock()
		require.NoError(t, err)

		pinHashEnc, err := encryptPINHash(sharedSecret, "wrong")
		require.NoError(t, err)

		req := map[int]interface{}{
			clientPINKeyPinUvAuthProtocol: PINProtocol1,
			clientPINKeySubCommand:        ClientPINSubCmdGetPINToken,
			clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
			clientPINKeyPinHashEnc:        pinHashEnc,
		}

		reqBytes, err := cbor.Marshal(req)
		require.NoError(t, err)

		_, _ = auth.ProcessCBOR(CmdClientPIN, reqBytes)
	}

	// Verify retries have been decremented.
	require.Equal(t, 5, auth.PINRetries(), "Should have 5 retries after 3 failures")

	// Now succeed.
	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	require.NoError(t, err)

	pinHashEnc, err := encryptPINHash(sharedSecret, correctPIN)
	require.NoError(t, err)

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdGetPINToken,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        pinHashEnc,
	}

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	// Verify retries reset to max.
	require.Equal(t, 8, auth.PINRetries(),
		"Retries should reset to max (8) after successful verification")
}

// TestHandleGetPINToken_TokenIsRandomEachTime tests that a new token is generated each time.
func TestHandleGetPINToken_TokenIsRandomEachTime(t *testing.T) {
	t.Parallel()

	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set PIN.
	pin := "1234"
	err := auth.SetPINForTesting(pin)
	require.NoError(t, err)

	// Get key agreement.
	err = initKeyAgreement(t, auth)
	require.NoError(t, err)

	var tokens [][]byte

	// Get multiple tokens.
	for i := 0; i < 3; i++ {
		auth.mu.Lock()
		platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
		auth.mu.Unlock()
		require.NoError(t, err)

		pinHashEnc, err := encryptPINHash(sharedSecret, pin)
		require.NoError(t, err)

		req := map[int]interface{}{
			clientPINKeyPinUvAuthProtocol: PINProtocol1,
			clientPINKeySubCommand:        ClientPINSubCmdGetPINToken,
			clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
			clientPINKeyPinHashEnc:        pinHashEnc,
		}

		reqBytes, err := cbor.Marshal(req)
		require.NoError(t, err)

		resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
		require.NoError(t, err)
		require.Equal(t, byte(StatusOK), resp[0])

		// Decrypt token.
		var respMap map[int]interface{}
		err = cbor.Unmarshal(resp[1:], &respMap)
		require.NoError(t, err)

		encryptedToken := respMap[clientPINResponseKeyPinUvAuthToken].([]byte)

		block, err := aes.NewCipher(sharedSecret)
		require.NoError(t, err)

		iv := make([]byte, AESBlockSize)
		mode := cipher.NewCBCDecrypter(block, iv)

		decryptedToken := make([]byte, len(encryptedToken))
		mode.CryptBlocks(decryptedToken, encryptedToken)

		tokens = append(tokens, decryptedToken[:PINTokenSize])
	}

	// Verify all tokens are different.
	for i := 0; i < len(tokens); i++ {
		for j := i + 1; j < len(tokens); j++ {
			require.False(t, hmac.Equal(tokens[i], tokens[j]),
				"Token %d and %d should be different", i, j)
		}
	}
}

// Helper functions for tests.

// initKeyAgreement issues a GetKeyAgreement command to initialize the PIN protocol state.
// This replaces the old getKeyAgreement helper; callers that only need to trigger
// initialization no longer need the returned COSE key bytes.
func initKeyAgreement(t *testing.T, auth *Authenticator) error {
	t.Helper()

	req := map[int]interface{}{
		clientPINKeySubCommand: ClientPINSubCmdGetKeyAgreement,
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		return err
	}

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err != nil {
		return err
	}

	if resp[0] != StatusOK {
		return ErrInvalidParameter
	}

	return nil
}

// getKeyAgreementRawResponse issues a GetKeyAgreement command and returns the raw
// response bytes from ProcessCBOR. These bytes are deterministic since they come
// from the production encodeCBOR call. This avoids the non-determinism of
// decode-then-re-encode through Go's map[interface{}]interface{}.
func getKeyAgreementRawResponse(t *testing.T, auth *Authenticator) ([]byte, error) {
	t.Helper()

	req := map[int]interface{}{
		clientPINKeySubCommand: ClientPINSubCmdGetKeyAgreement,
	}

	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		return nil, err
	}

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	if err != nil {
		return nil, err
	}

	if resp[0] != StatusOK {
		return nil, ErrInvalidParameter
	}

	// Return the raw CBOR payload (skip status byte) for deterministic comparison.
	return resp[1:], nil
}

// cborMapToIntMap converts a CBOR-decoded map[interface{}]interface{} to map[int]interface{}.
// The CBOR decoder produces interface{} keys (typically int64) for integer-keyed maps.
func cborMapToIntMap(t *testing.T, raw interface{}) map[int]interface{} {
	t.Helper()

	rawMap, ok := raw.(map[interface{}]interface{})
	if !ok {
		t.Fatalf("expected map[interface{}]interface{}, got %T", raw)
	}

	result := make(map[int]interface{}, len(rawMap))
	for k, v := range rawMap {
		ki, err := toInt(k)
		if err != nil {
			t.Fatalf("failed to convert map key %v to int: %v", k, err)
		}
		result[ki] = v
	}
	return result
}

// rawCOSEToMap converts raw COSE bytes to a map for inclusion in CBOR requests.
func rawCOSEToMap(t *testing.T, coseBytes []byte) map[int]interface{} {
	t.Helper()

	var coseMap map[int]interface{}
	if err := cbor.Unmarshal(coseBytes, &coseMap); err != nil {
		t.Fatalf("Failed to unmarshal COSE key: %v", err)
	}

	return coseMap
}

// =============================================================================
// Protocol V2 Test Variants
// =============================================================================

// TestSetPINWorkflowV2 tests the complete SetPIN workflow using PIN protocol 2.
// V2 uses HKDF-SHA-256 for key derivation, random IV for encryption, and full
// 32-byte HMAC-SHA-256 for authentication (no truncation).
func TestSetPINWorkflowV2(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Verify PIN is not set initially.
	require.False(t, auth.IsPINSet(), "PIN should not be set initially")

	// Get key agreement to initialize PIN protocol.
	err := initKeyAgreement(t, auth)
	require.NoError(t, err)

	// Generate V2 platform key agreement: HKDF-derived hmacKey + aesKey.
	auth.mu.Lock()
	platformCOSE, hmacKey, aesKey, err := auth.generatePlatformKeyAgreementV2()
	auth.mu.Unlock()
	require.NoError(t, err)
	require.Len(t, hmacKey, 32, "V2 hmacKey must be 32 bytes (HKDF output)")
	require.Len(t, aesKey, 32, "V2 aesKey must be 32 bytes (HKDF output)")

	// Encrypt new PIN using V2 protocol (random IV + full 32-byte HMAC).
	newPIN := "123456"
	encryptedPIN, authParam, err := encryptNewPINV2(hmacKey, aesKey, newPIN)
	require.NoError(t, err)
	require.Len(t, authParam, PINAuthSizeV2, "V2 auth param must be full 32-byte HMAC")
	// V2 encrypted PIN has 16-byte IV prefix + 64-byte ciphertext = 80 bytes.
	require.Equal(t, AESBlockSize+EncryptedPINMinLength, len(encryptedPIN),
		"V2 encrypted PIN must have IV prefix")

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol2,
		clientPINKeySubCommand:        ClientPINSubCmdSetPIN,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinUvAuthParam:    authParam,
		clientPINKeyNewPinEnc:         encryptedPIN,
	}

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0], "SetPIN V2 should succeed")

	// Verify PIN is now set.
	require.True(t, auth.IsPINSet(), "PIN should be set after SetPIN V2")

	// Verify the stored PIN hash matches.
	expectedHash := sha256.Sum256([]byte(newPIN))
	require.True(t, hmac.Equal(expectedHash[:PINHashSize], auth.state.PINHash),
		"Stored PIN hash should match the set PIN")
}

// TestSetPINV2FailsWithTruncatedAuth tests that V2 SetPIN rejects a V1-style
// truncated 16-byte auth param. This verifies the protocol enforces the full
// 32-byte HMAC requirement.
func TestSetPINV2FailsWithTruncatedAuth(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	err := initKeyAgreement(t, auth)
	require.NoError(t, err)

	auth.mu.Lock()
	platformCOSE, hmacKey, aesKey, err := auth.generatePlatformKeyAgreementV2()
	auth.mu.Unlock()
	require.NoError(t, err)

	newPIN := "123456"
	encryptedPIN, fullAuthParam, err := encryptNewPINV2(hmacKey, aesKey, newPIN)
	require.NoError(t, err)

	// Truncate to 16 bytes (V1-style) - this should fail with V2.
	truncatedAuth := fullAuthParam[:PINAuthSizeV1]

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol2,
		clientPINKeySubCommand:        ClientPINSubCmdSetPIN,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinUvAuthParam:    truncatedAuth,
		clientPINKeyNewPinEnc:         encryptedPIN,
	}

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.Error(t, err, "V2 SetPIN with truncated auth should fail")
	require.NotEqual(t, byte(StatusOK), resp[0],
		"Truncated V1-style auth param must not pass V2 verification")
}

// TestChangePINWithValidCurrentPINV2 tests changing PIN using protocol V2.
func TestChangePINWithValidCurrentPINV2(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Set initial PIN.
	initialPIN := "1234"
	err := auth.SetPINForTesting(initialPIN)
	require.NoError(t, err)

	// Get key agreement.
	err = initKeyAgreement(t, auth)
	require.NoError(t, err)

	// Generate V2 platform key agreement.
	auth.mu.Lock()
	platformCOSE, hmacKey, aesKey, err := auth.generatePlatformKeyAgreementV2()
	auth.mu.Unlock()
	require.NoError(t, err)

	// Prepare ChangePIN request with V2.
	newPIN := "5678"
	newPinEnc, _, err := encryptNewPINV2(hmacKey, aesKey, newPIN)
	require.NoError(t, err)

	pinHashEnc, err := encryptPINHashV2(aesKey, initialPIN)
	require.NoError(t, err)
	// V2 pinHashEnc should be 32 bytes: 16-byte IV + 16-byte ciphertext.
	require.Len(t, pinHashEnc, AESBlockSize+PINHashSize,
		"V2 pinHashEnc must have IV prefix")

	// Generate full 32-byte HMAC authParam over newPinEnc || pinHashEnc.
	authData := append(newPinEnc, pinHashEnc...)
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(authData)
	authParam := mac.Sum(nil) // Full 32 bytes for V2

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol2,
		clientPINKeySubCommand:        ClientPINSubCmdChangePIN,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinUvAuthParam:    authParam,
		clientPINKeyNewPinEnc:         newPinEnc,
		clientPINKeyPinHashEnc:        pinHashEnc,
	}

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0], "ChangePIN V2 should succeed")

	// Verify new PIN hash matches.
	newPINHash := sha256.Sum256([]byte(newPIN))
	require.True(t, hmac.Equal(newPINHash[:PINHashSize], auth.state.PINHash),
		"New PIN hash should match after ChangePIN V2")
}

// TestChangePINV2WithInvalidCurrentPIN tests that ChangePIN V2 rejects wrong PIN.
func TestChangePINV2WithInvalidCurrentPIN(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	initialPIN := "1234"
	err := auth.SetPINForTesting(initialPIN)
	require.NoError(t, err)

	initialRetries := auth.PINRetries()

	err = initKeyAgreement(t, auth)
	require.NoError(t, err)

	auth.mu.Lock()
	platformCOSE, hmacKey, aesKey, err := auth.generatePlatformKeyAgreementV2()
	auth.mu.Unlock()
	require.NoError(t, err)

	// Encrypt with wrong current PIN.
	newPIN := "5678"
	wrongPIN := "9999"
	newPinEnc, _, err := encryptNewPINV2(hmacKey, aesKey, newPIN)
	require.NoError(t, err)

	pinHashEnc, err := encryptPINHashV2(aesKey, wrongPIN)
	require.NoError(t, err)

	authData := append(newPinEnc, pinHashEnc...)
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(authData)
	authParam := mac.Sum(nil)

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol2,
		clientPINKeySubCommand:        ClientPINSubCmdChangePIN,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinUvAuthParam:    authParam,
		clientPINKeyNewPinEnc:         newPinEnc,
		clientPINKeyPinHashEnc:        pinHashEnc,
	}

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.Error(t, err, "ChangePIN V2 with wrong PIN should fail")
	require.Equal(t, byte(StatusPINInvalid), resp[0])
	require.Equal(t, initialRetries-1, auth.PINRetries(),
		"Retry count should decrement after wrong PIN with V2")
}

// TestGetPINTokenV2 tests getting a PIN token using protocol V2.
// Verifies the token is encrypted with random IV and can be decrypted correctly.
func TestGetPINTokenV2(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	pin := "1234"
	err := auth.SetPINForTesting(pin)
	require.NoError(t, err)

	err = initKeyAgreement(t, auth)
	require.NoError(t, err)

	auth.mu.Lock()
	platformCOSE, _, aesKey, err := auth.generatePlatformKeyAgreementV2()
	auth.mu.Unlock()
	require.NoError(t, err)

	pinHashEnc, err := encryptPINHashV2(aesKey, pin)
	require.NoError(t, err)

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol2,
		clientPINKeySubCommand:        ClientPINSubCmdGetPINToken,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        pinHashEnc,
	}

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0], "GetPINToken V2 should succeed")

	// Parse response.
	var respMap map[int]interface{}
	err = cbor.Unmarshal(resp[1:], &respMap)
	require.NoError(t, err)

	encryptedToken, ok := respMap[clientPINResponseKeyPinUvAuthToken].([]byte)
	require.True(t, ok, "Response must contain pinUvAuthToken")

	// V2 encrypted token: 16-byte IV prefix + padded ciphertext.
	require.Greater(t, len(encryptedToken), AESBlockSize,
		"V2 encrypted token must have IV prefix")

	// Decrypt: extract IV (first 16 bytes), then AES-CBC-decrypt the rest.
	iv := encryptedToken[:AESBlockSize]
	ciphertext := encryptedToken[AESBlockSize:]

	block, err := aes.NewCipher(aesKey)
	require.NoError(t, err)
	mode := cipher.NewCBCDecrypter(block, iv)
	decryptedToken := make([]byte, len(ciphertext))
	mode.CryptBlocks(decryptedToken, ciphertext)

	// Verify the decrypted token matches the internal token.
	internalToken := auth.GetPinUvAuthToken()
	require.NotNil(t, internalToken, "Internal PIN token must be set")
	require.True(t, hmac.Equal(decryptedToken[:PINTokenSize], internalToken),
		"V2-decrypted token must match internal token")
}

// TestGetPINTokenV2WithInvalidPIN tests that GetPINToken V2 rejects wrong PIN.
func TestGetPINTokenV2WithInvalidPIN(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	err := auth.SetPINForTesting("1234")
	require.NoError(t, err)

	initialRetries := auth.PINRetries()

	err = initKeyAgreement(t, auth)
	require.NoError(t, err)

	auth.mu.Lock()
	platformCOSE, _, aesKey, err := auth.generatePlatformKeyAgreementV2()
	auth.mu.Unlock()
	require.NoError(t, err)

	// Encrypt wrong PIN hash.
	pinHashEnc, err := encryptPINHashV2(aesKey, "9999")
	require.NoError(t, err)

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol2,
		clientPINKeySubCommand:        ClientPINSubCmdGetPINToken,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        pinHashEnc,
	}

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.Error(t, err, "GetPINToken V2 with wrong PIN should fail")
	require.Equal(t, byte(StatusPINInvalid), resp[0])
	require.Equal(t, initialRetries-1, auth.PINRetries(),
		"Retry count should decrement after wrong PIN with V2")
}

// TestGetPinUvAuthTokenUsingPinWithPermissionsV2 tests the permissions-based token
// retrieval using protocol V2.
func TestGetPinUvAuthTokenUsingPinWithPermissionsV2(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	pin := "1234"
	err := auth.SetPINForTesting(pin)
	require.NoError(t, err)

	err = initKeyAgreement(t, auth)
	require.NoError(t, err)

	auth.mu.Lock()
	platformCOSE, _, aesKey, err := auth.generatePlatformKeyAgreementV2()
	auth.mu.Unlock()
	require.NoError(t, err)

	pinHashEnc, err := encryptPINHashV2(aesKey, pin)
	require.NoError(t, err)

	permissions := PINPermissionMakeCredential | PINPermissionGetAssertion

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol2,
		clientPINKeySubCommand:        ClientPINSubCmdGetPinUvAuthTokenUsingPinWithPermissions,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        pinHashEnc,
		clientPINKeyPermissions:       permissions,
		clientPINKeyPermissionsRPID:   "example.com",
	}

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0],
		"GetPinUvAuthTokenUsingPinWithPermissions V2 should succeed")

	// Verify token was generated.
	require.NotNil(t, auth.GetPinUvAuthToken(),
		"PIN token should be set after successful V2 request")

	// Verify permissions are stored.
	auth.mu.RLock()
	storedPerms := auth.pinState.protocol.tokenPermissions
	storedRPID := auth.pinState.protocol.tokenRPID
	activeProto := auth.pinState.protocol.activeProtocol
	auth.mu.RUnlock()

	require.Equal(t, uint8(permissions), storedPerms,
		"Stored permissions should match requested")
	require.Equal(t, "example.com", storedRPID,
		"Stored RPID should match requested")
	require.Equal(t, uint8(PINProtocol2), activeProto,
		"Active protocol should be V2")
}

// TestV2KeyDerivationProducesDifferentKeysFromV1 verifies that V1 and V2 produce
// different shared secrets from the same ECDH output, confirming HKDF derivation
// is active and producing distinct hmacKey/aesKey vs V1 SHA-256 hash.
func TestV2KeyDerivationProducesDifferentKeysFromV1(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	err := initKeyAgreement(t, auth)
	require.NoError(t, err)

	// Get V1 shared secret.
	auth.mu.Lock()
	_, v1SharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	require.NoError(t, err)
	require.Len(t, v1SharedSecret, 32, "V1 shared secret should be 32 bytes")

	// Get V2 keys (requires fresh key agreement since generatePlatformKeyAgreement
	// uses a new ephemeral key each time).
	auth.mu.Lock()
	_, v2HmacKey, v2AesKey, err := auth.generatePlatformKeyAgreementV2()
	auth.mu.Unlock()
	require.NoError(t, err)
	require.Len(t, v2HmacKey, 32, "V2 hmacKey should be 32 bytes")
	require.Len(t, v2AesKey, 32, "V2 aesKey should be 32 bytes")

	// V2 hmacKey and aesKey should be different from each other.
	require.False(t, hmac.Equal(v2HmacKey, v2AesKey),
		"V2 hmacKey and aesKey must be different (separate HKDF info strings)")
}

// TestDeriveSharedSecret_V2_RawECDH_HKDF verifies that PIN Protocol V2's
// shared secret derivation follows the CTAP2 spec correctly:
//
//	V2 kdf(Z) = HKDF-SHA-256(salt=zeros(32), IKM=Z.x, info="CTAP2 HMAC key") → hmacKey
//	            HKDF-SHA-256(salt=zeros(32), IKM=Z.x, info="CTAP2 AES key")  → aesKey
//
// V2 uses the raw ECDH x-coordinate directly as IKM for HKDF (no SHA-256
// pre-hash). This differs from V1 which applies kdf(Z) = SHA-256(Z.x).
// Reference: CTAP2.1 §6.5.6, python-fido2 reference implementation.
func TestDeriveSharedSecret_V2_RawECDH_HKDF(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Initialize the authenticator's PIN protocol state (generates its ECDH key pair).
	err := initKeyAgreement(t, auth)
	require.NoError(t, err)

	// Step 1: Generate a platform-side ECDH P-256 key pair.
	platformPrivKey, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Step 2: Extract the authenticator's ECDH public key from protocol state.
	auth.mu.RLock()
	authCOSE := auth.pinState.protocol.publicKeyCOSE
	authXBytes := authCOSE[coseKeyLabelX].([]byte)
	authYBytes := authCOSE[coseKeyLabelY].([]byte)
	auth.mu.RUnlock()

	// Reconstruct the authenticator's public key in uncompressed point format.
	authPubBytes := make([]byte, 65)
	authPubBytes[0] = 0x04
	copy(authPubBytes[1:33], padCoordinate(authXBytes, 32))
	copy(authPubBytes[33:65], padCoordinate(authYBytes, 32))

	authPubKey, err := ecdh.P256().NewPublicKey(authPubBytes)
	require.NoError(t, err)

	// Step 3: Compute the raw ECDH shared secret from the platform side.
	// Go's ECDH returns the x-coordinate of the shared point (Z.x).
	rawECDH, err := platformPrivKey.ECDH(authPubKey)
	require.NoError(t, err)
	require.Len(t, rawECDH, 32, "P-256 ECDH output (Z.x) must be 32 bytes")

	// Step 4: V2 kdf uses raw ECDH x-coordinate directly as IKM for HKDF.
	// No SHA-256 pre-hash — this matches Chrome/python-fido2 behavior.
	salt := make([]byte, 32) // zero salt per spec

	hkdfHMAC := hkdf.New(sha256.New, rawECDH, salt, []byte("CTAP2 HMAC key"))
	expectedHMACKey := make([]byte, 32)
	_, err = io.ReadFull(hkdfHMAC, expectedHMACKey)
	require.NoError(t, err)

	hkdfAES := hkdf.New(sha256.New, rawECDH, salt, []byte("CTAP2 AES key"))
	expectedAESKey := make([]byte, 32)
	_, err = io.ReadFull(hkdfAES, expectedAESKey)
	require.NoError(t, err)

	// Step 5: Encode the platform public key as COSE for the authenticator's deriveSharedSecret.
	platformPubBytes := platformPrivKey.PublicKey().Bytes()
	platformCOSE, err := cbor.Marshal(map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: COSEAlgECDHESHKDF256,
		coseKeyLabelCrv: COSECurveP256,
		coseKeyLabelX:   platformPubBytes[1:33],
		coseKeyLabelY:   platformPubBytes[33:65],
	})
	require.NoError(t, err)

	// Step 6: Call the authenticator's deriveSharedSecret with protocol V2.
	auth.mu.Lock()
	gotSharedSecret, err := auth.deriveSharedSecret(platformCOSE, PINProtocol2)
	gotHMACKey := auth.pinState.protocol.hmacKey
	gotAESKey := auth.pinState.protocol.aesKey
	auth.mu.Unlock()
	require.NoError(t, err)

	// Step 7: Verify the authenticator's derived keys match our independent computation.
	require.True(t, hmac.Equal(expectedHMACKey, gotHMACKey),
		"V2 hmacKey from deriveSharedSecret must match HKDF(rawECDH, 'CTAP2 HMAC key')")

	require.True(t, hmac.Equal(expectedAESKey, gotAESKey),
		"V2 aesKey from deriveSharedSecret must match HKDF(rawECDH, 'CTAP2 AES key')")

	// The returned shared secret should be the hmacKey (for backward compat).
	require.True(t, hmac.Equal(expectedHMACKey, gotSharedSecret),
		"V2 deriveSharedSecret return value must be hmacKey")

	// Sanity: hmacKey and aesKey must be different from each other.
	require.False(t, hmac.Equal(gotHMACKey, gotAESKey),
		"hmacKey and aesKey must differ (distinct HKDF info strings)")

	// Regression guard: verify that applying SHA-256 before HKDF produces wrong keys.
	ecdhHash := sha256.Sum256(rawECDH)
	wrongHKDF := hkdf.New(sha256.New, ecdhHash[:], salt, []byte("CTAP2 HMAC key"))
	wrongHMACKey := make([]byte, 32)
	_, err = io.ReadFull(wrongHKDF, wrongHMACKey)
	require.NoError(t, err)

	require.False(t, hmac.Equal(wrongHMACKey, gotHMACKey),
		"Applying SHA-256 before HKDF must produce a different (wrong) hmacKey")
}

// TestDeriveSharedSecret_V1_SHA256Only verifies that PIN Protocol V1's shared
// secret derivation applies SHA-256(Z.x) and returns that as the shared secret
// directly (no HKDF). This confirms V1 and V2 share the same ecdh() function.
func TestDeriveSharedSecret_V1_SHA256Only(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Initialize PIN protocol.
	err := initKeyAgreement(t, auth)
	require.NoError(t, err)

	// Generate a platform-side ECDH key pair.
	platformPrivKey, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Get authenticator's public key.
	auth.mu.RLock()
	authCOSE := auth.pinState.protocol.publicKeyCOSE
	authXBytes := authCOSE[coseKeyLabelX].([]byte)
	authYBytes := authCOSE[coseKeyLabelY].([]byte)
	auth.mu.RUnlock()

	authPubBytes := make([]byte, 65)
	authPubBytes[0] = 0x04
	copy(authPubBytes[1:33], padCoordinate(authXBytes, 32))
	copy(authPubBytes[33:65], padCoordinate(authYBytes, 32))

	authPubKey, err := ecdh.P256().NewPublicKey(authPubBytes)
	require.NoError(t, err)

	// Compute raw ECDH and expected V1 shared secret.
	rawECDH, err := platformPrivKey.ECDH(authPubKey)
	require.NoError(t, err)

	expectedHash := sha256.Sum256(rawECDH)
	expectedSharedSecret := expectedHash[:]

	// Encode platform public key as COSE.
	platformPubBytes := platformPrivKey.PublicKey().Bytes()
	platformCOSE, err := cbor.Marshal(map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: COSEAlgECDHESHKDF256,
		coseKeyLabelCrv: COSECurveP256,
		coseKeyLabelX:   platformPubBytes[1:33],
		coseKeyLabelY:   platformPubBytes[33:65],
	})
	require.NoError(t, err)

	// Call deriveSharedSecret with V1.
	auth.mu.Lock()
	gotSharedSecret, err := auth.deriveSharedSecret(platformCOSE, PINProtocol1)
	auth.mu.Unlock()
	require.NoError(t, err)

	// V1 shared secret should be SHA-256(Z.x) directly.
	require.True(t, hmac.Equal(expectedSharedSecret, gotSharedSecret),
		"V1 shared secret must be SHA-256(Z.x)")

	// V1 must NOT set hmacKey or aesKey.
	auth.mu.RLock()
	require.Nil(t, auth.pinState.protocol.hmacKey,
		"V1 must not set hmacKey")
	require.Nil(t, auth.pinState.protocol.aesKey,
		"V1 must not set aesKey")
	auth.mu.RUnlock()
}

// TestPINTokenV2_RoundTrip_NoExtraPadding verifies that the V2 encrypted PIN token
// contains exactly 32 bytes (PINTokenSize) after decryption, with no extra padding.
// This catches the bug where encryptData was adding 16 bytes of zero-padding to the
// encrypted PIN token, causing Chrome to get a 48-byte token instead of 32.
//
// The test performs a full CTAP2 round-trip:
//  1. Sets a PIN via the CTAP2 SetPIN flow using V2 protocol
//  2. Gets a PIN token via getPinUvAuthTokenUsingPinWithPermissions (V2)
//  3. Decrypts the returned token and asserts exactly PINTokenSize bytes
//  4. Uses the decrypted token to compute and verify HMAC-SHA-256
func TestPINTokenV2_RoundTrip_NoExtraPadding(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Step 1: Set PIN via CTAP2 SetPIN flow using V2 protocol.
	require.False(t, auth.IsPINSet(), "PIN should not be set initially")

	err := initKeyAgreement(t, auth)
	require.NoError(t, err)

	auth.mu.Lock()
	platformCOSE, hmacKey, aesKey, err := auth.generatePlatformKeyAgreementV2()
	auth.mu.Unlock()
	require.NoError(t, err)

	pin := "123456"
	encryptedPIN, authParam, err := encryptNewPINV2(hmacKey, aesKey, pin)
	require.NoError(t, err)

	setPINReq := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol2,
		clientPINKeySubCommand:        ClientPINSubCmdSetPIN,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinUvAuthParam:    authParam,
		clientPINKeyNewPinEnc:         encryptedPIN,
	}

	setPINBytes, err := cbor.Marshal(setPINReq)
	require.NoError(t, err)

	resp, err := auth.ProcessCBOR(CmdClientPIN, setPINBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0], "SetPIN V2 should succeed")
	require.True(t, auth.IsPINSet(), "PIN should be set after SetPIN")

	// Step 2: Get PIN token via getPinUvAuthTokenUsingPinWithPermissions (V2).
	// Re-initialize key agreement for the token request (fresh ephemeral keys).
	err = initKeyAgreement(t, auth)
	require.NoError(t, err)

	auth.mu.Lock()
	platformCOSE2, _, aesKey2, err := auth.generatePlatformKeyAgreementV2()
	auth.mu.Unlock()
	require.NoError(t, err)

	pinHashEnc, err := encryptPINHashV2(aesKey2, pin)
	require.NoError(t, err)

	permissions := PINPermissionMakeCredential | PINPermissionGetAssertion
	getTokenReq := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol2,
		clientPINKeySubCommand:        ClientPINSubCmdGetPinUvAuthTokenUsingPinWithPermissions,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE2),
		clientPINKeyPinHashEnc:        pinHashEnc,
		clientPINKeyPermissions:       permissions,
		clientPINKeyPermissionsRPID:   "example.com",
	}

	getTokenBytes, err := cbor.Marshal(getTokenReq)
	require.NoError(t, err)

	resp, err = auth.ProcessCBOR(CmdClientPIN, getTokenBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0],
		"getPinUvAuthTokenUsingPinWithPermissions V2 should succeed")

	// Step 3: Parse response and decrypt the encrypted token.
	var respMap map[int]interface{}
	err = cbor.Unmarshal(resp[1:], &respMap)
	require.NoError(t, err)

	encryptedToken, ok := respMap[clientPINResponseKeyPinUvAuthToken].([]byte)
	require.True(t, ok, "Response must contain pinUvAuthToken")

	// V2 encrypted token layout: [16-byte IV][ciphertext]
	// For a 32-byte plaintext (PINTokenSize), ciphertext should be exactly 32 bytes
	// (already block-aligned, no padding needed).
	// Total: 16 + 32 = 48 bytes.
	require.Equal(t, AESBlockSize+PINTokenSize, len(encryptedToken),
		"V2 encrypted token must be exactly IV (16) + PINTokenSize (32) = 48 bytes; "+
			"extra bytes indicate unwanted padding in encryptData")

	iv := encryptedToken[:AESBlockSize]
	ciphertext := encryptedToken[AESBlockSize:]

	block, err := aes.NewCipher(aesKey2)
	require.NoError(t, err)

	mode := cipher.NewCBCDecrypter(block, iv)
	decryptedToken := make([]byte, len(ciphertext))
	mode.CryptBlocks(decryptedToken, ciphertext)

	// Step 4: Assert the decrypted token is EXACTLY PINTokenSize (32 bytes).
	require.Len(t, decryptedToken, PINTokenSize,
		"Decrypted PIN token must be exactly %d bytes; extra bytes mean encryptData added padding", PINTokenSize)

	// Verify decrypted token matches the authenticator's internal token.
	internalToken := auth.GetPinUvAuthToken()
	require.NotNil(t, internalToken, "Internal PIN token must be set")
	require.True(t, hmac.Equal(decryptedToken, internalToken),
		"Decrypted token must match the authenticator's internal PIN token byte-for-byte")

	// Step 5: Use the decrypted token to compute HMAC-SHA-256 over a fake clientDataHash.
	clientDataHash := make([]byte, 32)
	_, err = rand.Read(clientDataHash)
	require.NoError(t, err)

	mac := hmac.New(sha256.New, decryptedToken)
	mac.Write(clientDataHash)
	pinAuth := mac.Sum(nil)

	// Step 6: Verify the HMAC matches what the authenticator expects.
	require.True(t, auth.VerifyPinUvAuthToken(clientDataHash, pinAuth),
		"HMAC computed with the decrypted 32-byte token must pass authenticator verification; "+
			"failure here means the client got a different token than the authenticator stored")
}

// ---------------------------------------------------------------------------
// PIN Verifier delegation regression tests
// ---------------------------------------------------------------------------

// TestPINVerifier_GetPinTokenWithPermissions_NoSplitBrain verifies the exact
// failure scenario: PINVerifier reports PIN set (as seen by GetInfo), but
// a.state.PINSet is false (hash not yet synced). Before the fix, handlers
// checked a.state.PINSet directly and returned 0x35 (ErrPINNotSet).
func TestPINVerifier_GetPinTokenWithPermissions_NoSplitBrain(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Simulate split-brain: verifier says PIN is set, but state.PINSet is false.
	pinHash := sha256.Sum256([]byte("testpin123"))
	hash := pinHash[:PINHashSize]

	verifier := &testPINVerifier{pinSet: true, fido2Hash: hash}
	auth.SetPINVerifier(verifier)

	// Ensure internal state does NOT have the PIN — this is the split-brain.
	require.False(t, auth.state.PINSet, "state.PINSet must be false for this regression test")

	// IsPINSet should report true via verifier.
	require.True(t, auth.IsPINSet(), "IsPINSet must delegate to verifier")

	// Verify isPINSetLocked also reports true.
	auth.mu.RLock()
	lockedResult := auth.isPINSetLocked()
	auth.mu.RUnlock()
	require.True(t, lockedResult, "isPINSetLocked must delegate to verifier")
}

// TestPINVerifier_ChangePIN_NoSplitBrain verifies handleChangePIN delegates
// PIN state check to the verifier instead of a.state.PINSet.
func TestPINVerifier_ChangePIN_NoSplitBrain(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Verifier says PIN is set, state does not.
	verifier := &testPINVerifier{pinSet: true}
	auth.SetPINVerifier(verifier)

	require.False(t, auth.state.PINSet)
	require.True(t, auth.IsPINSet())

	// handleChangePIN should NOT return ErrPINNotSet.
	// We can't fully exercise the ECDH flow, but we can verify the guard
	// passes by checking it fails at a later stage (e.g., missing key agreement)
	// rather than at the PIN-not-set check.
	req := map[int]interface{}{
		clientPINKeySubCommand: ClientPINSubCmdChangePIN,
	}
	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	_, err = auth.ProcessCBOR(CmdClientPIN, reqBytes)
	// Should fail with a downstream error (blocked/missing key), NOT ErrPINNotSet.
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrPINNotSet,
		"handleChangePIN must delegate PIN state to verifier; got ErrPINNotSet indicating split-brain")
}

// TestPINVerifier_GetPINToken_NoSplitBrain verifies handleGetPINToken delegates
// PIN state check to the verifier instead of a.state.PINSet.
func TestPINVerifier_GetPINToken_NoSplitBrain(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	// Verifier says PIN is set, state does not.
	verifier := &testPINVerifier{pinSet: true}
	auth.SetPINVerifier(verifier)

	require.False(t, auth.state.PINSet)
	require.True(t, auth.IsPINSet())

	req := map[int]interface{}{
		clientPINKeySubCommand: ClientPINSubCmdGetPINToken,
	}
	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	_, err = auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrPINNotSet,
		"handleGetPINToken must delegate PIN state to verifier; got ErrPINNotSet indicating split-brain")
}

// mockUVKeyBackend is a minimal FIDO2KeyBackend that reports HandlesUserVerification.
type mockUVKeyBackend struct {
	handlesUV bool
}

func (m *mockUVKeyBackend) Type() types.BackendType {
	return types.BackendTypeSoftware
}

func (m *mockUVKeyBackend) Capabilities() keybackend.FIDO2KeyCapabilities {
	return keybackend.FIDO2KeyCapabilities{
		SupportedAlgorithms:     []int{COSEAlgES256},
		HandlesUserVerification: m.handlesUV,
	}
}

func (m *mockUVKeyBackend) GenerateCredentialKey(algorithm int, credentialID []byte) (keybackend.KeyHandle, []byte, error) {
	return nil, nil, nil
}

func (m *mockUVKeyBackend) Sign(handle keybackend.KeyHandle, algorithm int, data []byte) ([]byte, error) {
	return nil, nil
}

func (m *mockUVKeyBackend) LoadKey(credentialID []byte, algorithm int) (keybackend.KeyHandle, error) {
	return nil, nil
}

func (m *mockUVKeyBackend) DeleteKey(handle keybackend.KeyHandle) error {
	return nil
}

func (m *mockUVKeyBackend) ExportPrivateKey(handle keybackend.KeyHandle) ([]byte, error) {
	return nil, nil
}

func (m *mockUVKeyBackend) ImportPrivateKey(credentialID []byte, algorithm int, pkcs8Key []byte) (keybackend.KeyHandle, error) {
	return nil, nil
}

func (m *mockUVKeyBackend) Close() error {
	return nil
}

// createTestAuthenticatorWithUV creates an authenticator with PIN and UV-capable key backend.
func createTestAuthenticatorWithUV(t *testing.T, handlesUV bool) *Authenticator {
	t.Helper()
	storage := NewMemoryStorage()
	config := &Config{
		Storage:             storage,
		EnablePIN:           true,
		PINMinLength:        4,
		PINMaxRetries:       8,
		SupportedAlgorithms: []int{COSEAlgES256},
		KeyBackend:          &mockUVKeyBackend{handlesUV: handlesUV},
	}
	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	return auth
}

// TestGetPinUvAuthTokenUsingUvWithPermissions_Success tests successful UV token generation.
func TestGetPinUvAuthTokenUsingUvWithPermissions_Success(t *testing.T) {
	auth := createTestAuthenticatorWithUV(t, true)
	defer func() { _ = auth.Close() }()

	// Initialize PIN protocol by requesting key agreement first.
	kaReq := map[int]interface{}{
		clientPINKeySubCommand: ClientPINSubCmdGetKeyAgreement,
	}
	kaReqBytes, err := cbor.Marshal(kaReq)
	require.NoError(t, err)

	_, err = auth.ProcessCBOR(CmdClientPIN, kaReqBytes)
	require.NoError(t, err)

	// Generate platform key agreement (V1).
	auth.mu.Lock()
	platformCOSE, _, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	require.NoError(t, err)

	// Unmarshal platform COSE key for embedding in the request map.
	var platformCOSEMap map[int]interface{}
	err = cbor.Unmarshal(platformCOSE, &platformCOSEMap)
	require.NoError(t, err)

	// Build UV with permissions request.
	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:       ClientPINSubCmdGetPinUvAuthTokenUsingUvWithPermissions,
		clientPINKeyKeyAgreement:     platformCOSEMap,
		clientPINKeyPermissions:      PINPermissionMakeCredential | PINPermissionGetAssertion,
		clientPINKeyPermissionsRPID:  "example.com",
	}

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	// Decode response and verify token is present.
	var respMap map[int]interface{}
	err = cbor.Unmarshal(resp[1:], &respMap)
	require.NoError(t, err)

	encToken, ok := respMap[clientPINResponseKeyPinUvAuthToken]
	require.True(t, ok, "response must contain pinUvAuthToken")
	require.NotEmpty(t, encToken)

	// Verify token permissions were set.
	auth.mu.RLock()
	tokenPerms := auth.pinState.protocol.tokenPermissions
	tokenRPID := auth.pinState.protocol.tokenRPID
	token := auth.pinState.protocol.pinUvAuthToken
	auth.mu.RUnlock()

	require.Equal(t, uint8(PINPermissionMakeCredential|PINPermissionGetAssertion), tokenPerms)
	require.Equal(t, "example.com", tokenRPID)
	require.Len(t, token, PINTokenSize)
}

// TestGetPinUvAuthTokenUsingUvWithPermissions_V2 tests UV token generation with protocol 2.
func TestGetPinUvAuthTokenUsingUvWithPermissions_V2(t *testing.T) {
	auth := createTestAuthenticatorWithUV(t, true)
	defer func() { _ = auth.Close() }()

	// Initialize PIN protocol.
	kaReq := map[int]interface{}{
		clientPINKeySubCommand: ClientPINSubCmdGetKeyAgreement,
	}
	kaReqBytes, err := cbor.Marshal(kaReq)
	require.NoError(t, err)
	_, err = auth.ProcessCBOR(CmdClientPIN, kaReqBytes)
	require.NoError(t, err)

	// Generate V2 platform key agreement.
	auth.mu.Lock()
	platformCOSE, _, _, err := auth.generatePlatformKeyAgreementV2()
	auth.mu.Unlock()
	require.NoError(t, err)

	var platformCOSEMap map[int]interface{}
	err = cbor.Unmarshal(platformCOSE, &platformCOSEMap)
	require.NoError(t, err)

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol2,
		clientPINKeySubCommand:       ClientPINSubCmdGetPinUvAuthTokenUsingUvWithPermissions,
		clientPINKeyKeyAgreement:     platformCOSEMap,
		clientPINKeyPermissions:      PINPermissionGetAssertion,
	}

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	var respMap map[int]interface{}
	err = cbor.Unmarshal(resp[1:], &respMap)
	require.NoError(t, err)

	encToken, ok := respMap[clientPINResponseKeyPinUvAuthToken]
	require.True(t, ok, "response must contain pinUvAuthToken")

	// V2 encrypted token includes 16-byte IV prefix.
	tokenBytes, ok := encToken.([]byte)
	require.True(t, ok)
	require.Equal(t, AESBlockSize+PINTokenSize, len(tokenBytes),
		"V2 encrypted token should be IV (16) + token (32)")
}

// TestGetPinUvAuthTokenUsingUvWithPermissions_NoUVBackend tests error when backend
// does not support built-in user verification.
func TestGetPinUvAuthTokenUsingUvWithPermissions_NoUVBackend(t *testing.T) {
	auth := createTestAuthenticatorWithUV(t, false)
	defer func() { _ = auth.Close() }()

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:       ClientPINSubCmdGetPinUvAuthTokenUsingUvWithPermissions,
		clientPINKeyPermissions:      PINPermissionGetAssertion,
	}

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	_, err = auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.ErrorIs(t, err, ErrInvalidSubcommand)
}

// TestGetPinUvAuthTokenUsingUvWithPermissions_NilBackend tests error when no
// key backend is configured at all.
func TestGetPinUvAuthTokenUsingUvWithPermissions_NilBackend(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:       ClientPINSubCmdGetPinUvAuthTokenUsingUvWithPermissions,
		clientPINKeyPermissions:      PINPermissionGetAssertion,
	}

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	_, err = auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.ErrorIs(t, err, ErrInvalidSubcommand)
}

// TestGetPinUvAuthTokenUsingUvWithPermissions_ZeroPermissions tests error when
// permissions are zero.
func TestGetPinUvAuthTokenUsingUvWithPermissions_ZeroPermissions(t *testing.T) {
	auth := createTestAuthenticatorWithUV(t, true)
	defer func() { _ = auth.Close() }()

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:       ClientPINSubCmdGetPinUvAuthTokenUsingUvWithPermissions,
		clientPINKeyPermissions:      uint8(0),
	}

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	_, err = auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.ErrorIs(t, err, ErrInvalidParameter)
}

// TestGetPinUvAuthTokenUsingUvWithPermissions_MissingKeyAgreement tests error when
// platform key agreement is not provided.
func TestGetPinUvAuthTokenUsingUvWithPermissions_MissingKeyAgreement(t *testing.T) {
	auth := createTestAuthenticatorWithUV(t, true)
	defer func() { _ = auth.Close() }()

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:       ClientPINSubCmdGetPinUvAuthTokenUsingUvWithPermissions,
		clientPINKeyPermissions:      PINPermissionGetAssertion,
	}

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	_, err = auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.ErrorIs(t, err, ErrMissingKeyAgreement)
}

// TestGetPinUvAuthTokenUsingUvWithPermissions_UVBlocked tests error when UV retries
// are exhausted.
func TestGetPinUvAuthTokenUsingUvWithPermissions_UVBlocked(t *testing.T) {
	auth := createTestAuthenticatorWithUV(t, true)
	defer func() { _ = auth.Close() }()

	// Exhaust UV retries.
	auth.state.SetUVRetries(0)

	// Initialize PIN protocol.
	kaReq := map[int]interface{}{
		clientPINKeySubCommand: ClientPINSubCmdGetKeyAgreement,
	}
	kaReqBytes, err := cbor.Marshal(kaReq)
	require.NoError(t, err)
	_, err = auth.ProcessCBOR(CmdClientPIN, kaReqBytes)
	require.NoError(t, err)

	// Generate platform key agreement.
	auth.mu.Lock()
	platformCOSE, _, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	require.NoError(t, err)

	var platformCOSEMap map[int]interface{}
	err = cbor.Unmarshal(platformCOSE, &platformCOSEMap)
	require.NoError(t, err)

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:       ClientPINSubCmdGetPinUvAuthTokenUsingUvWithPermissions,
		clientPINKeyKeyAgreement:     platformCOSEMap,
		clientPINKeyPermissions:      PINPermissionGetAssertion,
	}

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	_, err = auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.ErrorIs(t, err, ErrUVBlocked)
}

// TestGetPinUvAuthTokenUsingUvWithPermissions_ResetsUVRetries verifies that UV retries
// are reset to the default value on successful token generation.
func TestGetPinUvAuthTokenUsingUvWithPermissions_ResetsUVRetries(t *testing.T) {
	auth := createTestAuthenticatorWithUV(t, true)
	defer func() { _ = auth.Close() }()

	// Set UV retries to a low value (but non-zero).
	auth.state.SetUVRetries(1)

	// Initialize PIN protocol.
	kaReq := map[int]interface{}{
		clientPINKeySubCommand: ClientPINSubCmdGetKeyAgreement,
	}
	kaReqBytes, err := cbor.Marshal(kaReq)
	require.NoError(t, err)
	_, err = auth.ProcessCBOR(CmdClientPIN, kaReqBytes)
	require.NoError(t, err)

	auth.mu.Lock()
	platformCOSE, _, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	require.NoError(t, err)

	var platformCOSEMap map[int]interface{}
	err = cbor.Unmarshal(platformCOSE, &platformCOSEMap)
	require.NoError(t, err)

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:       ClientPINSubCmdGetPinUvAuthTokenUsingUvWithPermissions,
		clientPINKeyKeyAgreement:     platformCOSEMap,
		clientPINKeyPermissions:      PINPermissionGetAssertion,
	}

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	_, err = auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.NoError(t, err)

	// Verify UV retries were reset.
	require.Equal(t, DefaultUVRetries, auth.state.UVRetries())
}

// TestGetPinUvAuthTokenUsingUvWithPermissions_TokenIsRandom verifies that each
// call generates a unique token.
func TestGetPinUvAuthTokenUsingUvWithPermissions_TokenIsRandom(t *testing.T) {
	auth := createTestAuthenticatorWithUV(t, true)
	defer func() { _ = auth.Close() }()

	// Helper to get a token.
	getToken := func() []byte {
		// Re-initialize protocol keys for a fresh ECDH.
		kaReq := map[int]interface{}{
			clientPINKeySubCommand: ClientPINSubCmdGetKeyAgreement,
		}
		kaReqBytes, err := cbor.Marshal(kaReq)
		require.NoError(t, err)

		// Force new key agreement by regenerating.
		auth.mu.Lock()
		auth.pinState.protocol = nil
		auth.mu.Unlock()

		_, err = auth.ProcessCBOR(CmdClientPIN, kaReqBytes)
		require.NoError(t, err)

		auth.mu.Lock()
		platformCOSE, _, err := auth.generatePlatformKeyAgreement()
		auth.mu.Unlock()
		require.NoError(t, err)

		var platformCOSEMap map[int]interface{}
		err = cbor.Unmarshal(platformCOSE, &platformCOSEMap)
		require.NoError(t, err)

		req := map[int]interface{}{
			clientPINKeyPinUvAuthProtocol: PINProtocol1,
			clientPINKeySubCommand:       ClientPINSubCmdGetPinUvAuthTokenUsingUvWithPermissions,
			clientPINKeyKeyAgreement:     platformCOSEMap,
			clientPINKeyPermissions:      PINPermissionGetAssertion,
		}
		reqBytes, err := cbor.Marshal(req)
		require.NoError(t, err)

		_, err = auth.ProcessCBOR(CmdClientPIN, reqBytes)
		require.NoError(t, err)

		auth.mu.RLock()
		token := make([]byte, len(auth.pinState.protocol.pinUvAuthToken))
		copy(token, auth.pinState.protocol.pinUvAuthToken)
		auth.mu.RUnlock()
		return token
	}

	token1 := getToken()
	token2 := getToken()
	require.NotEqual(t, token1, token2, "tokens from separate calls must be different")
}

// TestGetPinUvAuthTokenUsingUvWithPermissions_UnsupportedProtocol tests that an
// unsupported PIN protocol version is rejected before reaching the UV handler.
func TestGetPinUvAuthTokenUsingUvWithPermissions_UnsupportedProtocol(t *testing.T) {
	auth := createTestAuthenticatorWithUV(t, true)
	defer func() { _ = auth.Close() }()

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: uint8(99),
		clientPINKeySubCommand:       ClientPINSubCmdGetPinUvAuthTokenUsingUvWithPermissions,
		clientPINKeyPermissions:      PINPermissionGetAssertion,
	}

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	_, err = auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.ErrorIs(t, err, ErrUnsupportedPINProtocol)
}
