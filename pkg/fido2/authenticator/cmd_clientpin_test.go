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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
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

	// The keyAgreement is a byte string containing CBOR-encoded COSE key.
	coseKeyBytes, ok := keyAgreementRaw.([]byte)
	if !ok {
		t.Fatalf("keyAgreement is not a byte string, got %T", keyAgreementRaw)
	}

	// Parse COSE key.
	var keyMap map[int]interface{}
	if err := cbor.Unmarshal(coseKeyBytes, &keyMap); err != nil {
		t.Fatalf("Failed to parse COSE key: %v", err)
	}

	// Verify key type is EC2 (2).
	kty, err := clientPINToUint8(keyMap[coseKeyLabelKty])
	if err != nil || kty != COSEKeyTypeEC2 {
		t.Errorf("Expected kty=2 (EC2), got %v", keyMap[coseKeyLabelKty])
	}

	// Verify algorithm is ES256 (-7).
	alg, ok := keyMap[coseKeyLabelAlg]
	if !ok {
		t.Error("COSE key missing algorithm")
	}
	algInt, err := toInt(alg)
	if err != nil || algInt != COSEAlgES256 {
		t.Errorf("Expected alg=-7 (ES256), got %v", alg)
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

	key1, err := getKeyAgreement(t, auth)
	if err != nil {
		t.Fatalf("First GetKeyAgreement failed: %v", err)
	}

	key2, err := getKeyAgreement(t, auth)
	if err != nil {
		t.Fatalf("Second GetKeyAgreement failed: %v", err)
	}

	if string(key1) != string(key2) {
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
	_, err := getKeyAgreement(t, auth)
	if err != nil {
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

	pinHashEnc, err := encryptPINHash(sharedSecret, "1234")
	if err != nil {
		t.Fatalf("Failed to encrypt PIN hash: %v", err)
	}

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: 2, // Protocol 2 not supported
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

// Helper functions for tests.

// getKeyAgreement issues a GetKeyAgreement command and returns the COSE key.
func getKeyAgreement(t *testing.T, auth *Authenticator) ([]byte, error) {
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

	var respMap map[int]interface{}
	if err := cbor.Unmarshal(resp[1:], &respMap); err != nil {
		return nil, err
	}

	keyAgreementRaw, ok := respMap[clientPINResponseKeyKeyAgreement]
	if !ok {
		return nil, ErrInvalidParameter
	}

	// The keyAgreement should be a byte string.
	coseKey, ok := keyAgreementRaw.([]byte)
	if !ok {
		return nil, ErrInvalidParameter
	}

	return coseKey, nil
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
