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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestNewPINProtocolV1(t *testing.T) {
	p := NewPINProtocolV1()
	if p == nil {
		t.Fatal("NewPINProtocolV1 returned nil")
	}
	if p.initialized {
		t.Error("protocol should not be initialized on creation")
	}
	if p.privateKey != nil {
		t.Error("private key should be nil on creation")
	}
	if p.publicKey != nil {
		t.Error("public key should be nil on creation")
	}
	if p.sharedSecret != nil {
		t.Error("shared secret should be nil on creation")
	}
}

func TestPINProtocolV1_Version(t *testing.T) {
	p := NewPINProtocolV1()
	if p.Version() != 1 {
		t.Errorf("expected version 1, got %d", p.Version())
	}
}

func TestPINProtocolV1_Initialize(t *testing.T) {
	p := NewPINProtocolV1()

	err := p.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	if !p.initialized {
		t.Error("protocol should be initialized after Initialize()")
	}
	if p.privateKey == nil {
		t.Error("private key should be set after Initialize()")
	}
	if p.publicKey == nil {
		t.Error("public key should be set after Initialize()")
	}
	if p.sharedSecret != nil {
		t.Error("shared secret should still be nil after Initialize()")
	}

	// Verify the key is on P-256 curve
	if p.publicKey.Curve != elliptic.P256() {
		t.Error("public key should be on P-256 curve")
	}
}

func TestPINProtocolV1_Initialize_MultipleCallsGenerateNewKeys(t *testing.T) {
	p := NewPINProtocolV1()

	err := p.Initialize()
	if err != nil {
		t.Fatalf("first Initialize failed: %v", err)
	}
	firstPrivKey := p.privateKey

	err = p.Initialize()
	if err != nil {
		t.Fatalf("second Initialize failed: %v", err)
	}

	// Keys should be different
	if p.privateKey.D.Cmp(firstPrivKey.D) == 0 {
		t.Error("Initialize should generate new keys each time")
	}
}

func TestPINProtocolV1_GetKeyAgreementKey_Success(t *testing.T) {
	p := NewPINProtocolV1()

	err := p.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	coseKey, err := p.GetKeyAgreementKey()
	if err != nil {
		t.Fatalf("GetKeyAgreementKey failed: %v", err)
	}

	// Decode and verify COSE key structure
	var keyMap map[int]interface{}
	err = cbor.Unmarshal(coseKey, &keyMap)
	if err != nil {
		t.Fatalf("failed to unmarshal COSE key: %v", err)
	}

	// Verify kty = 2 (EC2)
	kty, err := toInt(keyMap[coseKeyLabelKty])
	if err != nil || kty != COSEKeyTypeEC2 {
		t.Errorf("expected kty=2 (EC2), got %v", keyMap[coseKeyLabelKty])
	}

	// Verify alg = -25 (ECDH-ES+HKDF-256)
	alg, err := toInt(keyMap[coseKeyLabelAlg])
	if err != nil || alg != COSEAlgECDHESHKDF256 {
		t.Errorf("expected alg=-25, got %v", keyMap[coseKeyLabelAlg])
	}

	// Verify crv = 1 (P-256)
	crv, err := toInt(keyMap[coseKeyLabelCrv])
	if err != nil || crv != COSECurveP256 {
		t.Errorf("expected crv=1 (P-256), got %v", keyMap[coseKeyLabelCrv])
	}

	// Verify x coordinate is 32 bytes
	xBytes, ok := keyMap[coseKeyLabelX].([]byte)
	if !ok || len(xBytes) != ecdhP256CoordSize {
		t.Errorf("expected x coordinate of 32 bytes, got %d bytes", len(xBytes))
	}

	// Verify y coordinate is 32 bytes
	yBytes, ok := keyMap[coseKeyLabelY].([]byte)
	if !ok || len(yBytes) != ecdhP256CoordSize {
		t.Errorf("expected y coordinate of 32 bytes, got %d bytes", len(yBytes))
	}
}

func TestPINProtocolV1_GetKeyAgreementKey_NotInitialized(t *testing.T) {
	p := NewPINProtocolV1()

	_, err := p.GetKeyAgreementKey()
	if err != ErrPINProtocolNotInitialized {
		t.Errorf("expected ErrPINProtocolNotInitialized, got %v", err)
	}
}

func TestPINProtocolV1_SetPeerPublicKey_Success(t *testing.T) {
	// Create two protocol instances to simulate authenticator and client
	authenticator := NewPINProtocolV1()
	client := NewPINProtocolV1()

	err := authenticator.Initialize()
	if err != nil {
		t.Fatalf("authenticator Initialize failed: %v", err)
	}

	err = client.Initialize()
	if err != nil {
		t.Fatalf("client Initialize failed: %v", err)
	}

	// Exchange public keys
	authKey, err := authenticator.GetKeyAgreementKey()
	if err != nil {
		t.Fatalf("authenticator GetKeyAgreementKey failed: %v", err)
	}

	clientKey, err := client.GetKeyAgreementKey()
	if err != nil {
		t.Fatalf("client GetKeyAgreementKey failed: %v", err)
	}

	// Set peer keys
	err = authenticator.SetPeerPublicKey(clientKey)
	if err != nil {
		t.Fatalf("authenticator SetPeerPublicKey failed: %v", err)
	}

	err = client.SetPeerPublicKey(authKey)
	if err != nil {
		t.Fatalf("client SetPeerPublicKey failed: %v", err)
	}

	// Both should have derived the same shared secret
	if !bytes.Equal(authenticator.sharedSecret, client.sharedSecret) {
		t.Error("shared secrets should match after key exchange")
	}

	// Shared secret should be 32 bytes (SHA-256 output)
	if len(authenticator.sharedSecret) != 32 {
		t.Errorf("expected shared secret of 32 bytes, got %d", len(authenticator.sharedSecret))
	}
}

func TestPINProtocolV1_SetPeerPublicKey_NotInitialized(t *testing.T) {
	p := NewPINProtocolV1()

	// Create a valid peer key
	peerKey := createTestCOSEKey(t)

	err := p.SetPeerPublicKey(peerKey)
	if err != ErrPINProtocolNotInitialized {
		t.Errorf("expected ErrPINProtocolNotInitialized, got %v", err)
	}
}

func TestPINProtocolV1_SetPeerPublicKey_InvalidCOSEKey(t *testing.T) {
	p := NewPINProtocolV1()
	err := p.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	testCases := []struct {
		name string
		key  []byte
	}{
		{
			name: "empty data",
			key:  []byte{},
		},
		{
			name: "invalid CBOR",
			key:  []byte{0xff, 0xff, 0xff},
		},
		{
			name: "missing kty",
			key: mustMarshalCBOR(t, map[int]interface{}{
				coseKeyLabelCrv: COSECurveP256,
				coseKeyLabelX:   make([]byte, 32),
				coseKeyLabelY:   make([]byte, 32),
			}),
		},
		{
			name: "wrong kty (OKP instead of EC2)",
			key: mustMarshalCBOR(t, map[int]interface{}{
				coseKeyLabelKty: COSEKeyTypeOKP,
				coseKeyLabelCrv: COSECurveP256,
				coseKeyLabelX:   make([]byte, 32),
				coseKeyLabelY:   make([]byte, 32),
			}),
		},
		{
			name: "wrong curve (P-384 instead of P-256)",
			key: mustMarshalCBOR(t, map[int]interface{}{
				coseKeyLabelKty: COSEKeyTypeEC2,
				coseKeyLabelCrv: COSECurveP384,
				coseKeyLabelX:   make([]byte, 32),
				coseKeyLabelY:   make([]byte, 32),
			}),
		},
		{
			name: "missing crv",
			key: mustMarshalCBOR(t, map[int]interface{}{
				coseKeyLabelKty: COSEKeyTypeEC2,
				coseKeyLabelX:   make([]byte, 32),
				coseKeyLabelY:   make([]byte, 32),
			}),
		},
		{
			name: "missing x coordinate",
			key: mustMarshalCBOR(t, map[int]interface{}{
				coseKeyLabelKty: COSEKeyTypeEC2,
				coseKeyLabelCrv: COSECurveP256,
				coseKeyLabelY:   make([]byte, 32),
			}),
		},
		{
			name: "missing y coordinate",
			key: mustMarshalCBOR(t, map[int]interface{}{
				coseKeyLabelKty: COSEKeyTypeEC2,
				coseKeyLabelCrv: COSECurveP256,
				coseKeyLabelX:   make([]byte, 32),
			}),
		},
		{
			name: "x coordinate wrong type",
			key: mustMarshalCBOR(t, map[int]interface{}{
				coseKeyLabelKty: COSEKeyTypeEC2,
				coseKeyLabelCrv: COSECurveP256,
				coseKeyLabelX:   "not bytes",
				coseKeyLabelY:   make([]byte, 32),
			}),
		},
		{
			name: "y coordinate wrong type",
			key: mustMarshalCBOR(t, map[int]interface{}{
				coseKeyLabelKty: COSEKeyTypeEC2,
				coseKeyLabelCrv: COSECurveP256,
				coseKeyLabelX:   make([]byte, 32),
				coseKeyLabelY:   "not bytes",
			}),
		},
		{
			name: "empty x coordinate",
			key: mustMarshalCBOR(t, map[int]interface{}{
				coseKeyLabelKty: COSEKeyTypeEC2,
				coseKeyLabelCrv: COSECurveP256,
				coseKeyLabelX:   []byte{},
				coseKeyLabelY:   make([]byte, 32),
			}),
		},
		{
			name: "empty y coordinate",
			key: mustMarshalCBOR(t, map[int]interface{}{
				coseKeyLabelKty: COSEKeyTypeEC2,
				coseKeyLabelCrv: COSECurveP256,
				coseKeyLabelX:   make([]byte, 32),
				coseKeyLabelY:   []byte{},
			}),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := p.SetPeerPublicKey(tc.key)
			if err == nil {
				t.Error("expected error for invalid COSE key")
			}
		})
	}
}

func TestPINProtocolV1_SetPeerPublicKey_PointNotOnCurve(t *testing.T) {
	p := NewPINProtocolV1()
	err := p.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Create a key with coordinates that are not on P-256 curve
	invalidKey := mustMarshalCBOR(t, map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelCrv: COSECurveP256,
		coseKeyLabelX:   make([]byte, 32), // (0, 0) is not on P-256
		coseKeyLabelY:   make([]byte, 32),
	})

	err = p.SetPeerPublicKey(invalidKey)
	if err != ErrInvalidPeerPublicKey {
		t.Errorf("expected ErrInvalidPeerPublicKey, got %v", err)
	}
}

func TestPINProtocolV1_EncryptDecrypt_RoundTrip(t *testing.T) {
	authenticator, client := setupKeyExchange(t)

	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{
			name:      "single byte",
			plaintext: []byte{0x42},
		},
		{
			name:      "exactly one block (16 bytes)",
			plaintext: bytes.Repeat([]byte{0xAB}, 16),
		},
		{
			name:      "two blocks (32 bytes)",
			plaintext: bytes.Repeat([]byte{0xCD}, 32),
		},
		{
			name:      "PIN-like data (64 bytes padded PIN)",
			plaintext: bytes.Repeat([]byte{0x00}, 64),
		},
		{
			name:      "odd length",
			plaintext: []byte("Hello, CTAP2!"),
		},
		{
			name:      "empty",
			plaintext: []byte{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encrypt with authenticator
			ciphertext, err := authenticator.Encapsulate(tc.plaintext)
			if err != nil {
				t.Fatalf("Encapsulate failed: %v", err)
			}

			// Verify ciphertext is block-aligned
			if len(ciphertext)%aesBlockSize != 0 {
				t.Errorf("ciphertext length %d is not block-aligned", len(ciphertext))
			}

			// Decrypt with client (same shared secret)
			decrypted, err := client.Decapsulate(ciphertext)
			if err != nil {
				t.Fatalf("Decapsulate failed: %v", err)
			}

			if !bytes.Equal(decrypted, tc.plaintext) {
				t.Errorf("decrypted data mismatch: got %v, want %v", decrypted, tc.plaintext)
			}
		})
	}
}

func TestPINProtocolV1_Encapsulate_NoSharedSecret(t *testing.T) {
	p := NewPINProtocolV1()
	err := p.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	_, err = p.Encapsulate([]byte("test"))
	if err != ErrSharedSecretNotEstablished {
		t.Errorf("expected ErrSharedSecretNotEstablished, got %v", err)
	}
}

func TestPINProtocolV1_Decapsulate_NoSharedSecret(t *testing.T) {
	p := NewPINProtocolV1()
	err := p.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	_, err = p.Decapsulate(make([]byte, 16))
	if err != ErrSharedSecretNotEstablished {
		t.Errorf("expected ErrSharedSecretNotEstablished, got %v", err)
	}
}

func TestPINProtocolV1_Decapsulate_InvalidCiphertext(t *testing.T) {
	authenticator, _ := setupKeyExchange(t)

	testCases := []struct {
		name       string
		ciphertext []byte
	}{
		{
			name:       "empty",
			ciphertext: []byte{},
		},
		{
			name:       "not block-aligned (15 bytes)",
			ciphertext: make([]byte, 15),
		},
		{
			name:       "not block-aligned (17 bytes)",
			ciphertext: make([]byte, 17),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := authenticator.Decapsulate(tc.ciphertext)
			if err != ErrPINDecryptionFailed {
				t.Errorf("expected ErrPINDecryptionFailed, got %v", err)
			}
		})
	}
}

func TestPINProtocolV1_Decapsulate_InvalidPadding(t *testing.T) {
	authenticator, _ := setupKeyExchange(t)

	// Create a ciphertext that decrypts to data with invalid padding
	// We do this by encrypting valid data and then corrupting the last block
	plaintext := []byte("test data for invalid padding test!")
	ciphertext, err := authenticator.Encapsulate(plaintext)
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	// Corrupt the last byte of ciphertext to cause padding error
	ciphertext[len(ciphertext)-1] ^= 0xFF

	_, err = authenticator.Decapsulate(ciphertext)
	if err != ErrInvalidPKCS7Padding {
		t.Errorf("expected ErrInvalidPKCS7Padding, got %v", err)
	}
}

func TestPINProtocolV1_Authenticate_Success(t *testing.T) {
	authenticator, client := setupKeyExchange(t)

	data := []byte("data to authenticate")

	authToken, err := authenticator.Authenticate(data)
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	// Verify token is 16 bytes
	if len(authToken) != pinAuthSize {
		t.Errorf("expected auth token of %d bytes, got %d", pinAuthSize, len(authToken))
	}

	// Client should compute the same token
	clientToken, err := client.Authenticate(data)
	if err != nil {
		t.Fatalf("client Authenticate failed: %v", err)
	}

	if !bytes.Equal(authToken, clientToken) {
		t.Error("auth tokens should match between authenticator and client")
	}
}

func TestPINProtocolV1_Authenticate_NoSharedSecret(t *testing.T) {
	p := NewPINProtocolV1()
	err := p.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	_, err = p.Authenticate([]byte("test"))
	if err != ErrSharedSecretNotEstablished {
		t.Errorf("expected ErrSharedSecretNotEstablished, got %v", err)
	}
}

func TestPINProtocolV1_Verify_Success(t *testing.T) {
	authenticator, client := setupKeyExchange(t)

	data := []byte("data to verify")

	// Compute auth token with client
	authToken, err := client.Authenticate(data)
	if err != nil {
		t.Fatalf("client Authenticate failed: %v", err)
	}

	// Verify with authenticator
	err = authenticator.Verify(data, authToken)
	if err != nil {
		t.Errorf("Verify should succeed for valid auth token: %v", err)
	}
}

func TestPINProtocolV1_Verify_NoSharedSecret(t *testing.T) {
	p := NewPINProtocolV1()
	err := p.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	err = p.Verify([]byte("test"), make([]byte, 16))
	if err != ErrSharedSecretNotEstablished {
		t.Errorf("expected ErrSharedSecretNotEstablished, got %v", err)
	}
}

func TestPINProtocolV1_Verify_InvalidLength(t *testing.T) {
	authenticator, _ := setupKeyExchange(t)

	testCases := []struct {
		name    string
		pinAuth []byte
	}{
		{
			name:    "empty",
			pinAuth: []byte{},
		},
		{
			name:    "too short (15 bytes)",
			pinAuth: make([]byte, 15),
		},
		{
			name:    "too long (17 bytes)",
			pinAuth: make([]byte, 17),
		},
		{
			name:    "way too long (32 bytes)",
			pinAuth: make([]byte, 32),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := authenticator.Verify([]byte("test"), tc.pinAuth)
			if err != ErrPINAuthenticationFailed {
				t.Errorf("expected ErrPINAuthenticationFailed, got %v", err)
			}
		})
	}
}

func TestPINProtocolV1_Verify_InvalidToken(t *testing.T) {
	authenticator, client := setupKeyExchange(t)

	data := []byte("data to verify")

	// Compute valid auth token
	authToken, err := client.Authenticate(data)
	if err != nil {
		t.Fatalf("client Authenticate failed: %v", err)
	}

	// Corrupt the token
	authToken[0] ^= 0xFF

	err = authenticator.Verify(data, authToken)
	if err != ErrPINAuthenticationFailed {
		t.Errorf("expected ErrPINAuthenticationFailed, got %v", err)
	}
}

func TestPINProtocolV1_Verify_WrongData(t *testing.T) {
	authenticator, client := setupKeyExchange(t)

	// Compute auth token for one message
	authToken, err := client.Authenticate([]byte("original data"))
	if err != nil {
		t.Fatalf("client Authenticate failed: %v", err)
	}

	// Try to verify with different data
	err = authenticator.Verify([]byte("different data"), authToken)
	if err != ErrPINAuthenticationFailed {
		t.Errorf("expected ErrPINAuthenticationFailed, got %v", err)
	}
}

func TestPINProtocolV1_ResetSharedSecret(t *testing.T) {
	p := NewPINProtocolV1()

	err := p.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Set up a peer key to establish shared secret
	peer := NewPINProtocolV1()
	err = peer.Initialize()
	if err != nil {
		t.Fatalf("peer Initialize failed: %v", err)
	}

	peerKey, err := peer.GetKeyAgreementKey()
	if err != nil {
		t.Fatalf("peer GetKeyAgreementKey failed: %v", err)
	}

	err = p.SetPeerPublicKey(peerKey)
	if err != nil {
		t.Fatalf("SetPeerPublicKey failed: %v", err)
	}

	// Keep reference to shared secret to verify it gets zeroed
	sharedSecretRef := p.sharedSecret

	// Verify state before reset
	if p.sharedSecret == nil {
		t.Error("shared secret should be set before reset")
	}

	// ResetSharedSecret
	p.ResetSharedSecret()

	// Verify shared secret is cleared
	if p.sharedSecret != nil {
		t.Error("shared secret should be nil after ResetSharedSecret")
	}

	// Verify the original byte slice was zeroed
	allZero := true
	for _, b := range sharedSecretRef {
		if b != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Error("shared secret data should be zeroed on reset")
	}

	// Verify key pair is retained
	if !p.initialized {
		t.Error("initialized should remain true after ResetSharedSecret")
	}
	if p.privateKey == nil {
		t.Error("private key should be retained after ResetSharedSecret")
	}
	if p.publicKey == nil {
		t.Error("public key should be retained after ResetSharedSecret")
	}
}

func TestPINProtocolV1_Reset(t *testing.T) {
	p := NewPINProtocolV1()

	err := p.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Set up a peer key to establish shared secret
	peer := NewPINProtocolV1()
	err = peer.Initialize()
	if err != nil {
		t.Fatalf("peer Initialize failed: %v", err)
	}

	peerKey, err := peer.GetKeyAgreementKey()
	if err != nil {
		t.Fatalf("peer GetKeyAgreementKey failed: %v", err)
	}

	err = p.SetPeerPublicKey(peerKey)
	if err != nil {
		t.Fatalf("SetPeerPublicKey failed: %v", err)
	}

	// Verify state before reset
	if p.sharedSecret == nil {
		t.Error("shared secret should be set before reset")
	}

	// Reset
	p.Reset()

	// Verify state after reset
	if p.initialized {
		t.Error("initialized should be false after reset")
	}
	if p.privateKey != nil {
		t.Error("private key should be nil after reset")
	}
	if p.publicKey != nil {
		t.Error("public key should be nil after reset")
	}
	if p.sharedSecret != nil {
		t.Error("shared secret should be nil after reset")
	}
}

func TestPINProtocolV1_Reset_ClearsSecretData(t *testing.T) {
	p := NewPINProtocolV1()

	err := p.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Set up a peer key to establish shared secret
	peer := NewPINProtocolV1()
	err = peer.Initialize()
	if err != nil {
		t.Fatalf("peer Initialize failed: %v", err)
	}

	peerKey, err := peer.GetKeyAgreementKey()
	if err != nil {
		t.Fatalf("peer GetKeyAgreementKey failed: %v", err)
	}

	err = p.SetPeerPublicKey(peerKey)
	if err != nil {
		t.Fatalf("SetPeerPublicKey failed: %v", err)
	}

	// Keep reference to shared secret to verify it gets zeroed
	sharedSecretRef := p.sharedSecret

	// Reset
	p.Reset()

	// Verify the original byte slice was zeroed
	allZero := true
	for _, b := range sharedSecretRef {
		if b != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Error("shared secret data should be zeroed on reset")
	}
}

func TestPINProtocolV1_AfterReset_RequiresReinitialize(t *testing.T) {
	p := NewPINProtocolV1()

	err := p.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	p.Reset()

	// All operations should fail after reset
	_, err = p.GetKeyAgreementKey()
	if err != ErrPINProtocolNotInitialized {
		t.Errorf("GetKeyAgreementKey after reset: expected ErrPINProtocolNotInitialized, got %v", err)
	}

	peerKey := createTestCOSEKey(t)
	err = p.SetPeerPublicKey(peerKey)
	if err != ErrPINProtocolNotInitialized {
		t.Errorf("SetPeerPublicKey after reset: expected ErrPINProtocolNotInitialized, got %v", err)
	}
}

func TestPINProtocolV1_AfterResetSharedSecret_CanReestablishSecret(t *testing.T) {
	authenticator := NewPINProtocolV1()
	client := NewPINProtocolV1()

	err := authenticator.Initialize()
	if err != nil {
		t.Fatalf("authenticator Initialize failed: %v", err)
	}

	err = client.Initialize()
	if err != nil {
		t.Fatalf("client Initialize failed: %v", err)
	}

	// First key exchange
	authKey, _ := authenticator.GetKeyAgreementKey()
	clientKey, _ := client.GetKeyAgreementKey()

	err = authenticator.SetPeerPublicKey(clientKey)
	if err != nil {
		t.Fatalf("first SetPeerPublicKey failed: %v", err)
	}
	err = client.SetPeerPublicKey(authKey)
	if err != nil {
		t.Fatalf("first client SetPeerPublicKey failed: %v", err)
	}

	firstSharedSecret := make([]byte, len(authenticator.sharedSecret))
	copy(firstSharedSecret, authenticator.sharedSecret)

	// Reset shared secrets
	authenticator.ResetSharedSecret()
	client.ResetSharedSecret()

	// Re-establish with same keys (should work since keys are retained)
	err = authenticator.SetPeerPublicKey(clientKey)
	if err != nil {
		t.Fatalf("second SetPeerPublicKey failed: %v", err)
	}
	err = client.SetPeerPublicKey(authKey)
	if err != nil {
		t.Fatalf("second client SetPeerPublicKey failed: %v", err)
	}

	// Shared secrets should be the same
	if !bytes.Equal(authenticator.sharedSecret, firstSharedSecret) {
		t.Error("re-established shared secret should match original")
	}
}

func TestPINProtocolV1_InterfaceCompliance(t *testing.T) {
	var _ PINProtocol = (*PINProtocolV1)(nil)
}

func TestPINProtocolV1_ConcurrentAccess(t *testing.T) {
	authenticator, client := setupKeyExchange(t)

	// Run concurrent operations
	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func(id int) {
			data := []byte("concurrent data")

			// Encrypt/decrypt
			ciphertext, err := authenticator.Encapsulate(data)
			if err != nil {
				t.Errorf("goroutine %d: Encapsulate failed: %v", id, err)
				done <- true
				return
			}

			plaintext, err := client.Decapsulate(ciphertext)
			if err != nil {
				t.Errorf("goroutine %d: Decapsulate failed: %v", id, err)
				done <- true
				return
			}

			if !bytes.Equal(plaintext, data) {
				t.Errorf("goroutine %d: data mismatch", id)
			}

			// Authenticate/verify
			authToken, err := client.Authenticate(data)
			if err != nil {
				t.Errorf("goroutine %d: Authenticate failed: %v", id, err)
				done <- true
				return
			}

			err = authenticator.Verify(data, authToken)
			if err != nil {
				t.Errorf("goroutine %d: Verify failed: %v", id, err)
			}

			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestPkcs7Pad(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		expected int // expected padded length
	}{
		{
			name:     "empty",
			input:    []byte{},
			expected: 16,
		},
		{
			name:     "1 byte",
			input:    []byte{0x01},
			expected: 16,
		},
		{
			name:     "15 bytes",
			input:    bytes.Repeat([]byte{0xAB}, 15),
			expected: 16,
		},
		{
			name:     "16 bytes (full block)",
			input:    bytes.Repeat([]byte{0xCD}, 16),
			expected: 32, // adds full padding block
		},
		{
			name:     "17 bytes",
			input:    bytes.Repeat([]byte{0xEF}, 17),
			expected: 32,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			padded := pkcs7Pad(tc.input, aesBlockSize)

			if len(padded) != tc.expected {
				t.Errorf("expected padded length %d, got %d", tc.expected, len(padded))
			}

			// Verify padding bytes
			paddingLen := int(padded[len(padded)-1])
			for i := len(padded) - paddingLen; i < len(padded); i++ {
				if padded[i] != byte(paddingLen) {
					t.Errorf("invalid padding byte at position %d: got %d, want %d", i, padded[i], paddingLen)
				}
			}

			// Verify original data is preserved
			if !bytes.Equal(padded[:len(tc.input)], tc.input) {
				t.Error("original data not preserved in padded output")
			}
		})
	}
}

func TestPkcs7Unpad(t *testing.T) {
	testCases := []struct {
		name        string
		input       []byte
		expected    []byte
		expectError bool
	}{
		{
			name:        "empty",
			input:       []byte{},
			expectError: true,
		},
		{
			name:        "zero padding byte",
			input:       bytes.Repeat([]byte{0x00}, 16),
			expectError: true,
		},
		{
			name:        "padding too large",
			input:       append(bytes.Repeat([]byte{0xAB}, 8), bytes.Repeat([]byte{17}, 8)...),
			expectError: true,
		},
		{
			name:        "inconsistent padding",
			input:       append(bytes.Repeat([]byte{0xAB}, 12), []byte{0x04, 0x04, 0x04, 0x05}...),
			expectError: true,
		},
		{
			name:     "valid 1 byte padding",
			input:    append(bytes.Repeat([]byte{0xAB}, 15), 0x01),
			expected: bytes.Repeat([]byte{0xAB}, 15),
		},
		{
			name:     "valid full block padding",
			input:    bytes.Repeat([]byte{16}, 16),
			expected: []byte{},
		},
		{
			name:     "valid 8 byte padding",
			input:    append(bytes.Repeat([]byte{0xCD}, 8), bytes.Repeat([]byte{8}, 8)...),
			expected: bytes.Repeat([]byte{0xCD}, 8),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := pkcs7Unpad(tc.input)

			if tc.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !bytes.Equal(result, tc.expected) {
				t.Errorf("result mismatch: got %v, want %v", result, tc.expected)
			}
		})
	}
}

func TestPkcs7_RoundTrip(t *testing.T) {
	testCases := [][]byte{
		{},
		{0x01},
		bytes.Repeat([]byte{0xAB}, 15),
		bytes.Repeat([]byte{0xCD}, 16),
		bytes.Repeat([]byte{0xEF}, 17),
		bytes.Repeat([]byte{0x12}, 100),
	}

	for i, tc := range testCases {
		padded := pkcs7Pad(tc, aesBlockSize)
		unpadded, err := pkcs7Unpad(padded)
		if err != nil {
			t.Errorf("test case %d: unexpected error: %v", i, err)
			continue
		}
		if !bytes.Equal(unpadded, tc) {
			t.Errorf("test case %d: round trip failed", i)
		}
	}
}

// Helper functions

func setupKeyExchange(t *testing.T) (*PINProtocolV1, *PINProtocolV1) {
	t.Helper()

	authenticator := NewPINProtocolV1()
	client := NewPINProtocolV1()

	if err := authenticator.Initialize(); err != nil {
		t.Fatalf("authenticator Initialize failed: %v", err)
	}

	if err := client.Initialize(); err != nil {
		t.Fatalf("client Initialize failed: %v", err)
	}

	authKey, err := authenticator.GetKeyAgreementKey()
	if err != nil {
		t.Fatalf("authenticator GetKeyAgreementKey failed: %v", err)
	}

	clientKey, err := client.GetKeyAgreementKey()
	if err != nil {
		t.Fatalf("client GetKeyAgreementKey failed: %v", err)
	}

	if err := authenticator.SetPeerPublicKey(clientKey); err != nil {
		t.Fatalf("authenticator SetPeerPublicKey failed: %v", err)
	}

	if err := client.SetPeerPublicKey(authKey); err != nil {
		t.Fatalf("client SetPeerPublicKey failed: %v", err)
	}

	return authenticator, client
}

func createTestCOSEKey(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	coseKey := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: COSEAlgECDHESHKDF256,
		coseKeyLabelCrv: COSECurveP256,
		coseKeyLabelX:   padCoordinate(key.X.Bytes(), ecdhP256CoordSize),
		coseKeyLabelY:   padCoordinate(key.Y.Bytes(), ecdhP256CoordSize),
	}

	data, err := cbor.Marshal(coseKey)
	if err != nil {
		t.Fatalf("failed to marshal COSE key: %v", err)
	}

	return data
}

func mustMarshalCBOR(t *testing.T, v interface{}) []byte {
	t.Helper()

	data, err := cbor.Marshal(v)
	if err != nil {
		t.Fatalf("failed to marshal CBOR: %v", err)
	}

	return data
}
