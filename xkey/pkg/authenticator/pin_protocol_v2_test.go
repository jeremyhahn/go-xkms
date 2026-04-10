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
	"crypto/elliptic"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestNewPINProtocolV2(t *testing.T) {
	p := NewPINProtocolV2()
	if p == nil {
		t.Fatal("NewPINProtocolV2 returned nil")
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
	if p.hmacKey != nil {
		t.Error("hmacKey should be nil on creation")
	}
	if p.aesKey != nil {
		t.Error("aesKey should be nil on creation")
	}
}

func TestPINProtocolV2_Version(t *testing.T) {
	p := NewPINProtocolV2()
	if p.Version() != 2 {
		t.Errorf("expected version 2, got %d", p.Version())
	}
}

func TestPINProtocolV2_Initialize(t *testing.T) {
	p := NewPINProtocolV2()

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
	if p.hmacKey != nil {
		t.Error("hmacKey should still be nil after Initialize()")
	}
	if p.aesKey != nil {
		t.Error("aesKey should still be nil after Initialize()")
	}

	// Verify the key is on P-256 curve
	if p.publicKey.Curve != elliptic.P256() {
		t.Error("public key should be on P-256 curve")
	}
}

func TestPINProtocolV2_Initialize_MultipleCallsGenerateNewKeys(t *testing.T) {
	p := NewPINProtocolV2()

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

func TestPINProtocolV2_GetKeyAgreementKey_Success(t *testing.T) {
	p := NewPINProtocolV2()

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

func TestPINProtocolV2_GetKeyAgreementKey_NotInitialized(t *testing.T) {
	p := NewPINProtocolV2()

	_, err := p.GetKeyAgreementKey()
	if err != ErrPINProtocolNotInitialized {
		t.Errorf("expected ErrPINProtocolNotInitialized, got %v", err)
	}
}

func TestPINProtocolV2_SetPeerPublicKey_Success(t *testing.T) {
	// Create two protocol instances to simulate authenticator and client
	authenticator := NewPINProtocolV2()
	client := NewPINProtocolV2()

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

	// Both should have derived the same hmacKey and aesKey
	if !bytes.Equal(authenticator.hmacKey, client.hmacKey) {
		t.Error("hmacKeys should match after key exchange")
	}
	if !bytes.Equal(authenticator.aesKey, client.aesKey) {
		t.Error("aesKeys should match after key exchange")
	}

	// Keys should be 32 bytes each
	if len(authenticator.hmacKey) != 32 {
		t.Errorf("expected hmacKey of 32 bytes, got %d", len(authenticator.hmacKey))
	}
	if len(authenticator.aesKey) != 32 {
		t.Errorf("expected aesKey of 32 bytes, got %d", len(authenticator.aesKey))
	}

	// hmacKey and aesKey should be different from each other
	if bytes.Equal(authenticator.hmacKey, authenticator.aesKey) {
		t.Error("hmacKey and aesKey should be different (derived with different info strings)")
	}
}

func TestPINProtocolV2_SetPeerPublicKey_NotInitialized(t *testing.T) {
	p := NewPINProtocolV2()

	// Create a valid peer key
	peerKey := createTestCOSEKey(t)

	err := p.SetPeerPublicKey(peerKey)
	if err != ErrPINProtocolNotInitialized {
		t.Errorf("expected ErrPINProtocolNotInitialized, got %v", err)
	}
}

func TestPINProtocolV2_SetPeerPublicKey_InvalidCOSEKey(t *testing.T) {
	p := NewPINProtocolV2()
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

func TestPINProtocolV2_SetPeerPublicKey_PointNotOnCurve(t *testing.T) {
	p := NewPINProtocolV2()
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

func TestPINProtocolV2_EncryptDecrypt_RoundTrip(t *testing.T) {
	authenticator, client := setupV2KeyExchange(t)

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
			plaintext: []byte("Hello, CTAP2.1!"),
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

			// V2 ciphertext = IV (16 bytes) + encrypted data (block-aligned)
			if len(ciphertext) < aesBlockSize+aesBlockSize {
				t.Errorf("ciphertext too short: %d bytes", len(ciphertext))
			}
			if len(ciphertext)%aesBlockSize != 0 {
				t.Errorf("ciphertext length %d is not block-aligned", len(ciphertext))
			}

			// Decrypt with client (same derived keys)
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

func TestPINProtocolV2_Encapsulate_RandomIV(t *testing.T) {
	authenticator, _ := setupV2KeyExchange(t)

	plaintext := []byte("same plaintext each time")

	// Encrypt the same plaintext twice
	ct1, err := authenticator.Encapsulate(plaintext)
	if err != nil {
		t.Fatalf("first Encapsulate failed: %v", err)
	}

	ct2, err := authenticator.Encapsulate(plaintext)
	if err != nil {
		t.Fatalf("second Encapsulate failed: %v", err)
	}

	// Ciphertexts should differ because V2 uses a random IV
	if bytes.Equal(ct1, ct2) {
		t.Error("V2 ciphertexts for identical plaintext should differ (random IV)")
	}

	// IVs (first 16 bytes) should differ
	if bytes.Equal(ct1[:aesBlockSize], ct2[:aesBlockSize]) {
		t.Error("V2 IVs should differ between encryptions")
	}
}

func TestPINProtocolV2_Encapsulate_NoSharedSecret(t *testing.T) {
	p := NewPINProtocolV2()
	err := p.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	_, err = p.Encapsulate([]byte("test"))
	if err != ErrSharedSecretNotEstablished {
		t.Errorf("expected ErrSharedSecretNotEstablished, got %v", err)
	}
}

func TestPINProtocolV2_Decapsulate_NoSharedSecret(t *testing.T) {
	p := NewPINProtocolV2()
	err := p.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	_, err = p.Decapsulate(make([]byte, 32))
	if err != ErrSharedSecretNotEstablished {
		t.Errorf("expected ErrSharedSecretNotEstablished, got %v", err)
	}
}

func TestPINProtocolV2_Decapsulate_InvalidCiphertext(t *testing.T) {
	authenticator, _ := setupV2KeyExchange(t)

	testCases := []struct {
		name       string
		ciphertext []byte
	}{
		{
			name:       "empty",
			ciphertext: []byte{},
		},
		{
			name:       "too short for IV plus one block (31 bytes)",
			ciphertext: make([]byte, 31),
		},
		{
			name:       "only IV, no data (16 bytes)",
			ciphertext: make([]byte, 16),
		},
		{
			name:       "not block-aligned (33 bytes)",
			ciphertext: make([]byte, 33),
		},
		{
			name:       "not block-aligned (47 bytes)",
			ciphertext: make([]byte, 47),
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

func TestPINProtocolV2_Decapsulate_InvalidPadding(t *testing.T) {
	authenticator, _ := setupV2KeyExchange(t)

	// Create a valid ciphertext and then corrupt the encrypted portion
	plaintext := []byte("test data for invalid padding test!")
	ciphertext, err := authenticator.Encapsulate(plaintext)
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	// Corrupt the last byte of the encrypted portion (after IV)
	ciphertext[len(ciphertext)-1] ^= 0xFF

	_, err = authenticator.Decapsulate(ciphertext)
	if err != ErrInvalidPKCS7Padding {
		t.Errorf("expected ErrInvalidPKCS7Padding, got %v", err)
	}
}

func TestPINProtocolV2_Authenticate_Success(t *testing.T) {
	authenticator, client := setupV2KeyExchange(t)

	data := []byte("data to authenticate")

	authToken, err := authenticator.Authenticate(data)
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	// V2: Verify token is full 32 bytes
	if len(authToken) != pinAuthSizeV2 {
		t.Errorf("expected auth token of %d bytes, got %d", pinAuthSizeV2, len(authToken))
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

func TestPINProtocolV2_Authenticate_NoSharedSecret(t *testing.T) {
	p := NewPINProtocolV2()
	err := p.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	_, err = p.Authenticate([]byte("test"))
	if err != ErrSharedSecretNotEstablished {
		t.Errorf("expected ErrSharedSecretNotEstablished, got %v", err)
	}
}

func TestPINProtocolV2_Verify_Success(t *testing.T) {
	authenticator, client := setupV2KeyExchange(t)

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

func TestPINProtocolV2_Verify_NoSharedSecret(t *testing.T) {
	p := NewPINProtocolV2()
	err := p.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	err = p.Verify([]byte("test"), make([]byte, 32))
	if err != ErrSharedSecretNotEstablished {
		t.Errorf("expected ErrSharedSecretNotEstablished, got %v", err)
	}
}

func TestPINProtocolV2_Verify_InvalidLength(t *testing.T) {
	authenticator, _ := setupV2KeyExchange(t)

	testCases := []struct {
		name    string
		pinAuth []byte
	}{
		{
			name:    "empty",
			pinAuth: []byte{},
		},
		{
			name:    "too short (16 bytes - V1 size)",
			pinAuth: make([]byte, 16),
		},
		{
			name:    "too short (31 bytes)",
			pinAuth: make([]byte, 31),
		},
		{
			name:    "too long (33 bytes)",
			pinAuth: make([]byte, 33),
		},
		{
			name:    "way too long (64 bytes)",
			pinAuth: make([]byte, 64),
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

func TestPINProtocolV2_Verify_InvalidToken(t *testing.T) {
	authenticator, client := setupV2KeyExchange(t)

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

func TestPINProtocolV2_Verify_WrongData(t *testing.T) {
	authenticator, client := setupV2KeyExchange(t)

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

func TestPINProtocolV2_ResetSharedSecret(t *testing.T) {
	p := NewPINProtocolV2()

	err := p.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Set up a peer key to establish derived keys
	peer := NewPINProtocolV2()
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

	// Keep references to verify they get zeroed
	hmacKeyRef := p.hmacKey
	aesKeyRef := p.aesKey

	// Verify state before reset
	if p.hmacKey == nil {
		t.Error("hmacKey should be set before reset")
	}
	if p.aesKey == nil {
		t.Error("aesKey should be set before reset")
	}

	// ResetSharedSecret
	p.ResetSharedSecret()

	// Verify keys are cleared
	if p.hmacKey != nil {
		t.Error("hmacKey should be nil after ResetSharedSecret")
	}
	if p.aesKey != nil {
		t.Error("aesKey should be nil after ResetSharedSecret")
	}

	// Verify the original byte slices were zeroed
	for _, b := range hmacKeyRef {
		if b != 0 {
			t.Error("hmacKey data should be zeroed on reset")
			break
		}
	}
	for _, b := range aesKeyRef {
		if b != 0 {
			t.Error("aesKey data should be zeroed on reset")
			break
		}
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

func TestPINProtocolV2_Reset(t *testing.T) {
	p := NewPINProtocolV2()

	err := p.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Set up a peer key to establish derived keys
	peer := NewPINProtocolV2()
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
	if p.hmacKey == nil {
		t.Error("hmacKey should be set before reset")
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
	if p.hmacKey != nil {
		t.Error("hmacKey should be nil after reset")
	}
	if p.aesKey != nil {
		t.Error("aesKey should be nil after reset")
	}
}

func TestPINProtocolV2_Reset_ClearsSecretData(t *testing.T) {
	p := NewPINProtocolV2()

	err := p.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Set up a peer key to establish derived keys
	peer := NewPINProtocolV2()
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

	// Keep references to verify they get zeroed
	hmacKeyRef := p.hmacKey
	aesKeyRef := p.aesKey

	// Reset
	p.Reset()

	// Verify the original byte slices were zeroed
	for _, b := range hmacKeyRef {
		if b != 0 {
			t.Error("hmacKey data should be zeroed on reset")
			break
		}
	}
	for _, b := range aesKeyRef {
		if b != 0 {
			t.Error("aesKey data should be zeroed on reset")
			break
		}
	}
}

func TestPINProtocolV2_AfterReset_RequiresReinitialize(t *testing.T) {
	p := NewPINProtocolV2()

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

func TestPINProtocolV2_AfterResetSharedSecret_CanReestablishSecret(t *testing.T) {
	authenticator := NewPINProtocolV2()
	client := NewPINProtocolV2()

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

	firstHMACKey := make([]byte, len(authenticator.hmacKey))
	copy(firstHMACKey, authenticator.hmacKey)
	firstAESKey := make([]byte, len(authenticator.aesKey))
	copy(firstAESKey, authenticator.aesKey)

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

	// Derived keys should be the same (same ECDH secret, same HKDF params)
	if !bytes.Equal(authenticator.hmacKey, firstHMACKey) {
		t.Error("re-established hmacKey should match original")
	}
	if !bytes.Equal(authenticator.aesKey, firstAESKey) {
		t.Error("re-established aesKey should match original")
	}
}

func TestPINProtocolV2_InterfaceCompliance(t *testing.T) {
	var _ PINProtocol = (*PINProtocolV2)(nil)
}

func TestPINProtocolV2_ConcurrentAccess(t *testing.T) {
	authenticator, client := setupV2KeyExchange(t)

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

func TestPINProtocolV2_V1V2_DerivesDifferentSecrets(t *testing.T) {
	// Verify V1 and V2 derive different secrets from the same ECDH result.
	// This validates that the HKDF derivation in V2 produces distinct keys
	// compared to the SHA-256 hash in V1.
	v1Auth := NewPINProtocolV1()
	v2Auth := NewPINProtocolV2()

	err := v1Auth.Initialize()
	if err != nil {
		t.Fatalf("V1 Initialize failed: %v", err)
	}
	err = v2Auth.Initialize()
	if err != nil {
		t.Fatalf("V2 Initialize failed: %v", err)
	}

	// Create a common peer
	peer := NewPINProtocolV1()
	err = peer.Initialize()
	if err != nil {
		t.Fatalf("peer Initialize failed: %v", err)
	}
	peerKey, _ := peer.GetKeyAgreementKey()

	err = v1Auth.SetPeerPublicKey(peerKey)
	if err != nil {
		t.Fatalf("V1 SetPeerPublicKey failed: %v", err)
	}
	err = v2Auth.SetPeerPublicKey(peerKey)
	if err != nil {
		t.Fatalf("V2 SetPeerPublicKey failed: %v", err)
	}

	// V1's sharedSecret should differ from V2's hmacKey and aesKey
	if bytes.Equal(v1Auth.sharedSecret, v2Auth.hmacKey) {
		t.Error("V1 sharedSecret should differ from V2 hmacKey")
	}
	if bytes.Equal(v1Auth.sharedSecret, v2Auth.aesKey) {
		t.Error("V1 sharedSecret should differ from V2 aesKey")
	}
}

func TestPINProtocolV2_CrossEncryptDecrypt(t *testing.T) {
	// Verify that V2 encrypt/decrypt works both ways:
	// authenticator encrypts -> client decrypts, and client encrypts -> authenticator decrypts.
	authenticator, client := setupV2KeyExchange(t)

	plaintext := []byte("bidirectional encryption test")

	// Direction 1: authenticator -> client
	ct1, err := authenticator.Encapsulate(plaintext)
	if err != nil {
		t.Fatalf("authenticator Encapsulate failed: %v", err)
	}
	pt1, err := client.Decapsulate(ct1)
	if err != nil {
		t.Fatalf("client Decapsulate failed: %v", err)
	}
	if !bytes.Equal(pt1, plaintext) {
		t.Error("direction 1: decrypted data mismatch")
	}

	// Direction 2: client -> authenticator
	ct2, err := client.Encapsulate(plaintext)
	if err != nil {
		t.Fatalf("client Encapsulate failed: %v", err)
	}
	pt2, err := authenticator.Decapsulate(ct2)
	if err != nil {
		t.Fatalf("authenticator Decapsulate failed: %v", err)
	}
	if !bytes.Equal(pt2, plaintext) {
		t.Error("direction 2: decrypted data mismatch")
	}
}

// setupV2KeyExchange creates two V2 protocol instances with an established shared secret.
func setupV2KeyExchange(t *testing.T) (*PINProtocolV2, *PINProtocolV2) {
	t.Helper()

	authenticator := NewPINProtocolV2()
	client := NewPINProtocolV2()

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
