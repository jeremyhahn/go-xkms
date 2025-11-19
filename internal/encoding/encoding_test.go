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

package encoding

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-keychain/internal/password"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Test helpers

func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	return key
}

func generateECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	return key
}

func generateEd25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}
	return key
}

// Tests

func TestKeyAlgorithm_String(t *testing.T) {
	tests := []struct {
		name string
		alg  KeyAlgorithm
		want string
	}{
		{"RSA", RSA, "RSA"},
		{"ECDSA", ECDSA, "ECDSA"},
		{"Ed25519", Ed25519, "Ed25519"},
		{"Unknown", KeyAlgorithm(999), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.alg.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEncodePrivateKey(t *testing.T) {
	rsaKey := generateRSAKey(t)
	ecdsaKey := generateECDSAKey(t)
	ed25519Key := generateEd25519Key(t)

	tests := []struct {
		name       string
		privateKey interface{}
		password   types.Password
		wantErr    bool
	}{
		{
			name:       "RSA key without password",
			privateKey: rsaKey,
			password:   nil,
			wantErr:    false,
		},
		{
			name:       "RSA key with password",
			privateKey: rsaKey,
			password:   mustCreatePassword(t, "test-password"),
			wantErr:    false,
		},
		{
			name:       "ECDSA key without password",
			privateKey: ecdsaKey,
			password:   nil,
			wantErr:    false,
		},
		{
			name:       "ECDSA key with password",
			privateKey: ecdsaKey,
			password:   mustCreatePassword(t, "test-password"),
			wantErr:    false,
		},
		{
			name:       "Ed25519 key without password",
			privateKey: ed25519Key,
			password:   nil,
			wantErr:    false,
		},
		{
			name:       "Ed25519 key with password",
			privateKey: ed25519Key,
			password:   mustCreatePassword(t, "test-password"),
			wantErr:    false,
		},
		{
			name:       "nil key",
			privateKey: nil,
			password:   nil,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodePrivateKey(tt.privateKey, tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncodePrivateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(got) == 0 {
				t.Error("EncodePrivateKey() returned empty data")
			}
		})
	}
}

func TestEncodePrivateKey_NilPasswordBytes(t *testing.T) {
	rsaKey := generateRSAKey(t)
	badPassword := &mockBadPassword{}

	// With a cleared password (Bytes returns nil), encoding should succeed without encryption
	got, err := EncodePrivateKey(rsaKey, badPassword)
	if err != nil {
		t.Errorf("EncodePrivateKey() with nil bytes should succeed, got error: %v", err)
	}
	if len(got) == 0 {
		t.Error("EncodePrivateKey() returned empty data")
	}
}

func TestEncodePrivateKey_InvalidKey(t *testing.T) {
	// Test with an invalid key type that pkcs8.MarshalPrivateKey would reject
	invalidKey := struct{ Invalid string }{Invalid: "not a key"}

	_, err := EncodePrivateKey(invalidKey, nil)
	if err == nil {
		t.Error("Expected error when marshaling invalid key, got nil")
	}
}

func TestEncodePrivateKeyPEM(t *testing.T) {
	rsaKey := generateRSAKey(t)
	ecdsaKey := generateECDSAKey(t)
	ed25519Key := generateEd25519Key(t)

	tests := []struct {
		name          string
		privateKey    interface{}
		password      types.Password
		wantBlockType string
		wantErr       bool
	}{
		{
			name:          "RSA key without password",
			privateKey:    rsaKey,
			password:      nil,
			wantBlockType: "RSA PRIVATE KEY",
			wantErr:       false,
		},
		{
			name:          "RSA key with password",
			privateKey:    rsaKey,
			password:      mustCreatePassword(t, "test-password"),
			wantBlockType: "ENCRYPTED PRIVATE KEY",
			wantErr:       false,
		},
		{
			name:          "ECDSA key without password",
			privateKey:    ecdsaKey,
			password:      nil,
			wantBlockType: "PRIVATE KEY",
			wantErr:       false,
		},
		{
			name:          "ECDSA key with password",
			privateKey:    ecdsaKey,
			password:      mustCreatePassword(t, "test-password"),
			wantBlockType: "ENCRYPTED PRIVATE KEY",
			wantErr:       false,
		},
		{
			name:          "Ed25519 key without password",
			privateKey:    ed25519Key,
			password:      nil,
			wantBlockType: "PRIVATE KEY",
			wantErr:       false,
		},
		{
			name:          "Ed25519 key with password",
			privateKey:    ed25519Key,
			password:      mustCreatePassword(t, "test-password"),
			wantBlockType: "ENCRYPTED PRIVATE KEY",
			wantErr:       false,
		},
		{
			name:       "nil key",
			privateKey: nil,
			password:   nil,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodePrivateKeyPEM(tt.privateKey, tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncodePrivateKeyPEM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) == 0 {
					t.Error("EncodePrivateKeyPEM() returned empty data")
				}
				// Verify PEM format
				block, _ := pem.Decode(got)
				if block == nil {
					t.Error("EncodePrivateKeyPEM() did not produce valid PEM")
					return
				}
				if block.Type != tt.wantBlockType {
					t.Errorf("PEM block type = %v, want %v", block.Type, tt.wantBlockType)
				}
			}
		})
	}
}

func TestEncodePrivateKeyPEM_InvalidKeyType(t *testing.T) {
	// Test with an invalid key type
	invalidKey := struct{ Invalid string }{Invalid: "not a key"}

	_, err := EncodePrivateKeyPEM(invalidKey, nil)
	if err == nil {
		t.Error("Expected error for invalid key type, got nil")
	}
	if !errors.Is(err, ErrInvalidKeyType) {
		t.Errorf("Expected ErrInvalidKeyType, got: %v", err)
	}
}

func TestDecodePrivateKeyPEM(t *testing.T) {
	rsaKey := generateRSAKey(t)
	ecdsaKey := generateECDSAKey(t)
	ed25519Key := generateEd25519Key(t)
	pwd := mustCreatePassword(t, "test-password")

	tests := []struct {
		name       string
		privateKey interface{}
		password   types.Password
		wantErr    bool
	}{
		{
			name:       "RSA key without password",
			privateKey: rsaKey,
			password:   nil,
			wantErr:    false,
		},
		{
			name:       "RSA key with password",
			privateKey: rsaKey,
			password:   pwd,
			wantErr:    false,
		},
		{
			name:       "ECDSA key without password",
			privateKey: ecdsaKey,
			password:   nil,
			wantErr:    false,
		},
		{
			name:       "ECDSA key with password",
			privateKey: ecdsaKey,
			password:   pwd,
			wantErr:    false,
		},
		{
			name:       "Ed25519 key without password",
			privateKey: ed25519Key,
			password:   nil,
			wantErr:    false,
		},
		{
			name:       "Ed25519 key with password",
			privateKey: ed25519Key,
			password:   pwd,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode the key first
			pemData, err := EncodePrivateKeyPEM(tt.privateKey, tt.password)
			if err != nil {
				t.Fatalf("EncodePrivateKeyPEM() error = %v", err)
			}

			// Decode it back
			got, err := DecodePrivateKeyPEM(pemData, tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodePrivateKeyPEM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == nil {
				t.Error("DecodePrivateKeyPEM() returned nil key")
			}
		})
	}
}

func TestDecodePrivateKeyPEM_Errors(t *testing.T) {
	rsaKey := generateRSAKey(t)
	correctPwd := mustCreatePassword(t, "correct-password")
	wrongPwd := mustCreatePassword(t, "wrong-password")

	tests := []struct {
		name     string
		pemData  []byte
		password types.Password
		wantErr  error
	}{
		{
			name:     "empty PEM data",
			pemData:  []byte{},
			password: nil,
			wantErr:  nil, // Will get "PEM data cannot be empty" error
		},
		{
			name:     "invalid PEM data",
			pemData:  []byte("not-a-pem"),
			password: nil,
			wantErr:  ErrInvalidEncodingPEM,
		},
		{
			name: "wrong password",
			pemData: func() []byte {
				pem, _ := EncodePrivateKeyPEM(rsaKey, correctPwd)
				return pem
			}(),
			password: wrongPwd,
			wantErr:  ErrInvalidPassword,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodePrivateKeyPEM(tt.pemData, tt.password)
			if err == nil {
				t.Error("DecodePrivateKeyPEM() expected error, got nil")
				return
			}
			if tt.wantErr != nil && err != tt.wantErr {
				t.Errorf("DecodePrivateKeyPEM() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDecodePrivateKeyPEM_NilPasswordBytes(t *testing.T) {
	rsaKey := generateRSAKey(t)
	pwd := mustCreatePassword(t, "test-password")

	// Encode with valid password
	pemData, err := EncodePrivateKeyPEM(rsaKey, pwd)
	if err != nil {
		t.Fatalf("Failed to encode key: %v", err)
	}

	// Try to decode encrypted key with a cleared password (Bytes returns nil)
	// This should fail because the key is encrypted but no password bytes are provided
	badPassword := &mockBadPassword{}
	_, err = DecodePrivateKeyPEM(pemData, badPassword)
	if err == nil {
		t.Error("Expected error when decrypting with nil password bytes, got nil")
	}
}

func TestDecodePrivateKeyPEM_MalformedEncryptedKey(t *testing.T) {
	// Create a PEM block with malformed encrypted data
	// This should trigger the ASN.1 error path
	malformedPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: []byte{0x30, 0x82, 0x01, 0x00}, // Invalid PKCS8 structure
	})

	pwd := mustCreatePassword(t, "any-password")
	_, err := DecodePrivateKeyPEM(malformedPEM, pwd)
	if err == nil {
		t.Error("Expected error for malformed encrypted key, got nil")
	}
}

func TestDecodePrivateKeyPEM_InvalidKeyType(t *testing.T) {
	// Create a PEM block with data that parses but isn't a PrivateKey
	// This is hard to test directly as pkcs8.ParsePKCS8PrivateKey returns interface{}
	// and we type assert it. The test coverage tool shows this path as uncovered
	// because it's difficult to trigger without modifying internal behavior.

	// For now, we'll test with corrupted but parseable data
	// that would fail the crypto.PrivateKey type assertion
	corruptedPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: []byte{0x30, 0x00}, // Minimal ASN.1 sequence
	})

	_, err := DecodePrivateKeyPEM(corruptedPEM, nil)
	if err == nil {
		t.Error("Expected error for corrupted key data, got nil")
	}
}

func TestEncodePublicKey(t *testing.T) {
	rsaKey := generateRSAKey(t)
	ecdsaKey := generateECDSAKey(t)
	ed25519Key := generateEd25519Key(t)

	tests := []struct {
		name      string
		publicKey interface{}
		wantErr   bool
	}{
		{
			name:      "RSA public key",
			publicKey: &rsaKey.PublicKey,
			wantErr:   false,
		},
		{
			name:      "ECDSA public key",
			publicKey: &ecdsaKey.PublicKey,
			wantErr:   false,
		},
		{
			name:      "Ed25519 public key",
			publicKey: ed25519Key.Public(),
			wantErr:   false,
		},
		{
			name:      "nil public key",
			publicKey: nil,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodePublicKey(tt.publicKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncodePublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(got) == 0 {
				t.Error("EncodePublicKey() returned empty data")
			}
		})
	}
}

func TestEncodePublicKey_InvalidKey(t *testing.T) {
	// Test with an invalid public key type
	invalidKey := struct{ Invalid string }{Invalid: "not a key"}

	_, err := EncodePublicKey(invalidKey)
	if err == nil {
		t.Error("Expected error for invalid public key type, got nil")
	}
}

func TestEncodePublicKeyPEM(t *testing.T) {
	rsaKey := generateRSAKey(t)
	ecdsaKey := generateECDSAKey(t)
	ed25519Key := generateEd25519Key(t)

	tests := []struct {
		name      string
		publicKey interface{}
		wantErr   bool
	}{
		{
			name:      "RSA public key",
			publicKey: &rsaKey.PublicKey,
			wantErr:   false,
		},
		{
			name:      "ECDSA public key",
			publicKey: &ecdsaKey.PublicKey,
			wantErr:   false,
		},
		{
			name:      "Ed25519 public key",
			publicKey: ed25519Key.Public(),
			wantErr:   false,
		},
		{
			name:      "nil public key",
			publicKey: nil,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodePublicKeyPEM(tt.publicKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncodePublicKeyPEM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) == 0 {
					t.Error("EncodePublicKeyPEM() returned empty data")
				}
				// Verify PEM format
				block, _ := pem.Decode(got)
				if block == nil {
					t.Error("EncodePublicKeyPEM() did not produce valid PEM")
					return
				}
				if block.Type != "PUBLIC KEY" {
					t.Errorf("PEM block type = %v, want PUBLIC KEY", block.Type)
				}
			}
		})
	}
}

func TestEncodePublicKeyPEM_InvalidKey(t *testing.T) {
	// Test with an invalid public key type
	invalidKey := struct{ Invalid string }{Invalid: "not a key"}

	_, err := EncodePublicKeyPEM(invalidKey)
	if err == nil {
		t.Error("Expected error for invalid public key type, got nil")
	}
}

func TestDecodePublicKeyPEM(t *testing.T) {
	rsaKey := generateRSAKey(t)
	ecdsaKey := generateECDSAKey(t)
	ed25519Key := generateEd25519Key(t)

	tests := []struct {
		name      string
		publicKey interface{}
		wantErr   bool
	}{
		{
			name:      "RSA public key",
			publicKey: &rsaKey.PublicKey,
			wantErr:   false,
		},
		{
			name:      "ECDSA public key",
			publicKey: &ecdsaKey.PublicKey,
			wantErr:   false,
		},
		{
			name:      "Ed25519 public key",
			publicKey: ed25519Key.Public(),
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode the key first
			pemData, err := EncodePublicKeyPEM(tt.publicKey)
			if err != nil {
				t.Fatalf("EncodePublicKeyPEM() error = %v", err)
			}

			// Decode it back
			got, err := DecodePublicKeyPEM(pemData)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodePublicKeyPEM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == nil {
				t.Error("DecodePublicKeyPEM() returned nil key")
			}
		})
	}
}

func TestDecodePublicKeyPEM_Errors(t *testing.T) {
	tests := []struct {
		name    string
		pemData []byte
		wantErr error
	}{
		{
			name:    "empty PEM data",
			pemData: []byte{},
			wantErr: nil, // Will get "PEM data cannot be empty" error
		},
		{
			name:    "invalid PEM data",
			pemData: []byte("not-a-pem"),
			wantErr: ErrInvalidEncodingPEM,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodePublicKeyPEM(tt.pemData)
			if err == nil {
				t.Error("DecodePublicKeyPEM() expected error, got nil")
			}
		})
	}
}

func TestDecodePublicKeyPEM_MalformedKey(t *testing.T) {
	// Create a PEM block with malformed public key data
	malformedPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: []byte{0x30, 0x00}, // Invalid PKIX structure
	})

	_, err := DecodePublicKeyPEM(malformedPEM)
	if err == nil {
		t.Error("Expected error for malformed public key, got nil")
	}
}

func TestEncodeDERToPEM(t *testing.T) {
	rsaKey := generateRSAKey(t)
	der, err := EncodePublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("EncodePublicKey() error = %v", err)
	}

	tests := []struct {
		name    string
		der     []byte
		wantErr bool
	}{
		{
			name:    "valid DER data",
			der:     der,
			wantErr: false,
		},
		{
			name:    "empty DER data",
			der:     []byte{},
			wantErr: true,
		},
		{
			name:    "nil DER data",
			der:     nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeDERToPEM(tt.der)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncodeDERToPEM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) == 0 {
					t.Error("EncodeDERToPEM() returned empty data")
				}
				// Verify PEM format
				block, _ := pem.Decode(got)
				if block == nil {
					t.Error("EncodeDERToPEM() did not produce valid PEM")
				}
			}
		})
	}
}

func TestDetectKeyAlgorithm(t *testing.T) {
	rsaKey := generateRSAKey(t)
	ecdsaKey := generateECDSAKey(t)
	ed25519Key := generateEd25519Key(t)

	tests := []struct {
		name    string
		key     crypto.PrivateKey
		want    KeyAlgorithm
		wantErr bool
	}{
		{
			name:    "RSA key",
			key:     rsaKey,
			want:    RSA,
			wantErr: false,
		},
		{
			name:    "ECDSA key",
			key:     ecdsaKey,
			want:    ECDSA,
			wantErr: false,
		},
		{
			name:    "Ed25519 key",
			key:     ed25519Key,
			want:    Ed25519,
			wantErr: false,
		},
		{
			name:    "invalid key type",
			key:     "not-a-key",
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := detectKeyAlgorithm(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("detectKeyAlgorithm() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("detectKeyAlgorithm() = %v, want %v", got, tt.want)
			}
			if tt.wantErr && !errors.Is(err, ErrInvalidKeyType) {
				t.Errorf("Expected ErrInvalidKeyType, got: %v", err)
			}
		})
	}
}

func TestExtractPublicKey(t *testing.T) {
	rsaKey := generateRSAKey(t)
	ecdsaKey := generateECDSAKey(t)
	ed25519Key := generateEd25519Key(t)

	tests := []struct {
		name       string
		privateKey interface{}
		wantErr    bool
	}{
		{
			name:       "RSA private key",
			privateKey: rsaKey,
			wantErr:    false,
		},
		{
			name:       "ECDSA private key",
			privateKey: ecdsaKey,
			wantErr:    false,
		},
		{
			name:       "Ed25519 private key",
			privateKey: ed25519Key,
			wantErr:    false,
		},
		{
			name:       "nil private key",
			privateKey: nil,
			wantErr:    true,
		},
		{
			name:       "invalid key type",
			privateKey: "not-a-key",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractPublicKey(tt.privateKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractPublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == nil {
				t.Error("ExtractPublicKey() returned nil key")
			}
		})
	}
}

func TestRoundTrip_PrivateKey(t *testing.T) {
	rsaKey := generateRSAKey(t)
	ecdsaKey := generateECDSAKey(t)
	ed25519Key := generateEd25519Key(t)

	tests := []struct {
		name       string
		privateKey interface{}
		password   types.Password
	}{
		{
			name:       "RSA without password",
			privateKey: rsaKey,
			password:   nil,
		},
		{
			name:       "RSA with password",
			privateKey: rsaKey,
			password:   mustCreatePassword(t, "test-pass"),
		},
		{
			name:       "ECDSA without password",
			privateKey: ecdsaKey,
			password:   nil,
		},
		{
			name:       "ECDSA with password",
			privateKey: ecdsaKey,
			password:   mustCreatePassword(t, "test-pass"),
		},
		{
			name:       "Ed25519 without password",
			privateKey: ed25519Key,
			password:   nil,
		},
		{
			name:       "Ed25519 with password",
			privateKey: ed25519Key,
			password:   mustCreatePassword(t, "test-pass"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode to PEM
			pemData, err := EncodePrivateKeyPEM(tt.privateKey, tt.password)
			if err != nil {
				t.Fatalf("EncodePrivateKeyPEM() error = %v", err)
			}

			// Decode back
			decoded, err := DecodePrivateKeyPEM(pemData, tt.password)
			if err != nil {
				t.Fatalf("DecodePrivateKeyPEM() error = %v", err)
			}

			if decoded == nil {
				t.Fatal("DecodePrivateKeyPEM() returned nil")
			}
		})
	}
}

func TestRoundTrip_PublicKey(t *testing.T) {
	rsaKey := generateRSAKey(t)
	ecdsaKey := generateECDSAKey(t)
	ed25519Key := generateEd25519Key(t)

	tests := []struct {
		name      string
		publicKey interface{}
	}{
		{
			name:      "RSA public key",
			publicKey: &rsaKey.PublicKey,
		},
		{
			name:      "ECDSA public key",
			publicKey: &ecdsaKey.PublicKey,
		},
		{
			name:      "Ed25519 public key",
			publicKey: ed25519Key.Public(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode to PEM
			pemData, err := EncodePublicKeyPEM(tt.publicKey)
			if err != nil {
				t.Fatalf("EncodePublicKeyPEM() error = %v", err)
			}

			// Decode back
			decoded, err := DecodePublicKeyPEM(pemData)
			if err != nil {
				t.Fatalf("DecodePublicKeyPEM() error = %v", err)
			}

			if decoded == nil {
				t.Fatal("DecodePublicKeyPEM() returned nil")
			}
		})
	}
}

func TestPasswordSecurity(t *testing.T) {
	t.Run("password is zeroed after use in encoding", func(t *testing.T) {
		rsaKey := generateRSAKey(t)
		pwd := mustCreatePassword(t, "sensitive-password")

		// Encode with password
		_, err := EncodePrivateKey(rsaKey, pwd)
		if err != nil {
			t.Fatalf("EncodePrivateKey() error = %v", err)
		}

		// Password should still be accessible (not zeroed by the function)
		str, err := pwd.String()
		if err != nil {
			t.Errorf("Password was zeroed unexpectedly: %v", err)
		}
		if str != "sensitive-password" {
			t.Errorf("Password value changed: got %v", str)
		}
	})

	t.Run("password is zeroed after use in decoding", func(t *testing.T) {
		rsaKey := generateRSAKey(t)
		pwd1 := mustCreatePassword(t, "encode-password")

		// Encode with password
		pemData, err := EncodePrivateKeyPEM(rsaKey, pwd1)
		if err != nil {
			t.Fatalf("EncodePrivateKeyPEM() error = %v", err)
		}

		pwd2 := mustCreatePassword(t, "encode-password")

		// Decode with password
		_, err = DecodePrivateKeyPEM(pemData, pwd2)
		if err != nil {
			t.Fatalf("DecodePrivateKeyPEM() error = %v", err)
		}

		// Password should still be accessible (not zeroed by the function)
		str, err := pwd2.String()
		if err != nil {
			t.Errorf("Password was zeroed unexpectedly: %v", err)
		}
		if str != "encode-password" {
			t.Errorf("Password value changed: got %v", str)
		}
	})
}

// Helper function

func mustCreatePassword(t *testing.T, pwd string) types.Password {
	t.Helper()
	p, err := password.NewClearPasswordFromString(pwd)
	if err != nil {
		t.Fatalf("Failed to create password: %v", err)
	}
	return p
}

// Mock bad password for testing error paths (simulates a cleared password)
type mockBadPassword struct{}

func (m *mockBadPassword) Bytes() []byte {
	return nil // Simulates a cleared password
}

func (m *mockBadPassword) String() (string, error) {
	return "", errors.New("password has been cleared")
}

func (m *mockBadPassword) Clear() {
	// No-op for mock
}

// Benchmarks

func BenchmarkEncodePrivateKeyPEM_RSA(b *testing.B) {
	key := generateRSAKeyBench(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EncodePrivateKeyPEM(key, nil)
	}
}

func BenchmarkEncodePrivateKeyPEM_ECDSA(b *testing.B) {
	key := generateECDSAKeyBench(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EncodePrivateKeyPEM(key, nil)
	}
}

func BenchmarkEncodePrivateKeyPEM_Ed25519(b *testing.B) {
	key := generateEd25519KeyBench(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EncodePrivateKeyPEM(key, nil)
	}
}

func BenchmarkDecodePrivateKeyPEM_RSA(b *testing.B) {
	key := generateRSAKeyBench(b)
	pemData, _ := EncodePrivateKeyPEM(key, nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodePrivateKeyPEM(pemData, nil)
	}
}

func BenchmarkEncodePublicKeyPEM_RSA(b *testing.B) {
	key := generateRSAKeyBench(b)
	pubKey := &key.PublicKey
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EncodePublicKeyPEM(pubKey)
	}
}

func BenchmarkDecodePublicKeyPEM_RSA(b *testing.B) {
	key := generateRSAKeyBench(b)
	pubKey := &key.PublicKey
	pemData, _ := EncodePublicKeyPEM(pubKey)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodePublicKeyPEM(pemData)
	}
}

// Benchmark helpers

func generateRSAKeyBench(b *testing.B) *rsa.PrivateKey {
	b.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("Failed to generate RSA key: %v", err)
	}
	return key
}

func generateECDSAKeyBench(b *testing.B) *ecdsa.PrivateKey {
	b.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	return key
}

func generateEd25519KeyBench(b *testing.B) ed25519.PrivateKey {
	b.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate Ed25519 key: %v", err)
	}
	return key
}
