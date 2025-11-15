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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestEncodePKCS8_RSA(t *testing.T) {
	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Test without password
	t.Run("Unencrypted", func(t *testing.T) {
		der, err := EncodePKCS8(privateKey, nil)
		if err != nil {
			t.Fatalf("EncodePKCS8 failed: %v", err)
		}
		if len(der) == 0 {
			t.Fatal("EncodePKCS8 returned empty data")
		}

		// Verify we can decode it back
		decoded, err := DecodePKCS8(der, nil)
		if err != nil {
			t.Fatalf("DecodePKCS8 failed: %v", err)
		}

		decodedRSA, ok := decoded.(*rsa.PrivateKey)
		if !ok {
			t.Fatal("Decoded key is not *rsa.PrivateKey")
		}

		// Verify key equality
		if decodedRSA.N.Cmp(privateKey.N) != 0 {
			t.Fatal("Decoded key N doesn't match original")
		}
	})

	// Test with password
	t.Run("Encrypted", func(t *testing.T) {
		password := []byte("test-password-123")
		der, err := EncodePKCS8(privateKey, password)
		if err != nil {
			t.Fatalf("EncodePKCS8 failed: %v", err)
		}
		if len(der) == 0 {
			t.Fatal("EncodePKCS8 returned empty data")
		}

		// Verify we can decode it back with correct password
		decoded, err := DecodePKCS8(der, password)
		if err != nil {
			t.Fatalf("DecodePKCS8 failed: %v", err)
		}

		decodedRSA, ok := decoded.(*rsa.PrivateKey)
		if !ok {
			t.Fatal("Decoded key is not *rsa.PrivateKey")
		}

		if decodedRSA.N.Cmp(privateKey.N) != 0 {
			t.Fatal("Decoded key doesn't match original")
		}
	})

	// Test wrong password
	t.Run("WrongPassword", func(t *testing.T) {
		password := []byte("test-password-123")
		wrongPassword := []byte("wrong-password")

		der, err := EncodePKCS8(privateKey, password)
		if err != nil {
			t.Fatalf("EncodePKCS8 failed: %v", err)
		}

		_, err = DecodePKCS8(der, wrongPassword)
		if err == nil {
			t.Fatal("DecodePKCS8 should have failed with wrong password")
		}
		if err != ErrInvalidPassword {
			t.Fatalf("Expected ErrInvalidPassword, got: %v", err)
		}
	})
}

func TestEncodePKCS8_ECDSA(t *testing.T) {
	// Generate ECDSA key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// Test without password
	t.Run("Unencrypted", func(t *testing.T) {
		der, err := EncodePKCS8(privateKey, nil)
		if err != nil {
			t.Fatalf("EncodePKCS8 failed: %v", err)
		}
		if len(der) == 0 {
			t.Fatal("EncodePKCS8 returned empty data")
		}

		decoded, err := DecodePKCS8(der, nil)
		if err != nil {
			t.Fatalf("DecodePKCS8 failed: %v", err)
		}

		decodedECDSA, ok := decoded.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatal("Decoded key is not *ecdsa.PrivateKey")
		}

		if decodedECDSA.X.Cmp(privateKey.X) != 0 || decodedECDSA.Y.Cmp(privateKey.Y) != 0 {
			t.Fatal("Decoded key doesn't match original")
		}
	})

	// Test with password
	t.Run("Encrypted", func(t *testing.T) {
		password := []byte("ecdsa-password")
		der, err := EncodePKCS8(privateKey, password)
		if err != nil {
			t.Fatalf("EncodePKCS8 failed: %v", err)
		}

		decoded, err := DecodePKCS8(der, password)
		if err != nil {
			t.Fatalf("DecodePKCS8 failed: %v", err)
		}

		decodedECDSA, ok := decoded.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatal("Decoded key is not *ecdsa.PrivateKey")
		}

		if decodedECDSA.X.Cmp(privateKey.X) != 0 {
			t.Fatal("Decoded key doesn't match original")
		}
	})
}

func TestEncodePKCS8_Ed25519(t *testing.T) {
	// Generate Ed25519 key
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	// Test without password
	t.Run("Unencrypted", func(t *testing.T) {
		der, err := EncodePKCS8(privateKey, nil)
		if err != nil {
			t.Fatalf("EncodePKCS8 failed: %v", err)
		}
		if len(der) == 0 {
			t.Fatal("EncodePKCS8 returned empty data")
		}

		decoded, err := DecodePKCS8(der, nil)
		if err != nil {
			t.Fatalf("DecodePKCS8 failed: %v", err)
		}

		decodedEd25519, ok := decoded.(ed25519.PrivateKey)
		if !ok {
			t.Fatal("Decoded key is not ed25519.PrivateKey")
		}

		// Verify public keys match
		if !decodedEd25519.Public().(ed25519.PublicKey).Equal(publicKey) {
			t.Fatal("Decoded key doesn't match original")
		}
	})

	// Test with password
	t.Run("Encrypted", func(t *testing.T) {
		password := []byte("ed25519-password")
		der, err := EncodePKCS8(privateKey, password)
		if err != nil {
			t.Fatalf("EncodePKCS8 failed: %v", err)
		}

		decoded, err := DecodePKCS8(der, password)
		if err != nil {
			t.Fatalf("DecodePKCS8 failed: %v", err)
		}

		decodedEd25519, ok := decoded.(ed25519.PrivateKey)
		if !ok {
			t.Fatal("Decoded key is not ed25519.PrivateKey")
		}

		if !decodedEd25519.Public().(ed25519.PublicKey).Equal(publicKey) {
			t.Fatal("Decoded key doesn't match original")
		}
	})
}

func TestEncodePKCS8_Errors(t *testing.T) {
	t.Run("NilPrivateKey", func(t *testing.T) {
		_, err := EncodePKCS8(nil, nil)
		if err != ErrInvalidPrivateKey {
			t.Fatalf("Expected ErrInvalidPrivateKey, got: %v", err)
		}
	})
}

func TestDecodePKCS8_Errors(t *testing.T) {
	t.Run("EmptyData", func(t *testing.T) {
		_, err := DecodePKCS8(nil, nil)
		if err != ErrInvalidData {
			t.Fatalf("Expected ErrInvalidData, got: %v", err)
		}

		_, err = DecodePKCS8([]byte{}, nil)
		if err != ErrInvalidData {
			t.Fatalf("Expected ErrInvalidData, got: %v", err)
		}
	})

	t.Run("InvalidData", func(t *testing.T) {
		_, err := DecodePKCS8([]byte("invalid data"), nil)
		if err == nil {
			t.Fatal("DecodePKCS8 should have failed with invalid data")
		}
	})
}

func TestEncodePublicKeyPKIX(t *testing.T) {
	// Test RSA
	t.Run("RSA", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		der, err := EncodePublicKeyPKIX(privateKey.Public())
		if err != nil {
			t.Fatalf("EncodePublicKeyPKIX failed: %v", err)
		}
		if len(der) == 0 {
			t.Fatal("EncodePublicKeyPKIX returned empty data")
		}

		decoded, err := DecodePublicKeyPKIX(der)
		if err != nil {
			t.Fatalf("DecodePublicKeyPKIX failed: %v", err)
		}

		decodedRSA, ok := decoded.(*rsa.PublicKey)
		if !ok {
			t.Fatal("Decoded key is not *rsa.PublicKey")
		}

		if decodedRSA.N.Cmp(privateKey.N) != 0 {
			t.Fatal("Decoded public key doesn't match original")
		}
	})

	// Test ECDSA
	t.Run("ECDSA", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key: %v", err)
		}

		der, err := EncodePublicKeyPKIX(privateKey.Public())
		if err != nil {
			t.Fatalf("EncodePublicKeyPKIX failed: %v", err)
		}

		decoded, err := DecodePublicKeyPKIX(der)
		if err != nil {
			t.Fatalf("DecodePublicKeyPKIX failed: %v", err)
		}

		decodedECDSA, ok := decoded.(*ecdsa.PublicKey)
		if !ok {
			t.Fatal("Decoded key is not *ecdsa.PublicKey")
		}

		if decodedECDSA.X.Cmp(privateKey.X) != 0 {
			t.Fatal("Decoded public key doesn't match original")
		}
	})

	// Test Ed25519
	t.Run("Ed25519", func(t *testing.T) {
		publicKey, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 key: %v", err)
		}

		der, err := EncodePublicKeyPKIX(publicKey)
		if err != nil {
			t.Fatalf("EncodePublicKeyPKIX failed: %v", err)
		}

		decoded, err := DecodePublicKeyPKIX(der)
		if err != nil {
			t.Fatalf("DecodePublicKeyPKIX failed: %v", err)
		}

		decodedEd25519, ok := decoded.(ed25519.PublicKey)
		if !ok {
			t.Fatal("Decoded key is not ed25519.PublicKey")
		}

		if !decodedEd25519.Equal(publicKey) {
			t.Fatal("Decoded public key doesn't match original")
		}
	})
}

func TestEncodePublicKeyPKIX_Errors(t *testing.T) {
	t.Run("NilPublicKey", func(t *testing.T) {
		_, err := EncodePublicKeyPKIX(nil)
		if err != ErrInvalidPublicKey {
			t.Fatalf("Expected ErrInvalidPublicKey, got: %v", err)
		}
	})
}

func TestDecodePublicKeyPKIX_Errors(t *testing.T) {
	t.Run("EmptyData", func(t *testing.T) {
		_, err := DecodePublicKeyPKIX(nil)
		if err != ErrInvalidData {
			t.Fatalf("Expected ErrInvalidData, got: %v", err)
		}

		_, err = DecodePublicKeyPKIX([]byte{})
		if err != ErrInvalidData {
			t.Fatalf("Expected ErrInvalidData, got: %v", err)
		}
	})

	t.Run("InvalidData", func(t *testing.T) {
		_, err := DecodePublicKeyPKIX([]byte("invalid data"))
		if err == nil {
			t.Fatal("DecodePublicKeyPKIX should have failed with invalid data")
		}
	})
}
