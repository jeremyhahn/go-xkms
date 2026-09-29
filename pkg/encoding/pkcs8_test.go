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

package encoding

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/youmark/pkcs8"
)

// pbes2Params and pbkdf2Params mirror the unexported ASN.1 shapes
// github.com/youmark/pkcs8 encodes a PBES2-wrapped key with (RFC 8018), so a
// test here can read back the iteration count actually written to a blob
// without a decryption round trip.
type pbes2Params struct {
	KeyDerivationFunc pkix.AlgorithmIdentifier
	EncryptionScheme  pkix.AlgorithmIdentifier
}

type pbkdf2Params struct {
	Salt           []byte
	IterationCount int
	PRF            pkix.AlgorithmIdentifier `asn1:"optional"`
}

type encryptedPrivateKeyInfo struct {
	EncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedData       []byte
}

// pbes2IterationCount extracts the PBKDF2 iteration count recorded in a
// PBES2-encrypted PKCS#8 DER blob.
func pbes2IterationCount(t *testing.T, der []byte) int {
	t.Helper()

	var privKey encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		t.Fatalf("asn1.Unmarshal(encryptedPrivateKeyInfo) error = %v", err)
	}

	var params pbes2Params
	if _, err := asn1.Unmarshal(privKey.EncryptionAlgorithm.Parameters.FullBytes, &params); err != nil {
		t.Fatalf("asn1.Unmarshal(pbes2Params) error = %v", err)
	}

	var kdfParams pbkdf2Params
	if _, err := asn1.Unmarshal(params.KeyDerivationFunc.Parameters.FullBytes, &kdfParams); err != nil {
		t.Fatalf("asn1.Unmarshal(pbkdf2Params) error = %v", err)
	}

	return kdfParams.IterationCount
}

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

		if !decodedECDSA.Equal(privateKey) {
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

		if !decodedECDSA.Equal(&privateKey.PublicKey) {
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

// TestEncodePKCS8_IterationCount proves EncodePKCS8 writes
// pbkdf2IterationCount (go-xkms#1286: OWASP's 2023 PBKDF2-SHA256
// recommendation), not this package's old default of 10,000, into the
// PBES2 parameters of the blob it produces.
func TestEncodePKCS8_IterationCount(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	der, err := EncodePKCS8(privateKey, []byte("test-password"))
	if err != nil {
		t.Fatalf("EncodePKCS8() error = %v", err)
	}

	got := pbes2IterationCount(t, der)
	if got != pbkdf2IterationCount {
		t.Errorf("PBES2 iteration count = %d, want %d", got, pbkdf2IterationCount)
	}
}

// TestDecodePKCS8_LegacyIterationCount proves a blob encrypted at this
// package's old iteration count (10,000, before go-xkms#1286 raised the
// default to 600,000) stays decryptable: PBES2 records its own iteration
// count in the blob, so DecodePKCS8 must read it from there rather than
// assume pbkdf2IterationCount.
func TestDecodePKCS8_LegacyIterationCount(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}

	legacyOpts := &pkcs8.Opts{
		Cipher: pkcs8.AES256CBC,
		KDFOpts: pkcs8.PBKDF2Opts{
			SaltSize:       16,
			IterationCount: 10000,
			HMACHash:       crypto.SHA256,
		},
	}
	password := []byte("legacy-password")
	der, err := pkcs8.MarshalPrivateKey(privateKey, password, legacyOpts)
	if err != nil {
		t.Fatalf("pkcs8.MarshalPrivateKey() error = %v", err)
	}
	if got := pbes2IterationCount(t, der); got != 10000 {
		t.Fatalf("test setup: PBES2 iteration count = %d, want 10000", got)
	}

	decoded, err := DecodePKCS8(der, password)
	if err != nil {
		t.Fatalf("DecodePKCS8() error = %v, want a legacy-iteration-count blob to stay decryptable", err)
	}

	decodedECDSA, ok := decoded.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("Decoded key is not *ecdsa.PrivateKey")
	}
	if !decodedECDSA.Equal(privateKey) {
		t.Fatal("Decoded key doesn't match original")
	}
}
