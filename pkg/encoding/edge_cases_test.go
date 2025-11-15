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
	"crypto/x509"
	"testing"
)

// TestPasswordErrorDetection tests the isPasswordError function
func TestPasswordErrorDetection(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		expected bool
	}{
		{
			name:     "NilError",
			errMsg:   "",
			expected: false,
		},
		{
			name:     "IncorrectPasswordError",
			errMsg:   "pkcs8: incorrect password",
			expected: true,
		},
		{
			name:     "ShortIncorrectPassword",
			errMsg:   "incorrect password",
			expected: true,
		},
		{
			name:     "ASN1StructureError",
			errMsg:   "asn1: structure error",
			expected: true,
		},
		{
			name:     "TagsDontMatch",
			errMsg:   "tags don't match",
			expected: true,
		},
		{
			name:     "OtherError",
			errMsg:   "some other error",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.errMsg != "" {
				err = &testError{msg: tt.errMsg}
			}
			result := isPasswordError(err)
			if result != tt.expected {
				t.Fatalf("Expected %v, got %v for error: %s", tt.expected, result, tt.errMsg)
			}
		})
	}
}

// testError is a simple error type for testing
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

// TestEncodeDecodeRoundTrips tests various encode/decode round trips
func TestEncodeDecodeRoundTrips(t *testing.T) {
	t.Run("RSA_2048", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		// Test with empty password (should be treated as no password)
		pemData, err := EncodePrivateKeyPEM(privateKey, x509.RSA, []byte{})
		if err != nil {
			t.Fatalf("EncodePrivateKeyPEM failed: %v", err)
		}

		decoded, err := DecodePrivateKeyPEM(pemData, []byte{})
		if err != nil {
			t.Fatalf("DecodePrivateKeyPEM failed: %v", err)
		}

		decodedRSA, ok := decoded.(*rsa.PrivateKey)
		if !ok {
			t.Fatal("Decoded key is not *rsa.PrivateKey")
		}

		if decodedRSA.N.Cmp(privateKey.N) != 0 {
			t.Fatal("Decoded key doesn't match original")
		}
	})

	t.Run("RSA_4096", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		pemData, err := EncodePrivateKeyPEM(privateKey, x509.RSA, nil)
		if err != nil {
			t.Fatalf("EncodePrivateKeyPEM failed: %v", err)
		}

		decoded, err := DecodePrivateKeyPEM(pemData, nil)
		if err != nil {
			t.Fatalf("DecodePrivateKeyPEM failed: %v", err)
		}

		decodedRSA, ok := decoded.(*rsa.PrivateKey)
		if !ok {
			t.Fatal("Decoded key is not *rsa.PrivateKey")
		}

		if decodedRSA.N.Cmp(privateKey.N) != 0 {
			t.Fatal("Decoded key doesn't match original")
		}
	})

	t.Run("ECDSA_P384", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key: %v", err)
		}

		pemData, err := EncodePrivateKeyPEM(privateKey, x509.ECDSA, []byte("password"))
		if err != nil {
			t.Fatalf("EncodePrivateKeyPEM failed: %v", err)
		}

		decoded, err := DecodePrivateKeyPEM(pemData, []byte("password"))
		if err != nil {
			t.Fatalf("DecodePrivateKeyPEM failed: %v", err)
		}

		decodedECDSA, ok := decoded.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatal("Decoded key is not *ecdsa.PrivateKey")
		}

		if decodedECDSA.X.Cmp(privateKey.X) != 0 {
			t.Fatal("Decoded key doesn't match original")
		}
	})

	t.Run("ECDSA_P521", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key: %v", err)
		}

		pemData, err := EncodePrivateKeyPEM(privateKey, x509.ECDSA, nil)
		if err != nil {
			t.Fatalf("EncodePrivateKeyPEM failed: %v", err)
		}

		decoded, err := DecodePrivateKeyPEM(pemData, nil)
		if err != nil {
			t.Fatalf("DecodePrivateKeyPEM failed: %v", err)
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

// TestPublicKeyEncodeDecodeRoundTrips tests public key encoding/decoding
func TestPublicKeyEncodeDecodeRoundTrips(t *testing.T) {
	t.Run("RSA_PublicKey_FromPrivate", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		// Test with public key from private key
		publicKey := &privateKey.PublicKey

		pemData, err := EncodePublicKeyPEM(publicKey)
		if err != nil {
			t.Fatalf("EncodePublicKeyPEM failed: %v", err)
		}

		decoded, err := DecodePublicKeyPEM(pemData)
		if err != nil {
			t.Fatalf("DecodePublicKeyPEM failed: %v", err)
		}

		decodedRSA, ok := decoded.(*rsa.PublicKey)
		if !ok {
			t.Fatal("Decoded key is not *rsa.PublicKey")
		}

		if decodedRSA.N.Cmp(publicKey.N) != 0 || decodedRSA.E != publicKey.E {
			t.Fatal("Decoded public key doesn't match original")
		}
	})

	t.Run("ECDSA_PublicKey_P256", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key: %v", err)
		}

		publicKey := &privateKey.PublicKey

		pemData, err := EncodePublicKeyPEM(publicKey)
		if err != nil {
			t.Fatalf("EncodePublicKeyPEM failed: %v", err)
		}

		decoded, err := DecodePublicKeyPEM(pemData)
		if err != nil {
			t.Fatalf("DecodePublicKeyPEM failed: %v", err)
		}

		decodedECDSA, ok := decoded.(*ecdsa.PublicKey)
		if !ok {
			t.Fatal("Decoded key is not *ecdsa.PublicKey")
		}

		if decodedECDSA.X.Cmp(publicKey.X) != 0 || decodedECDSA.Y.Cmp(publicKey.Y) != 0 {
			t.Fatal("Decoded public key doesn't match original")
		}
	})

	t.Run("Ed25519_PublicKey", func(t *testing.T) {
		publicKey, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 key: %v", err)
		}

		pemData, err := EncodePublicKeyPEM(publicKey)
		if err != nil {
			t.Fatalf("EncodePublicKeyPEM failed: %v", err)
		}

		decoded, err := DecodePublicKeyPEM(pemData)
		if err != nil {
			t.Fatalf("DecodePublicKeyPEM failed: %v", err)
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

// TestCertificateEdgeCases tests edge cases for certificate encoding/decoding
func TestCertificateEdgeCases(t *testing.T) {
	t.Run("MultipleCertificatesWithDifferentKeys", func(t *testing.T) {
		var certs []*x509.Certificate

		// RSA certificate
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}
		certs = append(certs, generateTestCertificate(t, rsaKey))

		// ECDSA certificate
		ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key: %v", err)
		}
		certs = append(certs, generateTestCertificate(t, ecdsaKey))

		// Ed25519 certificate
		_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 key: %v", err)
		}
		certs = append(certs, generateTestCertificate(t, ed25519Key))

		pemData, err := EncodeCertificateChainPEM(certs)
		if err != nil {
			t.Fatalf("EncodeCertificateChainPEM failed: %v", err)
		}

		decoded, err := DecodeCertificateChainPEM(pemData)
		if err != nil {
			t.Fatalf("DecodeCertificateChainPEM failed: %v", err)
		}

		if len(decoded) != len(certs) {
			t.Fatalf("Expected %d certificates, got %d", len(certs), len(decoded))
		}
	})
}

// TestStringHelperEdgeCases tests edge cases for string helper functions
func TestStringHelperEdgeCases(t *testing.T) {
	t.Run("ContainsWithSpecialCharacters", func(t *testing.T) {
		if !contains("test\nwith\nnewlines", "with") {
			t.Fatal("Should find 'with' in string with newlines")
		}
		if !contains("test\twith\ttabs", "with") {
			t.Fatal("Should find 'with' in string with tabs")
		}
	})

	t.Run("IndexOfAtBoundaries", func(t *testing.T) {
		// Test finding at the very end
		if indexOf("hello world", "world") != 6 {
			t.Fatal("Should find 'world' at position 6")
		}
		// Test finding at the very beginning
		if indexOf("hello world", "hello") != 0 {
			t.Fatal("Should find 'hello' at position 0")
		}
		// Test exact match
		if indexOf("test", "test") != 0 {
			t.Fatal("Should find exact match at position 0")
		}
	})

	t.Run("IndexOfWithLongStrings", func(t *testing.T) {
		longString := "this is a very long string with many words and characters that we want to search through"
		// The actual index is 47, not 50
		if indexOf(longString, "characters") != 47 {
			t.Fatalf("Expected index 47, got %d", indexOf(longString, "characters"))
		}
	})
}

// TestPKCS8EdgeCases tests edge cases for PKCS8 encoding/decoding
func TestPKCS8EdgeCases(t *testing.T) {
	t.Run("VeryLongPassword", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		// Use a very long password
		longPassword := make([]byte, 1000)
		for i := range longPassword {
			longPassword[i] = byte(i % 256)
		}

		der, err := EncodePKCS8(privateKey, longPassword)
		if err != nil {
			t.Fatalf("EncodePKCS8 failed: %v", err)
		}

		decoded, err := DecodePKCS8(der, longPassword)
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

	t.Run("SingleBytePassword", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key: %v", err)
		}

		password := []byte{0x42} // Single byte password

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
