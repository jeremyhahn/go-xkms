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
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// Helper function to generate a test certificate
func generateTestCertificate(t *testing.T, privateKey interface{}) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	var publicKey interface{}
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		publicKey = &key.PublicKey
	case *ecdsa.PrivateKey:
		publicKey = &key.PublicKey
	case ed25519.PrivateKey:
		publicKey = key.Public()
	default:
		t.Fatalf("Unsupported key type: %T", privateKey)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

func TestEncodePrivateKeyPEM_RSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Test unencrypted
	t.Run("Unencrypted", func(t *testing.T) {
		pemData, err := EncodePrivateKeyPEM(privateKey, x509.RSA, nil)
		if err != nil {
			t.Fatalf("EncodePrivateKeyPEM failed: %v", err)
		}
		if len(pemData) == 0 {
			t.Fatal("EncodePrivateKeyPEM returned empty data")
		}

		// Verify PEM contains RSA PRIVATE KEY block type
		if !contains(string(pemData), PEMTypeRSAPrivateKey) {
			t.Fatalf("Expected PEM type %s, got: %s", PEMTypeRSAPrivateKey, string(pemData))
		}

		// Decode and verify
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

	// Test encrypted
	t.Run("Encrypted", func(t *testing.T) {
		password := []byte("test-password")
		pemData, err := EncodePrivateKeyPEM(privateKey, x509.RSA, password)
		if err != nil {
			t.Fatalf("EncodePrivateKeyPEM failed: %v", err)
		}
		if len(pemData) == 0 {
			t.Fatal("EncodePrivateKeyPEM returned empty data")
		}

		// Verify PEM contains ENCRYPTED PRIVATE KEY block type
		if !contains(string(pemData), PEMTypeEncryptedPrivateKey) {
			t.Fatalf("Expected PEM type %s, got: %s", PEMTypeEncryptedPrivateKey, string(pemData))
		}

		// Decode and verify
		decoded, err := DecodePrivateKeyPEM(pemData, password)
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
}

func TestEncodePrivateKeyPEM_ECDSA(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// Test unencrypted
	t.Run("Unencrypted", func(t *testing.T) {
		pemData, err := EncodePrivateKeyPEM(privateKey, x509.ECDSA, nil)
		if err != nil {
			t.Fatalf("EncodePrivateKeyPEM failed: %v", err)
		}
		if len(pemData) == 0 {
			t.Fatal("EncodePrivateKeyPEM returned empty data")
		}

		// Verify PEM contains EC PRIVATE KEY block type
		if !contains(string(pemData), PEMTypeECPrivateKey) {
			t.Fatalf("Expected PEM type %s", PEMTypeECPrivateKey)
		}

		// Decode and verify
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

	// Test encrypted
	t.Run("Encrypted", func(t *testing.T) {
		password := []byte("ecdsa-password")
		pemData, err := EncodePrivateKeyPEM(privateKey, x509.ECDSA, password)
		if err != nil {
			t.Fatalf("EncodePrivateKeyPEM failed: %v", err)
		}

		// Verify PEM contains ENCRYPTED PRIVATE KEY block type
		if !contains(string(pemData), PEMTypeEncryptedPrivateKey) {
			t.Fatalf("Expected PEM type %s", PEMTypeEncryptedPrivateKey)
		}

		// Decode and verify
		decoded, err := DecodePrivateKeyPEM(pemData, password)
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

func TestEncodePrivateKeyPEM_Ed25519(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	// Test unencrypted
	t.Run("Unencrypted", func(t *testing.T) {
		pemData, err := EncodePrivateKeyPEM(privateKey, x509.Ed25519, nil)
		if err != nil {
			t.Fatalf("EncodePrivateKeyPEM failed: %v", err)
		}
		if len(pemData) == 0 {
			t.Fatal("EncodePrivateKeyPEM returned empty data")
		}

		// Verify PEM contains PRIVATE KEY block type (Ed25519 uses generic type)
		if !contains(string(pemData), PEMTypePrivateKey) {
			t.Fatalf("Expected PEM type %s", PEMTypePrivateKey)
		}

		// Decode and verify
		decoded, err := DecodePrivateKeyPEM(pemData, nil)
		if err != nil {
			t.Fatalf("DecodePrivateKeyPEM failed: %v", err)
		}

		decodedEd25519, ok := decoded.(ed25519.PrivateKey)
		if !ok {
			t.Fatal("Decoded key is not ed25519.PrivateKey")
		}

		if !decodedEd25519.Public().(ed25519.PublicKey).Equal(publicKey) {
			t.Fatal("Decoded key doesn't match original")
		}
	})

	// Test encrypted
	t.Run("Encrypted", func(t *testing.T) {
		password := []byte("ed25519-password")
		pemData, err := EncodePrivateKeyPEM(privateKey, x509.Ed25519, password)
		if err != nil {
			t.Fatalf("EncodePrivateKeyPEM failed: %v", err)
		}

		// Verify PEM contains ENCRYPTED PRIVATE KEY block type
		if !contains(string(pemData), PEMTypeEncryptedPrivateKey) {
			t.Fatalf("Expected PEM type %s", PEMTypeEncryptedPrivateKey)
		}

		// Decode and verify
		decoded, err := DecodePrivateKeyPEM(pemData, password)
		if err != nil {
			t.Fatalf("DecodePrivateKeyPEM failed: %v", err)
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

func TestEncodePrivateKeyPEM_Errors(t *testing.T) {
	t.Run("NilPrivateKey", func(t *testing.T) {
		_, err := EncodePrivateKeyPEM(nil, x509.RSA, nil)
		if err != ErrInvalidPrivateKey {
			t.Fatalf("Expected ErrInvalidPrivateKey, got: %v", err)
		}
	})
}

func TestDecodePrivateKeyPEM_Errors(t *testing.T) {
	t.Run("EmptyData", func(t *testing.T) {
		_, err := DecodePrivateKeyPEM(nil, nil)
		if err != ErrInvalidData {
			t.Fatalf("Expected ErrInvalidData, got: %v", err)
		}

		_, err = DecodePrivateKeyPEM([]byte{}, nil)
		if err != ErrInvalidData {
			t.Fatalf("Expected ErrInvalidData, got: %v", err)
		}
	})

	t.Run("InvalidPEM", func(t *testing.T) {
		_, err := DecodePrivateKeyPEM([]byte("not a valid PEM"), nil)
		if err != ErrInvalidPEMEncoding {
			t.Fatalf("Expected ErrInvalidPEMEncoding, got: %v", err)
		}
	})

	t.Run("WrongPassword", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		password := []byte("correct-password")
		pemData, err := EncodePrivateKeyPEM(privateKey, x509.RSA, password)
		if err != nil {
			t.Fatalf("EncodePrivateKeyPEM failed: %v", err)
		}

		_, err = DecodePrivateKeyPEM(pemData, []byte("wrong-password"))
		if err == nil {
			t.Fatal("DecodePrivateKeyPEM should have failed with wrong password")
		}
		if err != ErrInvalidPassword {
			t.Fatalf("Expected ErrInvalidPassword, got: %v", err)
		}
	})
}

func TestEncodePublicKeyPEM(t *testing.T) {
	// Test RSA
	t.Run("RSA", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		pemData, err := EncodePublicKeyPEM(&privateKey.PublicKey)
		if err != nil {
			t.Fatalf("EncodePublicKeyPEM failed: %v", err)
		}
		if len(pemData) == 0 {
			t.Fatal("EncodePublicKeyPEM returned empty data")
		}

		// Verify PEM contains PUBLIC KEY block type
		if !contains(string(pemData), PEMTypePublicKey) {
			t.Fatalf("Expected PEM type %s", PEMTypePublicKey)
		}

		// Decode and verify
		decoded, err := DecodePublicKeyPEM(pemData)
		if err != nil {
			t.Fatalf("DecodePublicKeyPEM failed: %v", err)
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

		pemData, err := EncodePublicKeyPEM(&privateKey.PublicKey)
		if err != nil {
			t.Fatalf("EncodePublicKeyPEM failed: %v", err)
		}

		// Decode and verify
		decoded, err := DecodePublicKeyPEM(pemData)
		if err != nil {
			t.Fatalf("DecodePublicKeyPEM failed: %v", err)
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

		pemData, err := EncodePublicKeyPEM(publicKey)
		if err != nil {
			t.Fatalf("EncodePublicKeyPEM failed: %v", err)
		}

		// Decode and verify
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

func TestEncodePublicKeyPEM_Errors(t *testing.T) {
	t.Run("NilPublicKey", func(t *testing.T) {
		_, err := EncodePublicKeyPEM(nil)
		if err != ErrInvalidPublicKey {
			t.Fatalf("Expected ErrInvalidPublicKey, got: %v", err)
		}
	})
}

func TestDecodePublicKeyPEM_Errors(t *testing.T) {
	t.Run("EmptyData", func(t *testing.T) {
		_, err := DecodePublicKeyPEM(nil)
		if err != ErrInvalidData {
			t.Fatalf("Expected ErrInvalidData, got: %v", err)
		}

		_, err = DecodePublicKeyPEM([]byte{})
		if err != ErrInvalidData {
			t.Fatalf("Expected ErrInvalidData, got: %v", err)
		}
	})

	t.Run("InvalidPEM", func(t *testing.T) {
		_, err := DecodePublicKeyPEM([]byte("not a valid PEM"))
		if err != ErrInvalidPEMEncoding {
			t.Fatalf("Expected ErrInvalidPEMEncoding, got: %v", err)
		}
	})
}

func TestEncodeCertificatePEM(t *testing.T) {
	// Test RSA certificate
	t.Run("RSACertificate", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		cert := generateTestCertificate(t, privateKey)

		pemData, err := EncodeCertificatePEM(cert)
		if err != nil {
			t.Fatalf("EncodeCertificatePEM failed: %v", err)
		}
		if len(pemData) == 0 {
			t.Fatal("EncodeCertificatePEM returned empty data")
		}

		// Verify PEM contains CERTIFICATE block type
		if !contains(string(pemData), PEMTypeCertificate) {
			t.Fatalf("Expected PEM type %s", PEMTypeCertificate)
		}

		// Decode and verify
		decoded, err := DecodeCertificatePEM(pemData)
		if err != nil {
			t.Fatalf("DecodeCertificatePEM failed: %v", err)
		}

		if decoded.Subject.CommonName != cert.Subject.CommonName {
			t.Fatal("Decoded certificate doesn't match original")
		}
	})

	// Test ECDSA certificate
	t.Run("ECDSACertificate", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key: %v", err)
		}

		cert := generateTestCertificate(t, privateKey)

		pemData, err := EncodeCertificatePEM(cert)
		if err != nil {
			t.Fatalf("EncodeCertificatePEM failed: %v", err)
		}

		// Decode and verify
		decoded, err := DecodeCertificatePEM(pemData)
		if err != nil {
			t.Fatalf("DecodeCertificatePEM failed: %v", err)
		}

		if decoded.Subject.CommonName != cert.Subject.CommonName {
			t.Fatal("Decoded certificate doesn't match original")
		}
	})

	// Test Ed25519 certificate
	t.Run("Ed25519Certificate", func(t *testing.T) {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 key: %v", err)
		}

		cert := generateTestCertificate(t, privateKey)

		pemData, err := EncodeCertificatePEM(cert)
		if err != nil {
			t.Fatalf("EncodeCertificatePEM failed: %v", err)
		}

		// Decode and verify
		decoded, err := DecodeCertificatePEM(pemData)
		if err != nil {
			t.Fatalf("DecodeCertificatePEM failed: %v", err)
		}

		if decoded.Subject.CommonName != cert.Subject.CommonName {
			t.Fatal("Decoded certificate doesn't match original")
		}
	})
}

func TestEncodeCertificatePEM_Errors(t *testing.T) {
	t.Run("NilCertificate", func(t *testing.T) {
		_, err := EncodeCertificatePEM(nil)
		if err != ErrInvalidCertificate {
			t.Fatalf("Expected ErrInvalidCertificate, got: %v", err)
		}
	})
}

func TestDecodeCertificatePEM_Errors(t *testing.T) {
	t.Run("EmptyData", func(t *testing.T) {
		_, err := DecodeCertificatePEM(nil)
		if err != ErrInvalidData {
			t.Fatalf("Expected ErrInvalidData, got: %v", err)
		}

		_, err = DecodeCertificatePEM([]byte{})
		if err != ErrInvalidData {
			t.Fatalf("Expected ErrInvalidData, got: %v", err)
		}
	})

	t.Run("InvalidPEM", func(t *testing.T) {
		_, err := DecodeCertificatePEM([]byte("not a valid PEM"))
		if err != ErrInvalidPEMEncoding {
			t.Fatalf("Expected ErrInvalidPEMEncoding, got: %v", err)
		}
	})

	t.Run("InvalidCertificateData", func(t *testing.T) {
		// Create a PEM with invalid certificate data
		invalidPEM := `-----BEGIN CERTIFICATE-----
aW52YWxpZCBjZXJ0aWZpY2F0ZSBkYXRh
-----END CERTIFICATE-----
`
		_, err := DecodeCertificatePEM([]byte(invalidPEM))
		if err == nil {
			t.Fatal("DecodeCertificatePEM should have failed with invalid certificate data")
		}
	})
}

func TestEncodeCertificateChainPEM(t *testing.T) {
	t.Run("MultiCertificateChain", func(t *testing.T) {
		// Generate multiple certificates
		var certs []*x509.Certificate

		// Create 3 certificates
		for i := 0; i < 3; i++ {
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("Failed to generate RSA key: %v", err)
			}

			cert := generateTestCertificate(t, privateKey)
			certs = append(certs, cert)
		}

		pemData, err := EncodeCertificateChainPEM(certs)
		if err != nil {
			t.Fatalf("EncodeCertificateChainPEM failed: %v", err)
		}
		if len(pemData) == 0 {
			t.Fatal("EncodeCertificateChainPEM returned empty data")
		}

		// Decode and verify
		decoded, err := DecodeCertificateChainPEM(pemData)
		if err != nil {
			t.Fatalf("DecodeCertificateChainPEM failed: %v", err)
		}

		if len(decoded) != len(certs) {
			t.Fatalf("Expected %d certificates, got %d", len(certs), len(decoded))
		}

		for i := range certs {
			if decoded[i].Subject.CommonName != certs[i].Subject.CommonName {
				t.Fatalf("Certificate %d doesn't match original", i)
			}
		}
	})

	t.Run("SingleCertificateInChain", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		cert := generateTestCertificate(t, privateKey)
		certs := []*x509.Certificate{cert}

		pemData, err := EncodeCertificateChainPEM(certs)
		if err != nil {
			t.Fatalf("EncodeCertificateChainPEM failed: %v", err)
		}

		decoded, err := DecodeCertificateChainPEM(pemData)
		if err != nil {
			t.Fatalf("DecodeCertificateChainPEM failed: %v", err)
		}

		if len(decoded) != 1 {
			t.Fatalf("Expected 1 certificate, got %d", len(decoded))
		}
	})
}

func TestEncodeCertificateChainPEM_Errors(t *testing.T) {
	t.Run("EmptyChain", func(t *testing.T) {
		_, err := EncodeCertificateChainPEM(nil)
		if err != ErrInvalidCertificate {
			t.Fatalf("Expected ErrInvalidCertificate, got: %v", err)
		}

		_, err = EncodeCertificateChainPEM([]*x509.Certificate{})
		if err != ErrInvalidCertificate {
			t.Fatalf("Expected ErrInvalidCertificate, got: %v", err)
		}
	})

	t.Run("NilCertificateInChain", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		cert := generateTestCertificate(t, privateKey)
		certs := []*x509.Certificate{cert, nil}

		_, err = EncodeCertificateChainPEM(certs)
		if err != ErrInvalidCertificate {
			t.Fatalf("Expected ErrInvalidCertificate, got: %v", err)
		}
	})
}

func TestDecodeCertificateChainPEM_Errors(t *testing.T) {
	t.Run("EmptyData", func(t *testing.T) {
		_, err := DecodeCertificateChainPEM(nil)
		if err != ErrInvalidData {
			t.Fatalf("Expected ErrInvalidData, got: %v", err)
		}

		_, err = DecodeCertificateChainPEM([]byte{})
		if err != ErrInvalidData {
			t.Fatalf("Expected ErrInvalidData, got: %v", err)
		}
	})

	t.Run("InvalidPEM", func(t *testing.T) {
		_, err := DecodeCertificateChainPEM([]byte("not a valid PEM"))
		if err != ErrInvalidPEMEncoding {
			t.Fatalf("Expected ErrInvalidPEMEncoding, got: %v", err)
		}
	})

	t.Run("InvalidCertificateInChain", func(t *testing.T) {
		// Create a PEM with one valid and one invalid certificate
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		cert := generateTestCertificate(t, privateKey)
		validPEM, err := EncodeCertificatePEM(cert)
		if err != nil {
			t.Fatalf("Failed to encode certificate: %v", err)
		}

		invalidPEM := `-----BEGIN CERTIFICATE-----
aW52YWxpZCBjZXJ0aWZpY2F0ZSBkYXRh
-----END CERTIFICATE-----
`
		chainPEM := append(validPEM, []byte(invalidPEM)...)

		_, err = DecodeCertificateChainPEM(chainPEM)
		if err == nil {
			t.Fatal("DecodeCertificateChainPEM should have failed with invalid certificate in chain")
		}
	})
}

func TestGetPEMBlockType(t *testing.T) {
	// Test all combinations of algorithms and encryption
	tests := []struct {
		name      string
		algorithm x509.PublicKeyAlgorithm
		password  []byte
		expected  string
	}{
		{
			name:      "RSA unencrypted",
			algorithm: x509.RSA,
			password:  nil,
			expected:  PEMTypeRSAPrivateKey,
		},
		{
			name:      "RSA encrypted",
			algorithm: x509.RSA,
			password:  []byte("password"),
			expected:  PEMTypeEncryptedPrivateKey,
		},
		{
			name:      "ECDSA unencrypted",
			algorithm: x509.ECDSA,
			password:  nil,
			expected:  PEMTypeECPrivateKey,
		},
		{
			name:      "ECDSA encrypted",
			algorithm: x509.ECDSA,
			password:  []byte("password"),
			expected:  PEMTypeEncryptedPrivateKey,
		},
		{
			name:      "Ed25519 unencrypted",
			algorithm: x509.Ed25519,
			password:  nil,
			expected:  PEMTypePrivateKey,
		},
		{
			name:      "Ed25519 encrypted",
			algorithm: x509.Ed25519,
			password:  []byte("password"),
			expected:  PEMTypeEncryptedPrivateKey,
		},
		{
			name:      "Unknown algorithm unencrypted",
			algorithm: x509.PublicKeyAlgorithm(999),
			password:  nil,
			expected:  PEMTypePrivateKey,
		},
		{
			name:      "Unknown algorithm encrypted",
			algorithm: x509.PublicKeyAlgorithm(999),
			password:  []byte("password"),
			expected:  PEMTypeEncryptedPrivateKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getPEMBlockType(tt.algorithm, tt.password)
			if result != tt.expected {
				t.Fatalf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestContainsHelper(t *testing.T) {
	t.Run("ContainsSubstring", func(t *testing.T) {
		if !contains("hello world", "world") {
			t.Fatal("Expected to find 'world' in 'hello world'")
		}
		if !contains("hello world", "hello") {
			t.Fatal("Expected to find 'hello' in 'hello world'")
		}
		if !contains("test", "test") {
			t.Fatal("Expected to find 'test' in 'test'")
		}
	})

	t.Run("DoesNotContainSubstring", func(t *testing.T) {
		if contains("hello world", "goodbye") {
			t.Fatal("Should not find 'goodbye' in 'hello world'")
		}
		if contains("test", "testing") {
			t.Fatal("Should not find 'testing' in 'test'")
		}
	})

	t.Run("EmptyStrings", func(t *testing.T) {
		if contains("", "test") {
			t.Fatal("Empty string should not contain 'test'")
		}
		if !contains("test", "") {
			t.Fatal("Any string contains empty substring")
		}
	})
}

func TestIndexOfHelper(t *testing.T) {
	t.Run("FindSubstring", func(t *testing.T) {
		if indexOf("hello world", "world") != 6 {
			t.Fatal("Expected index 6 for 'world' in 'hello world'")
		}
		if indexOf("hello world", "hello") != 0 {
			t.Fatal("Expected index 0 for 'hello' in 'hello world'")
		}
	})

	t.Run("SubstringNotFound", func(t *testing.T) {
		if indexOf("hello world", "goodbye") != -1 {
			t.Fatal("Expected -1 when substring not found")
		}
	})

	t.Run("EmptySubstring", func(t *testing.T) {
		if indexOf("hello", "") != 0 {
			t.Fatal("Expected 0 for empty substring")
		}
	})
}
