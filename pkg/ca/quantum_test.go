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

package ca

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/quantum"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// generateTestMLDSAKey generates an ML-DSA key pair using the quantum backend.
func generateTestMLDSAKey(t *testing.T, algorithm types.QuantumAlgorithm) *quantum.MLDSAPrivateKey {
	t.Helper()

	store := storage.NewMemory()
	qb, err := quantum.New(store)
	if err != nil {
		t.Fatalf("Failed to create quantum backend: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:        "test-quantum-" + string(algorithm),
		StoreType: types.StoreQuantum,
		KeyType:   types.KeyTypeSigning,
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: algorithm,
		},
	}

	key, err := qb.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate ML-DSA key: %v", err)
	}

	mldsaKey, ok := key.(*quantum.MLDSAPrivateKey)
	if !ok {
		t.Fatalf("Expected *quantum.MLDSAPrivateKey, got %T", key)
	}

	return mldsaKey
}

// makeQuantumCACertTemplate creates a CA certificate template for testing.
func makeQuantumCACertTemplate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Quantum CA",
			Organization: []string{"Test Org"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
}

// makeQuantumLeafCertTemplate creates a leaf certificate template for testing.
func makeQuantumLeafCertTemplate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "Test Quantum Leaf",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
}

func TestSignCertificateWithQuantum_MLDSA44(t *testing.T) {
	caKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA44)
	template := makeQuantumCACertTemplate()

	// Self-signed CA certificate
	certDER, err := signCertificateWithQuantum(template, template, caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("signCertificateWithQuantum failed: %v", err)
	}

	if len(certDER) == 0 {
		t.Fatal("Expected non-empty certificate DER")
	}

	// Verify the certificate
	err = verifyQuantumCertificate(certDER, caKey.PublicKey)
	if err != nil {
		t.Fatalf("verifyQuantumCertificate failed: %v", err)
	}
}

func TestSignCertificateWithQuantum_MLDSA65(t *testing.T) {
	caKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA65)
	template := makeQuantumCACertTemplate()

	certDER, err := signCertificateWithQuantum(template, template, caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("signCertificateWithQuantum failed: %v", err)
	}

	if len(certDER) == 0 {
		t.Fatal("Expected non-empty certificate DER")
	}

	err = verifyQuantumCertificate(certDER, caKey.PublicKey)
	if err != nil {
		t.Fatalf("verifyQuantumCertificate failed: %v", err)
	}
}

func TestSignCertificateWithQuantum_MLDSA87(t *testing.T) {
	caKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA87)
	template := makeQuantumCACertTemplate()

	certDER, err := signCertificateWithQuantum(template, template, caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("signCertificateWithQuantum failed: %v", err)
	}

	if len(certDER) == 0 {
		t.Fatal("Expected non-empty certificate DER")
	}

	err = verifyQuantumCertificate(certDER, caKey.PublicKey)
	if err != nil {
		t.Fatalf("verifyQuantumCertificate failed: %v", err)
	}
}

func TestSignCertificateWithQuantum_CASignsLeaf(t *testing.T) {
	// Generate CA key and create self-signed CA cert
	caKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA65)
	caTemplate := makeQuantumCACertTemplate()

	caCertDER, err := signCertificateWithQuantum(caTemplate, caTemplate, caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	// We need a parsed "parent" cert for the issuer name. Since our custom
	// certs cannot be parsed by x509.ParseCertificate (unknown sig algo),
	// we use the template directly as the parent.
	leafKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA65)
	leafTemplate := makeQuantumLeafCertTemplate()

	// Sign the leaf with the CA key, using caTemplate as parent
	leafDER, err := signCertificateWithQuantum(leafTemplate, caTemplate, leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create leaf certificate: %v", err)
	}

	if len(leafDER) == 0 {
		t.Fatal("Expected non-empty leaf certificate DER")
	}

	// Verify the leaf cert was signed by the CA
	err = verifyQuantumCertificate(leafDER, caKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to verify leaf certificate: %v", err)
	}

	// Verify the CA cert is also valid
	err = verifyQuantumCertificate(caCertDER, caKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to verify CA certificate: %v", err)
	}
}

func TestSignCertificateWithQuantum_InvalidKey(t *testing.T) {
	template := makeQuantumCACertTemplate()

	t.Run("nil_template", func(t *testing.T) {
		caKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA65)
		_, err := signCertificateWithQuantum(nil, template, caKey.PublicKey, caKey)
		if err == nil {
			t.Fatal("Expected error for nil template")
		}
	})

	t.Run("nil_parent", func(t *testing.T) {
		caKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA65)
		_, err := signCertificateWithQuantum(template, nil, caKey.PublicKey, caKey)
		if err == nil {
			t.Fatal("Expected error for nil parent")
		}
	})

	t.Run("nil_private_key", func(t *testing.T) {
		caKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA65)
		_, err := signCertificateWithQuantum(template, template, caKey.PublicKey, nil)
		if err == nil {
			t.Fatal("Expected error for nil private key")
		}
	})

	t.Run("wrong_public_key_type", func(t *testing.T) {
		caKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA65)
		// Pass a non-quantum public key
		_, err := signCertificateWithQuantum(template, template, "not-a-public-key", caKey)
		if err == nil {
			t.Fatal("Expected error for wrong public key type")
		}
	})
}

func TestVerifyQuantumCertificate(t *testing.T) {
	// Test round-trip: sign and verify for each algorithm
	algorithms := []types.QuantumAlgorithm{
		types.QuantumAlgorithmMLDSA44,
		types.QuantumAlgorithmMLDSA65,
		types.QuantumAlgorithmMLDSA87,
	}

	for _, algo := range algorithms {
		t.Run(string(algo), func(t *testing.T) {
			caKey := generateTestMLDSAKey(t, algo)
			template := makeQuantumCACertTemplate()

			certDER, err := signCertificateWithQuantum(template, template, caKey.PublicKey, caKey)
			if err != nil {
				t.Fatalf("signCertificateWithQuantum failed: %v", err)
			}

			err = verifyQuantumCertificate(certDER, caKey.PublicKey)
			if err != nil {
				t.Fatalf("verifyQuantumCertificate failed: %v", err)
			}
		})
	}
}

func TestVerifyQuantumCertificate_Tampered(t *testing.T) {
	caKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA65)
	template := makeQuantumCACertTemplate()

	certDER, err := signCertificateWithQuantum(template, template, caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("signCertificateWithQuantum failed: %v", err)
	}

	// Tamper with the certificate by flipping bits near the end (in the signature)
	tamperedDER := make([]byte, len(certDER))
	copy(tamperedDER, certDER)
	// Flip a byte in the signature portion (near the end of the cert)
	if len(tamperedDER) > 100 {
		tamperedDER[len(tamperedDER)-50] ^= 0xFF
	}

	err = verifyQuantumCertificate(tamperedDER, caKey.PublicKey)
	if err == nil {
		t.Fatal("Expected verification to fail for tampered certificate")
	}
}

func TestVerifyQuantumCertificate_WrongKey(t *testing.T) {
	caKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA65)
	otherKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA65)
	template := makeQuantumCACertTemplate()

	certDER, err := signCertificateWithQuantum(template, template, caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("signCertificateWithQuantum failed: %v", err)
	}

	// Try to verify with a different key
	err = verifyQuantumCertificate(certDER, otherKey.PublicKey)
	if err == nil {
		t.Fatal("Expected verification to fail with wrong key")
	}
}

func TestVerifyQuantumCertificate_EmptyInput(t *testing.T) {
	caKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA65)

	err := verifyQuantumCertificate(nil, caKey.PublicKey)
	if err == nil {
		t.Fatal("Expected error for nil certificate data")
	}

	err = verifyQuantumCertificate([]byte{}, caKey.PublicKey)
	if err == nil {
		t.Fatal("Expected error for empty certificate data")
	}
}

func TestVerifyQuantumCertificate_NilPublicKey(t *testing.T) {
	caKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA65)
	template := makeQuantumCACertTemplate()

	certDER, err := signCertificateWithQuantum(template, template, caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("signCertificateWithQuantum failed: %v", err)
	}

	err = verifyQuantumCertificate(certDER, nil)
	if err == nil {
		t.Fatal("Expected error for nil public key")
	}
}

func TestVerifyQuantumCertificate_AlgorithmMismatch(t *testing.T) {
	// Sign with ML-DSA-65, verify with ML-DSA-44 key
	caKey65 := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA65)
	caKey44 := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA44)
	template := makeQuantumCACertTemplate()

	certDER, err := signCertificateWithQuantum(template, template, caKey65.PublicKey, caKey65)
	if err != nil {
		t.Fatalf("signCertificateWithQuantum failed: %v", err)
	}

	err = verifyQuantumCertificate(certDER, caKey44.PublicKey)
	if err == nil {
		t.Fatal("Expected error for algorithm mismatch")
	}
}

func TestQuantumAlgorithmOID(t *testing.T) {
	t.Run("valid_algorithms", func(t *testing.T) {
		testCases := []struct {
			algorithm string
			expected  string
		}{
			{"ML-DSA-44", "2.16.840.1.101.3.4.3.17"},
			{"ML-DSA-65", "2.16.840.1.101.3.4.3.18"},
			{"ML-DSA-87", "2.16.840.1.101.3.4.3.19"},
		}

		for _, tc := range testCases {
			oid, err := quantumAlgorithmOID(tc.algorithm)
			if err != nil {
				t.Errorf("quantumAlgorithmOID(%s) returned error: %v", tc.algorithm, err)
				continue
			}
			if oid.String() != tc.expected {
				t.Errorf("quantumAlgorithmOID(%s) = %s, want %s", tc.algorithm, oid.String(), tc.expected)
			}
		}
	})

	t.Run("invalid_algorithm", func(t *testing.T) {
		_, err := quantumAlgorithmOID("ML-DSA-999")
		if err == nil {
			t.Fatal("Expected error for invalid algorithm")
		}
		if _, ok := err.(*QuantumAlgorithmError); !ok {
			t.Fatalf("Expected *QuantumAlgorithmError, got %T", err)
		}
	})
}

func TestOIDToQuantumAlgorithm(t *testing.T) {
	t.Run("valid_OIDs", func(t *testing.T) {
		testCases := []struct {
			oid       []int
			algorithm string
		}{
			{[]int{2, 16, 840, 1, 101, 3, 4, 3, 17}, "ML-DSA-44"},
			{[]int{2, 16, 840, 1, 101, 3, 4, 3, 18}, "ML-DSA-65"},
			{[]int{2, 16, 840, 1, 101, 3, 4, 3, 19}, "ML-DSA-87"},
		}

		for _, tc := range testCases {
			algo, err := oidToQuantumAlgorithm(tc.oid)
			if err != nil {
				t.Errorf("oidToQuantumAlgorithm(%v) returned error: %v", tc.oid, err)
				continue
			}
			if algo != tc.algorithm {
				t.Errorf("oidToQuantumAlgorithm(%v) = %s, want %s", tc.oid, algo, tc.algorithm)
			}
		}
	})

	t.Run("invalid_OID", func(t *testing.T) {
		_, err := oidToQuantumAlgorithm([]int{1, 2, 3, 4, 5})
		if err == nil {
			t.Fatal("Expected error for invalid OID")
		}
	})
}

func TestSignCertificateWithQuantum_SignerInterface(t *testing.T) {
	// Verify MLDSAPrivateKey implements crypto.Signer
	caKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA65)
	var _ crypto.Signer = caKey

	// Test Sign method directly
	msg := []byte("test message for ML-DSA signing")
	sig, err := caKey.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("Expected non-empty signature")
	}

	// Verify the signature
	valid, err := caKey.Verify(msg, sig)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Fatal("Signature verification failed")
	}
}
