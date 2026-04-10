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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// makeHybridCACertTemplate creates a CA certificate template for hybrid testing.
func makeHybridCACertTemplate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject: pkix.Name{
			CommonName:   "Test Hybrid CA",
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

func TestCreateHybridCertificate(t *testing.T) {
	// Generate classical ECDSA key
	classicalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// Generate quantum ML-DSA-65 key
	quantumKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA65)

	template := makeHybridCACertTemplate()

	// Create self-signed hybrid certificate
	certDER, err := CreateHybridCertificate(template, template, classicalKey, quantumKey)
	if err != nil {
		t.Fatalf("CreateHybridCertificate failed: %v", err)
	}

	if len(certDER) == 0 {
		t.Fatal("Expected non-empty certificate DER")
	}

	// Parse the certificate to verify it is valid X.509
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse hybrid certificate: %v", err)
	}

	// Verify the certificate has the hybrid extensions
	var hasAltPubKey, hasAltSigAlg, hasAltSigVal bool
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidSubjectAltPublicKeyInfo) {
			hasAltPubKey = true
		}
		if ext.Id.Equal(oidAltSignatureAlgorithm) {
			hasAltSigAlg = true
		}
		if ext.Id.Equal(oidAltSignatureValue) {
			hasAltSigVal = true
		}
	}

	if !hasAltPubKey {
		t.Error("Missing subjectAltPublicKeyInfo extension")
	}
	if !hasAltSigAlg {
		t.Error("Missing altSignatureAlgorithm extension")
	}
	if !hasAltSigVal {
		t.Error("Missing altSignatureValue extension")
	}
}

func TestCreateHybridCertificate_ECDSA_MLDSA44(t *testing.T) {
	classicalKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA P-384 key: %v", err)
	}

	quantumKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA44)
	template := makeHybridCACertTemplate()

	certDER, err := CreateHybridCertificate(template, template, classicalKey, quantumKey)
	if err != nil {
		t.Fatalf("CreateHybridCertificate failed: %v", err)
	}

	if len(certDER) == 0 {
		t.Fatal("Expected non-empty certificate DER")
	}

	// Parse and verify it is a valid X.509 certificate
	_, err = x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse hybrid certificate: %v", err)
	}
}

func TestCreateHybridCertificate_ECDSA_MLDSA87(t *testing.T) {
	classicalKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA P-521 key: %v", err)
	}

	quantumKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA87)
	template := makeHybridCACertTemplate()

	certDER, err := CreateHybridCertificate(template, template, classicalKey, quantumKey)
	if err != nil {
		t.Fatalf("CreateHybridCertificate failed: %v", err)
	}

	if len(certDER) == 0 {
		t.Fatal("Expected non-empty certificate DER")
	}
}

func TestCreateHybridCertificate_InvalidQuantumKey(t *testing.T) {
	classicalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	template := makeHybridCACertTemplate()

	t.Run("nil_quantum_key", func(t *testing.T) {
		_, err := CreateHybridCertificate(template, template, classicalKey, nil)
		if err == nil {
			t.Fatal("Expected error for nil quantum key")
		}
	})

	t.Run("nil_classical_key", func(t *testing.T) {
		quantumKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA65)
		_, err := CreateHybridCertificate(template, template, nil, quantumKey)
		if err == nil {
			t.Fatal("Expected error for nil classical key")
		}
	})

	t.Run("nil_template", func(t *testing.T) {
		quantumKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA65)
		_, err := CreateHybridCertificate(nil, template, classicalKey, quantumKey)
		if err == nil {
			t.Fatal("Expected error for nil template")
		}
	})

	t.Run("nil_parent", func(t *testing.T) {
		quantumKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA65)
		_, err := CreateHybridCertificate(template, nil, classicalKey, quantumKey)
		if err == nil {
			t.Fatal("Expected error for nil parent")
		}
	})
}

func TestVerifyHybridCertificate(t *testing.T) {
	// Generate keys
	classicalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	quantumKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA65)

	// Create self-signed hybrid CA certificate
	template := makeHybridCACertTemplate()

	certDER, err := CreateHybridCertificate(template, template, classicalKey, quantumKey)
	if err != nil {
		t.Fatalf("CreateHybridCertificate failed: %v", err)
	}

	// Parse it to get the x509.Certificate for classical verification
	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse hybrid certificate: %v", err)
	}

	// Verify both signatures
	err = VerifyHybridCertificate(certDER, parsedCert, quantumKey.PublicKey)
	if err != nil {
		t.Fatalf("VerifyHybridCertificate failed: %v", err)
	}
}

func TestVerifyHybridCertificate_TamperedClassical(t *testing.T) {
	classicalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	quantumKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA65)

	template := makeHybridCACertTemplate()

	certDER, err := CreateHybridCertificate(template, template, classicalKey, quantumKey)
	if err != nil {
		t.Fatalf("CreateHybridCertificate failed: %v", err)
	}

	// Tamper with the classical signature (near the end of the cert)
	tamperedDER := make([]byte, len(certDER))
	copy(tamperedDER, certDER)
	if len(tamperedDER) > 10 {
		tamperedDER[len(tamperedDER)-5] ^= 0xFF
	}

	// Try to parse (might fail due to corruption)
	parsedCert, parseErr := x509.ParseCertificate(tamperedDER)
	if parseErr != nil {
		// Certificate is too corrupted to even parse, which also counts as detection
		return
	}

	// Verification should fail due to tampered classical signature
	err = VerifyHybridCertificate(tamperedDER, parsedCert, quantumKey.PublicKey)
	if err == nil {
		t.Fatal("Expected verification to fail for tampered classical signature")
	}
}

func TestVerifyHybridCertificate_TamperedQuantum(t *testing.T) {
	classicalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	quantumKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA65)

	template := makeHybridCACertTemplate()

	certDER, err := CreateHybridCertificate(template, template, classicalKey, quantumKey)
	if err != nil {
		t.Fatalf("CreateHybridCertificate failed: %v", err)
	}

	// Parse the certificate
	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse hybrid certificate: %v", err)
	}

	// Verify with a different quantum key (should fail)
	wrongQuantumKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA65)
	err = VerifyHybridCertificate(certDER, parsedCert, wrongQuantumKey.PublicKey)
	if err == nil {
		t.Fatal("Expected verification to fail with wrong quantum key")
	}
}

func TestVerifyHybridCertificate_EmptyInput(t *testing.T) {
	classicalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	quantumKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA65)

	// Create a self-signed cert for classical issuer
	template := makeHybridCACertTemplate()
	certDER, cerr := x509.CreateCertificate(rand.Reader, template, template, classicalKey.Public(), classicalKey)
	if cerr != nil {
		t.Fatalf("Failed to create classical cert: %v", cerr)
	}
	parsedCert, cerr := x509.ParseCertificate(certDER)
	if cerr != nil {
		t.Fatalf("Failed to parse cert: %v", cerr)
	}

	t.Run("nil_certDER", func(t *testing.T) {
		err := VerifyHybridCertificate(nil, parsedCert, quantumKey.PublicKey)
		if err == nil {
			t.Fatal("Expected error for nil certDER")
		}
	})

	t.Run("empty_certDER", func(t *testing.T) {
		err := VerifyHybridCertificate([]byte{}, parsedCert, quantumKey.PublicKey)
		if err == nil {
			t.Fatal("Expected error for empty certDER")
		}
	})

	t.Run("nil_classical_issuer", func(t *testing.T) {
		err := VerifyHybridCertificate(certDER, nil, quantumKey.PublicKey)
		if err == nil {
			t.Fatal("Expected error for nil classical issuer")
		}
	})

	t.Run("nil_quantum_pubkey", func(t *testing.T) {
		err := VerifyHybridCertificate(certDER, parsedCert, nil)
		if err == nil {
			t.Fatal("Expected error for nil quantum public key")
		}
	})
}

func TestVerifyHybridCertificate_MissingExtensions(t *testing.T) {
	// Create a classical-only certificate (no hybrid extensions)
	classicalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	quantumKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA65)

	template := makeHybridCACertTemplate()
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, classicalKey.Public(), classicalKey)
	if err != nil {
		t.Fatalf("Failed to create classical certificate: %v", err)
	}

	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Try to verify as hybrid - should fail due to missing extensions
	err = VerifyHybridCertificate(certDER, parsedCert, quantumKey.PublicKey)
	if err == nil {
		t.Fatal("Expected error for certificate without hybrid extensions")
	}
}

func TestCreateHybridCertificate_DoesNotMutateTemplate(t *testing.T) {
	classicalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	quantumKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA65)

	template := makeHybridCACertTemplate()
	originalExtCount := len(template.ExtraExtensions)

	_, err = CreateHybridCertificate(template, template, classicalKey, quantumKey)
	if err != nil {
		t.Fatalf("CreateHybridCertificate failed: %v", err)
	}

	// Verify the original template was not mutated
	if len(template.ExtraExtensions) != originalExtCount {
		t.Fatalf("Template was mutated: ExtraExtensions had %d, now has %d",
			originalExtCount, len(template.ExtraExtensions))
	}
}

func TestCreateHybridCertificate_SignerInterface(t *testing.T) {
	// Verify that both keys satisfy crypto.Signer
	classicalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	quantumKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA65)

	var _ crypto.Signer = classicalKey
	var _ crypto.Signer = quantumKey
}

func TestHybridExtensionOIDs(t *testing.T) {
	// Verify the OID values are correct per ITU-T X.509 (2019) Amendment 1
	expectedOIDs := map[string]string{
		"subjectAltPublicKeyInfo": "2.5.29.72",
		"altSignatureAlgorithm":   "2.5.29.73",
		"altSignatureValue":       "2.5.29.74",
	}

	if oidSubjectAltPublicKeyInfo.String() != expectedOIDs["subjectAltPublicKeyInfo"] {
		t.Errorf("oidSubjectAltPublicKeyInfo = %s, want %s",
			oidSubjectAltPublicKeyInfo.String(), expectedOIDs["subjectAltPublicKeyInfo"])
	}
	if oidAltSignatureAlgorithm.String() != expectedOIDs["altSignatureAlgorithm"] {
		t.Errorf("oidAltSignatureAlgorithm = %s, want %s",
			oidAltSignatureAlgorithm.String(), expectedOIDs["altSignatureAlgorithm"])
	}
	if oidAltSignatureValue.String() != expectedOIDs["altSignatureValue"] {
		t.Errorf("oidAltSignatureValue = %s, want %s",
			oidAltSignatureValue.String(), expectedOIDs["altSignatureValue"])
	}
}

func TestIsStandardExtension(t *testing.T) {
	testCases := []struct {
		name     string
		oid      []int
		expected bool
	}{
		{"basicConstraints", []int{2, 5, 29, 19}, true},
		{"keyUsage", []int{2, 5, 29, 15}, true},
		{"subjectAltName", []int{2, 5, 29, 17}, true},
		{"authorityKeyIdentifier", []int{2, 5, 29, 35}, true},
		{"subjectAltPublicKeyInfo", []int{2, 5, 29, 72}, false},
		{"altSignatureAlgorithm", []int{2, 5, 29, 73}, false},
		{"altSignatureValue", []int{2, 5, 29, 74}, false},
		{"custom_extension", []int{1, 2, 3, 4, 5}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := isStandardExtension(tc.oid)
			if result != tc.expected {
				t.Errorf("isStandardExtension(%v) = %v, want %v", tc.oid, result, tc.expected)
			}
		})
	}
}
