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

package truststore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestFingerprint(t *testing.T) {
	cert := generateTestCert(t, "Test CA")
	fp := Fingerprint(cert)

	if len(fp) != fingerprintLen {
		t.Errorf("Fingerprint() length = %d, want %d", len(fp), fingerprintLen)
	}

	if !fingerprintPattern.MatchString(fp) {
		t.Errorf("Fingerprint() = %q, does not match lowercase hex pattern", fp)
	}

	// Same cert should produce the same fingerprint.
	fp2 := Fingerprint(cert)
	if fp != fp2 {
		t.Errorf("Fingerprint() not deterministic: %q != %q", fp, fp2)
	}
}

func TestFingerprint_DifferentCerts(t *testing.T) {
	cert1 := generateTestCert(t, "CA One")
	cert2 := generateTestCert(t, "CA Two")

	fp1 := Fingerprint(cert1)
	fp2 := Fingerprint(cert2)

	if fp1 == fp2 {
		t.Error("Fingerprint() should produce different values for different certificates")
	}
}

func TestAlgorithmName(t *testing.T) {
	tests := []struct {
		algo x509.PublicKeyAlgorithm
		want string
	}{
		{x509.RSA, "RSA"},
		{x509.ECDSA, "ECDSA"},
		{x509.Ed25519, "Ed25519"},
		{x509.DSA, "DSA"},
		{x509.UnknownPublicKeyAlgorithm, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := algorithmName(tt.algo)
			if got != tt.want {
				t.Errorf("algorithmName(%v) = %q, want %q", tt.algo, got, tt.want)
			}
		})
	}
}

func TestAlgorithmName_UnmappedValue(t *testing.T) {
	// Use a value beyond known algorithms.
	got := algorithmName(x509.PublicKeyAlgorithm(255))
	if got == "" {
		t.Error("algorithmName(255) returned empty string, want fallback")
	}
}

// generateTestCert creates a self-signed CA certificate for testing.
func generateTestCert(t *testing.T, commonName string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create self-signed certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse generated certificate: %v", err)
	}

	return cert
}

// generateTestCertPEM creates PEM-encoded self-signed certificate data for testing.
func generateTestCertPEM(t *testing.T, commonName string) []byte {
	t.Helper()

	cert := generateTestCert(t, commonName)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}
