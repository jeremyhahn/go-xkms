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

package attestation

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// TestNewVerifier tests verifier creation
func TestNewVerifier(t *testing.T) {
	v := NewVerifier(nil)
	if v == nil {
		t.Errorf("NewVerifier() returned nil")
	}

	// Test with trusted roots
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Root CA",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	v = NewVerifier([]*x509.Certificate{cert})
	if v == nil {
		t.Errorf("NewVerifier() returned nil")
	}
}

// TestVerifyChainValid tests certificate chain validation with valid chain
func TestVerifyChainValid(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	// Create a self-signed certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Cert",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		PublicKeyAlgorithm:    x509.RSA,
		PublicKey:             publicKey,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Self-sign the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, publicKey, privKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	parsedCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    publicKey,
		Signature:             []byte("test-signature"),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		CertificateChain:      []*x509.Certificate{parsedCert},
		AttestedKeyPublic:     publicKey,
		AttestationData:       []byte("test-data"),
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{
		AllowSelfSigned: true,
	}

	err = v.VerifyChain(stmt, opts)
	if err != nil {
		t.Errorf("VerifyChain() failed: %v", err)
	}
}

// TestVerifyChainEmpty tests chain validation with empty chain
func TestVerifyChainEmpty(t *testing.T) {
	stmt := &AttestationStatement{
		Format:            "tpm2",
		CertificateChain:  []*x509.Certificate{},
		AttestedKeyPublic: &rsa.PublicKey{},
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{}

	err := v.VerifyChain(stmt, opts)
	if err == nil {
		t.Errorf("VerifyChain() should fail with empty chain")
	}
}

// TestVerifyChainExpired tests chain validation with expired certificate
func TestVerifyChainExpired(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	// Create an expired certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Expired Cert",
		},
		NotBefore:          time.Now().AddDate(-2, 0, 0), // 2 years ago
		NotAfter:           time.Now().AddDate(-1, 0, 0), // 1 year ago (expired)
		KeyUsage:           x509.KeyUsageDigitalSignature,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	stmt := &AttestationStatement{
		Format:             "tpm2",
		CertificateChain:   []*x509.Certificate{cert},
		AttestingKeyPublic: publicKey,
		AttestedKeyPublic:  publicKey,
		SignatureAlgorithm: x509.SHA256WithRSA,
		Signature:          []byte("test"),
		AttestationData:    []byte("test"),
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{}

	err := v.VerifyChain(stmt, opts)
	if err == nil {
		t.Errorf("VerifyChain() should fail with expired certificate")
	}
}

// TestVerifySignature tests RSA signature verification
func TestVerifySignature(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	// Create data to sign
	data := []byte("test attestation data")
	h := sha256.Sum256(data)

	// Sign the data
	sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    publicKey,
		Signature:             sig,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		AttestationData:       data,
		AttestedKeyPublic:     publicKey,
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{}

	err = v.VerifySignature(stmt, opts)
	if err != nil {
		t.Errorf("VerifySignature() failed: %v", err)
	}
}

// TestVerifySignatureInvalid tests invalid signature detection
func TestVerifySignatureInvalid(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    publicKey,
		Signature:             []byte("invalid-signature"),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		AttestationData:       []byte("test data"),
		AttestedKeyPublic:     publicKey,
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{}

	err := v.VerifySignature(stmt, opts)
	if err == nil {
		t.Errorf("VerifySignature() should fail with invalid signature")
	}
}

// TestVerifyFreshness tests freshness validation
func TestVerifyFreshness(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    publicKey,
		Signature:             []byte("test-sig"),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		AttestationData:       []byte("test-data"),
		AttestedKeyPublic:     publicKey,
		CreatedAt:             time.Now().Format(time.RFC3339),
		Nonce:                 []byte("test-nonce"),
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{
		CheckFreshness:  true,
		FreshnessWindow: 300,
		ExpectedNonce:   []byte("test-nonce"),
	}

	err := v.verifyFreshness(stmt, opts)
	if err != nil {
		t.Errorf("verifyFreshness() failed: %v", err)
	}
}

// TestVerifyFreshnessTooOld tests rejection of old attestations
func TestVerifyFreshnessTooOld(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	// Create attestation from 1 hour ago
	oldTime := time.Now().AddDate(0, 0, -1).Format(time.RFC3339)

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    publicKey,
		Signature:             []byte("test-sig"),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		AttestationData:       []byte("test-data"),
		AttestedKeyPublic:     publicKey,
		CreatedAt:             oldTime,
		Nonce:                 []byte("test-nonce"),
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{
		CheckFreshness:  true,
		FreshnessWindow: 300, // 5 minutes
		ExpectedNonce:   []byte("test-nonce"),
	}

	err := v.verifyFreshness(stmt, opts)
	if err == nil {
		t.Errorf("verifyFreshness() should fail for old attestation")
	}
}

// TestVerifyFreshnessNonceMismatch tests nonce validation
func TestVerifyFreshnessNonceMismatch(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    publicKey,
		Signature:             []byte("test-sig"),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		AttestationData:       []byte("test-data"),
		AttestedKeyPublic:     publicKey,
		CreatedAt:             time.Now().Format(time.RFC3339),
		Nonce:                 []byte("nonce-in-attestation"),
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{
		CheckFreshness:  true,
		FreshnessWindow: 300,
		ExpectedNonce:   []byte("different-nonce"),
	}

	err := v.verifyFreshness(stmt, opts)
	if err == nil {
		t.Errorf("verifyFreshness() should fail with nonce mismatch")
	}
}

// TestVerifyPCRsMatch tests PCR verification with matching values
func TestVerifyPCRsMatch(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	pcrValues := map[uint32][]byte{
		0: {0x00, 0x01, 0x02, 0x03},
		1: {0x04, 0x05, 0x06, 0x07},
	}

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    publicKey,
		AttestedKeyPublic:     publicKey,
		PCRValues:             pcrValues,
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{
		VerifyPCRs:   true,
		ExpectedPCRs: pcrValues,
	}

	err := v.verifyPCRs(stmt, opts)
	if err != nil {
		t.Errorf("verifyPCRs() failed: %v", err)
	}
}

// TestVerifyPCRsMismatch tests PCR verification with mismatched values
func TestVerifyPCRsMismatch(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    publicKey,
		AttestedKeyPublic:     publicKey,
		PCRValues: map[uint32][]byte{
			0: {0x00, 0x01, 0x02, 0x03},
		},
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{
		VerifyPCRs: true,
		ExpectedPCRs: map[uint32][]byte{
			0: {0xFF, 0xFF, 0xFF, 0xFF},
		},
	}

	err := v.verifyPCRs(stmt, opts)
	if err == nil {
		t.Errorf("verifyPCRs() should fail with mismatched PCR values")
	}
}

// TestAttestationStatementHash tests public key hashing
func TestAttestationStatementHash(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	stmt := &AttestationStatement{
		AttestedKeyPublic: publicKey,
	}

	hash, err := stmt.Hash()
	if err != nil {
		t.Errorf("Hash() failed: %v", err)
	}

	if len(hash) == 0 {
		t.Errorf("Hash() returned empty hash")
	}

	// Hash should be 32 bytes (SHA256)
	if len(hash) != 32 {
		t.Errorf("Hash() returned %d bytes, expected 32", len(hash))
	}
}

// BenchmarkVerifySignature benchmarks signature verification
func BenchmarkVerifySignature(b *testing.B) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	data := []byte("test attestation data")
	h := sha256.Sum256(data)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, h[:])

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    publicKey,
		Signature:             sig,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		AttestationData:       data,
		AttestedKeyPublic:     publicKey,
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = v.VerifySignature(stmt, opts)
	}
}
