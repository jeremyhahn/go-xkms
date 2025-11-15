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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// TestVerify tests the complete Verify function
func TestVerify(t *testing.T) {
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
		Signature:             sig,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		CertificateChain:      []*x509.Certificate{parsedCert},
		AttestedKeyPublic:     publicKey,
		AttestationData:       data,
		CreatedAt:             time.Now().Format(time.RFC3339),
		Backend:               "tpm2",
		Nonce:                 []byte("test-nonce"),
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{
		AllowSelfSigned: true,
		CheckFreshness:  true,
		FreshnessWindow: 300,
		ExpectedNonce:   []byte("test-nonce"),
	}

	err = v.Verify(stmt, opts)
	if err != nil {
		t.Errorf("Verify() failed: %v", err)
	}
}

// TestVerifyInvalidStatement tests Verify with invalid statement
func TestVerifyInvalidStatement(t *testing.T) {
	v := NewVerifier(nil)
	opts := &VerifyOptions{}

	stmt := &AttestationStatement{
		Format: "", // Invalid - empty format
	}

	err := v.Verify(stmt, opts)
	if err == nil {
		t.Errorf("Verify() should fail with invalid statement")
	}
}

// TestVerifyInvalidOptions tests Verify with invalid options
func TestVerifyInvalidOptions(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Cert",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    publicKey,
		Signature:             []byte("test-sig"),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		CertificateChain:      []*x509.Certificate{cert},
		AttestedKeyPublic:     publicKey,
		AttestationData:       []byte("test-data"),
	}

	v := NewVerifier(nil)

	// Test with nil options
	err := v.Verify(stmt, nil)
	if err == nil {
		t.Errorf("Verify() should fail with nil options")
	}

	// Test with invalid freshness window
	opts := &VerifyOptions{
		FreshnessWindow: -1,
	}

	err = v.Verify(stmt, opts)
	if err == nil {
		t.Errorf("Verify() should fail with invalid freshness window")
	}
}

// TestVerifyChainInvalidSignature tests chain verification with invalid signature
func TestVerifyChainInvalidSignature(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	// Create two different key pairs
	privKey2, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey2 := &privKey2.PublicKey

	// Create a root certificate template
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		PublicKeyAlgorithm:    x509.RSA,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create a leaf certificate template
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Leaf Cert",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		PublicKeyAlgorithm:    x509.RSA,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Create root cert signed by itself
	rootBytes, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, publicKey, privKey)
	parsedRoot, _ := x509.ParseCertificate(rootBytes)

	// Sign leaf with WRONG key (privKey2 instead of privKey)
	// This will create a leaf certificate that claims to be signed by root, but isn't
	leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, publicKey2, privKey2)
	parsedLeaf, _ := x509.ParseCertificate(leafBytes)

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    publicKey2,
		Signature:             []byte("test-sig"),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		CertificateChain:      []*x509.Certificate{parsedLeaf, parsedRoot},
		AttestedKeyPublic:     publicKey2,
		AttestationData:       []byte("test-data"),
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{}

	err := v.VerifyChain(stmt, opts)
	if err == nil {
		t.Errorf("VerifyChain() should fail with invalid signature")
	}
}

// TestVerifyChainNotYetValid tests chain with certificate not yet valid
func TestVerifyChainNotYetValid(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	// Create a certificate that's not yet valid
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Future Cert",
		},
		NotBefore:          time.Now().Add(24 * time.Hour), // Valid tomorrow
		NotAfter:           time.Now().Add(48 * time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    publicKey,
		Signature:             []byte("test-sig"),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		CertificateChain:      []*x509.Certificate{cert},
		AttestedKeyPublic:     publicKey,
		AttestationData:       []byte("test-data"),
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{}

	err := v.VerifyChain(stmt, opts)
	if err == nil {
		t.Errorf("VerifyChain() should fail with not yet valid certificate")
	}
}

// TestVerifyChainWithCurrentTime tests chain verification with custom time
func TestVerifyChainWithCurrentTime(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	// Create a certificate
	validFrom := time.Now().AddDate(0, 0, -10)
	validTo := time.Now().AddDate(0, 0, 10)

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Cert",
		},
		NotBefore:             validFrom,
		NotAfter:              validTo,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		PublicKeyAlgorithm:    x509.RSA,
		PublicKey:             publicKey,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certBytes, _ := x509.CreateCertificate(rand.Reader, cert, cert, publicKey, privKey)
	parsedCert, _ := x509.ParseCertificate(certBytes)

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    publicKey,
		Signature:             []byte("test-sig"),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		CertificateChain:      []*x509.Certificate{parsedCert},
		AttestedKeyPublic:     publicKey,
		AttestationData:       []byte("test-data"),
	}

	v := NewVerifier(nil)

	// Test with time before valid period
	beforeTime := validFrom.Add(-24 * time.Hour).Unix()
	opts := &VerifyOptions{
		CurrentTime: &beforeTime,
	}

	err := v.VerifyChain(stmt, opts)
	if err == nil {
		t.Errorf("VerifyChain() should fail when CurrentTime is before NotBefore")
	}

	// Test with time after valid period
	afterTime := validTo.Add(24 * time.Hour).Unix()
	opts.CurrentTime = &afterTime

	err = v.VerifyChain(stmt, opts)
	if err == nil {
		t.Errorf("VerifyChain() should fail when CurrentTime is after NotAfter")
	}

	// Test with valid time
	validTime := validFrom.Add(24 * time.Hour).Unix()
	opts.CurrentTime = &validTime

	err = v.VerifyChain(stmt, opts)
	if err != nil {
		t.Errorf("VerifyChain() should succeed when CurrentTime is within validity period: %v", err)
	}
}

// TestVerifyChainMultipleCerts tests chain with multiple certificates
func TestVerifyChainMultipleCerts(t *testing.T) {
	// Create root key pair
	rootPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootPub := &rootPriv.PublicKey

	// Create intermediate key pair
	intPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	intPub := &intPriv.PublicKey

	// Create leaf key pair
	leafPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafPub := &leafPriv.PublicKey

	// Create root certificate
	rootCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Root CA",
		},
		NotBefore:             time.Now().AddDate(0, 0, -1),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		PublicKeyAlgorithm:    x509.RSA,
		PublicKey:             rootPub,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Self-sign root
	rootBytes, _ := x509.CreateCertificate(rand.Reader, rootCert, rootCert, rootPub, rootPriv)
	parsedRoot, _ := x509.ParseCertificate(rootBytes)

	// Create intermediate certificate
	intCert := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Intermediate CA",
		},
		NotBefore:             time.Now().AddDate(0, 0, -1),
		NotAfter:              time.Now().AddDate(0, 6, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		PublicKeyAlgorithm:    x509.RSA,
		PublicKey:             intPub,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Sign intermediate with root
	intBytes, _ := x509.CreateCertificate(rand.Reader, intCert, parsedRoot, intPub, rootPriv)
	parsedInt, _ := x509.ParseCertificate(intBytes)

	// Create leaf certificate
	leafCert := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: "Leaf Cert",
		},
		NotBefore:             time.Now().AddDate(0, 0, -1),
		NotAfter:              time.Now().AddDate(0, 3, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		PublicKeyAlgorithm:    x509.RSA,
		PublicKey:             leafPub,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Sign leaf with intermediate
	leafBytes, _ := x509.CreateCertificate(rand.Reader, leafCert, parsedInt, leafPub, intPriv)
	parsedLeaf, _ := x509.ParseCertificate(leafBytes)

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    leafPub,
		Signature:             []byte("test-sig"),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		CertificateChain:      []*x509.Certificate{parsedLeaf, parsedInt, parsedRoot},
		AttestedKeyPublic:     leafPub,
		AttestationData:       []byte("test-data"),
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{}

	err := v.VerifyChain(stmt, opts)
	if err != nil {
		t.Errorf("VerifyChain() failed with valid multi-cert chain: %v", err)
	}
}

// TestVerifyChainIntermediateExpired tests chain with expired intermediate
func TestVerifyChainIntermediateExpired(t *testing.T) {
	// Create root key pair
	rootPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootPub := &rootPriv.PublicKey

	// Create intermediate key pair
	intPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	intPub := &intPriv.PublicKey

	// Create root certificate
	rootCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Root CA",
		},
		NotBefore:             time.Now().AddDate(0, 0, -1),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		PublicKeyAlgorithm:    x509.RSA,
		PublicKey:             rootPub,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootBytes, _ := x509.CreateCertificate(rand.Reader, rootCert, rootCert, rootPub, rootPriv)
	parsedRoot, _ := x509.ParseCertificate(rootBytes)

	// Create expired intermediate certificate
	intCert := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Expired Intermediate",
		},
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(0, 0, -1), // Expired yesterday
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		PublicKeyAlgorithm:    x509.RSA,
		PublicKey:             intPub,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	intBytes, _ := x509.CreateCertificate(rand.Reader, intCert, parsedRoot, intPub, rootPriv)
	parsedInt, _ := x509.ParseCertificate(intBytes)

	// Create leaf cert
	leafPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafPub := &leafPriv.PublicKey

	leafCert := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: "Leaf Cert",
		},
		NotBefore:             time.Now().AddDate(0, 0, -1),
		NotAfter:              time.Now().AddDate(0, 3, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		PublicKeyAlgorithm:    x509.RSA,
		PublicKey:             leafPub,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	leafBytes, _ := x509.CreateCertificate(rand.Reader, leafCert, parsedInt, leafPub, intPriv)
	parsedLeaf, _ := x509.ParseCertificate(leafBytes)

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    leafPub,
		Signature:             []byte("test-sig"),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		CertificateChain:      []*x509.Certificate{parsedLeaf, parsedInt, parsedRoot},
		AttestedKeyPublic:     leafPub,
		AttestationData:       []byte("test-data"),
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{}

	err := v.VerifyChain(stmt, opts)
	if err == nil {
		t.Errorf("VerifyChain() should fail with expired intermediate certificate")
	}
}

// TestVerifyChainIntermediateNotYetValid tests chain with intermediate not yet valid
func TestVerifyChainIntermediateNotYetValid(t *testing.T) {
	// Create root key pair
	rootPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootPub := &rootPriv.PublicKey

	// Create intermediate key pair
	intPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	intPub := &intPriv.PublicKey

	// Create root certificate
	rootCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Root CA",
		},
		NotBefore:             time.Now().AddDate(0, 0, -1),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		PublicKeyAlgorithm:    x509.RSA,
		PublicKey:             rootPub,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootBytes, _ := x509.CreateCertificate(rand.Reader, rootCert, rootCert, rootPub, rootPriv)
	parsedRoot, _ := x509.ParseCertificate(rootBytes)

	// Create intermediate certificate not yet valid
	intCert := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Future Intermediate",
		},
		NotBefore:             time.Now().AddDate(0, 0, 1), // Valid tomorrow
		NotAfter:              time.Now().AddDate(0, 6, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		PublicKeyAlgorithm:    x509.RSA,
		PublicKey:             intPub,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	intBytes, _ := x509.CreateCertificate(rand.Reader, intCert, parsedRoot, intPub, rootPriv)
	parsedInt, _ := x509.ParseCertificate(intBytes)

	// Create leaf cert
	leafPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafPub := &leafPriv.PublicKey

	leafCert := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: "Leaf Cert",
		},
		NotBefore:             time.Now().AddDate(0, 0, -1),
		NotAfter:              time.Now().AddDate(0, 3, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		PublicKeyAlgorithm:    x509.RSA,
		PublicKey:             leafPub,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	leafBytes, _ := x509.CreateCertificate(rand.Reader, leafCert, parsedInt, leafPub, intPriv)
	parsedLeaf, _ := x509.ParseCertificate(leafBytes)

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    leafPub,
		Signature:             []byte("test-sig"),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		CertificateChain:      []*x509.Certificate{parsedLeaf, parsedInt, parsedRoot},
		AttestedKeyPublic:     leafPub,
		AttestationData:       []byte("test-data"),
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{}

	err := v.VerifyChain(stmt, opts)
	if err == nil {
		t.Errorf("VerifyChain() should fail with intermediate not yet valid")
	}
}

// TestVerifySignatureEmptySignature tests signature verification with empty signature
func TestVerifySignatureEmptySignature(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    publicKey,
		Signature:             []byte{}, // Empty
		SignatureAlgorithm:    x509.SHA256WithRSA,
		AttestationData:       []byte("test data"),
		AttestedKeyPublic:     publicKey,
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{}

	err := v.VerifySignature(stmt, opts)
	if err == nil {
		t.Errorf("VerifySignature() should fail with empty signature")
	}
}

// TestVerifySignatureNilAttestingKey tests signature verification with nil attesting key
func TestVerifySignatureNilAttestingKey(t *testing.T) {
	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    nil, // Nil
		Signature:             []byte("test-sig"),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		AttestationData:       []byte("test data"),
		AttestedKeyPublic:     &rsa.PublicKey{},
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{}

	err := v.VerifySignature(stmt, opts)
	if err == nil {
		t.Errorf("VerifySignature() should fail with nil attesting key")
	}
}

// TestVerifySignatureNoAttestationData tests signature verification without attestation data
func TestVerifySignatureNoAttestationData(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	// Sign the marshaled public key
	pubBytes, _ := x509.MarshalPKIXPublicKey(publicKey)
	h := sha256.Sum256(pubBytes)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, h[:])

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    publicKey,
		Signature:             sig,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		AttestationData:       []byte{}, // Empty - should use public key
		AttestedKeyPublic:     publicKey,
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{}

	err := v.VerifySignature(stmt, opts)
	if err != nil {
		t.Errorf("VerifySignature() should succeed using public key fallback: %v", err)
	}
}

// TestVerifySignatureUnsupportedKeyType tests signature verification with unsupported key type
func TestVerifySignatureUnsupportedKeyType(t *testing.T) {
	// Use ECDSA which is not supported
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.ECDSA,
		AttestingKeyPublic:    &ecKey.PublicKey,
		Signature:             []byte("test-sig"),
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		AttestationData:       []byte("test data"),
		AttestedKeyPublic:     &ecKey.PublicKey,
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{}

	err := v.VerifySignature(stmt, opts)
	if err == nil {
		t.Errorf("VerifySignature() should fail with unsupported key type")
	}
}

// TestVerifyRSASignatureSHA384 tests RSA signature verification with SHA384
func TestVerifyRSASignatureSHA384(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	data := []byte("test attestation data")
	h := sha512.Sum384(data)

	sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA384, h[:])
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    publicKey,
		Signature:             sig,
		SignatureAlgorithm:    x509.SHA384WithRSA,
		AttestationData:       data,
		AttestedKeyPublic:     publicKey,
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{}

	err = v.VerifySignature(stmt, opts)
	if err != nil {
		t.Errorf("VerifySignature() failed with SHA384: %v", err)
	}
}

// TestVerifyRSASignatureSHA512 tests RSA signature verification with SHA512
func TestVerifyRSASignatureSHA512(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	data := []byte("test attestation data")
	h := sha512.Sum512(data)

	sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA512, h[:])
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    publicKey,
		Signature:             sig,
		SignatureAlgorithm:    x509.SHA512WithRSA,
		AttestationData:       data,
		AttestedKeyPublic:     publicKey,
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{}

	err = v.VerifySignature(stmt, opts)
	if err != nil {
		t.Errorf("VerifySignature() failed with SHA512: %v", err)
	}
}

// TestVerifyRSASignatureUnsupportedAlgorithm tests RSA signature with unsupported algorithm
func TestVerifyRSASignatureUnsupportedAlgorithm(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    publicKey,
		Signature:             []byte("test-sig"),
		SignatureAlgorithm:    x509.MD5WithRSA, // Unsupported
		AttestationData:       []byte("test data"),
		AttestedKeyPublic:     publicKey,
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{}

	err := v.VerifySignature(stmt, opts)
	if err == nil {
		t.Errorf("VerifySignature() should fail with unsupported algorithm")
	}
}

// TestVerifyFreshnessNoTimestamp tests freshness verification without timestamp
func TestVerifyFreshnessNoTimestamp(t *testing.T) {
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
		CreatedAt:             "", // Missing
		Nonce:                 []byte("test-nonce"),
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{
		CheckFreshness:  true,
		FreshnessWindow: 300,
	}

	err := v.verifyFreshness(stmt, opts)
	if err == nil {
		t.Errorf("verifyFreshness() should fail without timestamp")
	}
}

// TestVerifyFreshnessInvalidTimestamp tests freshness verification with invalid timestamp
func TestVerifyFreshnessInvalidTimestamp(t *testing.T) {
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
		CreatedAt:             "invalid-timestamp",
		Nonce:                 []byte("test-nonce"),
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{
		CheckFreshness:  true,
		FreshnessWindow: 300,
	}

	err := v.verifyFreshness(stmt, opts)
	if err == nil {
		t.Errorf("verifyFreshness() should fail with invalid timestamp")
	}
}

// TestVerifyFreshnessFutureTime tests freshness verification with future time
func TestVerifyFreshnessFutureTime(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	// Create timestamp in the future
	futureTime := time.Now().Add(24 * time.Hour).Format(time.RFC3339)

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    publicKey,
		Signature:             []byte("test-sig"),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		AttestationData:       []byte("test-data"),
		AttestedKeyPublic:     publicKey,
		CreatedAt:             futureTime,
		Nonce:                 []byte("test-nonce"),
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{
		CheckFreshness:  true,
		FreshnessWindow: 300,
	}

	err := v.verifyFreshness(stmt, opts)
	if err == nil {
		t.Errorf("verifyFreshness() should fail with future timestamp")
	}
}

// TestVerifyFreshnessWithCurrentTime tests freshness verification with custom current time
func TestVerifyFreshnessWithCurrentTime(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	createdTime := time.Now().Add(-10 * time.Minute)
	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    publicKey,
		Signature:             []byte("test-sig"),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		AttestationData:       []byte("test-data"),
		AttestedKeyPublic:     publicKey,
		CreatedAt:             createdTime.Format(time.RFC3339),
		Nonce:                 []byte("test-nonce"),
	}

	v := NewVerifier(nil)

	// Set current time to make attestation too old
	currentTime := createdTime.Add(20 * time.Minute).Unix()
	opts := &VerifyOptions{
		CheckFreshness:  true,
		FreshnessWindow: 300, // 5 minutes
		CurrentTime:     &currentTime,
	}

	err := v.verifyFreshness(stmt, opts)
	if err == nil {
		t.Errorf("verifyFreshness() should fail when attestation is too old based on CurrentTime")
	}

	// Set current time within freshness window
	currentTime = createdTime.Add(2 * time.Minute).Unix()
	opts.CurrentTime = &currentTime

	err = v.verifyFreshness(stmt, opts)
	if err != nil {
		t.Errorf("verifyFreshness() should succeed when within freshness window: %v", err)
	}
}

// TestVerifyPCRsNoExpectedPCRs tests PCR verification with no expected values
func TestVerifyPCRsNoExpectedPCRs(t *testing.T) {
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
		VerifyPCRs:   true,
		ExpectedPCRs: map[uint32][]byte{}, // No expected values
	}

	err := v.verifyPCRs(stmt, opts)
	if err != nil {
		t.Errorf("verifyPCRs() should succeed with no expected PCRs: %v", err)
	}
}

// TestVerifyPCRsNoPCRValuesInStatement tests PCR verification when statement has no PCRs
func TestVerifyPCRsNoPCRValuesInStatement(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    publicKey,
		AttestedKeyPublic:     publicKey,
		PCRValues:             nil, // No PCRs
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{
		VerifyPCRs:   true,
		ExpectedPCRs: map[uint32][]byte{}, // No expected values
	}

	err := v.verifyPCRs(stmt, opts)
	if err != nil {
		t.Errorf("verifyPCRs() should succeed when both have no PCRs: %v", err)
	}
}

// TestVerifyPCRsExpectedButNoneProvided tests PCR verification expecting PCRs but none in statement
func TestVerifyPCRsExpectedButNoneProvided(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    publicKey,
		AttestedKeyPublic:     publicKey,
		PCRValues:             nil, // No PCRs
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{
		VerifyPCRs: true,
		ExpectedPCRs: map[uint32][]byte{
			0: {0x00, 0x01, 0x02, 0x03},
		},
	}

	err := v.verifyPCRs(stmt, opts)
	if err == nil {
		t.Errorf("verifyPCRs() should fail when expected PCRs but none provided")
	}
}

// TestVerifyPCRsMissingPCR tests PCR verification with missing PCR index
func TestVerifyPCRsMissingPCR(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    publicKey,
		AttestedKeyPublic:     publicKey,
		PCRValues: map[uint32][]byte{
			0: {0x00, 0x01, 0x02, 0x03},
			// PCR 1 is missing
		},
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{
		VerifyPCRs: true,
		ExpectedPCRs: map[uint32][]byte{
			0: {0x00, 0x01, 0x02, 0x03},
			1: {0x04, 0x05, 0x06, 0x07},
		},
	}

	err := v.verifyPCRs(stmt, opts)
	if err == nil {
		t.Errorf("verifyPCRs() should fail when expected PCR is missing")
	}
}

// TestHashInvalidPublicKey tests Hash with invalid public key
func TestHashInvalidPublicKey(t *testing.T) {
	// Use a type that can't be marshaled
	type invalidKey struct{}

	stmt := &AttestationStatement{
		AttestedKeyPublic: invalidKey{},
	}

	_, err := stmt.Hash()
	if err == nil {
		t.Errorf("Hash() should fail with invalid public key type")
	}
}

// TestBytesEqualDifferentLengths tests bytesEqual with different lengths
func TestBytesEqualDifferentLengths(t *testing.T) {
	a := []byte{0x01, 0x02, 0x03}
	b := []byte{0x01, 0x02}

	if bytesEqual(a, b) {
		t.Errorf("bytesEqual() should return false for different lengths")
	}
}

// TestBytesEqualSame tests bytesEqual with identical bytes
func TestBytesEqualSame(t *testing.T) {
	a := []byte{0x01, 0x02, 0x03}
	b := []byte{0x01, 0x02, 0x03}

	if !bytesEqual(a, b) {
		t.Errorf("bytesEqual() should return true for identical bytes")
	}
}

// TestBytesEqualDifferent tests bytesEqual with different bytes
func TestBytesEqualDifferent(t *testing.T) {
	a := []byte{0x01, 0x02, 0x03}
	b := []byte{0x01, 0x02, 0x04}

	if bytesEqual(a, b) {
		t.Errorf("bytesEqual() should return false for different bytes")
	}
}

// TestVerifyWithPCRs tests complete verification with PCR validation
func TestVerifyWithPCRs(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	data := []byte("test attestation data")
	h := sha256.Sum256(data)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, h[:])

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

	certBytes, _ := x509.CreateCertificate(rand.Reader, cert, cert, publicKey, privKey)
	parsedCert, _ := x509.ParseCertificate(certBytes)

	pcrValues := map[uint32][]byte{
		0: {0x00, 0x01, 0x02, 0x03},
		1: {0x04, 0x05, 0x06, 0x07},
	}

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    publicKey,
		Signature:             sig,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		CertificateChain:      []*x509.Certificate{parsedCert},
		AttestedKeyPublic:     publicKey,
		AttestationData:       data,
		CreatedAt:             time.Now().Format(time.RFC3339),
		Backend:               "tpm2",
		Nonce:                 []byte("test-nonce"),
		PCRValues:             pcrValues,
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{
		AllowSelfSigned: true,
		CheckFreshness:  true,
		FreshnessWindow: 300,
		ExpectedNonce:   []byte("test-nonce"),
		VerifyPCRs:      true,
		ExpectedPCRs:    pcrValues,
	}

	err := v.Verify(stmt, opts)
	if err != nil {
		t.Errorf("Verify() with PCRs failed: %v", err)
	}
}

// TestVerifyFailsOnInvalidPCRs tests complete verification fails with invalid PCRs
func TestVerifyFailsOnInvalidPCRs(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	data := []byte("test attestation data")
	h := sha256.Sum256(data)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, h[:])

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

	certBytes, _ := x509.CreateCertificate(rand.Reader, cert, cert, publicKey, privKey)
	parsedCert, _ := x509.ParseCertificate(certBytes)

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    publicKey,
		Signature:             sig,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		CertificateChain:      []*x509.Certificate{parsedCert},
		AttestedKeyPublic:     publicKey,
		AttestationData:       data,
		CreatedAt:             time.Now().Format(time.RFC3339),
		Backend:               "tpm2",
		Nonce:                 []byte("test-nonce"),
		PCRValues: map[uint32][]byte{
			0: {0x00, 0x01, 0x02, 0x03},
		},
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{
		AllowSelfSigned: true,
		CheckFreshness:  true,
		FreshnessWindow: 300,
		ExpectedNonce:   []byte("test-nonce"),
		VerifyPCRs:      true,
		ExpectedPCRs: map[uint32][]byte{
			0: {0xFF, 0xFF, 0xFF, 0xFF}, // Different values
		},
	}

	err := v.Verify(stmt, opts)
	if err == nil {
		t.Errorf("Verify() should fail with mismatched PCRs")
	}
}

// TestVerifyFailsOnInvalidSignature tests complete verification fails with invalid signature
func TestVerifyFailsOnInvalidSignature(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

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

	certBytes, _ := x509.CreateCertificate(rand.Reader, cert, cert, publicKey, privKey)
	parsedCert, _ := x509.ParseCertificate(certBytes)

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    publicKey,
		Signature:             []byte("invalid-signature"), // Invalid signature
		SignatureAlgorithm:    x509.SHA256WithRSA,
		CertificateChain:      []*x509.Certificate{parsedCert},
		AttestedKeyPublic:     publicKey,
		AttestationData:       []byte("test data"),
		CreatedAt:             time.Now().Format(time.RFC3339),
		Backend:               "tpm2",
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{
		AllowSelfSigned: true,
	}

	err := v.Verify(stmt, opts)
	if err == nil {
		t.Errorf("Verify() should fail with invalid signature")
	}
}

// TestVerifyFailsOnFreshness tests complete verification fails on freshness check
func TestVerifyFailsOnFreshness(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	data := []byte("test attestation data")
	h := sha256.Sum256(data)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, h[:])

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

	certBytes, _ := x509.CreateCertificate(rand.Reader, cert, cert, publicKey, privKey)
	parsedCert, _ := x509.ParseCertificate(certBytes)

	// Create old attestation
	oldTime := time.Now().AddDate(0, 0, -1).Format(time.RFC3339)

	stmt := &AttestationStatement{
		Format:                "tpm2",
		AttestingKeyAlgorithm: x509.RSA,
		AttestingKeyPublic:    publicKey,
		Signature:             sig,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		CertificateChain:      []*x509.Certificate{parsedCert},
		AttestedKeyPublic:     publicKey,
		AttestationData:       data,
		CreatedAt:             oldTime, // Old timestamp
		Backend:               "tpm2",
		Nonce:                 []byte("test-nonce"),
	}

	v := NewVerifier(nil)
	opts := &VerifyOptions{
		AllowSelfSigned: true,
		CheckFreshness:  true,
		FreshnessWindow: 300,
		ExpectedNonce:   []byte("test-nonce"),
	}

	err := v.Verify(stmt, opts)
	if err == nil {
		t.Errorf("Verify() should fail on freshness check")
	}
}

// TestVerifyRSASignatureHashNil tests handling of nil hash
func TestVerifyRSASignatureHashNil(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privKey.PublicKey

	v := NewVerifier(nil)

	// Use an algorithm that would create a nil hash
	err := v.verifyRSASignature(publicKey, []byte("sig"), []byte("data"), x509.SHA1WithRSA)
	if err == nil {
		t.Errorf("verifyRSASignature() should fail with unsupported hash algorithm")
	}
}
