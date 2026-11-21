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

package android

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"
)

// makeTestAttestationCert creates a self-signed EC P-256 certificate with
// a minimal Android Key Attestation extension.
func makeTestAttestationCert(
	t *testing.T,
	securityLevel SecurityLevel,
	challenge []byte,
) *x509.Certificate {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}

	extBytes, err := BuildMinimalAttestationExtension(
		3, // attestation version
		securityLevel,
		4,                               // keymaster version
		SecurityLevelTrustedEnvironment, // keymaster security level
		challenge,
		nil, // no unique ID
	)
	if err != nil {
		t.Fatalf("failed to build attestation extension: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Android Attestation",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    AndroidKeyAttestationOID,
				Value: extBytes,
			},
		},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

// makeTestCA creates a self-signed CA certificate and returns it along with the private key.
func makeTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1000),
		Subject: pkix.Name{
			CommonName: "Test Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	return caCert, caKey
}

// makeTestAttestationCertWithRootOfTrust creates a certificate with a RootOfTrust
// embedded in the teeEnforced AuthorizationList.
func makeTestAttestationCertWithRootOfTrust(
	t *testing.T,
	securityLevel SecurityLevel,
	challenge []byte,
	bootState VerifiedBootState,
	deviceLocked bool,
) *x509.Certificate {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}

	extBytes, err := buildAttestationExtensionWithRootOfTrust(
		3, securityLevel, 4, SecurityLevelTrustedEnvironment,
		challenge, nil, bootState, deviceLocked,
	)
	if err != nil {
		t.Fatalf("failed to build attestation extension with RootOfTrust: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Android Attestation with RootOfTrust",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    AndroidKeyAttestationOID,
				Value: extBytes,
			},
		},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

// buildAttestationExtensionWithRootOfTrust creates an attestation extension
// that includes a RootOfTrust in the teeEnforced AuthorizationList.
func buildAttestationExtensionWithRootOfTrust(
	version int,
	attestSecLevel SecurityLevel,
	kmVersion int,
	kmSecLevel SecurityLevel,
	challenge []byte,
	uniqueID []byte,
	bootState VerifiedBootState,
	deviceLocked bool,
) ([]byte, error) {
	// Build empty AuthorizationList for softwareEnforced
	emptySeq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      []byte{},
	})
	if err != nil {
		return nil, err
	}

	// Build RootOfTrust SEQUENCE
	rot := rootOfTrustASN1{
		VerifiedBootKey:   []byte("verified-boot-key-data-32-bytes!"),
		DeviceLocked:      deviceLocked,
		VerifiedBootState: asn1.Enumerated(bootState),
		VerifiedBootHash:  []byte("verified-boot-hash-32-bytes!!!!"),
	}
	rotBytes, err := asn1.Marshal(rot)
	if err != nil {
		return nil, err
	}

	// Wrap RootOfTrust in its context-specific constructed tag, 704.
	rotTagged := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        704, // rootOfTrust, as every real device encodes it
		IsCompound: true,
		Bytes:      rotBytes,
	}
	rotTaggedBytes, err := asn1.Marshal(rotTagged)
	if err != nil {
		return nil, err
	}

	// Build teeEnforced AuthorizationList with RootOfTrust inside
	teeSeq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      rotTaggedBytes,
	})
	if err != nil {
		return nil, err
	}

	// Marshal individual fields
	versionBytes, err := asn1.Marshal(version)
	if err != nil {
		return nil, err
	}
	attestSecBytes, err := asn1.Marshal(asn1.Enumerated(attestSecLevel))
	if err != nil {
		return nil, err
	}
	kmVersionBytes, err := asn1.Marshal(kmVersion)
	if err != nil {
		return nil, err
	}
	kmSecBytes, err := asn1.Marshal(asn1.Enumerated(kmSecLevel))
	if err != nil {
		return nil, err
	}
	challengeBytes, err := asn1.Marshal(challenge)
	if err != nil {
		return nil, err
	}
	uniqueIDBytes, err := asn1.Marshal(uniqueID)
	if err != nil {
		return nil, err
	}

	var seqContent bytes.Buffer
	seqContent.Write(versionBytes)
	seqContent.Write(attestSecBytes)
	seqContent.Write(kmVersionBytes)
	seqContent.Write(kmSecBytes)
	seqContent.Write(challengeBytes)
	seqContent.Write(uniqueIDBytes)
	seqContent.Write(emptySeq) // softwareEnforced
	seqContent.Write(teeSeq)   // teeEnforced with RootOfTrust

	result, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      seqContent.Bytes(),
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}

// TestParseKeyAttestation_NilCertificate verifies that a nil certificate returns ErrNilCertificate.
func TestParseKeyAttestation_NilCertificate(t *testing.T) {
	desc, err := ParseKeyAttestation(nil)
	if desc != nil {
		t.Errorf("expected nil KeyDescription, got %+v", desc)
	}
	if !errors.Is(err, ErrNilCertificate) {
		t.Errorf("expected ErrNilCertificate, got: %v", err)
	}
}

// TestParseKeyAttestation_NoExtension verifies that a certificate without the
// Android attestation OID returns ErrExtensionNotFound.
func TestParseKeyAttestation_NoExtension(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "No Attestation Extension",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	desc, err := ParseKeyAttestation(cert)
	if desc != nil {
		t.Errorf("expected nil KeyDescription, got %+v", desc)
	}
	if !errors.Is(err, ErrExtensionNotFound) {
		t.Errorf("expected ErrExtensionNotFound, got: %v", err)
	}
}

// TestParseKeyAttestation_ValidExtension verifies successful parsing of a
// certificate with a valid attestation extension.
func TestParseKeyAttestation_ValidExtension(t *testing.T) {
	challenge := []byte("test-challenge-nonce")
	cert := makeTestAttestationCert(t, SecurityLevelTrustedEnvironment, challenge)

	desc, err := ParseKeyAttestation(cert)
	if err != nil {
		t.Fatalf("ParseKeyAttestation() unexpected error: %v", err)
	}

	if desc.AttestationVersion != 3 {
		t.Errorf("AttestationVersion = %d, want 3", desc.AttestationVersion)
	}

	if desc.AttestationSecurityLevel != SecurityLevelTrustedEnvironment {
		t.Errorf("AttestationSecurityLevel = %v, want %v",
			desc.AttestationSecurityLevel, SecurityLevelTrustedEnvironment)
	}

	if desc.KeymasterVersion != 4 {
		t.Errorf("KeymasterVersion = %d, want 4", desc.KeymasterVersion)
	}

	if desc.KeymasterSecurityLevel != SecurityLevelTrustedEnvironment {
		t.Errorf("KeymasterSecurityLevel = %v, want %v",
			desc.KeymasterSecurityLevel, SecurityLevelTrustedEnvironment)
	}

	if string(desc.AttestationChallenge) != string(challenge) {
		t.Errorf("AttestationChallenge = %q, want %q",
			desc.AttestationChallenge, challenge)
	}
}

// TestParseKeyAttestation_InvalidASN1 verifies that malformed ASN.1 data
// in the extension returns ErrExtensionParseFailed.
func TestParseKeyAttestation_InvalidASN1(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Bad ASN1 Attestation",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    AndroidKeyAttestationOID,
				Value: []byte{0xFF, 0xFF, 0xFF}, // Invalid ASN.1
			},
		},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	desc, err := ParseKeyAttestation(cert)
	if desc != nil {
		t.Errorf("expected nil KeyDescription, got %+v", desc)
	}
	if !errors.Is(err, ErrExtensionParseFailed) {
		t.Errorf("expected ErrExtensionParseFailed, got: %v", err)
	}
}

// TestParseKeyAttestation_TrailingData verifies that trailing data after the
// KeyDescription SEQUENCE is rejected.
func TestParseKeyAttestation_TrailingData(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	extBytes, err := BuildMinimalAttestationExtension(
		3, SecurityLevelSoftware, 4, SecurityLevelSoftware,
		[]byte("challenge"), nil,
	)
	if err != nil {
		t.Fatalf("failed to build extension: %v", err)
	}

	// Append trailing bytes
	extBytes = append(extBytes, 0x00, 0x00)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Trailing Data",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    AndroidKeyAttestationOID,
				Value: extBytes,
			},
		},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	desc, err := ParseKeyAttestation(cert)
	if desc != nil {
		t.Errorf("expected nil KeyDescription, got %+v", desc)
	}
	if !errors.Is(err, ErrExtensionParseFailed) {
		t.Errorf("expected ErrExtensionParseFailed, got: %v", err)
	}
}

// TestSecurityLevel_String verifies the String() method for all SecurityLevel values.
func TestSecurityLevel_String(t *testing.T) {
	tests := []struct {
		level    SecurityLevel
		expected string
	}{
		{SecurityLevelSoftware, "software"},
		{SecurityLevelTrustedEnvironment, "tee"},
		{SecurityLevelStrongBox, "strongbox"},
		{SecurityLevel(99), "unknown(99)"},
		{SecurityLevel(-1), "unknown(-1)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.level.String()
			if result != tt.expected {
				t.Errorf("SecurityLevel(%d).String() = %q, want %q",
					int(tt.level), result, tt.expected)
			}
		})
	}
}

// TestVerifiedBootState_String verifies the String() method for all VerifiedBootState values.
func TestVerifiedBootState_String(t *testing.T) {
	tests := []struct {
		state    VerifiedBootState
		expected string
	}{
		{VerifiedBootVerified, "verified"},
		{VerifiedBootSelfSigned, "self-signed"},
		{VerifiedBootUnverified, "unverified"},
		{VerifiedBootFailed, "failed"},
		{VerifiedBootState(42), "unknown(42)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.state.String()
			if result != tt.expected {
				t.Errorf("VerifiedBootState(%d).String() = %q, want %q",
					int(tt.state), result, tt.expected)
			}
		})
	}
}

// TestVerifyKeyAttestation_NilChain verifies ErrChainTooShort on nil chain.
func TestVerifyKeyAttestation_NilChain(t *testing.T) {
	opts := &VerifyOptions{
		ExpectedNonce:    []byte("nonce"),
		MinSecurityLevel: SecurityLevelSoftware,
	}

	desc, err := VerifyKeyAttestation(nil, opts)
	if desc != nil {
		t.Errorf("expected nil KeyDescription, got %+v", desc)
	}
	if !errors.Is(err, ErrChainTooShort) {
		t.Errorf("expected ErrChainTooShort, got: %v", err)
	}
}

// TestVerifyKeyAttestation_EmptyChain verifies ErrChainTooShort on empty chain.
func TestVerifyKeyAttestation_EmptyChain(t *testing.T) {
	opts := &VerifyOptions{
		ExpectedNonce:    []byte("nonce"),
		MinSecurityLevel: SecurityLevelSoftware,
	}

	desc, err := VerifyKeyAttestation([]*x509.Certificate{}, opts)
	if desc != nil {
		t.Errorf("expected nil KeyDescription, got %+v", desc)
	}
	if !errors.Is(err, ErrChainTooShort) {
		t.Errorf("expected ErrChainTooShort, got: %v", err)
	}
}

// TestVerifyKeyAttestation_NilOptions verifies ErrNilVerifyOptions on nil opts.
func TestVerifyKeyAttestation_NilOptions(t *testing.T) {
	cert := makeTestAttestationCert(t, SecurityLevelTrustedEnvironment, []byte("nonce"))

	desc, err := VerifyKeyAttestation([]*x509.Certificate{cert}, nil)
	if desc != nil {
		t.Errorf("expected nil KeyDescription, got %+v", desc)
	}
	if !errors.Is(err, ErrNilVerifyOptions) {
		t.Errorf("expected ErrNilVerifyOptions, got: %v", err)
	}
}

// TestVerifyKeyAttestation_NonceMismatch creates a cert with one nonce and
// verifies that providing a different expected nonce returns ErrNonceMismatch.
func TestVerifyKeyAttestation_NonceMismatch(t *testing.T) {
	actualNonce := []byte("actual-nonce-value")
	cert := makeTestAttestationCert(t, SecurityLevelTrustedEnvironment, actualNonce)

	opts := &VerifyOptions{
		ExpectedNonce:    []byte("different-nonce"),
		MinSecurityLevel: SecurityLevelSoftware,
	}

	desc, err := VerifyKeyAttestation([]*x509.Certificate{cert}, opts)
	if desc != nil {
		t.Errorf("expected nil KeyDescription, got %+v", desc)
	}
	if !errors.Is(err, ErrNonceMismatch) {
		t.Errorf("expected ErrNonceMismatch, got: %v", err)
	}
}

// TestVerifyKeyAttestation_NonceMismatchDifferentLength verifies nonce mismatch
// when nonces have different lengths.
func TestVerifyKeyAttestation_NonceMismatchDifferentLength(t *testing.T) {
	actualNonce := []byte("short")
	cert := makeTestAttestationCert(t, SecurityLevelTrustedEnvironment, actualNonce)

	opts := &VerifyOptions{
		ExpectedNonce:    []byte("much-longer-nonce-value"),
		MinSecurityLevel: SecurityLevelSoftware,
	}

	desc, err := VerifyKeyAttestation([]*x509.Certificate{cert}, opts)
	if desc != nil {
		t.Errorf("expected nil KeyDescription, got %+v", desc)
	}
	if !errors.Is(err, ErrNonceMismatch) {
		t.Errorf("expected ErrNonceMismatch, got: %v", err)
	}
}

// TestVerifyKeyAttestation_InsufficientSecurityLevel creates an attestation
// with Software level and verifies that requiring TEE returns ErrInsufficientSecurityLevel.
func TestVerifyKeyAttestation_InsufficientSecurityLevel(t *testing.T) {
	nonce := []byte("test-nonce")
	cert := makeTestAttestationCert(t, SecurityLevelSoftware, nonce)

	opts := &VerifyOptions{
		ExpectedNonce:    nonce,
		MinSecurityLevel: SecurityLevelTrustedEnvironment,
	}

	desc, err := VerifyKeyAttestation([]*x509.Certificate{cert}, opts)
	if desc != nil {
		t.Errorf("expected nil KeyDescription, got %+v", desc)
	}
	if !errors.Is(err, ErrInsufficientSecurityLevel) {
		t.Errorf("expected ErrInsufficientSecurityLevel, got: %v", err)
	}
}

// TestVerifyKeyAttestation_InsufficientSecurityLevel_StrongBox verifies that
// requiring StrongBox rejects TEE-level attestations.
func TestVerifyKeyAttestation_InsufficientSecurityLevel_StrongBox(t *testing.T) {
	nonce := []byte("strongbox-test")
	cert := makeTestAttestationCert(t, SecurityLevelTrustedEnvironment, nonce)

	opts := &VerifyOptions{
		ExpectedNonce:    nonce,
		MinSecurityLevel: SecurityLevelStrongBox,
	}

	desc, err := VerifyKeyAttestation([]*x509.Certificate{cert}, opts)
	if desc != nil {
		t.Errorf("expected nil KeyDescription, got %+v", desc)
	}
	if !errors.Is(err, ErrInsufficientSecurityLevel) {
		t.Errorf("expected ErrInsufficientSecurityLevel, got: %v", err)
	}
}

// TestVerifyKeyAttestation_Success verifies a valid attestation chain
// with matching nonce and sufficient security level.
func TestVerifyKeyAttestation_Success(t *testing.T) {
	nonce := []byte("valid-nonce-1234")
	cert := makeTestAttestationCert(t, SecurityLevelTrustedEnvironment, nonce)

	opts := &VerifyOptions{
		ExpectedNonce:    nonce,
		MinSecurityLevel: SecurityLevelSoftware,
	}

	desc, err := VerifyKeyAttestation([]*x509.Certificate{cert}, opts)
	if err != nil {
		t.Fatalf("VerifyKeyAttestation() unexpected error: %v", err)
	}

	if desc.AttestationSecurityLevel != SecurityLevelTrustedEnvironment {
		t.Errorf("AttestationSecurityLevel = %v, want %v",
			desc.AttestationSecurityLevel, SecurityLevelTrustedEnvironment)
	}

	if string(desc.AttestationChallenge) != string(nonce) {
		t.Errorf("AttestationChallenge = %q, want %q",
			desc.AttestationChallenge, nonce)
	}
}

// TestVerifyKeyAttestation_NoNonceCheck verifies that omitting ExpectedNonce
// skips nonce verification.
func TestVerifyKeyAttestation_NoNonceCheck(t *testing.T) {
	cert := makeTestAttestationCert(t, SecurityLevelTrustedEnvironment, []byte("any-nonce"))

	opts := &VerifyOptions{
		ExpectedNonce:    nil, // Do not check nonce
		MinSecurityLevel: SecurityLevelSoftware,
	}

	desc, err := VerifyKeyAttestation([]*x509.Certificate{cert}, opts)
	if err != nil {
		t.Fatalf("VerifyKeyAttestation() unexpected error: %v", err)
	}

	if desc == nil {
		t.Fatal("expected non-nil KeyDescription")
	}
}

// TestVerifyKeyAttestation_ChainVerificationFailed verifies that an invalid
// chain against trusted roots returns ErrChainVerificationFailed.
func TestVerifyKeyAttestation_ChainVerificationFailed(t *testing.T) {
	nonce := []byte("chain-test")
	cert := makeTestAttestationCert(t, SecurityLevelTrustedEnvironment, nonce)

	// Create a root pool with a different key
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	otherTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(999),
		Subject: pkix.Name{
			CommonName: "Other Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	otherCertBytes, err := x509.CreateCertificate(rand.Reader, otherTemplate, otherTemplate,
		&otherKey.PublicKey, otherKey)
	if err != nil {
		t.Fatalf("failed to create other root cert: %v", err)
	}

	otherCert, err := x509.ParseCertificate(otherCertBytes)
	if err != nil {
		t.Fatalf("failed to parse other root cert: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(otherCert)

	opts := &VerifyOptions{
		TrustedRoots:     roots,
		ExpectedNonce:    nonce,
		MinSecurityLevel: SecurityLevelSoftware,
	}

	desc, err := VerifyKeyAttestation([]*x509.Certificate{cert}, opts)
	if desc != nil {
		t.Errorf("expected nil KeyDescription, got %+v", desc)
	}
	if !errors.Is(err, ErrChainVerificationFailed) {
		t.Errorf("expected ErrChainVerificationFailed, got: %v", err)
	}
}

// TestVerifyKeyAttestation_NoExtensionInLeaf verifies that a chain whose leaf
// lacks the attestation extension returns ErrExtensionNotFound.
func TestVerifyKeyAttestation_NoExtensionInLeaf(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "No Extension Leaf",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	opts := &VerifyOptions{
		MinSecurityLevel: SecurityLevelSoftware,
	}

	desc, err := VerifyKeyAttestation([]*x509.Certificate{cert}, opts)
	if desc != nil {
		t.Errorf("expected nil KeyDescription, got %+v", desc)
	}
	if !errors.Is(err, ErrExtensionNotFound) {
		t.Errorf("expected ErrExtensionNotFound, got: %v", err)
	}
}

// TestBuildMinimalAttestationExtension_RoundTrip verifies that
// BuildMinimalAttestationExtension produces valid ASN.1 that can be parsed.
func TestBuildMinimalAttestationExtension_RoundTrip(t *testing.T) {
	challenge := []byte("round-trip-test")
	uniqueID := []byte("device-123")

	extBytes, err := BuildMinimalAttestationExtension(
		4,                               // version
		SecurityLevelStrongBox,          // attest sec level
		100,                             // km version
		SecurityLevelTrustedEnvironment, // km sec level
		challenge,
		uniqueID,
	)
	if err != nil {
		t.Fatalf("BuildMinimalAttestationExtension() error: %v", err)
	}

	// Verify it can be parsed as ASN.1
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(extBytes, &raw)
	if err != nil {
		t.Fatalf("failed to unmarshal built extension: %v", err)
	}
	if len(rest) > 0 {
		t.Errorf("trailing data after unmarshal: %d bytes", len(rest))
	}

	// Now embed in a certificate and parse
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "RoundTrip Test",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    AndroidKeyAttestationOID,
				Value: extBytes,
			},
		},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	desc, err := ParseKeyAttestation(cert)
	if err != nil {
		t.Fatalf("ParseKeyAttestation() error: %v", err)
	}

	if desc.AttestationVersion != 4 {
		t.Errorf("AttestationVersion = %d, want 4", desc.AttestationVersion)
	}
	if desc.AttestationSecurityLevel != SecurityLevelStrongBox {
		t.Errorf("AttestationSecurityLevel = %v, want %v",
			desc.AttestationSecurityLevel, SecurityLevelStrongBox)
	}
	if desc.KeymasterVersion != 100 {
		t.Errorf("KeymasterVersion = %d, want 100", desc.KeymasterVersion)
	}
	if desc.KeymasterSecurityLevel != SecurityLevelTrustedEnvironment {
		t.Errorf("KeymasterSecurityLevel = %v, want %v",
			desc.KeymasterSecurityLevel, SecurityLevelTrustedEnvironment)
	}
	if string(desc.AttestationChallenge) != string(challenge) {
		t.Errorf("AttestationChallenge = %q, want %q",
			desc.AttestationChallenge, challenge)
	}
	if string(desc.UniqueID) != string(uniqueID) {
		t.Errorf("UniqueID = %q, want %q", desc.UniqueID, uniqueID)
	}
}

// TestAndroidKeyAttestationOID verifies the OID constant is correct.
func TestAndroidKeyAttestationOID(t *testing.T) {
	expected := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}
	if !AndroidKeyAttestationOID.Equal(expected) {
		t.Errorf("AndroidKeyAttestationOID = %v, want %v",
			AndroidKeyAttestationOID, expected)
	}
}

// TestParseAuthorizationList_Empty verifies that an empty authorization list
// does not cause errors.
func TestParseAuthorizationList_Empty(t *testing.T) {
	result := parseAuthorizationList(asn1.RawValue{})
	if result.RootOfTrust != nil {
		t.Errorf("expected nil RootOfTrust for empty AuthorizationList")
	}
	if len(result.Purpose) != 0 {
		t.Errorf("expected empty Purpose, got %v", result.Purpose)
	}
}

// TestFindRootOfTrust_NilData verifies that nil data returns nil.
func TestFindRootOfTrust_NilData(t *testing.T) {
	result := findRootOfTrust(nil)
	if result != nil {
		t.Errorf("expected nil for nil data, got %+v", result)
	}
}

// TestFindRootOfTrust_InvalidData verifies that invalid data returns nil.
func TestFindRootOfTrust_InvalidData(t *testing.T) {
	result := findRootOfTrust([]byte{0xFF, 0xFF})
	if result != nil {
		t.Errorf("expected nil for invalid data, got %+v", result)
	}
}

// TestFindRootOfTrust_ValidRootOfTrust verifies that a properly encoded
// RootOfTrust SEQUENCE is found and parsed within an AuthorizationList.
func TestFindRootOfTrust_ValidRootOfTrust(t *testing.T) {
	// Build a RootOfTrust SEQUENCE
	rot := rootOfTrustASN1{
		VerifiedBootKey:   []byte("verified-boot-key-data-32-bytes!"),
		DeviceLocked:      true,
		VerifiedBootState: asn1.Enumerated(VerifiedBootVerified),
		VerifiedBootHash:  []byte("verified-boot-hash-32-bytes!!!!"),
	}
	rotBytes, err := asn1.Marshal(rot)
	if err != nil {
		t.Fatalf("failed to marshal RootOfTrust: %v", err)
	}

	// Wrap in context-specific constructed tag
	rotTagged := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        704,
		IsCompound: true,
		Bytes:      rotBytes,
	}
	rotTaggedBytes, err := asn1.Marshal(rotTagged)
	if err != nil {
		t.Fatalf("failed to marshal tagged RootOfTrust: %v", err)
	}

	// Wrap in outer SEQUENCE (AuthorizationList)
	outerSeq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      rotTaggedBytes,
	})
	if err != nil {
		t.Fatalf("failed to marshal outer SEQUENCE: %v", err)
	}

	result := findRootOfTrust(outerSeq)
	if result == nil {
		t.Fatal("expected non-nil RootOfTrust")
	}
	if !result.DeviceLocked {
		t.Error("expected DeviceLocked = true")
	}
	if result.VerifiedBootState != VerifiedBootVerified {
		t.Errorf("VerifiedBootState = %v, want %v",
			result.VerifiedBootState, VerifiedBootVerified)
	}
	if !bytes.Equal(result.VerifiedBootKey, []byte("verified-boot-key-data-32-bytes!")) {
		t.Errorf("VerifiedBootKey mismatch")
	}
	if !bytes.Equal(result.VerifiedBootHash, []byte("verified-boot-hash-32-bytes!!!!")) {
		t.Errorf("VerifiedBootHash mismatch")
	}
}

// TestFindRootOfTrust_TrailingDataOnOuterSequence verifies that trailing data
// after the outer SEQUENCE causes findRootOfTrust to return nil.
func TestFindRootOfTrust_TrailingDataOnOuterSequence(t *testing.T) {
	// Build a valid SEQUENCE and append trailing bytes
	innerBytes, err := asn1.Marshal(42)
	if err != nil {
		t.Fatalf("failed to marshal inner value: %v", err)
	}

	outerSeq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      innerBytes,
	})
	if err != nil {
		t.Fatalf("failed to marshal outer SEQUENCE: %v", err)
	}

	// Append trailing data
	outerSeq = append(outerSeq, 0x00, 0x01)

	result := findRootOfTrust(outerSeq)
	if result != nil {
		t.Errorf("expected nil for trailing data, got %+v", result)
	}
}

// TestFindRootOfTrust_EmptySequence verifies that an empty outer SEQUENCE
// with no elements returns nil.
func TestFindRootOfTrust_EmptySequence(t *testing.T) {
	outerSeq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      []byte{},
	})
	if err != nil {
		t.Fatalf("failed to marshal empty SEQUENCE: %v", err)
	}

	result := findRootOfTrust(outerSeq)
	if result != nil {
		t.Errorf("expected nil for empty SEQUENCE, got %+v", result)
	}
}

// TestFindRootOfTrust_NonCompoundContextSpecific verifies that a context-specific
// element that is not compound (not constructed) is skipped.
func TestFindRootOfTrust_NonCompoundContextSpecific(t *testing.T) {
	// Create a context-specific PRIMITIVE element (not compound)
	primitiveElem := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        704, // the right tag, deliberately not constructed
		IsCompound: false,
		Bytes:      []byte{0x01, 0x02, 0x03},
	}
	primitiveBytes, err := asn1.Marshal(primitiveElem)
	if err != nil {
		t.Fatalf("failed to marshal primitive element: %v", err)
	}

	outerSeq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      primitiveBytes,
	})
	if err != nil {
		t.Fatalf("failed to marshal outer SEQUENCE: %v", err)
	}

	result := findRootOfTrust(outerSeq)
	if result != nil {
		t.Errorf("expected nil for non-compound context-specific, got %+v", result)
	}
}

// TestFindRootOfTrust_CompoundButNotRootOfTrust verifies that a compound
// context-specific element whose content is not a valid RootOfTrust is skipped.
func TestFindRootOfTrust_CompoundButNotRootOfTrust(t *testing.T) {
	// Create a compound context-specific element with content that cannot
	// be parsed as rootOfTrustASN1.
	invalidContent := []byte{0x02, 0x01, 0x05} // Just an INTEGER 5
	compoundElem := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        704, // the right tag, with content that is not a RootOfTrust
		IsCompound: true,
		Bytes:      invalidContent,
	}
	compoundBytes, err := asn1.Marshal(compoundElem)
	if err != nil {
		t.Fatalf("failed to marshal compound element: %v", err)
	}

	outerSeq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      compoundBytes,
	})
	if err != nil {
		t.Fatalf("failed to marshal outer SEQUENCE: %v", err)
	}

	result := findRootOfTrust(outerSeq)
	if result != nil {
		t.Errorf("expected nil for non-RootOfTrust compound, got %+v", result)
	}
}

// TestFindRootOfTrust_MixedElementsWithRootOfTrust verifies that findRootOfTrust
// correctly iterates past non-matching elements to find a valid RootOfTrust.
func TestFindRootOfTrust_MixedElementsWithRootOfTrust(t *testing.T) {
	// First element: a simple universal INTEGER (non-context-specific, should be skipped)
	intBytes, err := asn1.Marshal(42)
	if err != nil {
		t.Fatalf("failed to marshal integer: %v", err)
	}

	// Second element: compound context-specific but not parseable as RootOfTrust
	badCompound := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        1,
		IsCompound: true,
		Bytes:      []byte{0x02, 0x01, 0x05},
	}
	badCompoundBytes, err := asn1.Marshal(badCompound)
	if err != nil {
		t.Fatalf("failed to marshal bad compound: %v", err)
	}

	// Third element: the real RootOfTrust, under its own tag. The decoy above
	// keeps a different tag, so this now proves the walk selects by tag rather
	// than by whatever happens to decode.
	rot := rootOfTrustASN1{
		VerifiedBootKey:   []byte("boot-key-for-mixed-test-32byte!"),
		DeviceLocked:      false,
		VerifiedBootState: asn1.Enumerated(VerifiedBootSelfSigned),
		VerifiedBootHash:  []byte("boot-hash-for-mixed-test-32byt!"),
	}
	rotBytes, err := asn1.Marshal(rot)
	if err != nil {
		t.Fatalf("failed to marshal RootOfTrust: %v", err)
	}
	rotTagged := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        704,
		IsCompound: true,
		Bytes:      rotBytes,
	}
	rotTaggedBytes, err := asn1.Marshal(rotTagged)
	if err != nil {
		t.Fatalf("failed to marshal tagged RootOfTrust: %v", err)
	}

	// Concatenate all elements
	var content bytes.Buffer
	content.Write(intBytes)
	content.Write(badCompoundBytes)
	content.Write(rotTaggedBytes)

	outerSeq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      content.Bytes(),
	})
	if err != nil {
		t.Fatalf("failed to marshal outer SEQUENCE: %v", err)
	}

	result := findRootOfTrust(outerSeq)
	if result == nil {
		t.Fatal("expected non-nil RootOfTrust from mixed elements")
	}
	if result.DeviceLocked {
		t.Error("expected DeviceLocked = false")
	}
	if result.VerifiedBootState != VerifiedBootSelfSigned {
		t.Errorf("VerifiedBootState = %v, want %v",
			result.VerifiedBootState, VerifiedBootSelfSigned)
	}
}

// TestParseAuthorizationList_WithRootOfTrust verifies that parseAuthorizationList
// correctly populates the RootOfTrust field when present in the raw data.
func TestParseAuthorizationList_WithRootOfTrust(t *testing.T) {
	// Build a RootOfTrust inside a SEQUENCE
	rot := rootOfTrustASN1{
		VerifiedBootKey:   []byte("verified-boot-key-data-32-bytes!"),
		DeviceLocked:      true,
		VerifiedBootState: asn1.Enumerated(VerifiedBootVerified),
		VerifiedBootHash:  []byte("verified-boot-hash-32-bytes!!!!"),
	}
	rotBytes, err := asn1.Marshal(rot)
	if err != nil {
		t.Fatalf("failed to marshal RootOfTrust: %v", err)
	}

	rotTagged := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        704,
		IsCompound: true,
		Bytes:      rotBytes,
	}
	rotTaggedBytes, err := asn1.Marshal(rotTagged)
	if err != nil {
		t.Fatalf("failed to marshal tagged RootOfTrust: %v", err)
	}

	outerSeqBytes, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      rotTaggedBytes,
	})
	if err != nil {
		t.Fatalf("failed to marshal outer SEQUENCE: %v", err)
	}

	// Create a RawValue with FullBytes set (as asn1.Unmarshal would produce)
	rawVal := asn1.RawValue{
		FullBytes: outerSeqBytes,
	}

	result := parseAuthorizationList(rawVal)
	if result.RootOfTrust == nil {
		t.Fatal("expected non-nil RootOfTrust in AuthorizationList")
	}
	if !result.RootOfTrust.DeviceLocked {
		t.Error("expected DeviceLocked = true")
	}
	if result.RootOfTrust.VerifiedBootState != VerifiedBootVerified {
		t.Errorf("VerifiedBootState = %v, want %v",
			result.RootOfTrust.VerifiedBootState, VerifiedBootVerified)
	}
}

// TestVerifyKeyAttestation_BootStateVerifiedWithRootOfTrust verifies that boot
// state verification passes when the RootOfTrust has VerifiedBootVerified.
func TestVerifyKeyAttestation_BootStateVerifiedWithRootOfTrust(t *testing.T) {
	nonce := []byte("boot-verified-test")
	cert := makeTestAttestationCertWithRootOfTrust(
		t, SecurityLevelTrustedEnvironment, nonce,
		VerifiedBootVerified, true,
	)

	opts := &VerifyOptions{
		ExpectedNonce:    nonce,
		MinSecurityLevel: SecurityLevelSoftware,
		VerifyBootState:  true,
	}

	desc, err := VerifyKeyAttestation([]*x509.Certificate{cert}, opts)
	if err != nil {
		t.Fatalf("VerifyKeyAttestation() unexpected error: %v", err)
	}
	if desc == nil {
		t.Fatal("expected non-nil KeyDescription")
	}
}

// TestVerifyKeyAttestation_BootStateUnverifiedReturnsError verifies that boot
// state verification fails when the RootOfTrust shows unverified boot.
func TestVerifyKeyAttestation_BootStateUnverifiedReturnsError(t *testing.T) {
	nonce := []byte("boot-unverified-test")
	cert := makeTestAttestationCertWithRootOfTrust(
		t, SecurityLevelTrustedEnvironment, nonce,
		VerifiedBootUnverified, false,
	)

	opts := &VerifyOptions{
		ExpectedNonce:    nonce,
		MinSecurityLevel: SecurityLevelSoftware,
		VerifyBootState:  true,
	}

	desc, err := VerifyKeyAttestation([]*x509.Certificate{cert}, opts)
	if desc != nil {
		t.Errorf("expected nil KeyDescription, got %+v", desc)
	}
	if !errors.Is(err, ErrUnverifiedBoot) {
		t.Errorf("expected ErrUnverifiedBoot, got: %v", err)
	}
}

// TestVerifyKeyAttestation_BootStateNotCheckedWhenDisabled verifies that boot
// state verification is skipped when VerifyBootState is false, even if the
// device has an unverified boot state.
func TestVerifyKeyAttestation_BootStateNotCheckedWhenDisabled(t *testing.T) {
	nonce := []byte("boot-skip-test")
	cert := makeTestAttestationCertWithRootOfTrust(
		t, SecurityLevelTrustedEnvironment, nonce,
		VerifiedBootFailed, false,
	)

	opts := &VerifyOptions{
		ExpectedNonce:    nonce,
		MinSecurityLevel: SecurityLevelSoftware,
		VerifyBootState:  false, // Do not check boot state
	}

	desc, err := VerifyKeyAttestation([]*x509.Certificate{cert}, opts)
	if err != nil {
		t.Fatalf("VerifyKeyAttestation() unexpected error: %v", err)
	}
	if desc == nil {
		t.Fatal("expected non-nil KeyDescription")
	}
}

// TestVerifyKeyAttestation_BootStateNoRootOfTrust verifies that boot state
// verification passes when VerifyBootState is true but no RootOfTrust is present.
func TestVerifyKeyAttestation_BootStateNoRootOfTrust(t *testing.T) {
	nonce := []byte("no-rot-test")
	cert := makeTestAttestationCert(t, SecurityLevelTrustedEnvironment, nonce)

	opts := &VerifyOptions{
		ExpectedNonce:    nonce,
		MinSecurityLevel: SecurityLevelSoftware,
		VerifyBootState:  true, // Check boot state, but no RootOfTrust in cert
	}

	desc, err := VerifyKeyAttestation([]*x509.Certificate{cert}, opts)
	if err != nil {
		t.Fatalf("VerifyKeyAttestation() unexpected error: %v", err)
	}
	if desc == nil {
		t.Fatal("expected non-nil KeyDescription")
	}
}

// TestVerifyCertificateChain_SuccessWithIntermediates verifies successful chain
// verification with a root CA, intermediate CA, and leaf certificate.
func TestVerifyCertificateChain_SuccessWithIntermediates(t *testing.T) {
	// Create root CA
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate root key: %v", err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	rootCertBytes, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate,
		&rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to create root cert: %v", err)
	}

	rootCert, err := x509.ParseCertificate(rootCertBytes)
	if err != nil {
		t.Fatalf("failed to parse root cert: %v", err)
	}

	// Create intermediate CA
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate intermediate key: %v", err)
	}

	interTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Test Intermediate CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	interCertBytes, err := x509.CreateCertificate(rand.Reader, interTemplate, rootCert,
		&interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to create intermediate cert: %v", err)
	}

	interCert, err := x509.ParseCertificate(interCertBytes)
	if err != nil {
		t.Fatalf("failed to parse intermediate cert: %v", err)
	}

	// Create leaf certificate
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}

	nonce := []byte("chain-verify-nonce")
	extBytes, err := BuildMinimalAttestationExtension(
		3, SecurityLevelTrustedEnvironment, 4, SecurityLevelTrustedEnvironment,
		nonce, nil,
	)
	if err != nil {
		t.Fatalf("failed to build extension: %v", err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: "Test Leaf",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    AndroidKeyAttestationOID,
				Value: extBytes,
			},
		},
	}

	leafCertBytes, err := x509.CreateCertificate(rand.Reader, leafTemplate, interCert,
		&leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatalf("failed to create leaf cert: %v", err)
	}

	leafCert, err := x509.ParseCertificate(leafCertBytes)
	if err != nil {
		t.Fatalf("failed to parse leaf cert: %v", err)
	}

	// Build chain and verify
	chain := []*x509.Certificate{leafCert, interCert}
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	opts := &VerifyOptions{
		TrustedRoots:     roots,
		ExpectedNonce:    nonce,
		MinSecurityLevel: SecurityLevelSoftware,
	}

	desc, err := VerifyKeyAttestation(chain, opts)
	if err != nil {
		t.Fatalf("VerifyKeyAttestation() unexpected error: %v", err)
	}
	if desc == nil {
		t.Fatal("expected non-nil KeyDescription")
	}
	if desc.AttestationVersion != 3 {
		t.Errorf("AttestationVersion = %d, want 3", desc.AttestationVersion)
	}
}

// TestVerifyCertificateChain_EmptyChain verifies that verifyCertificateChain
// returns ErrChainTooShort when given an empty chain.
func TestVerifyCertificateChain_EmptyChain(t *testing.T) {
	roots := x509.NewCertPool()
	_, err := verifyCertificateChain([]*x509.Certificate{}, roots, time.Time{})
	if !errors.Is(err, ErrChainTooShort) {
		t.Errorf("expected ErrChainTooShort, got: %v", err)
	}
}

// TestVerifyCertificateChain_SelfSignedValidChain verifies successful chain
// verification when the leaf is self-signed and in the trusted roots.
func TestVerifyCertificateChain_SelfSignedValidChain(t *testing.T) {
	caCert, _ := makeTestCA(t)

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	verified, err := verifyCertificateChain([]*x509.Certificate{caCert}, roots, time.Time{})
	if err != nil {
		t.Fatalf("verifyCertificateChain() unexpected error: %v", err)
	}
	if len(verified) != 1 || verified[0][0] != caCert {
		t.Errorf("verifyCertificateChain() verified chains = %v, want the self-signed root", verified)
	}
}

// TestBuildMinimalAttestationExtension_EmptyChallenge verifies that building
// an extension with an empty challenge produces valid output.
func TestBuildMinimalAttestationExtension_EmptyChallenge(t *testing.T) {
	extBytes, err := BuildMinimalAttestationExtension(
		1, SecurityLevelSoftware, 1, SecurityLevelSoftware,
		[]byte{}, nil,
	)
	if err != nil {
		t.Fatalf("BuildMinimalAttestationExtension() error: %v", err)
	}
	if len(extBytes) == 0 {
		t.Error("expected non-empty extension bytes")
	}

	// Verify it parses correctly when embedded in a certificate
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Empty Challenge Test",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    AndroidKeyAttestationOID,
				Value: extBytes,
			},
		},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	desc, err := ParseKeyAttestation(cert)
	if err != nil {
		t.Fatalf("ParseKeyAttestation() error: %v", err)
	}
	if len(desc.AttestationChallenge) != 0 {
		t.Errorf("expected empty challenge, got %d bytes", len(desc.AttestationChallenge))
	}
}

// TestBuildMinimalAttestationExtension_NilChallenge verifies that building
// an extension with a nil challenge works correctly.
func TestBuildMinimalAttestationExtension_NilChallenge(t *testing.T) {
	extBytes, err := BuildMinimalAttestationExtension(
		2, SecurityLevelTrustedEnvironment, 3, SecurityLevelTrustedEnvironment,
		nil, nil,
	)
	if err != nil {
		t.Fatalf("BuildMinimalAttestationExtension() error: %v", err)
	}
	if len(extBytes) == 0 {
		t.Error("expected non-empty extension bytes")
	}
}

// TestParseKeyAttestation_WithRootOfTrust verifies that ParseKeyAttestation
// correctly extracts RootOfTrust from the teeEnforced AuthorizationList.
func TestParseKeyAttestation_WithRootOfTrust(t *testing.T) {
	challenge := []byte("rot-parse-test")
	cert := makeTestAttestationCertWithRootOfTrust(
		t, SecurityLevelTrustedEnvironment, challenge,
		VerifiedBootVerified, true,
	)

	desc, err := ParseKeyAttestation(cert)
	if err != nil {
		t.Fatalf("ParseKeyAttestation() unexpected error: %v", err)
	}

	if desc.TeeEnforced.RootOfTrust == nil {
		t.Fatal("expected non-nil RootOfTrust in TeeEnforced")
	}

	if !desc.TeeEnforced.RootOfTrust.DeviceLocked {
		t.Error("expected DeviceLocked = true")
	}

	if desc.TeeEnforced.RootOfTrust.VerifiedBootState != VerifiedBootVerified {
		t.Errorf("VerifiedBootState = %v, want %v",
			desc.TeeEnforced.RootOfTrust.VerifiedBootState, VerifiedBootVerified)
	}
}

// TestVerifyKeyAttestation_BootStateSelfSignedReturnsError verifies that boot
// state verification fails when the boot state is self-signed.
func TestVerifyKeyAttestation_BootStateSelfSignedReturnsError(t *testing.T) {
	nonce := []byte("boot-selfsigned-test")
	cert := makeTestAttestationCertWithRootOfTrust(
		t, SecurityLevelTrustedEnvironment, nonce,
		VerifiedBootSelfSigned, true,
	)

	opts := &VerifyOptions{
		ExpectedNonce:    nonce,
		MinSecurityLevel: SecurityLevelSoftware,
		VerifyBootState:  true,
	}

	desc, err := VerifyKeyAttestation([]*x509.Certificate{cert}, opts)
	if desc != nil {
		t.Errorf("expected nil KeyDescription, got %+v", desc)
	}
	if !errors.Is(err, ErrUnverifiedBoot) {
		t.Errorf("expected ErrUnverifiedBoot, got: %v", err)
	}
}

// TestVerifyKeyAttestation_BootStateFailedReturnsError verifies that boot
// state verification fails when the boot state is failed.
func TestVerifyKeyAttestation_BootStateFailedReturnsError(t *testing.T) {
	nonce := []byte("boot-failed-test")
	cert := makeTestAttestationCertWithRootOfTrust(
		t, SecurityLevelTrustedEnvironment, nonce,
		VerifiedBootFailed, false,
	)

	opts := &VerifyOptions{
		ExpectedNonce:    nonce,
		MinSecurityLevel: SecurityLevelSoftware,
		VerifyBootState:  true,
	}

	desc, err := VerifyKeyAttestation([]*x509.Certificate{cert}, opts)
	if desc != nil {
		t.Errorf("expected nil KeyDescription, got %+v", desc)
	}
	if !errors.Is(err, ErrUnverifiedBoot) {
		t.Errorf("expected ErrUnverifiedBoot, got: %v", err)
	}
}

// BenchmarkParseKeyAttestation benchmarks the attestation extension parsing.
func BenchmarkParseKeyAttestation(b *testing.B) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("failed to generate key: %v", err)
	}

	extBytes, err := BuildMinimalAttestationExtension(
		3, SecurityLevelTrustedEnvironment, 4, SecurityLevelTrustedEnvironment,
		[]byte("bench-nonce"), nil,
	)
	if err != nil {
		b.Fatalf("failed to build extension: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Benchmark Cert",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    AndroidKeyAttestationOID,
				Value: extBytes,
			},
		},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		b.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		b.Fatalf("failed to parse certificate: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseKeyAttestation(cert)
	}
}

// BenchmarkVerifyKeyAttestation benchmarks the full attestation verification flow.
func BenchmarkVerifyKeyAttestation(b *testing.B) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("failed to generate key: %v", err)
	}

	nonce := []byte("bench-verify-nonce")
	extBytes, err := BuildMinimalAttestationExtension(
		3, SecurityLevelTrustedEnvironment, 4, SecurityLevelTrustedEnvironment,
		nonce, nil,
	)
	if err != nil {
		b.Fatalf("failed to build extension: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Benchmark Verify",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    AndroidKeyAttestationOID,
				Value: extBytes,
			},
		},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		b.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		b.Fatalf("failed to parse certificate: %v", err)
	}

	chain := []*x509.Certificate{cert}
	opts := &VerifyOptions{
		ExpectedNonce:    nonce,
		MinSecurityLevel: SecurityLevelSoftware,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = VerifyKeyAttestation(chain, opts)
	}
}

// wrapAuthorizationListElements wraps DER-encoded AuthorizationList elements
// in the outer SEQUENCE findOrigin, findPurpose and findRootOfTrust each
// expect to walk.
func wrapAuthorizationListElements(t *testing.T, elements []byte) []byte {
	t.Helper()

	outer, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      elements,
	})
	if err != nil {
		t.Fatalf("marshal outer SEQUENCE: %v", err)
	}
	return outer
}

// TestFindOrigin_ValidOrigin verifies that a tag-702 EXPLICIT INTEGER is
// located and decoded regardless of what else sits beside it (go-xkms#132).
func TestFindOrigin_ValidOrigin(t *testing.T) {
	tagged, err := marshalExplicitInt(tagOrigin, OriginImported)
	if err != nil {
		t.Fatalf("marshal tagged origin: %v", err)
	}
	outer := wrapAuthorizationListElements(t, tagged)

	origin, ok := findOrigin(outer)
	if !ok {
		t.Fatal("expected ok=true for a present origin tag")
	}
	if origin != OriginImported {
		t.Errorf("origin = %d, want %d (OriginImported)", origin, OriginImported)
	}
}

// TestFindOrigin_AbsentTagReturnsNotOK verifies that an AuthorizationList
// with no tag-702 element reports ok=false rather than defaulting to 0
// (OriginGenerated's own value) -- the failure mode go-xkms#132 exists to
// prevent.
func TestFindOrigin_AbsentTagReturnsNotOK(t *testing.T) {
	tagged, err := marshalExplicitIntSet(tagPurpose, []int{PurposeSign})
	if err != nil {
		t.Fatalf("marshal tagged purpose: %v", err)
	}
	outer := wrapAuthorizationListElements(t, tagged)

	origin, ok := findOrigin(outer)
	if ok {
		t.Fatalf("expected ok=false when no origin tag is present, got origin=%d", origin)
	}
}

// TestFindOrigin_InvalidData verifies that malformed input returns ok=false
// rather than panicking or fabricating a value.
func TestFindOrigin_InvalidData(t *testing.T) {
	if _, ok := findOrigin([]byte{0xFF, 0xFF}); ok {
		t.Error("expected ok=false for malformed data")
	}
	if _, ok := findOrigin(nil); ok {
		t.Error("expected ok=false for nil data")
	}
}

// TestFindPurpose_ValidPurpose verifies that a tag-1 EXPLICIT SET OF INTEGER
// is located and decoded (go-xkms#132).
func TestFindPurpose_ValidPurpose(t *testing.T) {
	tagged, err := marshalExplicitIntSet(tagPurpose, []int{PurposeSign, PurposeVerify})
	if err != nil {
		t.Fatalf("marshal tagged purpose: %v", err)
	}
	outer := wrapAuthorizationListElements(t, tagged)

	purposes := findPurpose(outer)
	if len(purposes) != 2 {
		t.Fatalf("purposes = %v, want 2 entries", purposes)
	}
	if purposes[0] != PurposeSign || purposes[1] != PurposeVerify {
		t.Errorf("purposes = %v, want [%d %d]", purposes, PurposeSign, PurposeVerify)
	}
}

// TestFindPurpose_AbsentTagReturnsNil verifies that an AuthorizationList with
// no tag-1 element returns nil, distinct from a present but empty set.
func TestFindPurpose_AbsentTagReturnsNil(t *testing.T) {
	tagged, err := marshalExplicitInt(tagOrigin, OriginGenerated)
	if err != nil {
		t.Fatalf("marshal tagged origin: %v", err)
	}
	outer := wrapAuthorizationListElements(t, tagged)

	if purposes := findPurpose(outer); purposes != nil {
		t.Errorf("purposes = %v, want nil when no purpose tag is present", purposes)
	}
}

// TestFindPurpose_InvalidData verifies that malformed input returns nil
// rather than panicking or fabricating a value.
func TestFindPurpose_InvalidData(t *testing.T) {
	if purposes := findPurpose([]byte{0xFF, 0xFF}); purposes != nil {
		t.Errorf("purposes = %v, want nil for malformed data", purposes)
	}
	if purposes := findPurpose(nil); purposes != nil {
		t.Errorf("purposes = %v, want nil for nil data", purposes)
	}
}

// TestParseAuthorizationList_OriginDefaultsToUnknownWhenAbsent pins the
// default parseAuthorizationList must produce when a list makes no origin
// claim: OriginUnknown, never the bare zero value, because zero is also
// OriginGenerated's value (go-xkms#132).
func TestParseAuthorizationList_OriginDefaultsToUnknownWhenAbsent(t *testing.T) {
	result := parseAuthorizationList(asn1.RawValue{})
	if result.Origin != OriginUnknown {
		t.Errorf("Origin = %d, want OriginUnknown (%d) for an empty AuthorizationList",
			result.Origin, OriginUnknown)
	}

	tagged, err := marshalExplicitIntSet(tagPurpose, []int{PurposeSign})
	if err != nil {
		t.Fatalf("marshal tagged purpose: %v", err)
	}
	rawVal := asn1.RawValue{FullBytes: wrapAuthorizationListElements(t, tagged)}

	result = parseAuthorizationList(rawVal)
	if result.Origin != OriginUnknown {
		t.Errorf("Origin = %d, want OriginUnknown (%d) when only purpose is claimed",
			result.Origin, OriginUnknown)
	}
}

// TestParseAuthorizationList_WithOriginAndPurpose verifies that
// parseAuthorizationList populates both fields when present, alongside a
// RootOfTrust, mirroring how a real TEE-enforced list carries all three.
func TestParseAuthorizationList_WithOriginAndPurpose(t *testing.T) {
	originTagged, err := marshalExplicitInt(tagOrigin, OriginGenerated)
	if err != nil {
		t.Fatalf("marshal tagged origin: %v", err)
	}
	purposeTagged, err := marshalExplicitIntSet(tagPurpose, []int{PurposeSign})
	if err != nil {
		t.Fatalf("marshal tagged purpose: %v", err)
	}

	var elements bytes.Buffer
	elements.Write(purposeTagged)
	elements.Write(originTagged)
	rawVal := asn1.RawValue{FullBytes: wrapAuthorizationListElements(t, elements.Bytes())}

	result := parseAuthorizationList(rawVal)
	if result.Origin != OriginGenerated {
		t.Errorf("Origin = %d, want OriginGenerated (%d)", result.Origin, OriginGenerated)
	}
	if len(result.Purpose) != 1 || result.Purpose[0] != PurposeSign {
		t.Errorf("Purpose = %v, want [%d]", result.Purpose, PurposeSign)
	}
}

// TestBuildAttestationExtensionWithOptions_RoundTrip verifies that Origin,
// Purpose and RootOfTrust all survive a build-then-parse round trip inside
// teeEnforced, and that softwareEnforced stays empty (go-xkms#132).
func TestBuildAttestationExtensionWithOptions_RoundTrip(t *testing.T) {
	nonce := []byte("origin-purpose-round-trip")
	rot := &RootOfTrust{
		VerifiedBootKey:   []byte("boot-key"),
		DeviceLocked:      true,
		VerifiedBootState: VerifiedBootVerified,
		VerifiedBootHash:  []byte("boot-hash"),
	}

	extBytes, err := BuildAttestationExtensionWithOptions(
		3, SecurityLevelStrongBox, 4, SecurityLevelStrongBox, nonce, []byte("unique-id"),
		&AttestationExtensionOptions{
			RootOfTrust: rot,
			HasOrigin:   true,
			Origin:      OriginGenerated,
			Purpose:     []int{PurposeSign},
		},
	)
	if err != nil {
		t.Fatalf("build extension: %v", err)
	}

	cert := makeCertWithExtension(t, extBytes)
	desc, err := ParseKeyAttestation(cert)
	if err != nil {
		t.Fatalf("parse extension: %v", err)
	}

	if desc.TeeEnforced.Origin != OriginGenerated {
		t.Errorf("teeEnforced origin = %d, want OriginGenerated (%d)", desc.TeeEnforced.Origin, OriginGenerated)
	}
	if len(desc.TeeEnforced.Purpose) != 1 || desc.TeeEnforced.Purpose[0] != PurposeSign {
		t.Errorf("teeEnforced purpose = %v, want [%d]", desc.TeeEnforced.Purpose, PurposeSign)
	}
	if desc.TeeEnforced.RootOfTrust == nil || !desc.TeeEnforced.RootOfTrust.DeviceLocked {
		t.Error("teeEnforced root of trust missing or not locked")
	}
	if desc.SoftwareEnforced.Origin != OriginUnknown || len(desc.SoftwareEnforced.Purpose) != 0 {
		t.Errorf("softwareEnforced = %+v, want no claims", desc.SoftwareEnforced)
	}
}

// TestBuildAttestationExtensionWithOptions_NilOptions verifies that a nil
// opts reproduces BuildMinimalAttestationExtension's shape: teeEnforced
// makes no claim about origin, purpose, or boot state.
func TestBuildAttestationExtensionWithOptions_NilOptions(t *testing.T) {
	extBytes, err := BuildAttestationExtensionWithOptions(
		3, SecurityLevelSoftware, 4, SecurityLevelSoftware,
		[]byte("nil-options"), []byte("unique-id"), nil,
	)
	if err != nil {
		t.Fatalf("build extension: %v", err)
	}

	cert := makeCertWithExtension(t, extBytes)
	desc, err := ParseKeyAttestation(cert)
	if err != nil {
		t.Fatalf("parse extension: %v", err)
	}

	if desc.TeeEnforced.Origin != OriginUnknown {
		t.Errorf("teeEnforced origin = %d, want OriginUnknown (%d)", desc.TeeEnforced.Origin, OriginUnknown)
	}
	if len(desc.TeeEnforced.Purpose) != 0 {
		t.Errorf("teeEnforced purpose = %v, want none", desc.TeeEnforced.Purpose)
	}
	if desc.TeeEnforced.RootOfTrust != nil {
		t.Error("teeEnforced root of trust present, want none")
	}
}

// TestBuildAttestationExtensionWithOptions_ApplicationIDRoundTrip verifies
// that an attestationApplicationId is encoded where the Keystore daemon puts
// it -- tag 709 in softwareEnforced -- and parses back byte for byte, so a
// consumer can build fixtures for its application allow-list (go-xkms#1305).
func TestBuildAttestationExtensionWithOptions_ApplicationIDRoundTrip(t *testing.T) {
	digest := bytes.Repeat([]byte{0xab}, 32)
	appID := &AttestationApplicationID{
		Packages:         []AttestationPackageInfo{{Name: "com.example.app", Version: 42}},
		SignatureDigests: [][]byte{digest},
	}

	extBytes, err := BuildAttestationExtensionWithOptions(
		3, SecurityLevelTrustedEnvironment, 4, SecurityLevelTrustedEnvironment,
		[]byte("app-id-round-trip"), []byte("unique-id"),
		&AttestationExtensionOptions{ApplicationID: appID},
	)
	if err != nil {
		t.Fatalf("build extension: %v", err)
	}

	desc, err := ParseKeyAttestation(makeCertWithExtension(t, extBytes))
	if err != nil {
		t.Fatalf("parse extension: %v", err)
	}

	got := desc.SoftwareEnforced.AttestationApplicationID
	if got == nil {
		t.Fatal("softwareEnforced attestationApplicationId absent after round trip")
	}
	if len(got.Packages) != 1 || got.Packages[0].Name != "com.example.app" || got.Packages[0].Version != 42 {
		t.Errorf("packages = %+v, want [{com.example.app 42}]", got.Packages)
	}
	if len(got.SignatureDigests) != 1 || !bytes.Equal(got.SignatureDigests[0], digest) {
		t.Errorf("signature digests = %x, want [%x]", got.SignatureDigests, digest)
	}
	if desc.TeeEnforced.AttestationApplicationID != nil {
		t.Error("teeEnforced carries an attestationApplicationId; the Keystore daemon never puts it there")
	}
}

// TestBuildAttestationExtensionWithOptions_NoApplicationID verifies that
// omitting ApplicationID encodes no tag 709 at all, so a fixture can present
// evidence that names no application.
func TestBuildAttestationExtensionWithOptions_NoApplicationID(t *testing.T) {
	extBytes, err := BuildAttestationExtensionWithOptions(
		3, SecurityLevelTrustedEnvironment, 4, SecurityLevelTrustedEnvironment,
		[]byte("no-app-id"), []byte("unique-id"),
		&AttestationExtensionOptions{HasOrigin: true, Origin: OriginGenerated},
	)
	if err != nil {
		t.Fatalf("build extension: %v", err)
	}

	desc, err := ParseKeyAttestation(makeCertWithExtension(t, extBytes))
	if err != nil {
		t.Fatalf("parse extension: %v", err)
	}
	if desc.SoftwareEnforced.AttestationApplicationID != nil {
		t.Errorf("softwareEnforced attestationApplicationId = %+v, want none",
			desc.SoftwareEnforced.AttestationApplicationID)
	}
}

// TestParseKeyAttestation_UserAuthenticationFields round-trips the
// user-authentication tags 503-506 through the builder and the parser, in
// the list each was encoded into and no other.
func TestParseKeyAttestation_UserAuthenticationFields(t *testing.T) {
	extBytes, err := BuildAttestationExtensionWithOptions(
		3, SecurityLevelTrustedEnvironment, 4, SecurityLevelTrustedEnvironment,
		[]byte("user-auth"), []byte("unique-id"),
		&AttestationExtensionOptions{
			NoAuthRequired:         true,
			SoftwareNoAuthRequired: true,
			UserAuthType:           UserAuthTypePassword | UserAuthTypeFingerprint,
			HasAuthTimeout:         true,
			AuthTimeout:            30,
			AllowWhileOnBody:       true,
		},
	)
	if err != nil {
		t.Fatalf("build extension: %v", err)
	}

	desc, err := ParseKeyAttestation(makeCertWithExtension(t, extBytes))
	if err != nil {
		t.Fatalf("parse extension: %v", err)
	}

	tee := desc.TeeEnforced
	if !tee.NoAuthRequired {
		t.Error("teeEnforced noAuthRequired = false, want true")
	}
	if tee.UserAuthType != UserAuthTypePassword|UserAuthTypeFingerprint {
		t.Errorf("teeEnforced userAuthType = %d, want %d", tee.UserAuthType, UserAuthTypePassword|UserAuthTypeFingerprint)
	}
	if !tee.HasAuthTimeout || tee.AuthTimeout != 30 {
		t.Errorf("teeEnforced authTimeout = %d (present %v), want 30 (present)", tee.AuthTimeout, tee.HasAuthTimeout)
	}
	if !tee.AllowWhileOnBody {
		t.Error("teeEnforced allowWhileOnBody = false, want true")
	}

	sw := desc.SoftwareEnforced
	if !sw.NoAuthRequired {
		t.Error("softwareEnforced noAuthRequired = false, want true")
	}
	if sw.UserAuthType != UserAuthTypeNone || sw.HasAuthTimeout || sw.AllowWhileOnBody {
		t.Errorf("softwareEnforced carries claims it was not given: %+v", sw)
	}
}

// TestParseKeyAttestation_UserAuthenticationAbsent checks that a list without
// tags 503-506 reads as making none of their claims.
func TestParseKeyAttestation_UserAuthenticationAbsent(t *testing.T) {
	extBytes, err := BuildAttestationExtensionWithOptions(
		3, SecurityLevelTrustedEnvironment, 4, SecurityLevelTrustedEnvironment,
		[]byte("no-user-auth"), []byte("unique-id"),
		&AttestationExtensionOptions{HasOrigin: true, Origin: OriginGenerated},
	)
	if err != nil {
		t.Fatalf("build extension: %v", err)
	}

	desc, err := ParseKeyAttestation(makeCertWithExtension(t, extBytes))
	if err != nil {
		t.Fatalf("parse extension: %v", err)
	}
	tee := desc.TeeEnforced
	if tee.NoAuthRequired || tee.UserAuthType != UserAuthTypeNone || tee.HasAuthTimeout || tee.AllowWhileOnBody {
		t.Errorf("teeEnforced reads user-authentication claims it does not carry: %+v", tee)
	}
}

// TestParseKeyAttestation_MalformedAuthTimeoutStillPresent checks that an
// authTimeout whose content is not an INTEGER still reads as a timeout claim:
// treating it as absent would read a timed key as one that needs a fresh
// authentication on every use.
func TestParseKeyAttestation_MalformedAuthTimeoutStillPresent(t *testing.T) {
	body, err := asn1.Marshal([]byte("not-an-integer"))
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	tagged, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: tagAuthTimeout, IsCompound: true, Bytes: body,
	})
	if err != nil {
		t.Fatalf("marshal tag: %v", err)
	}

	extBytes, err := buildAttestationExtension(3, SecurityLevelTrustedEnvironment, 4,
		SecurityLevelTrustedEnvironment, []byte("bad-timeout"), []byte("unique-id"), nil, tagged)
	if err != nil {
		t.Fatalf("build extension: %v", err)
	}

	desc, err := ParseKeyAttestation(makeCertWithExtension(t, extBytes))
	if err != nil {
		t.Fatalf("parse extension: %v", err)
	}
	if !desc.TeeEnforced.HasAuthTimeout {
		t.Error("teeEnforced authTimeout read as absent, want present")
	}
}

// makeCertWithExtension wraps extBytes in a self-signed certificate carrying
// the Android key-attestation extension, for tests that only need to parse
// the extension back out.
func makeCertWithExtension(t *testing.T, extBytes []byte) *x509.Certificate {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Origin/Purpose Fixture"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtraExtensions: []pkix.Extension{
			{Id: AndroidKeyAttestationOID, Value: extBytes},
		},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// marshalAppIDElement DER-encodes an EXPLICIT context-specific tag-709
// element whose content is an OCTET STRING wrapping the DER of appID,
// matching how findAttestationApplicationID reads it back: two decodes,
// the outer tagged element then the OCTET STRING's own contents.
func marshalAppIDElement(t *testing.T, appID attestationApplicationIDASN1) []byte {
	t.Helper()

	wrapped, err := asn1.Marshal(appID)
	if err != nil {
		t.Fatalf("marshal attestationApplicationIDASN1: %v", err)
	}
	octetDER, err := asn1.Marshal(wrapped)
	if err != nil {
		t.Fatalf("marshal OCTET STRING: %v", err)
	}
	elem, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        tagAttestationApplicationID,
		IsCompound: true,
		Bytes:      octetDER,
	})
	if err != nil {
		t.Fatalf("marshal tag-709 element: %v", err)
	}
	return elem
}

// TestFindAttestationApplicationID_ValidAppID verifies that a tag-709
// element is located and both the package list and signature digests are
// decoded from the doubly-wrapped OCTET STRING/SEQUENCE it carries.
func TestFindAttestationApplicationID_ValidAppID(t *testing.T) {
	elem := marshalAppIDElement(t, attestationApplicationIDASN1{
		PackageInfos: []attestationPackageInfoASN1{
			{PackageName: []byte("com.example.app"), Version: 5},
		},
		SignatureDigests: [][]byte{{0x01, 0x02, 0x03}},
	})
	outer := wrapAuthorizationListElements(t, elem)

	got := findAttestationApplicationID(outer)
	if got == nil {
		t.Fatal("expected a decoded AttestationApplicationID, got nil")
	}
	if len(got.Packages) != 1 || got.Packages[0].Name != "com.example.app" || got.Packages[0].Version != 5 {
		t.Errorf("Packages = %+v, want [{com.example.app 5}]", got.Packages)
	}
	if len(got.SignatureDigests) != 1 || !bytes.Equal(got.SignatureDigests[0], []byte{0x01, 0x02, 0x03}) {
		t.Errorf("SignatureDigests = %v, want [[1 2 3]]", got.SignatureDigests)
	}
}

// TestFindAttestationApplicationID_AbsentTagReturnsNil verifies that an
// AuthorizationList with no tag-709 element reports nil rather than a zero
// value AttestationApplicationID.
func TestFindAttestationApplicationID_AbsentTagReturnsNil(t *testing.T) {
	tagged, err := marshalExplicitInt(tagOrigin, OriginGenerated)
	if err != nil {
		t.Fatalf("marshal tagged origin: %v", err)
	}
	outer := wrapAuthorizationListElements(t, tagged)

	if got := findAttestationApplicationID(outer); got != nil {
		t.Errorf("got %+v, want nil when no tag-709 element is present", got)
	}
}

// TestFindAttestationApplicationID_InvalidOuterData verifies that malformed
// or absent input returns nil rather than panicking.
func TestFindAttestationApplicationID_InvalidOuterData(t *testing.T) {
	if got := findAttestationApplicationID([]byte{0xFF, 0xFF}); got != nil {
		t.Errorf("got %+v, want nil for malformed data", got)
	}
	if got := findAttestationApplicationID(nil); got != nil {
		t.Errorf("got %+v, want nil for nil data", got)
	}
}

// TestFindAttestationApplicationID_TrailingDataOnOuterSequence verifies that
// trailing bytes after the outer SEQUENCE cause findAttestationApplicationID
// to return nil rather than ignoring the excess data.
func TestFindAttestationApplicationID_TrailingDataOnOuterSequence(t *testing.T) {
	elem := marshalAppIDElement(t, attestationApplicationIDASN1{})
	outer := wrapAuthorizationListElements(t, elem)
	outer = append(outer, 0x00, 0x01)

	if got := findAttestationApplicationID(outer); got != nil {
		t.Errorf("got %+v, want nil for trailing data", got)
	}
}

// TestFindAttestationApplicationID_MalformedElementBreaksLoop verifies that
// an element inside the outer SEQUENCE that fails to decode stops the walk
// and returns nil, rather than panicking on the unparsed remainder.
func TestFindAttestationApplicationID_MalformedElementBreaksLoop(t *testing.T) {
	outerSeq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      []byte{0xFF, 0xFF},
	})
	if err != nil {
		t.Fatalf("marshal outer SEQUENCE: %v", err)
	}

	if got := findAttestationApplicationID(outerSeq); got != nil {
		t.Errorf("got %+v, want nil when an element fails to decode", got)
	}
}

// TestFindAttestationApplicationID_WrappedNotOctetString verifies that a
// tag-709 element whose content is not an OCTET STRING -- an INTEGER here --
// returns nil at the first decode rather than misreading the tag mismatch.
func TestFindAttestationApplicationID_WrappedNotOctetString(t *testing.T) {
	intDER, err := asn1.Marshal(5)
	if err != nil {
		t.Fatalf("marshal INTEGER: %v", err)
	}
	elem, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        tagAttestationApplicationID,
		IsCompound: true,
		Bytes:      intDER,
	})
	if err != nil {
		t.Fatalf("marshal tag-709 element: %v", err)
	}
	outer := wrapAuthorizationListElements(t, elem)

	if got := findAttestationApplicationID(outer); got != nil {
		t.Errorf("got %+v, want nil when the tag-709 content is not an OCTET STRING", got)
	}
}

// TestFindAttestationApplicationID_ParsedInvalidContent verifies that an
// OCTET STRING whose content does not decode as attestationApplicationIDASN1
// returns nil at the second decode.
func TestFindAttestationApplicationID_ParsedInvalidContent(t *testing.T) {
	octetDER, err := asn1.Marshal([]byte{0x01, 0x02, 0x03})
	if err != nil {
		t.Fatalf("marshal OCTET STRING: %v", err)
	}
	elem, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        tagAttestationApplicationID,
		IsCompound: true,
		Bytes:      octetDER,
	})
	if err != nil {
		t.Fatalf("marshal tag-709 element: %v", err)
	}
	outer := wrapAuthorizationListElements(t, elem)

	if got := findAttestationApplicationID(outer); got != nil {
		t.Errorf("got %+v, want nil when the OCTET STRING content is not a valid "+
			"attestationApplicationIDASN1 SEQUENCE", got)
	}
}
