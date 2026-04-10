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

	// Wrap RootOfTrust in context-specific constructed tag (simulating tag 704)
	rotTagged := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0, // tag number within context-specific class
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
		Tag:        0,
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
		Tag:        0,
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
		Tag:        0,
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

	// Third element: valid RootOfTrust
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
		Tag:        2,
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
		Tag:        0,
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
	err := verifyCertificateChain([]*x509.Certificate{}, roots)
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

	err := verifyCertificateChain([]*x509.Certificate{caCert}, roots)
	if err != nil {
		t.Errorf("verifyCertificateChain() unexpected error: %v", err)
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
