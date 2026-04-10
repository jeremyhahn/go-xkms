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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	attestandroid "github.com/jeremyhahn/go-xkms/pkg/attestation/android"
	"github.com/jeremyhahn/go-xkms/pkg/backend/phone"
)

func TestNewAndroidVerifier_Success(t *testing.T) {
	cfg := &phone.AttestationConfig{
		MinSecurityLevel: "tee",
		VerifyBootState:  true,
	}
	pool := x509.NewCertPool()

	verifier, err := NewAndroidVerifier(pool, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verifier == nil {
		t.Fatal("expected non-nil verifier")
	}
	if verifier.Platform() != PlatformAndroid {
		t.Errorf("expected platform %q, got %q", PlatformAndroid, verifier.Platform())
	}
}

func TestNewAndroidVerifier_NilConfig(t *testing.T) {
	verifier, err := NewAndroidVerifier(nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verifier == nil {
		t.Fatal("expected non-nil verifier")
	}
}

func TestNewAndroidVerifier_EmptySecurityLevel(t *testing.T) {
	cfg := &phone.AttestationConfig{
		MinSecurityLevel: "",
	}

	verifier, err := NewAndroidVerifier(nil, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	av := verifier.(*AndroidVerifier)
	if av.minSecLevel != attestandroid.SecurityLevelSoftware {
		t.Errorf("expected SecurityLevelSoftware for empty string, got %d", av.minSecLevel)
	}
}

func TestAndroidVerifier_Platform(t *testing.T) {
	v := &AndroidVerifier{}
	if v.Platform() != PlatformAndroid {
		t.Errorf("expected %q, got %q", PlatformAndroid, v.Platform())
	}
}

func TestAndroidVerifier_VerifyAttestation_EmptyChain(t *testing.T) {
	v := &AndroidVerifier{}
	_, err := v.VerifyAttestation(nil, nil)
	if err != phone.ErrChainVerificationFailed {
		t.Errorf("expected ErrChainVerificationFailed, got %v", err)
	}

	_, err = v.VerifyAttestation([][]byte{}, nil)
	if err != phone.ErrChainVerificationFailed {
		t.Errorf("expected ErrChainVerificationFailed for empty slice, got %v", err)
	}
}

func TestAndroidVerifier_VerifyAttestation_InvalidCertDER(t *testing.T) {
	v := &AndroidVerifier{}
	_, err := v.VerifyAttestation([][]byte{[]byte("not-a-cert")}, nil)
	if err == nil {
		t.Fatal("expected error for invalid DER")
	}
}

func TestAndroidVerifier_VerifyAttestation_ValidChainWithAttestation(t *testing.T) {
	nonce := []byte("test-nonce-12345")

	// Create a self-signed CA.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA cert: %v", err)
	}

	// Create the attestation extension.
	extBytes, err := attestandroid.BuildMinimalAttestationExtension(
		3, // attestation version
		attestandroid.SecurityLevelStrongBox,
		4, // keymaster version
		attestandroid.SecurityLevelStrongBox,
		nonce,
		nil, // uniqueID
	)
	if err != nil {
		t.Fatalf("failed to build attestation extension: %v", err)
	}

	// Create a leaf certificate with the attestation extension.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Attestation Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17},
				Value: extBytes,
			},
		},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create leaf cert: %v", err)
	}

	// Set up trust pool.
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	v := &AndroidVerifier{
		trustPool:       pool,
		minSecLevel:     attestandroid.SecurityLevelSoftware,
		verifyBootState: false,
	}

	result, err := v.VerifyAttestation([][]byte{leafDER, caDER}, nonce)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.SecurityBackend != "android-keystore-strongbox" {
		t.Errorf("expected android-keystore-strongbox, got %s", result.SecurityBackend)
	}
	if result.PlatformData == nil {
		t.Error("expected non-nil PlatformData")
	}

	// Type-assert PlatformData.
	desc, ok := result.PlatformData.(*attestandroid.KeyDescription)
	if !ok {
		t.Fatalf("expected *attestandroid.KeyDescription, got %T", result.PlatformData)
	}
	if desc.AttestationSecurityLevel != attestandroid.SecurityLevelStrongBox {
		t.Errorf("expected SecurityLevelStrongBox, got %v", desc.AttestationSecurityLevel)
	}
}

// --- mapMinSecurityLevel ---

func TestMapMinSecurityLevel_AllLevels(t *testing.T) {
	tests := []struct {
		input    string
		expected attestandroid.SecurityLevel
	}{
		{"software", attestandroid.SecurityLevelSoftware},
		{"tee", attestandroid.SecurityLevelTrustedEnvironment},
		{"strongbox", attestandroid.SecurityLevelStrongBox},
		{"", attestandroid.SecurityLevelSoftware},
		{"unknown", attestandroid.SecurityLevelSoftware},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := mapMinSecurityLevel(tc.input)
			if result != tc.expected {
				t.Errorf("mapMinSecurityLevel(%q) = %d, want %d", tc.input, result, tc.expected)
			}
		})
	}
}

// --- mapSecurityLevel ---

func TestMapSecurityLevel_AllLevels(t *testing.T) {
	tests := []struct {
		input    attestandroid.SecurityLevel
		expected string
	}{
		{attestandroid.SecurityLevelSoftware, "android-keystore-software"},
		{attestandroid.SecurityLevelTrustedEnvironment, "android-keystore-tee"},
		{attestandroid.SecurityLevelStrongBox, "android-keystore-strongbox"},
		{attestandroid.SecurityLevel(99), "android-keystore-unknown(99)"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			result := mapSecurityLevel(tc.input)
			if result != tc.expected {
				t.Errorf("mapSecurityLevel(%d) = %q, want %q", tc.input, result, tc.expected)
			}
		})
	}
}

// --- securityLevelMapping completeness ---

func TestSecurityLevelMapping_AllEntries(t *testing.T) {
	expected := map[string]attestandroid.SecurityLevel{
		"software":  attestandroid.SecurityLevelSoftware,
		"tee":       attestandroid.SecurityLevelTrustedEnvironment,
		"strongbox": attestandroid.SecurityLevelStrongBox,
	}

	if len(securityLevelMapping) != len(expected) {
		t.Errorf("expected %d entries, got %d", len(expected), len(securityLevelMapping))
	}

	for key, expectedLevel := range expected {
		level, ok := securityLevelMapping[key]
		if !ok {
			t.Errorf("missing key %q", key)
			continue
		}
		if level != expectedLevel {
			t.Errorf("securityLevelMapping[%q] = %d, want %d", key, level, expectedLevel)
		}
	}
}

// --- securityLevelToBackend completeness ---

func TestSecurityLevelToBackend_AllEntries(t *testing.T) {
	expected := map[attestandroid.SecurityLevel]string{
		attestandroid.SecurityLevelSoftware:           "android-keystore-software",
		attestandroid.SecurityLevelTrustedEnvironment: "android-keystore-tee",
		attestandroid.SecurityLevelStrongBox:          "android-keystore-strongbox",
	}

	if len(securityLevelToBackend) != len(expected) {
		t.Errorf("expected %d entries, got %d", len(expected), len(securityLevelToBackend))
	}

	for level, expectedBackend := range expected {
		backend, ok := securityLevelToBackend[level]
		if !ok {
			t.Errorf("missing level %d", level)
			continue
		}
		if backend != expectedBackend {
			t.Errorf("securityLevelToBackend[%d] = %q, want %q", level, backend, expectedBackend)
		}
	}
}

// --- init registration ---

func TestInitRegistration(t *testing.T) {
	// The init() function in verifier.go should have registered "android".
	// We verify by creating a verifier through the registry.
	verifier, err := phone.NewPlatformVerifier(PlatformAndroid, nil, &phone.AttestationConfig{})
	if err != nil {
		t.Fatalf("expected android platform to be registered via init(), got error: %v", err)
	}
	if verifier.Platform() != PlatformAndroid {
		t.Errorf("expected platform %q, got %q", PlatformAndroid, verifier.Platform())
	}
}
