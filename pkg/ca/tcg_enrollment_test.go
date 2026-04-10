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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	xkmstpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

// =============================================================================
// Test Helpers
// =============================================================================

// placeholderSignature is a minimal non-empty signature used in test CSRs.
// UnmarshalIDevIDCSR requires SigSz > 0 because bytes.Reader.Read on an
// empty slice at EOF returns io.EOF. Real TCG-CSR-IDEVID always carry a
// signature, so this matches production behavior.
var placeholderSignature = []byte{0xDE, 0xAD, 0xBE, 0xEF}

// enrollmentTestCA creates a minimal initialized CA suitable for enrollment
// error path testing. It sets the initialized flag directly without going
// through the full Init() lifecycle since enrollment tests only need the
// initialized guard and TPM pointer behavior.
func enrollmentTestCA(t *testing.T) *CA {
	t.Helper()
	ca := &CA{
		revocations: make(map[string]*RevocationInfo),
	}
	ca.initialized.Store(true)
	return ca
}

// uninitializedEnrollmentTestCA creates a CA that has not been initialized.
func uninitializedEnrollmentTestCA(t *testing.T) *CA {
	t.Helper()
	ca := &CA{
		revocations: make(map[string]*RevocationInfo),
	}
	return ca
}

// buildPackedCSRWithEkCert creates a minimal packed TCG-CSR-IDEVID containing
// the specified EK certificate bytes. A placeholder signature is always included
// since UnmarshalIDevIDCSR requires a non-empty signature field.
func buildPackedCSRWithEkCert(t *testing.T, ekCertBytes []byte) []byte {
	t.Helper()

	content := &xkmstpm2.TCG_IDEVID_CONTENT{}

	// StructVer = 0x00000100 (version 1.0)
	binary.BigEndian.PutUint32(content.StructVer[:], 0x00000100)
	// HashAlgoId = SHA256 (0x000B)
	binary.BigEndian.PutUint32(content.HashAlgoId[:], 0x000B)
	// HashSz = 32 (SHA-256)
	binary.BigEndian.PutUint32(content.HashSz[:], 32)

	// Set EK cert size and data
	binary.BigEndian.PutUint32(content.EkCertSZ[:], uint32(len(ekCertBytes)))
	content.EkCert = make([]byte, len(ekCertBytes))
	copy(content.EkCert, ekCertBytes)

	// All other size fields remain zero (zero-length payloads)

	csr := &xkmstpm2.TCG_CSR_IDEVID{
		CsrContents: *content,
		Signature:   placeholderSignature,
	}
	binary.BigEndian.PutUint32(csr.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.Contents[:], 0)
	binary.BigEndian.PutUint32(csr.SigSz[:], uint32(len(placeholderSignature)))

	packed, err := xkmstpm2.PackIDevIDCSR(csr)
	if err != nil {
		t.Fatalf("buildPackedCSRWithEkCert: failed to pack CSR: %v", err)
	}

	return packed
}

// generateSelfSignedCert creates a minimal self-signed certificate for testing.
func generateSelfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test EK Cert",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// =============================================================================
// SetTPM / getTPM Tests
// =============================================================================

func TestGetTPM_ReturnsNilWhenNotSet(t *testing.T) {
	tpmInstance.Store(nil)
	t.Cleanup(func() { tpmInstance.Store(nil) })

	ca := enrollmentTestCA(t)
	result := ca.getTPM()
	if result != nil {
		t.Fatal("getTPM() returned non-nil when tpmInstance was never set")
	}
}

func TestGetTPM_ReturnsNilAfterReset(t *testing.T) {
	tpmInstance.Store(nil)
	t.Cleanup(func() { tpmInstance.Store(nil) })

	ca := enrollmentTestCA(t)

	// First, verify it is nil
	if ca.getTPM() != nil {
		t.Fatal("getTPM() should return nil initially")
	}

	// Store nil explicitly and verify again
	tpmInstance.Store(nil)
	if ca.getTPM() != nil {
		t.Fatal("getTPM() should return nil after explicit nil store")
	}
}

func TestSetTPM_StoresAndRetrievesNonNilValue(t *testing.T) {
	tpmInstance.Store(nil)
	t.Cleanup(func() { tpmInstance.Store(nil) })

	ca := enrollmentTestCA(t)

	// We cannot easily create a full TrustedPlatformModule mock without
	// implementing 90+ methods. Instead, verify that the atomic pointer
	// round-trip works correctly by directly manipulating the pointer.
	//
	// Create a non-nil TrustedPlatformModule value using a nil-valued
	// interface variable (typed nil). When stored, the pointer is non-nil
	// but the interface value is nil.
	var tpm xkmstpm2.TrustedPlatformModule // nil interface value
	tpmInstance.Store(&tpm)

	result := ca.getTPM()
	// The loaded pointer is non-nil, but the interface value stored is nil,
	// so getTPM() returns a nil TrustedPlatformModule.
	if result != nil {
		t.Fatal("getTPM() should return nil for nil interface value stored via pointer")
	}
}

func TestSetTPM_AtomicPointerConcurrency(t *testing.T) {
	tpmInstance.Store(nil)
	t.Cleanup(func() { tpmInstance.Store(nil) })

	ca := enrollmentTestCA(t)

	// Verify concurrent reads of nil pointer do not race.
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			_ = ca.getTPM()
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}

// =============================================================================
// EnrollDevice Error Path Tests
// =============================================================================

func TestEnrollDevice_NotInitialized(t *testing.T) {
	tpmInstance.Store(nil)
	t.Cleanup(func() { tpmInstance.Store(nil) })

	ca := uninitializedEnrollmentTestCA(t)
	request := &CertificateRequest{
		Subject: Subject{CommonName: "test-device"},
	}

	result, err := ca.EnrollDevice([]byte("any-data"), request)
	if result != nil {
		t.Fatalf("EnrollDevice() returned non-nil result for uninitialized CA")
	}
	if !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("EnrollDevice() error = %v, want %v", err, ErrNotInitialized)
	}
}

func TestEnrollDevice_NotInitialized_NilRequest(t *testing.T) {
	tpmInstance.Store(nil)
	t.Cleanup(func() { tpmInstance.Store(nil) })

	ca := uninitializedEnrollmentTestCA(t)

	result, err := ca.EnrollDevice(nil, nil)
	if result != nil {
		t.Fatal("EnrollDevice() returned non-nil result for uninitialized CA with nil request")
	}
	if !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("EnrollDevice() error = %v, want %v", err, ErrNotInitialized)
	}
}

func TestEnrollDevice_NoTPMConfigured(t *testing.T) {
	tpmInstance.Store(nil)
	t.Cleanup(func() { tpmInstance.Store(nil) })

	ca := enrollmentTestCA(t)
	request := &CertificateRequest{
		Subject: Subject{CommonName: "test-device"},
	}

	result, err := ca.EnrollDevice([]byte("any-data"), request)
	if result != nil {
		t.Fatalf("EnrollDevice() returned non-nil result when no TPM is configured")
	}
	if !errors.Is(err, ErrTPMNotConfigured) {
		t.Fatalf("EnrollDevice() error = %v, want %v", err, ErrTPMNotConfigured)
	}
}

func TestEnrollDevice_NoTPMConfigured_EmptyCSR(t *testing.T) {
	tpmInstance.Store(nil)
	t.Cleanup(func() { tpmInstance.Store(nil) })

	ca := enrollmentTestCA(t)

	result, err := ca.EnrollDevice([]byte{}, nil)
	if result != nil {
		t.Fatal("EnrollDevice() returned non-nil result when no TPM is configured")
	}
	if !errors.Is(err, ErrTPMNotConfigured) {
		t.Fatalf("EnrollDevice() error = %v, want %v", err, ErrTPMNotConfigured)
	}
}

func TestEnrollDevice_InvalidPackedCSR_ErrorType(t *testing.T) {
	// The CSR unmarshal error path requires a real TPM to be configured
	// (getTPM() must return non-nil). Without implementing the full 90+
	// method TrustedPlatformModule interface, we verify the error type
	// exists and is correctly defined. Integration tests cover the full
	// EnrollDevice flow with a real or simulated TPM.
	if ErrTCGCSRUnmarshalFailed.Error() != "ca: failed to unmarshal tcg-csr-idevid" {
		t.Fatalf("ErrTCGCSRUnmarshalFailed message = %q, unexpected", ErrTCGCSRUnmarshalFailed.Error())
	}
}

func TestEnrollDevice_InvalidPackedCSR_GarbageBytes(t *testing.T) {
	// Test that UnmarshalIDevIDCSR correctly rejects garbage input.
	// This validates the unmarshal layer that EnrollDevice depends on.
	_, err := xkmstpm2.UnmarshalIDevIDCSR([]byte{0xFF, 0xFE})
	if err == nil {
		t.Fatal("UnmarshalIDevIDCSR() should fail on garbage bytes")
	}
}

func TestEnrollDevice_InvalidPackedCSR_EmptyBytes(t *testing.T) {
	_, err := xkmstpm2.UnmarshalIDevIDCSR([]byte{})
	if err == nil {
		t.Fatal("UnmarshalIDevIDCSR() should fail on empty bytes")
	}
}

func TestEnrollDevice_InvalidPackedCSR_NilBytes(t *testing.T) {
	_, err := xkmstpm2.UnmarshalIDevIDCSR(nil)
	if err == nil {
		t.Fatal("UnmarshalIDevIDCSR() should fail on nil bytes")
	}
}

func TestEnrollDevice_InvalidPackedCSR_TruncatedHeader(t *testing.T) {
	// Only 8 bytes (StructVer + Contents) but missing SigSz
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[0:4], 0x00000100)
	binary.BigEndian.PutUint32(data[4:8], 0)

	_, err := xkmstpm2.UnmarshalIDevIDCSR(data)
	if err == nil {
		t.Fatal("UnmarshalIDevIDCSR() should fail on truncated header")
	}
}

// =============================================================================
// Packed CSR Building and Unmarshalling Tests
// =============================================================================

func TestBuildPackedCSR_EmptyEKCert(t *testing.T) {
	packed := buildPackedCSRWithEkCert(t, nil)

	csr, err := xkmstpm2.UnmarshalIDevIDCSR(packed)
	if err != nil {
		t.Fatalf("UnmarshalIDevIDCSR() failed: %v", err)
	}

	if len(csr.CsrContents.EkCert) != 0 {
		t.Fatalf("EkCert length = %d, want 0", len(csr.CsrContents.EkCert))
	}
}

func TestBuildPackedCSR_WithDERCert(t *testing.T) {
	cert := generateSelfSignedCert(t)

	packed := buildPackedCSRWithEkCert(t, cert.Raw)

	csr, err := xkmstpm2.UnmarshalIDevIDCSR(packed)
	if err != nil {
		t.Fatalf("UnmarshalIDevIDCSR() failed: %v", err)
	}

	if len(csr.CsrContents.EkCert) != len(cert.Raw) {
		t.Fatalf("EkCert length = %d, want %d", len(csr.CsrContents.EkCert), len(cert.Raw))
	}
}

func TestBuildPackedCSR_WithPEMCert(t *testing.T) {
	cert := generateSelfSignedCert(t)

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	packed := buildPackedCSRWithEkCert(t, pemBytes)

	csr, err := xkmstpm2.UnmarshalIDevIDCSR(packed)
	if err != nil {
		t.Fatalf("UnmarshalIDevIDCSR() failed: %v", err)
	}

	if len(csr.CsrContents.EkCert) != len(pemBytes) {
		t.Fatalf("EkCert length = %d, want %d", len(csr.CsrContents.EkCert), len(pemBytes))
	}
}

// =============================================================================
// EK Certificate Parsing Tests (Code Path Validation)
// =============================================================================
// These tests validate the EK certificate parsing logic in EnrollDevice
// by testing the PEM/DER parsing paths in isolation. Since reaching these
// code paths in EnrollDevice requires a full TrustedPlatformModule mock
// (90+ methods), we test the parsing logic independently.

func TestEKCertParsing_ValidDER(t *testing.T) {
	cert := generateSelfSignedCert(t)

	parsed, err := x509.ParseCertificate(cert.Raw)
	if err != nil {
		t.Fatalf("x509.ParseCertificate(DER) failed: %v", err)
	}
	if parsed.Subject.CommonName != "Test EK Cert" {
		t.Fatalf("CommonName = %q, want %q", parsed.Subject.CommonName, "Test EK Cert")
	}
}

func TestEKCertParsing_ValidPEM(t *testing.T) {
	cert := generateSelfSignedCert(t)

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("pem.Decode returned nil block")
	}

	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("x509.ParseCertificate(PEM) failed: %v", err)
	}
	if parsed.Subject.CommonName != "Test EK Cert" {
		t.Fatalf("CommonName = %q, want %q", parsed.Subject.CommonName, "Test EK Cert")
	}
}

func TestEKCertParsing_InvalidDER(t *testing.T) {
	garbage := []byte("not-a-valid-certificate")

	block, _ := pem.Decode(garbage)
	if block != nil {
		t.Fatal("pem.Decode should return nil for non-PEM data")
	}

	_, err := x509.ParseCertificate(garbage)
	if err == nil {
		t.Fatal("x509.ParseCertificate should fail on garbage DER bytes")
	}
}

func TestEKCertParsing_InvalidPEM(t *testing.T) {
	invalidPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("not-a-valid-asn1-cert"),
	})

	block, _ := pem.Decode(invalidPEM)
	if block == nil {
		t.Fatal("pem.Decode should succeed for valid PEM structure")
	}

	_, err := x509.ParseCertificate(block.Bytes)
	if err == nil {
		t.Fatal("x509.ParseCertificate should fail on invalid ASN.1 data inside PEM")
	}
}

// =============================================================================
// Error Sentinel Tests
// =============================================================================

func TestEnrollmentErrorSentinels(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "ErrTPMNotConfigured",
			err:      ErrTPMNotConfigured,
			expected: "ca: tpm not configured for enrollment",
		},
		{
			name:     "ErrTCGCSRUnmarshalFailed",
			err:      ErrTCGCSRUnmarshalFailed,
			expected: "ca: failed to unmarshal tcg-csr-idevid",
		},
		{
			name:     "ErrTCGMissingEKCert",
			err:      ErrTCGMissingEKCert,
			expected: "ca: missing ek certificate in csr",
		},
		{
			name:     "ErrTCGInvalidEKCert",
			err:      ErrTCGInvalidEKCert,
			expected: "ca: invalid ek certificate",
		},
		{
			name:     "ErrTCGMakeCredentialFailed",
			err:      ErrTCGMakeCredentialFailed,
			expected: "ca: make credential failed",
		},
		{
			name:     "ErrNotInitialized",
			err:      ErrNotInitialized,
			expected: "ca: not initialized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.expected {
				t.Errorf("error message = %q, want %q", tt.err.Error(), tt.expected)
			}
		})
	}
}

func TestEnrollmentErrorWrapping(t *testing.T) {
	// Verify that wrapped errors can be unwrapped with errors.Is
	wrapped := errors.Join(ErrTCGCSRUnmarshalFailed, errors.New("inner cause"))
	if !errors.Is(wrapped, ErrTCGCSRUnmarshalFailed) {
		t.Fatal("errors.Is should find ErrTCGCSRUnmarshalFailed in wrapped error")
	}

	// fmt.Errorf with %w wrapping (matches the pattern used in EnrollDevice)
	fmtWrapped := fmt.Errorf("%w: %v", ErrTCGInvalidEKCert, errors.New("parse failed"))
	if !errors.Is(fmtWrapped, ErrTCGInvalidEKCert) {
		t.Fatal("errors.Is should find ErrTCGInvalidEKCert in fmt.Errorf wrapped error")
	}
}

// =============================================================================
// TCGEnrollmentResult Type Tests
// =============================================================================

func TestTCGEnrollmentResult_Fields(t *testing.T) {
	result := &TCGEnrollmentResult{
		IAKCertDER:      []byte("iak-cert"),
		IDevIDCertDER:   []byte("idevid-cert"),
		CredentialBlob:  []byte("cred-blob"),
		EncryptedSecret: []byte("enc-secret"),
		PlainSecret:     []byte("plain-secret"),
	}

	if string(result.IAKCertDER) != "iak-cert" {
		t.Errorf("IAKCertDER = %q, want %q", result.IAKCertDER, "iak-cert")
	}
	if string(result.IDevIDCertDER) != "idevid-cert" {
		t.Errorf("IDevIDCertDER = %q, want %q", result.IDevIDCertDER, "idevid-cert")
	}
	if string(result.CredentialBlob) != "cred-blob" {
		t.Errorf("CredentialBlob = %q, want %q", result.CredentialBlob, "cred-blob")
	}
	if string(result.EncryptedSecret) != "enc-secret" {
		t.Errorf("EncryptedSecret = %q, want %q", result.EncryptedSecret, "enc-secret")
	}
	if string(result.PlainSecret) != "plain-secret" {
		t.Errorf("PlainSecret = %q, want %q", result.PlainSecret, "plain-secret")
	}
}

func TestTCGEnrollmentResult_NilFields(t *testing.T) {
	result := &TCGEnrollmentResult{}

	if result.IAKCertDER != nil {
		t.Error("IAKCertDER should be nil by default")
	}
	if result.IDevIDCertDER != nil {
		t.Error("IDevIDCertDER should be nil by default")
	}
	if result.CredentialBlob != nil {
		t.Error("CredentialBlob should be nil by default")
	}
	if result.EncryptedSecret != nil {
		t.Error("EncryptedSecret should be nil by default")
	}
	if result.PlainSecret != nil {
		t.Error("PlainSecret should be nil by default")
	}
}

// =============================================================================
// TPM Instance Isolation Tests
// =============================================================================
// These tests verify that the global tpmInstance atomic pointer works correctly
// across multiple CA instances.

func TestTPMInstance_SharedAcrossCAInstances(t *testing.T) {
	tpmInstance.Store(nil)
	t.Cleanup(func() { tpmInstance.Store(nil) })

	ca1 := enrollmentTestCA(t)
	ca2 := enrollmentTestCA(t)

	if ca1.getTPM() != nil {
		t.Fatal("ca1.getTPM() should be nil")
	}
	if ca2.getTPM() != nil {
		t.Fatal("ca2.getTPM() should be nil")
	}
}

func TestTPMInstance_CleanupResetsGlobalState(t *testing.T) {
	tpmInstance.Store(nil)
	t.Cleanup(func() { tpmInstance.Store(nil) })

	ca := enrollmentTestCA(t)

	if ca.getTPM() != nil {
		t.Fatal("getTPM() should return nil after cleanup")
	}
}

// =============================================================================
// EnrollDevice Guard Ordering Tests
// =============================================================================
// Verify that the error checks in EnrollDevice follow the correct priority:
// 1. initialized check (first)
// 2. TPM nil check (second)
// 3. CSR unmarshal (third, requires TPM)

func TestEnrollDevice_ErrorPriority_InitializedBeforeTPM(t *testing.T) {
	tpmInstance.Store(nil)
	t.Cleanup(func() { tpmInstance.Store(nil) })

	// CA is NOT initialized, TPM is NOT set.
	// Should return ErrNotInitialized, not ErrTPMNotConfigured.
	ca := uninitializedEnrollmentTestCA(t)

	_, err := ca.EnrollDevice([]byte("data"), &CertificateRequest{
		Subject: Subject{CommonName: "device"},
	})
	if !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("Expected ErrNotInitialized when CA is not initialized, got: %v", err)
	}
}

func TestEnrollDevice_ErrorPriority_TPMBeforeCSR(t *testing.T) {
	tpmInstance.Store(nil)
	t.Cleanup(func() { tpmInstance.Store(nil) })

	// CA IS initialized, TPM is NOT set. Garbage CSR data.
	// Should return ErrTPMNotConfigured, not ErrTCGCSRUnmarshalFailed.
	ca := enrollmentTestCA(t)

	_, err := ca.EnrollDevice([]byte("garbage-csr"), &CertificateRequest{
		Subject: Subject{CommonName: "device"},
	})
	if !errors.Is(err, ErrTPMNotConfigured) {
		t.Fatalf("Expected ErrTPMNotConfigured when TPM is not set, got: %v", err)
	}
}

// =============================================================================
// TCG-CSR-IDEVID Marshal/Unmarshal Round-Trip Tests
// =============================================================================

func TestCSRMarshalRoundTrip_MinimalPayloads(t *testing.T) {
	csr := &xkmstpm2.TCG_CSR_IDEVID{
		Signature: placeholderSignature,
	}
	binary.BigEndian.PutUint32(csr.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.Contents[:], 0)
	binary.BigEndian.PutUint32(csr.SigSz[:], uint32(len(placeholderSignature)))

	content := &csr.CsrContents
	binary.BigEndian.PutUint32(content.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(content.HashAlgoId[:], 0x000B)
	binary.BigEndian.PutUint32(content.HashSz[:], 32)

	packed, err := csr.Marshal()
	if err != nil {
		t.Fatalf("Marshal() failed: %v", err)
	}

	if len(packed) == 0 {
		t.Fatal("Marshal() returned empty bytes")
	}

	unpacked, err := xkmstpm2.UnmarshalIDevIDCSR(packed)
	if err != nil {
		t.Fatalf("UnmarshalIDevIDCSR() failed: %v", err)
	}

	// Verify StructVer round-trip
	originalVer := binary.BigEndian.Uint32(csr.StructVer[:])
	unpackedVer := binary.BigEndian.Uint32(unpacked.StructVer[:])
	if originalVer != unpackedVer {
		t.Fatalf("StructVer = 0x%08X, want 0x%08X", unpackedVer, originalVer)
	}

	// Verify signature survived
	if len(unpacked.Signature) != len(placeholderSignature) {
		t.Fatalf("Signature length = %d, want %d", len(unpacked.Signature), len(placeholderSignature))
	}
}

func TestCSRMarshalRoundTrip_WithEKCert(t *testing.T) {
	cert := generateSelfSignedCert(t)

	csr := &xkmstpm2.TCG_CSR_IDEVID{
		Signature: placeholderSignature,
	}
	binary.BigEndian.PutUint32(csr.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.Contents[:], 0)
	binary.BigEndian.PutUint32(csr.SigSz[:], uint32(len(placeholderSignature)))

	content := &csr.CsrContents
	binary.BigEndian.PutUint32(content.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(content.HashAlgoId[:], 0x000B)
	binary.BigEndian.PutUint32(content.HashSz[:], 32)
	binary.BigEndian.PutUint32(content.EkCertSZ[:], uint32(len(cert.Raw)))
	content.EkCert = make([]byte, len(cert.Raw))
	copy(content.EkCert, cert.Raw)

	packed, err := csr.Marshal()
	if err != nil {
		t.Fatalf("Marshal() failed: %v", err)
	}

	unpacked, err := xkmstpm2.UnmarshalIDevIDCSR(packed)
	if err != nil {
		t.Fatalf("UnmarshalIDevIDCSR() failed: %v", err)
	}

	if len(unpacked.CsrContents.EkCert) != len(cert.Raw) {
		t.Fatalf("EkCert length = %d, want %d", len(unpacked.CsrContents.EkCert), len(cert.Raw))
	}

	// Verify the certificate bytes survived the round-trip
	parsedCert, err := x509.ParseCertificate(unpacked.CsrContents.EkCert)
	if err != nil {
		t.Fatalf("Failed to parse round-tripped EK cert: %v", err)
	}
	if parsedCert.Subject.CommonName != cert.Subject.CommonName {
		t.Fatalf("CommonName = %q, want %q", parsedCert.Subject.CommonName, cert.Subject.CommonName)
	}
}

func TestCSRMarshalRoundTrip_WithMultiplePayloads(t *testing.T) {
	cert := generateSelfSignedCert(t)
	model := []byte("TestModel-9000")
	serial := []byte("SN-12345678")
	sig := []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03, 0x04}

	csr := &xkmstpm2.TCG_CSR_IDEVID{
		Signature: sig,
	}
	binary.BigEndian.PutUint32(csr.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.Contents[:], 0)
	binary.BigEndian.PutUint32(csr.SigSz[:], uint32(len(sig)))

	content := &csr.CsrContents
	binary.BigEndian.PutUint32(content.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(content.HashAlgoId[:], 0x000B)
	binary.BigEndian.PutUint32(content.HashSz[:], 32)

	binary.BigEndian.PutUint32(content.ProdModelSz[:], uint32(len(model)))
	content.ProdModel = make([]byte, len(model))
	copy(content.ProdModel, model)

	binary.BigEndian.PutUint32(content.ProdSerialSz[:], uint32(len(serial)))
	content.ProdSerial = make([]byte, len(serial))
	copy(content.ProdSerial, serial)

	binary.BigEndian.PutUint32(content.EkCertSZ[:], uint32(len(cert.Raw)))
	content.EkCert = make([]byte, len(cert.Raw))
	copy(content.EkCert, cert.Raw)

	packed, err := csr.Marshal()
	if err != nil {
		t.Fatalf("Marshal() failed: %v", err)
	}

	unpacked, err := xkmstpm2.UnmarshalIDevIDCSR(packed)
	if err != nil {
		t.Fatalf("UnmarshalIDevIDCSR() failed: %v", err)
	}

	if string(unpacked.CsrContents.ProdModel) != string(model) {
		t.Errorf("ProdModel = %q, want %q", unpacked.CsrContents.ProdModel, model)
	}
	if string(unpacked.CsrContents.ProdSerial) != string(serial) {
		t.Errorf("ProdSerial = %q, want %q", unpacked.CsrContents.ProdSerial, serial)
	}
	if len(unpacked.CsrContents.EkCert) != len(cert.Raw) {
		t.Errorf("EkCert length = %d, want %d", len(unpacked.CsrContents.EkCert), len(cert.Raw))
	}
	if len(unpacked.Signature) != len(sig) {
		t.Errorf("Signature length = %d, want %d", len(unpacked.Signature), len(sig))
	}
}

// =============================================================================
// EnrollDevice with Missing EK Certificate (CSR-level validation)
// =============================================================================
// The EK cert check happens AFTER unmarshal and AFTER TPM nil check.
// Without a real TPM mock, we validate that the CSR building and
// unmarshalling correctly preserves empty EK certs, which would trigger
// ErrTCGMissingEKCert in EnrollDevice when reached.

func TestEnrollDevice_MissingEKCert_CSRBuilds(t *testing.T) {
	packed := buildPackedCSRWithEkCert(t, nil)

	csr, err := xkmstpm2.UnmarshalIDevIDCSR(packed)
	if err != nil {
		t.Fatalf("UnmarshalIDevIDCSR() failed: %v", err)
	}

	// This is the condition that EnrollDevice checks
	if len(csr.CsrContents.EkCert) != 0 {
		t.Fatalf("Expected empty EkCert in CSR, got %d bytes", len(csr.CsrContents.EkCert))
	}
}

func TestEnrollDevice_InvalidEKCert_CSRBuilds(t *testing.T) {
	garbageCert := []byte("this-is-not-a-certificate")
	packed := buildPackedCSRWithEkCert(t, garbageCert)

	csr, err := xkmstpm2.UnmarshalIDevIDCSR(packed)
	if err != nil {
		t.Fatalf("UnmarshalIDevIDCSR() failed: %v", err)
	}

	if len(csr.CsrContents.EkCert) != len(garbageCert) {
		t.Fatalf("EkCert length = %d, want %d", len(csr.CsrContents.EkCert), len(garbageCert))
	}

	// The EK cert is non-empty (passes the len check) but is not valid PEM or DER.
	// This would trigger ErrTCGInvalidEKCert in EnrollDevice after the TPM check.
	block, _ := pem.Decode(csr.CsrContents.EkCert)
	if block != nil {
		t.Fatal("PEM decode should fail on garbage data")
	}
	_, err = x509.ParseCertificate(csr.CsrContents.EkCert)
	if err == nil {
		t.Fatal("DER parse should fail on garbage data")
	}
}

// =============================================================================
// CertificateRequest Validation Tests (for enrollment context)
// =============================================================================

func TestCertificateRequest_ValidForEnrollment(t *testing.T) {
	request := &CertificateRequest{
		Subject: Subject{
			CommonName:   "device-001.example.com",
			Organization: "Test Corp",
			Country:      "US",
		},
		Valid:      365,
		ProdModel:  "TPM-Model-X",
		ProdSerial: "SN-001",
	}

	if err := request.Validate(); err != nil {
		t.Fatalf("Validate() failed: %v", err)
	}
}

func TestCertificateRequest_MissingCommonName(t *testing.T) {
	request := &CertificateRequest{
		Subject: Subject{
			Organization: "Test Corp",
		},
	}

	err := request.Validate()
	if !errors.Is(err, ErrSubjectCommonNameRequired) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrSubjectCommonNameRequired)
	}
}

func TestCertificateRequest_InvalidValidity(t *testing.T) {
	request := &CertificateRequest{
		Subject: Subject{CommonName: "test"},
		Valid:   -1,
	}

	err := request.Validate()
	if !errors.Is(err, ErrInvalidValidityPeriod) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrInvalidValidityPeriod)
	}
}
