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

package deviceattest01

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock implementations for testing

type mockCA struct {
	verifyError         error
	verifyAKChainError  error
	verifyAKChainCount  int
	verifyAKChainCalled bool
}

func (m *mockCA) VerifyAttestationObject(obj *AttestationObject, expectedChallenge []byte) error {
	if m.verifyError != nil {
		return m.verifyError
	}
	return nil
}

func (m *mockCA) VerifyAKCertificateChain(certs [][]byte) error {
	m.verifyAKChainCalled = true
	m.verifyAKChainCount++
	if m.verifyAKChainError != nil {
		return m.verifyAKChainError
	}
	return nil
}

type mockTPMAttributes struct {
	publicKeyBytes []byte
	bPublic        *mockTPM2BPublic
}

func (m *mockTPMAttributes) GetPublicKeyBytes() []byte {
	return m.publicKeyBytes
}

func (m *mockTPMAttributes) GetBPublic() TPM2BPublic {
	return m.bPublic
}

type mockTPM2BPublic struct {
	bytes []byte
}

func (m *mockTPM2BPublic) Bytes() []byte {
	return m.bytes
}

type mockKeyAttributes struct {
	keyAlgorithm  x509.PublicKeyAlgorithm
	tpmAttributes *mockTPMAttributes
}

func (m *mockKeyAttributes) GetKeyAlgorithm() x509.PublicKeyAlgorithm {
	return m.keyAlgorithm
}

func (m *mockKeyAttributes) GetTPMAttributes() TPMAttributes {
	return m.tpmAttributes
}

type mockQuote struct {
	signature []byte
	quoted    []byte
}

func (m *mockQuote) GetSignature() []byte {
	return m.signature
}

func (m *mockQuote) GetQuoted() []byte {
	return m.quoted
}

type mockTPM struct {
	quoteResult  *mockQuote
	quoteError   error
	quoteCalled  bool
	quotePCRs    []uint
	quoteQualify []byte
}

func (m *mockTPM) Quote(pcrIndices []uint, qualifyingData []byte) (Quote, error) {
	m.quoteCalled = true
	m.quotePCRs = pcrIndices
	m.quoteQualify = qualifyingData

	if m.quoteError != nil {
		return nil, m.quoteError
	}
	return m.quoteResult, nil
}

func TestAttestationFormat_String(t *testing.T) {
	format := FormatTPM
	if format.String() != "tpm" {
		t.Errorf("Expected 'tpm', got %q", format.String())
	}
}

func TestVerify_NetworkError(t *testing.T) {
	ca := &mockCA{}
	resolver := net.DefaultResolver

	// Use invalid port to trigger network error
	err := Verify(resolver, ca, "127.0.0.1", "99999", "token", "keyauth")
	if err == nil {
		t.Error("Verify() should fail with network error")
	}

	// Verify it's a network error, not a CA verification error
	if !strings.Contains(err.Error(), "failed to contact client") {
		t.Errorf("Expected network error, got: %v", err)
	}
}

func TestVerify_HTTPStatusError(t *testing.T) {
	// Create mock HTTP server that returns non-200 status
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	serverURL := strings.TrimPrefix(server.URL, "http://")
	parts := strings.Split(serverURL, ":")
	host := parts[0]
	port := parts[1]

	ca := &mockCA{}
	resolver := net.DefaultResolver

	err := Verify(resolver, ca, host, port, "token", "keyauth")
	if err == nil {
		t.Error("Verify() should fail with non-200 status")
	}

	if !strings.Contains(err.Error(), "unexpected status code") {
		t.Errorf("Expected status code error, got: %v", err)
	}
}

func TestVerify_InvalidJSON(t *testing.T) {
	// Create mock HTTP server that returns invalid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	serverURL := strings.TrimPrefix(server.URL, "http://")
	parts := strings.Split(serverURL, ":")
	host := parts[0]
	port := parts[1]

	ca := &mockCA{}
	resolver := net.DefaultResolver

	err := Verify(resolver, ca, host, port, "token", "keyauth")
	if err == nil {
		t.Error("Verify() should fail with invalid JSON")
	}

	if !strings.Contains(err.Error(), "invalid attestation request") {
		t.Errorf("Expected JSON error, got: %v", err)
	}
}

func TestVerify_InvalidCBOR(t *testing.T) {
	// Create attestation request with invalid CBOR
	attestReq := AttestationRequest{AttStmt: []byte("not valid cbor")}
	jsonData, _ := json.Marshal(attestReq)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(jsonData)
	}))
	defer server.Close()

	serverURL := strings.TrimPrefix(server.URL, "http://")
	parts := strings.Split(serverURL, ":")
	host := parts[0]
	port := parts[1]

	ca := &mockCA{}
	resolver := net.DefaultResolver

	err := Verify(resolver, ca, host, port, "token", "keyauth")
	if err == nil {
		t.Error("Verify() should fail with invalid CBOR")
	}

	if !strings.Contains(err.Error(), "device-attest-01") {
		t.Errorf("Expected device-attest-01 error, got: %v", err)
	}
}

func TestVerify_InvalidAttestationFormat(t *testing.T) {
	// Create attestation object with invalid format
	obj := &AttestationObject{
		Format: "invalid-format",
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      -257,
			X5c:      []interface{}{[]byte("cert-bytes")},
			Sig:      []byte("signature"),
			CertInfo: []byte("cert-info"),
			PubArea:  []byte("pub-area"),
		},
	}

	cborData, _ := cbor.Marshal(obj)
	attestReq := AttestationRequest{AttStmt: cborData}
	jsonData, _ := json.Marshal(attestReq)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(jsonData)
	}))
	defer server.Close()

	serverURL := strings.TrimPrefix(server.URL, "http://")
	parts := strings.Split(serverURL, ":")
	host := parts[0]
	port := parts[1]

	ca := &mockCA{}
	resolver := net.DefaultResolver

	err := Verify(resolver, ca, host, port, "token", "keyauth")
	if err != ErrInvalidAttestationFormat {
		t.Errorf("Expected ErrInvalidAttestationFormat, got: %v", err)
	}
}

func TestVerify_CAVerificationError(t *testing.T) {
	// Create valid attestation object
	obj := &AttestationObject{
		Format: "tpm",
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      -257,
			X5c:      []interface{}{[]byte("cert-bytes")},
			Sig:      []byte("signature"),
			CertInfo: []byte("cert-info-with-keyauth"),
			PubArea:  []byte("pub-area"),
		},
	}

	cborData, _ := cbor.Marshal(obj)
	attestReq := AttestationRequest{AttStmt: cborData}
	jsonData, _ := json.Marshal(attestReq)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(jsonData)
	}))
	defer server.Close()

	serverURL := strings.TrimPrefix(server.URL, "http://")
	parts := strings.Split(serverURL, ":")
	host := parts[0]
	port := parts[1]

	ca := &mockCA{
		verifyError: errors.New("CA verification failed"),
	}
	resolver := net.DefaultResolver

	err := Verify(resolver, ca, host, port, "token", "keyauth")
	if err == nil {
		t.Error("Verify() should fail when CA verification fails")
	}

	if !strings.Contains(err.Error(), "attestation verification failed") {
		t.Errorf("Expected attestation verification error, got: %v", err)
	}
}

func TestVerify_AKCertificateChainError(t *testing.T) {
	// Create attestation with certificate chain
	obj := &AttestationObject{
		Format: "tpm",
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      -257,
			X5c:      []interface{}{[]byte("cert-bytes")},
			Sig:      []byte("signature"),
			CertInfo: []byte("cert-info-with-keyauth"),
			PubArea:  []byte("pub-area"),
		},
	}

	cborData, _ := cbor.Marshal(obj)
	attestReq := AttestationRequest{AttStmt: cborData}
	jsonData, _ := json.Marshal(attestReq)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(jsonData)
	}))
	defer server.Close()

	serverURL := strings.TrimPrefix(server.URL, "http://")
	parts := strings.Split(serverURL, ":")
	host := parts[0]
	port := parts[1]

	ca := &mockCA{
		verifyAKChainError: errors.New("AK chain verification failed"),
	}
	resolver := net.DefaultResolver

	err := Verify(resolver, ca, host, port, "token", "keyauth")
	if err != ErrCertificateChainInvalid {
		t.Errorf("Expected ErrCertificateChainInvalid, got: %v", err)
	}
}

func TestSetup_RSA_Success(t *testing.T) {
	keyAuth := "test-keyauth"
	signature := []byte("test-signature")
	quoted := []byte("test-quoted")
	pubKeyBytes := []byte("test-public-key")
	pubAreaBytes := []byte("test-pub-area")

	akAttrs := &mockKeyAttributes{
		keyAlgorithm: x509.RSA,
		tpmAttributes: &mockTPMAttributes{
			publicKeyBytes: pubKeyBytes,
			bPublic: &mockTPM2BPublic{
				bytes: pubAreaBytes,
			},
		},
	}

	tpm := &mockTPM{
		quoteResult: &mockQuote{
			signature: signature,
			quoted:    quoted,
		},
	}

	payload, err := Setup(keyAuth, akAttrs, FormatTPM, tpm)
	if err != nil {
		t.Fatalf("Setup() failed: %v", err)
	}

	if payload == nil {
		t.Fatal("Setup() should return payload")
	}

	// Verify TPM Quote was called correctly
	if !tpm.quoteCalled {
		t.Error("Setup() should call TPM Quote")
	}

	if len(tpm.quotePCRs) != 1 || tpm.quotePCRs[0] != 14 {
		t.Errorf("Expected PCR [14], got %v", tpm.quotePCRs)
	}

	if string(tpm.quoteQualify) != keyAuth {
		t.Errorf("Expected qualifying data %q, got %q", keyAuth, string(tpm.quoteQualify))
	}

	// Decode and verify payload
	var req struct {
		AttStmt []byte `json:"attStmt"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}

	var obj AttestationObject
	if err := cbor.Unmarshal(req.AttStmt, &obj); err != nil {
		t.Fatalf("Failed to unmarshal CBOR: %v", err)
	}

	if obj.Format != "tpm" {
		t.Errorf("Expected format 'tpm', got %q", obj.Format)
	}

	if obj.AttStatement.Ver != "2.0" {
		t.Errorf("Expected version '2.0', got %q", obj.AttStatement.Ver)
	}

	if obj.AttStatement.Alg != -257 {
		t.Errorf("Expected algorithm -257 (RS256), got %d", obj.AttStatement.Alg)
	}

	if len(obj.AttStatement.X5c) != 1 {
		t.Fatalf("Expected 1 certificate, got %d", len(obj.AttStatement.X5c))
	}

	if string(obj.AttStatement.Sig) != string(signature) {
		t.Error("Signature mismatch")
	}

	if string(obj.AttStatement.CertInfo) != string(quoted) {
		t.Error("CertInfo mismatch")
	}

	if string(obj.AttStatement.PubArea) != string(pubAreaBytes) {
		t.Error("PubArea mismatch")
	}
}

func TestSetup_ECDSA_Success(t *testing.T) {
	akAttrs := &mockKeyAttributes{
		keyAlgorithm: x509.ECDSA,
		tpmAttributes: &mockTPMAttributes{
			publicKeyBytes: []byte("ecdsa-public-key"),
			bPublic: &mockTPM2BPublic{
				bytes: []byte("ecdsa-pub-area"),
			},
		},
	}

	tpm := &mockTPM{
		quoteResult: &mockQuote{
			signature: []byte("ecdsa-signature"),
			quoted:    []byte("ecdsa-quoted"),
		},
	}

	payload, err := Setup("keyauth", akAttrs, FormatTPM, tpm)
	if err != nil {
		t.Fatalf("Setup() failed for ECDSA: %v", err)
	}

	var req struct {
		AttStmt []byte `json:"attStmt"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}

	var obj AttestationObject
	if err := cbor.Unmarshal(req.AttStmt, &obj); err != nil {
		t.Fatalf("Failed to unmarshal CBOR: %v", err)
	}

	if obj.AttStatement.Alg != -7 {
		t.Errorf("Expected algorithm -7 (ES256), got %d", obj.AttStatement.Alg)
	}
}

func TestSetup_Ed25519_Success(t *testing.T) {
	akAttrs := &mockKeyAttributes{
		keyAlgorithm: x509.Ed25519,
		tpmAttributes: &mockTPMAttributes{
			publicKeyBytes: []byte("ed25519-public-key"),
			bPublic: &mockTPM2BPublic{
				bytes: []byte("ed25519-pub-area"),
			},
		},
	}

	tpm := &mockTPM{
		quoteResult: &mockQuote{
			signature: []byte("ed25519-signature"),
			quoted:    []byte("ed25519-quoted"),
		},
	}

	payload, err := Setup("keyauth", akAttrs, FormatTPM, tpm)
	if err != nil {
		t.Fatalf("Setup() failed for Ed25519: %v", err)
	}

	var req struct {
		AttStmt []byte `json:"attStmt"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}

	var obj AttestationObject
	if err := cbor.Unmarshal(req.AttStmt, &obj); err != nil {
		t.Fatalf("Failed to unmarshal CBOR: %v", err)
	}

	if obj.AttStatement.Alg != -8 {
		t.Errorf("Expected algorithm -8 (EdDSA), got %d", obj.AttStatement.Alg)
	}
}

func TestSetup_InvalidKeyAlgorithm(t *testing.T) {
	akAttrs := &mockKeyAttributes{
		keyAlgorithm: x509.DSA, // Unsupported algorithm
		tpmAttributes: &mockTPMAttributes{
			publicKeyBytes: []byte("dsa-public-key"),
			bPublic: &mockTPM2BPublic{
				bytes: []byte("dsa-pub-area"),
			},
		},
	}

	tpm := &mockTPM{
		quoteResult: &mockQuote{
			signature: []byte("dsa-signature"),
			quoted:    []byte("dsa-quoted"),
		},
	}

	_, err := Setup("keyauth", akAttrs, FormatTPM, tpm)
	if err != ErrInvalidKeyAlgorithm {
		t.Errorf("Expected ErrInvalidKeyAlgorithm, got: %v", err)
	}
}

func TestSetup_InvalidAttestationFormat(t *testing.T) {
	akAttrs := &mockKeyAttributes{
		keyAlgorithm: x509.RSA,
		tpmAttributes: &mockTPMAttributes{
			publicKeyBytes: []byte("rsa-public-key"),
			bPublic: &mockTPM2BPublic{
				bytes: []byte("rsa-pub-area"),
			},
		},
	}

	tpm := &mockTPM{
		quoteResult: &mockQuote{
			signature: []byte("rsa-signature"),
			quoted:    []byte("rsa-quoted"),
		},
	}

	_, err := Setup("keyauth", akAttrs, AttestationFormat("invalid"), tpm)
	if err != ErrInvalidAttestationFormat {
		t.Errorf("Expected ErrInvalidAttestationFormat, got: %v", err)
	}
}

func TestSetup_QuoteError(t *testing.T) {
	akAttrs := &mockKeyAttributes{
		keyAlgorithm: x509.RSA,
		tpmAttributes: &mockTPMAttributes{
			publicKeyBytes: []byte("rsa-public-key"),
			bPublic: &mockTPM2BPublic{
				bytes: []byte("rsa-pub-area"),
			},
		},
	}

	tpm := &mockTPM{
		quoteError: errors.New("TPM quote failed"),
	}

	_, err := Setup("keyauth", akAttrs, FormatTPM, tpm)
	if err == nil {
		t.Error("Setup() should fail when TPM Quote fails")
	}
	if !strings.Contains(err.Error(), "TPM quote failed") {
		t.Errorf("Expected TPM quote error, got: %v", err)
	}
}

func TestParseAttestationObject_Success(t *testing.T) {
	obj := &AttestationObject{
		Format: "tpm",
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      -257,
			X5c:      []interface{}{[]byte("cert-bytes")},
			Sig:      []byte("signature"),
			CertInfo: []byte("cert-info"),
			PubArea:  []byte("pub-area"),
		},
	}

	data, err := cbor.Marshal(obj)
	if err != nil {
		t.Fatalf("Failed to marshal test object: %v", err)
	}

	parsed, err := ParseAttestationObject(data)
	if err != nil {
		t.Fatalf("ParseAttestationObject() failed: %v", err)
	}

	if parsed.Format != "tpm" {
		t.Errorf("Expected format 'tpm', got %q", parsed.Format)
	}

	if parsed.AttStatement.Ver != "2.0" {
		t.Errorf("Expected version '2.0', got %q", parsed.AttStatement.Ver)
	}

	if parsed.AttStatement.Alg != -257 {
		t.Errorf("Expected algorithm -257, got %d", parsed.AttStatement.Alg)
	}
}

func TestParseAttestationObject_InvalidCBOR(t *testing.T) {
	invalidData := []byte("not-valid-cbor")

	_, err := ParseAttestationObject(invalidData)
	if err == nil {
		t.Error("ParseAttestationObject() should fail with invalid CBOR")
	}
}

func TestValidateAttestationFormat_TPM(t *testing.T) {
	if !ValidateAttestationFormat(FormatTPM) {
		t.Error("ValidateAttestationFormat() should return true for FormatTPM")
	}
}

func TestValidateAttestationFormat_Invalid(t *testing.T) {
	if ValidateAttestationFormat(AttestationFormat("invalid")) {
		t.Error("ValidateAttestationFormat() should return false for invalid format")
	}

	if ValidateAttestationFormat(AttestationFormat("fido-u2f")) {
		t.Error("ValidateAttestationFormat() should return false for unsupported format")
	}

	if ValidateAttestationFormat(AttestationFormat("")) {
		t.Error("ValidateAttestationFormat() should return false for empty format")
	}
}

func TestSetup_Integration(t *testing.T) {
	// Integration test simulating full device-attest-01 setup flow
	keyAuth := "integration-test-keyauth"

	akAttrs := &mockKeyAttributes{
		keyAlgorithm: x509.RSA,
		tpmAttributes: &mockTPMAttributes{
			publicKeyBytes: []byte("integration-public-key"),
			bPublic: &mockTPM2BPublic{
				bytes: []byte("integration-pub-area"),
			},
		},
	}

	tpm := &mockTPM{
		quoteResult: &mockQuote{
			signature: []byte("integration-signature"),
			quoted:    []byte("integration-quoted"),
		},
	}

	// Generate attestation
	payload, err := Setup(keyAuth, akAttrs, FormatTPM, tpm)
	if err != nil {
		t.Fatalf("Integration test failed: %v", err)
	}

	// Parse and validate
	var req struct {
		AttStmt []byte `json:"attStmt"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	parsed, err := ParseAttestationObject(req.AttStmt)
	if err != nil {
		t.Fatalf("Failed to parse attestation object: %v", err)
	}

	// Validate format
	if !ValidateAttestationFormat(AttestationFormat(parsed.Format)) {
		t.Error("Attestation format should be valid")
	}

	// Verify structure
	if parsed.AttStatement.Ver != "2.0" {
		t.Error("Version should be '2.0'")
	}

	if parsed.AttStatement.Alg != -257 {
		t.Error("Algorithm should be -257 for RSA")
	}

	if len(parsed.AttStatement.X5c) != 1 {
		t.Error("Should have exactly one certificate")
	}

	// Verify TPM was called correctly
	if !tpm.quoteCalled {
		t.Error("TPM Quote should have been called")
	}

	if string(tpm.quoteQualify) != keyAuth {
		t.Error("Qualifying data should match key authorization")
	}
}

func TestSetup_AllAlgorithms(t *testing.T) {
	testCases := []struct {
		name     string
		alg      x509.PublicKeyAlgorithm
		expected int64
	}{
		{
			name:     "RSA",
			alg:      x509.RSA,
			expected: -257,
		},
		{
			name:     "ECDSA",
			alg:      x509.ECDSA,
			expected: -7,
		},
		{
			name:     "Ed25519",
			alg:      x509.Ed25519,
			expected: -8,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			akAttrs := &mockKeyAttributes{
				keyAlgorithm: tc.alg,
				tpmAttributes: &mockTPMAttributes{
					publicKeyBytes: []byte("test-public-key"),
					bPublic: &mockTPM2BPublic{
						bytes: []byte("test-pub-area"),
					},
				},
			}

			tpm := &mockTPM{
				quoteResult: &mockQuote{
					signature: []byte("test-signature"),
					quoted:    []byte("test-quoted"),
				},
			}

			payload, err := Setup("keyauth", akAttrs, FormatTPM, tpm)
			if err != nil {
				t.Fatalf("Setup() failed for %s: %v", tc.name, err)
			}

			var req struct {
				AttStmt []byte `json:"attStmt"`
			}
			if err := json.Unmarshal(payload, &req); err != nil {
				t.Fatalf("Failed to unmarshal payload: %v", err)
			}

			var obj AttestationObject
			if err := cbor.Unmarshal(req.AttStmt, &obj); err != nil {
				t.Fatalf("Failed to unmarshal CBOR: %v", err)
			}

			if obj.AttStatement.Alg != tc.expected {
				t.Errorf("Expected algorithm %d, got %d", tc.expected, obj.AttStatement.Alg)
			}
		})
	}
}

// Tests for VerifyQualifyingData

func TestVerifyQualifyingData_Success(t *testing.T) {
	certInfo := []byte("this contains the expected qualifying data")
	expectedData := []byte("expected qualifying data")

	if !VerifyQualifyingData(certInfo, expectedData) {
		t.Error("VerifyQualifyingData() should return true when data is present")
	}
}

func TestVerifyQualifyingData_NotFound(t *testing.T) {
	certInfo := []byte("this does not contain the data")
	expectedData := []byte("missing data")

	if VerifyQualifyingData(certInfo, expectedData) {
		t.Error("VerifyQualifyingData() should return false when data is not present")
	}
}

func TestVerifyQualifyingData_EmptyCertInfo(t *testing.T) {
	certInfo := []byte("")
	expectedData := []byte("some data")

	if VerifyQualifyingData(certInfo, expectedData) {
		t.Error("VerifyQualifyingData() should return false for empty certInfo")
	}
}

func TestVerifyQualifyingData_EmptyExpected(t *testing.T) {
	certInfo := []byte("some cert info")
	expectedData := []byte("")

	// Empty string is always contained
	if !VerifyQualifyingData(certInfo, expectedData) {
		t.Error("VerifyQualifyingData() should return true for empty expected data")
	}
}

func TestVerifyQualifyingData_PartialMatch(t *testing.T) {
	certInfo := []byte("some-prefix-EXPECTED-DATA-suffix")
	expected := []byte("EXPECTED-DATA")

	result := VerifyQualifyingData(certInfo, expected)
	assert.True(t, result, "Should find expected data within certInfo")
}

func TestVerifyQualifyingData_NoMatch(t *testing.T) {
	certInfo := []byte("completely-different-data")
	expected := []byte("EXPECTED-DATA")

	result := VerifyQualifyingData(certInfo, expected)
	assert.False(t, result, "Should not find expected data")
}

func TestVerifyQualifyingData_InvalidCertInfoFallback(t *testing.T) {
	// Use certInfo that is too short to parse as TPMS_ATTEST
	// but still contains the expected data (fallback to bytes.Contains)
	certInfo := []byte("short-certinfo-with-expected-data")
	expectedData := []byte("expected-data")

	// This should fall back to bytes.Contains since ParseTPMSAttest will fail
	result := VerifyQualifyingData(certInfo, expectedData)
	assert.True(t, result, "Should find expected data via fallback containment check")
}

func TestVerifyQualifyingData_InvalidCertInfoFallbackNotFound(t *testing.T) {
	// Short certInfo that will fail TPMS_ATTEST parsing
	certInfo := []byte("short-certinfo")
	expectedData := []byte("missing-data")

	// Should return false via fallback bytes.Contains
	result := VerifyQualifyingData(certInfo, expectedData)
	assert.False(t, result, "Should not find missing data")
}

func TestVerifyQualifyingData_ValidTPMSAttestExactMatch(t *testing.T) {
	// Build a valid TPMS_ATTEST structure with specific extraData
	expectedData := []byte("test-keyauth")

	// Build TPMS_ATTEST with the expectedData in the extraData field
	var buf []byte

	// Magic (4 bytes, big-endian): TPM_GENERATED_VALUE = 0xFF544347
	buf = append(buf, 0xFF, 0x54, 0x43, 0x47)

	// Type (2 bytes): TPM_ST_ATTEST_QUOTE = 0x8018
	buf = append(buf, 0x80, 0x18)

	// QualifiedSigner (TPM2B_NAME: 2-byte size + data)
	buf = append(buf, 0x00, 0x02) // size = 2
	buf = append(buf, 0xAA, 0xBB) // data

	// ExtraData (TPM2B_DATA: 2-byte size + data)
	extraDataSize := len(expectedData)
	buf = append(buf, byte(extraDataSize>>8), byte(extraDataSize&0xFF)) // size
	buf = append(buf, expectedData...)                                  // data

	// ClockInfo (TPMS_CLOCK_INFO = 17 bytes)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01) // Clock
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)                         // ResetCount
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)                         // RestartCount
	buf = append(buf, 0x01)                                           // Safe

	// FirmwareVersion (8 bytes)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)

	// TPML_PCR_SELECTION (for quote type)
	buf = append(buf, 0x00, 0x00, 0x00, 0x01) // count = 1

	// TPMS_PCR_SELECTION
	buf = append(buf, 0x00, 0x0B) // hash = SHA256
	buf = append(buf, 0x03)       // sizeOfSelect = 3
	buf = append(buf, 0x01, 0x00, 0x00)

	// pcrDigest
	buf = append(buf, 0x00, 0x20) // size = 32
	buf = append(buf, make([]byte, 32)...)

	// VerifyQualifyingData should parse and compare extraData field
	result := VerifyQualifyingData(buf, expectedData)
	assert.True(t, result, "Should find expected data in extraData field of valid TPMS_ATTEST")
}

func TestVerifyQualifyingData_ValidTPMSAttestMismatch(t *testing.T) {
	expectedData := []byte("different-keyauth")
	actualExtraData := []byte("test-keyauth")

	// Build TPMS_ATTEST with different extraData
	var buf []byte

	// Magic
	buf = append(buf, 0xFF, 0x54, 0x43, 0x47)

	// Type
	buf = append(buf, 0x80, 0x18)

	// QualifiedSigner
	buf = append(buf, 0x00, 0x02)
	buf = append(buf, 0xAA, 0xBB)

	// ExtraData (with actualExtraData, not expectedData)
	extraDataSize := len(actualExtraData)
	buf = append(buf, byte(extraDataSize>>8), byte(extraDataSize&0xFF))
	buf = append(buf, actualExtraData...)

	// ClockInfo
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	buf = append(buf, 0x01)

	// FirmwareVersion
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)

	// TPML_PCR_SELECTION
	buf = append(buf, 0x00, 0x00, 0x00, 0x01)
	buf = append(buf, 0x00, 0x0B)
	buf = append(buf, 0x03)
	buf = append(buf, 0x01, 0x00, 0x00)
	buf = append(buf, 0x00, 0x20)
	buf = append(buf, make([]byte, 32)...)

	// Should return false because extraData doesn't match expected
	result := VerifyQualifyingData(buf, expectedData)
	assert.False(t, result, "Should not match when extraData differs from expected")
}

func TestVerifyQualifyingData_ExactMatch(t *testing.T) {
	certInfo := []byte("test-data")
	expected := []byte("test-data")

	result := VerifyQualifyingData(certInfo, expected)
	assert.True(t, result)
}

func TestVerifyQualifyingData_BinaryData(t *testing.T) {
	certInfo := []byte{0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00}
	expected := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	result := VerifyQualifyingData(certInfo, expected)
	assert.True(t, result)
}

// Tests for ExtractPCRsFromCertInfo

func TestExtractPCRsFromCertInfo_Success(t *testing.T) {
	// Create a valid TPMS_ATTEST structure with TPM_GENERATED magic
	// and TPM_ST_ATTEST_QUOTE type (0x8018)
	certInfo := buildValidTPMSAttest()

	pcrs, err := ExtractPCRsFromCertInfo(certInfo)
	if err != nil {
		t.Errorf("ExtractPCRsFromCertInfo() should not return error: %v", err)
	}

	// After parsing, pcrs should be populated with PCR selection info
	if pcrs == nil {
		t.Error("ExtractPCRsFromCertInfo() should return PCR data for valid input")
	}
}

func TestExtractPCRsFromCertInfo_EmptyInput(t *testing.T) {
	certInfo := []byte("")

	_, err := ExtractPCRsFromCertInfo(certInfo)
	if err == nil {
		t.Error("ExtractPCRsFromCertInfo() should return error for empty input")
	}
}

func TestExtractPCRsFromCertInfo_InvalidMagic(t *testing.T) {
	certInfo := []byte("test-cert-info-invalid")

	_, err := ExtractPCRsFromCertInfo(certInfo)
	if err == nil {
		t.Error("ExtractPCRsFromCertInfo() should return error for invalid TPM magic")
	}
}

func TestExtractPCRsFromCertInfo_ValidPCRSelection(t *testing.T) {
	data := buildValidTPMSAttest()

	pcrs, err := ExtractPCRsFromCertInfo(data)
	require.NoError(t, err)
	assert.NotNil(t, pcrs)
}

func TestExtractPCRsFromCertInfo_TruncatedQuoteInfo(t *testing.T) {
	// Build data with valid header but truncated quote info
	data := []byte{
		0xFF, 0x54, 0x43, 0x47, // Magic
		0x80, 0x18, // Type (quote)
		0x00, 0x00, // QualifiedSigner size = 0
		0x00, 0x00, // ExtraData size = 0
		// ClockInfo (17 bytes)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x01,
		// FirmwareVersion (8 bytes)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		// Truncated QuoteInfo - missing count
	}

	_, err := ExtractPCRsFromCertInfo(data)
	require.Error(t, err)
}

func TestExtractPCRsFromCertInfo_MultiplePCRsSelected(t *testing.T) {
	// Build valid TPMS_ATTEST with multiple PCRs selected in bitmap
	var buf []byte

	buf = append(buf, 0xFF, 0x54, 0x43, 0x47) // Magic
	buf = append(buf, 0x80, 0x18)             // Type: QUOTE
	buf = append(buf, 0x00, 0x00)             // QualifiedSigner (empty)
	buf = append(buf, 0x00, 0x00)             // ExtraData (empty)

	// ClockInfo
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	buf = append(buf, 0x01)

	// FirmwareVersion
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)

	// TPML_PCR_SELECTION
	buf = append(buf, 0x00, 0x00, 0x00, 0x01) // count = 1

	// TPMS_PCR_SELECTION with PCRs 0, 1, 7, 14 selected
	// Byte 0: bits 0,1,7 = 0x83
	// Byte 1: bit 6 (PCR 14) = 0x40
	buf = append(buf, 0x00, 0x0B) // hash = SHA256
	buf = append(buf, 0x03)       // sizeOfSelect = 3
	buf = append(buf, 0x83, 0x40, 0x00)

	// pcrDigest
	buf = append(buf, 0x00, 0x20)
	buf = append(buf, make([]byte, 32)...)

	pcrs, err := ExtractPCRsFromCertInfo(buf)
	assert.NoError(t, err)
	assert.NotNil(t, pcrs)

	// Should have PCRs 0, 1, 7, 14 in the map
	_, hasPCR0 := pcrs[0]
	_, hasPCR1 := pcrs[1]
	_, hasPCR7 := pcrs[7]
	_, hasPCR14 := pcrs[14]

	assert.True(t, hasPCR0, "PCR 0 should be selected")
	assert.True(t, hasPCR1, "PCR 1 should be selected")
	assert.True(t, hasPCR7, "PCR 7 should be selected")
	assert.True(t, hasPCR14, "PCR 14 should be selected")
}

// buildValidTPMSAttest creates a minimal valid TPMS_ATTEST structure for testing
func buildValidTPMSAttest() []byte {
	// Build a sequential TPMS_ATTEST structure as per TPM 2.0 spec
	var buf []byte

	// Magic (4 bytes, big-endian): TPM_GENERATED_VALUE = 0xFF544347
	buf = append(buf, 0xFF, 0x54, 0x43, 0x47)

	// Type (2 bytes): TPM_ST_ATTEST_QUOTE = 0x8018
	buf = append(buf, 0x80, 0x18)

	// QualifiedSigner (TPM2B_NAME: 2-byte size + data)
	buf = append(buf, 0x00, 0x02) // size = 2
	buf = append(buf, 0xAA, 0xBB) // data

	// ExtraData (TPM2B_DATA: 2-byte size + data)
	buf = append(buf, 0x00, 0x04)             // size = 4
	buf = append(buf, 0x01, 0x02, 0x03, 0x04) // data

	// ClockInfo (TPMS_CLOCK_INFO = 17 bytes)
	// clock (8 bytes)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
	// resetCount (4 bytes)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	// restartCount (4 bytes)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	// safe (1 byte)
	buf = append(buf, 0x01)

	// FirmwareVersion (8 bytes)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)

	// TPMS_QUOTE_INFO (attested data for TPM_ST_ATTEST_QUOTE)
	// pcrSelect (TPML_PCR_SELECTION)
	// count (4 bytes)
	buf = append(buf, 0x00, 0x00, 0x00, 0x01) // 1 selection

	// TPMS_PCR_SELECTION
	// hash (2 bytes): TPM_ALG_SHA256 = 0x000B
	buf = append(buf, 0x00, 0x0B)
	// sizeOfSelect (1 byte)
	buf = append(buf, 0x03)
	// pcrSelect (3 bytes bitmap)
	buf = append(buf, 0xFF, 0x00, 0x00) // PCRs 0-7 selected

	// pcrDigest (TPM2B_DIGEST: 2-byte size + digest)
	buf = append(buf, 0x00, 0x20) // size = 32 (SHA256)
	// Digest data (32 zero bytes)
	digest := make([]byte, 32)
	buf = append(buf, digest...)

	return buf
}

// buildTPMSAttestWithExtraData builds a TPMS_ATTEST with specific extra data
func buildTPMSAttestWithExtraData(extraData []byte) []byte {
	var buf []byte

	// Magic (4 bytes): TPM_GENERATED_VALUE = 0xFF544347
	buf = append(buf, 0xFF, 0x54, 0x43, 0x47)

	// Type (2 bytes): TPM_ST_ATTEST_QUOTE = 0x8018
	buf = append(buf, 0x80, 0x18)

	// QualifiedSigner (TPM2B_NAME: 2-byte size + data)
	buf = append(buf, 0x00, 0x02) // size = 2
	buf = append(buf, 0xAA, 0xBB) // data

	// ExtraData (TPM2B_DATA: 2-byte size + data)
	extraDataLen := uint16(len(extraData))
	buf = append(buf, byte(extraDataLen>>8), byte(extraDataLen&0xFF))
	buf = append(buf, extraData...)

	// ClockInfo (TPMS_CLOCK_INFO = 17 bytes)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01) // clock
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)                         // resetCount
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)                         // restartCount
	buf = append(buf, 0x01)                                           // safe

	// FirmwareVersion (8 bytes)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)

	// TPMS_QUOTE_INFO
	buf = append(buf, 0x00, 0x00, 0x00, 0x01) // count = 1
	buf = append(buf, 0x00, 0x0B)             // hash = TPM_ALG_SHA256
	buf = append(buf, 0x03)                   // sizeOfSelect = 3
	buf = append(buf, 0xFF, 0x00, 0x00)       // pcrSelect
	buf = append(buf, 0x00, 0x20)             // digest size = 32
	digest := make([]byte, 32)
	buf = append(buf, digest...)

	return buf
}

// Tests for SetupWithPCRs

func TestSetupWithPCRs_RSA_Success(t *testing.T) {
	keyAuth := "test-keyauth"
	pcrs := []uint{0, 1, 2, 7, 14}

	akAttrs := &mockKeyAttributes{
		keyAlgorithm: x509.RSA,
		tpmAttributes: &mockTPMAttributes{
			publicKeyBytes: []byte("rsa-public-key"),
			bPublic: &mockTPM2BPublic{
				bytes: []byte("rsa-pub-area"),
			},
		},
	}

	tpm := &mockTPM{
		quoteResult: &mockQuote{
			signature: []byte("rsa-signature"),
			quoted:    []byte("rsa-quoted"),
		},
	}

	payload, err := SetupWithPCRs(keyAuth, akAttrs, FormatTPM, tpm, pcrs)
	if err != nil {
		t.Fatalf("SetupWithPCRs() failed: %v", err)
	}

	if payload == nil {
		t.Fatal("SetupWithPCRs() should return payload")
	}

	// Verify TPM was called with correct PCRs
	if !tpm.quoteCalled {
		t.Error("SetupWithPCRs() should call TPM Quote")
	}

	if len(tpm.quotePCRs) != len(pcrs) {
		t.Errorf("Expected %d PCRs, got %d", len(pcrs), len(tpm.quotePCRs))
	}

	for i, pcr := range pcrs {
		if tpm.quotePCRs[i] != pcr {
			t.Errorf("PCR mismatch at index %d: expected %d, got %d", i, pcr, tpm.quotePCRs[i])
		}
	}

	// Verify payload structure
	var req AttestationRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}

	var obj AttestationObject
	if err := cbor.Unmarshal(req.AttStmt, &obj); err != nil {
		t.Fatalf("Failed to unmarshal CBOR: %v", err)
	}

	if obj.Format != "tpm" {
		t.Errorf("Expected format 'tpm', got %q", obj.Format)
	}

	if obj.AttStatement.Alg != -257 {
		t.Errorf("Expected algorithm -257 (RS256), got %d", obj.AttStatement.Alg)
	}
}

func TestSetupWithPCRs_ECDSA_Success(t *testing.T) {
	akAttrs := &mockKeyAttributes{
		keyAlgorithm: x509.ECDSA,
		tpmAttributes: &mockTPMAttributes{
			publicKeyBytes: []byte("ecdsa-public-key"),
			bPublic: &mockTPM2BPublic{
				bytes: []byte("ecdsa-pub-area"),
			},
		},
	}

	tpm := &mockTPM{
		quoteResult: &mockQuote{
			signature: []byte("ecdsa-signature"),
			quoted:    []byte("ecdsa-quoted"),
		},
	}

	payload, err := SetupWithPCRs("keyauth", akAttrs, FormatTPM, tpm, []uint{7})
	if err != nil {
		t.Fatalf("SetupWithPCRs() failed for ECDSA: %v", err)
	}

	var req AttestationRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}

	var obj AttestationObject
	if err := cbor.Unmarshal(req.AttStmt, &obj); err != nil {
		t.Fatalf("Failed to unmarshal CBOR: %v", err)
	}

	if obj.AttStatement.Alg != -7 {
		t.Errorf("Expected algorithm -7 (ES256), got %d", obj.AttStatement.Alg)
	}
}

func TestSetupWithPCRs_Ed25519_Success(t *testing.T) {
	akAttrs := &mockKeyAttributes{
		keyAlgorithm: x509.Ed25519,
		tpmAttributes: &mockTPMAttributes{
			publicKeyBytes: []byte("ed25519-public-key"),
			bPublic: &mockTPM2BPublic{
				bytes: []byte("ed25519-pub-area"),
			},
		},
	}

	tpm := &mockTPM{
		quoteResult: &mockQuote{
			signature: []byte("ed25519-signature"),
			quoted:    []byte("ed25519-quoted"),
		},
	}

	payload, err := SetupWithPCRs("keyauth", akAttrs, FormatTPM, tpm, []uint{14})
	if err != nil {
		t.Fatalf("SetupWithPCRs() failed for Ed25519: %v", err)
	}

	var req AttestationRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}

	var obj AttestationObject
	if err := cbor.Unmarshal(req.AttStmt, &obj); err != nil {
		t.Fatalf("Failed to unmarshal CBOR: %v", err)
	}

	if obj.AttStatement.Alg != -8 {
		t.Errorf("Expected algorithm -8 (EdDSA), got %d", obj.AttStatement.Alg)
	}
}

func TestSetupWithPCRs_InvalidKeyAlgorithm(t *testing.T) {
	akAttrs := &mockKeyAttributes{
		keyAlgorithm: x509.DSA,
		tpmAttributes: &mockTPMAttributes{
			publicKeyBytes: []byte("dsa-public-key"),
			bPublic: &mockTPM2BPublic{
				bytes: []byte("dsa-pub-area"),
			},
		},
	}

	tpm := &mockTPM{
		quoteResult: &mockQuote{
			signature: []byte("dsa-signature"),
			quoted:    []byte("dsa-quoted"),
		},
	}

	_, err := SetupWithPCRs("keyauth", akAttrs, FormatTPM, tpm, []uint{14})
	if err != ErrInvalidKeyAlgorithm {
		t.Errorf("Expected ErrInvalidKeyAlgorithm, got: %v", err)
	}
}

func TestSetupWithPCRs_InvalidAttestationFormat(t *testing.T) {
	akAttrs := &mockKeyAttributes{
		keyAlgorithm: x509.RSA,
		tpmAttributes: &mockTPMAttributes{
			publicKeyBytes: []byte("rsa-public-key"),
			bPublic: &mockTPM2BPublic{
				bytes: []byte("rsa-pub-area"),
			},
		},
	}

	tpm := &mockTPM{
		quoteResult: &mockQuote{
			signature: []byte("rsa-signature"),
			quoted:    []byte("rsa-quoted"),
		},
	}

	_, err := SetupWithPCRs("keyauth", akAttrs, AttestationFormat("invalid"), tpm, []uint{14})
	if err != ErrInvalidAttestationFormat {
		t.Errorf("Expected ErrInvalidAttestationFormat, got: %v", err)
	}
}

func TestSetupWithPCRs_QuoteError(t *testing.T) {
	akAttrs := &mockKeyAttributes{
		keyAlgorithm: x509.RSA,
		tpmAttributes: &mockTPMAttributes{
			publicKeyBytes: []byte("rsa-public-key"),
			bPublic: &mockTPM2BPublic{
				bytes: []byte("rsa-pub-area"),
			},
		},
	}

	expectedErr := errors.New("TPM quote failed")
	tpm := &mockTPM{
		quoteError: expectedErr,
	}

	_, err := SetupWithPCRs("keyauth", akAttrs, FormatTPM, tpm, []uint{14})
	if err == nil {
		t.Error("SetupWithPCRs() should fail when TPM Quote fails")
	}
	if !strings.Contains(err.Error(), "quote failed") {
		t.Errorf("Expected quote error message, got: %v", err)
	}
}

func TestSetupWithPCRs_EmptyPCRs(t *testing.T) {
	akAttrs := &mockKeyAttributes{
		keyAlgorithm: x509.RSA,
		tpmAttributes: &mockTPMAttributes{
			publicKeyBytes: []byte("rsa-public-key"),
			bPublic: &mockTPM2BPublic{
				bytes: []byte("rsa-pub-area"),
			},
		},
	}

	tpm := &mockTPM{
		quoteResult: &mockQuote{
			signature: []byte("rsa-signature"),
			quoted:    []byte("rsa-quoted"),
		},
	}

	payload, err := SetupWithPCRs("keyauth", akAttrs, FormatTPM, tpm, []uint{})
	if err != nil {
		t.Fatalf("SetupWithPCRs() should succeed with empty PCRs: %v", err)
	}

	if len(tpm.quotePCRs) != 0 {
		t.Errorf("Expected 0 PCRs, got %d", len(tpm.quotePCRs))
	}

	if payload == nil {
		t.Error("SetupWithPCRs() should return payload")
	}
}

// Tests for EncodeAttestationForSubmission

func TestEncodeAttestationForSubmission_Success(t *testing.T) {
	obj := &AttestationObject{
		Format: "tpm",
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      -257,
			X5c:      []interface{}{[]byte("cert-bytes")},
			Sig:      []byte("signature"),
			CertInfo: []byte("cert-info"),
			PubArea:  []byte("pub-area"),
		},
	}

	encoded, err := EncodeAttestationForSubmission(obj)
	if err != nil {
		t.Fatalf("EncodeAttestationForSubmission() failed: %v", err)
	}

	if encoded == "" {
		t.Error("EncodeAttestationForSubmission() should return non-empty string")
	}

	// Verify it's valid base64 URL encoding
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("EncodeAttestationForSubmission() should produce valid base64URL: %v", err)
	}

	// Verify it decodes back to the same object
	var decodedObj AttestationObject
	if err := cbor.Unmarshal(decoded, &decodedObj); err != nil {
		t.Fatalf("Decoded data should be valid CBOR: %v", err)
	}

	if decodedObj.Format != obj.Format {
		t.Errorf("Format mismatch: expected %q, got %q", obj.Format, decodedObj.Format)
	}

	if decodedObj.AttStatement.Ver != obj.AttStatement.Ver {
		t.Errorf("Version mismatch: expected %q, got %q", obj.AttStatement.Ver, decodedObj.AttStatement.Ver)
	}

	if decodedObj.AttStatement.Alg != obj.AttStatement.Alg {
		t.Errorf("Algorithm mismatch: expected %d, got %d", obj.AttStatement.Alg, decodedObj.AttStatement.Alg)
	}
}

func TestEncodeAttestationForSubmission_EmptyObject(t *testing.T) {
	obj := &AttestationObject{}

	encoded, err := EncodeAttestationForSubmission(obj)
	if err != nil {
		t.Fatalf("EncodeAttestationForSubmission() should handle empty object: %v", err)
	}

	if encoded == "" {
		t.Error("EncodeAttestationForSubmission() should return non-empty string")
	}

	// Verify it decodes
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("Should produce valid base64URL: %v", err)
	}

	var decodedObj AttestationObject
	if err := cbor.Unmarshal(decoded, &decodedObj); err != nil {
		t.Fatalf("Decoded data should be valid CBOR: %v", err)
	}
}

func TestEncodeAttestationForSubmission_WithStatement(t *testing.T) {
	obj := &AttestationObject{
		Format: "tpm",
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      -257,
			Sig:      []byte("test-signature"),
			CertInfo: []byte("test-certinfo"),
		},
	}

	encoded, err := EncodeAttestationForSubmission(obj)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)

	// Verify roundtrip
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err)

	var decodedObj AttestationObject
	err = cbor.Unmarshal(decoded, &decodedObj)
	require.NoError(t, err)
	assert.Equal(t, obj.Format, decodedObj.Format)
	assert.Equal(t, obj.AttStatement.Alg, decodedObj.AttStatement.Alg)
}

func TestEncodeAttestationForSubmission_LargeObject(t *testing.T) {
	// Create a large attestation object
	largeCertChain := make([]interface{}, 10)
	for i := 0; i < 10; i++ {
		largeCertChain[i] = make([]byte, 1024) // 1KB per cert
	}

	obj := &AttestationObject{
		Format: "tpm",
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      -257,
			X5c:      largeCertChain,
			Sig:      make([]byte, 256),
			CertInfo: make([]byte, 512),
			PubArea:  make([]byte, 256),
		},
	}

	encoded, err := EncodeAttestationForSubmission(obj)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)

	// Verify roundtrip
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err)

	var decodedObj AttestationObject
	err = cbor.Unmarshal(decoded, &decodedObj)
	require.NoError(t, err)
	assert.Equal(t, obj.Format, decodedObj.Format)
}

func TestEncodeAttestationForSubmission_MinimalObject(t *testing.T) {
	obj := &AttestationObject{
		Format: "tpm",
	}

	encoded, err := EncodeAttestationForSubmission(obj)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)

	// Verify it's valid base64url
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err)
	assert.NotEmpty(t, decoded)
}

func TestEncodeAttestationForSubmission_AllAlgorithms(t *testing.T) {
	algorithms := []int64{
		-257, // RS256
		-7,   // ES256
		-8,   // EdDSA
	}

	for _, alg := range algorithms {
		t.Run(algorithmName(alg), func(t *testing.T) {
			obj := &AttestationObject{
				Format: "tpm",
				AttStatement: AttestationStatement{
					Ver:      "2.0",
					Alg:      alg,
					Sig:      []byte("test-signature"),
					CertInfo: []byte("test-certinfo"),
				},
			}

			encoded, err := EncodeAttestationForSubmission(obj)
			require.NoError(t, err)
			assert.NotEmpty(t, encoded)

			// Verify roundtrip preserves algorithm
			decoded, err := base64.RawURLEncoding.DecodeString(encoded)
			require.NoError(t, err)

			var decodedObj AttestationObject
			err = cbor.Unmarshal(decoded, &decodedObj)
			require.NoError(t, err)
			assert.Equal(t, alg, decodedObj.AttStatement.Alg)
		})
	}
}

// algorithmName returns a human-readable name for a COSE algorithm
func algorithmName(alg int64) string {
	switch alg {
	case -257:
		return "RS256"
	case -7:
		return "ES256"
	case -8:
		return "EdDSA"
	default:
		return "Unknown"
	}
}

func TestEncodeAttestationForSubmission_SpecialCharacters(t *testing.T) {
	obj := &AttestationObject{
		Format: "tpm",
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      -257,
			Sig:      []byte{0x00, 0xFF, 0xFE, 0x01, 0x02}, // Binary data
			CertInfo: []byte("cert-info-with-\x00-null"),
			PubArea:  []byte{0xDE, 0xAD, 0xBE, 0xEF},
		},
	}

	encoded, err := EncodeAttestationForSubmission(obj)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)

	// Verify roundtrip preserves binary data
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err)

	var decodedObj AttestationObject
	err = cbor.Unmarshal(decoded, &decodedObj)
	require.NoError(t, err)
	assert.Equal(t, obj.AttStatement.Sig, decodedObj.AttStatement.Sig)
}

func TestEncodeAttestationForSubmission_NilValues(t *testing.T) {
	obj := &AttestationObject{
		Format: "tpm",
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      -257,
			X5c:      nil,
			Sig:      nil,
			CertInfo: nil,
			PubArea:  nil,
		},
	}

	encoded, err := EncodeAttestationForSubmission(obj)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)
}

func TestEncodeAttestationForSubmission_EmptyX5c(t *testing.T) {
	obj := &AttestationObject{
		Format: "tpm",
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      -257,
			X5c:      []interface{}{},
			Sig:      []byte("signature"),
			CertInfo: []byte("certinfo"),
			PubArea:  []byte("pubarea"),
		},
	}

	encoded, err := EncodeAttestationForSubmission(obj)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)

	// Verify roundtrip
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err)

	var decodedObj AttestationObject
	err = cbor.Unmarshal(decoded, &decodedObj)
	require.NoError(t, err)
	assert.Equal(t, 0, len(decodedObj.AttStatement.X5c))
}

func TestEncodeAttestationForSubmission_Deterministic(t *testing.T) {
	obj := &AttestationObject{
		Format: "tpm",
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      -257,
			X5c:      []interface{}{[]byte("cert")},
			Sig:      []byte("signature"),
			CertInfo: []byte("certinfo"),
			PubArea:  []byte("pubarea"),
		},
	}

	// Encode multiple times
	encoded1, err1 := EncodeAttestationForSubmission(obj)
	require.NoError(t, err1)

	encoded2, err2 := EncodeAttestationForSubmission(obj)
	require.NoError(t, err2)

	encoded3, err3 := EncodeAttestationForSubmission(obj)
	require.NoError(t, err3)

	// All encodings should be identical
	assert.Equal(t, encoded1, encoded2)
	assert.Equal(t, encoded2, encoded3)
}

func TestEncodeAttestationForSubmission_LargePayload(t *testing.T) {
	// Create attestation object with large payload
	largeCert := make([]byte, 4096)
	for i := range largeCert {
		largeCert[i] = byte(i % 256)
	}

	obj := &AttestationObject{
		Format: "tpm",
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      -257,
			X5c:      []interface{}{largeCert},
			Sig:      make([]byte, 512),
			CertInfo: make([]byte, 1024),
			PubArea:  make([]byte, 256),
		},
	}

	encoded, err := EncodeAttestationForSubmission(obj)
	assert.NoError(t, err)
	assert.NotEmpty(t, encoded)

	// Verify the encoded string is valid base64url
	assert.NotContains(t, encoded, "+")
	assert.NotContains(t, encoded, "/")
	assert.NotContains(t, encoded, "=")
}

func TestEncodeAttestationForSubmission_CBORMarshalError(t *testing.T) {
	// cbor.Marshal returns an error when it encounters unsupported types like
	// channels or functions. The X5c field is []interface{} which can contain
	// any type, including unsupported ones.
	t.Run("unsupported_type_channel_in_x5c", func(t *testing.T) {
		obj := &AttestationObject{
			Format: FormatTPM.String(),
			AttStatement: AttestationStatement{
				Ver: "2.0",
				Alg: int64(-257),
				// Put a channel in X5c - cbor cannot marshal channels
				X5c: []interface{}{make(chan int)},
			},
		}

		encoded, err := EncodeAttestationForSubmission(obj)
		require.Error(t, err)
		assert.Empty(t, encoded)
		assert.Contains(t, err.Error(), "unsupported type")
	})

	t.Run("unsupported_type_function_in_x5c", func(t *testing.T) {
		obj := &AttestationObject{
			Format: FormatTPM.String(),
			AttStatement: AttestationStatement{
				Ver: "2.0",
				Alg: int64(-257),
				// Put a function in X5c - cbor cannot marshal functions
				X5c: []interface{}{func() {}},
			},
		}

		encoded, err := EncodeAttestationForSubmission(obj)
		require.Error(t, err)
		assert.Empty(t, encoded)
		assert.Contains(t, err.Error(), "unsupported type")
	})

	t.Run("mixed_valid_and_invalid_types_in_x5c", func(t *testing.T) {
		obj := &AttestationObject{
			Format: FormatTPM.String(),
			AttStatement: AttestationStatement{
				Ver: "2.0",
				Alg: int64(-257),
				// Mix of valid bytes and invalid channel
				X5c: []interface{}{
					[]byte("valid-cert"),
					make(chan struct{}),
				},
			},
		}

		encoded, err := EncodeAttestationForSubmission(obj)
		require.Error(t, err)
		assert.Empty(t, encoded)
	})

	t.Run("nested_unsupported_type", func(t *testing.T) {
		// Create a nested structure with an unsupported type
		type nestedWithFunc struct {
			F func()
		}

		obj := &AttestationObject{
			Format: FormatTPM.String(),
			AttStatement: AttestationStatement{
				Ver: "2.0",
				Alg: int64(-257),
				X5c: []interface{}{nestedWithFunc{F: func() {}}},
			},
		}

		encoded, err := EncodeAttestationForSubmission(obj)
		require.Error(t, err)
		assert.Empty(t, encoded)
	})
}

// Tests for ParseTPMSAttest

func TestParseTPMSAttest_Success(t *testing.T) {
	// Build a valid TPMS_ATTEST structure
	data := buildValidTPMSAttest()

	attest, err := ParseTPMSAttest(data)
	require.NoError(t, err)
	assert.NotNil(t, attest)
	assert.Equal(t, uint32(0xFF544347), attest.Magic)
}

func TestParseTPMSAttest_DataTooShort(t *testing.T) {
	// Less than 10 bytes
	data := []byte{0x01, 0x02, 0x03}

	_, err := ParseTPMSAttest(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "data too short")
}

func TestParseTPMSAttest_InvalidMagic(t *testing.T) {
	// Build data with wrong magic
	data := []byte{
		0x00, 0x00, 0x00, 0x00, // Invalid magic
		0x00, 0x00, // Type
		0x00, 0x00, 0x00, 0x00, // Some padding
	}

	_, err := ParseTPMSAttest(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid TPM magic")
}

func TestParseTPMSAttest_TooShortForQualifiedSignerSize(t *testing.T) {
	// Test with exactly 10 bytes - passes initial check, but at offset 6
	// signerSize check needs offset+2=8 <= len(10), so it passes
	// Then we read signerSize and check offset+signerSize > len
	data := []byte{
		0xFF, 0x54, 0x43, 0x47, // Magic (4 bytes)
		0x00, 0x18, // Type (2 bytes)
		0x00, 0x10, // QualifiedSigner size = 16 bytes (2 bytes)
		0x00, 0x00, // Only 2 bytes of padding
	}

	_, err := ParseTPMSAttest(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "qualifiedSigner")
}

func TestParseTPMSAttest_TooShortForQualifiedSignerData(t *testing.T) {
	// Build data with valid magic but truncated qualifiedSigner data
	data := []byte{
		0xFF, 0x54, 0x43, 0x47, // Magic (4 bytes)
		0x00, 0x18, // Type (2 bytes)
		0x00, 0x20, // QualifiedSigner size = 32 bytes (2 bytes)
		0x00, 0x00, // Only 2 bytes of data instead of 32
	}

	_, err := ParseTPMSAttest(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "qualifiedSigner")
}

func TestParseTPMSAttest_TooShortForExtraDataSize(t *testing.T) {
	// Build data with valid magic and qualifiedSigner but truncated at extraData
	data := []byte{
		0xFF, 0x54, 0x43, 0x47, // Magic (4 bytes)
		0x00, 0x18, // Type (2 bytes)
		0x00, 0x02, // QualifiedSigner size = 2 (2 bytes)
		0xAB, 0xCD, // QualifiedSigner data (2 bytes)
		// Total = 10 bytes, at offset 10, need 2 more for extraData size
	}

	_, err := ParseTPMSAttest(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "extraData")
}

func TestParseTPMSAttest_TooShortForExtraData(t *testing.T) {
	data := []byte{
		0xFF, 0x54, 0x43, 0x47, // Magic
		0x00, 0x18, // Type
		0x00, 0x02, // QualifiedSigner size = 2
		0xAB, 0xCD, // QualifiedSigner data
		0x00, 0x10, // ExtraData size = 16
		// No extraData follows
	}

	_, err := ParseTPMSAttest(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "extraData")
}

func TestParseTPMSAttest_TooShortForClockInfo(t *testing.T) {
	data := []byte{
		0xFF, 0x54, 0x43, 0x47, // Magic
		0x00, 0x18, // Type
		0x00, 0x02, // QualifiedSigner size = 2
		0xAB, 0xCD, // QualifiedSigner data
		0x00, 0x02, // ExtraData size = 2
		0xEF, 0x12, // ExtraData
		// Missing ClockInfo (17 bytes)
	}

	_, err := ParseTPMSAttest(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "clockInfo")
}

func TestParseTPMSAttest_TooShortForFirmwareVersion(t *testing.T) {
	// Build minimal valid up to clockInfo, then truncate
	data := []byte{
		0xFF, 0x54, 0x43, 0x47, // Magic
		0x00, 0x18, // Type
		0x00, 0x00, // QualifiedSigner size = 0
		0x00, 0x00, // ExtraData size = 0
		// ClockInfo (17 bytes)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Clock
		0x00, 0x00, 0x00, 0x00, // ResetCount
		0x00, 0x00, 0x00, 0x00, // RestartCount
		0x01, // Safe
		// Missing FirmwareVersion (8 bytes)
	}

	_, err := ParseTPMSAttest(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "firmwareVersion")
}

func TestParseTPMSAttest_ValidQuoteInfo(t *testing.T) {
	// Build a valid TPMS_ATTEST with quote info
	data := buildValidTPMSAttest()

	attest, err := ParseTPMSAttest(data)
	require.NoError(t, err)
	assert.NotNil(t, attest)

	// Verify magic
	assert.Equal(t, uint32(0xFF544347), attest.Magic)

	// Verify type is quote
	assert.Equal(t, uint16(0x8018), attest.Type)

	// Verify attested info exists (quote info)
	assert.NotNil(t, attest.Attested)
}

func TestParseTPMSAttest_ExtractExtraData(t *testing.T) {
	// Build TPMS_ATTEST with specific extra data
	data := buildTPMSAttestWithExtraData([]byte("test-qualifying-data"))

	attest, err := ParseTPMSAttest(data)
	require.NoError(t, err)
	assert.NotNil(t, attest)
	assert.Equal(t, []byte("test-qualifying-data"), attest.ExtraData)
}

func TestParseTPMSAttest_NonQuoteType(t *testing.T) {
	// Build TPMS_ATTEST with a different type (not TPM_ST_ATTEST_QUOTE)
	var buf []byte

	// Magic
	buf = append(buf, 0xFF, 0x54, 0x43, 0x47)

	// Type: TPM_ST_ATTEST_CERTIFY = 0x8017 (different from QUOTE)
	buf = append(buf, 0x80, 0x17)

	// QualifiedSigner
	buf = append(buf, 0x00, 0x02)
	buf = append(buf, 0xAA, 0xBB)

	// ExtraData
	buf = append(buf, 0x00, 0x04)
	buf = append(buf, 0x01, 0x02, 0x03, 0x04)

	// ClockInfo
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	buf = append(buf, 0x01)

	// FirmwareVersion
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)

	// For non-quote types, TPMS_QUOTE_INFO parsing is skipped
	attest, err := ParseTPMSAttest(buf)
	assert.NoError(t, err)
	assert.NotNil(t, attest)
	assert.Equal(t, uint16(0x8017), attest.Type)

	// Quote-specific fields should be empty
	assert.Empty(t, attest.Attested.PCRSelect)
	assert.Empty(t, attest.Attested.PCRDigest)
}

func TestParseTPMSAttest_QuoteWithMultiplePCRSelections(t *testing.T) {
	var buf []byte

	// Magic
	buf = append(buf, 0xFF, 0x54, 0x43, 0x47)

	// Type: TPM_ST_ATTEST_QUOTE
	buf = append(buf, 0x80, 0x18)

	// QualifiedSigner
	buf = append(buf, 0x00, 0x02)
	buf = append(buf, 0xAA, 0xBB)

	// ExtraData
	buf = append(buf, 0x00, 0x04)
	buf = append(buf, 0x01, 0x02, 0x03, 0x04)

	// ClockInfo
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	buf = append(buf, 0x01)

	// FirmwareVersion
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)

	// TPML_PCR_SELECTION with count = 2
	buf = append(buf, 0x00, 0x00, 0x00, 0x02)

	// First TPMS_PCR_SELECTION (SHA256)
	buf = append(buf, 0x00, 0x0B) // hash = SHA256
	buf = append(buf, 0x03)       // sizeOfSelect = 3
	buf = append(buf, 0xFF, 0x00, 0x00)

	// Second TPMS_PCR_SELECTION (SHA384)
	buf = append(buf, 0x00, 0x0C) // hash = SHA384
	buf = append(buf, 0x03)       // sizeOfSelect = 3
	buf = append(buf, 0x00, 0xFF, 0x00)

	// pcrDigest
	buf = append(buf, 0x00, 0x30) // size = 48 (SHA384)
	buf = append(buf, make([]byte, 48)...)

	attest, err := ParseTPMSAttest(buf)
	assert.NoError(t, err)
	assert.NotNil(t, attest)
	assert.Len(t, attest.Attested.PCRSelect, 2)
	assert.Equal(t, uint16(0x000B), attest.Attested.PCRSelect[0].Hash)
	assert.Equal(t, uint16(0x000C), attest.Attested.PCRSelect[1].Hash)
}

func TestParseTPMSAttest_TooShortForPCRSelectionCount(t *testing.T) {
	var buf []byte

	// Magic
	buf = append(buf, 0xFF, 0x54, 0x43, 0x47)

	// Type: TPM_ST_ATTEST_QUOTE
	buf = append(buf, 0x80, 0x18)

	// QualifiedSigner (empty)
	buf = append(buf, 0x00, 0x00)

	// ExtraData (empty)
	buf = append(buf, 0x00, 0x00)

	// ClockInfo
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	buf = append(buf, 0x01)

	// FirmwareVersion
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)

	// Missing TPML_PCR_SELECTION count (truncated here)

	_, err := ParseTPMSAttest(buf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "PCR selection count")
}

func TestParseTPMSAttest_TooShortForPCRSelection(t *testing.T) {
	var buf []byte

	// Magic
	buf = append(buf, 0xFF, 0x54, 0x43, 0x47)

	// Type: TPM_ST_ATTEST_QUOTE
	buf = append(buf, 0x80, 0x18)

	// QualifiedSigner (empty)
	buf = append(buf, 0x00, 0x00)

	// ExtraData (empty)
	buf = append(buf, 0x00, 0x00)

	// ClockInfo
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	buf = append(buf, 0x01)

	// FirmwareVersion
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)

	// TPML_PCR_SELECTION with count = 1
	buf = append(buf, 0x00, 0x00, 0x00, 0x01)

	// Incomplete TPMS_PCR_SELECTION (only 2 bytes instead of 3+)
	buf = append(buf, 0x00, 0x0B) // hash only, missing sizeOfSelect

	_, err := ParseTPMSAttest(buf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "PCR selection")
}

func TestParseTPMSAttest_TooShortForPCRBitmap(t *testing.T) {
	var buf []byte

	// Magic
	buf = append(buf, 0xFF, 0x54, 0x43, 0x47)

	// Type: TPM_ST_ATTEST_QUOTE
	buf = append(buf, 0x80, 0x18)

	// QualifiedSigner (empty)
	buf = append(buf, 0x00, 0x00)

	// ExtraData (empty)
	buf = append(buf, 0x00, 0x00)

	// ClockInfo
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	buf = append(buf, 0x01)

	// FirmwareVersion
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)

	// TPML_PCR_SELECTION with count = 1
	buf = append(buf, 0x00, 0x00, 0x00, 0x01)

	// TPMS_PCR_SELECTION header
	buf = append(buf, 0x00, 0x0B) // hash
	buf = append(buf, 0x10)       // sizeOfSelect = 16 (too large for remaining data)
	buf = append(buf, 0x01, 0x02) // Only 2 bytes of bitmap

	_, err := ParseTPMSAttest(buf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "PCR bitmap")
}

func TestParseTPMSAttest_TooShortForPCRDigestSize(t *testing.T) {
	var buf []byte

	// Magic
	buf = append(buf, 0xFF, 0x54, 0x43, 0x47)

	// Type: TPM_ST_ATTEST_QUOTE
	buf = append(buf, 0x80, 0x18)

	// QualifiedSigner (empty)
	buf = append(buf, 0x00, 0x00)

	// ExtraData (empty)
	buf = append(buf, 0x00, 0x00)

	// ClockInfo
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	buf = append(buf, 0x01)

	// FirmwareVersion
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)

	// TPML_PCR_SELECTION with count = 1
	buf = append(buf, 0x00, 0x00, 0x00, 0x01)

	// Complete TPMS_PCR_SELECTION
	buf = append(buf, 0x00, 0x0B) // hash
	buf = append(buf, 0x03)       // sizeOfSelect = 3
	buf = append(buf, 0x01, 0x00, 0x00)

	// Missing pcrDigest size

	_, err := ParseTPMSAttest(buf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "PCR digest size")
}

func TestParseTPMSAttest_TooShortForPCRDigest(t *testing.T) {
	var buf []byte

	// Magic
	buf = append(buf, 0xFF, 0x54, 0x43, 0x47)

	// Type: TPM_ST_ATTEST_QUOTE
	buf = append(buf, 0x80, 0x18)

	// QualifiedSigner (empty)
	buf = append(buf, 0x00, 0x00)

	// ExtraData (empty)
	buf = append(buf, 0x00, 0x00)

	// ClockInfo
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	buf = append(buf, 0x01)

	// FirmwareVersion
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)

	// TPML_PCR_SELECTION with count = 1
	buf = append(buf, 0x00, 0x00, 0x00, 0x01)

	// Complete TPMS_PCR_SELECTION
	buf = append(buf, 0x00, 0x0B) // hash
	buf = append(buf, 0x03)       // sizeOfSelect = 3
	buf = append(buf, 0x01, 0x00, 0x00)

	// pcrDigest size indicates 32 bytes, but only 2 bytes follow
	buf = append(buf, 0x00, 0x20) // size = 32
	buf = append(buf, 0xAB, 0xCD) // Only 2 bytes

	_, err := ParseTPMSAttest(buf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "PCR digest")
}

func TestParseTPMSAttest_EdgeCases(t *testing.T) {
	t.Run("exactly_minimum_size", func(t *testing.T) {
		// Create minimal valid data
		data := make([]byte, 10)
		// Set magic value
		data[0] = 0xff
		data[1] = 0x54
		data[2] = 0x43
		data[3] = 0x47

		_, err := ParseTPMSAttest(data)
		// Should fail due to missing data but magic is valid
		assert.Error(t, err)
	})

	t.Run("invalid_magic", func(t *testing.T) {
		data := make([]byte, 100)
		// Set invalid magic
		data[0] = 0x00
		data[1] = 0x00
		data[2] = 0x00
		data[3] = 0x00

		_, err := ParseTPMSAttest(data)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid TPM magic")
	})

	t.Run("truncated_data", func(t *testing.T) {
		data := make([]byte, 8)
		// Set valid magic
		data[0] = 0xff
		data[1] = 0x54
		data[2] = 0x43
		data[3] = 0x47
		// Set type
		data[4] = 0x00
		data[5] = 0x00

		_, err := ParseTPMSAttest(data)
		assert.Error(t, err)
		// The error could be about data being too short or qualifiedSigner
		assert.True(t, err != nil)
	})
}

func TestParseTPMSAttest_TooShort(t *testing.T) {
	_, err := ExtractPCRsFromCertInfo([]byte{1, 2, 3})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

// Tests for AttestationObject CBOR roundtrip

func TestAttestationObject_CBORRoundtrip(t *testing.T) {
	original := &AttestationObject{
		Format: "tpm",
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      -7,
			X5c:      []interface{}{[]byte("cert1"), []byte("cert2")},
			Sig:      []byte("test-signature"),
			CertInfo: []byte("test-certinfo"),
			PubArea:  []byte("test-pubarea"),
		},
	}

	// Encode
	encoded, err := cbor.Marshal(original)
	require.NoError(t, err)

	// Decode
	var decoded AttestationObject
	err = cbor.Unmarshal(encoded, &decoded)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.Format, decoded.Format)
	assert.Equal(t, original.AttStatement.Ver, decoded.AttStatement.Ver)
	assert.Equal(t, original.AttStatement.Alg, decoded.AttStatement.Alg)
	assert.Equal(t, original.AttStatement.Sig, decoded.AttStatement.Sig)
	assert.Equal(t, original.AttStatement.CertInfo, decoded.AttStatement.CertInfo)
	assert.Equal(t, original.AttStatement.PubArea, decoded.AttStatement.PubArea)
}

// Tests for type validation and error definitions

func TestValidateAttestationFormat_AllFormats(t *testing.T) {
	t.Run("valid_tpm", func(t *testing.T) {
		assert.True(t, ValidateAttestationFormat(FormatTPM))
	})

	t.Run("invalid_unknown", func(t *testing.T) {
		assert.False(t, ValidateAttestationFormat(AttestationFormat("unknown")))
	})

	t.Run("invalid_empty", func(t *testing.T) {
		assert.False(t, ValidateAttestationFormat(AttestationFormat("")))
	})

	t.Run("invalid_packed", func(t *testing.T) {
		assert.False(t, ValidateAttestationFormat(AttestationFormat("packed")))
	})
}

func TestParseAttestationObject_AllPaths(t *testing.T) {
	t.Run("valid_object", func(t *testing.T) {
		obj := &AttestationObject{
			Format: FormatTPM.String(),
			AttStatement: AttestationStatement{
				Ver: "2.0",
				Alg: int64(-257),
			},
		}

		encoded, err := cbor.Marshal(obj)
		require.NoError(t, err)

		parsed, err := ParseAttestationObject(encoded)
		require.NoError(t, err)
		assert.Equal(t, obj.Format, parsed.Format)
	})

	t.Run("invalid_cbor", func(t *testing.T) {
		_, err := ParseAttestationObject([]byte("not-cbor"))
		assert.Error(t, err)
	})

	t.Run("empty_data", func(t *testing.T) {
		_, err := ParseAttestationObject([]byte{})
		assert.Error(t, err)
	})
}

func TestAttestationRequest_Fields(t *testing.T) {
	req := AttestationRequest{
		AttStmt: []byte("attestation-statement"),
	}

	assert.Equal(t, []byte("attestation-statement"), req.AttStmt)
}

func TestTPMSAttest_Struct(t *testing.T) {
	clockInfo := TPMSClockInfo{
		Clock:        12345,
		ResetCount:   1,
		RestartCount: 2,
		Safe:         true,
	}

	assert.Equal(t, uint64(12345), clockInfo.Clock)
	assert.Equal(t, uint32(1), clockInfo.ResetCount)
	assert.Equal(t, uint32(2), clockInfo.RestartCount)
	assert.True(t, clockInfo.Safe)

	quoteInfo := TPMSQuoteInfo{
		PCRSelect: []TPMSPCRSelection{
			{
				Hash:         0x000b,
				SizeOfBitmap: 3,
				PCRBitmap:    []byte{0x01, 0x00, 0x00},
			},
		},
		PCRDigest: []byte("digest"),
	}

	assert.Equal(t, 1, len(quoteInfo.PCRSelect))
	assert.Equal(t, []byte("digest"), quoteInfo.PCRDigest)
}

func TestErrorVariables(t *testing.T) {
	assert.NotNil(t, ErrInvalidKeyAlgorithm)
	assert.NotNil(t, ErrInvalidAttestationFormat)
	assert.NotNil(t, ErrInvalidAttestationObject)
	assert.NotNil(t, ErrTPMAttestationInvalid)
	assert.NotNil(t, ErrAIKCertificateInvalid)
	assert.NotNil(t, ErrPCRMismatch)
	assert.NotNil(t, ErrCertificateChainInvalid)

	assert.Contains(t, ErrInvalidKeyAlgorithm.Error(), "invalid key algorithm")
	assert.Contains(t, ErrInvalidAttestationFormat.Error(), "invalid attestation format")
	assert.Contains(t, ErrInvalidAttestationObject.Error(), "invalid attestation object")
	assert.Contains(t, ErrTPMAttestationInvalid.Error(), "tpm attestation statement invalid")
	assert.Contains(t, ErrAIKCertificateInvalid.Error(), "AIK certificate")
	assert.Contains(t, ErrPCRMismatch.Error(), "PCR values do not match")
	assert.Contains(t, ErrCertificateChainInvalid.Error(), "certificate chain invalid")
}

func TestAttestationStatement_EmptyFields(t *testing.T) {
	stmt := AttestationStatement{}

	assert.Equal(t, "", stmt.Ver)
	assert.Equal(t, int64(0), stmt.Alg)
	assert.Nil(t, stmt.X5c)
	assert.Nil(t, stmt.Sig)
	assert.Nil(t, stmt.CertInfo)
	assert.Nil(t, stmt.PubArea)
}

func TestAttestationObject_EmptyFields(t *testing.T) {
	obj := AttestationObject{}

	assert.Equal(t, "", obj.Format)
	assert.Equal(t, "", obj.AttStatement.Ver)
}

// Benchmarks

func BenchmarkSetup(b *testing.B) {
	akAttrs := &mockKeyAttributes{
		keyAlgorithm: x509.RSA,
		tpmAttributes: &mockTPMAttributes{
			publicKeyBytes: []byte("bench-public-key"),
			bPublic: &mockTPM2BPublic{
				bytes: []byte("bench-pub-area"),
			},
		},
	}

	tpm := &mockTPM{
		quoteResult: &mockQuote{
			signature: []byte("bench-signature"),
			quoted:    []byte("bench-quoted"),
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Setup("bench-keyauth", akAttrs, FormatTPM, tpm)
	}
}

func BenchmarkParseAttestationObject(b *testing.B) {
	obj := &AttestationObject{
		Format: "tpm",
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      -257,
			X5c:      []interface{}{[]byte("cert-bytes")},
			Sig:      []byte("signature"),
			CertInfo: []byte("cert-info"),
			PubArea:  []byte("pub-area"),
		},
	}

	data, _ := cbor.Marshal(obj)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseAttestationObject(data)
	}
}
