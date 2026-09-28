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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/validation"
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
	client := loopbackClient()

	// Port 1 on loopback has no listener: the connection is refused.
	err := Verify(client, ca, "127.0.0.1", "1", "token", "keyauth")
	if err == nil {
		t.Fatal("Verify() should fail with network error")
	}

	// Verify it's a network error, not a CA verification error
	var verr *validation.Error
	if !errors.As(err, &verr) || verr.Kind != validation.KindConnection {
		t.Errorf("Expected a KindConnection *validation.Error, got: %v", err)
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
	client := loopbackClient()

	err := Verify(client, ca, host, port, "token", "keyauth")
	if err == nil {
		t.Error("Verify() should fail with non-200 status")
	}

	var status *validation.StatusError
	if !errors.As(err, &status) || status.StatusCode != http.StatusNotFound {
		t.Errorf("Expected a 404 *validation.StatusError, got: %v", err)
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
	client := loopbackClient()

	err := Verify(client, ca, host, port, "token", "keyauth")
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
	client := loopbackClient()

	err := Verify(client, ca, host, port, "token", "keyauth")
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
	client := loopbackClient()

	err := Verify(client, ca, host, port, "token", "keyauth")
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
	client := loopbackClient()

	err := Verify(client, ca, host, port, "token", "keyauth")
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
	client := loopbackClient()

	err := Verify(client, ca, host, port, "token", "keyauth")
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

func TestErrorVariables(t *testing.T) {
	assert.NotNil(t, ErrInvalidKeyAlgorithm)
	assert.NotNil(t, ErrInvalidAttestationFormat)
	assert.NotNil(t, ErrInvalidAttestationObject)
	assert.NotNil(t, ErrTPMAttestationInvalid)
	assert.NotNil(t, ErrAIKCertificateInvalid)
	assert.NotNil(t, ErrCertificateChainInvalid)

	assert.Contains(t, ErrInvalidKeyAlgorithm.Error(), "invalid key algorithm")
	assert.Contains(t, ErrInvalidAttestationFormat.Error(), "invalid attestation format")
	assert.Contains(t, ErrInvalidAttestationObject.Error(), "invalid attestation object")
	assert.Contains(t, ErrTPMAttestationInvalid.Error(), "tpm attestation statement invalid")
	assert.Contains(t, ErrAIKCertificateInvalid.Error(), "AIK certificate")
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
