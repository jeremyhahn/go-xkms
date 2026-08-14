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

package endorse01

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"testing"
)

// Mock implementations for testing

type mockCA struct {
	createCSRResult []byte
	createCSRError  error
	createCSRReq    *CertificateRequest
	createCSRCount  int
	defaultSigAlg   x509.SignatureAlgorithm
}

func (m *mockCA) CreateCSR(req CertificateRequest) ([]byte, error) {
	m.createCSRCount++
	m.createCSRReq = &req
	if m.createCSRError != nil {
		return nil, m.createCSRError
	}
	return m.createCSRResult, nil
}

func (m *mockCA) DefaultSignatureAlgorithm() x509.SignatureAlgorithm {
	return m.defaultSigAlg
}

type mockEKAttributes struct {
	CN string
}

func (m *mockEKAttributes) GetCN() string {
	return m.CN
}

type mockTPM struct {
	ekPubKey   crypto.PublicKey
	ekAttrs    interface{}
	ekAttrsErr error
}

func (m *mockTPM) EK() crypto.PublicKey {
	return m.ekPubKey
}

func (m *mockTPM) EKAttributes() (interface{}, error) {
	if m.ekAttrsErr != nil {
		return nil, m.ekAttrsErr
	}
	return m.ekAttrs, nil
}

type mockSerializer struct {
	serializeResult []byte
	serializeError  error
	serializeInput  interface{}
	serializeCount  int
}

func (m *mockSerializer) Serialize(key interface{}) ([]byte, error) {
	m.serializeCount++
	m.serializeInput = key
	if m.serializeError != nil {
		return nil, m.serializeError
	}
	return m.serializeResult, nil
}

// TestVerify_ReturnsNil tests that Verify always returns nil.
// The endorse-01 challenge doesn't perform HTTP verification because:
// - The TPM doesn't have an EK certificate yet (that's what this challenge issues)
// - Validation is handled via EAB and server policy during CSR processing
func TestVerify_ReturnsNil(t *testing.T) {
	resolver := net.DefaultResolver

	// Verify should always return nil regardless of inputs
	err := Verify(resolver, "127.0.0.1", "8080", "token", "keyauth")
	if err != nil {
		t.Errorf("Verify() should return nil, got: %v", err)
	}
}

func TestVerify_ReturnsNilWithEmptyParams(t *testing.T) {

	// Even with empty parameters, Verify should return nil
	err := Verify(nil, "", "", "", "")
	if err != nil {
		t.Errorf("Verify() should return nil even with empty params, got: %v", err)
	}
}

func TestVerify_ReturnsNilWithNilCA(t *testing.T) {
	// Verify should return nil even with nil CA
	// (though in practice CA should never be nil)
	err := Verify(nil, "domain", "port", "token", "keyauth")
	if err != nil {
		t.Errorf("Verify() should return nil even with nil CA, got: %v", err)
	}
}

func TestSetup_Success(t *testing.T) {
	ekAttrs := &mockEKAttributes{CN: "test-device"}
	ekPubKeyBytes := []byte("serialized-ek-pubkey")
	csrBytes := []byte("test-csr")

	ca := &mockCA{
		createCSRResult: csrBytes,
	}

	tpm := &mockTPM{
		ekPubKey: nil, // nil is valid for mock
		ekAttrs:  ekAttrs,
	}

	serializer := &mockSerializer{
		serializeResult: ekPubKeyBytes,
	}

	csr, err := Setup("test-token", ca, tpm, serializer)
	if err != nil {
		t.Fatalf("Setup() failed: %v", err)
	}

	if csr == nil {
		t.Fatal("Setup() should return CSR bytes")
	}

	if len(csr) != len(csrBytes) {
		t.Errorf("Expected CSR length %d, got %d", len(csrBytes), len(csr))
	}

	// Verify serializer was called
	if serializer.serializeCount != 1 {
		t.Errorf("Expected Serialize to be called once, got %d", serializer.serializeCount)
	}

	// Verify CA CreateCSR was called
	if ca.createCSRCount != 1 {
		t.Errorf("Expected CreateCSR to be called once, got %d", ca.createCSRCount)
	}

	if ca.createCSRReq == nil {
		t.Fatal("CreateCSR should have received a request")
	}

	if ca.createCSRReq.PermanentID != string(ekPubKeyBytes) {
		t.Errorf("Expected PermanentID %q, got %q", string(ekPubKeyBytes), ca.createCSRReq.PermanentID)
	}

	if ca.createCSRReq.Subject.CommonName != "test-device" {
		t.Errorf("Expected CN %q, got %q", "test-device", ca.createCSRReq.Subject.CommonName)
	}
}

func TestSetup_EKAttributesError(t *testing.T) {
	ca := &mockCA{}

	tpm := &mockTPM{
		ekPubKey:   nil,
		ekAttrsErr: errors.New("failed to retrieve EK attributes"),
	}

	serializer := &mockSerializer{
		serializeResult: []byte("serialized"),
	}

	_, err := Setup("test-token", ca, tpm, serializer)
	if err == nil {
		t.Error("Setup() should fail when EK attributes retrieval fails")
	}

	if err.Error() != "failed to retrieve EK attributes" {
		t.Errorf("Expected EK attributes error, got: %v", err)
	}
}

func TestSetup_SerializationError(t *testing.T) {
	ca := &mockCA{}

	tpm := &mockTPM{
		ekPubKey: nil,
		ekAttrs:  &mockEKAttributes{CN: "test"},
	}

	serializer := &mockSerializer{
		serializeError: errors.New("serialization failed"),
	}

	_, err := Setup("test-token", ca, tpm, serializer)
	if err == nil {
		t.Error("Setup() should fail when serialization fails")
	}

	if err.Error() != "serialization failed" {
		t.Errorf("Expected serialization error, got: %v", err)
	}
}

func TestSetup_CreateCSRError(t *testing.T) {
	ca := &mockCA{
		createCSRError: errors.New("CSR creation failed"),
	}

	tpm := &mockTPM{
		ekPubKey: nil,
		ekAttrs:  &mockEKAttributes{CN: "test"},
	}

	serializer := &mockSerializer{
		serializeResult: []byte("serialized"),
	}

	_, err := Setup("test-token", ca, tpm, serializer)
	if err == nil {
		t.Error("Setup() should fail when CSR creation fails")
	}

	if err.Error() != "CSR creation failed" {
		t.Errorf("Expected CSR creation error, got: %v", err)
	}
}

func TestSetup_WithoutCNInterface(t *testing.T) {
	// Test Setup with EK attributes that don't implement GetCN()
	ca := &mockCA{
		createCSRResult: []byte("test-csr"),
	}

	// Use a simple struct without GetCN() method
	simpleAttrs := struct {
		Name string
	}{Name: "test"}

	tpm := &mockTPM{
		ekPubKey: nil,
		ekAttrs:  simpleAttrs,
	}

	serializer := &mockSerializer{
		serializeResult: []byte("serialized"),
	}

	csr, err := Setup("test-token", ca, tpm, serializer)
	if err != nil {
		t.Fatalf("Setup() should succeed even without GetCN() method: %v", err)
	}

	if csr == nil {
		t.Error("Setup() should return CSR")
	}

	// CN should be empty string when GetCN() is not available
	if ca.createCSRReq.Subject.CommonName != "" {
		t.Errorf("Expected empty CN, got %q", ca.createCSRReq.Subject.CommonName)
	}
}

func TestSetup_Integration(t *testing.T) {
	// Integration test simulating full endorse-01 setup flow
	ekPubKey := map[string]interface{}{
		"algorithm": "RSA",
		"keyBits":   2048,
		"modulus":   "test-modulus",
		"exponent":  65537,
	}

	ekAttrs := &mockEKAttributes{
		CN: "device-123.example.com",
	}

	// Use real JSON serialization
	ekPubKeyBytes, _ := json.Marshal(ekPubKey)

	expectedCSR := []byte("-----BEGIN CERTIFICATE REQUEST-----\ntest-csr-content\n-----END CERTIFICATE REQUEST-----")

	ca := &mockCA{
		createCSRResult: expectedCSR,
	}

	tpm := &mockTPM{
		ekPubKey: nil,
		ekAttrs:  ekAttrs,
	}

	serializer := &mockSerializer{
		serializeResult: ekPubKeyBytes,
	}

	// Execute setup
	csr, err := Setup("integration-test-token", ca, tpm, serializer)
	if err != nil {
		t.Fatalf("Integration test failed: %v", err)
	}

	// Verify results
	if string(csr) != string(expectedCSR) {
		t.Errorf("Expected CSR %q, got %q", string(expectedCSR), string(csr))
	}

	// Verify the CA received correct request
	if ca.createCSRReq.Subject.CommonName != "device-123.example.com" {
		t.Errorf("Expected CN 'device-123.example.com', got %q", ca.createCSRReq.Subject.CommonName)
	}

	if ca.createCSRReq.PermanentID != string(ekPubKeyBytes) {
		t.Error("PermanentID should contain serialized EK public key")
	}
}

func BenchmarkSetup(b *testing.B) {
	ca := &mockCA{
		createCSRResult: []byte("bench-csr"),
	}

	tpm := &mockTPM{
		ekPubKey: nil,
		ekAttrs:  &mockEKAttributes{CN: "bench-device"},
	}

	serializer := &mockSerializer{
		serializeResult: []byte("bench-serialized"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Setup("bench-token", ca, tpm, serializer)
	}
}

func BenchmarkVerify(b *testing.B) {

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Verify(nil, "domain", "port", "token", "keyauth")
	}
}
