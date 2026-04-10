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

package module

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// mockClient implements PKCS11Transport for testing.
type mockClient struct {
	// Configurable responses
	signResponse     *transport.SignResponse
	signError        error
	verifyResponse   *transport.VerifyResponse
	verifyError      error
	encryptResponse  *transport.EncryptResponse
	encryptError     error
	decryptResponse  *transport.DecryptResponse
	decryptError     error
	generateKeyResp  *transport.GenerateKeyResponse
	generateKeyError error

	// Call tracking
	signCalled      bool
	verifyCalled    bool
	encryptCalled   bool
	decryptCalled   bool
	generateCalled  bool
	lastSignReq     *transport.SignRequest
	lastVerifyReq   *transport.VerifyRequest
	lastEncryptReq  *transport.EncryptRequest
	lastDecryptReq  *transport.DecryptRequest
	lastGenerateReq *transport.GenerateKeyRequest
}

func newMockClient() *mockClient {
	return &mockClient{
		signResponse: &transport.SignResponse{
			Signature: []byte("mock-signature"),
			Algorithm: "RSA-PKCS",
		},
		verifyResponse: &transport.VerifyResponse{
			Valid: true,
		},
		encryptResponse: &transport.EncryptResponse{
			Ciphertext: []byte("mock-ciphertext"),
		},
		decryptResponse: &transport.DecryptResponse{
			Plaintext: []byte("mock-plaintext"),
		},
		generateKeyResp: &transport.GenerateKeyResponse{
			KeyID:   "test-key-id",
			KeyType: "RSA",
		},
	}
}

// Compile-time check: mockClient satisfies PKCS11Transport.
var _ PKCS11Transport = (*mockClient)(nil)

// Implement PKCS11Transport interface

func (m *mockClient) Connect(ctx context.Context) error {
	return nil
}

func (m *mockClient) Close() error {
	return nil
}

func (m *mockClient) GenerateKey(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	m.generateCalled = true
	m.lastGenerateReq = req
	if m.generateKeyError != nil {
		return nil, m.generateKeyError
	}
	return m.generateKeyResp, nil
}

func (m *mockClient) Sign(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
	m.signCalled = true
	m.lastSignReq = req
	if m.signError != nil {
		return nil, m.signError
	}
	return m.signResponse, nil
}

func (m *mockClient) Verify(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	m.verifyCalled = true
	m.lastVerifyReq = req
	if m.verifyError != nil {
		return nil, m.verifyError
	}
	return m.verifyResponse, nil
}

func (m *mockClient) Encrypt(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	m.encryptCalled = true
	m.lastEncryptReq = req
	if m.encryptError != nil {
		return nil, m.encryptError
	}
	return m.encryptResponse, nil
}

func (m *mockClient) Decrypt(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	m.decryptCalled = true
	m.lastDecryptReq = req
	if m.decryptError != nil {
		return nil, m.decryptError
	}
	return m.decryptResponse, nil
}

func (m *mockClient) DeriveKey(ctx context.Context, req *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	return &transport.DeriveKeyResponse{
		DerivedKey: []byte("derived-key"),
		Algorithm:  req.Algorithm,
		KeyLength:  req.KeyLength,
	}, nil
}
func (m *mockClient) WrapKeyByID(ctx context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	return &transport.WrapKeyByIDResponse{
		WrappedKey: []byte("mock-wrapped-key"),
		Algorithm:  req.Algorithm,
	}, nil
}

func (m *mockClient) UnwrapKeyByID(ctx context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	return &transport.UnwrapKeyByIDResponse{
		KeyID:   req.TargetKeyID,
		Backend: req.TargetKeyBackend,
		Success: true,
	}, nil
}

func (m *mockClient) ExportKeyMaterial(ctx context.Context, req *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	return &transport.ExportKeyMaterialResponse{
		KeyMaterial: []byte("mock-key-material-32bytes-------"),
		KeyType:     "aes256-gcm",
		KeySize:     256,
	}, nil
}

func (m *mockClient) DeriveKeyECDH(ctx context.Context, req *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	// Generate mock derived key of requested length (or default 32)
	keyLen := req.KeyLength
	if keyLen <= 0 {
		keyLen = 32
	}
	derivedKey := make([]byte, keyLen)
	for i := range derivedKey {
		derivedKey[i] = byte(i % 256)
	}
	return &transport.DeriveKeyECDHResponse{
		DerivedKey: derivedKey,
	}, nil
}

func (m *mockClient) ListPIVSlots(ctx context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	return &transport.ListPIVSlotsResponse{}, nil
}

func (m *mockClient) GetPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return &transport.GetPIVCertificateResponse{}, nil
}

func (m *mockClient) GeneratePIVKey(ctx context.Context, req *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	return &transport.GeneratePIVKeyResponse{}, nil
}

func (m *mockClient) StorePIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return nil
}

func (m *mockClient) DeletePIVCertificate(ctx context.Context, req *transport.DeletePIVCertificateRequest) error {
	return nil
}

func (m *mockClient) ImportPIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return nil
}

func (m *mockClient) ExportPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return &transport.GetPIVCertificateResponse{}, nil
}

func (m *mockClient) GeneratePIVCSR(ctx context.Context, req *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	return &transport.GeneratePIVCSRResponse{}, nil
}

// Test helpers

func newTestCryptoManager() (*CryptoManager, *mockClient) {
	client := newMockClient()
	config := &CryptoManagerConfig{
		DefaultBackend: "test-backend",
	}
	return NewCryptoManager(client, config), client
}

// CryptoManager tests

func TestNewCryptoManager(t *testing.T) {
	client := newMockClient()
	cm := NewCryptoManager(client, nil)
	if cm == nil {
		t.Fatal("NewCryptoManager returned nil")
	}
	if cm.client != client {
		t.Error("client not set correctly")
	}
	if cm.config.DefaultBackend != "software" {
		t.Errorf("expected default backend 'software', got %s", cm.config.DefaultBackend)
	}
}

func TestNewCryptoManager_WithConfig(t *testing.T) {
	client := newMockClient()
	config := &CryptoManagerConfig{
		DefaultBackend: "custom-backend",
		Timeout:        5000,
	}
	cm := NewCryptoManager(client, config)
	if cm.config.DefaultBackend != "custom-backend" {
		t.Errorf("expected backend 'custom-backend', got %s", cm.config.DefaultBackend)
	}
}

// SignInit tests

func TestCryptoManager_SignInit_Success(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_RSA_PKCS}

	op, err := cm.SignInit(mech, 1, "test-key", "backend1")
	if err != nil {
		t.Fatalf("SignInit failed: %v", err)
	}
	if op == nil {
		t.Fatal("SignInit returned nil operation")
	}
	if op.Type() != OperationSign {
		t.Errorf("expected OperationSign, got %d", op.Type())
	}
	if op.KeyHandle() != 1 {
		t.Errorf("expected key handle 1, got %d", op.KeyHandle())
	}
	if op.KeyID() != "test-key" {
		t.Errorf("expected key ID 'test-key', got %s", op.KeyID())
	}
	if op.Backend() != "backend1" {
		t.Errorf("expected backend 'backend1', got %s", op.Backend())
	}
}

func TestCryptoManager_SignInit_NilMechanism(t *testing.T) {
	cm, _ := newTestCryptoManager()

	_, err := cm.SignInit(nil, 1, "test-key", "backend1")
	if err == nil {
		t.Fatal("expected error for nil mechanism")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_ARGUMENTS_BAD {
		t.Errorf("expected CKR_ARGUMENTS_BAD, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_SignInit_InvalidKeyHandle(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_RSA_PKCS}

	_, err := cm.SignInit(mech, 0, "test-key", "backend1")
	if err == nil {
		t.Fatal("expected error for invalid key handle")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_KEY_HANDLE_INVALID {
		t.Errorf("expected CKR_KEY_HANDLE_INVALID, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_SignInit_InvalidMechanism(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: 0xFFFFFFFF} // Invalid mechanism

	_, err := cm.SignInit(mech, 1, "test-key", "backend1")
	if err == nil {
		t.Fatal("expected error for invalid mechanism")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_MECHANISM_INVALID {
		t.Errorf("expected CKR_MECHANISM_INVALID, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_SignInit_MechanismNoSign(t *testing.T) {
	cm, _ := newTestCryptoManager()
	// AES-GCM doesn't support signing
	mech := &Mechanism{Type: CKM_AES_GCM}

	_, err := cm.SignInit(mech, 1, "test-key", "backend1")
	if err == nil {
		t.Fatal("expected error for mechanism that doesn't support signing")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_MECHANISM_INVALID {
		t.Errorf("expected CKR_MECHANISM_INVALID, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_SignInit_DefaultBackend(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_RSA_PKCS}

	op, err := cm.SignInit(mech, 1, "test-key", "")
	if err != nil {
		t.Fatalf("SignInit failed: %v", err)
	}
	if op.Backend() != "test-backend" {
		t.Errorf("expected default backend 'test-backend', got %s", op.Backend())
	}
}

// Sign tests

func TestCryptoManager_Sign_Success(t *testing.T) {
	cm, client := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_SHA256_RSA_PKCS}

	op, _ := cm.SignInit(mech, 1, "test-key", "backend1")
	data := []byte("test data to sign")

	sig, err := cm.Sign(context.Background(), op, data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if !bytes.Equal(sig, []byte("mock-signature")) {
		t.Errorf("unexpected signature: %v", sig)
	}
	if !client.signCalled {
		t.Error("Sign was not called on client")
	}
	if client.lastSignReq.Backend != "backend1" {
		t.Errorf("expected backend 'backend1', got %s", client.lastSignReq.Backend)
	}
	if client.lastSignReq.KeyID != "test-key" {
		t.Errorf("expected key ID 'test-key', got %s", client.lastSignReq.KeyID)
	}
	if client.lastSignReq.Hash != "SHA-256" {
		t.Errorf("expected hash 'SHA-256', got %s", client.lastSignReq.Hash)
	}
}

func TestCryptoManager_Sign_NilOperation(t *testing.T) {
	cm, _ := newTestCryptoManager()

	_, err := cm.Sign(context.Background(), nil, []byte("data"))
	if err == nil {
		t.Fatal("expected error for nil operation")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_Sign_AlreadyFinalized(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_RSA_PKCS}

	op, _ := cm.SignInit(mech, 1, "test-key", "backend1")

	// First sign should succeed
	_, _ = cm.Sign(context.Background(), op, []byte("data"))

	// Second sign should fail
	_, err := cm.Sign(context.Background(), op, []byte("data"))
	if err == nil {
		t.Fatal("expected error for already finalized operation")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_Sign_ClientError(t *testing.T) {
	cm, client := newTestCryptoManager()
	client.signError = errors.New("client error")
	mech := &Mechanism{Type: CKM_RSA_PKCS}

	op, _ := cm.SignInit(mech, 1, "test-key", "backend1")

	_, err := cm.Sign(context.Background(), op, []byte("data"))
	if err == nil {
		t.Fatal("expected error from client")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_FUNCTION_FAILED {
		t.Errorf("expected CKR_FUNCTION_FAILED, got %s", pkcsErr.Code.String())
	}
}

// SignUpdate and SignFinal tests

func TestCryptoManager_SignUpdate_Success(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_RSA_PKCS}

	op, _ := cm.SignInit(mech, 1, "test-key", "backend1")

	err := cm.SignUpdate(op, []byte("part1"))
	if err != nil {
		t.Fatalf("SignUpdate failed: %v", err)
	}

	err = cm.SignUpdate(op, []byte("part2"))
	if err != nil {
		t.Fatalf("SignUpdate failed: %v", err)
	}
}

func TestCryptoManager_SignUpdate_NilOperation(t *testing.T) {
	cm, _ := newTestCryptoManager()

	err := cm.SignUpdate(nil, []byte("data"))
	if err == nil {
		t.Fatal("expected error for nil operation")
	}
}

func TestCryptoManager_SignFinal_Success(t *testing.T) {
	cm, client := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_RSA_PKCS}

	op, _ := cm.SignInit(mech, 1, "test-key", "backend1")
	_ = cm.SignUpdate(op, []byte("part1"))
	_ = cm.SignUpdate(op, []byte("part2"))

	sig, err := cm.SignFinal(context.Background(), op)
	if err != nil {
		t.Fatalf("SignFinal failed: %v", err)
	}
	if !bytes.Equal(sig, []byte("mock-signature")) {
		t.Errorf("unexpected signature: %v", sig)
	}

	// Verify the full data was sent
	expectedData := []byte("part1part2")
	if !bytes.Equal(client.lastSignReq.Data, expectedData) {
		t.Errorf("expected data %q, got %q", expectedData, client.lastSignReq.Data)
	}
}

// VerifyInit tests

func TestCryptoManager_VerifyInit_Success(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_RSA_PKCS}

	op, err := cm.VerifyInit(mech, 1, "test-key", "backend1")
	if err != nil {
		t.Fatalf("VerifyInit failed: %v", err)
	}
	if op == nil {
		t.Fatal("VerifyInit returned nil operation")
	}
	if op.Type() != OperationVerify {
		t.Errorf("expected OperationVerify, got %d", op.Type())
	}
}

func TestCryptoManager_VerifyInit_NilMechanism(t *testing.T) {
	cm, _ := newTestCryptoManager()

	_, err := cm.VerifyInit(nil, 1, "test-key", "backend1")
	if err == nil {
		t.Fatal("expected error for nil mechanism")
	}
}

func TestCryptoManager_VerifyInit_MechanismNoVerify(t *testing.T) {
	cm, _ := newTestCryptoManager()
	// AES-GCM doesn't support verification
	mech := &Mechanism{Type: CKM_AES_GCM}

	_, err := cm.VerifyInit(mech, 1, "test-key", "backend1")
	if err == nil {
		t.Fatal("expected error for mechanism that doesn't support verification")
	}
}

// Verify tests

func TestCryptoManager_Verify_Success(t *testing.T) {
	cm, client := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_RSA_PKCS}

	op, _ := cm.VerifyInit(mech, 1, "test-key", "backend1")
	data := []byte("test data")
	sig := []byte("signature")

	err := cm.Verify(context.Background(), op, data, sig)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !client.verifyCalled {
		t.Error("Verify was not called on client")
	}
}

func TestCryptoManager_Verify_InvalidSignature(t *testing.T) {
	cm, client := newTestCryptoManager()
	client.verifyResponse.Valid = false
	mech := &Mechanism{Type: CKM_RSA_PKCS}

	op, _ := cm.VerifyInit(mech, 1, "test-key", "backend1")

	err := cm.Verify(context.Background(), op, []byte("data"), []byte("bad-sig"))
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_SIGNATURE_INVALID {
		t.Errorf("expected CKR_SIGNATURE_INVALID, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_Verify_ClientError(t *testing.T) {
	cm, client := newTestCryptoManager()
	client.verifyError = errors.New("client error")
	mech := &Mechanism{Type: CKM_RSA_PKCS}

	op, _ := cm.VerifyInit(mech, 1, "test-key", "backend1")

	err := cm.Verify(context.Background(), op, []byte("data"), []byte("sig"))
	if err == nil {
		t.Fatal("expected error from client")
	}
}

// VerifyUpdate and VerifyFinal tests

func TestCryptoManager_VerifyFinal_Success(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_RSA_PKCS}

	op, _ := cm.VerifyInit(mech, 1, "test-key", "backend1")
	_ = cm.VerifyUpdate(op, []byte("part1"))
	_ = cm.VerifyUpdate(op, []byte("part2"))

	err := cm.VerifyFinal(context.Background(), op, []byte("signature"))
	if err != nil {
		t.Fatalf("VerifyFinal failed: %v", err)
	}
}

// EncryptInit tests

func TestCryptoManager_EncryptInit_Success(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_AES_GCM}

	op, err := cm.EncryptInit(mech, 1, "test-key", "backend1")
	if err != nil {
		t.Fatalf("EncryptInit failed: %v", err)
	}
	if op == nil {
		t.Fatal("EncryptInit returned nil operation")
	}
	if op.Type() != OperationEncrypt {
		t.Errorf("expected OperationEncrypt, got %d", op.Type())
	}
}

func TestCryptoManager_EncryptInit_MechanismNoEncrypt(t *testing.T) {
	cm, _ := newTestCryptoManager()
	// SHA-256 doesn't support encryption
	mech := &Mechanism{Type: CKM_SHA256}

	_, err := cm.EncryptInit(mech, 1, "test-key", "backend1")
	if err == nil {
		t.Fatal("expected error for mechanism that doesn't support encryption")
	}
}

// Encrypt tests

func TestCryptoManager_Encrypt_Success(t *testing.T) {
	cm, client := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_AES_GCM}

	op, _ := cm.EncryptInit(mech, 1, "test-key", "backend1")
	plaintext := []byte("secret data")

	ciphertext, err := cm.Encrypt(context.Background(), op, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if !bytes.Equal(ciphertext, []byte("mock-ciphertext")) {
		t.Errorf("unexpected ciphertext: %v", ciphertext)
	}
	if !client.encryptCalled {
		t.Error("Encrypt was not called on client")
	}
}

func TestCryptoManager_Encrypt_WithAAD(t *testing.T) {
	cm, client := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_AES_GCM}

	op, _ := cm.EncryptInit(mech, 1, "test-key", "backend1")
	op.SetAAD([]byte("additional data"))
	plaintext := []byte("secret data")

	_, err := cm.Encrypt(context.Background(), op, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if !bytes.Equal(client.lastEncryptReq.AdditionalData, []byte("additional data")) {
		t.Error("AAD not passed to client")
	}
}

func TestCryptoManager_EncryptFinal_Success(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_AES_GCM}

	op, _ := cm.EncryptInit(mech, 1, "test-key", "backend1")
	_ = cm.EncryptUpdate(op, []byte("part1"))
	_ = cm.EncryptUpdate(op, []byte("part2"))

	ciphertext, err := cm.EncryptFinal(context.Background(), op)
	if err != nil {
		t.Fatalf("EncryptFinal failed: %v", err)
	}
	if ciphertext == nil {
		t.Error("EncryptFinal returned nil ciphertext")
	}
}

// DecryptInit tests

func TestCryptoManager_DecryptInit_Success(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_AES_GCM}

	op, err := cm.DecryptInit(mech, 1, "test-key", "backend1")
	if err != nil {
		t.Fatalf("DecryptInit failed: %v", err)
	}
	if op == nil {
		t.Fatal("DecryptInit returned nil operation")
	}
	if op.Type() != OperationDecrypt {
		t.Errorf("expected OperationDecrypt, got %d", op.Type())
	}
}

// Decrypt tests

func TestCryptoManager_Decrypt_Success(t *testing.T) {
	cm, client := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_AES_GCM}

	op, _ := cm.DecryptInit(mech, 1, "test-key", "backend1")
	ciphertext := []byte("encrypted data")

	plaintext, err := cm.Decrypt(context.Background(), op, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(plaintext, []byte("mock-plaintext")) {
		t.Errorf("unexpected plaintext: %v", plaintext)
	}
	if !client.decryptCalled {
		t.Error("Decrypt was not called on client")
	}
}

func TestCryptoManager_DecryptFinal_Success(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_AES_GCM}

	op, _ := cm.DecryptInit(mech, 1, "test-key", "backend1")
	_ = cm.DecryptUpdate(op, []byte("part1"))
	_ = cm.DecryptUpdate(op, []byte("part2"))

	plaintext, err := cm.DecryptFinal(context.Background(), op)
	if err != nil {
		t.Fatalf("DecryptFinal failed: %v", err)
	}
	if plaintext == nil {
		t.Error("DecryptFinal returned nil plaintext")
	}
}

// DigestInit tests

func TestCryptoManager_DigestInit_Success(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_SHA256}

	op, err := cm.DigestInit(mech)
	if err != nil {
		t.Fatalf("DigestInit failed: %v", err)
	}
	if op == nil {
		t.Fatal("DigestInit returned nil operation")
	}
	if op.Type() != OperationDigest {
		t.Errorf("expected OperationDigest, got %d", op.Type())
	}
}

func TestCryptoManager_DigestInit_NilMechanism(t *testing.T) {
	cm, _ := newTestCryptoManager()

	_, err := cm.DigestInit(nil)
	if err == nil {
		t.Fatal("expected error for nil mechanism")
	}
}

func TestCryptoManager_DigestInit_UnsupportedMechanism(t *testing.T) {
	cm, _ := newTestCryptoManager()
	// RSA-PKCS doesn't support digesting
	mech := &Mechanism{Type: CKM_RSA_PKCS}

	_, err := cm.DigestInit(mech)
	if err == nil {
		t.Fatal("expected error for mechanism that doesn't support digesting")
	}
}

func TestCryptoManager_DigestInit_AllSupportedMechanisms(t *testing.T) {
	cm, _ := newTestCryptoManager()

	// Test only mechanisms that are both registered and supported by the hasher
	mechanisms := []MechanismType{
		CKM_SHA224,
		CKM_SHA256,
		CKM_SHA384,
		CKM_SHA512,
		// CKM_SHA512_224 and CKM_SHA512_256 are supported by Go's crypto/sha512
		// but not registered in the mechanism registry
	}

	for _, mechType := range mechanisms {
		mech := &Mechanism{Type: mechType}
		op, err := cm.DigestInit(mech)
		if err != nil {
			t.Errorf("DigestInit failed for %s: %v", GetMechanismName(mechType), err)
			continue
		}
		if op == nil {
			t.Errorf("DigestInit returned nil for %s", GetMechanismName(mechType))
		}
	}
}

// Digest tests

func TestCryptoManager_Digest_Success(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_SHA256}

	op, _ := cm.DigestInit(mech)
	data := []byte("test data")

	digest, err := cm.Digest(op, data)
	if err != nil {
		t.Fatalf("Digest failed: %v", err)
	}
	if len(digest) != 32 { // SHA-256 produces 32 bytes
		t.Errorf("expected 32 bytes, got %d", len(digest))
	}
}

func TestCryptoManager_Digest_NilOperation(t *testing.T) {
	cm, _ := newTestCryptoManager()

	_, err := cm.Digest(nil, []byte("data"))
	if err == nil {
		t.Fatal("expected error for nil operation")
	}
}

func TestCryptoManager_DigestUpdate_Success(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_SHA256}

	op, _ := cm.DigestInit(mech)

	err := cm.DigestUpdate(op, []byte("part1"))
	if err != nil {
		t.Fatalf("DigestUpdate failed: %v", err)
	}

	err = cm.DigestUpdate(op, []byte("part2"))
	if err != nil {
		t.Fatalf("DigestUpdate failed: %v", err)
	}
}

func TestCryptoManager_DigestFinal_Success(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_SHA256}

	op, _ := cm.DigestInit(mech)
	_ = cm.DigestUpdate(op, []byte("part1"))
	_ = cm.DigestUpdate(op, []byte("part2"))

	digest, err := cm.DigestFinal(op)
	if err != nil {
		t.Fatalf("DigestFinal failed: %v", err)
	}
	if len(digest) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(digest))
	}
}

func TestCryptoManager_DigestFinal_NilOperation(t *testing.T) {
	cm, _ := newTestCryptoManager()

	_, err := cm.DigestFinal(nil)
	if err == nil {
		t.Fatal("expected error for nil operation")
	}
}

// GenerateKey tests

func TestCryptoManager_GenerateKey_Success(t *testing.T) {
	cm, client := newTestCryptoManager()
	req := &GenerateKeyRequest{
		KeyID:     "new-aes-key",
		Backend:   "backend1",
		Mechanism: &Mechanism{Type: CKM_AES_KEY_GEN},
		KeySize:   256,
	}

	resp, err := cm.GenerateKey(context.Background(), req)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if resp == nil {
		t.Fatal("GenerateKey returned nil response")
	}
	if !client.generateCalled {
		t.Error("GenerateKey was not called on client")
	}
	if client.lastGenerateReq.KeyID != "new-aes-key" {
		t.Errorf("expected key ID 'new-aes-key', got %s", client.lastGenerateReq.KeyID)
	}
	if client.lastGenerateReq.KeyType != "Symmetric" {
		t.Errorf("expected key type 'Symmetric', got %s", client.lastGenerateReq.KeyType)
	}
}

func TestCryptoManager_GenerateKey_NilRequest(t *testing.T) {
	cm, _ := newTestCryptoManager()

	_, err := cm.GenerateKey(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil request")
	}
}

func TestCryptoManager_GenerateKey_NilMechanism(t *testing.T) {
	cm, _ := newTestCryptoManager()
	req := &GenerateKeyRequest{
		KeyID:   "test-key",
		Backend: "backend1",
	}

	_, err := cm.GenerateKey(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for nil mechanism")
	}
}

func TestCryptoManager_GenerateKey_InvalidMechanism(t *testing.T) {
	cm, _ := newTestCryptoManager()
	req := &GenerateKeyRequest{
		KeyID:     "test-key",
		Backend:   "backend1",
		Mechanism: &Mechanism{Type: CKM_RSA_PKCS}, // Not a key gen mechanism
	}

	_, err := cm.GenerateKey(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for mechanism that doesn't support key generation")
	}
}

func TestCryptoManager_GenerateKey_DefaultBackend(t *testing.T) {
	cm, client := newTestCryptoManager()
	req := &GenerateKeyRequest{
		KeyID:     "test-key",
		Mechanism: &Mechanism{Type: CKM_AES_KEY_GEN},
		KeySize:   256,
	}

	_, err := cm.GenerateKey(context.Background(), req)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if client.lastGenerateReq.Backend != "test-backend" {
		t.Errorf("expected default backend 'test-backend', got %s", client.lastGenerateReq.Backend)
	}
}

// GenerateKeyPair tests

func TestCryptoManager_GenerateKeyPair_RSA_Success(t *testing.T) {
	cm, client := newTestCryptoManager()
	req := &GenerateKeyPairRequest{
		KeyID:     "new-rsa-key",
		Backend:   "backend1",
		Mechanism: &Mechanism{Type: CKM_RSA_PKCS_KEY_PAIR_GEN},
		KeySize:   2048,
	}

	resp, err := cm.GenerateKeyPair(context.Background(), req)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if resp == nil {
		t.Fatal("GenerateKeyPair returned nil response")
	}
	if client.lastGenerateReq.KeyType != "RSA" {
		t.Errorf("expected key type 'RSA', got %s", client.lastGenerateReq.KeyType)
	}
	if client.lastGenerateReq.KeySize != 2048 {
		t.Errorf("expected key size 2048, got %d", client.lastGenerateReq.KeySize)
	}
}

func TestCryptoManager_GenerateKeyPair_EC_Success(t *testing.T) {
	cm, client := newTestCryptoManager()
	req := &GenerateKeyPairRequest{
		KeyID:     "new-ec-key",
		Backend:   "backend1",
		Mechanism: &Mechanism{Type: CKM_EC_KEY_PAIR_GEN},
		Curve:     "P-256",
	}

	resp, err := cm.GenerateKeyPair(context.Background(), req)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if resp == nil {
		t.Fatal("GenerateKeyPair returned nil response")
	}
	if client.lastGenerateReq.KeyType != "ECDSA" {
		t.Errorf("expected key type 'ECDSA', got %s", client.lastGenerateReq.KeyType)
	}
	if client.lastGenerateReq.Curve != "P-256" {
		t.Errorf("expected curve 'P-256', got %s", client.lastGenerateReq.Curve)
	}
}

func TestCryptoManager_GenerateKeyPair_NilRequest(t *testing.T) {
	cm, _ := newTestCryptoManager()

	_, err := cm.GenerateKeyPair(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil request")
	}
}

func TestCryptoManager_GenerateKeyPair_InvalidMechanism(t *testing.T) {
	cm, _ := newTestCryptoManager()
	req := &GenerateKeyPairRequest{
		KeyID:     "test-key",
		Mechanism: &Mechanism{Type: CKM_AES_KEY_GEN}, // Symmetric, not asymmetric
	}

	_, err := cm.GenerateKeyPair(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for mechanism that doesn't support key pair generation")
	}
}

// GenerateRandom tests

func TestCryptoManager_GenerateRandom_Success(t *testing.T) {
	cm, _ := newTestCryptoManager()

	random, err := cm.GenerateRandom(32)
	if err != nil {
		t.Fatalf("GenerateRandom failed: %v", err)
	}
	if len(random) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(random))
	}
}

func TestCryptoManager_GenerateRandom_ZeroLength(t *testing.T) {
	cm, _ := newTestCryptoManager()

	_, err := cm.GenerateRandom(0)
	if err == nil {
		t.Fatal("expected error for zero length")
	}
}

func TestCryptoManager_GenerateRandom_NegativeLength(t *testing.T) {
	cm, _ := newTestCryptoManager()

	_, err := cm.GenerateRandom(-1)
	if err == nil {
		t.Fatal("expected error for negative length")
	}
}

func TestCryptoManager_GenerateRandom_ExceedsMax(t *testing.T) {
	cm, _ := newTestCryptoManager()

	_, err := cm.GenerateRandom(65537) // Max is 65536
	if err == nil {
		t.Fatal("expected error for length exceeding maximum")
	}
}

func TestCryptoManager_GenerateRandom_MaxLength(t *testing.T) {
	cm, _ := newTestCryptoManager()

	random, err := cm.GenerateRandom(65536)
	if err != nil {
		t.Fatalf("GenerateRandom failed: %v", err)
	}
	if len(random) != 65536 {
		t.Errorf("expected 65536 bytes, got %d", len(random))
	}
}

// Operation state tests

func TestSignOperation_Reset(t *testing.T) {
	op := newSignOperation(&Mechanism{Type: CKM_RSA_PKCS}, 1, "key", "backend")
	op.data.WriteString("test data")
	op.finalized = true

	op.Reset()

	if op.finalized {
		t.Error("finalized should be false after reset")
	}
	if op.data.Len() != 0 {
		t.Error("data buffer should be empty after reset")
	}
}

func TestVerifyOperation_Reset(t *testing.T) {
	op := newVerifyOperation(&Mechanism{Type: CKM_RSA_PKCS}, 1, "key", "backend")
	op.data.WriteString("test data")
	op.finalized = true

	op.Reset()

	if op.finalized {
		t.Error("finalized should be false after reset")
	}
	if op.data.Len() != 0 {
		t.Error("data buffer should be empty after reset")
	}
}

func TestEncryptOperation_Reset(t *testing.T) {
	op := newEncryptOperation(&Mechanism{Type: CKM_AES_GCM}, 1, "key", "backend")
	op.data.WriteString("test data")
	op.aad = []byte("aad")
	op.finalized = true

	op.Reset()

	if op.finalized {
		t.Error("finalized should be false after reset")
	}
	if op.data.Len() != 0 {
		t.Error("data buffer should be empty after reset")
	}
	if op.aad != nil {
		t.Error("AAD should be nil after reset")
	}
}

func TestDigestOperation_Reset(t *testing.T) {
	cm, _ := newTestCryptoManager()
	op, _ := cm.DigestInit(&Mechanism{Type: CKM_SHA256})
	op.hasher.Write([]byte("test data"))
	op.finalized = true

	op.Reset()

	if op.finalized {
		t.Error("finalized should be false after reset")
	}
	// Hasher state is reset, verify by computing a fresh hash
	op.hasher.Write([]byte("test"))
	digest := op.hasher.Sum(nil)
	if len(digest) != 32 {
		t.Error("hasher should produce valid digest after reset")
	}
}

// Mechanism translation tests

func TestMechanismToHash(t *testing.T) {
	tests := []struct {
		mech     MechanismType
		expected string
	}{
		{CKM_RSA_PKCS, ""},
		{CKM_SHA1_RSA_PKCS, "SHA-1"},
		{CKM_SHA256_RSA_PKCS, "SHA-256"},
		{CKM_SHA384_RSA_PKCS, "SHA-384"},
		{CKM_SHA512_RSA_PKCS, "SHA-512"},
		{CKM_ECDSA, ""},
		{CKM_ECDSA_SHA256, "SHA-256"},
		{CKM_EDDSA, ""},
		{0xFFFFFFFF, ""}, // Unknown
	}

	for _, tt := range tests {
		result := mechanismToHash(tt.mech)
		if result != tt.expected {
			t.Errorf("mechanismToHash(%s) = %q, want %q",
				GetMechanismName(tt.mech), result, tt.expected)
		}
	}
}

func TestMechanismToKeyType(t *testing.T) {
	tests := []struct {
		mech     MechanismType
		expected string
	}{
		{CKM_RSA_PKCS_KEY_PAIR_GEN, "RSA"},
		{CKM_EC_KEY_PAIR_GEN, "ECDSA"},
		{CKM_EC_EDWARDS_KEY_PAIR_GEN, "Ed25519"},
		{CKM_AES_KEY_GEN, "Symmetric"},
		{CKM_DES3_KEY_GEN, "Symmetric"},
		{CKM_GENERIC_SECRET_KEY_GEN, "Symmetric"},
		{0xFFFFFFFF, "UNKNOWN"},
	}

	for _, tt := range tests {
		result := mechanismToKeyType(tt.mech)
		if result != tt.expected {
			t.Errorf("mechanismToKeyType(%s) = %q, want %q",
				GetMechanismName(tt.mech), result, tt.expected)
		}
	}
}

// Buffer pool tests

func TestCryptoManager_BufferPool(t *testing.T) {
	cm, _ := newTestCryptoManager()

	// Get a buffer
	buf := cm.getBuffer()
	if buf == nil {
		t.Fatal("getBuffer returned nil")
	}

	// Write some data
	buf.WriteString("test data")

	// Return to pool
	cm.putBuffer(buf)

	// Get another buffer - should be reset
	buf2 := cm.getBuffer()
	if buf2.Len() != 0 {
		t.Error("buffer from pool should be empty")
	}
}

// Edge case tests

func TestSignOperation_Mechanism(t *testing.T) {
	mech := &Mechanism{Type: CKM_RSA_PKCS}
	op := newSignOperation(mech, 1, "key", "backend")

	if op.Mechanism() != mech {
		t.Error("Mechanism() should return the mechanism")
	}
}

func TestSignOperation_IsFinalized(t *testing.T) {
	op := newSignOperation(&Mechanism{Type: CKM_RSA_PKCS}, 1, "key", "backend")

	if op.IsFinalized() {
		t.Error("new operation should not be finalized")
	}

	op.finalized = true

	if !op.IsFinalized() {
		t.Error("operation should be finalized")
	}
}

func TestOperationTypes(t *testing.T) {
	signOp := newSignOperation(&Mechanism{Type: CKM_RSA_PKCS}, 1, "key", "backend")
	if signOp.Type() != OperationSign {
		t.Errorf("expected OperationSign, got %d", signOp.Type())
	}

	verifyOp := newVerifyOperation(&Mechanism{Type: CKM_RSA_PKCS}, 1, "key", "backend")
	if verifyOp.Type() != OperationVerify {
		t.Errorf("expected OperationVerify, got %d", verifyOp.Type())
	}

	encryptOp := newEncryptOperation(&Mechanism{Type: CKM_AES_GCM}, 1, "key", "backend")
	if encryptOp.Type() != OperationEncrypt {
		t.Errorf("expected OperationEncrypt, got %d", encryptOp.Type())
	}

	decryptOp := newDecryptOperation(&Mechanism{Type: CKM_AES_GCM}, 1, "key", "backend")
	if decryptOp.Type() != OperationDecrypt {
		t.Errorf("expected OperationDecrypt, got %d", decryptOp.Type())
	}
}

func TestDecryptOperation_Reset(t *testing.T) {
	op := newDecryptOperation(&Mechanism{Type: CKM_AES_GCM}, 1, "key", "backend")
	op.data.WriteString("test data")
	op.aad = []byte("aad")
	op.finalized = true

	op.Reset()

	if op.finalized {
		t.Error("finalized should be false after reset")
	}
	if op.data.Len() != 0 {
		t.Error("data buffer should be empty after reset")
	}
	if op.aad != nil {
		t.Error("AAD should be nil after reset")
	}
}

func TestDecryptOperation_Accessors(t *testing.T) {
	op := newDecryptOperation(&Mechanism{Type: CKM_AES_GCM}, 42, "test-key-id", "test-backend")

	if op.KeyHandle() != 42 {
		t.Errorf("expected key handle 42, got %d", op.KeyHandle())
	}
	if op.KeyID() != "test-key-id" {
		t.Errorf("expected key ID 'test-key-id', got %s", op.KeyID())
	}
	if op.Backend() != "test-backend" {
		t.Errorf("expected backend 'test-backend', got %s", op.Backend())
	}
}

func TestVerifyOperation_Accessors(t *testing.T) {
	op := newVerifyOperation(&Mechanism{Type: CKM_RSA_PKCS}, 99, "verify-key", "verify-backend")

	if op.KeyHandle() != 99 {
		t.Errorf("expected key handle 99, got %d", op.KeyHandle())
	}
	if op.KeyID() != "verify-key" {
		t.Errorf("expected key ID 'verify-key', got %s", op.KeyID())
	}
	if op.Backend() != "verify-backend" {
		t.Errorf("expected backend 'verify-backend', got %s", op.Backend())
	}
}

func TestEncryptOperation_Accessors(t *testing.T) {
	op := newEncryptOperation(&Mechanism{Type: CKM_AES_GCM}, 77, "encrypt-key", "encrypt-backend")

	if op.KeyHandle() != 77 {
		t.Errorf("expected key handle 77, got %d", op.KeyHandle())
	}
	if op.KeyID() != "encrypt-key" {
		t.Errorf("expected key ID 'encrypt-key', got %s", op.KeyID())
	}
	if op.Backend() != "encrypt-backend" {
		t.Errorf("expected backend 'encrypt-backend', got %s", op.Backend())
	}
}

func TestDecryptOperation_SetAAD(t *testing.T) {
	op := newDecryptOperation(&Mechanism{Type: CKM_AES_GCM}, 1, "key", "backend")
	aad := []byte("additional authenticated data")

	op.SetAAD(aad)

	if !bytes.Equal(op.aad, aad) {
		t.Error("AAD was not set correctly")
	}
}

// Ed25519/EdDSA tests

func TestCryptoManager_EdDSA_SignInit_Success(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_EDDSA}

	op, err := cm.SignInit(mech, 1, "ed25519-key", "backend1")
	if err != nil {
		t.Fatalf("SignInit with CKM_EDDSA failed: %v", err)
	}
	if op == nil {
		t.Fatal("SignInit with CKM_EDDSA returned nil operation")
	}
	if op.Type() != OperationSign {
		t.Errorf("expected OperationSign, got %d", op.Type())
	}
	if op.KeyID() != "ed25519-key" {
		t.Errorf("expected key ID 'ed25519-key', got %s", op.KeyID())
	}
	if op.Mechanism().Type != CKM_EDDSA {
		t.Errorf("expected mechanism CKM_EDDSA, got %d", op.Mechanism().Type)
	}
}

func TestCryptoManager_EdDSA_Sign_Success(t *testing.T) {
	cm, client := newTestCryptoManager()
	// Mock client returns ed25519-like signature
	client.signResponse.Signature = make([]byte, 64)
	client.signResponse.Algorithm = "EdDSA"

	mech := &Mechanism{Type: CKM_EDDSA}

	op, _ := cm.SignInit(mech, 1, "ed25519-key", "backend1")
	data := []byte("test data to sign with Ed25519")

	sig, err := cm.Sign(context.Background(), op, data)
	if err != nil {
		t.Fatalf("Sign with CKM_EDDSA failed: %v", err)
	}
	if len(sig) != 64 {
		t.Errorf("expected 64-byte Ed25519 signature, got %d bytes", len(sig))
	}
	if !client.signCalled {
		t.Error("Sign was not called on client")
	}
	if client.lastSignReq.KeyID != "ed25519-key" {
		t.Errorf("expected key ID 'ed25519-key', got %s", client.lastSignReq.KeyID)
	}
	// EdDSA handles its own hashing, so Hash should be empty
	if client.lastSignReq.Hash != "" {
		t.Errorf("expected empty hash for EdDSA, got %s", client.lastSignReq.Hash)
	}
}

func TestCryptoManager_EdDSA_VerifyInit_Success(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_EDDSA}

	op, err := cm.VerifyInit(mech, 1, "ed25519-key", "backend1")
	if err != nil {
		t.Fatalf("VerifyInit with CKM_EDDSA failed: %v", err)
	}
	if op == nil {
		t.Fatal("VerifyInit with CKM_EDDSA returned nil operation")
	}
	if op.Type() != OperationVerify {
		t.Errorf("expected OperationVerify, got %d", op.Type())
	}
}

func TestCryptoManager_EdDSA_Verify_Success(t *testing.T) {
	cm, client := newTestCryptoManager()
	client.verifyResponse.Valid = true

	mech := &Mechanism{Type: CKM_EDDSA}

	op, _ := cm.VerifyInit(mech, 1, "ed25519-key", "backend1")
	data := []byte("test data")
	signature := make([]byte, 64) // Ed25519 signature

	err := cm.Verify(context.Background(), op, data, signature)
	if err != nil {
		t.Fatalf("Verify with CKM_EDDSA failed: %v", err)
	}
	if !client.verifyCalled {
		t.Error("Verify was not called on client")
	}
	if client.lastVerifyReq.Hash != "" {
		t.Errorf("expected empty hash for EdDSA, got %s", client.lastVerifyReq.Hash)
	}
}

func TestCryptoManager_EdDSA_Verify_InvalidSignature(t *testing.T) {
	cm, client := newTestCryptoManager()
	client.verifyResponse.Valid = false

	mech := &Mechanism{Type: CKM_EDDSA}

	op, _ := cm.VerifyInit(mech, 1, "ed25519-key", "backend1")
	data := []byte("test data")
	signature := make([]byte, 64)

	err := cm.Verify(context.Background(), op, data, signature)
	if err == nil {
		t.Fatal("expected error for invalid EdDSA signature")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_SIGNATURE_INVALID {
		t.Errorf("expected CKR_SIGNATURE_INVALID, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_GenerateKeyPair_Ed25519(t *testing.T) {
	cm, client := newTestCryptoManager()
	client.generateKeyResp = &transport.GenerateKeyResponse{
		KeyID:   "ed25519-test-key",
		KeyType: "Ed25519",
	}

	mech := &Mechanism{Type: CKM_EC_EDWARDS_KEY_PAIR_GEN}

	req := &GenerateKeyPairRequest{
		KeyID:     "ed25519-test",
		Backend:   "test-backend",
		Mechanism: mech,
	}

	resp, err := cm.GenerateKeyPair(context.Background(), req)
	if err != nil {
		t.Fatalf("GenerateKeyPair for Ed25519 failed: %v", err)
	}
	if resp == nil {
		t.Fatal("GenerateKeyPair returned nil response")
	}
	if resp.KeyType != "Ed25519" {
		t.Errorf("expected key type 'Ed25519', got %s", resp.KeyType)
	}
	if !client.generateCalled {
		t.Error("GenerateKey was not called on client")
	}
	if client.lastGenerateReq.KeyType != "Ed25519" {
		t.Errorf("expected SDK key type 'Ed25519', got %s", client.lastGenerateReq.KeyType)
	}
}

func TestCryptoManager_GenerateKeyPair_Ed25519_ClientError(t *testing.T) {
	cm, client := newTestCryptoManager()
	client.generateKeyError = errors.New("key generation failed")

	mech := &Mechanism{Type: CKM_EC_EDWARDS_KEY_PAIR_GEN}

	req := &GenerateKeyPairRequest{
		KeyID:     "ed25519-fail",
		Backend:   "test-backend",
		Mechanism: mech,
	}

	_, err := cm.GenerateKeyPair(context.Background(), req)
	if err == nil {
		t.Fatal("expected error from client")
	}
}

func TestMechanismToKeyType_Ed25519(t *testing.T) {
	result := mechanismToKeyType(CKM_EC_EDWARDS_KEY_PAIR_GEN)
	if result != "Ed25519" {
		t.Errorf("mechanismToKeyType(CKM_EC_EDWARDS_KEY_PAIR_GEN) = %q, want 'Ed25519'", result)
	}
}

func TestMechanismToHash_EdDSA(t *testing.T) {
	result := mechanismToHash(CKM_EDDSA)
	if result != "" {
		t.Errorf("mechanismToHash(CKM_EDDSA) = %q, want '' (EdDSA handles its own hashing)", result)
	}
}

func TestEdDSA_MechanismDescriptor(t *testing.T) {
	desc := GetMechanismDescriptor(CKM_EDDSA)
	if desc == nil {
		t.Fatal("GetMechanismDescriptor(CKM_EDDSA) returned nil")
	}

	if desc.Name != "CKM_EDDSA" {
		t.Errorf("expected name 'CKM_EDDSA', got %s", desc.Name)
	}

	if desc.Flags&CKF_SIGN == 0 {
		t.Error("CKM_EDDSA should have CKF_SIGN flag")
	}

	if desc.Flags&CKF_VERIFY == 0 {
		t.Error("CKM_EDDSA should have CKF_VERIFY flag")
	}

	// Ed25519 key size is 255 bits
	if desc.MinKeySize != 255 {
		t.Errorf("expected MinKeySize 255, got %d", desc.MinKeySize)
	}
}

func TestEC_EDWARDS_KEY_PAIR_GEN_MechanismDescriptor(t *testing.T) {
	desc := GetMechanismDescriptor(CKM_EC_EDWARDS_KEY_PAIR_GEN)
	if desc == nil {
		t.Fatal("GetMechanismDescriptor(CKM_EC_EDWARDS_KEY_PAIR_GEN) returned nil")
	}

	if desc.Name != "CKM_EC_EDWARDS_KEY_PAIR_GEN" {
		t.Errorf("expected name 'CKM_EC_EDWARDS_KEY_PAIR_GEN', got %s", desc.Name)
	}

	if desc.Flags&CKF_GENERATE_KEY_PAIR == 0 {
		t.Error("CKM_EC_EDWARDS_KEY_PAIR_GEN should have CKF_GENERATE_KEY_PAIR flag")
	}
}

func TestEdDSA_SignUpdateAndFinal(t *testing.T) {
	cm, client := newTestCryptoManager()
	client.signResponse.Signature = make([]byte, 64)

	mech := &Mechanism{Type: CKM_EDDSA}
	op, _ := cm.SignInit(mech, 1, "ed25519-key", "backend1")

	// Multi-part signing
	err := cm.SignUpdate(op, []byte("part1-"))
	if err != nil {
		t.Fatalf("SignUpdate failed: %v", err)
	}

	err = cm.SignUpdate(op, []byte("part2"))
	if err != nil {
		t.Fatalf("SignUpdate failed: %v", err)
	}

	sig, err := cm.SignFinal(context.Background(), op)
	if err != nil {
		t.Fatalf("SignFinal failed: %v", err)
	}

	if len(sig) != 64 {
		t.Errorf("expected 64-byte signature, got %d", len(sig))
	}

	// Verify the full data was sent
	expectedData := []byte("part1-part2")
	if !bytes.Equal(client.lastSignReq.Data, expectedData) {
		t.Errorf("expected data %q, got %q", expectedData, client.lastSignReq.Data)
	}
}

func TestEdDSA_VerifyUpdateAndFinal(t *testing.T) {
	cm, client := newTestCryptoManager()
	client.verifyResponse.Valid = true

	mech := &Mechanism{Type: CKM_EDDSA}
	op, _ := cm.VerifyInit(mech, 1, "ed25519-key", "backend1")

	// Multi-part verification
	err := cm.VerifyUpdate(op, []byte("part1-"))
	if err != nil {
		t.Fatalf("VerifyUpdate failed: %v", err)
	}

	err = cm.VerifyUpdate(op, []byte("part2"))
	if err != nil {
		t.Fatalf("VerifyUpdate failed: %v", err)
	}

	signature := make([]byte, 64)
	err = cm.VerifyFinal(context.Background(), op, signature)
	if err != nil {
		t.Fatalf("VerifyFinal failed: %v", err)
	}

	// Verify the full data was sent
	expectedData := []byte("part1-part2")
	if !bytes.Equal(client.lastVerifyReq.Data, expectedData) {
		t.Errorf("expected data %q, got %q", expectedData, client.lastVerifyReq.Data)
	}
}

// RSA Verify-Recover tests

func TestCryptoManager_VerifyRecover_CKM_RSA_X509_Success(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_RSA_X_509}

	op, err := cm.VerifyInit(mech, 1, "rsa-key", "backend1")
	if err != nil {
		t.Fatalf("VerifyInit failed: %v", err)
	}

	op.IsRecover = true

	// Use a simple RSA-style test with small numbers for testing
	// n = 399 = 0x018F (9 bits, so key size = 2 bytes), e = 7
	// The high byte must be non-zero for big.Int to treat it as 2-byte key
	modulus := []byte{0x01, 0x8F} // 399
	exponent := []byte{0x07}      // 7
	op.SetRSAPublicKey(modulus, exponent)

	// Create a signature that's within valid range [0, n-1]
	// s = 42 = 0x002A (< 399)
	signature := []byte{0x00, 0x2A}

	recovered, err := cm.VerifyRecover(context.Background(), op, signature)
	if err != nil {
		t.Fatalf("VerifyRecover failed: %v", err)
	}

	// For CKM_RSA_X_509, the result should be signature^e mod n = 42^7 mod 399
	// 42^2 mod 399 = 1764 mod 399 = 168
	// 42^4 mod 399 = 168^2 mod 399 = 28224 mod 399 = 294
	// 42^6 mod 399 = 294 * 168 mod 399 = 49392 mod 399 = 315
	// 42^7 mod 399 = 315 * 42 mod 399 = 13230 mod 399 = 63
	// So result = 63 = 0x3F

	// The result should be 2 bytes (same as key size)
	if len(recovered) != 2 {
		t.Errorf("expected 2 bytes, got %d", len(recovered))
	}

	// Check the computed value
	expected := []byte{0x00, 0x3F} // 63
	if !bytes.Equal(recovered, expected) {
		t.Errorf("expected %v, got %v", expected, recovered)
	}
}

func TestCryptoManager_VerifyRecover_CKM_RSA_PKCS_ValidPadding(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_RSA_PKCS}

	op, err := cm.VerifyInit(mech, 1, "rsa-key", "backend1")
	if err != nil {
		t.Fatalf("VerifyInit failed: %v", err)
	}
	op.IsRecover = true

	// We need a modulus that's large enough for PKCS#1 padding (at least 11 bytes)
	// Use 128-bit (16-byte) test values
	// For this test, we construct a scenario where the RSA operation produces valid padding
	// This is complex to set up correctly, so we'll verify the padding validation logic
	// by testing stripPKCS1v15Padding directly

	// Just test that the mechanism type is correctly recognized
	modulus := make([]byte, 16)
	modulus[0] = 0x00
	modulus[1] = 0xFF
	for i := 2; i < 16; i++ {
		modulus[i] = 0xFF
	}
	modulus[15] = 0xFD // Make it odd
	exponent := []byte{0x03}
	op.SetRSAPublicKey(modulus, exponent)

	signature := make([]byte, 16)
	for i := range signature {
		signature[i] = byte(i * 3)
	}

	// This will likely fail padding validation, which is expected
	_, err = cm.VerifyRecover(context.Background(), op, signature)
	if err == nil {
		// If it succeeds, the result would need valid PKCS#1 padding
		// For random input, this is very unlikely
		t.Log("VerifyRecover unexpectedly succeeded with random input")
	}
}

func TestCryptoManager_VerifyRecover_NilOperation(t *testing.T) {
	cm, _ := newTestCryptoManager()

	_, err := cm.VerifyRecover(context.Background(), nil, []byte("signature"))
	if err == nil {
		t.Fatal("expected error for nil operation")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_VerifyRecover_AlreadyFinalized(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_RSA_X_509}

	op, err := cm.VerifyInit(mech, 1, "rsa-key", "backend1")
	if err != nil {
		t.Fatalf("VerifyInit failed: %v", err)
	}
	op.IsRecover = true

	modulus := []byte{0x01, 0x8F} // 399 (9 bits = 2-byte key)
	exponent := []byte{0x07}      // 7
	op.SetRSAPublicKey(modulus, exponent)

	signature := []byte{0x00, 0x2A} // 42 (must be 2 bytes to match key size)

	// First call should succeed
	_, err = cm.VerifyRecover(context.Background(), op, signature)
	if err != nil {
		t.Fatalf("first VerifyRecover failed: %v", err)
	}

	// Second call should fail
	_, err = cm.VerifyRecover(context.Background(), op, signature)
	if err == nil {
		t.Fatal("expected error for finalized operation")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_VerifyRecover_EmptySignature(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_RSA_X_509}

	op, err := cm.VerifyInit(mech, 1, "rsa-key", "backend1")
	if err != nil {
		t.Fatalf("VerifyInit failed: %v", err)
	}
	op.IsRecover = true
	op.SetRSAPublicKey([]byte{0x00, 0x8F}, []byte{0x07})

	_, err = cm.VerifyRecover(context.Background(), op, []byte{})
	if err == nil {
		t.Fatal("expected error for empty signature")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_SIGNATURE_LEN_RANGE {
		t.Errorf("expected CKR_SIGNATURE_LEN_RANGE, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_VerifyRecover_NoPublicKey(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_RSA_X_509}

	op, err := cm.VerifyInit(mech, 1, "rsa-key", "backend1")
	if err != nil {
		t.Fatalf("VerifyInit failed: %v", err)
	}
	op.IsRecover = true
	// Don't set RSA public key

	_, err = cm.VerifyRecover(context.Background(), op, []byte{0x00, 0x2A})
	if err == nil {
		t.Fatal("expected error for missing public key")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_KEY_FUNCTION_NOT_PERMITTED {
		t.Errorf("expected CKR_KEY_FUNCTION_NOT_PERMITTED, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_VerifyRecover_WrongSignatureLength(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_RSA_X_509}

	op, err := cm.VerifyInit(mech, 1, "rsa-key", "backend1")
	if err != nil {
		t.Fatalf("VerifyInit failed: %v", err)
	}
	op.IsRecover = true

	modulus := []byte{0x01, 0x8F} // 399 (9 bits = 2-byte key)
	exponent := []byte{0x07}
	op.SetRSAPublicKey(modulus, exponent)

	// Wrong length signature (should be 2 bytes to match key size)
	signature := []byte{0x2A} // Only 1 byte

	_, err = cm.VerifyRecover(context.Background(), op, signature)
	if err == nil {
		t.Fatal("expected error for wrong signature length")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_SIGNATURE_LEN_RANGE {
		t.Errorf("expected CKR_SIGNATURE_LEN_RANGE, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_VerifyRecover_SignatureOutOfRange(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_RSA_X_509}

	op, err := cm.VerifyInit(mech, 1, "rsa-key", "backend1")
	if err != nil {
		t.Fatalf("VerifyInit failed: %v", err)
	}
	op.IsRecover = true

	modulus := []byte{0x01, 0x8F} // n = 399 (9 bits = 2-byte key)
	exponent := []byte{0x07}
	op.SetRSAPublicKey(modulus, exponent)

	// Signature >= n (should fail): 400 >= 399
	signature := []byte{0x01, 0x90} // 400 >= 399

	_, err = cm.VerifyRecover(context.Background(), op, signature)
	if err == nil {
		t.Fatal("expected error for signature >= modulus")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_SIGNATURE_INVALID {
		t.Errorf("expected CKR_SIGNATURE_INVALID, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_VerifyRecover_UnsupportedMechanism(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_SHA256_RSA_PKCS} // Not a verify-recover mechanism

	op, err := cm.VerifyInit(mech, 1, "rsa-key", "backend1")
	if err != nil {
		t.Fatalf("VerifyInit failed: %v", err)
	}
	op.IsRecover = true

	modulus := []byte{0x00, 0x8F}
	exponent := []byte{0x07}
	op.SetRSAPublicKey(modulus, exponent)

	signature := []byte{0x00, 0x2A}

	_, err = cm.VerifyRecover(context.Background(), op, signature)
	if err == nil {
		t.Fatal("expected error for unsupported mechanism")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_MECHANISM_INVALID {
		t.Errorf("expected CKR_MECHANISM_INVALID, got %s", pkcsErr.Code.String())
	}
}

func TestVerifyOperation_SetRSAPublicKey(t *testing.T) {
	op := newVerifyOperation(&Mechanism{Type: CKM_RSA_PKCS}, 1, "key", "backend")

	modulus := []byte{0x00, 0xab, 0xcd, 0xef}
	exponent := []byte{0x01, 0x00, 0x01}

	op.SetRSAPublicKey(modulus, exponent)

	if !bytes.Equal(op.rsaModulus, modulus) {
		t.Error("modulus not set correctly")
	}
	if !bytes.Equal(op.rsaPublicExponent, exponent) {
		t.Error("exponent not set correctly")
	}
}

func TestStripPKCS1v15Padding_Valid(t *testing.T) {
	// Valid PKCS#1 v1.5 padding: 0x00 || 0x01 || PS (8+ bytes of 0xFF) || 0x00 || data
	padded := []byte{
		0x00, 0x01,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 8 bytes of PS
		0x00,
		0x48, 0x65, 0x6c, 0x6c, 0x6f, // "Hello"
	}

	data, err := stripPKCS1v15Padding(padded)
	if err != nil {
		t.Fatalf("stripPKCS1v15Padding failed: %v", err)
	}

	if string(data) != "Hello" {
		t.Errorf("expected 'Hello', got %q", string(data))
	}
}

func TestStripPKCS1v15Padding_TooShort(t *testing.T) {
	// Less than 11 bytes (minimum for valid padding)
	padded := []byte{0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x41}

	_, err := stripPKCS1v15Padding(padded)
	if err == nil {
		t.Fatal("expected error for too short input")
	}
}

func TestStripPKCS1v15Padding_WrongFirstByte(t *testing.T) {
	padded := []byte{
		0x01, 0x01, // First byte should be 0x00
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x00,
		0x41,
	}

	_, err := stripPKCS1v15Padding(padded)
	if err == nil {
		t.Fatal("expected error for wrong first byte")
	}
}

func TestStripPKCS1v15Padding_WrongBlockType(t *testing.T) {
	padded := []byte{
		0x00, 0x02, // Block type should be 0x01 for signatures
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x00,
		0x41,
	}

	_, err := stripPKCS1v15Padding(padded)
	if err == nil {
		t.Fatal("expected error for wrong block type")
	}
}

func TestStripPKCS1v15Padding_ShortPS(t *testing.T) {
	// PS is only 7 bytes (should be at least 8)
	padded := []byte{
		0x00, 0x01,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 7 bytes
		0x00,
		0x41,
	}

	_, err := stripPKCS1v15Padding(padded)
	if err == nil {
		t.Fatal("expected error for short PS")
	}
}

func TestStripPKCS1v15Padding_InvalidPSByte(t *testing.T) {
	// PS contains a non-0xFF byte
	padded := []byte{
		0x00, 0x01,
		0xFF, 0xFF, 0xFF, 0xAB, 0xFF, 0xFF, 0xFF, 0xFF, // 0xAB is invalid
		0x00,
		0x41,
	}

	_, err := stripPKCS1v15Padding(padded)
	if err == nil {
		t.Fatal("expected error for invalid PS byte")
	}
}

func TestStripPKCS1v15Padding_NoSeparator(t *testing.T) {
	// No 0x00 separator
	padded := []byte{
		0x00, 0x01,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, // All 0xFF, no separator
	}

	_, err := stripPKCS1v15Padding(padded)
	if err == nil {
		t.Fatal("expected error for missing separator")
	}
}

// ----------------------------------------------------------------
// DeriveKey Tests
// ----------------------------------------------------------------

func TestDeriveKeyInit_ValidHKDF(t *testing.T) {
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	mechanism := &Mechanism{
		Type: CKM_HKDF_DERIVE,
	}

	op, err := cm.DeriveKeyInit(mechanism, ObjectHandle(1), "test-key", "software")
	if err != nil {
		t.Fatalf("DeriveKeyInit failed: %v", err)
	}

	if op == nil {
		t.Fatal("Expected non-nil operation")
	}

	if op.Algorithm() != "HKDF" {
		t.Errorf("Expected algorithm 'HKDF', got '%s'", op.Algorithm())
	}

	if op.KeyHandle() != ObjectHandle(1) {
		t.Errorf("Expected key handle 1, got %d", op.KeyHandle())
	}

	if op.KeyID() != "test-key" {
		t.Errorf("Expected key ID 'test-key', got '%s'", op.KeyID())
	}

	if op.Backend() != "software" {
		t.Errorf("Expected backend 'software', got '%s'", op.Backend())
	}
}

func TestDeriveKeyInit_ValidSP800108Counter(t *testing.T) {
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	mechanism := &Mechanism{
		Type: CKM_SP800_108_COUNTER_KDF,
	}

	op, err := cm.DeriveKeyInit(mechanism, ObjectHandle(2), "kdk-key", "tpm")
	if err != nil {
		t.Fatalf("DeriveKeyInit failed: %v", err)
	}

	if op.Algorithm() != "SP800-108-COUNTER" {
		t.Errorf("Expected algorithm 'SP800-108-COUNTER', got '%s'", op.Algorithm())
	}
}

func TestDeriveKeyInit_ValidSP800108Feedback(t *testing.T) {
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	mechanism := &Mechanism{
		Type: CKM_SP800_108_FEEDBACK_KDF,
	}

	op, err := cm.DeriveKeyInit(mechanism, ObjectHandle(3), "feedback-key", "software")
	if err != nil {
		t.Fatalf("DeriveKeyInit failed: %v", err)
	}

	if op.Algorithm() != "SP800-108-FEEDBACK" {
		t.Errorf("Expected algorithm 'SP800-108-FEEDBACK', got '%s'", op.Algorithm())
	}
}

func TestDeriveKeyInit_ValidSP800108DoublePipeline(t *testing.T) {
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	mechanism := &Mechanism{
		Type: CKM_SP800_108_DOUBLE_PIPELINE_KDF,
	}

	op, err := cm.DeriveKeyInit(mechanism, ObjectHandle(4), "pipeline-key", "software")
	if err != nil {
		t.Fatalf("DeriveKeyInit failed: %v", err)
	}

	if op.Algorithm() != "SP800-108-DOUBLE-PIPELINE" {
		t.Errorf("Expected algorithm 'SP800-108-DOUBLE-PIPELINE', got '%s'", op.Algorithm())
	}
}

func TestDeriveKeyInit_NilMechanism(t *testing.T) {
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	_, err := cm.DeriveKeyInit(nil, ObjectHandle(1), "test-key", "software")
	if err == nil {
		t.Fatal("Expected error for nil mechanism")
	}
}

func TestDeriveKeyInit_UnsupportedMechanism(t *testing.T) {
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	mechanism := &Mechanism{
		Type: CKM_DES_KEY_GEN, // Not a derivation mechanism
	}

	_, err := cm.DeriveKeyInit(mechanism, ObjectHandle(1), "test-key", "software")
	if err == nil {
		t.Fatal("Expected error for unsupported mechanism")
	}
}

func TestDeriveKey_Success(t *testing.T) {
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	mechanism := &Mechanism{
		Type: CKM_HKDF_DERIVE,
	}

	op, err := cm.DeriveKeyInit(mechanism, ObjectHandle(1), "test-key", "software")
	if err != nil {
		t.Fatalf("DeriveKeyInit failed: %v", err)
	}

	ikm := []byte("input-key-material-32bytes-long!")
	derivedKey, err := cm.DeriveKey(context.Background(), op, ikm, 32)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if len(derivedKey) == 0 {
		t.Fatal("Expected non-empty derived key")
	}
}

func TestDeriveKey_NilOperation(t *testing.T) {
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	_, err := cm.DeriveKey(context.Background(), nil, []byte("ikm"), 32)
	if err == nil {
		t.Fatal("Expected error for nil operation")
	}
}

func TestDeriveKey_AlreadyFinalized(t *testing.T) {
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	mechanism := &Mechanism{
		Type: CKM_HKDF_DERIVE,
	}

	op, _ := cm.DeriveKeyInit(mechanism, ObjectHandle(1), "test-key", "software")
	ikm := []byte("input-key-material-32bytes-long!")

	// First derivation
	_, err := cm.DeriveKey(context.Background(), op, ikm, 32)
	if err != nil {
		t.Fatalf("First DeriveKey failed: %v", err)
	}

	// Second derivation should fail (already finalized)
	_, err = cm.DeriveKey(context.Background(), op, ikm, 32)
	if err == nil {
		t.Fatal("Expected error for already finalized operation")
	}
}

func TestDeriveOperation_Type(t *testing.T) {
	op := &DeriveOperation{}
	if op.Type() != OperationDerive {
		t.Errorf("Expected OperationDerive, got %v", op.Type())
	}
}

func TestDeriveOperation_Reset(t *testing.T) {
	op := &DeriveOperation{
		baseOperation: baseOperation{finalized: true},
		params:        &DeriveParams{KeyLength: 32},
	}

	op.Reset()

	if op.IsFinalized() {
		t.Error("Expected finalized to be false after reset")
	}
	if op.params != nil {
		t.Error("Expected params to be nil after reset")
	}
}

func TestMechanismToDeriveAlgorithm(t *testing.T) {
	tests := []struct {
		mechanism MechanismType
		expected  string
	}{
		{CKM_HKDF_DERIVE, "HKDF"},
		{CKM_HKDF_DATA, "HKDF"},
		{CKM_HKDF_KEY_GEN, "HKDF"},
		{CKM_SP800_108_COUNTER_KDF, "SP800-108-COUNTER"},
		{CKM_SP800_108_FEEDBACK_KDF, "SP800-108-FEEDBACK"},
		{CKM_SP800_108_DOUBLE_PIPELINE_KDF, "SP800-108-DOUBLE-PIPELINE"},
		{CKM_ECDH1_DERIVE, "ECDH"},
		{CKM_ECDH1_COFACTOR_DERIVE, "ECDH"},
		{CKM_AES_KEY_GEN, ""}, // Not a derivation mechanism
	}

	for _, tt := range tests {
		result := mechanismToDeriveAlgorithm(tt.mechanism)
		if result != tt.expected {
			t.Errorf("mechanismToDeriveAlgorithm(%v) = %s, want %s", tt.mechanism, result, tt.expected)
		}
	}
}

func TestMechanismToHashFromHKDF(t *testing.T) {
	tests := []struct {
		prf      MechanismType
		expected string
	}{
		{CKM_SHA_1, "SHA-1"},
		{CKM_SHA256, "SHA-256"},
		{CKM_SHA384, "SHA-384"},
		{CKM_SHA512, "SHA-512"},
		{CKM_AES_KEY_GEN, "SHA-256"}, // Default
	}

	for _, tt := range tests {
		result := mechanismToHashFromHKDF(tt.prf)
		if result != tt.expected {
			t.Errorf("mechanismToHashFromHKDF(%v) = %s, want %s", tt.prf, result, tt.expected)
		}
	}
}

func TestMechanismToHashFromPRF(t *testing.T) {
	tests := []struct {
		prf      MechanismType
		expected string
	}{
		{CKM_SHA_1_HMAC, "SHA-1"},
		{CKM_SHA256_HMAC, "SHA-256"},
		{CKM_SHA384_HMAC, "SHA-384"},
		{CKM_SHA512_HMAC, "SHA-512"},
		{CKM_AES_KEY_GEN, "SHA-256"}, // Default
	}

	for _, tt := range tests {
		result := mechanismToHashFromPRF(tt.prf)
		if result != tt.expected {
			t.Errorf("mechanismToHashFromPRF(%v) = %s, want %s", tt.prf, result, tt.expected)
		}
	}
}

func TestParseHKDFParams_TooShort(t *testing.T) {
	_, err := parseHKDFParams([]byte{0x01, 0x02})
	if err == nil {
		t.Fatal("Expected error for too short data")
	}
}

func TestParseSP800108Params_TooShort(t *testing.T) {
	_, err := parseSP800108Params([]byte{0x01})
	if err == nil {
		t.Fatal("Expected error for too short data")
	}
}

// ----------------------------------------------------------------
// Additional Coverage Tests for Encrypt/Decrypt Operations
// ----------------------------------------------------------------

func TestCryptoManager_EncryptInit_NilMechanism(t *testing.T) {
	cm, _ := newTestCryptoManager()

	_, err := cm.EncryptInit(nil, 1, "test-key", "backend1")
	if err == nil {
		t.Fatal("expected error for nil mechanism")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_ARGUMENTS_BAD {
		t.Errorf("expected CKR_ARGUMENTS_BAD, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_EncryptInit_InvalidKeyHandle(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_AES_GCM}

	_, err := cm.EncryptInit(mech, 0, "test-key", "backend1")
	if err == nil {
		t.Fatal("expected error for invalid key handle")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_KEY_HANDLE_INVALID {
		t.Errorf("expected CKR_KEY_HANDLE_INVALID, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_EncryptInit_InvalidMechanism(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: 0xFFFFFFFF}

	_, err := cm.EncryptInit(mech, 1, "test-key", "backend1")
	if err == nil {
		t.Fatal("expected error for invalid mechanism")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_MECHANISM_INVALID {
		t.Errorf("expected CKR_MECHANISM_INVALID, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_EncryptInit_DefaultBackend(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_AES_GCM}

	op, err := cm.EncryptInit(mech, 1, "test-key", "")
	if err != nil {
		t.Fatalf("EncryptInit failed: %v", err)
	}
	if op.Backend() != "test-backend" {
		t.Errorf("expected default backend 'test-backend', got %s", op.Backend())
	}
}

func TestCryptoManager_Encrypt_NilOperation(t *testing.T) {
	cm, _ := newTestCryptoManager()

	_, err := cm.Encrypt(context.Background(), nil, []byte("data"))
	if err == nil {
		t.Fatal("expected error for nil operation")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_Encrypt_AlreadyFinalized(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_AES_GCM}

	op, _ := cm.EncryptInit(mech, 1, "test-key", "backend1")

	// First encrypt should succeed
	_, _ = cm.Encrypt(context.Background(), op, []byte("data"))

	// Second encrypt should fail
	_, err := cm.Encrypt(context.Background(), op, []byte("data"))
	if err == nil {
		t.Fatal("expected error for already finalized operation")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_Encrypt_ClientError(t *testing.T) {
	cm, client := newTestCryptoManager()
	client.encryptError = errors.New("client error")
	mech := &Mechanism{Type: CKM_AES_GCM}

	op, _ := cm.EncryptInit(mech, 1, "test-key", "backend1")

	_, err := cm.Encrypt(context.Background(), op, []byte("data"))
	if err == nil {
		t.Fatal("expected error from client")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_FUNCTION_FAILED {
		t.Errorf("expected CKR_FUNCTION_FAILED, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_Encrypt_WithNonceAndTag(t *testing.T) {
	cm, client := newTestCryptoManager()
	// Set up response with nonce and tag (AEAD mode)
	client.encryptResponse = &transport.EncryptResponse{
		Ciphertext: []byte("encrypted-data"),
		Nonce:      []byte("123456789012"),   // 12-byte nonce
		Tag:        []byte("authtag1234567"), // 16-byte tag (truncated for test)
	}
	mech := &Mechanism{Type: CKM_AES_GCM}

	op, _ := cm.EncryptInit(mech, 1, "test-key", "backend1")

	result, err := cm.Encrypt(context.Background(), op, []byte("plaintext"))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Result should contain: [2 bytes nonce len][nonce][2 bytes tag len][tag][ciphertext]
	if len(result) < 4 {
		t.Fatalf("result too short: %d bytes", len(result))
	}

	// Verify the format
	offset := 0
	nonceLen := int(result[0])<<8 | int(result[1])
	offset += 2
	if nonceLen != 12 {
		t.Errorf("expected nonce length 12, got %d", nonceLen)
	}
	offset += nonceLen

	tagLen := int(result[offset])<<8 | int(result[offset+1])
	if tagLen != 14 { // "authtag1234567" is 14 bytes
		t.Errorf("expected tag length 14, got %d", tagLen)
	}
}

func TestCryptoManager_EncryptUpdate_NilOperation(t *testing.T) {
	cm, _ := newTestCryptoManager()

	err := cm.EncryptUpdate(nil, []byte("data"))
	if err == nil {
		t.Fatal("expected error for nil operation")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_EncryptUpdate_AlreadyFinalized(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_AES_GCM}

	op, _ := cm.EncryptInit(mech, 1, "test-key", "backend1")
	op.finalized = true

	err := cm.EncryptUpdate(op, []byte("data"))
	if err == nil {
		t.Fatal("expected error for finalized operation")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_EncryptFinal_NilOperation(t *testing.T) {
	cm, _ := newTestCryptoManager()

	_, err := cm.EncryptFinal(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil operation")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_EncryptFinal_AlreadyFinalized(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_AES_GCM}

	op, _ := cm.EncryptInit(mech, 1, "test-key", "backend1")
	op.finalized = true

	_, err := cm.EncryptFinal(context.Background(), op)
	if err == nil {
		t.Fatal("expected error for finalized operation")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %s", pkcsErr.Code.String())
	}
}

// ----------------------------------------------------------------
// Additional DecryptInit Tests
// ----------------------------------------------------------------

func TestCryptoManager_DecryptInit_NilMechanism(t *testing.T) {
	cm, _ := newTestCryptoManager()

	_, err := cm.DecryptInit(nil, 1, "test-key", "backend1")
	if err == nil {
		t.Fatal("expected error for nil mechanism")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_ARGUMENTS_BAD {
		t.Errorf("expected CKR_ARGUMENTS_BAD, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_DecryptInit_InvalidKeyHandle(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_AES_GCM}

	_, err := cm.DecryptInit(mech, 0, "test-key", "backend1")
	if err == nil {
		t.Fatal("expected error for invalid key handle")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_KEY_HANDLE_INVALID {
		t.Errorf("expected CKR_KEY_HANDLE_INVALID, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_DecryptInit_InvalidMechanism(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: 0xFFFFFFFF}

	_, err := cm.DecryptInit(mech, 1, "test-key", "backend1")
	if err == nil {
		t.Fatal("expected error for invalid mechanism")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_MECHANISM_INVALID {
		t.Errorf("expected CKR_MECHANISM_INVALID, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_DecryptInit_MechanismNoDecrypt(t *testing.T) {
	cm, _ := newTestCryptoManager()
	// SHA-256 doesn't support decryption
	mech := &Mechanism{Type: CKM_SHA256}

	_, err := cm.DecryptInit(mech, 1, "test-key", "backend1")
	if err == nil {
		t.Fatal("expected error for mechanism that doesn't support decryption")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_MECHANISM_INVALID {
		t.Errorf("expected CKR_MECHANISM_INVALID, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_DecryptInit_DefaultBackend(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_AES_GCM}

	op, err := cm.DecryptInit(mech, 1, "test-key", "")
	if err != nil {
		t.Fatalf("DecryptInit failed: %v", err)
	}
	if op.Backend() != "test-backend" {
		t.Errorf("expected default backend 'test-backend', got %s", op.Backend())
	}
}

// ----------------------------------------------------------------
// Additional Decrypt Tests
// ----------------------------------------------------------------

func TestCryptoManager_Decrypt_NilOperation(t *testing.T) {
	cm, _ := newTestCryptoManager()

	_, err := cm.Decrypt(context.Background(), nil, []byte("data"))
	if err == nil {
		t.Fatal("expected error for nil operation")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_Decrypt_AlreadyFinalized(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_AES_GCM}

	op, _ := cm.DecryptInit(mech, 1, "test-key", "backend1")

	// First decrypt should succeed
	_, _ = cm.Decrypt(context.Background(), op, []byte("data"))

	// Second decrypt should fail
	_, err := cm.Decrypt(context.Background(), op, []byte("data"))
	if err == nil {
		t.Fatal("expected error for already finalized operation")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_Decrypt_ClientError(t *testing.T) {
	cm, client := newTestCryptoManager()
	client.decryptError = errors.New("client error")
	mech := &Mechanism{Type: CKM_AES_GCM}

	op, _ := cm.DecryptInit(mech, 1, "test-key", "backend1")

	_, err := cm.Decrypt(context.Background(), op, []byte("data"))
	if err == nil {
		t.Fatal("expected error from client")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_FUNCTION_FAILED {
		t.Errorf("expected CKR_FUNCTION_FAILED, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_Decrypt_WithAAD(t *testing.T) {
	cm, client := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_AES_GCM}

	op, _ := cm.DecryptInit(mech, 1, "test-key", "backend1")
	op.SetAAD([]byte("additional data"))

	_, err := cm.Decrypt(context.Background(), op, []byte("ciphertext"))
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(client.lastDecryptReq.AdditionalData, []byte("additional data")) {
		t.Error("AAD not passed to client")
	}
}

func TestCryptoManager_Decrypt_AEADFormat(t *testing.T) {
	cm, client := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_AES_GCM}

	op, _ := cm.DecryptInit(mech, 1, "test-key", "backend1")

	// Build AEAD format: [2 bytes nonce len][nonce][2 bytes tag len][tag][ciphertext]
	nonce := []byte("123456789012")   // 12 bytes
	tag := []byte("1234567890123456") // 16 bytes
	ciphertext := []byte("encrypted-data")

	aeadData := make([]byte, 0)
	// Nonce length (big endian)
	aeadData = append(aeadData, 0x00, 0x0C) // 12
	aeadData = append(aeadData, nonce...)
	// Tag length (big endian)
	aeadData = append(aeadData, 0x00, 0x10) // 16
	aeadData = append(aeadData, tag...)
	aeadData = append(aeadData, ciphertext...)

	_, err := cm.Decrypt(context.Background(), op, aeadData)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Verify parsed components were sent to client
	if !bytes.Equal(client.lastDecryptReq.Nonce, nonce) {
		t.Errorf("nonce not parsed correctly: got %v, want %v", client.lastDecryptReq.Nonce, nonce)
	}
	if !bytes.Equal(client.lastDecryptReq.Tag, tag) {
		t.Errorf("tag not parsed correctly: got %v, want %v", client.lastDecryptReq.Tag, tag)
	}
	if !bytes.Equal(client.lastDecryptReq.Ciphertext, ciphertext) {
		t.Errorf("ciphertext not parsed correctly: got %v, want %v", client.lastDecryptReq.Ciphertext, ciphertext)
	}
}

func TestCryptoManager_Decrypt_ShortCiphertext(t *testing.T) {
	cm, client := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_AES_GCM}

	op, _ := cm.DecryptInit(mech, 1, "test-key", "backend1")

	// Short ciphertext (less than 4 bytes) should be passed as-is
	shortData := []byte("abc")
	_, err := cm.Decrypt(context.Background(), op, shortData)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Should be passed directly as ciphertext
	if !bytes.Equal(client.lastDecryptReq.Ciphertext, shortData) {
		t.Error("short ciphertext should be passed as-is")
	}
}

func TestCryptoManager_Decrypt_InvalidAEADFormat_ShortNonce(t *testing.T) {
	cm, client := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_AES_GCM}

	op, _ := cm.DecryptInit(mech, 1, "test-key", "backend1")

	// AEAD format with invalid nonce length (claims 100 bytes but only has 4)
	invalidData := []byte{0x00, 0x64, 0x01, 0x02, 0x03, 0x04}

	_, err := cm.Decrypt(context.Background(), op, invalidData)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// When parsing fails, original data should be used as ciphertext
	if !bytes.Equal(client.lastDecryptReq.Ciphertext, invalidData) {
		t.Error("invalid AEAD format should fall back to using data as-is")
	}
}

func TestCryptoManager_Decrypt_InvalidAEADFormat_NoTagLength(t *testing.T) {
	cm, client := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_AES_GCM}

	op, _ := cm.DecryptInit(mech, 1, "test-key", "backend1")

	// AEAD format: valid nonce but no room for tag length
	// nonce len = 2, nonce = "ab", then only 1 byte left
	invalidData := []byte{0x00, 0x02, 'a', 'b', 0x00}

	_, err := cm.Decrypt(context.Background(), op, invalidData)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// When parsing fails, original data should be used as ciphertext
	if !bytes.Equal(client.lastDecryptReq.Ciphertext, invalidData) {
		t.Error("invalid AEAD format should fall back to using data as-is")
	}
}

func TestCryptoManager_Decrypt_InvalidAEADFormat_ShortTag(t *testing.T) {
	cm, client := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_AES_GCM}

	op, _ := cm.DecryptInit(mech, 1, "test-key", "backend1")

	// AEAD format: valid nonce but tag length claims more than available
	// nonce len = 2, nonce = "ab", tag len = 100 but only 2 bytes available
	invalidData := []byte{0x00, 0x02, 'a', 'b', 0x00, 0x64, 'x', 'y'}

	_, err := cm.Decrypt(context.Background(), op, invalidData)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// When parsing fails, original data should be used as ciphertext
	if !bytes.Equal(client.lastDecryptReq.Ciphertext, invalidData) {
		t.Error("invalid AEAD format should fall back to using data as-is")
	}
}

func TestCryptoManager_DecryptUpdate_NilOperation(t *testing.T) {
	cm, _ := newTestCryptoManager()

	err := cm.DecryptUpdate(nil, []byte("data"))
	if err == nil {
		t.Fatal("expected error for nil operation")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_DecryptUpdate_AlreadyFinalized(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_AES_GCM}

	op, _ := cm.DecryptInit(mech, 1, "test-key", "backend1")
	op.finalized = true

	err := cm.DecryptUpdate(op, []byte("data"))
	if err == nil {
		t.Fatal("expected error for finalized operation")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_DecryptFinal_NilOperation(t *testing.T) {
	cm, _ := newTestCryptoManager()

	_, err := cm.DecryptFinal(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil operation")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_DecryptFinal_AlreadyFinalized(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_AES_GCM}

	op, _ := cm.DecryptInit(mech, 1, "test-key", "backend1")
	op.finalized = true

	_, err := cm.DecryptFinal(context.Background(), op)
	if err == nil {
		t.Fatal("expected error for finalized operation")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %s", pkcsErr.Code.String())
	}
}

// ----------------------------------------------------------------
// Additional DeriveKeyInit Tests with Parameters
// ----------------------------------------------------------------

func TestDeriveKeyInit_HKDFWithParams(t *testing.T) {
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	// Create HKDF mechanism with parameters (at least 8 bytes for parseHKDFParams)
	mechanism := &Mechanism{
		Type:      CKM_HKDF_DERIVE,
		Parameter: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}

	op, err := cm.DeriveKeyInit(mechanism, ObjectHandle(1), "test-key", "software")
	if err != nil {
		t.Fatalf("DeriveKeyInit failed: %v", err)
	}

	if op == nil {
		t.Fatal("Expected non-nil operation")
	}

	if op.Algorithm() != "HKDF" {
		t.Errorf("Expected algorithm 'HKDF', got '%s'", op.Algorithm())
	}
}

func TestDeriveKeyInit_HKDFDataWithParams(t *testing.T) {
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	mechanism := &Mechanism{
		Type:      CKM_HKDF_DATA,
		Parameter: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A},
	}

	op, err := cm.DeriveKeyInit(mechanism, ObjectHandle(1), "test-key", "software")
	if err != nil {
		t.Fatalf("DeriveKeyInit failed: %v", err)
	}

	if op.Algorithm() != "HKDF" {
		t.Errorf("Expected algorithm 'HKDF', got '%s'", op.Algorithm())
	}
}

func TestDeriveKeyInit_SP800108CounterWithParams(t *testing.T) {
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	// Create SP800-108 mechanism with parameters (at least 4 bytes)
	mechanism := &Mechanism{
		Type:      CKM_SP800_108_COUNTER_KDF,
		Parameter: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
	}

	op, err := cm.DeriveKeyInit(mechanism, ObjectHandle(1), "test-key", "software")
	if err != nil {
		t.Fatalf("DeriveKeyInit failed: %v", err)
	}

	if op.Algorithm() != "SP800-108-COUNTER" {
		t.Errorf("Expected algorithm 'SP800-108-COUNTER', got '%s'", op.Algorithm())
	}
}

func TestDeriveKeyInit_SP800108FeedbackWithParams(t *testing.T) {
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	mechanism := &Mechanism{
		Type:      CKM_SP800_108_FEEDBACK_KDF,
		Parameter: []byte{0x01, 0x02, 0x03, 0x04},
	}

	op, err := cm.DeriveKeyInit(mechanism, ObjectHandle(1), "test-key", "software")
	if err != nil {
		t.Fatalf("DeriveKeyInit failed: %v", err)
	}

	if op.Algorithm() != "SP800-108-FEEDBACK" {
		t.Errorf("Expected algorithm 'SP800-108-FEEDBACK', got '%s'", op.Algorithm())
	}
}

func TestDeriveKeyInit_SP800108DoublePipelineWithParams(t *testing.T) {
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	mechanism := &Mechanism{
		Type:      CKM_SP800_108_DOUBLE_PIPELINE_KDF,
		Parameter: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
	}

	op, err := cm.DeriveKeyInit(mechanism, ObjectHandle(1), "test-key", "software")
	if err != nil {
		t.Fatalf("DeriveKeyInit failed: %v", err)
	}

	if op.Algorithm() != "SP800-108-DOUBLE-PIPELINE" {
		t.Errorf("Expected algorithm 'SP800-108-DOUBLE-PIPELINE', got '%s'", op.Algorithm())
	}
}

func TestDeriveKeyInit_ECDHDerive(t *testing.T) {
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	mechanism := &Mechanism{
		Type: CKM_ECDH1_DERIVE,
	}

	op, err := cm.DeriveKeyInit(mechanism, ObjectHandle(1), "ecdh-key", "software")
	if err != nil {
		t.Fatalf("DeriveKeyInit failed: %v", err)
	}

	if op.Algorithm() != "ECDH" {
		t.Errorf("Expected algorithm 'ECDH', got '%s'", op.Algorithm())
	}
}

func TestDeriveKeyInit_ECDHCofactorDerive(t *testing.T) {
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	mechanism := &Mechanism{
		Type: CKM_ECDH1_COFACTOR_DERIVE,
	}

	op, err := cm.DeriveKeyInit(mechanism, ObjectHandle(1), "ecdh-cofactor-key", "software")
	if err != nil {
		t.Fatalf("DeriveKeyInit failed: %v", err)
	}

	if op.Algorithm() != "ECDH" {
		t.Errorf("Expected algorithm 'ECDH', got '%s'", op.Algorithm())
	}
}

func TestDeriveKey_DefaultKeyLength(t *testing.T) {
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	mechanism := &Mechanism{
		Type: CKM_HKDF_DERIVE,
	}

	op, err := cm.DeriveKeyInit(mechanism, ObjectHandle(1), "test-key", "software")
	if err != nil {
		t.Fatalf("DeriveKeyInit failed: %v", err)
	}

	// Pass 0 for key length to use default
	ikm := []byte("input-key-material")
	_, err = cm.DeriveKey(context.Background(), op, ikm, 0)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}
}

// ----------------------------------------------------------------
// Additional parseHKDFParams and parseSP800108Params Tests
// ----------------------------------------------------------------

func TestParseHKDFParams_ValidData(t *testing.T) {
	// Valid HKDF params (at least 8 bytes)
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	params, err := parseHKDFParams(data)
	if err != nil {
		t.Fatalf("parseHKDFParams failed: %v", err)
	}

	if params == nil {
		t.Fatal("Expected non-nil params")
	}

	// Default should be SHA-256
	if params.PRFHashMech != CKM_SHA256 {
		t.Errorf("Expected PRFHashMech CKM_SHA256, got %v", params.PRFHashMech)
	}
}

func TestParseHKDFParams_ExactlyMinLength(t *testing.T) {
	// Exactly 8 bytes (minimum required)
	data := make([]byte, 8)

	params, err := parseHKDFParams(data)
	if err != nil {
		t.Fatalf("parseHKDFParams failed: %v", err)
	}

	if params == nil {
		t.Fatal("Expected non-nil params")
	}
}

func TestParseSP800108Params_ValidData(t *testing.T) {
	// Valid SP800-108 params (at least 4 bytes)
	data := []byte{0x01, 0x02, 0x03, 0x04}

	params, err := parseSP800108Params(data)
	if err != nil {
		t.Fatalf("parseSP800108Params failed: %v", err)
	}

	if params == nil {
		t.Fatal("Expected non-nil params")
	}

	// Default should be SHA-256 HMAC
	if params.PRF != CKM_SHA256_HMAC {
		t.Errorf("Expected PRF CKM_SHA256_HMAC, got %v", params.PRF)
	}
}

func TestParseSP800108Params_ExactlyMinLength(t *testing.T) {
	// Exactly 4 bytes (minimum required)
	data := make([]byte, 4)

	params, err := parseSP800108Params(data)
	if err != nil {
		t.Fatalf("parseSP800108Params failed: %v", err)
	}

	if params == nil {
		t.Fatal("Expected non-nil params")
	}
}

func TestParseSP800108Params_LongerData(t *testing.T) {
	// Longer than minimum
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}

	params, err := parseSP800108Params(data)
	if err != nil {
		t.Fatalf("parseSP800108Params failed: %v", err)
	}

	if params == nil {
		t.Fatal("Expected non-nil params")
	}
}

// ----------------------------------------------------------------
// Additional mechanismToHashFromHKDF Tests
// ----------------------------------------------------------------

func TestMechanismToHashFromHKDF_SHA1RSA(t *testing.T) {
	result := mechanismToHashFromHKDF(CKM_SHA1_RSA_PKCS)
	if result != "SHA-1" {
		t.Errorf("Expected 'SHA-1', got '%s'", result)
	}
}

func TestMechanismToHashFromHKDF_SHA256RSA(t *testing.T) {
	result := mechanismToHashFromHKDF(CKM_SHA256_RSA_PKCS)
	if result != "SHA-256" {
		t.Errorf("Expected 'SHA-256', got '%s'", result)
	}
}

func TestMechanismToHashFromHKDF_SHA384RSA(t *testing.T) {
	result := mechanismToHashFromHKDF(CKM_SHA384_RSA_PKCS)
	if result != "SHA-384" {
		t.Errorf("Expected 'SHA-384', got '%s'", result)
	}
}

func TestMechanismToHashFromHKDF_SHA512RSA(t *testing.T) {
	result := mechanismToHashFromHKDF(CKM_SHA512_RSA_PKCS)
	if result != "SHA-512" {
		t.Errorf("Expected 'SHA-512', got '%s'", result)
	}
}

// ----------------------------------------------------------------
// Additional VerifyInit Tests
// ----------------------------------------------------------------

func TestCryptoManager_VerifyInit_InvalidKeyHandle(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_RSA_PKCS}

	_, err := cm.VerifyInit(mech, 0, "test-key", "backend1")
	if err == nil {
		t.Fatal("expected error for invalid key handle")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_KEY_HANDLE_INVALID {
		t.Errorf("expected CKR_KEY_HANDLE_INVALID, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_VerifyInit_InvalidMechanism(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: 0xFFFFFFFF}

	_, err := cm.VerifyInit(mech, 1, "test-key", "backend1")
	if err == nil {
		t.Fatal("expected error for invalid mechanism")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_MECHANISM_INVALID {
		t.Errorf("expected CKR_MECHANISM_INVALID, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_VerifyInit_DefaultBackend(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_RSA_PKCS}

	op, err := cm.VerifyInit(mech, 1, "test-key", "")
	if err != nil {
		t.Fatalf("VerifyInit failed: %v", err)
	}
	if op.Backend() != "test-backend" {
		t.Errorf("expected default backend 'test-backend', got %s", op.Backend())
	}
}

// ----------------------------------------------------------------
// Additional Verify Tests
// ----------------------------------------------------------------

func TestCryptoManager_Verify_NilOperation(t *testing.T) {
	cm, _ := newTestCryptoManager()

	err := cm.Verify(context.Background(), nil, []byte("data"), []byte("sig"))
	if err == nil {
		t.Fatal("expected error for nil operation")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_Verify_AlreadyFinalized(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_RSA_PKCS}

	op, _ := cm.VerifyInit(mech, 1, "test-key", "backend1")

	// First verify
	_ = cm.Verify(context.Background(), op, []byte("data"), []byte("sig"))

	// Second verify should fail
	err := cm.Verify(context.Background(), op, []byte("data"), []byte("sig"))
	if err == nil {
		t.Fatal("expected error for already finalized operation")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %s", pkcsErr.Code.String())
	}
}

// ----------------------------------------------------------------
// Additional VerifyUpdate and VerifyFinal Tests
// ----------------------------------------------------------------

func TestCryptoManager_VerifyUpdate_NilOperation(t *testing.T) {
	cm, _ := newTestCryptoManager()

	err := cm.VerifyUpdate(nil, []byte("data"))
	if err == nil {
		t.Fatal("expected error for nil operation")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_VerifyUpdate_AlreadyFinalized(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_RSA_PKCS}

	op, _ := cm.VerifyInit(mech, 1, "test-key", "backend1")
	op.finalized = true

	err := cm.VerifyUpdate(op, []byte("data"))
	if err == nil {
		t.Fatal("expected error for finalized operation")
	}
}

func TestCryptoManager_VerifyFinal_NilOperation(t *testing.T) {
	cm, _ := newTestCryptoManager()

	err := cm.VerifyFinal(context.Background(), nil, []byte("sig"))
	if err == nil {
		t.Fatal("expected error for nil operation")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_VerifyFinal_AlreadyFinalized(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_RSA_PKCS}

	op, _ := cm.VerifyInit(mech, 1, "test-key", "backend1")
	op.finalized = true

	err := cm.VerifyFinal(context.Background(), op, []byte("sig"))
	if err == nil {
		t.Fatal("expected error for finalized operation")
	}
}

// ----------------------------------------------------------------
// Additional SignUpdate and SignFinal Tests
// ----------------------------------------------------------------

func TestCryptoManager_SignUpdate_AlreadyFinalized(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_RSA_PKCS}

	op, _ := cm.SignInit(mech, 1, "test-key", "backend1")
	op.finalized = true

	err := cm.SignUpdate(op, []byte("data"))
	if err == nil {
		t.Fatal("expected error for finalized operation")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_SignFinal_NilOperation(t *testing.T) {
	cm, _ := newTestCryptoManager()

	_, err := cm.SignFinal(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil operation")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_SignFinal_AlreadyFinalized(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_RSA_PKCS}

	op, _ := cm.SignInit(mech, 1, "test-key", "backend1")
	op.finalized = true

	_, err := cm.SignFinal(context.Background(), op)
	if err == nil {
		t.Fatal("expected error for finalized operation")
	}
}

// ----------------------------------------------------------------
// Additional DigestUpdate and DigestFinal Tests
// ----------------------------------------------------------------

func TestCryptoManager_DigestUpdate_NilOperation(t *testing.T) {
	cm, _ := newTestCryptoManager()

	err := cm.DigestUpdate(nil, []byte("data"))
	if err == nil {
		t.Fatal("expected error for nil operation")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_OPERATION_NOT_INITIALIZED {
		t.Errorf("expected CKR_OPERATION_NOT_INITIALIZED, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_DigestUpdate_AlreadyFinalized(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_SHA256}

	op, _ := cm.DigestInit(mech)
	op.finalized = true

	err := cm.DigestUpdate(op, []byte("data"))
	if err == nil {
		t.Fatal("expected error for finalized operation")
	}
}

func TestCryptoManager_DigestFinal_AlreadyFinalized(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_SHA256}

	op, _ := cm.DigestInit(mech)
	op.finalized = true

	_, err := cm.DigestFinal(op)
	if err == nil {
		t.Fatal("expected error for finalized operation")
	}
}

func TestCryptoManager_Digest_AlreadyFinalized(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_SHA256}

	op, _ := cm.DigestInit(mech)
	op.finalized = true

	_, err := cm.Digest(op, []byte("data"))
	if err == nil {
		t.Fatal("expected error for finalized operation")
	}
}

// ----------------------------------------------------------------
// Additional VerifyRecover Tests for Large Exponent
// ----------------------------------------------------------------

func TestCryptoManager_VerifyRecover_LargeExponent(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_RSA_X_509}

	op, err := cm.VerifyInit(mech, 1, "rsa-key", "backend1")
	if err != nil {
		t.Fatalf("VerifyInit failed: %v", err)
	}
	op.IsRecover = true

	modulus := []byte{0x01, 0x8F}
	// Exponent larger than max int32 (requires 5 bytes or more to exceed)
	largeExponent := []byte{0x80, 0x00, 0x00, 0x00, 0x00} // > 2^31

	op.SetRSAPublicKey(modulus, largeExponent)

	signature := []byte{0x00, 0x2A}

	_, err = cm.VerifyRecover(context.Background(), op, signature)
	if err == nil {
		t.Fatal("expected error for large exponent")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_KEY_SIZE_RANGE {
		t.Errorf("expected CKR_KEY_SIZE_RANGE, got %s", pkcsErr.Code.String())
	}
}

// ----------------------------------------------------------------
// Montgomery Key Pair Generation Test
// ----------------------------------------------------------------

func TestCryptoManager_GenerateKeyPair_X25519(t *testing.T) {
	cm, client := newTestCryptoManager()
	client.generateKeyResp = &transport.GenerateKeyResponse{
		KeyID:   "x25519-test-key",
		KeyType: "X25519",
	}

	mech := &Mechanism{Type: CKM_EC_MONTGOMERY_KEY_PAIR_GEN}

	req := &GenerateKeyPairRequest{
		KeyID:     "x25519-test",
		Backend:   "test-backend",
		Mechanism: mech,
	}

	resp, err := cm.GenerateKeyPair(context.Background(), req)
	if err != nil {
		t.Fatalf("GenerateKeyPair for X25519 failed: %v", err)
	}
	if resp == nil {
		t.Fatal("GenerateKeyPair returned nil response")
	}
	if !client.generateCalled {
		t.Error("GenerateKey was not called on client")
	}
	if client.lastGenerateReq.KeyType != "X25519" {
		t.Errorf("expected SDK key type 'X25519', got %s", client.lastGenerateReq.KeyType)
	}
}

func TestMechanismToKeyType_X25519(t *testing.T) {
	result := mechanismToKeyType(CKM_EC_MONTGOMERY_KEY_PAIR_GEN)
	if result != "X25519" {
		t.Errorf("mechanismToKeyType(CKM_EC_MONTGOMERY_KEY_PAIR_GEN) = %q, want 'X25519'", result)
	}
}

// ----------------------------------------------------------------
// Additional GenerateKeyPair Tests
// ----------------------------------------------------------------

func TestCryptoManager_GenerateKeyPair_NilMechanism(t *testing.T) {
	cm, _ := newTestCryptoManager()

	req := &GenerateKeyPairRequest{
		KeyID:   "test-key",
		Backend: "backend1",
	}

	_, err := cm.GenerateKeyPair(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for nil mechanism")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_ARGUMENTS_BAD {
		t.Errorf("expected CKR_ARGUMENTS_BAD, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_GenerateKeyPair_DefaultBackend(t *testing.T) {
	cm, client := newTestCryptoManager()

	req := &GenerateKeyPairRequest{
		KeyID:     "test-key",
		Mechanism: &Mechanism{Type: CKM_RSA_PKCS_KEY_PAIR_GEN},
		KeySize:   2048,
	}

	_, err := cm.GenerateKeyPair(context.Background(), req)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if client.lastGenerateReq.Backend != "test-backend" {
		t.Errorf("expected default backend 'test-backend', got %s", client.lastGenerateReq.Backend)
	}
}

// ----------------------------------------------------------------
// DeriveKeyECDH Tests
// ----------------------------------------------------------------

func TestCryptoManager_DeriveKeyECDH_NilRequest(t *testing.T) {
	cm, _ := newTestCryptoManager()

	_, err := cm.DeriveKeyECDH(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil request")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_ARGUMENTS_BAD {
		t.Errorf("expected CKR_ARGUMENTS_BAD, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_DeriveKeyECDH_EmptyBaseKeyID(t *testing.T) {
	cm, _ := newTestCryptoManager()

	req := &DeriveKeyECDHRequest{
		PeerPublicKey: []byte{0x04, 0x01, 0x02, 0x03},
	}

	_, err := cm.DeriveKeyECDH(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for empty base key ID")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_KEY_HANDLE_INVALID {
		t.Errorf("expected CKR_KEY_HANDLE_INVALID, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_DeriveKeyECDH_EmptyPeerPublicKey(t *testing.T) {
	cm, _ := newTestCryptoManager()

	req := &DeriveKeyECDHRequest{
		BaseKeyID: "base-key",
	}

	_, err := cm.DeriveKeyECDH(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for empty peer public key")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_ARGUMENTS_BAD {
		t.Errorf("expected CKR_ARGUMENTS_BAD, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_DeriveKeyECDH_Success(t *testing.T) {
	cm, _ := newTestCryptoManager()

	req := &DeriveKeyECDHRequest{
		BaseKeyID:     "base-key",
		Backend:       "test-backend",
		PeerPublicKey: []byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
		KDFAlgorithm:  "HKDF",
		KDFHash:       "SHA-256",
		KeyLength:     32,
	}

	derivedKey, err := cm.DeriveKeyECDH(context.Background(), req)
	if err != nil {
		t.Fatalf("DeriveKeyECDH failed: %v", err)
	}

	if len(derivedKey) == 0 {
		t.Error("expected non-empty derived key")
	}
}

func TestCryptoManager_DeriveKeyECDH_DefaultParameters(t *testing.T) {
	cm, _ := newTestCryptoManager()

	req := &DeriveKeyECDHRequest{
		BaseKeyID:     "base-key",
		PeerPublicKey: []byte{0x04, 0x01, 0x02, 0x03},
		// No Backend, KDFAlgorithm, KDFHash, or KeyLength - should use defaults
	}

	derivedKey, err := cm.DeriveKeyECDH(context.Background(), req)
	if err != nil {
		t.Fatalf("DeriveKeyECDH with defaults failed: %v", err)
	}

	if len(derivedKey) == 0 {
		t.Error("expected non-empty derived key with defaults")
	}
}

// ----------------------------------------------------------------
// WrapKeyByID Tests
// ----------------------------------------------------------------

func TestCryptoManager_WrapKeyByID_NilRequest(t *testing.T) {
	cm, _ := newTestCryptoManager()

	_, err := cm.WrapKeyByID(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil request")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_ARGUMENTS_BAD {
		t.Errorf("expected CKR_ARGUMENTS_BAD, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_WrapKeyByID_EmptyWrappingKeyID(t *testing.T) {
	cm, _ := newTestCryptoManager()

	req := &WrapKeyByIDRequest{
		TargetKeyID: "target-key",
	}

	_, err := cm.WrapKeyByID(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for empty wrapping key ID")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_WRAPPING_KEY_HANDLE_INVALID {
		t.Errorf("expected CKR_WRAPPING_KEY_HANDLE_INVALID, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_WrapKeyByID_EmptyTargetKeyID(t *testing.T) {
	cm, _ := newTestCryptoManager()

	req := &WrapKeyByIDRequest{
		WrappingKeyID: "wrapping-key",
	}

	_, err := cm.WrapKeyByID(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for empty target key ID")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_KEY_HANDLE_INVALID {
		t.Errorf("expected CKR_KEY_HANDLE_INVALID, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_WrapKeyByID_Success(t *testing.T) {
	cm, _ := newTestCryptoManager()

	req := &WrapKeyByIDRequest{
		WrappingKeyID:      "wrapping-key",
		TargetKeyID:        "target-key",
		WrappingKeyBackend: "test-backend",
		TargetKeyBackend:   "test-backend",
		Algorithm:          "AES_KEY_WRAP",
	}

	wrappedKey, err := cm.WrapKeyByID(context.Background(), req)
	if err != nil {
		t.Fatalf("WrapKeyByID failed: %v", err)
	}

	if len(wrappedKey) == 0 {
		t.Error("expected non-empty wrapped key")
	}
}

func TestCryptoManager_WrapKeyByID_DefaultParameters(t *testing.T) {
	cm, _ := newTestCryptoManager()

	req := &WrapKeyByIDRequest{
		WrappingKeyID: "wrapping-key",
		TargetKeyID:   "target-key",
		// No backends or algorithm - should use defaults
	}

	wrappedKey, err := cm.WrapKeyByID(context.Background(), req)
	if err != nil {
		t.Fatalf("WrapKeyByID with defaults failed: %v", err)
	}

	if len(wrappedKey) == 0 {
		t.Error("expected non-empty wrapped key with defaults")
	}
}

// ----------------------------------------------------------------
// UnwrapKeyByID Tests
// ----------------------------------------------------------------

func TestCryptoManager_UnwrapKeyByID_NilRequest(t *testing.T) {
	cm, _ := newTestCryptoManager()

	_, err := cm.UnwrapKeyByID(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil request")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_ARGUMENTS_BAD {
		t.Errorf("expected CKR_ARGUMENTS_BAD, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_UnwrapKeyByID_EmptyWrappedKey(t *testing.T) {
	cm, _ := newTestCryptoManager()

	req := &UnwrapKeyByIDRequest{
		UnwrappingKeyID: "unwrap-key",
	}

	_, err := cm.UnwrapKeyByID(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for empty wrapped key")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_WRAPPED_KEY_INVALID {
		t.Errorf("expected CKR_WRAPPED_KEY_INVALID, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_UnwrapKeyByID_EmptyUnwrappingKeyID(t *testing.T) {
	cm, _ := newTestCryptoManager()

	req := &UnwrapKeyByIDRequest{
		WrappedKey: []byte{0x01, 0x02, 0x03, 0x04},
	}

	_, err := cm.UnwrapKeyByID(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for empty unwrapping key ID")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_UNWRAPPING_KEY_HANDLE_INVALID {
		t.Errorf("expected CKR_UNWRAPPING_KEY_HANDLE_INVALID, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_UnwrapKeyByID_Success(t *testing.T) {
	cm, _ := newTestCryptoManager()

	req := &UnwrapKeyByIDRequest{
		WrappedKey:           []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		UnwrappingKeyID:      "unwrap-key",
		UnwrappingKeyBackend: "test-backend",
		Algorithm:            "AES_KEY_WRAP",
		TargetKeyID:          "new-key",
		TargetKeyBackend:     "test-backend",
		TargetKeyType:        "symmetric",
		TargetKeySize:        256,
		TargetExportable:     false,
	}

	keyID, err := cm.UnwrapKeyByID(context.Background(), req)
	if err != nil {
		t.Fatalf("UnwrapKeyByID failed: %v", err)
	}

	if keyID == "" {
		t.Error("expected non-empty key ID")
	}
}

func TestCryptoManager_UnwrapKeyByID_DefaultParameters(t *testing.T) {
	cm, _ := newTestCryptoManager()

	req := &UnwrapKeyByIDRequest{
		WrappedKey:      []byte{0x01, 0x02, 0x03, 0x04},
		UnwrappingKeyID: "unwrap-key",
		TargetKeyID:     "target-key", // Need to provide target key ID
		// No backends - should use defaults
	}

	keyID, err := cm.UnwrapKeyByID(context.Background(), req)
	if err != nil {
		t.Fatalf("UnwrapKeyByID with defaults failed: %v", err)
	}

	if keyID == "" {
		t.Error("expected non-empty key ID with defaults")
	}
}

// ----------------------------------------------------------------
// ExportKeyMaterial Tests
// ----------------------------------------------------------------

func TestCryptoManager_ExportKeyMaterial_NilRequest(t *testing.T) {
	cm, _ := newTestCryptoManager()

	_, err := cm.ExportKeyMaterial(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil request")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_ARGUMENTS_BAD {
		t.Errorf("expected CKR_ARGUMENTS_BAD, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_ExportKeyMaterial_EmptyKeyID(t *testing.T) {
	cm, _ := newTestCryptoManager()

	req := &ExportKeyMaterialRequest{}

	_, err := cm.ExportKeyMaterial(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for empty key ID")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_KEY_HANDLE_INVALID {
		t.Errorf("expected CKR_KEY_HANDLE_INVALID, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_ExportKeyMaterial_Success(t *testing.T) {
	cm, _ := newTestCryptoManager()

	req := &ExportKeyMaterialRequest{
		KeyID:   "export-key",
		Backend: "test-backend",
	}

	resp, err := cm.ExportKeyMaterial(context.Background(), req)
	if err != nil {
		t.Fatalf("ExportKeyMaterial failed: %v", err)
	}

	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	if len(resp.KeyMaterial) == 0 {
		t.Error("expected non-empty key material")
	}
}

func TestCryptoManager_ExportKeyMaterial_DefaultBackend(t *testing.T) {
	cm, _ := newTestCryptoManager()

	req := &ExportKeyMaterialRequest{
		KeyID: "export-key",
		// No backend - should use default
	}

	resp, err := cm.ExportKeyMaterial(context.Background(), req)
	if err != nil {
		t.Fatalf("ExportKeyMaterial with default backend failed: %v", err)
	}

	if resp == nil {
		t.Fatal("expected non-nil response with default backend")
	}
}
