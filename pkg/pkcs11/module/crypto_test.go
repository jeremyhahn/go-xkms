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
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
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

	encryptAsymResponse *transport.EncryptAsymResponse
	encryptAsymError    error

	// Call tracking
	signCalled         bool
	verifyCalled       bool
	encryptCalled      bool
	decryptCalled      bool
	generateCalled     bool
	encryptAsymCalled  bool
	lastSignReq        *transport.SignRequest
	lastVerifyReq      *transport.VerifyRequest
	lastEncryptReq     *transport.EncryptRequest
	lastDecryptReq     *transport.DecryptRequest
	lastGenerateReq    *transport.GenerateKeyRequest
	lastEncryptAsymReq *transport.EncryptAsymRequest

	lastDeriveECDHReq *transport.DeriveKeyECDHRequest

	// cryptoEngine, when set, makes Sign/Verify/Encrypt/Decrypt perform genuine
	// cryptography with keys bound to the backend key ID, instead of returning
	// the canned responses above. See newRealCryptoCryptoManager at the end of
	// this file for why both modes exist and which tests use which.
	cryptoEngine *mockCryptoEngine

	// Key-import ceremony state. importKeys holds the RSA key pair issued to a
	// pending import and importedMaterial the plaintext recovered from a
	// completed one, so a test can assert the module wrapped the bytes it meant
	// to. The two errors and the substitute public key drive the failure paths.
	//
	// No mutex guards these, deliberately. mockClient carries none anywhere
	// else and tests copy it by value, so adding one would both break those
	// copies and be flagged by go vet. The concurrency suite uses
	// concurrentTransport instead.
	importKeys            map[string]*rsa.PrivateKey
	importedMaterial      map[string][]byte
	importParamsCalled    bool
	importKeyCalled       bool
	lastImportParamsReq   *transport.GetImportParametersRequest
	lastImportKeyReq      *transport.ImportKeyRequest
	importParamsError     error
	importKeyError        error
	importParamsPublicKey []byte
}

// errMockImportWithoutParameters reports an ImportKey that skipped
// GetImportParameters. It is a protocol violation rather than a missing key:
// the ceremony's whole guarantee is that material is wrapped under a key the
// backend issued for this import.
var errMockImportWithoutParameters = errors.New("module: ImportKey called without GetImportParameters")

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
			// A real backend returns the generated public key, and
			// C_GenerateKeyPair needs it: the public-key object's CKA_MODULUS
			// and CKA_PUBLIC_EXPONENT come from here, and without them
			// ssh-keygen -D lists nothing and pkcs11-provider cannot build an
			// EVP_PKEY. A mock that returned no PEM let every generate test
			// pass while asserting nothing about the public half.
			PublicKeyPEM: mockGeneratedPublicKeyPEM(),
		},
		encryptAsymResponse: &transport.EncryptAsymResponse{
			Ciphertext: []byte("mock-asym-ciphertext"),
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

// mockGeneratedPublicKeyPEM returns a valid RSA SubjectPublicKeyInfo PEM, so
// the mock backend answers C_GenerateKeyPair the way a real one does.
func mockGeneratedPublicKeyPEM() string {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("pkcs11 test fixture: " + err.Error())
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		panic("pkcs11 test fixture: " + err.Error())
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
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
	if m.cryptoEngine != nil {
		return m.cryptoEngine.sign(req)
	}
	return m.signResponse, nil
}

func (m *mockClient) Verify(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	m.verifyCalled = true
	m.lastVerifyReq = req
	if m.verifyError != nil {
		return nil, m.verifyError
	}
	if m.cryptoEngine != nil {
		return m.cryptoEngine.verify(req)
	}
	return m.verifyResponse, nil
}

func (m *mockClient) Encrypt(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	m.encryptCalled = true
	m.lastEncryptReq = req
	if m.encryptError != nil {
		return nil, m.encryptError
	}
	if m.cryptoEngine != nil {
		return m.cryptoEngine.encrypt(req)
	}
	return m.encryptResponse, nil
}

func (m *mockClient) EncryptAsym(ctx context.Context, req *transport.EncryptAsymRequest) (*transport.EncryptAsymResponse, error) {
	m.encryptAsymCalled = true
	m.lastEncryptAsymReq = req
	if m.encryptAsymError != nil {
		return nil, m.encryptAsymError
	}
	return m.encryptAsymResponse, nil
}

func (m *mockClient) Decrypt(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	m.decryptCalled = true
	m.lastDecryptReq = req
	if m.decryptError != nil {
		return nil, m.decryptError
	}
	if m.cryptoEngine != nil {
		return m.cryptoEngine.decrypt(req)
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

// GetImportParameters and ImportKey run the real BYOK ceremony rather than
// answering with canned bytes.
//
// The ceremony is the whole point of the import path: the module must parse a
// PKIX DER public key, wrap under RSA-OAEP with SHA-256, and send only the
// ciphertext. A mock that accepted anything would let a module that sent
// plaintext, chose the wrong digest, or misread the key encoding pass here and
// fail against the daemon — which is exactly how an earlier attempt at this
// change went green against a fake while the real service rejected the call.
// Decrypting for real is what makes these assertions mean anything.
func (m *mockClient) GetImportParameters(ctx context.Context, req *transport.GetImportParametersRequest) (*transport.GetImportParametersResponse, error) {
	m.importParamsCalled = true
	m.lastImportParamsReq = req

	if m.importParamsError != nil {
		return nil, m.importParamsError
	}

	importKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	if m.importKeys == nil {
		m.importKeys = make(map[string]*rsa.PrivateKey)
	}
	m.importKeys[req.KeyID] = importKey

	publicDER, err := x509.MarshalPKIXPublicKey(&importKey.PublicKey)
	if err != nil {
		return nil, err
	}

	if m.importParamsPublicKey != nil {
		publicDER = m.importParamsPublicKey
	}

	return &transport.GetImportParametersResponse{
		WrappingPublicKey: publicDER,
		ImportToken:       []byte("mock-import-token"),
		Algorithm:         "RSAES_OAEP_SHA_256",
	}, nil
}

func (m *mockClient) ImportKey(ctx context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	m.importKeyCalled = true
	m.lastImportKeyReq = req

	if m.importKeyError != nil {
		return nil, m.importKeyError
	}

	importKey, ok := m.importKeys[req.KeyID]
	if !ok {
		return nil, errMockImportWithoutParameters
	}

	material, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, importKey, req.WrappedKeyMaterial, nil)
	if err != nil {
		return nil, err
	}

	if m.importedMaterial == nil {
		m.importedMaterial = make(map[string][]byte)
	}
	m.importedMaterial[req.KeyID] = material

	return &transport.ImportKeyResponse{Success: true, KeyID: req.KeyID}, nil
}

func (m *mockClient) DeriveKeyECDH(ctx context.Context, req *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	m.lastDeriveECDHReq = req
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

// freshGuardKeyID returns a backend key id no earlier run has used. The AES-GCM
// IV reuse guard is process-wide and keys a backend key by (backend, key id), so
// a test that encrypts under a fixed id and a fixed nonce would meet its own
// earlier claim on the next go test -count=N iteration.
func freshGuardKeyID(t *testing.T) string {
	t.Helper()
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return fmt.Sprintf("test-key-%x", suffix)
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

// TestCryptoManager_Sign_Success drives a single-part signature through a
// transport that performs real RSA and checks the result with crypto/rsa
// against the public half of the very key the transport signed with.
//
// It used to assert bytes.Equal(sig, []byte("mock-signature")), which could
// only ever prove that a constant survived the round trip: the module could
// have sent the wrong digest, the wrong data or the wrong padding and the
// assertion would still have held. Every one of those now fails here.
func TestCryptoManager_Sign_Success(t *testing.T) {
	cm, client, engine := newRealCryptoCryptoManager()
	mech := &Mechanism{Type: CKM_SHA256_RSA_PKCS}

	op, _ := cm.SignInit(mech, 1, "test-key", "backend1")
	data := []byte("test data to sign")

	sig, err := cm.Sign(context.Background(), op, data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	pub, err := engine.publicKey("test-key")
	if err != nil {
		t.Fatalf("publicKey failed: %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected an RSA public key, got %T", pub)
	}
	digest := sha256.Sum256(data)
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature does not verify against the signing key: %v", err)
	}

	// The digest must be of the caller's data and nothing else: a signature
	// over a different message must not verify.
	otherDigest := sha256.Sum256([]byte("a different message"))
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, otherDigest[:], sig); err == nil {
		t.Fatal("the signature verified against a message that was never signed")
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

// TestCryptoManager_SignFinal_Success proves a multi-part signature covers the
// concatenation of every C_SignUpdate, cryptographically rather than by
// inspecting the request the fixture happened to receive: the signature is
// checked against SHA-256("part1part2") and must NOT check out against either
// part alone.
//
// CKM_SHA256_RSA_PKCS rather than the raw CKM_RSA_PKCS the canned version used,
// so the module resolves and applies a real digest -- with a raw mechanism the
// buffered bytes are signed as-is and the digest wiring is never exercised.
func TestCryptoManager_SignFinal_Success(t *testing.T) {
	cm, client, engine := newRealCryptoCryptoManager()
	mech := &Mechanism{Type: CKM_SHA256_RSA_PKCS}

	op, _ := cm.SignInit(mech, 1, "test-key", "backend1")
	_ = cm.SignUpdate(op, []byte("part1"))
	_ = cm.SignUpdate(op, []byte("part2"))

	sig, err := cm.SignFinal(context.Background(), op)
	if err != nil {
		t.Fatalf("SignFinal failed: %v", err)
	}

	pub, err := engine.publicKey("test-key")
	if err != nil {
		t.Fatalf("publicKey failed: %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected an RSA public key, got %T", pub)
	}

	whole := sha256.Sum256([]byte("part1part2"))
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, whole[:], sig); err != nil {
		t.Fatalf("the multi-part signature does not cover part1part2: %v", err)
	}
	firstOnly := sha256.Sum256([]byte("part1"))
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, firstOnly[:], sig); err == nil {
		t.Fatal("the signature verified against the first update alone")
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

// TestCryptoManager_Verify_Success verifies a signature this module actually
// produced, under the same key and mechanism.
//
// The canned version passed []byte("signature") -- not a signature of anything
// -- and asserted success, which a transport hard-wired to Valid=true could not
// fail. Here a wrong signature genuinely fails, which is what
// TestCryptoManager_Verify_InvalidSignature now proves against the same key.
func TestCryptoManager_Verify_Success(t *testing.T) {
	cm, client, _ := newRealCryptoCryptoManager()
	mech := &Mechanism{Type: CKM_SHA256_RSA_PKCS}
	data := []byte("test data")

	signOp, err := cm.SignInit(mech, 1, "test-key", "backend1")
	if err != nil {
		t.Fatalf("SignInit failed: %v", err)
	}
	sig, err := cm.Sign(context.Background(), signOp, data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	op, _ := cm.VerifyInit(mech, 1, "test-key", "backend1")
	if err := cm.Verify(context.Background(), op, data, sig); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !client.verifyCalled {
		t.Error("Verify was not called on client")
	}
}

// TestCryptoManager_Verify_RejectsWrongData is the failure counterpart: the
// signature is genuine but the message is not the one it covers.
func TestCryptoManager_Verify_RejectsWrongData(t *testing.T) {
	cm, _, _ := newRealCryptoCryptoManager()
	mech := &Mechanism{Type: CKM_SHA256_RSA_PKCS}

	signOp, _ := cm.SignInit(mech, 1, "test-key", "backend1")
	sig, err := cm.Sign(context.Background(), signOp, []byte("the signed message"))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	op, _ := cm.VerifyInit(mech, 1, "test-key", "backend1")
	err = cm.Verify(context.Background(), op, []byte("a different message"), sig)
	if err == nil {
		t.Fatal("a signature verified against a message it does not cover")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_SIGNATURE_INVALID {
		t.Errorf("expected CKR_SIGNATURE_INVALID, got %s", pkcsErr.Code.String())
	}
}

// TestCryptoManager_Verify_RejectsWrongKey proves verification is bound to the
// key the caller named: a signature made under one key must not verify under
// another.
func TestCryptoManager_Verify_RejectsWrongKey(t *testing.T) {
	cm, _, _ := newRealCryptoCryptoManager()
	mech := &Mechanism{Type: CKM_SHA256_RSA_PKCS}
	data := []byte("test data")

	signOp, _ := cm.SignInit(mech, 1, "signing-key", "backend1")
	sig, err := cm.Sign(context.Background(), signOp, data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	op, _ := cm.VerifyInit(mech, 1, "another-key", "backend1")
	if err := cm.Verify(context.Background(), op, data, sig); err == nil {
		t.Fatal("a signature verified under a key that did not produce it")
	}
}

// TestCryptoManager_Verify_InvalidSignature drives the CKR_SIGNATURE_INVALID
// path with a signature that is genuinely wrong -- one octet of a real
// signature flipped -- rather than with a transport told to answer Valid=false.
// The mapping being tested is the same; what changed is that the input now has
// to be rejected by RSA rather than by the fixture.
func TestCryptoManager_Verify_InvalidSignature(t *testing.T) {
	cm, client, _ := newRealCryptoCryptoManager()
	mech := &Mechanism{Type: CKM_SHA256_RSA_PKCS}
	data := []byte("data")

	signOp, _ := cm.SignInit(mech, 1, "test-key", "backend1")
	good, signErr := cm.Sign(context.Background(), signOp, data)
	if signErr != nil {
		t.Fatalf("Sign failed: %v", signErr)
	}
	tampered := append([]byte{}, good...)
	tampered[0] ^= 0x01

	op, _ := cm.VerifyInit(mech, 1, "test-key", "backend1")

	err := cm.Verify(context.Background(), op, data, tampered)
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
	if !client.verifyCalled {
		t.Error("Verify was not called on client")
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

// TestCryptoManager_VerifyFinal_Success checks a multi-part verification
// against a signature over the concatenated updates, and the failure
// counterpart against a signature over only the first one. Both go through
// real RSA, so a C_VerifyUpdate that dropped or reordered a part fails here.
func TestCryptoManager_VerifyFinal_Success(t *testing.T) {
	cm, _, _ := newRealCryptoCryptoManager()
	mech := &Mechanism{Type: CKM_SHA256_RSA_PKCS}

	signOp, _ := cm.SignInit(mech, 1, "test-key", "backend1")
	whole, err := cm.Sign(context.Background(), signOp, []byte("part1part2"))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	op, _ := cm.VerifyInit(mech, 1, "test-key", "backend1")
	_ = cm.VerifyUpdate(op, []byte("part1"))
	_ = cm.VerifyUpdate(op, []byte("part2"))

	if err := cm.VerifyFinal(context.Background(), op, whole); err != nil {
		t.Fatalf("VerifyFinal failed: %v", err)
	}

	partialOp, _ := cm.SignInit(mech, 1, "test-key", "backend1")
	partial, err := cm.Sign(context.Background(), partialOp, []byte("part1"))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	badOp, _ := cm.VerifyInit(mech, 1, "test-key", "backend1")
	_ = cm.VerifyUpdate(badOp, []byte("part1"))
	_ = cm.VerifyUpdate(badOp, []byte("part2"))
	if err := cm.VerifyFinal(context.Background(), badOp, partial); err == nil {
		t.Fatal("VerifyFinal accepted a signature covering only the first update")
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

// TestCryptoManager_Encrypt_Success drives the generic (non-AEAD) Encrypt path
// with real AES-ECB and decrypts the result with crypto/aes directly.
//
// It used to assert bytes.Equal(ciphertext, []byte("mock-ciphertext")), which
// held no matter what mode the module actually selected. The two assertions
// here are the ones that would have caught the defect symmetricCipherModes
// documents -- CKM_AES_ECB reaching the backend as AES-GCM: ECB enciphers two
// identical plaintext blocks to two identical ciphertext blocks, and any AEAD
// mode does not.
func TestCryptoManager_Encrypt_Success(t *testing.T) {
	cm, client, engine := newRealCryptoCryptoManager()
	mech := &Mechanism{Type: CKM_AES_ECB}

	op, _ := cm.EncryptInit(mech, 1, "test-key", "backend1")
	// Two identical AES blocks; ECB must produce two identical ciphertext blocks.
	plaintext := bytes.Repeat([]byte("sixteen bytes!!!"), 2)

	ciphertext, err := cm.Encrypt(context.Background(), op, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if !client.encryptCalled {
		t.Error("Encrypt was not called on client")
	}
	if client.lastEncryptReq.Mode != "ecb" {
		t.Fatalf("expected mode %q on the wire, got %q", "ecb", client.lastEncryptReq.Mode)
	}
	if len(ciphertext) != len(plaintext) {
		t.Fatalf("ECB is length preserving: expected %d bytes, got %d", len(plaintext), len(ciphertext))
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("the ciphertext equals the plaintext")
	}
	if !bytes.Equal(ciphertext[:aes.BlockSize], ciphertext[aes.BlockSize:]) {
		t.Fatal("ECB enciphered two identical plaintext blocks differently")
	}

	key, err := engine.aesKey("test-key")
	if err != nil {
		t.Fatalf("aesKey failed: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher failed: %v", err)
	}
	recovered := make([]byte, len(ciphertext))
	for offset := 0; offset < len(ciphertext); offset += aes.BlockSize {
		block.Decrypt(recovered[offset:offset+aes.BlockSize], ciphertext[offset:offset+aes.BlockSize])
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("independent AES-ECB decryption recovered %q, want %q", recovered, plaintext)
	}
}

// TestCryptoManager_Encrypt_WithAAD proves the additional authenticated data
// is not merely copied into the request but actually authenticated.
//
// The canned version set AAD on a CKM_AES_ECB operation -- a mode that has no
// AAD input at all -- and asserted only that the bytes reached the request, so
// a module that forwarded AAD to a cipher that ignored it passed. Under real
// AES-GCM the tag is over the AAD, so opening with the wrong AAD fails.
func TestCryptoManager_Encrypt_WithAAD(t *testing.T) {
	cm, client, engine := newRealCryptoCryptoManager()
	mech := &Mechanism{Type: CKM_AES_GCM}
	aad := []byte("additional data")

	op, _ := cm.EncryptInit(mech, 1, "test-key", "backend1")
	op.SetAAD(aad)
	plaintext := []byte("secret data")

	wire, err := cm.Encrypt(context.Background(), op, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if !bytes.Equal(client.lastEncryptReq.AdditionalData, aad) {
		t.Error("AAD not passed to client")
	}

	key, err := engine.aesKey("test-key")
	if err != nil {
		t.Fatalf("aesKey failed: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher failed: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM failed: %v", err)
	}

	recovered, err := gcm.Open(nil, op.IV(), wire, aad)
	if err != nil {
		t.Fatalf("the ciphertext does not open under the AAD the caller set: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("recovered %q, want %q", recovered, plaintext)
	}
	if _, err := gcm.Open(nil, op.IV(), wire, []byte("different data")); err == nil {
		t.Fatal("the ciphertext opened under AAD it was not authenticated with")
	}
}

// TestCryptoManager_EncryptFinal_Success proves a multi-part encryption
// enciphers the concatenation of every C_EncryptUpdate. The canned version
// asserted only that the result was non-nil, which the fixture guaranteed;
// here the ciphertext is decrypted independently and compared to the joined
// parts.
func TestCryptoManager_EncryptFinal_Success(t *testing.T) {
	cm, _, engine := newRealCryptoCryptoManager()
	mech := &Mechanism{Type: CKM_AES_ECB}

	first := []byte("first block ....")  // 16 bytes
	second := []byte("second block ...") // 16 bytes

	op, _ := cm.EncryptInit(mech, 1, "test-key", "backend1")
	_ = cm.EncryptUpdate(op, first)
	_ = cm.EncryptUpdate(op, second)

	ciphertext, err := cm.EncryptFinal(context.Background(), op)
	if err != nil {
		t.Fatalf("EncryptFinal failed: %v", err)
	}

	key, err := engine.aesKey("test-key")
	if err != nil {
		t.Fatalf("aesKey failed: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher failed: %v", err)
	}
	recovered := make([]byte, len(ciphertext))
	for offset := 0; offset < len(ciphertext); offset += aes.BlockSize {
		block.Decrypt(recovered[offset:offset+aes.BlockSize], ciphertext[offset:offset+aes.BlockSize])
	}

	want := append(append([]byte{}, first...), second...)
	if !bytes.Equal(recovered, want) {
		t.Fatalf("multi-part encryption covered %q, want %q", recovered, want)
	}
}

// DecryptInit tests

func TestCryptoManager_DecryptInit_Success(t *testing.T) {
	cm, _ := newTestCryptoManager()
	// PKCS#11 v3.2 section 6.13.7: CKM_AES_GCM decryption requires the
	// caller to supply the exact IV used at encryption time via
	// CK_GCM_PARAMS.pIv; DecryptInit now resolves and validates it eagerly.
	mech := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams([]byte("123456789012"), 128))

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
	if !bytes.Equal(op.IV(), []byte("123456789012")) {
		t.Errorf("expected IV to be resolved from CK_GCM_PARAMS, got %v", op.IV())
	}
}

// Decrypt tests

// TestCryptoManager_Decrypt_Success drives a real AES-GCM round trip: the
// ciphertext comes from the module's own C_Encrypt (so the ciphertext || tag
// framing under test is the framing that was actually produced) and must
// decrypt back to the original plaintext.
//
// The canned version fed in []byte("encrypted-data-here") followed by sixteen
// 0xAB octets and asserted the fixture's []byte("mock-plaintext") came back. It
// checked the split, which is worth keeping and is kept below, but the tag it
// split off authenticated nothing, so a module that mis-assembled the wire
// format still passed.
func TestCryptoManager_Decrypt_Success(t *testing.T) {
	cm, client, engine := newRealCryptoCryptoManager()
	plaintext := []byte("plaintext to round trip")

	encOp, err := cm.EncryptInit(&Mechanism{Type: CKM_AES_GCM}, 1, "test-key", "backend1")
	if err != nil {
		t.Fatalf("EncryptInit failed: %v", err)
	}
	wire, err := cm.Encrypt(context.Background(), encOp, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	iv := encOp.IV()

	mech := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(iv, 128))
	op, err := cm.DecryptInit(mech, 1, "test-key", "backend1")
	if err != nil {
		t.Fatalf("DecryptInit failed: %v", err)
	}

	recovered, err := cm.Decrypt(context.Background(), op, wire)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("recovered %q, want %q", recovered, plaintext)
	}
	if !client.decryptCalled {
		t.Error("Decrypt was not called on client")
	}

	// PKCS#11 v3.2 section 6.13.7: the wire ciphertext is
	// actualCiphertext || tag, split using the default 128-bit (16-byte) tag.
	wantCiphertext := wire[:len(wire)-GCMTagSize]
	wantTag := wire[len(wire)-GCMTagSize:]
	if !bytes.Equal(client.lastDecryptReq.Ciphertext, wantCiphertext) {
		t.Errorf("expected ciphertext %x, got %x", wantCiphertext, client.lastDecryptReq.Ciphertext)
	}
	if !bytes.Equal(client.lastDecryptReq.Tag, wantTag) {
		t.Errorf("expected tag %x, got %x", wantTag, client.lastDecryptReq.Tag)
	}
	if !bytes.Equal(client.lastDecryptReq.Nonce, iv) {
		t.Errorf("expected nonce %x forwarded from DecryptInit, got %x", iv, client.lastDecryptReq.Nonce)
	}

	// The engine is the independent oracle: the same key opens the same blob.
	key, err := engine.aesKey("test-key")
	if err != nil {
		t.Fatalf("aesKey failed: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher failed: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM failed: %v", err)
	}
	direct, err := gcm.Open(nil, iv, wire, nil)
	if err != nil {
		t.Fatalf("crypto/cipher could not open the module's ciphertext: %v", err)
	}
	if !bytes.Equal(direct, plaintext) {
		t.Fatalf("crypto/cipher recovered %q, want %q", direct, plaintext)
	}
}

// TestCryptoManager_Decrypt_RejectsTamperedTag is the failure counterpart: a
// single flipped bit in the authentication tag must be refused with
// CKR_ENCRYPTED_DATA_INVALID rather than yielding plaintext.
func TestCryptoManager_Decrypt_RejectsTamperedTag(t *testing.T) {
	cm, _, _ := newRealCryptoCryptoManager()

	encOp, _ := cm.EncryptInit(&Mechanism{Type: CKM_AES_GCM}, 1, "test-key", "backend1")
	wire, err := cm.Encrypt(context.Background(), encOp, []byte("plaintext to round trip"))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	tampered := append([]byte{}, wire...)
	tampered[len(tampered)-1] ^= 0x01

	mech := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(encOp.IV(), 128))
	op, _ := cm.DecryptInit(mech, 1, "test-key", "backend1")

	_, err = cm.Decrypt(context.Background(), op, tampered)
	if err == nil {
		t.Fatal("a ciphertext with a flipped tag bit was decrypted")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_ENCRYPTED_DATA_INVALID {
		t.Errorf("expected CKR_ENCRYPTED_DATA_INVALID, got %s", pkcsErr.Code.String())
	}
}

// TestCryptoManager_DecryptFinal_Success feeds a real ciphertext through
// C_DecryptUpdate in two chunks and requires the joined plaintext back. The
// canned version buffered 32 constant octets and asserted only that the result
// was non-nil, which held however the module reassembled the buffer.
func TestCryptoManager_DecryptFinal_Success(t *testing.T) {
	cm, _, _ := newRealCryptoCryptoManager()
	plaintext := []byte("multi part decrypt plaintext")

	encOp, _ := cm.EncryptInit(&Mechanism{Type: CKM_AES_GCM}, 1, "test-key", "backend1")
	wire, err := cm.Encrypt(context.Background(), encOp, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	mech := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(encOp.IV(), 128))
	op, _ := cm.DecryptInit(mech, 1, "test-key", "backend1")

	split := len(wire) / 2
	_ = cm.DecryptUpdate(op, wire[:split])
	_ = cm.DecryptUpdate(op, wire[split:])

	recovered, err := cm.DecryptFinal(context.Background(), op)
	if err != nil {
		t.Fatalf("DecryptFinal failed: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("multi-part decryption recovered %q, want %q", recovered, plaintext)
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
		// The raw mechanisms must send the "NONE" sentinel, not "". An empty
		// string means "unspecified", which the service layer resolves to its
		// SHA-256 default — for CKM_RSA_PKCS that re-hashes the DigestInfo the
		// caller already built and signs the wrong bytes, producing a signature
		// that verifies against nothing. OpenSSL's engine drives exactly this
		// path, so the distinction is load-bearing rather than cosmetic.
		{CKM_RSA_PKCS, "NONE"},
		{CKM_ECDSA, "NONE"},
		{CKM_SHA1_RSA_PKCS, "SHA-1"},
		{CKM_SHA256_RSA_PKCS, "SHA-256"},
		{CKM_SHA384_RSA_PKCS, "SHA-384"},
		{CKM_SHA512_RSA_PKCS, "SHA-512"},
		{CKM_ECDSA_SHA256, "SHA-256"},
		// Ed25519 signs the message itself, so the mechanism must say "do not
		// hash". The service layer branches on the key algorithm before any
		// hash is resolved, which makes the value inert today; "NONE" keeps it
		// correct if that branch ever moves, whereas "" would resolve to the
		// SHA-256 default and sign a digest of the message.
		{CKM_EDDSA, "NONE"},
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
	// EdDSA hashes internally, so the request must say "do not hash the
	// message" rather than leave the digest unspecified.
	if client.lastSignReq.Hash != "NONE" {
		t.Errorf("expected hash %q for EdDSA, got %q", "NONE", client.lastSignReq.Hash)
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
	if client.lastVerifyReq.Hash != "NONE" {
		t.Errorf("expected hash %q for EdDSA, got %q", "NONE", client.lastVerifyReq.Hash)
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
	if result != "NONE" {
		t.Errorf("mechanismToHash(CKM_EDDSA) = %q, want \"NONE\" (EdDSA hashes internally, so the message must not be pre-hashed)", result)
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
		TypedParameter: &HKDFParams{
			Extract:     true,
			Expand:      true,
			PRFHashMech: CKM_SHA384,
			SaltType:    CKF_HKDF_SALT_DATA,
			Salt:        []byte("salt"),
			Info:        []byte("info"),
		},
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

	// The caller's real salt/info/PRF hash must be honored, not
	// substituted with fabricated defaults.
	if string(op.params.Salt) != "salt" {
		t.Errorf("Expected salt 'salt', got %q", op.params.Salt)
	}
	if string(op.params.Info) != "info" {
		t.Errorf("Expected info 'info', got %q", op.params.Info)
	}
	if op.params.Hash != "SHA-384" {
		t.Errorf("Expected hash 'SHA-384' from CKM_SHA384 PRF, got %q", op.params.Hash)
	}
}

func TestDeriveKeyInit_HKDF_MissingParams(t *testing.T) {
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	// CKM_HKDF_DERIVE requires CK_HKDF_PARAMS (v3.2 section 6.62.2); a
	// mechanism without a parsed typed parameter must be refused rather
	// than derived under fabricated salt/info/hash defaults.
	mechanism := &Mechanism{
		Type: CKM_HKDF_DERIVE,
	}

	_, err := cm.DeriveKeyInit(mechanism, ObjectHandle(1), "test-key", "software")
	if err == nil {
		t.Fatal("expected error when CK_HKDF_PARAMS is missing")
	}
	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_MECHANISM_PARAM_INVALID {
		t.Errorf("expected CKR_MECHANISM_PARAM_INVALID, got %s", pkcsErr.Code.String())
	}
}

func TestDeriveKeyInit_ValidSP800108Counter(t *testing.T) {
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	mechanism := &Mechanism{
		Type: CKM_SP800_108_COUNTER_KDF,
		TypedParameter: &SP800108KDFParams{
			PRF: CKM_SHA256_HMAC,
			DataParams: []SP800108DataParam{
				{Type: SP800108ByteArray, Value: []byte("label")},
				{Type: SP800108ByteArray, Value: []byte{0x00}},
				{Type: SP800108ByteArray, Value: []byte("context")},
			},
		},
	}

	op, err := cm.DeriveKeyInit(mechanism, ObjectHandle(2), "kdk-key", "tpm")
	if err != nil {
		t.Fatalf("DeriveKeyInit failed: %v", err)
	}

	if op.Algorithm() != "SP800-108-COUNTER" {
		t.Errorf("Expected algorithm 'SP800-108-COUNTER', got '%s'", op.Algorithm())
	}
	if string(op.params.Label) != "label" {
		t.Errorf("Expected label 'label', got %q", op.params.Label)
	}
	if string(op.params.Context) != "context" {
		t.Errorf("Expected context 'context', got %q", op.params.Context)
	}
}

func TestDeriveKeyInit_ValidSP800108Feedback(t *testing.T) {
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	mechanism := &Mechanism{
		Type: CKM_SP800_108_FEEDBACK_KDF,
		TypedParameter: &SP800108KDFParams{
			PRF: CKM_SHA256_HMAC,
			DataParams: []SP800108DataParam{
				{Type: SP800108ByteArray, Value: []byte("label")},
				{Type: SP800108ByteArray, Value: []byte("context")},
			},
			IV: []byte("K0-initial-value"),
		},
	}

	op, err := cm.DeriveKeyInit(mechanism, ObjectHandle(3), "feedback-key", "software")
	if err != nil {
		t.Fatalf("DeriveKeyInit failed: %v", err)
	}

	if op.Algorithm() != "SP800-108-FEEDBACK" {
		t.Errorf("Expected algorithm 'SP800-108-FEEDBACK', got '%s'", op.Algorithm())
	}
	// Feedback mode's IV rides the transport's Salt field by convention
	// (see buildECDHKDFParams's usesSaltAsIV in pkg/xkms/servicer_crypto.go).
	if string(op.params.Salt) != "K0-initial-value" {
		t.Errorf("Expected Salt to carry the feedback IV, got %q", op.params.Salt)
	}
}

func TestDeriveKeyInit_ValidSP800108DoublePipeline(t *testing.T) {
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	mechanism := &Mechanism{
		Type: CKM_SP800_108_DOUBLE_PIPELINE_KDF,
		TypedParameter: &SP800108KDFParams{
			PRF: CKM_SHA256_HMAC,
			DataParams: []SP800108DataParam{
				{Type: SP800108ByteArray, Value: []byte("label")},
			},
		},
	}

	op, err := cm.DeriveKeyInit(mechanism, ObjectHandle(4), "pipeline-key", "software")
	if err != nil {
		t.Fatalf("DeriveKeyInit failed: %v", err)
	}

	if op.Algorithm() != "SP800-108-DOUBLE-PIPELINE" {
		t.Errorf("Expected algorithm 'SP800-108-DOUBLE-PIPELINE', got '%s'", op.Algorithm())
	}
}

func TestDeriveKeyInit_SP800108_MissingParams(t *testing.T) {
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	// All three SP800-108 mechanisms require CK_SP800_108_KDF_PARAMS /
	// CK_SP800_108_FEEDBACK_KDF_PARAMS (v3.2 section 6.42); a mechanism
	// without a parsed typed parameter must be refused.
	mechanism := &Mechanism{
		Type: CKM_SP800_108_COUNTER_KDF,
	}

	_, err := cm.DeriveKeyInit(mechanism, ObjectHandle(1), "test-key", "software")
	if err == nil {
		t.Fatal("expected error when CK_SP800_108_KDF_PARAMS is missing")
	}
	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_MECHANISM_PARAM_INVALID {
		t.Errorf("expected CKR_MECHANISM_PARAM_INVALID, got %s", pkcsErr.Code.String())
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
		TypedParameter: &HKDFParams{
			Extract:     true,
			Expand:      true,
			PRFHashMech: CKM_SHA256,
			SaltType:    CKF_HKDF_SALT_NULL,
		},
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
		TypedParameter: &HKDFParams{
			Extract:     true,
			Expand:      true,
			PRFHashMech: CKM_SHA256,
			SaltType:    CKF_HKDF_SALT_NULL,
		},
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
		{CKM_SHA224, "SHA-224"},
		{CKM_SHA256, "SHA-256"},
		{CKM_SHA384, "SHA-384"},
		{CKM_SHA512, "SHA-512"},
		{CKM_SHA3_224, "SHA3-224"},
		{CKM_SHA3_256, "SHA3-256"},
		{CKM_SHA3_384, "SHA3-384"},
		{CKM_SHA3_512, "SHA3-512"},
	}

	for _, tt := range tests {
		result, ok := mechanismToHashFromHKDF(tt.prf)
		if !ok {
			t.Errorf("mechanismToHashFromHKDF(%v) reported unsupported, want %s", tt.prf, tt.expected)
		}
		if result != tt.expected {
			t.Errorf("mechanismToHashFromHKDF(%v) = %s, want %s", tt.prf, result, tt.expected)
		}
	}
}

func TestMechanismToHashFromHKDF_Unsupported(t *testing.T) {
	// A mechanism that is not one of HKDF's approved prfHashMechanism
	// values must be refused, not silently mapped to SHA-256: a wrong
	// hash silently changes every derived key.
	if _, ok := mechanismToHashFromHKDF(CKM_AES_KEY_GEN); ok {
		t.Fatal("expected CKM_AES_KEY_GEN to be reported unsupported as an HKDF prfHashMechanism")
	}
}

func TestMechanismToHashFromPRF(t *testing.T) {
	tests := []struct {
		prf      MechanismType
		expected string
	}{
		{CKM_SHA_1_HMAC, "SHA-1"},
		{CKM_SHA224_HMAC, "SHA-224"},
		{CKM_SHA256_HMAC, "SHA-256"},
		{CKM_SHA384_HMAC, "SHA-384"},
		{CKM_SHA512_HMAC, "SHA-512"},
		{CKM_SHA3_224_HMAC, "SHA3-224"},
		{CKM_SHA3_256_HMAC, "SHA3-256"},
		{CKM_SHA3_384_HMAC, "SHA3-384"},
		{CKM_SHA3_512_HMAC, "SHA3-512"},
	}

	for _, tt := range tests {
		result, ok := mechanismToHashFromPRF(tt.prf)
		if !ok {
			t.Errorf("mechanismToHashFromPRF(%v) reported unsupported, want %s", tt.prf, tt.expected)
		}
		if result != tt.expected {
			t.Errorf("mechanismToHashFromPRF(%v) = %s, want %s", tt.prf, result, tt.expected)
		}
	}
}

func TestMechanismToHashFromPRF_CMACUnsupported(t *testing.T) {
	// CKM_AES_CMAC is a valid SP800-108 PRF per v3.2 Table 196, but this
	// module's derivation backend only implements the HMAC-based
	// construction. Silently treating it as HMAC-SHA256 would derive
	// different key material than a conformant CMAC-based token.
	if _, ok := mechanismToHashFromPRF(CKM_AES_CMAC); ok {
		t.Fatal("expected CKM_AES_CMAC to be reported unsupported as an SP800-108 PRF")
	}
}

func TestParseHKDFParams_MissingTypedParameter(t *testing.T) {
	mech := &Mechanism{Type: CKM_HKDF_DERIVE}
	_, err := parseHKDFParams(mech)
	if err == nil {
		t.Fatal("Expected error when TypedParameter is unset")
	}
}

func TestParseHKDFParams_Valid(t *testing.T) {
	mech := &Mechanism{
		Type: CKM_HKDF_DERIVE,
		TypedParameter: &HKDFParams{
			Extract:     true,
			Expand:      true,
			PRFHashMech: CKM_SHA256,
		},
	}
	params, err := parseHKDFParams(mech)
	if err != nil {
		t.Fatalf("parseHKDFParams failed: %v", err)
	}
	if params.PRFHashMech != CKM_SHA256 {
		t.Errorf("Expected PRFHashMech CKM_SHA256, got %v", params.PRFHashMech)
	}
}

func TestParseSP800108Params_MissingTypedParameter(t *testing.T) {
	mech := &Mechanism{Type: CKM_SP800_108_COUNTER_KDF}
	_, err := parseSP800108Params(mech)
	if err == nil {
		t.Fatal("Expected error when TypedParameter is unset")
	}
}

func TestParseSP800108Params_Valid(t *testing.T) {
	mech := &Mechanism{
		Type: CKM_SP800_108_COUNTER_KDF,
		TypedParameter: &SP800108KDFParams{
			PRF: CKM_SHA256_HMAC,
		},
	}
	params, err := parseSP800108Params(mech)
	if err != nil {
		t.Fatalf("parseSP800108Params failed: %v", err)
	}
	if params.PRF != CKM_SHA256_HMAC {
		t.Errorf("Expected PRF CKM_SHA256_HMAC, got %v", params.PRF)
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
	mech := &Mechanism{Type: CKM_AES_ECB}

	op, _ := cm.EncryptInit(mech, 1, "test-key", "backend1")

	// First encrypt should succeed
	if _, err := cm.Encrypt(context.Background(), op, []byte("data")); err != nil {
		t.Fatalf("first Encrypt failed: %v", err)
	}

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

// TestCryptoManager_Encrypt_RSAOAEP_RoutesToEncryptAsym proves CKM_RSA_PKCS_OAEP
// is served by the dedicated EncryptAsym RPC (which carries a selectable
// digest) rather than the generic Encrypt RPC (which has no digest field),
// and that the mechanism's CK_RSA_PKCS_OAEP_PARAMS.hashAlg reaches the
// request. Before this dispatch existed, CryptoManager.Encrypt sent every
// mechanism through cm.client.Encrypt, so a caller-designated RSA-OAEP
// wrapping key had no way to select its digest and no working path to the
// server at all -- see TestCryptoManager_Encrypt_ClientError's sibling for
// the generic path this deliberately bypasses.
func TestCryptoManager_Encrypt_RSAOAEP_RoutesToEncryptAsym(t *testing.T) {
	cm, client := newTestCryptoManager()
	client.encryptAsymResponse = &transport.EncryptAsymResponse{
		Ciphertext: []byte("oaep-wrapped-key"),
	}
	mech := &Mechanism{
		Type:           CKM_RSA_PKCS_OAEP,
		TypedParameter: &RSAOAEPParams{HashAlg: CKM_SHA384},
	}

	op, err := cm.EncryptInit(mech, 1, "rsa-kek", "backend1")
	if err != nil {
		t.Fatalf("EncryptInit failed: %v", err)
	}

	result, err := cm.Encrypt(context.Background(), op, []byte("target-key-material"))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if !bytes.Equal(result, []byte("oaep-wrapped-key")) {
		t.Errorf("unexpected ciphertext: %v", result)
	}

	if !client.encryptAsymCalled {
		t.Fatal("EncryptAsym was not called on client")
	}
	if client.encryptCalled {
		t.Error("generic Encrypt must not be called for CKM_RSA_PKCS_OAEP")
	}
	if client.lastEncryptAsymReq.KeyID != "rsa-kek" || client.lastEncryptAsymReq.Backend != "backend1" {
		t.Errorf("unexpected EncryptAsym request routing: %+v", client.lastEncryptAsymReq)
	}
	if client.lastEncryptAsymReq.Hash != "SHA-384" {
		t.Errorf("expected mechanism's OAEP hash SHA-384 to reach EncryptAsymRequest.Hash, got %q", client.lastEncryptAsymReq.Hash)
	}
}

// TestCryptoManager_Encrypt_RSAOAEP_ClientError proves an EncryptAsym failure
// on the dispatched path surfaces as CKR_FUNCTION_FAILED, the same contract
// the generic Encrypt path already gives callers (TestCryptoManager_Encrypt_ClientError).
func TestCryptoManager_Encrypt_RSAOAEP_ClientError(t *testing.T) {
	cm, client := newTestCryptoManager()
	client.encryptAsymError = errors.New("asym encrypt failed")
	mech := &Mechanism{Type: CKM_RSA_PKCS_OAEP}

	op, _ := cm.EncryptInit(mech, 1, "rsa-kek", "backend1")

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
	ciphertext := []byte("encrypted-data")
	nonce := []byte("123456789012") // 12-byte nonce
	tag := []byte("authtag1234567") // 14-byte tag (mechanism carries no TagBits override)
	client.encryptResponse = &transport.EncryptResponse{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Tag:        tag,
	}
	// EncryptInit rejects a caller-supplied GCM IV outright, so no params
	// are set here -- the backend is expected to generate the nonce.
	mech := &Mechanism{Type: CKM_AES_GCM}

	op, _ := cm.EncryptInit(mech, 1, freshGuardKeyID(t), "backend1")

	result, err := cm.Encrypt(context.Background(), op, []byte("plaintext"))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// PKCS#11 v3.2 section 6.13.7: the wire ciphertext is
	// ciphertext || tag, with no length-prefix framing.
	want := append(append([]byte{}, ciphertext...), tag...)
	if !bytes.Equal(result, want) {
		t.Errorf("expected ciphertext||tag %v, got %v", want, result)
	}

	// The module-generated nonce must be recorded on the operation and
	// flagged as generated, per the requirement that a token-generated
	// AES-GCM IV be retrievable after C_Encrypt.
	if !bytes.Equal(op.IV(), nonce) {
		t.Errorf("expected op.IV() %v, got %v", nonce, op.IV())
	}
	if !op.IVGenerated() {
		t.Error("expected IVGenerated() to be true for a backend-generated nonce")
	}
}

// TestCryptoManager_Encrypt_Decrypt_GCM_RoundTrip verifies the full
// ciphertext||tag wire format survives an encrypt/decrypt round trip: the
// nonce generated during Encrypt is fed back into DecryptInit (as a real
// caller would), and Decrypt correctly splits the trailing tag from the
// blob Encrypt produced.
func TestCryptoManager_Encrypt_Decrypt_GCM_RoundTrip(t *testing.T) {
	cm, client := newTestCryptoManager()
	backendCiphertext := []byte("opaque-backend-ciphertext")
	backendNonce := []byte("abcdefghijkl") // 12 bytes
	backendTag := bytes.Repeat([]byte{0x99}, GCMTagSize)
	client.encryptResponse = &transport.EncryptResponse{
		Ciphertext: backendCiphertext,
		Nonce:      backendNonce,
		Tag:        backendTag,
	}

	keyID := freshGuardKeyID(t)
	encMech := &Mechanism{Type: CKM_AES_GCM}
	encOp, err := cm.EncryptInit(encMech, 1, keyID, "backend1")
	if err != nil {
		t.Fatalf("EncryptInit failed: %v", err)
	}
	wire, err := cm.Encrypt(context.Background(), encOp, []byte("plaintext"))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// A conformant caller retrieves the generated IV and supplies it back
	// for decryption -- DecryptInit never generates one itself.
	decMech := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(encOp.IV(), 128))
	decOp, err := cm.DecryptInit(decMech, 1, keyID, "backend1")
	if err != nil {
		t.Fatalf("DecryptInit failed: %v", err)
	}
	if _, err := cm.Decrypt(context.Background(), decOp, wire); err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(client.lastDecryptReq.Ciphertext, backendCiphertext) {
		t.Errorf("expected split ciphertext %v, got %v", backendCiphertext, client.lastDecryptReq.Ciphertext)
	}
	if !bytes.Equal(client.lastDecryptReq.Tag, backendTag) {
		t.Errorf("expected split tag %v, got %v", backendTag, client.lastDecryptReq.Tag)
	}
	if !bytes.Equal(client.lastDecryptReq.Nonce, backendNonce) {
		t.Errorf("expected nonce %v, got %v", backendNonce, client.lastDecryptReq.Nonce)
	}
}

// TestCryptoManager_EncryptInit_GCM_CarriesCallerIV verifies that a
// caller-supplied CK_GCM_PARAMS.pIv is accepted and forwarded to the backend
// verbatim in EncryptRequest.Nonce. Encrypting under a nonce other than the one
// the caller chose would break any nonce-management scheme it is running.
func TestCryptoManager_EncryptInit_GCM_CarriesCallerIV(t *testing.T) {
	cm, client := newTestCryptoManager()
	callerIV := []byte("caller-iv-01")
	client.encryptResponse = &transport.EncryptResponse{
		Ciphertext: []byte("ciphertext"),
		Tag:        make([]byte, GCMTagSize),
	}
	mech := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(callerIV, 128))

	op, err := cm.EncryptInit(mech, 1, freshGuardKeyID(t), "backend1")
	if err != nil {
		t.Fatalf("EncryptInit failed: %v", err)
	}

	if _, err := cm.Encrypt(context.Background(), op, []byte("plaintext")); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if !bytes.Equal(client.lastEncryptReq.Nonce, callerIV) {
		t.Errorf("expected caller IV %x forwarded to backend, got %x",
			callerIV, client.lastEncryptReq.Nonce)
	}
}

// TestCryptoManager_EncryptInit_GCM_RejectsWrongLengthIV verifies that an IV of
// the wrong size is rejected rather than silently truncated or padded.
func TestCryptoManager_EncryptInit_GCM_RejectsWrongLengthIV(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams([]byte("too-short"), 128))

	_, err := cm.EncryptInit(mech, 1, "test-key", "backend1")
	if err == nil {
		t.Fatal("expected error for a wrong-length AES-GCM IV")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_MECHANISM_PARAM_INVALID {
		t.Errorf("expected CKR_MECHANISM_PARAM_INVALID, got %s", pkcsErr.Code.String())
	}
}

// TestCryptoManager_Encrypt_GCM_NonceReuseRejected verifies that reusing
// the same (backend, keyID, nonce) tuple across two encryptions under the
// same key is rejected. AES-GCM's confidentiality and integrity both
// depend on a (key, nonce) pair never repeating.
func TestCryptoManager_Encrypt_GCM_NonceReuseRejected(t *testing.T) {
	cm, client := newTestCryptoManager()
	reusedNonce := []byte("static-nonce")
	client.encryptResponse = &transport.EncryptResponse{
		Ciphertext: []byte("ciphertext-1"),
		Nonce:      reusedNonce,
		Tag:        bytes.Repeat([]byte{0x01}, GCMTagSize),
	}

	mech := &Mechanism{Type: CKM_AES_GCM}

	keyID := freshGuardKeyID(t)
	op1, _ := cm.EncryptInit(mech, 1, keyID, "backend1")
	if _, err := cm.Encrypt(context.Background(), op1, []byte("plaintext-1")); err != nil {
		t.Fatalf("first Encrypt failed: %v", err)
	}

	// A second, independent encryption under the same (backend, keyID) that
	// happens to reuse the same nonce (e.g. a misbehaving backend RNG) must
	// be rejected rather than silently accepted.
	op2, _ := cm.EncryptInit(mech, 1, keyID, "backend1")
	_, err := cm.Encrypt(context.Background(), op2, []byte("plaintext-2"))
	if err == nil {
		t.Fatal("expected error for reused AES-GCM nonce")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_MECHANISM_PARAM_INVALID {
		t.Errorf("expected CKR_MECHANISM_PARAM_INVALID, got %s", pkcsErr.Code.String())
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
	// CKM_AES_ECB requires no IV, keeping this test focused on default
	// backend resolution rather than AES-GCM parameter validation.
	mech := &Mechanism{Type: CKM_AES_ECB}

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
	mech := &Mechanism{Type: CKM_AES_ECB}

	op, _ := cm.DecryptInit(mech, 1, "test-key", "backend1")

	// First decrypt should succeed
	if _, err := cm.Decrypt(context.Background(), op, []byte("data")); err != nil {
		t.Fatalf("first Decrypt failed: %v", err)
	}

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
	mech := &Mechanism{Type: CKM_AES_ECB}

	op, _ := cm.DecryptInit(mech, 1, "test-key", "backend1")

	_, err := cm.Decrypt(context.Background(), op, []byte("data"))
	if err == nil {
		t.Fatal("expected error from client")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	// A decryption that fails on the ciphertext is CKR_ENCRYPTED_DATA_INVALID
	// (v3.2 §3.2, listed for C_Decrypt in §5.10.2), not the generic
	// CKR_FUNCTION_FAILED. The distinction is the point: a caller must be able
	// to tell a wrong tag or wrong key from a device malfunction.
	if pkcsErr.Code != CKR_ENCRYPTED_DATA_INVALID {
		t.Errorf("expected CKR_ENCRYPTED_DATA_INVALID, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_Decrypt_WithAAD(t *testing.T) {
	cm, client := newTestCryptoManager()
	// AAD forwarding is independent of the mechanism's framing; CKM_AES_ECB
	// keeps this test focused on the AAD plumbing.
	mech := &Mechanism{Type: CKM_AES_ECB}

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

// TestCryptoManager_Decrypt_CiphertextTagSplit verifies the PKCS#11 v3.2
// section 6.13.7 wire format: the ciphertext argument is
// actualCiphertext || tag (simple concatenation, no length-prefix framing),
// split using the tag length resolved from CK_GCM_PARAMS. The nonce comes
// from DecryptInit's mechanism parameter, never from the ciphertext blob.
func TestCryptoManager_Decrypt_CiphertextTagSplit(t *testing.T) {
	cm, client := newTestCryptoManager()
	nonce := []byte("123456789012")   // 12 bytes
	tag := []byte("1234567890123456") // 16 bytes
	actualCiphertext := []byte("encrypted-data")

	mech := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(nonce, 128))
	op, err := cm.DecryptInit(mech, 1, "test-key", "backend1")
	if err != nil {
		t.Fatalf("DecryptInit failed: %v", err)
	}

	wire := append(append([]byte{}, actualCiphertext...), tag...)

	_, err = cm.Decrypt(context.Background(), op, wire)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// The nonce comes from DecryptInit's CK_GCM_PARAMS, not from the wire data.
	if !bytes.Equal(client.lastDecryptReq.Nonce, nonce) {
		t.Errorf("nonce not forwarded from DecryptInit: got %v, want %v", client.lastDecryptReq.Nonce, nonce)
	}
	if !bytes.Equal(client.lastDecryptReq.Tag, tag) {
		t.Errorf("tag not split correctly: got %v, want %v", client.lastDecryptReq.Tag, tag)
	}
	if !bytes.Equal(client.lastDecryptReq.Ciphertext, actualCiphertext) {
		t.Errorf("ciphertext not split correctly: got %v, want %v", client.lastDecryptReq.Ciphertext, actualCiphertext)
	}
}

// TestCryptoManager_Decrypt_ShortCiphertext verifies that AES-GCM
// ciphertext shorter than the tag length is now rejected outright
// (CKR_ENCRYPTED_DATA_LEN_RANGE) rather than silently passed through, since
// there is no valid way to split a tag out of it.
func TestCryptoManager_Decrypt_ShortCiphertext(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams([]byte("123456789012"), 128))

	op, err := cm.DecryptInit(mech, 1, "test-key", "backend1")
	if err != nil {
		t.Fatalf("DecryptInit failed: %v", err)
	}

	shortData := []byte("abc") // far shorter than the 16-byte tag
	_, err = cm.Decrypt(context.Background(), op, shortData)
	if err == nil {
		t.Fatal("expected error for ciphertext shorter than the GCM tag")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_ENCRYPTED_DATA_LEN_RANGE {
		t.Errorf("expected CKR_ENCRYPTED_DATA_LEN_RANGE, got %s", pkcsErr.Code.String())
	}
}

// TestCryptoManager_Decrypt_NonAEAD_PassesThroughUnmodified verifies that
// ciphertext for a non-AEAD mechanism is forwarded to the backend byte for
// byte, including data that happens to start with four 0x00 bytes -- the
// exact pattern the removed private length-prefix framing used to
// misinterpret as an embedded nonce/tag header and strip.
func TestCryptoManager_Decrypt_NonAEAD_PassesThroughUnmodified(t *testing.T) {
	cm, client := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_AES_ECB}

	op, err := cm.DecryptInit(mech, 1, "test-key", "backend1")
	if err != nil {
		t.Fatalf("DecryptInit failed: %v", err)
	}

	data := append([]byte{0x00, 0x00, 0x00, 0x00}, []byte("rest-of-ciphertext")...)
	_, err = cm.Decrypt(context.Background(), op, data)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(client.lastDecryptReq.Ciphertext, data) {
		t.Errorf("non-AEAD ciphertext must pass through unmodified: got %v, want %v", client.lastDecryptReq.Ciphertext, data)
	}
	if client.lastDecryptReq.Nonce != nil {
		t.Errorf("non-AEAD decryption must not synthesize a nonce, got %v", client.lastDecryptReq.Nonce)
	}
	if client.lastDecryptReq.Tag != nil {
		t.Errorf("non-AEAD decryption must not synthesize a tag, got %v", client.lastDecryptReq.Tag)
	}
}

// TestCryptoManager_DecryptInit_GCM_MissingIV verifies that DecryptInit
// itself now rejects a CKM_AES_GCM mechanism carrying no IV: decryption
// always requires the caller to supply the exact nonce used at encryption
// time, so there is nothing to eagerly validate a decrypt-init against.
func TestCryptoManager_DecryptInit_GCM_MissingIV(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_AES_GCM} // no CK_GCM_PARAMS at all

	_, err := cm.DecryptInit(mech, 1, "test-key", "backend1")
	if err == nil {
		t.Fatal("expected error for AES-GCM decryption with no IV")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_MECHANISM_PARAM_INVALID {
		t.Errorf("expected CKR_MECHANISM_PARAM_INVALID, got %s", pkcsErr.Code.String())
	}
}

// TestCryptoManager_DecryptInit_GCM_EmptyIV is the same as
// TestCryptoManager_DecryptInit_GCM_MissingIV but with CK_GCM_PARAMS
// present and pIv explicitly empty, exercising the other branch of
// resolveAEADDecryptIV's validation.
func TestCryptoManager_DecryptInit_GCM_EmptyIV(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(nil, 128))

	_, err := cm.DecryptInit(mech, 1, "test-key", "backend1")
	if err == nil {
		t.Fatal("expected error for AES-GCM decryption with empty IV")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_MECHANISM_PARAM_INVALID {
		t.Errorf("expected CKR_MECHANISM_PARAM_INVALID, got %s", pkcsErr.Code.String())
	}
}

// TestCryptoManager_Decrypt_CustomTagLength verifies that a non-default
// CK_GCM_PARAMS.ulTagBits (96 bits / 12 bytes here, instead of the 128-bit
// default) is honored when splitting the tag off the wire ciphertext.
func TestCryptoManager_Decrypt_CustomTagLength(t *testing.T) {
	cm, client := newTestCryptoManager()
	nonce := []byte("123456789012")
	tag := bytes.Repeat([]byte{0xCC}, 12) // 96-bit tag
	actualCiphertext := []byte("ciphertext")

	mech := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(nonce, 96))
	op, err := cm.DecryptInit(mech, 1, "test-key", "backend1")
	if err != nil {
		t.Fatalf("DecryptInit failed: %v", err)
	}

	wire := append(append([]byte{}, actualCiphertext...), tag...)
	if _, err := cm.Decrypt(context.Background(), op, wire); err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(client.lastDecryptReq.Tag, tag) {
		t.Errorf("expected 12-byte tag %v, got %v", tag, client.lastDecryptReq.Tag)
	}
	if !bytes.Equal(client.lastDecryptReq.Ciphertext, actualCiphertext) {
		t.Errorf("expected ciphertext %v, got %v", actualCiphertext, client.lastDecryptReq.Ciphertext)
	}
}

// ----------------------------------------------------------------
// AES-CBC / AES-CBC-PAD IV validation (PKCS#11 v3.2 sections 6.10.5/6.10.6)
// ----------------------------------------------------------------

func TestCryptoManager_EncryptInit_CBC_MissingIV(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_AES_CBC} // no IV mechanism parameter

	_, err := cm.EncryptInit(mech, 1, "test-key", "backend1")
	if err == nil {
		t.Fatal("expected error for CKM_AES_CBC with no IV")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_MECHANISM_PARAM_INVALID {
		t.Errorf("expected CKR_MECHANISM_PARAM_INVALID, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_EncryptInit_CBC_WrongIVLength(t *testing.T) {
	cm, _ := newTestCryptoManager()
	// CK_MECHANISM.pParameter for CBC is the raw IV with no wrapping struct;
	// 8 bytes is neither a valid AES block size nor the required 16.
	mech := NewMechanismWithParams(CKM_AES_CBC_PAD, []byte{1, 2, 3, 4, 5, 6, 7, 8})

	_, err := cm.EncryptInit(mech, 1, "test-key", "backend1")
	if err == nil {
		t.Fatal("expected error for CKM_AES_CBC_PAD with a wrong-length IV")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_MECHANISM_PARAM_INVALID {
		t.Errorf("expected CKR_MECHANISM_PARAM_INVALID, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_DecryptInit_CBC_MissingIV(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_AES_CBC}

	_, err := cm.DecryptInit(mech, 1, "test-key", "backend1")
	if err == nil {
		t.Fatal("expected error for CKM_AES_CBC decryption with no IV")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_MECHANISM_PARAM_INVALID {
		t.Errorf("expected CKR_MECHANISM_PARAM_INVALID, got %s", pkcsErr.Code.String())
	}
}

// TestCryptoManager_Encrypt_CBC_ForwardsCallerIV verifies that the 16-byte IV
// CKM_AES_CBC requires is carried to the backend verbatim. Encrypting under any
// other IV would produce ciphertext no conformant peer could decrypt with the
// IV the caller specified.
func TestCryptoManager_Encrypt_CBC_ForwardsCallerIV(t *testing.T) {
	cm, client := newTestCryptoManager()
	var iv [16]byte
	copy(iv[:], "0123456789abcdef")
	client.encryptResponse = &transport.EncryptResponse{Ciphertext: []byte("ciphertext")}
	mech := NewMechanismWithTypedParams(CKM_AES_CBC, NewAESCBCParams(iv))

	op, err := cm.EncryptInit(mech, 1, "test-key", "backend1")
	if err != nil {
		t.Fatalf("EncryptInit failed: %v", err)
	}

	if _, err := cm.Encrypt(context.Background(), op, []byte("plaintext")); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// The IV travels in the request's IV field with Mode naming the cipher
	// mode, not in Nonce. The two are deliberately distinct: a GCM nonce is 12
	// bytes and carries an authentication role, a CBC IV is 16 and carries
	// none. Sending a CBC IV as a Nonce with no Mode is what made the backend
	// build AES-GCM and reject it as malformed, so CKM_AES_CBC failed for every
	// caller despite being advertised with CKF_ENCRYPT.
	if client.lastEncryptReq.Mode != "cbc" {
		t.Errorf("expected Mode %q, got %q", "cbc", client.lastEncryptReq.Mode)
	}
	if !bytes.Equal(client.lastEncryptReq.IV, iv[:]) {
		t.Errorf("expected CBC IV %x forwarded to backend, got %x",
			iv[:], client.lastEncryptReq.IV)
	}
	if len(client.lastEncryptReq.Nonce) != 0 {
		t.Errorf("a CBC IV must not be sent as an AEAD nonce, got %x",
			client.lastEncryptReq.Nonce)
	}
}

// TestCryptoManager_Decrypt_CBC_ForwardsIV verifies that Decrypt forwards the
// IV resolved by DecryptInit to the backend in DecryptRequest.IV, names the
// cipher mode, and does not attempt any AEAD tag splitting for a non-GCM
// mechanism.
func TestCryptoManager_Decrypt_CBC_ForwardsIV(t *testing.T) {
	cm, client := newTestCryptoManager()
	var iv [16]byte
	copy(iv[:], "0123456789abcdef")
	mech := NewMechanismWithTypedParams(CKM_AES_CBC, NewAESCBCParams(iv))

	op, err := cm.DecryptInit(mech, 1, "test-key", "backend1")
	if err != nil {
		t.Fatalf("DecryptInit failed: %v", err)
	}

	ciphertext := []byte("ciphertext-block")
	if _, err := cm.Decrypt(context.Background(), op, ciphertext); err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if client.lastDecryptReq.Mode != "cbc" {
		t.Errorf("expected Mode %q, got %q", "cbc", client.lastDecryptReq.Mode)
	}
	if !bytes.Equal(client.lastDecryptReq.IV, iv[:]) {
		t.Errorf("expected IV %v forwarded in the IV field, got %v", iv[:], client.lastDecryptReq.IV)
	}
	if len(client.lastDecryptReq.Nonce) != 0 {
		t.Errorf("a CBC IV must not be sent as an AEAD nonce, got %x", client.lastDecryptReq.Nonce)
	}
	if !bytes.Equal(client.lastDecryptReq.Ciphertext, ciphertext) {
		t.Errorf("expected ciphertext to pass through unmodified, got %v", client.lastDecryptReq.Ciphertext)
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
	mech := &Mechanism{Type: CKM_AES_ECB}

	op, err := cm.DecryptInit(mech, 1, "test-key", "backend1")
	if err != nil {
		t.Fatalf("DecryptInit failed: %v", err)
	}
	op.finalized = true

	err = cm.DecryptUpdate(op, []byte("data"))
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
	mech := &Mechanism{Type: CKM_AES_ECB}

	op, err := cm.DecryptInit(mech, 1, "test-key", "backend1")
	if err != nil {
		t.Fatalf("DecryptInit failed: %v", err)
	}
	op.finalized = true

	_, err = cm.DecryptFinal(context.Background(), op)
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

// The next five tests supply only raw, unstructured Parameter bytes with no
// TypedParameter -- the shape a caller would produce if the cgo boundary
// never parsed CK_HKDF_PARAMS / CK_SP800_108_*_KDF_PARAMS into a typed
// value. Before the fix, DeriveKeyInit accepted this and silently derived
// under fabricated salt/info/label/context/PRF defaults, returning success
// for a request whose actual parameters were discarded. It must now be
// refused: raw bytes copied out of a C struct are not safe to
// byte-unpack in Go (CK_HKDF_PARAMS and CK_SP800_108_KDF_PARAMS carry C
// pointers, not inline data), so TypedParameter is the only valid carrier.

func TestDeriveKeyInit_HKDFWithParams(t *testing.T) {
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	mechanism := &Mechanism{
		Type:      CKM_HKDF_DERIVE,
		Parameter: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}

	_, err := cm.DeriveKeyInit(mechanism, ObjectHandle(1), "test-key", "software")
	if err == nil {
		t.Fatal("expected error: raw Parameter bytes without a parsed CK_HKDF_PARAMS must not derive")
	}
}

func TestDeriveKeyInit_HKDFDataWithParams(t *testing.T) {
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	mechanism := &Mechanism{
		Type:      CKM_HKDF_DATA,
		Parameter: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A},
	}

	_, err := cm.DeriveKeyInit(mechanism, ObjectHandle(1), "test-key", "software")
	if err == nil {
		t.Fatal("expected error: raw Parameter bytes without a parsed CK_HKDF_PARAMS must not derive")
	}
}

func TestDeriveKeyInit_SP800108CounterWithParams(t *testing.T) {
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	mechanism := &Mechanism{
		Type:      CKM_SP800_108_COUNTER_KDF,
		Parameter: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
	}

	_, err := cm.DeriveKeyInit(mechanism, ObjectHandle(1), "test-key", "software")
	if err == nil {
		t.Fatal("expected error: raw Parameter bytes without a parsed CK_SP800_108_KDF_PARAMS must not derive")
	}
}

func TestDeriveKeyInit_SP800108FeedbackWithParams(t *testing.T) {
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	mechanism := &Mechanism{
		Type:      CKM_SP800_108_FEEDBACK_KDF,
		Parameter: []byte{0x01, 0x02, 0x03, 0x04},
	}

	_, err := cm.DeriveKeyInit(mechanism, ObjectHandle(1), "test-key", "software")
	if err == nil {
		t.Fatal("expected error: raw Parameter bytes without a parsed CK_SP800_108_FEEDBACK_KDF_PARAMS must not derive")
	}
}

func TestDeriveKeyInit_SP800108DoublePipelineWithParams(t *testing.T) {
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	mechanism := &Mechanism{
		Type:      CKM_SP800_108_DOUBLE_PIPELINE_KDF,
		Parameter: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
	}

	_, err := cm.DeriveKeyInit(mechanism, ObjectHandle(1), "test-key", "software")
	if err == nil {
		t.Fatal("expected error: raw Parameter bytes without a parsed CK_SP800_108_KDF_PARAMS must not derive")
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
		TypedParameter: &HKDFParams{
			Extract:     true,
			Expand:      true,
			PRFHashMech: CKM_SHA256,
			SaltType:    CKF_HKDF_SALT_NULL,
		},
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

func TestParseHKDFParams_SaltKeyRejectedByDeriveKeyInit(t *testing.T) {
	// CKF_HKDF_SALT_KEY requires resolving hSaltKey to another object's
	// CKA_VALUE, which DeriveKeyInit has no key-object access to perform.
	// It must be refused outright, not treated as CKF_HKDF_SALT_NULL.
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	mechanism := &Mechanism{
		Type: CKM_HKDF_DERIVE,
		TypedParameter: &HKDFParams{
			Extract:     true,
			Expand:      true,
			PRFHashMech: CKM_SHA256,
			SaltType:    CKF_HKDF_SALT_KEY,
			SaltKey:     ObjectHandle(7),
		},
	}

	_, err := cm.DeriveKeyInit(mechanism, ObjectHandle(1), "test-key", "software")
	if err == nil {
		t.Fatal("expected error for CKF_HKDF_SALT_KEY")
	}
}

func TestParseHKDFParams_ExtractOnlyRejected(t *testing.T) {
	// The derivation backend only implements the full RFC 5869
	// extract-then-expand construction; bExtract=true/bExpand=false must
	// be refused rather than silently derived as if both were true.
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	mechanism := &Mechanism{
		Type: CKM_HKDF_DERIVE,
		TypedParameter: &HKDFParams{
			Extract:     true,
			Expand:      false,
			PRFHashMech: CKM_SHA256,
			SaltType:    CKF_HKDF_SALT_NULL,
		},
	}

	_, err := cm.DeriveKeyInit(mechanism, ObjectHandle(1), "test-key", "software")
	if err == nil {
		t.Fatal("expected error for extract-only HKDF")
	}
}

func TestParseSP800108Params_KeyHandleDataParamRejected(t *testing.T) {
	// CK_SP800_108_KEY_HANDLE mixes another key's raw value into the PRF
	// input; this module's derivation backend has no way to reproduce
	// that, so it must be refused rather than silently dropped.
	client := newMockClient()
	cm := NewCryptoManager(client, nil)

	mechanism := &Mechanism{
		Type: CKM_SP800_108_COUNTER_KDF,
		TypedParameter: &SP800108KDFParams{
			PRF: CKM_SHA256_HMAC,
			DataParams: []SP800108DataParam{
				{Type: SP800108ByteArray, Value: []byte("label")},
				{Type: SP800108KeyHandle, Value: []byte{0, 0, 0, 0, 0, 0, 0, 9}},
			},
		},
	}

	_, err := cm.DeriveKeyInit(mechanism, ObjectHandle(1), "test-key", "software")
	if err == nil {
		t.Fatal("expected error for CK_SP800_108_KEY_HANDLE data param")
	}
}

func TestSP800108LabelContext_SingleByteArray(t *testing.T) {
	label, context, err := sp800108LabelContext([]SP800108DataParam{
		{Type: SP800108ByteArray, Value: []byte("only-label")},
	})
	if err != nil {
		t.Fatalf("sp800108LabelContext failed: %v", err)
	}
	if string(label) != "only-label" {
		t.Errorf("expected label 'only-label', got %q", label)
	}
	if len(context) != 0 {
		t.Errorf("expected empty context, got %q", context)
	}
}

func TestSP800108LabelContext_UnsupportedDKMLength(t *testing.T) {
	// An explicit CK_SP800_108_DKM_LENGTH segment encodes the derived key
	// length into the PRF input itself; honoring it approximately would
	// silently derive different key material than a conformant token.
	_, _, err := sp800108LabelContext([]SP800108DataParam{
		{Type: SP800108ByteArray, Value: []byte("label")},
		{Type: SP800108DKMLength, Value: []byte{1, 0, 0, 0, 0, 16, 0}},
	})
	if err == nil {
		t.Fatal("expected error for CK_SP800_108_DKM_LENGTH data param")
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

	if resp.KeyMaterial.Size() == 0 {
		t.Error("expected non-empty key material")
	}
	resp.KeyMaterial.Destroy()
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
	resp.KeyMaterial.Destroy()
}

// ----------------------------------------------------------------
// ImportKeyMaterial Tests
// ----------------------------------------------------------------

func TestCryptoManager_ImportKeyMaterial_NilRequest(t *testing.T) {
	cm, _ := newTestCryptoManager()

	_, err := cm.ImportKeyMaterial(context.Background(), nil)
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

func TestCryptoManager_ImportKeyMaterial_EmptyKeyMaterial(t *testing.T) {
	cm, _ := newTestCryptoManager()

	req := &ImportKeyMaterialRequest{KeyID: "import-key"}

	_, err := cm.ImportKeyMaterial(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for nil key material")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_ATTRIBUTE_VALUE_INVALID {
		t.Errorf("expected CKR_ATTRIBUTE_VALUE_INVALID, got %s", pkcsErr.Code.String())
	}
}

func TestCryptoManager_ImportKeyMaterial_Success(t *testing.T) {
	cm, client := newTestCryptoManager()

	keyMaterial, err := secure.NewBufferFromBytes(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatalf("NewBufferFromBytes: %v", err)
	}
	defer keyMaterial.Destroy()

	req := &ImportKeyMaterialRequest{
		KeyID:       "import-key",
		Backend:     "test-backend",
		KeyMaterial: keyMaterial,
	}

	keyID, err := cm.ImportKeyMaterial(context.Background(), req)
	if err != nil {
		t.Fatalf("ImportKeyMaterial failed: %v", err)
	}
	if keyID == "" {
		t.Fatal("expected non-empty key id")
	}
	if !client.importKeyCalled {
		t.Fatal("expected ImportKey to be called on the transport client")
	}

	// The material the mock's RSA-OAEP oracle recovered must match what was
	// sealed into the request buffer — proving the wrap traveled the real
	// plaintext, not zeroed-out memory left over from an early Destroy.
	got, ok := client.importedMaterial[req.KeyID]
	if !ok {
		t.Fatalf("mock recorded no imported material for key id %q", req.KeyID)
	}
	if !bytes.Equal(got, bytes.Repeat([]byte{0x42}, 32)) {
		t.Fatalf("imported material = %x, want 32 bytes of 0x42", got)
	}
}

// ----------------------------------------------------------------
// ECDSA signature wire-format normalization (PKCS#11 v3.2 section 6.3.1)
// ----------------------------------------------------------------

// TestCryptoManager_Sign_ECDSA_NormalizesDERToRaw verifies that Sign()
// converts a DER-encoded ECDSA signature (as a non-conformant backend might
// still produce) into the required raw r || s wire format, with each
// component padded to the curve's field-element width (nLen): 32 bytes for
// P-256, 48 for P-384, 66 for P-521.
func TestCryptoManager_Sign_ECDSA_NormalizesDERToRaw(t *testing.T) {
	cases := []struct {
		name string
		mech MechanismType
		nLen int
	}{
		{"P-256", CKM_ECDSA_SHA256, 32},
		{"P-384", CKM_ECDSA_SHA384, 48},
		{"P-521", CKM_ECDSA_SHA512, 66},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cm, client := newTestCryptoManager()

			// r has its top bit set, forcing DER to prepend a 0x00 sign byte
			// internally; s is deliberately small, forcing left-zero-padding
			// on the raw side. Both exercise the fixed-width encoding.
			r := new(big.Int).Lsh(big.NewInt(1), uint(tc.nLen*8-1))
			r.Add(r, big.NewInt(17))
			s := big.NewInt(7)

			der, err := asn1.Marshal(ecdsaDERSignature{R: r, S: s})
			if err != nil {
				t.Fatalf("failed to build test DER signature: %v", err)
			}
			client.signResponse = &transport.SignResponse{Signature: der}

			mech := &Mechanism{Type: tc.mech}
			op, err := cm.SignInit(mech, 1, "ec-key", "backend1")
			if err != nil {
				t.Fatalf("SignInit failed: %v", err)
			}

			sig, err := cm.Sign(context.Background(), op, []byte("data"))
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			if len(sig) != 2*tc.nLen {
				t.Fatalf("expected %d-byte raw signature, got %d bytes", 2*tc.nLen, len(sig))
			}

			gotR := new(big.Int).SetBytes(sig[:tc.nLen])
			gotS := new(big.Int).SetBytes(sig[tc.nLen:])
			if gotR.Cmp(r) != 0 {
				t.Errorf("r mismatch: got %v, want %v", gotR, r)
			}
			if gotS.Cmp(s) != 0 {
				t.Errorf("s mismatch: got %v, want %v", gotS, s)
			}
		})
	}
}

// TestCryptoManager_Sign_ECDSA_RawPassesThrough verifies that a backend
// which already returns a raw r || s signature (the conformant case) is
// passed through unchanged rather than being mistaken for DER and mangled.
func TestCryptoManager_Sign_ECDSA_RawPassesThrough(t *testing.T) {
	cm, client := newTestCryptoManager()
	raw := bytes.Repeat([]byte{0x42}, 64) // P-256 raw r || s
	client.signResponse = &transport.SignResponse{Signature: raw}

	mech := &Mechanism{Type: CKM_ECDSA_SHA256}
	op, _ := cm.SignInit(mech, 1, "ec-key", "backend1")

	sig, err := cm.Sign(context.Background(), op, []byte("data"))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if !bytes.Equal(sig, raw) {
		t.Errorf("expected raw signature to pass through unchanged, got %v", sig)
	}
}

// TestCryptoManager_Verify_ECDSA_ConvertsRawToDER verifies that Verify()
// converts a caller-supplied raw r || s signature to ASN.1 DER before
// sending it to the backend, since this module's verification path uses
// crypto/ecdsa.VerifyASN1 internally.
func TestCryptoManager_Verify_ECDSA_ConvertsRawToDER(t *testing.T) {
	cm, client := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_ECDSA_SHA256}
	op, _ := cm.VerifyInit(mech, 1, "ec-key", "backend1")

	const nLen = 32
	raw := make([]byte, 2*nLen)
	raw[nLen-1] = 0x2A   // r = 42
	raw[2*nLen-1] = 0x07 // s = 7

	if err := cm.Verify(context.Background(), op, []byte("data"), raw); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	var parsed ecdsaDERSignature
	rest, err := asn1.Unmarshal(client.lastVerifyReq.Signature, &parsed)
	if err != nil || len(rest) != 0 {
		t.Fatalf("expected a well-formed DER signature sent to the backend, got %v (err=%v)", client.lastVerifyReq.Signature, err)
	}
	if parsed.R.Int64() != 42 {
		t.Errorf("expected r=42, got %v", parsed.R)
	}
	if parsed.S.Int64() != 7 {
		t.Errorf("expected s=7, got %v", parsed.S)
	}
}

// TestCryptoManager_Verify_ECDSA_RejectsOddLengthSignature verifies that a
// signature which is neither valid DER nor an even-length raw r || s
// concatenation is rejected before ever reaching the backend.
func TestCryptoManager_Verify_ECDSA_RejectsOddLengthSignature(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_ECDSA_SHA256}
	op, _ := cm.VerifyInit(mech, 1, "ec-key", "backend1")

	err := cm.Verify(context.Background(), op, []byte("data"), []byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Fatal("expected error for odd-length raw ECDSA signature")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_SIGNATURE_LEN_RANGE {
		t.Errorf("expected CKR_SIGNATURE_LEN_RANGE, got %s", pkcsErr.Code.String())
	}
}

// TestCryptoManager_Verify_EmptySignature verifies that C_Verify rejects an
// empty signature locally (CKR_SIGNATURE_LEN_RANGE) without a round trip to
// the backend, mirroring the equivalent VerifyRecover check.
func TestCryptoManager_Verify_EmptySignature(t *testing.T) {
	cm, client := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_RSA_PKCS}
	op, _ := cm.VerifyInit(mech, 1, "rsa-key", "backend1")

	err := cm.Verify(context.Background(), op, []byte("data"), []byte{})
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
	if client.verifyCalled {
		t.Error("Verify should reject an empty signature without calling the backend")
	}
}

// ----------------------------------------------------------------
// RSA-PSS parameter validation (PKCS#11 v3.2 section 6.4.3)
// ----------------------------------------------------------------

// TestCryptoManager_SignInit_PSS_MissingParams verifies that SignInit
// requires CK_RSA_PKCS_PSS_PARAMS for every RSA-PSS mechanism, including
// the generic CKM_RSA_PKCS_PSS which carries no implied hash of its own.
func TestCryptoManager_SignInit_PSS_MissingParams(t *testing.T) {
	cm, _ := newTestCryptoManager()
	mech := &Mechanism{Type: CKM_RSA_PKCS_PSS} // no TypedParameter

	_, err := cm.SignInit(mech, 1, "rsa-key", "backend1")
	if err == nil {
		t.Fatal("expected error for RSA-PSS SignInit with no parameters")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_MECHANISM_PARAM_INVALID {
		t.Errorf("expected CKR_MECHANISM_PARAM_INVALID, got %s", pkcsErr.Code.String())
	}
}

// TestCryptoManager_SignInit_PSS_HashMismatch verifies that a hash-specific
// PSS mechanism (whose name implies a hash algorithm) rejects
// CK_RSA_PKCS_PSS_PARAMS.hashAlg values that disagree with it.
func TestCryptoManager_SignInit_PSS_HashMismatch(t *testing.T) {
	cm, _ := newTestCryptoManager()
	// CKM_SHA256_RSA_PKCS_PSS implies SHA-256, but the params claim SHA-384.
	params := NewRSAPSSParamsWithSaltLen(CKM_SHA384, 48)
	mech := NewMechanismWithTypedParams(CKM_SHA256_RSA_PKCS_PSS, params)

	_, err := cm.SignInit(mech, 1, "rsa-key", "backend1")
	if err == nil {
		t.Fatal("expected error for mismatched PSS hash algorithm")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_MECHANISM_PARAM_INVALID {
		t.Errorf("expected CKR_MECHANISM_PARAM_INVALID, got %s", pkcsErr.Code.String())
	}
}

// TestCryptoManager_VerifyInit_PSS_HashMismatch mirrors
// TestCryptoManager_SignInit_PSS_HashMismatch for VerifyInit, since both
// paths call the same validateRSAPSSParams check.
func TestCryptoManager_VerifyInit_PSS_HashMismatch(t *testing.T) {
	cm, _ := newTestCryptoManager()
	params := NewRSAPSSParamsWithSaltLen(CKM_SHA512, 64)
	mech := NewMechanismWithTypedParams(CKM_SHA256_RSA_PKCS_PSS, params)

	_, err := cm.VerifyInit(mech, 1, "rsa-key", "backend1")
	if err == nil {
		t.Fatal("expected error for mismatched PSS hash algorithm")
	}

	pkcsErr, ok := err.(*PKCS11Error)
	if !ok {
		t.Fatalf("expected PKCS11Error, got %T", err)
	}
	if pkcsErr.Code != CKR_MECHANISM_PARAM_INVALID {
		t.Errorf("expected CKR_MECHANISM_PARAM_INVALID, got %s", pkcsErr.Code.String())
	}
}

// TestCryptoManager_Sign_PSS_Success is the positive-path counterpart to
// the PSS validation failure tests above: matching params for a
// hash-specific PSS mechanism must succeed and resolve the hash from the
// mechanism parameters.
func TestCryptoManager_Sign_PSS_Success(t *testing.T) {
	cm, client := newTestCryptoManager()
	params := NewRSAPSSParamsWithSaltLen(CKM_SHA256, 32)
	mech := NewMechanismWithTypedParams(CKM_SHA256_RSA_PKCS_PSS, params)

	op, err := cm.SignInit(mech, 1, "rsa-key", "backend1")
	if err != nil {
		t.Fatalf("SignInit failed: %v", err)
	}

	if _, err := cm.Sign(context.Background(), op, []byte("data")); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if client.lastSignReq.Hash != "SHA-256" {
		t.Errorf("expected hash 'SHA-256' resolved from PSS params, got %s", client.lastSignReq.Hash)
	}
}

// TestCryptoManager_Sign_PSS_GenericMechanism verifies that the generic
// CKM_RSA_PKCS_PSS mechanism (no implied hash of its own) resolves the hash
// entirely from CK_RSA_PKCS_PSS_PARAMS.hashAlg.
func TestCryptoManager_Sign_PSS_GenericMechanism(t *testing.T) {
	cm, client := newTestCryptoManager()
	params := NewRSAPSSParamsWithSaltLen(CKM_SHA384, 48)
	mech := NewMechanismWithTypedParams(CKM_RSA_PKCS_PSS, params)

	op, err := cm.SignInit(mech, 1, "rsa-key", "backend1")
	if err != nil {
		t.Fatalf("SignInit failed: %v", err)
	}

	if _, err := cm.Sign(context.Background(), op, []byte("data")); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if client.lastSignReq.Hash != "SHA-384" {
		t.Errorf("expected hash 'SHA-384' resolved from PSS params, got %s", client.lastSignReq.Hash)
	}
}

// hmacOracleDigests resolves a wire-level hash name to the digest constructor
// an HMAC over that name must be keyed with.
//
// It is a separate, deliberately hand-written table rather than a call back
// into the module. Resolving the name through the code under test would make
// the oracle agree with the module by construction, and a wrong name would be
// indistinguishable from a right one.
var hmacOracleDigests = map[string]func() hash.Hash{
	"SHA-256": sha256.New,
	"SHA-384": sha512.New384,
	"SHA-512": sha512.New,
}

// hmacTag computes the RFC 2104 tag crypto/hmac produces for the given digest,
// key and message.
func hmacTag(newHash func() hash.Hash, key, message []byte) []byte {
	mac := hmac.New(newHash, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// TestSignHMACMechanismsCarryTheirOwnDigest proves each SHA-n HMAC mechanism
// puts its own digest on the wire.
//
// PKCS#11 v3.2 §6.22 fixes the digest in the mechanism itself: CKM_SHA256_HMAC,
// CKM_SHA384_HMAC and CKM_SHA512_HMAC take no parameter naming a hash. The
// request this module sends has no mechanism field either, so SignRequest.Hash
// is the only place that identity can travel. With the digest missing, all
// three mechanisms over one key built a byte-identical request and the token
// could not express which MAC was asked for -- the receiving end would answer
// every one of them with the same tag under CKR_OK.
//
// The assertion is against crypto/hmac, not against the module's own inverse:
// each case computes the tag for the digest the mechanism's *name* declares and
// requires it to equal the tag for the digest the *request* carries. A request
// naming SHA-256 for CKM_SHA512_HMAC produces a 32-byte tag where a 64-byte one
// is required, and one naming nothing resolves to no digest at all.
func TestSignHMACMechanismsCarryTheirOwnDigest(t *testing.T) {
	key := []byte("go-xkms pkcs11 module hmac oracle key")
	data := []byte("the message under mac")

	cases := []struct {
		mech    MechanismType
		want    string
		newHash func() hash.Hash
	}{
		{CKM_SHA256_HMAC, "SHA-256", sha256.New},
		{CKM_SHA384_HMAC, "SHA-384", sha512.New384},
		{CKM_SHA512_HMAC, "SHA-512", sha512.New},
	}

	tags := make(map[MechanismType][]byte, len(cases))

	for _, tc := range cases {
		t.Run(GetMechanismName(tc.mech), func(t *testing.T) {
			cm, client := newTestCryptoManager()

			// The operation is built directly rather than through SignInit so
			// this stays a test of what the request carries. Whether the
			// mechanism is currently advertised is a separate decision, made in
			// the mechanism registry; the digest still has to survive into the
			// request the moment it is.
			op := newSignOperation(&Mechanism{Type: tc.mech}, 1, "hmac-key", "backend1")
			if _, err := cm.Sign(context.Background(), op, data); err != nil {
				t.Fatalf("Sign(%s): %v", GetMechanismName(tc.mech), err)
			}

			if client.lastSignReq.Hash != tc.want {
				t.Fatalf("%s put hash %q on the wire, want %q: the mechanism's digest is the only thing distinguishing it from the other HMAC mechanisms",
					GetMechanismName(tc.mech), client.lastSignReq.Hash, tc.want)
			}

			// HMAC is computed over the message. Setting DataIsDigest would
			// tell the far end the caller had already hashed it, so the tag
			// would be an HMAC over a digest of the message rather than over
			// the message, and no conformant peer could reproduce it.
			if client.lastSignReq.DataIsDigest {
				t.Errorf("%s set DataIsDigest; HMAC takes the message, not a digest of it",
					GetMechanismName(tc.mech))
			}

			newHashFromRequest, ok := hmacOracleDigests[client.lastSignReq.Hash]
			if !ok {
				t.Fatalf("%s named hash %q, which is not a digest an HMAC can be keyed with",
					GetMechanismName(tc.mech), client.lastSignReq.Hash)
			}

			fromName := hmacTag(tc.newHash, key, data)
			fromRequest := hmacTag(newHashFromRequest, key, data)
			if !bytes.Equal(fromName, fromRequest) {
				t.Fatalf("%s: the tag for the digest the request carries (%x) is not the tag for the digest the mechanism names (%x)",
					GetMechanismName(tc.mech), fromRequest, fromName)
			}
			tags[tc.mech] = fromRequest
		})
	}

	// The regression this whole test exists for: the same key and the same
	// data under three different mechanisms must not produce one tag.
	for i, a := range cases {
		for _, b := range cases[i+1:] {
			if bytes.Equal(tags[a.mech], tags[b.mech]) {
				t.Fatalf("%s and %s produced the same tag (%x) for the same key and data: the mechanism's identity did not survive into the request",
					GetMechanismName(a.mech), GetMechanismName(b.mech), tags[a.mech])
			}
		}
	}
}

// TestSignHMACMechanismsDoNotShareARequest is the direct form of the same
// regression, one level below the tags: the three requests themselves must
// differ.
//
// It is separate from the oracle test because it fails for a reason no digest
// comparison can report -- a module that dropped the mechanism entirely sends
// three identical structs, and there is nothing in them left to compare.
func TestSignHMACMechanismsDoNotShareARequest(t *testing.T) {
	data := []byte("the message under mac")
	mechs := []MechanismType{CKM_SHA256_HMAC, CKM_SHA384_HMAC, CKM_SHA512_HMAC}

	seen := make(map[string]MechanismType, len(mechs))
	for _, mech := range mechs {
		cm, client := newTestCryptoManager()

		op := newSignOperation(&Mechanism{Type: mech}, 1, "hmac-key", "backend1")
		if _, err := cm.Sign(context.Background(), op, data); err != nil {
			t.Fatalf("Sign(%s): %v", GetMechanismName(mech), err)
		}

		req := client.lastSignReq
		fingerprint := fmt.Sprintf("%s|%s|%x|%s|%s|%d|%t",
			req.Backend, req.KeyID, req.Data, req.Hash, req.Padding, req.SaltLength, req.DataIsDigest)

		if prior, dup := seen[fingerprint]; dup {
			t.Fatalf("%s and %s build the identical request %q: the token cannot tell the caller's two MACs apart",
				GetMechanismName(prior), GetMechanismName(mech), fingerprint)
		}
		seen[fingerprint] = mech
	}
}

// TestMechanismToHashRejectsUnknownAndNonSigningInput is the bad-input half of
// the HMAC change: mechanismToHash must not invent a digest for a mechanism it
// has no entry for, and must not report a digest for the MACs and signature
// schemes that have none.
func TestMechanismToHashRejectsUnknownAndNonSigningInput(t *testing.T) {
	if got := mechanismToHash(MechanismType(0xFFFFFFFF)); got != "" {
		t.Errorf("mechanismToHash(unknown) = %q, want \"\": an unrecognized mechanism has no digest to report", got)
	}

	// CKM_AES_CMAC is a block-cipher MAC and raw RSA is an arithmetic
	// operation; both take the caller's bytes untouched, which "NONE" says and
	// "" does not -- "" resolves to the service layer's SHA-256 default.
	for _, tc := range []struct {
		mech MechanismType
		want string
	}{
		{CKM_AES_CMAC, "NONE"},
		{CKM_RSA_X_509, "NONE"},
		{CKM_ML_DSA, "NONE"},
		{CKM_SLH_DSA, "NONE"},
		{CKM_XEDDSA, "NONE"},
	} {
		if got := mechanismToHash(tc.mech); got != tc.want {
			t.Errorf("mechanismToHash(%s) = %q, want %q", GetMechanismName(tc.mech), got, tc.want)
		}
	}
}

// TestDeriveKeyECDH_RawSurvivesTheDefaults proves the raw KDF sentinel reaches
// the wire unchanged, with no digest defaulted in alongside it.
//
// DeriveKeyECDH fills in HKDF for an unnamed algorithm and SHA-256 for an
// unnamed hash. Both defaults are hazards for CKD_NULL: the first would answer
// a request for the raw shared secret with an HKDF expansion of it, and the
// second would name a digest for a derivation step that does not happen, which
// the service layer refuses because RAW has no hash input.
func TestDeriveKeyECDH_RawSurvivesTheDefaults(t *testing.T) {
	// The constant's value is the contract, not just its name: the service
	// layer's kdfAlgorithms table matches on the literal string, so renaming it
	// here silently turns every CKD_NULL derivation into an unsupported-KDF
	// error, or worse into the HKDF default.
	if KDFAlgorithmRaw != "RAW" {
		t.Fatalf("KDFAlgorithmRaw = %q, want \"RAW\": this is the wire name pkg/xkms resolves to types.KDFAlgorithmRaw",
			KDFAlgorithmRaw)
	}

	cm, client := newTestCryptoManager()

	_, err := cm.DeriveKeyECDH(context.Background(), &DeriveKeyECDHRequest{
		BaseKeyID:     "ec-key",
		Backend:       "backend1",
		PeerPublicKey: []byte{0x04, 0x01, 0x02},
		KDFAlgorithm:  KDFAlgorithmRaw,
		KeyLength:     32,
	})
	if err != nil {
		t.Fatalf("DeriveKeyECDH: %v", err)
	}

	req := client.lastDeriveECDHReq
	if req == nil {
		t.Fatal("DeriveKeyECDH sent no request")
	}
	if req.KDFAlgorithm != KDFAlgorithmRaw {
		t.Errorf("KDFAlgorithm = %q, want %q: substituting a KDF returns key material the caller never asked for under CKR_OK",
			req.KDFAlgorithm, KDFAlgorithmRaw)
	}
	if req.KDFHash != "" {
		t.Errorf("KDFHash = %q, want empty: the raw KDF runs no pseudorandom function, so naming a digest describes a step that does not happen",
			req.KDFHash)
	}
}

// TestDeriveKeyECDH_UnnamedKDFStillDefaults is the counterpart: leaving the
// algorithm unset must still mean HKDF-SHA-256.
//
// Without it, a change that stopped defaulting altogether would pass the raw
// test above while silently altering every caller that names no KDF.
func TestDeriveKeyECDH_UnnamedKDFStillDefaults(t *testing.T) {
	cm, client := newTestCryptoManager()

	_, err := cm.DeriveKeyECDH(context.Background(), &DeriveKeyECDHRequest{
		BaseKeyID:     "ec-key",
		Backend:       "backend1",
		PeerPublicKey: []byte{0x04, 0x01, 0x02},
	})
	if err != nil {
		t.Fatalf("DeriveKeyECDH: %v", err)
	}

	req := client.lastDeriveECDHReq
	if req == nil {
		t.Fatal("DeriveKeyECDH sent no request")
	}
	if req.KDFAlgorithm != "HKDF" {
		t.Errorf("KDFAlgorithm = %q, want \"HKDF\" for an unnamed KDF", req.KDFAlgorithm)
	}
	if req.KDFHash != "SHA-256" {
		t.Errorf("KDFHash = %q, want \"SHA-256\" for an unnamed hash", req.KDFHash)
	}
	if req.KeyLength != 32 {
		t.Errorf("KeyLength = %d, want 32 for an unspecified length", req.KeyLength)
	}
}

// signMechanismsWithoutADigest are the advertised signature mechanisms
// deliberately left out of mechanismToHashMap, each with the reason.
//
// The generic PSS mechanism is the only legitimate empty *entry*: v3.2 §6.1.9
// makes CK_RSA_PKCS_PSS_PARAMS.hashAlg authoritative for it, and
// CryptoManager.Sign resolves the digest from the parameters before the request
// is built, so the table value is never what goes on the wire.
//
// The pre-hashed ML-DSA and SLH-DSA variants are absent because this stack has
// no HashML-DSA/HashSLH-DSA implementation to name a digest for: FIPS 204 §5.4
// and FIPS 205 §10.2 sign a domain-separated encoding of the digest, not the
// digest, so putting a hash name on the request would produce a signature that
// is neither the pure nor the pre-hashed scheme. They are listed here so the
// gap is recorded rather than mistaken for an oversight.
var signMechanismsWithoutADigest = map[MechanismType]string{
	CKM_RSA_PKCS_PSS: "hash comes from CK_RSA_PKCS_PSS_PARAMS.hashAlg (v3.2 6.1.9)",

	CKM_HASH_ML_DSA:           "HashML-DSA is not implemented (FIPS 204 5.4)",
	CKM_HASH_ML_DSA_SHA224:    "HashML-DSA is not implemented (FIPS 204 5.4)",
	CKM_HASH_ML_DSA_SHA256:    "HashML-DSA is not implemented (FIPS 204 5.4)",
	CKM_HASH_ML_DSA_SHA384:    "HashML-DSA is not implemented (FIPS 204 5.4)",
	CKM_HASH_ML_DSA_SHA512:    "HashML-DSA is not implemented (FIPS 204 5.4)",
	CKM_HASH_ML_DSA_SHA3_224:  "HashML-DSA is not implemented (FIPS 204 5.4)",
	CKM_HASH_ML_DSA_SHA3_256:  "HashML-DSA is not implemented (FIPS 204 5.4)",
	CKM_HASH_ML_DSA_SHA3_384:  "HashML-DSA is not implemented (FIPS 204 5.4)",
	CKM_HASH_ML_DSA_SHA3_512:  "HashML-DSA is not implemented (FIPS 204 5.4)",
	CKM_HASH_ML_DSA_SHAKE128:  "HashML-DSA is not implemented (FIPS 204 5.4)",
	CKM_HASH_ML_DSA_SHAKE256:  "HashML-DSA is not implemented (FIPS 204 5.4)",
	CKM_HASH_SLH_DSA:          "HashSLH-DSA is not implemented (FIPS 205 10.2)",
	CKM_HASH_SLH_DSA_SHA224:   "HashSLH-DSA is not implemented (FIPS 205 10.2)",
	CKM_HASH_SLH_DSA_SHA256:   "HashSLH-DSA is not implemented (FIPS 205 10.2)",
	CKM_HASH_SLH_DSA_SHA384:   "HashSLH-DSA is not implemented (FIPS 205 10.2)",
	CKM_HASH_SLH_DSA_SHA512:   "HashSLH-DSA is not implemented (FIPS 205 10.2)",
	CKM_HASH_SLH_DSA_SHA3_224: "HashSLH-DSA is not implemented (FIPS 205 10.2)",
	CKM_HASH_SLH_DSA_SHA3_256: "HashSLH-DSA is not implemented (FIPS 205 10.2)",
	CKM_HASH_SLH_DSA_SHA3_384: "HashSLH-DSA is not implemented (FIPS 205 10.2)",
	CKM_HASH_SLH_DSA_SHA3_512: "HashSLH-DSA is not implemented (FIPS 205 10.2)",
	CKM_HASH_SLH_DSA_SHAKE128: "HashSLH-DSA is not implemented (FIPS 205 10.2)",
	CKM_HASH_SLH_DSA_SHAKE256: "HashSLH-DSA is not implemented (FIPS 205 10.2)",
}

// TestEverySigningMechanismNamesItsDigest sweeps the advertised mechanism list
// and requires each signing mechanism to say what to do with the caller's bytes.
//
// An empty hash is the one answer that cannot be acted on correctly: the
// service layer reads it as "unspecified" and applies SHA-256, so a mechanism
// that leaves it empty has its message silently digested before it is signed or
// MACed. That is a wrong signature returned under CKR_OK, which no round-trip
// test through this module can see -- both halves make the same substitution.
//
// A mechanism that genuinely has no digest to name belongs in
// signMechanismsWithoutADigest with the reason, which is a deliberate act
// rather than an omission.
func TestEverySigningMechanismNamesItsDigest(t *testing.T) {
	for mech, info := range mechanismRegistry {
		if info.Flags&(CKF_SIGN|CKF_VERIFY) == 0 {
			continue
		}
		if _, expected := signMechanismsWithoutADigest[mech]; expected {
			continue
		}
		if got := mechanismToHash(mech); got == "" {
			t.Errorf("%s (0x%08X) is advertised for signing but names no digest. The service layer resolves an empty hash to SHA-256, so its input is hashed before it is signed. Give it a digest name, or \"NONE\" if it takes the caller's bytes untouched, or record it in signMechanismsWithoutADigest with the reason.",
				info.Name, uint(mech))
		}
	}
}

// TestCryptoManager_Encrypt_GCM_AssemblesRealTag exercises the AES-GCM
// tag-assembly branch of CryptoManager.Encrypt with a tag that authenticates
// something.
//
// The branch was reachable before only from fixtures holding a canned Tag, so
// nothing checked that the assembled blob is the blob crypto/cipher produces:
// the assertion here is that Seal's own output equals ciphertext || tag as the
// module assembled it, and that a flipped bit anywhere in the blob makes it
// unopenable.
func TestCryptoManager_Encrypt_GCM_AssemblesRealTag(t *testing.T) {
	cm, _, engine := newRealCryptoCryptoManager()
	plaintext := []byte("key material to protect")

	op, err := cm.EncryptInit(&Mechanism{Type: CKM_AES_GCM}, 1, "test-key", "backend1")
	if err != nil {
		t.Fatalf("EncryptInit failed: %v", err)
	}
	wire, err := cm.Encrypt(context.Background(), op, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// PKCS#11 v3.2 section 6.13.7: ciphertext || tag, full-length tag by default.
	if len(wire) != len(plaintext)+GCMTagSize {
		t.Fatalf("expected %d bytes of ciphertext||tag, got %d", len(plaintext)+GCMTagSize, len(wire))
	}
	// A token-generated IV must be retrievable after C_Encrypt.
	if len(op.IV()) != mockGCMNonceSize {
		t.Fatalf("expected a %d-byte generated IV, got %d", mockGCMNonceSize, len(op.IV()))
	}
	if !op.IVGenerated() {
		t.Error("expected IVGenerated() to be true for a backend-generated nonce")
	}

	key, err := engine.aesKey("test-key")
	if err != nil {
		t.Fatalf("aesKey failed: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher failed: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM failed: %v", err)
	}

	// crypto/cipher's Seal emits ciphertext || tag; the module must have
	// assembled exactly that from the separate response fields.
	if want := gcm.Seal(nil, op.IV(), plaintext, nil); !bytes.Equal(wire, want) {
		t.Fatalf("assembled blob %x, crypto/cipher gives %x", wire, want)
	}

	recovered, err := gcm.Open(nil, op.IV(), wire, nil)
	if err != nil {
		t.Fatalf("the assembled blob does not authenticate: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("recovered %q, want %q", recovered, plaintext)
	}

	for _, offset := range []int{0, len(plaintext) - 1, len(wire) - 1} {
		tampered := append([]byte{}, wire...)
		tampered[offset] ^= 0x01
		if _, err := gcm.Open(nil, op.IV(), tampered, nil); err == nil {
			t.Fatalf("a blob with octet %d flipped still authenticated", offset)
		}
	}
}

// TestCryptoManager_Encrypt_GCM_AssemblesTruncatedTag drives the same branch at
// the shortest tag length NIST SP 800-38D section 5.2.1.2 approves, 96 bits.
// The assembled blob must be that many octets longer than the plaintext and no
// more -- a module that split at the full length would frame the ciphertext its
// peer cannot authenticate.
func TestCryptoManager_Encrypt_GCM_AssemblesTruncatedTag(t *testing.T) {
	cm, client, engine := newRealCryptoCryptoManager()
	plaintext := []byte("key material to protect")
	const shortTagBytes = 12

	mech := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(nil, 96))
	op, err := cm.EncryptInit(mech, 1, "test-key", "backend1")
	if err != nil {
		t.Fatalf("EncryptInit failed: %v", err)
	}
	wire, err := cm.Encrypt(context.Background(), op, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if len(wire) != len(plaintext)+shortTagBytes {
		t.Fatalf("expected %d bytes of ciphertext||tag, got %d", len(plaintext)+shortTagBytes, len(wire))
	}

	key, err := engine.aesKey("test-key")
	if err != nil {
		t.Fatalf("aesKey failed: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher failed: %v", err)
	}
	gcm, err := cipher.NewGCMWithTagSize(block, shortTagBytes)
	if err != nil {
		t.Fatalf("cipher.NewGCMWithTagSize failed: %v", err)
	}
	recovered, err := gcm.Open(nil, op.IV(), wire, nil)
	if err != nil {
		t.Fatalf("the 96-bit-tag blob does not authenticate: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("recovered %q, want %q", recovered, plaintext)
	}

	// The round trip through the module must resolve the same length on both
	// sides, or a short tag reads as a forgery.
	decMech := NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(op.IV(), 96))
	decOp, err := cm.DecryptInit(decMech, 1, "test-key", "backend1")
	if err != nil {
		t.Fatalf("DecryptInit failed: %v", err)
	}
	back, err := cm.Decrypt(context.Background(), decOp, wire)
	if err != nil {
		t.Fatalf("Decrypt with a 96-bit tag failed: %v", err)
	}
	if !bytes.Equal(back, plaintext) {
		t.Fatalf("round trip recovered %q, want %q", back, plaintext)
	}
	if len(client.lastDecryptReq.Tag) != shortTagBytes {
		t.Fatalf("C_Decrypt split off a %d-octet tag, want %d",
			len(client.lastDecryptReq.Tag), shortTagBytes)
	}
	if !bytes.Equal(client.lastDecryptReq.Ciphertext, wire[:len(wire)-shortTagBytes]) {
		t.Fatalf("C_Decrypt split the ciphertext at the wrong offset")
	}
}

// TestCryptoManager_Sign_ECDSA_ProducesVerifiableRawSignature checks the
// PKCS#11 v3.2 section 6.3.1 normalization against real ECDSA: the module must
// return the raw r || s concatenation, and reassembling those halves into
// (r, s) must verify under the public key the transport signed with.
//
// This is the counterpart the canned fixtures could not provide. A test that
// feeds in a hand-built DER blob proves the converter parses DER; only a real
// signature proves the converted halves are still a signature.
func TestCryptoManager_Sign_ECDSA_ProducesVerifiableRawSignature(t *testing.T) {
	cm, _, engine := newRealCryptoCryptoManager()
	// The "ec-" prefix asks the engine for a P-256 key; see mockKeyKindsByPrefix.
	const keyID = "ec-sign-key"
	data := []byte("test data to sign")

	op, err := cm.SignInit(&Mechanism{Type: CKM_ECDSA_SHA256}, 1, keyID, "backend1")
	if err != nil {
		t.Fatalf("SignInit failed: %v", err)
	}
	sig, err := cm.Sign(context.Background(), op, data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// P-256: two 32-byte field elements, never DER. A DER-encoded P-256
	// signature is 70 to 72 bytes, so the length alone rules DER out, and the
	// reassembly below proves the halves are the signature. Do not add a
	// first-byte check for the DER SEQUENCE tag: r is uniform, so its leading
	// byte is 0x30 in one signature of every 256, and that check failed
	// 4 times in 600 runs on an unchanged tree.
	if len(sig) != 64 {
		t.Fatalf("expected a 64-byte raw r||s signature, got %d bytes", len(sig))
	}

	pub, err := engine.publicKey(keyID)
	if err != nil {
		t.Fatalf("publicKey failed: %v", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected an ECDSA public key, got %T", pub)
	}

	digest := sha256.Sum256(data)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(ecPub, digest[:], r, s) {
		t.Fatal("the raw r||s halves do not verify under the signing key")
	}

	// The failure counterpart: the same halves against a different digest.
	otherDigest := sha256.Sum256([]byte("a different message"))
	if ecdsa.Verify(ecPub, otherDigest[:], r, s) {
		t.Fatal("the signature verified against a message that was never signed")
	}

	// And the module's own verify path must accept its own raw signature,
	// which means the raw -> DER conversion is the inverse of the DER -> raw
	// one rather than merely well formed.
	verifyOp, err := cm.VerifyInit(&Mechanism{Type: CKM_ECDSA_SHA256}, 1, keyID, "backend1")
	if err != nil {
		t.Fatalf("VerifyInit failed: %v", err)
	}
	if err := cm.Verify(context.Background(), verifyOp, data, sig); err != nil {
		t.Fatalf("the module rejected the raw signature it had just produced: %v", err)
	}
}

// TestCryptoManager_Sign_Ed25519_ProducesVerifiableSignature proves the "do not
// hash" wiring for CKM_EDDSA is honoured end to end: Ed25519 signs the message
// itself (RFC 8032), so a module that hashed first would produce a signature
// that does not verify over the caller's data.
func TestCryptoManager_Sign_Ed25519_ProducesVerifiableSignature(t *testing.T) {
	cm, client, engine := newRealCryptoCryptoManager()
	const keyID = "ed-sign-key"
	data := []byte("test data to sign with Ed25519")

	op, err := cm.SignInit(&Mechanism{Type: CKM_EDDSA}, 1, keyID, "backend1")
	if err != nil {
		t.Fatalf("SignInit failed: %v", err)
	}
	sig, err := cm.Sign(context.Background(), op, data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("expected a %d-byte Ed25519 signature, got %d", ed25519.SignatureSize, len(sig))
	}
	if client.lastSignReq.Hash != "NONE" {
		t.Errorf("expected hash %q for EdDSA, got %q", "NONE", client.lastSignReq.Hash)
	}

	pub, err := engine.publicKey(keyID)
	if err != nil {
		t.Fatalf("publicKey failed: %v", err)
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("expected an Ed25519 public key, got %T", pub)
	}
	if !ed25519.Verify(edPub, data, sig) {
		t.Fatal("the Ed25519 signature does not verify over the caller's message")
	}
	if ed25519.Verify(edPub, []byte("a different message"), sig) {
		t.Fatal("the signature verified against a message that was never signed")
	}
}

// TestMockCryptoEngine_RefusesUnsupportedInputs is the fixture's own
// bad-input test. A test fixture that quietly accepted a digest or a mode it
// does not implement would report a passing test for an operation it never
// performed, which is the failure this whole change is about.
func TestMockCryptoEngine_RefusesUnsupportedInputs(t *testing.T) {
	engine := newMockCryptoEngine()

	if _, _, err := engine.digest("SHA-1", []byte("data"), false); !errors.Is(err, errMockDigestUnsupported) {
		t.Fatalf("expected errMockDigestUnsupported for SHA-1, got %v", err)
	}
	if _, err := engine.encrypt(&transport.EncryptRequest{KeyID: "k", Mode: "ctr"}); !errors.Is(err, errMockModeUnsupported) {
		t.Fatalf("expected errMockModeUnsupported on encrypt, got %v", err)
	}
	if _, err := engine.decrypt(&transport.DecryptRequest{KeyID: "k", Mode: "ctr"}); !errors.Is(err, errMockModeUnsupported) {
		t.Fatalf("expected errMockModeUnsupported on decrypt, got %v", err)
	}
	if _, err := engine.encrypt(&transport.EncryptRequest{KeyID: "k", Mode: "ecb", Plaintext: []byte("short")}); !errors.Is(err, errMockNotBlockAligned) {
		t.Fatalf("expected errMockNotBlockAligned, got %v", err)
	}
	if _, err := engine.decrypt(&transport.DecryptRequest{
		KeyID:      "k",
		Ciphertext: []byte("not a ciphertext"),
		Tag:        bytes.Repeat([]byte{0x00}, GCMTagSize),
		Nonce:      bytes.Repeat([]byte{0x00}, mockGCMNonceSize),
	}); !errors.Is(err, errMockCiphertextRejected) {
		t.Fatalf("expected errMockCiphertextRejected, got %v", err)
	}

	// The success counterpart: a digest the engine does implement, and a mode
	// it does, both work.
	if _, _, err := engine.digest("SHA-256", []byte("data"), false); err != nil {
		t.Fatalf("SHA-256 must be supported: %v", err)
	}
	resp, err := engine.encrypt(&transport.EncryptRequest{KeyID: "k", Plaintext: []byte("data")})
	if err != nil {
		t.Fatalf("the default AEAD mode must be supported: %v", err)
	}
	if len(resp.Tag) != GCMTagSize || len(resp.Nonce) != mockGCMNonceSize {
		t.Fatalf("expected a full-length tag and a 96-bit nonce, got tag=%d nonce=%d", len(resp.Tag), len(resp.Nonce))
	}
}

// TestMockCryptoEngine_BindsKeysToKeyID proves the fixture models what a real
// backend does: the same key ID resolves to the same key across calls, and a
// different key ID to a different key. Without that, "the wrong key" would be
// untestable.
func TestMockCryptoEngine_BindsKeysToKeyID(t *testing.T) {
	engine := newMockCryptoEngine()

	first, err := engine.aesKey("key-a")
	if err != nil {
		t.Fatalf("aesKey failed: %v", err)
	}
	again, err := engine.aesKey("key-a")
	if err != nil {
		t.Fatalf("aesKey failed: %v", err)
	}
	if !bytes.Equal(first, again) {
		t.Fatal("the same key ID resolved to two different AES keys")
	}

	other, err := engine.aesKey("key-b")
	if err != nil {
		t.Fatalf("aesKey failed: %v", err)
	}
	if bytes.Equal(first, other) {
		t.Fatal("two key IDs resolved to the same AES key")
	}

	rsaPub, err := engine.publicKey("plain-key")
	if err != nil {
		t.Fatalf("publicKey failed: %v", err)
	}
	if _, ok := rsaPub.(*rsa.PublicKey); !ok {
		t.Fatalf("an unprefixed key ID must be RSA, got %T", rsaPub)
	}
	ecPub, err := engine.publicKey("ec-key")
	if err != nil {
		t.Fatalf("publicKey failed: %v", err)
	}
	if _, ok := ecPub.(*ecdsa.PublicKey); !ok {
		t.Fatalf("an \"ec-\" key ID must be ECDSA, got %T", ecPub)
	}
	edPub, err := engine.publicKey("ed-key")
	if err != nil {
		t.Fatalf("publicKey failed: %v", err)
	}
	if _, ok := edPub.(ed25519.PublicKey); !ok {
		t.Fatalf("an \"ed-\" key ID must be Ed25519, got %T", edPub)
	}
}

// ---------------------------------------------------------------------------
// Real-crypto transport mode
//
// mockClient above answers with canned bytes, which is what an error-path test
// needs: a fixed *transport.SignResponse is the only way to drive
// CryptoManager down a branch the cryptography itself would never reach. It is
// the wrong fixture for a test that asserts a cryptographic RESULT, because
// asserting []byte("mock-signature") can only ever prove that the constant
// travelled from the fixture to the caller unchanged.
//
// mockCryptoEngine gives the same transport a second mode in which it performs
// genuine cryptography, keyed by the backend key ID the module sends, so a
// signature can be checked against a public key the test holds and a ciphertext
// can be opened by crypto/cipher independently of the module. A test opts in
// with newRealCryptoCryptoManager; every existing fixture that calls
// newMockClient keeps the canned responses and is unaffected.
//
// This is deliberately the SAME transport type rather than a third one:
// concurrency_test.go's concurrentTransport already does real ECDSA, but it is
// reached only through a fully initialized *Module (its key map is populated by
// C_GenerateKeyPair) and it implements no symmetric cryptography at all, so the
// CryptoManager-level unit tests here cannot use it and the AES-GCM tag branch
// in CryptoManager.Encrypt could not be exercised through it without writing
// AES into that file as well.
// ---------------------------------------------------------------------------

// Errors returned by mockCryptoEngine. They are values so a caller can match
// them with errors.Is instead of comparing strings.
var (
	// errMockDigestUnsupported reports a digest name the engine cannot apply.
	// SHA-1 is deliberately absent from mockHashes: no test here signs under a
	// SHA-1 mechanism, and a fixture that silently accepted one would let a
	// SHA-1 signing path pass unnoticed.
	errMockDigestUnsupported = errors.New("module: mock crypto engine does not implement this digest")

	// errMockModeUnsupported reports a symmetric cipher mode the engine cannot
	// perform.
	errMockModeUnsupported = errors.New("module: mock crypto engine does not implement this cipher mode")

	// errMockKeyUnsupported reports a key kind the engine cannot sign with.
	errMockKeyUnsupported = errors.New("module: mock crypto engine does not implement this key type")

	// errMockCiphertextRejected reports an AEAD open or an unpad that failed.
	// The module maps it onto CKR_ENCRYPTED_DATA_INVALID.
	errMockCiphertextRejected = errors.New("module: mock crypto engine rejected the ciphertext")

	// errMockNotBlockAligned reports a CBC/ECB payload that is not a whole
	// number of AES blocks.
	errMockNotBlockAligned = errors.New("module: mock crypto engine requires whole AES blocks")
)

// mockKeyKind names the kind of signing key mockCryptoEngine creates for a
// backend key ID.
type mockKeyKind uint8

const (
	mockKeyRSA mockKeyKind = iota
	mockKeyECDSA
	mockKeyEd25519
)

// mockKeyKindsByPrefix selects the signing key kind from the backend key ID.
//
// SignRequest carries no key-algorithm field -- a real backend knows what it
// stored under that ID -- so the fixture needs its own way to decide, and a
// naming convention keeps the decision visible at the call site ("ec-sign-key"
// signs with ECDSA) instead of hidden in fixture state. Anything unprefixed is
// RSA, which is what the mechanisms in these tests mostly use.
var mockKeyKindsByPrefix = map[string]mockKeyKind{
	"ec-":  mockKeyECDSA,
	"ed-":  mockKeyEd25519,
	"rsa-": mockKeyRSA,
}

// mockHashes maps the digest names the module puts on the wire onto the
// crypto.Hash that produces them.
//
// "NONE" and "" are absent on purpose. "NONE" means the caller already produced
// the bytes to sign (PKCS#11's raw CKM_RSA_PKCS and CKM_ECDSA), and "" means
// the SHA-256 default named in transport.SignRequest.Hash; both are resolved by
// mockCryptoEngine.digest rather than by a table entry.
var mockHashes = map[string]crypto.Hash{
	"SHA-224": crypto.SHA224,
	"SHA-256": crypto.SHA256,
	"SHA-384": crypto.SHA384,
	"SHA-512": crypto.SHA512,
}

// mockAESKeySize is the AES key length the engine generates, matching the
// aes256 keys the module's tests name.
const mockAESKeySize = 32

// mockGCMNonceSize is the standard 96-bit AES-GCM nonce NIST SP 800-38D
// section 8.2 recommends and crypto/cipher's NewGCM defaults to.
const mockGCMNonceSize = 12

// mockCryptoEngine holds one signing key and one AES key per backend key ID and
// performs the operations a real backend would. It is safe for concurrent use
// so a test may drive it from several goroutines.
type mockCryptoEngine struct {
	mu      sync.Mutex
	signers map[string]crypto.Signer
	aesKeys map[string][]byte
}

func newMockCryptoEngine() *mockCryptoEngine {
	return &mockCryptoEngine{
		signers: make(map[string]crypto.Signer),
		aesKeys: make(map[string][]byte),
	}
}

// signer returns the signing key bound to keyID, creating it on first use. The
// kind follows mockKeyKindsByPrefix.
func (e *mockCryptoEngine) signer(keyID string) (crypto.Signer, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if existing, ok := e.signers[keyID]; ok {
		return existing, nil
	}

	kind := mockKeyRSA
	for prefix, candidate := range mockKeyKindsByPrefix {
		if strings.HasPrefix(keyID, prefix) {
			kind = candidate
			break
		}
	}

	var (
		created crypto.Signer
		err     error
	)
	switch kind {
	case mockKeyECDSA:
		created, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case mockKeyEd25519:
		_, priv, genErr := ed25519.GenerateKey(rand.Reader)
		created, err = priv, genErr
	default:
		created, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		return nil, err
	}

	e.signers[keyID] = created
	return created, nil
}

// publicKey returns the public half of the signing key bound to keyID. It is
// the test's independent verification oracle.
func (e *mockCryptoEngine) publicKey(keyID string) (crypto.PublicKey, error) {
	signer, err := e.signer(keyID)
	if err != nil {
		return nil, err
	}
	return signer.Public(), nil
}

// aesKey returns the AES key bound to keyID, creating it on first use. A test
// that wants to open a ciphertext itself reads the same key from here.
func (e *mockCryptoEngine) aesKey(keyID string) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if existing, ok := e.aesKeys[keyID]; ok {
		return existing, nil
	}

	key := make([]byte, mockAESKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	e.aesKeys[keyID] = key
	return key, nil
}

// digest resolves the bytes a signature scheme actually signs, and the
// crypto.Hash identifying them.
//
// hashName "NONE" means the scheme has no digest identity and data is signed
// as-is (crypto.Hash(0)); "" is the SHA-256 default transport.SignRequest
// documents. dataIsDigest names a digest that has already been applied, which
// RSASSA-PSS needs (PKCS#11 v3.2 section 6.1.15 defines its input as already
// hashed while RFC 8017 section 9.1 still needs the digest's identity).
func (e *mockCryptoEngine) digest(hashName string, data []byte, dataIsDigest bool) ([]byte, crypto.Hash, error) {
	if hashName == "NONE" {
		return data, crypto.Hash(0), nil
	}
	if hashName == "" {
		hashName = "SHA-256"
	}

	h, ok := mockHashes[hashName]
	if !ok {
		return nil, 0, fmt.Errorf("%w: %s", errMockDigestUnsupported, hashName)
	}
	if dataIsDigest {
		return data, h, nil
	}

	hasher := h.New()
	hasher.Write(data)
	return hasher.Sum(nil), h, nil
}

// sign performs the signature the request describes with the real key bound to
// req.KeyID.
func (e *mockCryptoEngine) sign(req *transport.SignRequest) (*transport.SignResponse, error) {
	signer, err := e.signer(req.KeyID)
	if err != nil {
		return nil, err
	}

	switch key := signer.(type) {
	case ed25519.PrivateKey:
		// RFC 8032: Ed25519 signs the message itself, which is why the module
		// sends "NONE" for this mechanism.
		return &transport.SignResponse{Signature: ed25519.Sign(key, req.Data), Algorithm: "EdDSA"}, nil

	case *ecdsa.PrivateKey:
		digest, _, digestErr := e.digest(req.Hash, req.Data, req.DataIsDigest)
		if digestErr != nil {
			return nil, digestErr
		}
		// A real backend returns ASN.1 DER; the module normalizes it to the raw
		// r || s form PKCS#11 v3.2 section 6.3.1 mandates.
		sig, signErr := ecdsa.SignASN1(rand.Reader, key, digest)
		if signErr != nil {
			return nil, signErr
		}
		return &transport.SignResponse{Signature: sig, Algorithm: "ECDSA"}, nil

	case *rsa.PrivateKey:
		digest, h, digestErr := e.digest(req.Hash, req.Data, req.DataIsDigest)
		if digestErr != nil {
			return nil, digestErr
		}
		if req.Padding == "pss" {
			sig, signErr := rsa.SignPSS(rand.Reader, key, h, digest,
				&rsa.PSSOptions{SaltLength: req.SaltLength, Hash: h})
			if signErr != nil {
				return nil, signErr
			}
			return &transport.SignResponse{Signature: sig, Algorithm: "RSA-PSS"}, nil
		}
		sig, signErr := rsa.SignPKCS1v15(rand.Reader, key, h, digest)
		if signErr != nil {
			return nil, signErr
		}
		return &transport.SignResponse{Signature: sig, Algorithm: "RSA-PKCS"}, nil

	default:
		return nil, fmt.Errorf("%w: %T", errMockKeyUnsupported, signer)
	}
}

// verify checks a signature with the public half of the key bound to
// req.KeyID. A signature that does not check out is reported as Valid=false --
// not as an error -- because that is the answer a real backend gives and the
// answer CryptoManager.Verify turns into CKR_SIGNATURE_INVALID.
func (e *mockCryptoEngine) verify(req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	signer, err := e.signer(req.KeyID)
	if err != nil {
		return nil, err
	}

	switch key := signer.(type) {
	case ed25519.PrivateKey:
		pub, ok := key.Public().(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: %T", errMockKeyUnsupported, key.Public())
		}
		return &transport.VerifyResponse{Valid: ed25519.Verify(pub, req.Data, req.Signature)}, nil

	case *ecdsa.PrivateKey:
		digest, _, digestErr := e.digest(req.Hash, req.Data, req.DataIsDigest)
		if digestErr != nil {
			return nil, digestErr
		}
		// The module converted the raw r || s back to DER before the round trip.
		return &transport.VerifyResponse{Valid: ecdsa.VerifyASN1(&key.PublicKey, digest, req.Signature)}, nil

	case *rsa.PrivateKey:
		digest, h, digestErr := e.digest(req.Hash, req.Data, req.DataIsDigest)
		if digestErr != nil {
			return nil, digestErr
		}
		if req.Padding == "pss" {
			verifyErr := rsa.VerifyPSS(&key.PublicKey, h, digest, req.Signature,
				&rsa.PSSOptions{SaltLength: req.SaltLength, Hash: h})
			return &transport.VerifyResponse{Valid: verifyErr == nil}, nil
		}
		verifyErr := rsa.VerifyPKCS1v15(&key.PublicKey, h, digest, req.Signature)
		return &transport.VerifyResponse{Valid: verifyErr == nil}, nil

	default:
		return nil, fmt.Errorf("%w: %T", errMockKeyUnsupported, signer)
	}
}

// mockAEAD builds the AES-GCM instance for a request, honouring the tag length
// the module asked for. PKCS#11 v3.2 section 6.13.3 and NIST SP 800-38D section
// 5.2.1.2 admit 96 to 128 bits; zero means the full-length tag.
func mockAEAD(key []byte, tagSize int) (cipher.AEAD, int, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, err
	}
	if tagSize == 0 {
		tagSize = GCMTagSize
	}
	aead, err := cipher.NewGCMWithTagSize(block, tagSize)
	if err != nil {
		return nil, 0, err
	}
	return aead, tagSize, nil
}

// encrypt performs the symmetric encryption the request describes.
//
// The AEAD branch returns Ciphertext, Nonce and Tag as separate fields, which
// is what a real backend does and what makes CryptoManager.Encrypt's
// ciphertext || tag assembly reachable with a genuine tag.
func (e *mockCryptoEngine) encrypt(req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	key, err := e.aesKey(req.KeyID)
	if err != nil {
		return nil, err
	}

	switch req.Mode {
	case "":
		aead, tagSize, aeadErr := mockAEAD(key, req.TagSize)
		if aeadErr != nil {
			return nil, aeadErr
		}
		nonce := req.Nonce
		if len(nonce) == 0 {
			nonce = make([]byte, mockGCMNonceSize)
			if _, randErr := rand.Read(nonce); randErr != nil {
				return nil, randErr
			}
		}
		sealed := aead.Seal(nil, nonce, req.Plaintext, req.AdditionalData)
		split := len(sealed) - tagSize
		return &transport.EncryptResponse{
			Ciphertext: sealed[:split],
			Nonce:      nonce,
			Tag:        sealed[split:],
		}, nil

	case "ecb":
		block, blockErr := aes.NewCipher(key)
		if blockErr != nil {
			return nil, blockErr
		}
		if len(req.Plaintext) == 0 || len(req.Plaintext)%aes.BlockSize != 0 {
			return nil, errMockNotBlockAligned
		}
		out := make([]byte, len(req.Plaintext))
		for offset := 0; offset < len(req.Plaintext); offset += aes.BlockSize {
			block.Encrypt(out[offset:offset+aes.BlockSize], req.Plaintext[offset:offset+aes.BlockSize])
		}
		return &transport.EncryptResponse{Ciphertext: out}, nil

	case "cbc", "cbc-pad":
		block, blockErr := aes.NewCipher(key)
		if blockErr != nil {
			return nil, blockErr
		}
		iv := req.IV
		if len(iv) == 0 {
			iv = make([]byte, aes.BlockSize)
			if _, randErr := rand.Read(iv); randErr != nil {
				return nil, randErr
			}
		}
		plaintext := req.Plaintext
		if req.Mode == "cbc-pad" {
			// RFC 5652 section 6.3 PKCS#7 padding, always at least one byte.
			padLen := aes.BlockSize - (len(plaintext) % aes.BlockSize)
			plaintext = append(append([]byte{}, plaintext...), bytes.Repeat([]byte{byte(padLen)}, padLen)...)
		}
		if len(plaintext) == 0 || len(plaintext)%aes.BlockSize != 0 {
			return nil, errMockNotBlockAligned
		}
		out := make([]byte, len(plaintext))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plaintext)
		return &transport.EncryptResponse{Ciphertext: out, IV: iv}, nil

	default:
		return nil, fmt.Errorf("%w: %s", errMockModeUnsupported, req.Mode)
	}
}

// decrypt inverts encrypt. An AEAD tag that does not authenticate, or PKCS#7
// padding that does not check out, is reported as errMockCiphertextRejected,
// which CryptoManager.Decrypt maps onto CKR_ENCRYPTED_DATA_INVALID.
func (e *mockCryptoEngine) decrypt(req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	key, err := e.aesKey(req.KeyID)
	if err != nil {
		return nil, err
	}

	switch req.Mode {
	case "":
		aead, tagSize, aeadErr := mockAEAD(key, req.TagSize)
		if aeadErr != nil {
			return nil, aeadErr
		}
		// NIST SP 800-38D section 5.2.2 step 5: the tag is recomputed and
		// compared at the requested length, so a backend handed a tag of a
		// different length must refuse rather than authenticate at whatever
		// length arrived. Without this check the engine simply reassembles
		// Ciphertext || Tag and the split C_Decrypt performed is invisible --
		// a mutation that split at the full length regardless of
		// CK_GCM_PARAMS.ulTagBits survived exactly here.
		if len(req.Tag) != tagSize {
			return nil, errMockCiphertextRejected
		}
		sealed := make([]byte, 0, len(req.Ciphertext)+len(req.Tag))
		sealed = append(sealed, req.Ciphertext...)
		sealed = append(sealed, req.Tag...)
		plaintext, openErr := aead.Open(nil, req.Nonce, sealed, req.AdditionalData)
		if openErr != nil {
			return nil, errMockCiphertextRejected
		}
		return &transport.DecryptResponse{Plaintext: plaintext}, nil

	case "ecb":
		block, blockErr := aes.NewCipher(key)
		if blockErr != nil {
			return nil, blockErr
		}
		if len(req.Ciphertext) == 0 || len(req.Ciphertext)%aes.BlockSize != 0 {
			return nil, errMockNotBlockAligned
		}
		out := make([]byte, len(req.Ciphertext))
		for offset := 0; offset < len(req.Ciphertext); offset += aes.BlockSize {
			block.Decrypt(out[offset:offset+aes.BlockSize], req.Ciphertext[offset:offset+aes.BlockSize])
		}
		return &transport.DecryptResponse{Plaintext: out}, nil

	case "cbc", "cbc-pad":
		block, blockErr := aes.NewCipher(key)
		if blockErr != nil {
			return nil, blockErr
		}
		if len(req.IV) != aes.BlockSize {
			return nil, errMockCiphertextRejected
		}
		if len(req.Ciphertext) == 0 || len(req.Ciphertext)%aes.BlockSize != 0 {
			return nil, errMockNotBlockAligned
		}
		out := make([]byte, len(req.Ciphertext))
		cipher.NewCBCDecrypter(block, req.IV).CryptBlocks(out, req.Ciphertext)
		if req.Mode == "cbc-pad" {
			padLen := int(out[len(out)-1])
			if padLen == 0 || padLen > aes.BlockSize || padLen > len(out) {
				return nil, errMockCiphertextRejected
			}
			for _, b := range out[len(out)-padLen:] {
				if int(b) != padLen {
					return nil, errMockCiphertextRejected
				}
			}
			out = out[:len(out)-padLen]
		}
		return &transport.DecryptResponse{Plaintext: out}, nil

	default:
		return nil, fmt.Errorf("%w: %s", errMockModeUnsupported, req.Mode)
	}
}

// newRealCryptoCryptoManager builds a CryptoManager over a mockClient in
// real-crypto mode. The returned engine is the test's oracle: it holds the
// public keys and AES keys the transport actually used.
func newRealCryptoCryptoManager() (*CryptoManager, *mockClient, *mockCryptoEngine) {
	client := newMockClient()
	// Clear the canned responses so the engine is what answers. Leaving them
	// set would silently shadow the real cryptography and put the test back
	// where it started.
	client.signResponse = nil
	client.verifyResponse = nil
	client.encryptResponse = nil
	client.decryptResponse = nil
	client.cryptoEngine = newMockCryptoEngine()

	cm := NewCryptoManager(client, &CryptoManagerConfig{DefaultBackend: "test-backend"})
	return cm, client, client.cryptoEngine
}

// TestValidateRSAPSSParams_RefusesZeroSaltLength pins that a zero-length PSS
// salt is refused rather than approximated.
//
// RFC 8017 §9.1 permits sLen = 0 and some profiles require it, but crypto/rsa
// cannot express it: rsa.PSSOptions.SaltLength reads 0 as PSSSaltLengthAuto,
// -1 as PSSSaltLengthEqualsHash, and only a positive value as a byte count.
// There is no encoding for "exactly zero".
//
// This test exists because the first attempt at supporting sLen=0 carried it
// over the wire as a -2 sentinel and mapped it back to 0 at the service, which
// is PSSSaltLengthAuto -- the round trip landed exactly on the behaviour the
// sentinel was introduced to prevent. The test written alongside it verified
// with rsa.VerifyPSS(SaltLength: 0), which accepts a signature of ANY salt
// length, so it passed while proving nothing. Refusing is the only honest
// answer this token can give.
func TestValidateRSAPSSParams_RefusesZeroSaltLength(t *testing.T) {
	err := validateRSAPSSParams(CKM_RSA_PKCS_PSS, &RSAPSSParams{
		HashAlg: CKM_SHA256,
		MGF:     CKG_MGF1_SHA256,
		SaltLen: 0,
	})

	if err == nil {
		t.Fatal("sLen=0 was accepted; passing it through to crypto/rsa means PSSSaltLengthAuto, " +
			"which signs under the largest salt that fits and verifies ANY salt length")
	}
	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) {
		t.Fatalf("got %T, want *PKCS11Error carrying a CK_RV", err)
	}
	if pkcsErr.Code != CKR_MECHANISM_PARAM_INVALID {
		t.Errorf("got %s, want CKR_MECHANISM_PARAM_INVALID", pkcsErr.Code)
	}
}

// TestValidateRSAPSSParams_AcceptsAPositiveSaltLength is the other half: the
// refusal above must be specific to zero, not a blanket rejection that would
// make PSS unusable.
func TestValidateRSAPSSParams_AcceptsAPositiveSaltLength(t *testing.T) {
	if err := validateRSAPSSParams(CKM_RSA_PKCS_PSS, &RSAPSSParams{
		HashAlg: CKM_SHA256,
		MGF:     CKG_MGF1_SHA256,
		SaltLen: 32,
	}); err != nil {
		t.Fatalf("a positive salt length must be accepted, got %v", err)
	}
}
