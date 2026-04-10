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

package pairing

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockTransportClient implements transport.Client with configurable behavior per method.
type mockTransportClient struct {
	listBackendsResp *transport.ListBackendsResponse
	listBackendsErr  error

	listKeysResp *transport.ListKeysResponse
	listKeysErr  error

	getKeyResp *transport.GetKeyResponse
	getKeyErr  error

	deleteKeyResp *transport.DeleteKeyResponse
	deleteKeyErr  error

	signResp *transport.SignResponse
	signErr  error

	verifyResp *transport.VerifyResponse
	verifyErr  error

	encryptResp *transport.EncryptResponse
	encryptErr  error

	decryptResp *transport.DecryptResponse
	decryptErr  error

	generateKeyResp *transport.GenerateKeyResponse
	generateKeyErr  error

	deriveKeyECDHResp *transport.DeriveKeyECDHResponse
	deriveKeyECDHErr  error

	getBackendResp *transport.BackendInfo
	getBackendErr  error

	attestKeyResp *transport.AttestKeyResponse
	attestKeyErr  error
}

var errNotImplemented = errors.New("not implemented")

func (m *mockTransportClient) Connect(_ context.Context) error {
	return errNotImplemented
}

func (m *mockTransportClient) Close() error {
	return errNotImplemented
}

func (m *mockTransportClient) Health(_ context.Context) (*transport.HealthResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) ListBackends(_ context.Context, _ ...transport.ListOption) (*transport.ListBackendsResponse, error) {
	return m.listBackendsResp, m.listBackendsErr
}

func (m *mockTransportClient) GetBackend(_ context.Context, _ string) (*transport.BackendInfo, error) {
	return m.getBackendResp, m.getBackendErr
}

func (m *mockTransportClient) GenerateKey(_ context.Context, _ *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	return m.generateKeyResp, m.generateKeyErr
}

func (m *mockTransportClient) ListKeys(_ context.Context, _ string, _ ...transport.ListOption) (*transport.ListKeysResponse, error) {
	return m.listKeysResp, m.listKeysErr
}

func (m *mockTransportClient) GetKey(_ context.Context, _, _ string) (*transport.GetKeyResponse, error) {
	return m.getKeyResp, m.getKeyErr
}

func (m *mockTransportClient) DeleteKey(_ context.Context, _, _ string) (*transport.DeleteKeyResponse, error) {
	return m.deleteKeyResp, m.deleteKeyErr
}

func (m *mockTransportClient) Sign(_ context.Context, _ *transport.SignRequest) (*transport.SignResponse, error) {
	return m.signResp, m.signErr
}

func (m *mockTransportClient) Verify(_ context.Context, _ *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	return m.verifyResp, m.verifyErr
}

func (m *mockTransportClient) Encrypt(_ context.Context, _ *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	return m.encryptResp, m.encryptErr
}

func (m *mockTransportClient) Decrypt(_ context.Context, _ *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	return m.decryptResp, m.decryptErr
}

func (m *mockTransportClient) EncryptAsym(_ context.Context, _ *transport.EncryptAsymRequest) (*transport.EncryptAsymResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) DeriveKey(_ context.Context, _ *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) GetCertificate(_ context.Context, _, _ string) (*transport.GetCertificateResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) SaveCertificate(_ context.Context, _ *transport.SaveCertificateRequest) error {
	return errNotImplemented
}

func (m *mockTransportClient) DeleteCertificate(_ context.Context, _, _ string) error {
	return errNotImplemented
}

func (m *mockTransportClient) CertificateExists(_ context.Context, _, _ string) (bool, error) {
	return false, errNotImplemented
}

func (m *mockTransportClient) ImportKey(_ context.Context, _ *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) ExportKey(_ context.Context, _ *transport.ExportKeyRequest) (*transport.ExportKeyResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) RotateKey(_ context.Context, _ *transport.RotateKeyRequest) (*transport.RotateKeyResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) GetImportParameters(_ context.Context, _ *transport.GetImportParametersRequest) (*transport.GetImportParametersResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) WrapKey(_ context.Context, _ *transport.WrapKeyRequest) (*transport.WrapKeyResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) UnwrapKey(_ context.Context, _ *transport.UnwrapKeyRequest) (*transport.UnwrapKeyResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) WrapKeyByID(_ context.Context, _ *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) UnwrapKeyByID(_ context.Context, _ *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) ExportKeyMaterial(_ context.Context, _ *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) DeriveKeyECDH(_ context.Context, _ *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	return m.deriveKeyECDHResp, m.deriveKeyECDHErr
}

func (m *mockTransportClient) CopyKey(_ context.Context, _ *transport.CopyKeyRequest) (*transport.CopyKeyResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) ListCertificates(_ context.Context, _ string, _ ...transport.ListOption) (*transport.ListCertificatesResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) SaveCertificateChain(_ context.Context, _ *transport.SaveCertificateChainRequest) error {
	return errNotImplemented
}

func (m *mockTransportClient) GetCertificateChain(_ context.Context, _, _ string) (*transport.GetCertificateChainResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) GetTLSCertificate(_ context.Context, _, _ string) (*transport.GetTLSCertificateResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) Seal(_ context.Context, _ *transport.SealRequest) (*transport.SealResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) Unseal(_ context.Context, _ *transport.UnsealRequest) (*transport.UnsealResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) CanSeal(_ context.Context, _ string) (*transport.CanSealResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) AttestKey(_ context.Context, _ *transport.AttestKeyRequest) (*transport.AttestKeyResponse, error) {
	return m.attestKeyResp, m.attestKeyErr
}

func (m *mockTransportClient) ListUsers(_ context.Context, _ ...transport.ListOption) (*transport.ListUsersResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) GetUser(_ context.Context, _ string) (*transport.GetUserResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) DeleteUser(_ context.Context, _ string) error {
	return errNotImplemented
}

func (m *mockTransportClient) EnableUser(_ context.Context, _ string) error {
	return errNotImplemented
}

func (m *mockTransportClient) DisableUser(_ context.Context, _ string) error {
	return errNotImplemented
}

func (m *mockTransportClient) ListUserCredentials(_ context.Context, _ string) (*transport.ListUserCredentialsResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) BeginRegistration(_ context.Context, _ *transport.BeginRegistrationRequest) (*transport.BeginRegistrationResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) FinishRegistration(_ context.Context, _ *transport.FinishRegistrationRequest) (*transport.FinishRegistrationResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) BeginAuthentication(_ context.Context, _ *transport.BeginAuthenticationRequest) (*transport.BeginAuthenticationResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) FinishAuthentication(_ context.Context, _ *transport.FinishAuthenticationRequest) (*transport.FinishAuthenticationResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) GetCABundle(_ context.Context, _ *transport.GetCABundleRequest) (*transport.GetCABundleResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) GetCACertificate(_ context.Context, _ *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) SignCSR(_ context.Context, _ *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) IssueCertificate(_ context.Context, _ *transport.IssueCertificateRequest) (*transport.IssueCertificateResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) RevokeCertificate(_ context.Context, _ *transport.RevokeCertificateRequest) (*transport.RevokeCertificateResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) GenerateCRL(_ context.Context, _ *transport.GenerateCRLRequest) (*transport.GenerateCRLResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) IsRevoked(_ context.Context, _ *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error) {
	return nil, errNotImplemented
}

// PIV operations

func (m *mockTransportClient) ListPIVSlots(_ context.Context, _ *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) GetPIVCertificate(_ context.Context, _ *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) StorePIVCertificate(_ context.Context, _ *transport.StorePIVCertificateRequest) error {
	return errNotImplemented
}

func (m *mockTransportClient) DeletePIVCertificate(_ context.Context, _ *transport.DeletePIVCertificateRequest) error {
	return errNotImplemented
}

func (m *mockTransportClient) GeneratePIVKey(_ context.Context, _ *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) ImportPIVCertificate(_ context.Context, _ *transport.StorePIVCertificateRequest) error {
	return errNotImplemented
}

func (m *mockTransportClient) ExportPIVCertificate(_ context.Context, _ *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) GeneratePIVCSR(_ context.Context, _ *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	return nil, errNotImplemented
}

// generateTestPEM generates a well-formed EC P-256 public key PEM for testing.
func generateTestPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
	return string(pemBlock)
}

// newRemoteRequest constructs a JSON-RPC request for handler tests.
func newRemoteRequest(method string, params interface{}) *Request {
	return &Request{
		JSONRPC: JSONRPCVersion,
		ID:      1,
		Method:  method,
		Params:  params,
	}
}

// testLogger returns a quiet logger for tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(
		&discardWriter{},
		&slog.HandlerOptions{Level: slog.LevelError},
	))
}

// discardWriter discards all written bytes.
type discardWriter struct{}

func (d *discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// decodeResult is a helper that unmarshals a successful response's Result into T.
func decodeResult[T any](t *testing.T, resp *Response) T {
	t.Helper()
	require.NotNil(t, resp)
	require.Nil(t, resp.Error, "expected success but got error: %v", resp.Error)
	require.NotNil(t, resp.Result)
	var result T
	err := json.Unmarshal(resp.Result, &result)
	require.NoError(t, err)
	return result
}

// assertErrorResponse validates a JSON-RPC error response.
func assertErrorResponse(t *testing.T, resp *Response, expectedID uint64, expectedCode int) {
	t.Helper()
	require.NotNil(t, resp)
	assert.Equal(t, JSONRPCVersion, resp.JSONRPC)
	assert.Equal(t, expectedID, resp.ID)
	require.NotNil(t, resp.Error)
	assert.Equal(t, expectedCode, resp.Error.Code)
	assert.NotEmpty(t, resp.Error.Message)
}

// --- Constructor Tests ---

func TestNewBridge_NilClient(t *testing.T) {
	b, err := NewBridge(nil, nil)
	require.ErrorIs(t, err, ErrBridgeNotConnected)
	assert.Nil(t, b)
}

func TestNewBridge_NilConfig(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, nil)
	require.NoError(t, err)
	require.NotNil(t, b)
	assert.Equal(t, DefaultBridgeRequestTimeout, b.config.RequestTimeout)
	assert.NotNil(t, b.config.Logger)
}

func TestNewBridge_Success(t *testing.T) {
	client := &mockTransportClient{}
	config := &BridgeConfig{
		AllowedBackends: []string{"tpm2", "software"},
		DeniedBackends:  []string{"deprecated"},
		RequestTimeout:  10 * time.Second,
		Logger:          testLogger(),
	}

	b, err := NewBridge(client, config)
	require.NoError(t, err)
	require.NotNil(t, b)

	// Verify all 16 remote handlers are registered (13 original + 3 TCG-CSR-IDEVID).
	expectedMethods := []string{
		MethodRemoteListBackends,
		MethodRemoteListKeys,
		MethodRemoteGetPublicKey,
		MethodRemoteSign,
		MethodRemoteVerify,
		MethodRemoteEncrypt,
		MethodRemoteDecrypt,
		MethodRemoteDeriveKey,
		MethodRemoteGenerateKey,
		MethodRemoteGetKeyInfo,
		MethodRemoteDeleteKey,
		MethodRemoteAttestKey,
		MethodRemoteAttestDevice,
		// TCG-CSR-IDEVID enrollment methods
		MethodRemoteGetTCGCSRIDevID,
		MethodRemoteActivateCredential,
		MethodRemoteGetAttestationQuote,
	}
	for _, method := range expectedMethods {
		_, ok := b.handlers[method]
		assert.True(t, ok, "handler not registered for method %s", method)
	}

	// Verify access control sets were built.
	assert.Len(t, b.allowedSet, 2)
	assert.Len(t, b.deniedSet, 1)
	_, hasTpm2 := b.allowedSet["tpm2"]
	assert.True(t, hasTpm2)
	_, hasDeprecated := b.deniedSet["deprecated"]
	assert.True(t, hasDeprecated)
}

func TestNewBridge_ZeroTimeout(t *testing.T) {
	client := &mockTransportClient{}
	config := &BridgeConfig{
		RequestTimeout: 0,
		Logger:         testLogger(),
	}

	b, err := NewBridge(client, config)
	require.NoError(t, err)
	assert.Equal(t, DefaultBridgeRequestTimeout, b.config.RequestTimeout)
}

func TestNewBridge_NilLogger(t *testing.T) {
	client := &mockTransportClient{}
	config := &BridgeConfig{
		RequestTimeout: 5 * time.Second,
		Logger:         nil,
	}

	b, err := NewBridge(client, config)
	require.NoError(t, err)
	assert.NotNil(t, b.config.Logger)
}

// --- HandleRequest Tests ---

func TestHandleRequest_NilRequest(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	resp := b.HandleRequest(context.Background(), nil)
	assertErrorResponse(t, resp, 0, ErrorCodeInvalidRequest)
}

func TestHandleRequest_UnknownMethod(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest("unknown.method", nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeMethodNotFound)
	assert.Contains(t, resp.Error.Message, "unknown.method")
}

// --- Backend Access Control Tests ---

func TestBridge_AllowedBackends(t *testing.T) {
	config := &BridgeConfig{
		AllowedBackends: []string{"tpm2", "software"},
		Logger:          testLogger(),
	}

	b, err := NewBridge(&mockTransportClient{}, config)
	require.NoError(t, err)

	assert.True(t, b.isBackendAllowed("tpm2"))
	assert.True(t, b.isBackendAllowed("software"))
	assert.False(t, b.isBackendAllowed("pkcs11"))
	assert.False(t, b.isBackendAllowed("awskms"))
}

func TestBridge_DeniedBackends(t *testing.T) {
	config := &BridgeConfig{
		DeniedBackends: []string{"deprecated", "insecure"},
		Logger:         testLogger(),
	}

	b, err := NewBridge(&mockTransportClient{}, config)
	require.NoError(t, err)

	assert.False(t, b.isBackendAllowed("deprecated"))
	assert.False(t, b.isBackendAllowed("insecure"))
	// With no allow list and not denied, all others are accessible.
	assert.True(t, b.isBackendAllowed("tpm2"))
	assert.True(t, b.isBackendAllowed("software"))
}

func TestBridge_DenyOverridesAllow(t *testing.T) {
	config := &BridgeConfig{
		AllowedBackends: []string{"tpm2", "software", "pkcs11"},
		DeniedBackends:  []string{"pkcs11"},
		Logger:          testLogger(),
	}

	b, err := NewBridge(&mockTransportClient{}, config)
	require.NoError(t, err)

	assert.True(t, b.isBackendAllowed("tpm2"))
	assert.True(t, b.isBackendAllowed("software"))
	// pkcs11 is in both allow and deny; deny wins.
	assert.False(t, b.isBackendAllowed("pkcs11"))
}

func TestBridge_NoAccessControl(t *testing.T) {
	config := &BridgeConfig{
		Logger: testLogger(),
	}

	b, err := NewBridge(&mockTransportClient{}, config)
	require.NoError(t, err)

	assert.True(t, b.isBackendAllowed("tpm2"))
	assert.True(t, b.isBackendAllowed("software"))
	assert.True(t, b.isBackendAllowed("anything"))
}

// --- Handler Tests ---

func TestBridge_ListBackends(t *testing.T) {
	client := &mockTransportClient{
		listBackendsResp: &transport.ListBackendsResponse{
			Backends: []transport.BackendInfo{
				{
					ID:             "tpm2",
					Type:           "tpm2",
					HardwareBacked: true,
					Capabilities: transport.BackendCapabilities{
						Signing:    true,
						Decryption: true,
					},
				},
				{
					ID:   "software",
					Type: "software",
					Capabilities: transport.BackendCapabilities{
						Signing:             true,
						SymmetricEncryption: true,
						KeyAgreement:        true,
					},
				},
			},
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteListBackends, nil)
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteListBackendsResult](t, resp)
	assert.Equal(t, JSONRPCVersion, resp.JSONRPC)
	assert.Equal(t, uint64(1), resp.ID)
	require.Len(t, result.Backends, 2)

	assert.Equal(t, "tpm2", result.Backends[0].Name)
	assert.Equal(t, "tpm2", result.Backends[0].Type)
	assert.True(t, result.Backends[0].HardwareBacked)
	assert.True(t, result.Backends[0].Signing)
	assert.True(t, result.Backends[0].Decryption)
	assert.False(t, result.Backends[0].SymmetricCrypto)

	assert.Equal(t, "software", result.Backends[1].Name)
	assert.True(t, result.Backends[1].Signing)
	assert.True(t, result.Backends[1].SymmetricCrypto)
	assert.True(t, result.Backends[1].KeyAgreement)
}

func TestBridge_ListBackends_FiltersDenied(t *testing.T) {
	client := &mockTransportClient{
		listBackendsResp: &transport.ListBackendsResponse{
			Backends: []transport.BackendInfo{
				{ID: "tpm2", Type: "tpm2"},
				{ID: "insecure", Type: "software"},
				{ID: "pkcs11", Type: "pkcs11"},
			},
		},
	}

	config := &BridgeConfig{
		DeniedBackends: []string{"insecure"},
		Logger:         testLogger(),
	}

	b, err := NewBridge(client, config)
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteListBackends, nil)
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteListBackendsResult](t, resp)
	require.Len(t, result.Backends, 2)
	for _, backend := range result.Backends {
		assert.NotEqual(t, "insecure", backend.Name)
	}
}

func TestBridge_ListBackends_ClientError(t *testing.T) {
	clientErr := errors.New("connection refused")
	client := &mockTransportClient{
		listBackendsErr: clientErr,
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteListBackends, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInternalError)
	assert.Contains(t, resp.Error.Message, "connection refused")
}

func TestBridge_ListKeys_Success(t *testing.T) {
	client := &mockTransportClient{
		listKeysResp: &transport.ListKeysResponse{
			Keys: []transport.KeyInfo{
				{KeyID: "key1", Backend: "tpm2", Algorithm: "ECDSA-P256"},
				{KeyID: "key2", Backend: "tpm2", Algorithm: "RSA-2048"},
			},
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteListKeys, RemoteListKeysParams{
		Backend: "tpm2",
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteListKeysResult](t, resp)
	assert.Equal(t, JSONRPCVersion, resp.JSONRPC)
	require.Len(t, result.Keys, 2)
	assert.Equal(t, "key1", result.Keys[0].KeyID)
	assert.Equal(t, "ECDSA-P256", result.Keys[0].Algorithm)
	assert.Equal(t, "key2", result.Keys[1].KeyID)
}

func TestBridge_ListKeys_BackendDenied(t *testing.T) {
	client := &mockTransportClient{}
	config := &BridgeConfig{
		DeniedBackends: []string{"secret"},
		Logger:         testLogger(),
	}

	b, err := NewBridge(client, config)
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteListKeys, RemoteListKeysParams{
		Backend: "secret",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeBackendDenied)
}

func TestBridge_ListKeys_AlgorithmFilter(t *testing.T) {
	client := &mockTransportClient{
		listKeysResp: &transport.ListKeysResponse{
			Keys: []transport.KeyInfo{
				{KeyID: "ec-key", Backend: "software", Algorithm: "ECDSA-P256"},
				{KeyID: "rsa-key", Backend: "software", Algorithm: "RSA-2048"},
				{KeyID: "ec-key2", Backend: "software", Algorithm: "ECDSA-P256"},
			},
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteListKeys, RemoteListKeysParams{
		Backend:   "software",
		Algorithm: "ECDSA-P256",
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteListKeysResult](t, resp)
	require.Len(t, result.Keys, 2)
	for _, key := range result.Keys {
		assert.Equal(t, "ECDSA-P256", key.Algorithm)
	}
}

func TestBridge_ListKeys_NilParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteListKeys, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_GetPublicKey_DER(t *testing.T) {
	testPEM := generateTestPEM(t)

	client := &mockTransportClient{
		getKeyResp: &transport.GetKeyResponse{
			KeyInfo: transport.KeyInfo{
				KeyID:     "ec-key-1",
				Backend:   "tpm2",
				Algorithm: "ECDSA-P256",
			},
			PublicKeyPEM: testPEM,
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteGetPublicKey, RemoteGetPublicKeyParams{
		Backend: "tpm2",
		KeyID:   "ec-key-1",
		Format:  "der",
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteGetPublicKeyResult](t, resp)
	assert.Equal(t, "der", result.Format)
	assert.Equal(t, "ECDSA-P256", result.Algorithm)
	assert.NotEmpty(t, result.PublicKey)

	// Verify the DER bytes can be parsed back to a public key.
	pubKey, parseErr := x509.ParsePKIXPublicKey(result.PublicKey)
	require.NoError(t, parseErr)
	_, ok := pubKey.(*ecdsa.PublicKey)
	assert.True(t, ok)
}

func TestBridge_GetPublicKey_PEM(t *testing.T) {
	testPEM := generateTestPEM(t)

	client := &mockTransportClient{
		getKeyResp: &transport.GetKeyResponse{
			KeyInfo: transport.KeyInfo{
				KeyID:     "ec-key-1",
				Backend:   "software",
				Algorithm: "ECDSA-P256",
			},
			PublicKeyPEM: testPEM,
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteGetPublicKey, RemoteGetPublicKeyParams{
		Backend: "software",
		KeyID:   "ec-key-1",
		Format:  "pem",
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteGetPublicKeyResult](t, resp)
	assert.Equal(t, "pem", result.Format)
	assert.Equal(t, []byte(testPEM), result.PublicKey)
}

func TestBridge_GetPublicKey_DefaultFormat(t *testing.T) {
	testPEM := generateTestPEM(t)

	client := &mockTransportClient{
		getKeyResp: &transport.GetKeyResponse{
			KeyInfo: transport.KeyInfo{
				KeyID:     "ec-key-1",
				Backend:   "tpm2",
				Algorithm: "ECDSA-P256",
			},
			PublicKeyPEM: testPEM,
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// Empty format should default to DER.
	req := newRemoteRequest(MethodRemoteGetPublicKey, RemoteGetPublicKeyParams{
		Backend: "tpm2",
		KeyID:   "ec-key-1",
		Format:  "",
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteGetPublicKeyResult](t, resp)
	assert.Equal(t, "der", result.Format)
	assert.NotEmpty(t, result.PublicKey)
}

func TestBridge_Sign_Success(t *testing.T) {
	expectedSig := []byte("test-signature-bytes")
	client := &mockTransportClient{
		signResp: &transport.SignResponse{
			Signature: expectedSig,
			Algorithm: "ECDSA-SHA256",
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSign, RemoteSignParams{
		Backend:   "tpm2",
		KeyID:     "signing-key",
		Data:      []byte("data-to-sign"),
		Algorithm: "SHA-256",
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteSignResult](t, resp)
	assert.Equal(t, JSONRPCVersion, resp.JSONRPC)
	assert.Equal(t, expectedSig, result.Signature)
	assert.Equal(t, "ECDSA-SHA256", result.Algorithm)
}

func TestBridge_Sign_BackendDenied(t *testing.T) {
	client := &mockTransportClient{}
	config := &BridgeConfig{
		DeniedBackends: []string{"restricted"},
		Logger:         testLogger(),
	}

	b, err := NewBridge(client, config)
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSign, RemoteSignParams{
		Backend:   "restricted",
		KeyID:     "key1",
		Data:      []byte("data"),
		Algorithm: "SHA-256",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeBackendDenied)
}

func TestBridge_Verify_Success(t *testing.T) {
	client := &mockTransportClient{
		verifyResp: &transport.VerifyResponse{
			Valid: true,
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteVerify, RemoteVerifyParams{
		Backend:   "software",
		KeyID:     "verify-key",
		Data:      []byte("original-data"),
		Signature: []byte("signature-bytes"),
		Algorithm: "SHA-256",
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteVerifyResult](t, resp)
	assert.True(t, result.Valid)
}

func TestBridge_Verify_Invalid(t *testing.T) {
	client := &mockTransportClient{
		verifyResp: &transport.VerifyResponse{
			Valid: false,
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteVerify, RemoteVerifyParams{
		Backend:   "software",
		KeyID:     "verify-key",
		Data:      []byte("original-data"),
		Signature: []byte("bad-signature"),
		Algorithm: "SHA-256",
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteVerifyResult](t, resp)
	assert.False(t, result.Valid)
}

func TestBridge_Encrypt_Success(t *testing.T) {
	expectedCiphertext := []byte("encrypted-data")
	client := &mockTransportClient{
		encryptResp: &transport.EncryptResponse{
			Ciphertext: expectedCiphertext,
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteEncrypt, RemoteEncryptParams{
		Backend:   "software",
		KeyID:     "aes-key",
		Plaintext: []byte("secret-data"),
		AAD:       []byte("additional-data"),
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteEncryptResult](t, resp)
	assert.Equal(t, expectedCiphertext, result.Ciphertext)
}

func TestBridge_Decrypt_Success(t *testing.T) {
	expectedPlaintext := []byte("decrypted-data")
	client := &mockTransportClient{
		decryptResp: &transport.DecryptResponse{
			Plaintext: expectedPlaintext,
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteDecrypt, RemoteDecryptParams{
		Backend:    "tpm2",
		KeyID:      "aes-key",
		Ciphertext: []byte("encrypted-data"),
		AAD:        []byte("additional-data"),
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteDecryptResult](t, resp)
	assert.Equal(t, expectedPlaintext, result.Plaintext)
}

func TestBridge_DeriveKey_Success(t *testing.T) {
	expectedSecret := []byte("shared-secret-32-bytes-long-key!")
	client := &mockTransportClient{
		deriveKeyECDHResp: &transport.DeriveKeyECDHResponse{
			DerivedKey: expectedSecret,
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteDeriveKey, RemoteDeriveKeyParams{
		Backend:       "software",
		KeyID:         "ecdh-key",
		PeerPublicKey: []byte("peer-pubkey-bytes"),
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteDeriveKeyResult](t, resp)
	assert.Equal(t, expectedSecret, result.SharedSecret)
}

func TestBridge_DeriveKey_BackendDenied(t *testing.T) {
	client := &mockTransportClient{}
	config := &BridgeConfig{
		DeniedBackends: []string{"forbidden"},
		Logger:         testLogger(),
	}

	b, err := NewBridge(client, config)
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteDeriveKey, RemoteDeriveKeyParams{
		Backend:       "forbidden",
		KeyID:         "key1",
		PeerPublicKey: []byte("peer-pubkey"),
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeBackendDenied)
}

func TestBridge_DeriveKey_NilParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteDeriveKey, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_DeriveKey_ClientError(t *testing.T) {
	clientErr := errors.New("ecdh failed")
	client := &mockTransportClient{
		deriveKeyECDHErr: clientErr,
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteDeriveKey, RemoteDeriveKeyParams{
		Backend:       "software",
		KeyID:         "ecdh-key",
		PeerPublicKey: []byte("peer-pubkey"),
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInternalError)
}

func TestBridge_GenerateKey_Success(t *testing.T) {

	client := &mockTransportClient{
		generateKeyResp: &transport.GenerateKeyResponse{
			KeyID:   "new-key-1",
			KeyType: "ECDSA-P256",
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteGenerateKey, RemoteGenerateKeyParams{
		Backend:   "software",
		KeyID:     "new-key-1",
		Algorithm: "ECDSA-P256",
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteGenerateKeyResult](t, resp)
	assert.Equal(t, "new-key-1", result.KeyID)
	assert.Equal(t, "software", result.Backend)
}

func TestBridge_GenerateKey_BackendDenied(t *testing.T) {
	client := &mockTransportClient{}
	config := &BridgeConfig{
		DeniedBackends: []string{"restricted"},
		Logger:         testLogger(),
	}

	b, err := NewBridge(client, config)
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteGenerateKey, RemoteGenerateKeyParams{
		Backend:   "restricted",
		KeyID:     "key1",
		Algorithm: "ECDSA-P256",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeBackendDenied)
}

func TestBridge_GenerateKey_NilParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteGenerateKey, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_GenerateKey_ClientError(t *testing.T) {
	clientErr := errors.New("generation failed")
	client := &mockTransportClient{
		generateKeyErr: clientErr,
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteGenerateKey, RemoteGenerateKeyParams{
		Backend:   "software",
		KeyID:     "new-key",
		Algorithm: "RSA-2048",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInternalError)
}

func TestBridge_GetKeyInfo_Success(t *testing.T) {
	client := &mockTransportClient{
		getKeyResp: &transport.GetKeyResponse{
			KeyInfo: transport.KeyInfo{
				KeyID:     "test-key",
				Backend:   "tpm2",
				Algorithm: "ECDSA-P256",
			},
		},
		getBackendResp: &transport.BackendInfo{
			ID:             "tpm2",
			Type:           "tpm2",
			HardwareBacked: true,
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteGetKeyInfo, RemoteGetKeyInfoParams{
		Backend: "tpm2",
		KeyID:   "test-key",
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteGetKeyInfoResult](t, resp)
	assert.Equal(t, "test-key", result.KeyID)
	assert.Equal(t, "tpm2", result.Backend)
	assert.Equal(t, "ECDSA-P256", result.Algorithm)
	assert.True(t, result.HardwareBacked)
}

func TestBridge_GetKeyInfo_BackendDenied(t *testing.T) {
	client := &mockTransportClient{}
	config := &BridgeConfig{
		DeniedBackends: []string{"secret"},
		Logger:         testLogger(),
	}

	b, err := NewBridge(client, config)
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteGetKeyInfo, RemoteGetKeyInfoParams{
		Backend: "secret",
		KeyID:   "key1",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeBackendDenied)
}

func TestBridge_GetKeyInfo_NilParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteGetKeyInfo, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_GetKeyInfo_ClientError(t *testing.T) {
	clientErr := errors.New("key not found")
	client := &mockTransportClient{
		getKeyErr: clientErr,
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteGetKeyInfo, RemoteGetKeyInfoParams{
		Backend: "tpm2",
		KeyID:   "missing-key",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInternalError)
}

func TestBridge_GetKeyInfo_BackendInfoError(t *testing.T) {
	client := &mockTransportClient{
		getKeyResp: &transport.GetKeyResponse{
			KeyInfo: transport.KeyInfo{
				KeyID:     "test-key",
				Backend:   "software",
				Algorithm: "ECDSA-P256",
			},
		},
		getBackendErr: errors.New("backend info unavailable"),
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteGetKeyInfo, RemoteGetKeyInfoParams{
		Backend: "software",
		KeyID:   "test-key",
	})
	resp := b.HandleRequest(context.Background(), req)

	// Should succeed, just without hardware_backed info.
	result := decodeResult[RemoteGetKeyInfoResult](t, resp)
	assert.Equal(t, "test-key", result.KeyID)
	assert.False(t, result.HardwareBacked)
}

func TestBridge_DeleteKey_Success(t *testing.T) {
	client := &mockTransportClient{
		deleteKeyResp: &transport.DeleteKeyResponse{
			Success: true,
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteDeleteKey, RemoteDeleteKeyParams{
		Backend: "software",
		KeyID:   "key-to-delete",
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteDeleteKeyResult](t, resp)
	assert.True(t, result.Deleted)
}

func TestBridge_DeleteKey_BackendDenied(t *testing.T) {
	client := &mockTransportClient{}
	config := &BridgeConfig{
		DeniedBackends: []string{"restricted"},
		Logger:         testLogger(),
	}

	b, err := NewBridge(client, config)
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteDeleteKey, RemoteDeleteKeyParams{
		Backend: "restricted",
		KeyID:   "key1",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeBackendDenied)
}

func TestBridge_DeleteKey_NilParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteDeleteKey, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_DeleteKey_ClientError(t *testing.T) {
	clientErr := errors.New("delete failed")
	client := &mockTransportClient{
		deleteKeyErr: clientErr,
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteDeleteKey, RemoteDeleteKeyParams{
		Backend: "software",
		KeyID:   "key1",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInternalError)
}

func TestBridge_AttestKey_Success(t *testing.T) {
	client := &mockTransportClient{
		attestKeyResp: &transport.AttestKeyResponse{
			Format:           "tpm2",
			CertificateChain: [][]byte{[]byte("cert1"), []byte("cert2")},
			AttestationData:  []byte("attest-data"),
			Nonce:            []byte("echo-nonce"),
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteAttestKey, RemoteAttestKeyParams{
		Backend: "tpm2",
		KeyID:   "attest-key",
		Nonce:   []byte("challenge-nonce"),
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteAttestKeyResult](t, resp)
	assert.Equal(t, "tpm2", result.Format)
	require.Len(t, result.CertificateChain, 2)
	assert.Equal(t, []byte("attest-data"), result.AttestationData)
	assert.Equal(t, []byte("echo-nonce"), result.Nonce)
}

func TestBridge_AttestKey_BackendDenied(t *testing.T) {
	client := &mockTransportClient{}
	config := &BridgeConfig{
		DeniedBackends: []string{"restricted"},
		Logger:         testLogger(),
	}

	b, err := NewBridge(client, config)
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteAttestKey, RemoteAttestKeyParams{
		Backend: "restricted",
		KeyID:   "key1",
		Nonce:   []byte("nonce"),
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeBackendDenied)
}

func TestBridge_AttestKey_NilParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteAttestKey, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_AttestKey_ClientError(t *testing.T) {
	clientErr := errors.New("attestation failed")
	client := &mockTransportClient{
		attestKeyErr: clientErr,
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteAttestKey, RemoteAttestKeyParams{
		Backend: "tpm2",
		KeyID:   "key1",
		Nonce:   []byte("nonce"),
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInternalError)
}

func TestBridge_AttestDevice_SoftwareOnly(t *testing.T) {
	client := &mockTransportClient{
		listBackendsResp: &transport.ListBackendsResponse{
			Backends: []transport.BackendInfo{
				{ID: "software", Type: "software"},
			},
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i)
	}

	req := newRemoteRequest(MethodRemoteAttestDevice, RemoteAttestDeviceParams{
		Nonce: nonce,
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteAttestDeviceResult](t, resp)
	assert.Equal(t, "software", result.Format)
	assert.Equal(t, "software", result.SecurityLevel)
	assert.Equal(t, nonce, result.Nonce)
	assert.False(t, result.BootStateVerified)
}

func TestBridge_AttestDevice_WithTPM2(t *testing.T) {
	client := &mockTransportClient{
		listBackendsResp: &transport.ListBackendsResponse{
			Backends: []transport.BackendInfo{
				{ID: "software", Type: "software"},
				{ID: "tpm2", Type: "tpm2", HardwareBacked: true},
			},
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i)
	}

	req := newRemoteRequest(MethodRemoteAttestDevice, RemoteAttestDeviceParams{
		Nonce: nonce,
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteAttestDeviceResult](t, resp)
	assert.Equal(t, "tpm2", result.Format)
	assert.Equal(t, "hardware", result.SecurityLevel)
	assert.True(t, result.BootStateVerified)
	assert.NotEmpty(t, result.BootHashHex)
}

func TestBridge_AttestDevice_InvalidNonce(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// Nonce must be exactly 32 bytes.
	req := newRemoteRequest(MethodRemoteAttestDevice, RemoteAttestDeviceParams{
		Nonce: []byte("short"),
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_AttestDevice_NilParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteAttestDevice, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_AttestDevice_ListBackendsError(t *testing.T) {
	clientErr := errors.New("connection refused")
	client := &mockTransportClient{
		listBackendsErr: clientErr,
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	nonce := make([]byte, 32)
	req := newRemoteRequest(MethodRemoteAttestDevice, RemoteAttestDeviceParams{
		Nonce: nonce,
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInternalError)
}

// --- TCG-CSR-IDEVID Handler Tests ---

func TestBridge_GetTCGCSRIDevID_ReturnsTPM2DirectAccessRequired(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteGetTCGCSRIDevID, RemoteGetTCGCSRIDevIDParams{
		Backend: "tpm2",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeAttestUnsupported)
}

func TestBridge_GetTCGCSRIDevID_DefaultBackend(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// Empty backend should default to "tpm2".
	req := newRemoteRequest(MethodRemoteGetTCGCSRIDevID, RemoteGetTCGCSRIDevIDParams{})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeAttestUnsupported)
}

func TestBridge_GetTCGCSRIDevID_BackendDenied(t *testing.T) {
	client := &mockTransportClient{}
	config := &BridgeConfig{
		DeniedBackends: []string{"tpm2"},
		Logger:         testLogger(),
	}

	b, err := NewBridge(client, config)
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteGetTCGCSRIDevID, RemoteGetTCGCSRIDevIDParams{
		Backend: "tpm2",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeBackendDenied)
}

func TestBridge_ActivateCredential_ReturnsTPM2DirectAccessRequired(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteActivateCredential, RemoteActivateCredentialParams{
		Backend:         "tpm2",
		CredentialBlob:  []byte("blob"),
		EncryptedSecret: []byte("secret"),
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeAttestUnsupported)
}

func TestBridge_ActivateCredential_BackendDenied(t *testing.T) {
	client := &mockTransportClient{}
	config := &BridgeConfig{
		DeniedBackends: []string{"tpm2"},
		Logger:         testLogger(),
	}

	b, err := NewBridge(client, config)
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteActivateCredential, RemoteActivateCredentialParams{
		Backend:         "tpm2",
		CredentialBlob:  []byte("blob"),
		EncryptedSecret: []byte("secret"),
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeBackendDenied)
}

func TestBridge_GetAttestationQuote_ReturnsTPM2DirectAccessRequired(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteGetAttestationQuote, RemoteGetAttestationQuoteParams{
		Backend:    "tpm2",
		Nonce:      []byte("nonce"),
		PCRIndices: []int{0, 1, 2},
		PCRBank:    "sha256",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeAttestUnsupported)
}

func TestBridge_GetAttestationQuote_BackendDenied(t *testing.T) {
	client := &mockTransportClient{}
	config := &BridgeConfig{
		DeniedBackends: []string{"tpm2"},
		Logger:         testLogger(),
	}

	b, err := NewBridge(client, config)
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteGetAttestationQuote, RemoteGetAttestationQuoteParams{
		Backend: "tpm2",
		Nonce:   []byte("nonce"),
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeBackendDenied)
}

// --- Helper Function Tests ---

func TestExtractPublicKey_EmptyPEM(t *testing.T) {
	_, _, err := extractPublicKey("", "der")
	require.ErrorIs(t, err, ErrKeyNotFound)
}

func TestExtractPublicKey_InvalidPEM(t *testing.T) {
	_, _, err := extractPublicKey("not-a-pem", "der")
	require.ErrorIs(t, err, ErrInvalidPublicKey)
}

func TestExtractPublicKey_InvalidFormat(t *testing.T) {
	testPEM := generateTestPEM(t)
	_, _, err := extractPublicKey(testPEM, "jwk")
	require.ErrorIs(t, err, ErrInvalidFormat)
}

func TestUnmarshalParams_NilParams(t *testing.T) {
	var dest RemoteListKeysParams
	err := unmarshalParams(nil, &dest)
	require.ErrorIs(t, err, ErrBridgeInvalidParams)
}

func TestUnmarshalParams_EmptyParams(t *testing.T) {
	var dest RemoteListKeysParams
	err := unmarshalParams(json.RawMessage{}, &dest)
	require.ErrorIs(t, err, ErrBridgeInvalidParams)
}

func TestMapErrorToRPC_BridgeErrors(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		expectedCode int
	}{
		{"not connected", ErrBridgeNotConnected, ErrorCodeInternalError},
		{"backend denied", ErrBridgeBackendDenied, ErrorCodeBackendDenied},
		{"invalid params", ErrBridgeInvalidParams, ErrorCodeInvalidParams},
		{"attestation not supported", ErrAttestationNotSupported, ErrorCodeAttestUnsupported},
		{"tpm2 direct access", ErrTPM2DirectAccessRequired, ErrorCodeAttestUnsupported},
		{"share denied", ErrShareDenied, ErrorCodeShareDenied},
		{"share not exportable", ErrShareNotExportable, ErrorCodeShareNotExportable},
		{"invalid public key", ErrInvalidPublicKey, ErrorCodeInvalidPublicKey},
		{"backup failed", ErrBackupFailed, ErrorCodeBackupFailed},
		{"backup restore failed", ErrBackupRestoreFailed, ErrorCodeBackupRestore},
		{"backup not found", ErrBackupNotFound, ErrorCodeBackupNotFound},
		{"oath not found", ErrOATHCredentialNotFound, ErrorCodeOATHNotFound},
		{"oath generate", ErrOATHGenerateFailed, ErrorCodeOATHGenerate},
		{"oath store", ErrOATHStoreFailed, ErrorCodeOATHStore},
		{"piv slot not found", ErrPIVSlotNotFound, ErrorCodePIVSlotNotFound},
		{"piv slot occupied", ErrPIVSlotOccupied, ErrorCodePIVSlotOccupied},
		{"piv sign failed", ErrPIVSignFailed, ErrorCodePIVSignFailed},
		{"piv invalid slot", ErrPIVInvalidSlot, ErrorCodePIVInvalidSlot},
		{"sync failed", ErrSyncFailed, ErrorCodeSyncFailed},
		{"sync conflict", ErrSyncConflict, ErrorCodeSyncConflict},
		{"sync remote unavailable", ErrSyncRemoteUnavailable, ErrorCodeSyncRemoteUnavail},
		{"sync no data", ErrSyncNoData, ErrorCodeSyncNoData},
		{"sync version mismatch", ErrSyncVersionMismatch, ErrorCodeSyncVersionMismatch},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, msg := mapErrorToRPC(tt.err)
			assert.Equal(t, tt.expectedCode, code)
			assert.NotEmpty(t, msg)
		})
	}
}

func TestMapErrorToRPC_UnknownError(t *testing.T) {
	err := errors.New("something unexpected")
	code, msg := mapErrorToRPC(err)
	assert.Equal(t, ErrorCodeInternalError, code)
	assert.Equal(t, "something unexpected", msg)
}

func TestMapSDKBackendInfo(t *testing.T) {
	sdk := &transport.BackendInfo{
		ID:             "tpm2",
		Type:           "tpm2",
		HardwareBacked: true,
		Capabilities: transport.BackendCapabilities{
			Signing:     true,
			Attestation: true,
		},
	}

	info := mapSDKBackendInfo(sdk)
	assert.Equal(t, "tpm2", info.Name)
	assert.Equal(t, "tpm2", info.Type)
	assert.True(t, info.HardwareBacked)
	assert.True(t, info.Signing)
	assert.True(t, info.Attestation)
	assert.False(t, info.Decryption)
	assert.False(t, info.SymmetricCrypto)
	assert.False(t, info.KeyAgreement)
}

func TestMapSDKBackendInfo_NilCapabilities(t *testing.T) {
	sdk := &transport.BackendInfo{
		ID:   "software",
		Type: "software",
	}

	info := mapSDKBackendInfo(sdk)
	assert.Equal(t, "software", info.Name)
	assert.False(t, info.Signing)
	assert.False(t, info.Attestation)
}

func TestBridge_Close(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	err = b.Close()
	assert.NoError(t, err)
}

func TestDefaultBridgeConfig(t *testing.T) {
	config := DefaultBridgeConfig()
	assert.Equal(t, DefaultBridgeRequestTimeout, config.RequestTimeout)
	assert.NotNil(t, config.Logger)
}

func TestBridge_ComputeDeviceFingerprint_Empty(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	fp := b.computeDeviceFingerprint(nil, false)
	assert.Empty(t, fp)
}

func TestBridge_ComputeDeviceFingerprint_WithBackends(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	backends := []transport.BackendInfo{
		{ID: "software", Type: "software"},
		{ID: "tpm2", Type: "tpm2", HardwareBacked: true},
	}

	fp := b.computeDeviceFingerprint(backends, true)
	assert.NotEmpty(t, fp)
	assert.Len(t, fp, 64) // SHA-256 hex = 64 chars
}

func TestBridge_ComputeDeviceFingerprint_Deterministic(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	backends := []transport.BackendInfo{
		{ID: "software", Type: "software"},
	}

	fp1 := b.computeDeviceFingerprint(backends, false)
	fp2 := b.computeDeviceFingerprint(backends, false)
	assert.Equal(t, fp1, fp2)
}

// --- Barrier operations (mock only, not exercised by bridge) ---

func (m *mockTransportClient) BarrierInitialize(_ context.Context, _ *transport.BarrierInitializeRequest) error {
	return errNotImplemented
}

func (m *mockTransportClient) BarrierUnseal(_ context.Context, _ *transport.BarrierUnsealRequest) error {
	return errNotImplemented
}

func (m *mockTransportClient) BarrierSeal(_ context.Context) error {
	return errNotImplemented
}

func (m *mockTransportClient) BarrierStatus(_ context.Context) (*transport.BarrierStatusResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) BarrierInitializeShamir(_ context.Context, _ *transport.BarrierInitializeShamirRequest) (*transport.BarrierInitializeShamirResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) BarrierUnsealWithShare(_ context.Context, _ *transport.BarrierUnsealShareRequest) (*transport.BarrierUnsealShareResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) BarrierUnsealWithShares(_ context.Context, _ *transport.BarrierUnsealSharesRequest) error {
	return errNotImplemented
}

func (m *mockTransportClient) BarrierShamirListShares(_ context.Context) (*transport.BarrierShamirSharesResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) BarrierShamirDeleteShare(_ context.Context, _ *transport.BarrierShamirDeleteShareRequest) error {
	return errNotImplemented
}

func (m *mockTransportClient) BarrierShamirDeleteAllShares(_ context.Context) error {
	return errNotImplemented
}

func (m *mockTransportClient) BarrierShamirVerify(_ context.Context) error {
	return errNotImplemented
}

func (m *mockTransportClient) BarrierRekey(_ context.Context, _ *transport.BarrierRekeyRequest) (*transport.BarrierRekeyResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) BarrierGenerateRecoveryKeys(_ context.Context, _ *transport.BarrierGenerateRecoveryKeysRequest) (*transport.BarrierRecoveryKeysResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) BarrierRecoverWithKeys(_ context.Context, _ *transport.BarrierRecoverWithKeysRequest) error {
	return errNotImplemented
}

func (m *mockTransportClient) BarrierDeleteRecoveryKeys(_ context.Context) error {
	return errNotImplemented
}

func (m *mockTransportClient) BarrierHasRecoveryKeys(_ context.Context) (*transport.BarrierHasRecoveryKeysResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) BarrierGenerateRootToken(_ context.Context, _ *transport.BarrierGenerateRootTokenRequest) (*transport.BarrierRootTokenResponse, error) {
	return nil, errNotImplemented
}

// PIN operations

func (m *mockTransportClient) SetSOPIN(_ context.Context, _ *transport.SetSOPINRequest) error {
	return errNotImplemented
}

func (m *mockTransportClient) SetUserPIN(_ context.Context, _ *transport.SetUserPINRequest) error {
	return errNotImplemented
}

func (m *mockTransportClient) ChangeSOPIN(_ context.Context, _ *transport.ChangeSOPINRequest) error {
	return errNotImplemented
}

func (m *mockTransportClient) ChangeUserPIN(_ context.Context, _ *transport.ChangeUserPINRequest) error {
	return errNotImplemented
}

func (m *mockTransportClient) VerifySOPIN(_ context.Context, _ *transport.VerifySOPINRequest) error {
	return errNotImplemented
}

func (m *mockTransportClient) VerifyUserPIN(_ context.Context, _ *transport.VerifyUserPINRequest) error {
	return errNotImplemented
}

func (m *mockTransportClient) GetLockoutStatus(_ context.Context) (*transport.LockoutStatusResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) ResetLockout(_ context.Context, _ *transport.ResetLockoutRequest) error {
	return errNotImplemented
}

// Password operations

func (m *mockTransportClient) PasswordAdd(_ context.Context, _ *transport.PasswordAddRequest) (*transport.PasswordAddResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) PasswordGet(_ context.Context, _ *transport.PasswordGetRequest) (*transport.PasswordGetResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) PasswordList(_ context.Context, _ *transport.PasswordListRequest) (*transport.PasswordListResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) PasswordUpdate(_ context.Context, _ *transport.PasswordUpdateRequest) error {
	return errNotImplemented
}

func (m *mockTransportClient) PasswordDelete(_ context.Context, _ *transport.PasswordDeleteRequest) error {
	return errNotImplemented
}

func (m *mockTransportClient) PasswordStoreUnlock(_ context.Context, _ *transport.PasswordStoreUnlockRequest) error {
	return errNotImplemented
}

func (m *mockTransportClient) PasswordStoreLock(_ context.Context) error {
	return errNotImplemented
}

func (m *mockTransportClient) PasswordStoreStatus(_ context.Context) (*transport.PasswordStoreStatusResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) PasswordStoreSetAccessMode(_ context.Context, _ *transport.PasswordStoreSetAccessModeRequest) error {
	return errNotImplemented
}

func (m *mockTransportClient) PasswordGenerate(_ context.Context, _ *transport.PasswordGenerateRequest) (*transport.PasswordGenerateResponse, error) {
	return nil, errNotImplemented
}

// Platform store operations

func (m *mockTransportClient) SealStorePut(_ context.Context, _ *transport.SealStorePutRequest) error {
	return errNotImplemented
}

func (m *mockTransportClient) SealStoreGet(_ context.Context, _ *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) SealStoreDelete(_ context.Context, _ *transport.SealStoreDeleteRequest) error {
	return errNotImplemented
}

func (m *mockTransportClient) SealStoreList(_ context.Context) (*transport.SealStoreListResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) SealStoreReseal(_ context.Context, _ *transport.SealStoreResealRequest) error {
	return errNotImplemented
}

func (m *mockTransportClient) SealStoreStatus(_ context.Context) (*transport.SealStoreStatusResponse, error) {
	return nil, errNotImplemented
}

// Policy operations

func (m *mockTransportClient) PolicyCreate(_ context.Context, _ *transport.PolicyCreateRequest) (*transport.PolicyCreateResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) PolicyGet(_ context.Context, _ *transport.PolicyGetRequest) (*transport.PolicyGetResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) PolicyList(_ context.Context) (*transport.PolicyListResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) PolicyDelete(_ context.Context, _ *transport.PolicyDeleteRequest) error {
	return errNotImplemented
}

func (m *mockTransportClient) PolicyRefresh(_ context.Context, _ *transport.PolicyRefreshRequest) (*transport.PolicyGetResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) PolicyVerify(_ context.Context, _ *transport.PolicyVerifyRequest) (*transport.PolicyVerifyResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) PolicyExport(_ context.Context, _ *transport.PolicyExportRequest) (*transport.PolicyExportResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) IssueEKCertificate(_ context.Context, _ *transport.IssueEKCertificateRequest) (*transport.IssueEKCertificateResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) IssueAKCertificate(_ context.Context, _ *transport.IssueAKCertificateRequest) (*transport.IssueAKCertificateResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) SignTCGCSR(_ context.Context, _ *transport.SignTCGCSRRequest) (*transport.SignTCGCSRResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) EnrollDevice(_ context.Context, _ *transport.EnrollDeviceRequest) (*transport.EnrollDeviceResponse, error) {
	return nil, errNotImplemented
}

// --- Audit Logging Tests ---

// mockAuditLogger is a minimal audit logger for testing.
type mockAuditLogger struct {
	cryptoOps []string
	keyOps    []string
}

func (m *mockAuditLogger) Log(_ audit.Entry) {}
func (m *mockAuditLogger) LogConnectionEvent(_ audit.OperationType, _, _ string, _ map[string]any) {
}
func (m *mockAuditLogger) LogServiceEvent(_ audit.OperationType, _ map[string]any) {}

func (m *mockAuditLogger) LogKeyOperation(op audit.OperationType, _, _ string, _ bool, _ error, _ int64) {
	m.keyOps = append(m.keyOps, string(op))
}

func (m *mockAuditLogger) LogCryptoOperation(op audit.OperationType, _, _, _, _ string, _ bool, _ error, _ int64) {
	m.cryptoOps = append(m.cryptoOps, string(op))
}

func (m *mockAuditLogger) LogPINOperation(_ audit.OperationType, _ string, _ bool, _ error, _ map[string]any) {
}

func (m *mockAuditLogger) LogTPMOperation(_ audit.OperationType, _ bool, _ error, _ map[string]any) {
}

func (m *mockAuditLogger) LogPasswordStoreOperation(_ audit.OperationType, _ string, _ bool, _ error, _ map[string]any) {
}

func (m *mockAuditLogger) LogUserPresenceEvent(_ audit.OperationType, _ string, _ bool, _ map[string]any) {
}

func TestBridge_Sign_WithAuditLogger(t *testing.T) {
	client := &mockTransportClient{
		signResp: &transport.SignResponse{
			Signature: []byte("sig"),
			Algorithm: "ECDSA",
		},
	}

	auditLog := &mockAuditLogger{}
	b, err := NewBridge(client, &BridgeConfig{
		Logger:      testLogger(),
		AuditLogger: auditLog,
		DeviceID:    "test-device",
		DeviceName:  "Test Phone",
	})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSign, RemoteSignParams{
		Backend:   "software",
		KeyID:     "key1",
		Data:      []byte("data"),
		Algorithm: "SHA-256",
	})
	resp := b.HandleRequest(context.Background(), req)
	require.Nil(t, resp.Error)
	require.Len(t, auditLog.cryptoOps, 1)
	assert.Equal(t, string(audit.OpSignRequest), auditLog.cryptoOps[0])
}

func TestBridge_Sign_WithAuditLogger_ClientError(t *testing.T) {
	client := &mockTransportClient{
		signErr: errors.New("sign failed"),
	}

	auditLog := &mockAuditLogger{}
	b, err := NewBridge(client, &BridgeConfig{
		Logger:      testLogger(),
		AuditLogger: auditLog,
	})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSign, RemoteSignParams{
		Backend: "software",
		KeyID:   "key1",
		Data:    []byte("data"),
	})
	resp := b.HandleRequest(context.Background(), req)
	require.NotNil(t, resp.Error)
	// Audit logger should still be called even on error.
	require.Len(t, auditLog.cryptoOps, 1)
}

func TestBridge_Verify_WithAuditLogger(t *testing.T) {
	client := &mockTransportClient{
		verifyResp: &transport.VerifyResponse{Valid: true},
	}

	auditLog := &mockAuditLogger{}
	b, err := NewBridge(client, &BridgeConfig{
		Logger:      testLogger(),
		AuditLogger: auditLog,
	})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteVerify, RemoteVerifyParams{
		Backend:   "software",
		KeyID:     "key1",
		Data:      []byte("data"),
		Signature: []byte("sig"),
	})
	resp := b.HandleRequest(context.Background(), req)
	require.Nil(t, resp.Error)
	require.Len(t, auditLog.cryptoOps, 1)
	assert.Equal(t, string(audit.OpVerifyRequest), auditLog.cryptoOps[0])
}

func TestBridge_Encrypt_WithAuditLogger(t *testing.T) {
	client := &mockTransportClient{
		encryptResp: &transport.EncryptResponse{Ciphertext: []byte("ct")},
	}

	auditLog := &mockAuditLogger{}
	b, err := NewBridge(client, &BridgeConfig{
		Logger:      testLogger(),
		AuditLogger: auditLog,
	})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteEncrypt, RemoteEncryptParams{
		Backend:   "software",
		KeyID:     "key1",
		Plaintext: []byte("data"),
	})
	resp := b.HandleRequest(context.Background(), req)
	require.Nil(t, resp.Error)
	require.Len(t, auditLog.cryptoOps, 1)
	assert.Equal(t, string(audit.OpEncryptRequest), auditLog.cryptoOps[0])
}

func TestBridge_Decrypt_WithAuditLogger(t *testing.T) {
	client := &mockTransportClient{
		decryptResp: &transport.DecryptResponse{Plaintext: []byte("pt")},
	}

	auditLog := &mockAuditLogger{}
	b, err := NewBridge(client, &BridgeConfig{
		Logger:      testLogger(),
		AuditLogger: auditLog,
	})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteDecrypt, RemoteDecryptParams{
		Backend:    "software",
		KeyID:      "key1",
		Ciphertext: []byte("ct"),
	})
	resp := b.HandleRequest(context.Background(), req)
	require.Nil(t, resp.Error)
	require.Len(t, auditLog.cryptoOps, 1)
	assert.Equal(t, string(audit.OpDecryptRequest), auditLog.cryptoOps[0])
}

func TestBridge_DeriveKey_WithAuditLogger(t *testing.T) {
	client := &mockTransportClient{
		deriveKeyECDHResp: &transport.DeriveKeyECDHResponse{DerivedKey: []byte("secret")},
	}

	auditLog := &mockAuditLogger{}
	b, err := NewBridge(client, &BridgeConfig{
		Logger:      testLogger(),
		AuditLogger: auditLog,
	})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteDeriveKey, RemoteDeriveKeyParams{
		Backend:       "software",
		KeyID:         "key1",
		PeerPublicKey: []byte("peer"),
	})
	resp := b.HandleRequest(context.Background(), req)
	require.Nil(t, resp.Error)
	require.Len(t, auditLog.cryptoOps, 1)
	assert.Equal(t, string(audit.OpDeriveKey), auditLog.cryptoOps[0])
}

func TestBridge_GenerateKey_WithAuditLogger(t *testing.T) {
	client := &mockTransportClient{
		generateKeyResp: &transport.GenerateKeyResponse{
			KeyID:   "new-key",
			KeyType: "ECDSA-P256",
		},
	}

	auditLog := &mockAuditLogger{}
	b, err := NewBridge(client, &BridgeConfig{
		Logger:      testLogger(),
		AuditLogger: auditLog,
	})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteGenerateKey, RemoteGenerateKeyParams{
		Backend:   "software",
		KeyID:     "new-key",
		Algorithm: "ECDSA-P256",
	})
	resp := b.HandleRequest(context.Background(), req)
	require.Nil(t, resp.Error)
	require.Len(t, auditLog.keyOps, 1)
	assert.Equal(t, string(audit.OpKeyCreated), auditLog.keyOps[0])
}

func TestBridge_GenerateKey_WithPublicKeyPEM(t *testing.T) {
	testPEM := generateTestPEM(t)

	client := &mockTransportClient{
		generateKeyResp: &transport.GenerateKeyResponse{
			KeyID:        "new-key",
			KeyType:      "ECDSA-P256",
			PublicKeyPEM: testPEM,
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteGenerateKey, RemoteGenerateKeyParams{
		Backend:   "software",
		KeyID:     "new-key",
		Algorithm: "ECDSA-P256",
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteGenerateKeyResult](t, resp)
	assert.Equal(t, "new-key", result.KeyID)
	assert.NotEmpty(t, result.PublicKey) // Should have DER bytes
}

func TestBridge_DeleteKey_WithAuditLogger(t *testing.T) {
	client := &mockTransportClient{
		deleteKeyResp: &transport.DeleteKeyResponse{Success: true},
	}

	auditLog := &mockAuditLogger{}
	b, err := NewBridge(client, &BridgeConfig{
		Logger:      testLogger(),
		AuditLogger: auditLog,
	})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteDeleteKey, RemoteDeleteKeyParams{
		Backend: "software",
		KeyID:   "key1",
	})
	resp := b.HandleRequest(context.Background(), req)
	require.Nil(t, resp.Error)
	require.Len(t, auditLog.keyOps, 1)
	assert.Equal(t, string(audit.OpKeyDeleted), auditLog.keyOps[0])
}

func TestBridge_AttestKey_WithAuditLogger(t *testing.T) {
	client := &mockTransportClient{
		attestKeyResp: &transport.AttestKeyResponse{
			Format:          "tpm2",
			AttestationData: []byte("data"),
			Nonce:           []byte("nonce"),
		},
	}

	auditLog := &mockAuditLogger{}
	b, err := NewBridge(client, &BridgeConfig{
		Logger:      testLogger(),
		AuditLogger: auditLog,
	})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteAttestKey, RemoteAttestKeyParams{
		Backend: "tpm2",
		KeyID:   "key1",
		Nonce:   []byte("nonce"),
	})
	resp := b.HandleRequest(context.Background(), req)
	require.Nil(t, resp.Error)
	require.Len(t, auditLog.keyOps, 1)
	assert.Equal(t, string(audit.OpKeyAttested), auditLog.keyOps[0])
}

func TestBridge_AttestDevice_WithAuditLogger(t *testing.T) {
	client := &mockTransportClient{
		listBackendsResp: &transport.ListBackendsResponse{
			Backends: []transport.BackendInfo{
				{ID: "software", Type: "software"},
			},
		},
	}

	auditLog := &mockAuditLogger{}
	b, err := NewBridge(client, &BridgeConfig{
		Logger:      testLogger(),
		AuditLogger: auditLog,
	})
	require.NoError(t, err)

	nonce := make([]byte, 32)
	req := newRemoteRequest(MethodRemoteAttestDevice, RemoteAttestDeviceParams{
		Nonce: nonce,
	})
	resp := b.HandleRequest(context.Background(), req)
	require.Nil(t, resp.Error)
	require.Len(t, auditLog.cryptoOps, 1)
	assert.Equal(t, string(audit.OpDeviceAttested), auditLog.cryptoOps[0])
}

func TestBridge_CheckBackendAccess_WithAuditLogger(t *testing.T) {
	auditLog := &mockAuditLogger{}
	client := &mockTransportClient{}
	config := &BridgeConfig{
		DeniedBackends: []string{"restricted"},
		Logger:         testLogger(),
		AuditLogger:    auditLog,
		DeviceID:       "device-1",
		DeviceName:     "Test Device",
	}

	b, err := NewBridge(client, config)
	require.NoError(t, err)

	// Trigger a backend denied to exercise the audit logging in checkBackendAccess.
	req := newRemoteRequest(MethodRemoteListKeys, RemoteListKeysParams{
		Backend: "restricted",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeBackendDenied)
	require.Len(t, auditLog.cryptoOps, 1)
	assert.Equal(t, string(audit.OpPolicyDenied), auditLog.cryptoOps[0])
}

func TestBridge_GetPublicKey_ClientError(t *testing.T) {
	clientErr := errors.New("key not found")
	client := &mockTransportClient{
		getKeyErr: clientErr,
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteGetPublicKey, RemoteGetPublicKeyParams{
		Backend: "software",
		KeyID:   "missing-key",
		Format:  "der",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInternalError)
}

func TestBridge_GetPublicKey_NilParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteGetPublicKey, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_GetPublicKey_BackendDenied(t *testing.T) {
	client := &mockTransportClient{}
	config := &BridgeConfig{
		DeniedBackends: []string{"restricted"},
		Logger:         testLogger(),
	}

	b, err := NewBridge(client, config)
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteGetPublicKey, RemoteGetPublicKeyParams{
		Backend: "restricted",
		KeyID:   "key1",
		Format:  "der",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeBackendDenied)
}

func TestBridge_GetPublicKey_InvalidFormat(t *testing.T) {
	testPEM := generateTestPEM(t)
	client := &mockTransportClient{
		getKeyResp: &transport.GetKeyResponse{
			KeyInfo: transport.KeyInfo{
				KeyID:   "key1",
				Backend: "software",
			},
			PublicKeyPEM: testPEM,
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteGetPublicKey, RemoteGetPublicKeyParams{
		Backend: "software",
		KeyID:   "key1",
		Format:  "jwk",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidFormat)
}

func TestBridge_Verify_NilParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteVerify, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_Verify_ClientError(t *testing.T) {
	client := &mockTransportClient{
		verifyErr: errors.New("verify failed"),
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteVerify, RemoteVerifyParams{
		Backend:   "software",
		KeyID:     "key1",
		Data:      []byte("data"),
		Signature: []byte("sig"),
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInternalError)
}

func TestBridge_Encrypt_NilParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteEncrypt, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_Encrypt_ClientError(t *testing.T) {
	client := &mockTransportClient{
		encryptErr: errors.New("encrypt failed"),
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteEncrypt, RemoteEncryptParams{
		Backend:   "software",
		KeyID:     "key1",
		Plaintext: []byte("data"),
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInternalError)
}

func TestBridge_Encrypt_BackendDenied(t *testing.T) {
	client := &mockTransportClient{}
	config := &BridgeConfig{
		DeniedBackends: []string{"restricted"},
		Logger:         testLogger(),
	}

	b, err := NewBridge(client, config)
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteEncrypt, RemoteEncryptParams{
		Backend:   "restricted",
		KeyID:     "key1",
		Plaintext: []byte("data"),
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeBackendDenied)
}

func TestBridge_Decrypt_NilParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteDecrypt, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_Decrypt_ClientError(t *testing.T) {
	client := &mockTransportClient{
		decryptErr: errors.New("decrypt failed"),
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteDecrypt, RemoteDecryptParams{
		Backend:    "software",
		KeyID:      "key1",
		Ciphertext: []byte("ct"),
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInternalError)
}

func TestBridge_Decrypt_BackendDenied(t *testing.T) {
	client := &mockTransportClient{}
	config := &BridgeConfig{
		DeniedBackends: []string{"restricted"},
		Logger:         testLogger(),
	}

	b, err := NewBridge(client, config)
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteDecrypt, RemoteDecryptParams{
		Backend:    "restricted",
		KeyID:      "key1",
		Ciphertext: []byte("ct"),
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeBackendDenied)
}

func TestBridge_Sign_NilParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSign, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_Sign_ClientError(t *testing.T) {
	client := &mockTransportClient{
		signErr: errors.New("sign failed"),
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSign, RemoteSignParams{
		Backend: "software",
		KeyID:   "key1",
		Data:    []byte("data"),
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInternalError)
}

func TestBridge_Verify_BackendDenied(t *testing.T) {
	client := &mockTransportClient{}
	config := &BridgeConfig{
		DeniedBackends: []string{"restricted"},
		Logger:         testLogger(),
	}

	b, err := NewBridge(client, config)
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteVerify, RemoteVerifyParams{
		Backend:   "restricted",
		KeyID:     "key1",
		Data:      []byte("data"),
		Signature: []byte("sig"),
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeBackendDenied)
}

func TestBridge_ListKeys_ClientError(t *testing.T) {
	client := &mockTransportClient{
		listKeysErr: errors.New("list failed"),
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteListKeys, RemoteListKeysParams{
		Backend: "software",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInternalError)
}

// --- Coverage gap tests: HandleRequest edge cases ---

func TestBridge_HandleRequest_UnmarshalableParams(t *testing.T) {
	// Pass params that json.Marshal cannot serialize (a channel type).
	// This tests HandleRequest lines 188-191.
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := &Request{
		JSONRPC: JSONRPCVersion,
		ID:      999,
		Method:  MethodRemoteListBackends,
		Params:  make(chan int), // channels are not JSON-marshalable
	}
	resp := b.HandleRequest(context.Background(), req)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrorCodeInvalidParams, resp.Error.Code)
}

// --- Coverage gap tests: ActivateCredential/AttestationQuote nil params and empty backend ---

func TestBridge_ActivateCredential_NilParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteActivateCredential, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_ActivateCredential_EmptyBackendDefaultsToTPM2(t *testing.T) {
	// Empty backend should default to "tpm2" (covers the if backend == "" branch).
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteActivateCredential, RemoteActivateCredentialParams{
		Backend:         "", // empty, should default to tpm2
		CredentialBlob:  []byte("blob"),
		EncryptedSecret: []byte("secret"),
	})
	resp := b.HandleRequest(context.Background(), req)
	// Should hit ErrTPM2DirectAccessRequired since backend defaults to allowed tpm2.
	assertErrorResponse(t, resp, req.ID, ErrorCodeAttestUnsupported)
}

func TestBridge_GetAttestationQuote_NilParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteGetAttestationQuote, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_GetAttestationQuote_EmptyBackendDefaultsToTPM2(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteGetAttestationQuote, RemoteGetAttestationQuoteParams{
		Backend: "", // empty, should default to tpm2
		Nonce:   []byte("nonce"),
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeAttestUnsupported)
}

func TestBridge_GetTCGCSRIDevID_NilParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteGetTCGCSRIDevID, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

// --- Coverage gap tests: mapErrorToRPC ErrKeyNotFound ---

func TestBridge_GetPublicKey_KeyNotFound(t *testing.T) {
	// Test the new ErrKeyNotFound mapping in mapErrorToRPC.
	client := &mockTransportClient{
		getKeyResp: &transport.GetKeyResponse{
			KeyInfo: transport.KeyInfo{
				KeyID:   "key1",
				Backend: "software",
			},
			PublicKeyPEM: "", // empty triggers ErrKeyNotFound in extractPublicKey
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteGetPublicKey, RemoteGetPublicKeyParams{
		Backend: "software",
		KeyID:   "key1",
		Format:  "der",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeKeyNotFound)
}

// --- Coverage gap tests: PIV handlePIVListSlots bad JSON ---

func TestBridge_HandlePIVListSlots_BadJSON(t *testing.T) {
	// Pass invalid JSON as params to trigger the json.Unmarshal error branch.
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := &Request{
		JSONRPC: JSONRPCVersion,
		ID:      nextRequestID(),
		Method:  MethodRemotePIVListSlots,
		Params:  42,
	}
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

// --- Coverage gap tests: EncodeResponse marshal error ---

func TestEncodeResponse_MarshalError(t *testing.T) {
	// Pass a value that cannot be marshaled to JSON.
	_, err := EncodeResponse(1, make(chan int))
	require.Error(t, err)
}

// --- Coverage gap tests: message_loop handleInboundRequest edge cases ---

func TestMessageRouter_HandleInboundRequest_NoHandler(t *testing.T) {
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	// Create router with nil request handler.
	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()
	defer router.Stop()

	// Remote side sends an inbound request (not biometric).
	inboundReq := &Request{
		JSONRPC: JSONRPCVersion,
		ID:      nextRequestID(),
		Method:  MethodRemoteListBackends,
		Params:  nil,
	}
	reqBytes, err := json.Marshal(inboundReq)
	require.NoError(t, err)
	ciphertext, err := remoteSession.Encrypt(reqBytes)
	require.NoError(t, err)
	err = remoteTransport.Send(context.Background(), ciphertext)
	require.NoError(t, err)

	// Give router time to process. Since handler is nil, it should log and return.
	time.Sleep(200 * time.Millisecond)
}

func TestMessageRouter_HandleInboundRequest_BadJSON(t *testing.T) {
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	handler := &mockRequestHandler{
		handleFunc: func(_ context.Context, _ *Request) *Response {
			return nil
		},
	}

	router := NewMessageRouter(initiatorTransport, initiatorSession, handler, testLogger())
	router.Start()
	defer router.Stop()

	// Send invalid JSON as an "inbound request" by constructing a message that
	// looks like a request (has "method" in the JSON) but is malformed.
	// First, we need to craft encrypted data that, when decrypted, looks like
	// it has a "method" field for dispatch but fails json.Unmarshal.
	badJSON := []byte(`{"jsonrpc":"2.0","id":1,"method":"remote.listBackends","params":{broken}`)
	ciphertext, err := remoteSession.Encrypt(badJSON)
	require.NoError(t, err)
	err = remoteTransport.Send(context.Background(), ciphertext)
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)
}

func TestMessageRouter_HandleInboundRequest_HandlerReturnsNil(t *testing.T) {
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	handler := &mockRequestHandler{
		handleFunc: func(_ context.Context, _ *Request) *Response {
			return nil // handler returns nil response
		},
	}

	router := NewMessageRouter(initiatorTransport, initiatorSession, handler, testLogger())
	router.Start()
	defer router.Stop()

	inboundReq := &Request{
		JSONRPC: JSONRPCVersion,
		ID:      nextRequestID(),
		Method:  MethodRemoteListBackends,
	}
	reqBytes, err := json.Marshal(inboundReq)
	require.NoError(t, err)
	ciphertext, err := remoteSession.Encrypt(reqBytes)
	require.NoError(t, err)
	err = remoteTransport.Send(context.Background(), ciphertext)
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)
}

// --- Coverage gap tests: SendRequest edge cases ---

func TestMessageRouter_SendRequest_EncodeError(t *testing.T) {
	t.Parallel()

	transport, _ := newPipeTransports()
	initiatorSession, _ := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(transport, initiatorSession, nil, testLogger())
	router.Start()
	defer router.Stop()

	// A request with unmarshalable params should fail EncodeRequest.
	req := &Request{
		JSONRPC: JSONRPCVersion,
		ID:      nextRequestID(),
		Method:  MethodPing,
		Params:  make(chan int), // cannot be marshaled
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err := router.SendRequest(ctx, req)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrProtocolError)
}

// --- Coverage gap tests: routeResponse edge cases ---

func TestMessageRouter_RouteResponse_BadJSON(t *testing.T) {
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()
	defer router.Stop()

	// Send invalid JSON as a response (no method field, so dispatch routes to routeResponse).
	badResp := []byte(`{not valid json}`)
	ciphertext, err := remoteSession.Encrypt(badResp)
	require.NoError(t, err)
	err = remoteTransport.Send(context.Background(), ciphertext)
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)
}

func TestMessageRouter_RouteResponse_UnknownID(t *testing.T) {
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()
	defer router.Stop()

	// Send a valid response with an ID that has no pending request.
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      99999,
		Result:  json.RawMessage(`{"pong":true}`),
	}
	respBytes, err := json.Marshal(resp)
	require.NoError(t, err)
	ciphertext, err := remoteSession.Encrypt(respBytes)
	require.NoError(t, err)
	err = remoteTransport.Send(context.Background(), ciphertext)
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)
}

// --- Coverage gap tests: handleBiometricPending edge cases ---

func TestMessageRouter_HandleBiometricPending_BadJSON(t *testing.T) {
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	handler := &mockRequestHandler{}
	router := NewMessageRouter(initiatorTransport, initiatorSession, handler, testLogger())
	router.Start()
	defer router.Stop()

	// Send a message that has method=local.biometricPending but bad JSON.
	badBiometric := []byte(`{"jsonrpc":"2.0","id":1,"method":"local.biometricPending","params":{broken}`)
	ciphertext, err := remoteSession.Encrypt(badBiometric)
	require.NoError(t, err)
	err = remoteTransport.Send(context.Background(), ciphertext)
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)
}

func TestMessageRouter_HandleBiometricPending_BadParams(t *testing.T) {
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	handler := &mockRequestHandler{}
	router := NewMessageRouter(initiatorTransport, initiatorSession, handler, testLogger())
	router.Start()
	defer router.Stop()

	// Send biometric pending with valid JSON but bad params (not unmarshalable to LocalBiometricPendingParams).
	badParams := []byte(`{"jsonrpc":"2.0","id":1,"method":"local.biometricPending","params":"not-an-object"}`)
	ciphertext, err := remoteSession.Encrypt(badParams)
	require.NoError(t, err)
	err = remoteTransport.Send(context.Background(), ciphertext)
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)
}

// --- Coverage gap: SendRequest encrypt and send error paths ---

func TestMessageRouter_SendRequest_SendError(t *testing.T) {
	t.Parallel()

	initiatorTransport, _ := newPipeTransports()
	initiatorSession, _ := setupHandshakedNoiseSessions(t)

	// Inject a send error to cover message_loop.go line 152-154.
	initiatorTransport.sendErr = errors.New("transport send failed")

	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()
	defer router.Stop()

	req := NewRequest(MethodPing, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err := router.SendRequest(ctx, req)
	require.Error(t, err)
}

func TestMessageRouter_SendRequest_ChannelClosed(t *testing.T) {
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, _ := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()

	// Send a request but close the router's done channel before response comes.
	go func() {
		// Wait a bit for the request to be registered then stop the router.
		time.Sleep(100 * time.Millisecond)

		// Drain the send channel to prevent blocking.
		select {
		case <-remoteTransport.recvCh:
		default:
		}
		router.Stop()
	}()

	req := NewRequest(MethodPing, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := router.SendRequest(ctx, req)
	require.Error(t, err)
}

// --- Coverage gap: receiveLoop closed during read ---

func TestMessageRouter_ReceiveLoop_ClosedDuringRead(t *testing.T) {
	t.Parallel()

	initiatorTransport, _ := newPipeTransports()
	initiatorSession, _ := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()

	// Let the receive loop run, then close the transport to trigger the
	// closed check in receiveLoop (line 184-186).
	time.Sleep(50 * time.Millisecond)

	// Close the transport to make Receive fail.
	initiatorTransport.Close()

	// Stop the router (this sets closed=true).
	router.Stop()

	// Give time for the receive loop to exit.
	time.Sleep(100 * time.Millisecond)
}
