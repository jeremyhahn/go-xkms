// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/client"
)

// validTestCertPEM is a valid test certificate for testing
const validTestCertPEM = `-----BEGIN CERTIFICATE-----
MIIDAzCCAeugAwIBAgIUAt7wV0kfJwTTe07wL0iP50gg0rAwDQYJKoZIhvcNAQEL
BQAwETEPMA0GA1UEAwwGdGVzdGNhMB4XDTI2MDExNTA3MTc0NVoXDTI3MDExNTA3
MTc0NVowETEPMA0GA1UEAwwGdGVzdGNhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEA1164pwnrgwj+jJC3UdifAbPCclaD7MdvaGpnr8zBoCIGwn5o/vfm
rX8WNYWIaCHuOvFemSeIkGKM1TRSfxOKy4/ifPthZQXuYhFLIYO63wxrzajdlUVP
1K/dsXN9ek2Qeg3mbZrj9FBDdg4Su7Tw6dr1hHYajonf1Qh/J8ttz/jl8e8DwhDm
vjPQLHzePeiCv8XhV9d6CM7BLL3XfI03Yi4Fo5kN13bEOOvTnQ8qQGmXl+bt47gj
iIIk5KD/tFavsJhyKBiewgqxty7Z4kBOkdpl7+EF9Pp1vwIh8fd6YoGr4FCBZNj0
VgrUMalRWqig5Z5b3u90XiX5SBcjcWM9KwIDAQABo1MwUTAdBgNVHQ4EFgQUZKHT
8GkTvyE/q3FWNXH398TIjIQwHwYDVR0jBBgwFoAUZKHT8GkTvyE/q3FWNXH398TI
jIQwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEA1E917UeSDgFR
ulgBn26xrMpwWDt7JyJrziIfC3B8cdheRmr7rIsNln+ejbBxTA20nQsuA1yV7UsZ
JTTZqimW4cnwX9ncFEOtqM3GrI3rvBrpOIWWNE2GMUfoOyRg4cuZDrSY+qO5LV+5
S5pnKW9b9KU1o1ENrjIx6WMv5NoITwpsPkZQs/1hMGUljGmky0BH/01OOrSkgeaQ
SC8F4ef7TmIVUNVWAEqnBFOGAqNX+YntXgwOlHAETFT211DBjnq3H0Rt1x2/SA/f
HqAU2Sq3oDkdhbc5AeHV/wjiSPK6QKsvs3HPpWV1PFaOk2MwKv5cc3HCHJtiiq1+
95hO5pwgLQ==
-----END CERTIFICATE-----`

// MockClient implements client.Client for testing remote functions
type MockClient struct {
	// Configuration
	connectErr    error
	closeErr      error
	shouldConnect bool

	// Backend operations
	listBackendsResp *client.ListBackendsResponse
	listBackendsErr  error
	getBackendResp   *client.BackendInfo
	getBackendErr    error

	// Key operations
	generateKeyResp *client.GenerateKeyResponse
	generateKeyErr  error
	listKeysResp    *client.ListKeysResponse
	listKeysErr     error
	getKeyResp      *client.GetKeyResponse
	getKeyErr       error
	deleteKeyResp   *client.DeleteKeyResponse
	deleteKeyErr    error

	// Cryptographic operations
	signResp    *client.SignResponse
	signErr     error
	verifyResp  *client.VerifyResponse
	verifyErr   error
	encryptResp *client.EncryptResponse
	encryptErr  error
	decryptResp *client.DecryptResponse
	decryptErr  error

	// Asymmetric encryption
	encryptAsymResp *client.EncryptAsymResponse
	encryptAsymErr  error

	// Certificate operations
	getCertResp    *client.GetCertificateResponse
	getCertErr     error
	saveCertErr    error
	deleteCertErr  error
	listCertsResp  *client.ListCertificatesResponse
	listCertsErr   error
	saveChainErr   error
	getChainResp   *client.GetCertificateChainResponse
	getChainErr    error
	getTLSCertResp *client.GetTLSCertificateResponse
	getTLSCertErr  error

	// Import/Export operations
	importKeyResp    *client.ImportKeyResponse
	importKeyErr     error
	exportKeyResp    *client.ExportKeyResponse
	exportKeyErr     error
	rotateKeyResp    *client.RotateKeyResponse
	rotateKeyErr     error
	copyKeyResp      *client.CopyKeyResponse
	copyKeyErr       error
	wrapKeyResp      *client.WrapKeyResponse
	wrapKeyErr       error
	unwrapKeyResp    *client.UnwrapKeyResponse
	unwrapKeyErr     error
	getImportParams  *client.GetImportParametersResponse
	getImportParsErr error

	// Key version operations
	listKeyVersionsResp       *client.ListKeyVersionsResponse
	listKeyVersionsErr        error
	enableKeyVersionResp      *client.EnableKeyVersionResponse
	enableKeyVersionErr       error
	disableKeyVersionResp     *client.DisableKeyVersionResponse
	disableKeyVersionErr      error
	enableAllKeyVersionsResp  *client.EnableAllKeyVersionsResponse
	enableAllKeyVersionsErr   error
	disableAllKeyVersionsResp *client.DisableAllKeyVersionsResponse
	disableAllKeyVersionsErr  error

	// Health
	healthResp *client.HealthResponse
	healthErr  error
}

// NewMockClient creates a new mock client with default successful responses
func NewMockClient() *MockClient {
	return &MockClient{
		shouldConnect: true,
		listBackendsResp: &client.ListBackendsResponse{
			Backends: []client.BackendInfo{
				{ID: "software", Type: "software", HardwareBacked: false},
				{ID: "tpm2", Type: "tpm2", HardwareBacked: true},
			},
		},
		getBackendResp: &client.BackendInfo{
			ID:             "software",
			Type:           "software",
			HardwareBacked: false,
			Capabilities: map[string]interface{}{
				"keys":                 true,
				"signing":              true,
				"decryption":           true,
				"key_rotation":         true,
				"symmetric_encryption": true,
				"import":               true,
				"export":               true,
			},
		},
		generateKeyResp: &client.GenerateKeyResponse{
			KeyID:   "test-key",
			KeyType: "rsa",
			Message: "Key generated successfully",
		},
		listKeysResp: &client.ListKeysResponse{
			Keys: []client.KeyInfo{
				{KeyID: "key1", KeyType: "rsa", Backend: "software"},
				{KeyID: "key2", KeyType: "ecdsa", Backend: "software"},
			},
		},
		getKeyResp: &client.GetKeyResponse{
			KeyInfo: client.KeyInfo{
				KeyID:   "test-key",
				KeyType: "rsa",
				Backend: "software",
			},
		},
		deleteKeyResp: &client.DeleteKeyResponse{
			Success: true,
			Message: "Key deleted successfully",
		},
		signResp: &client.SignResponse{
			Signature: []byte("mock-signature-data"),
			Algorithm: "SHA256WithRSA",
		},
		verifyResp: &client.VerifyResponse{
			Valid:   true,
			Message: "Signature verified",
		},
		encryptResp: &client.EncryptResponse{
			Ciphertext: []byte("encrypted-data"),
			Nonce:      []byte("nonce-data"),
			Tag:        []byte("tag-data"),
		},
		decryptResp: &client.DecryptResponse{
			Plaintext: []byte("decrypted-data"),
		},
		encryptAsymResp: &client.EncryptAsymResponse{
			Ciphertext: []byte("asym-encrypted-data"),
		},
		getCertResp: &client.GetCertificateResponse{
			KeyID:          "test-key",
			CertificatePEM: validTestCertPEM,
		},
		listCertsResp: &client.ListCertificatesResponse{
			Certificates: []client.CertificateInfo{
				{KeyID: "cert1"},
				{KeyID: "cert2"},
			},
		},
		getChainResp: &client.GetCertificateChainResponse{
			KeyID: "test-key",
			ChainPEM: []string{
				validTestCertPEM,
			},
		},
		importKeyResp: &client.ImportKeyResponse{
			Success: true,
			KeyID:   "imported-key",
			Message: "Key imported successfully",
		},
		exportKeyResp: &client.ExportKeyResponse{
			KeyID:              "test-key",
			WrappedKeyMaterial: []byte("wrapped-key-material"),
			Algorithm:          "RSA-OAEP",
		},
		rotateKeyResp: &client.RotateKeyResponse{
			Success: true,
			KeyID:   "test-key",
			Message: "Key rotated successfully",
		},
		copyKeyResp: &client.CopyKeyResponse{
			Success: true,
			KeyID:   "copied-key",
			Message: "Key copied successfully",
		},
		wrapKeyResp: &client.WrapKeyResponse{
			WrappedKeyMaterial: []byte("wrapped-material"),
			Algorithm:          "RSA-OAEP",
		},
		unwrapKeyResp: &client.UnwrapKeyResponse{
			KeyMaterial: []byte("unwrapped-key-material"),
		},
		getImportParams: &client.GetImportParametersResponse{
			WrappingPublicKey: []byte("public-key-pem"),
			Algorithm:         "RSA-OAEP",
		},
		healthResp: &client.HealthResponse{
			Status:  "healthy",
			Version: "1.0.0",
		},
		listKeyVersionsResp: &client.ListKeyVersionsResponse{
			KeyID: "test-key",
			Versions: []*client.KeyVersion{
				{Version: 1, Status: "enabled"},
			},
			Total: 1,
		},
		enableKeyVersionResp: &client.EnableKeyVersionResponse{
			KeyID:   "test-key",
			Version: 1,
			Status:  "enabled",
		},
		disableKeyVersionResp: &client.DisableKeyVersionResponse{
			KeyID:   "test-key",
			Version: 1,
			Status:  "disabled",
		},
		enableAllKeyVersionsResp: &client.EnableAllKeyVersionsResponse{
			KeyID:   "test-key",
			Count:   2,
			Message: "Enabled 2 versions",
		},
		disableAllKeyVersionsResp: &client.DisableAllKeyVersionsResponse{
			KeyID:   "test-key",
			Count:   2,
			Message: "Disabled 2 versions",
		},
	}
}

// Connect implements client.Client
func (m *MockClient) Connect(ctx context.Context) error {
	if !m.shouldConnect {
		return m.connectErr
	}
	return nil
}

// Close implements client.Client
func (m *MockClient) Close() error {
	return m.closeErr
}

// Health implements client.Client
func (m *MockClient) Health(ctx context.Context) (*client.HealthResponse, error) {
	return m.healthResp, m.healthErr
}

// ListBackends implements client.Client
func (m *MockClient) ListBackends(ctx context.Context) (*client.ListBackendsResponse, error) {
	return m.listBackendsResp, m.listBackendsErr
}

// GetBackend implements client.Client
func (m *MockClient) GetBackend(ctx context.Context, backendID string) (*client.BackendInfo, error) {
	return m.getBackendResp, m.getBackendErr
}

// GenerateKey implements client.Client
func (m *MockClient) GenerateKey(ctx context.Context, req *client.GenerateKeyRequest) (*client.GenerateKeyResponse, error) {
	return m.generateKeyResp, m.generateKeyErr
}

// ListKeys implements client.Client
func (m *MockClient) ListKeys(ctx context.Context, backend string) (*client.ListKeysResponse, error) {
	return m.listKeysResp, m.listKeysErr
}

// GetKey implements client.Client
func (m *MockClient) GetKey(ctx context.Context, backend, keyID string) (*client.GetKeyResponse, error) {
	return m.getKeyResp, m.getKeyErr
}

// DeleteKey implements client.Client
func (m *MockClient) DeleteKey(ctx context.Context, backend, keyID string) (*client.DeleteKeyResponse, error) {
	return m.deleteKeyResp, m.deleteKeyErr
}

// Sign implements client.Client
func (m *MockClient) Sign(ctx context.Context, req *client.SignRequest) (*client.SignResponse, error) {
	return m.signResp, m.signErr
}

// Verify implements client.Client
func (m *MockClient) Verify(ctx context.Context, req *client.VerifyRequest) (*client.VerifyResponse, error) {
	return m.verifyResp, m.verifyErr
}

// Encrypt implements client.Client
func (m *MockClient) Encrypt(ctx context.Context, req *client.EncryptRequest) (*client.EncryptResponse, error) {
	return m.encryptResp, m.encryptErr
}

// Decrypt implements client.Client
func (m *MockClient) Decrypt(ctx context.Context, req *client.DecryptRequest) (*client.DecryptResponse, error) {
	return m.decryptResp, m.decryptErr
}

// EncryptAsym implements client.Client
func (m *MockClient) EncryptAsym(ctx context.Context, req *client.EncryptAsymRequest) (*client.EncryptAsymResponse, error) {
	return m.encryptAsymResp, m.encryptAsymErr
}

// GetCertificate implements client.Client
func (m *MockClient) GetCertificate(ctx context.Context, backend, keyID string) (*client.GetCertificateResponse, error) {
	return m.getCertResp, m.getCertErr
}

// SaveCertificate implements client.Client
func (m *MockClient) SaveCertificate(ctx context.Context, req *client.SaveCertificateRequest) error {
	return m.saveCertErr
}

// DeleteCertificate implements client.Client
func (m *MockClient) DeleteCertificate(ctx context.Context, backend, keyID string) error {
	return m.deleteCertErr
}

// ImportKey implements client.Client
func (m *MockClient) ImportKey(ctx context.Context, req *client.ImportKeyRequest) (*client.ImportKeyResponse, error) {
	return m.importKeyResp, m.importKeyErr
}

// ExportKey implements client.Client
func (m *MockClient) ExportKey(ctx context.Context, req *client.ExportKeyRequest) (*client.ExportKeyResponse, error) {
	return m.exportKeyResp, m.exportKeyErr
}

// RotateKey implements client.Client
func (m *MockClient) RotateKey(ctx context.Context, req *client.RotateKeyRequest) (*client.RotateKeyResponse, error) {
	return m.rotateKeyResp, m.rotateKeyErr
}

// ListKeyVersions implements client.Client
func (m *MockClient) ListKeyVersions(ctx context.Context, req *client.ListKeyVersionsRequest) (*client.ListKeyVersionsResponse, error) {
	return m.listKeyVersionsResp, m.listKeyVersionsErr
}

// EnableKeyVersion implements client.Client
func (m *MockClient) EnableKeyVersion(ctx context.Context, req *client.EnableKeyVersionRequest) (*client.EnableKeyVersionResponse, error) {
	return m.enableKeyVersionResp, m.enableKeyVersionErr
}

// DisableKeyVersion implements client.Client
func (m *MockClient) DisableKeyVersion(ctx context.Context, req *client.DisableKeyVersionRequest) (*client.DisableKeyVersionResponse, error) {
	return m.disableKeyVersionResp, m.disableKeyVersionErr
}

// EnableAllKeyVersions implements client.Client
func (m *MockClient) EnableAllKeyVersions(ctx context.Context, req *client.EnableAllKeyVersionsRequest) (*client.EnableAllKeyVersionsResponse, error) {
	return m.enableAllKeyVersionsResp, m.enableAllKeyVersionsErr
}

// DisableAllKeyVersions implements client.Client
func (m *MockClient) DisableAllKeyVersions(ctx context.Context, req *client.DisableAllKeyVersionsRequest) (*client.DisableAllKeyVersionsResponse, error) {
	return m.disableAllKeyVersionsResp, m.disableAllKeyVersionsErr
}

// GetImportParameters implements client.Client
func (m *MockClient) GetImportParameters(ctx context.Context, req *client.GetImportParametersRequest) (*client.GetImportParametersResponse, error) {
	return m.getImportParams, m.getImportParsErr
}

// WrapKey implements client.Client
func (m *MockClient) WrapKey(ctx context.Context, req *client.WrapKeyRequest) (*client.WrapKeyResponse, error) {
	return m.wrapKeyResp, m.wrapKeyErr
}

// UnwrapKey implements client.Client
func (m *MockClient) UnwrapKey(ctx context.Context, req *client.UnwrapKeyRequest) (*client.UnwrapKeyResponse, error) {
	return m.unwrapKeyResp, m.unwrapKeyErr
}

// CopyKey implements client.Client
func (m *MockClient) CopyKey(ctx context.Context, req *client.CopyKeyRequest) (*client.CopyKeyResponse, error) {
	return m.copyKeyResp, m.copyKeyErr
}

// ListCertificates implements client.Client
func (m *MockClient) ListCertificates(ctx context.Context, backend string) (*client.ListCertificatesResponse, error) {
	return m.listCertsResp, m.listCertsErr
}

// SaveCertificateChain implements client.Client
func (m *MockClient) SaveCertificateChain(ctx context.Context, req *client.SaveCertificateChainRequest) error {
	return m.saveChainErr
}

// GetCertificateChain implements client.Client
func (m *MockClient) GetCertificateChain(ctx context.Context, backend, keyID string) (*client.GetCertificateChainResponse, error) {
	return m.getChainResp, m.getChainErr
}

// GetTLSCertificate implements client.Client
func (m *MockClient) GetTLSCertificate(ctx context.Context, backend, keyID string) (*client.GetTLSCertificateResponse, error) {
	return m.getTLSCertResp, m.getTLSCertErr
}

// Verify MockClient implements client.Client interface
var _ client.Client = (*MockClient)(nil)

// createMockClientFactory creates a ClientFactory that returns a mock client
func createMockClientFactory(mockClient *MockClient) ClientFactory {
	return func(cfg *Config) (client.Client, error) {
		return mockClient, nil
	}
}

// createMockClientFactoryWithError creates a ClientFactory that returns an error
func createMockClientFactoryWithError(err error) ClientFactory {
	return func(cfg *Config) (client.Client, error) {
		return nil, err
	}
}

// setupGlobalConfig sets up the global config for testing and returns a cleanup function
func setupGlobalConfig(cfg *Config) func() {
	originalConfig := *globalConfig
	*globalConfig = *cfg
	return func() {
		*globalConfig = originalConfig
	}
}

// ============================================================================
// Test generateKeyRemote - using ClientFactory injection
// ============================================================================

func TestGenerateKeyRemote_Success(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	// Call the actual function
	generateKeyRemote(cfg, printer, "test-key", "rsa", "", "rsa", 2048, "", false)

	// Verify output contains success message
	output := buf.String()
	if output == "" {
		t.Error("Expected output from generateKeyRemote")
	}
}

func TestGenerateKeyRemote_ClientCreateError(t *testing.T) {
	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactoryWithError(errors.New("client creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	// This should call handleError which calls exitFunc
	exitCode := captureExit(t, func() {
		generateKeyRemote(cfg, printer, "test-key", "rsa", "", "rsa", 2048, "", false)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestGenerateKeyRemote_ConnectError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.shouldConnect = false
	mockClient.connectErr = errors.New("connection refused")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		generateKeyRemote(cfg, printer, "test-key", "rsa", "", "rsa", 2048, "", false)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestGenerateKeyRemote_GenerateError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.generateKeyErr = errors.New("key generation failed")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		generateKeyRemote(cfg, printer, "test-key", "rsa", "", "rsa", 2048, "", false)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// ============================================================================
// Test listKeysRemote
// ============================================================================

func TestListKeysRemote_Success(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	listKeysRemote(cfg, printer)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from listKeysRemote")
	}
}

func TestListKeysRemote_Error(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.listKeysErr = errors.New("list keys failed")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		listKeysRemote(cfg, printer)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// ============================================================================
// Test getKeyRemote
// ============================================================================

func TestGetKeyRemote_Success(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	getKeyRemote(cfg, printer, "test-key")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from getKeyRemote")
	}
}

func TestGetKeyRemote_Error(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.getKeyErr = errors.New("key not found")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		getKeyRemote(cfg, printer, "nonexistent")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// ============================================================================
// Test deleteKeyRemote
// ============================================================================

func TestDeleteKeyRemote_Success(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	deleteKeyRemote(cfg, printer, "test-key")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from deleteKeyRemote")
	}
}

func TestDeleteKeyRemote_Failure(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.deleteKeyResp = &client.DeleteKeyResponse{
		Success: false,
		Message: "key is in use",
	}

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		deleteKeyRemote(cfg, printer, "locked-key")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestDeleteKeyRemote_Error(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.deleteKeyErr = errors.New("delete failed")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		deleteKeyRemote(cfg, printer, "test-key")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// ============================================================================
// Test signRemote
// ============================================================================

func TestSignRemote_Success(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	signRemote(cfg, printer, "test-key", "data to sign", "SHA256")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from signRemote")
	}
}

func TestSignRemote_Error(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.signErr = errors.New("signing failed")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		signRemote(cfg, printer, "test-key", "data", "SHA256")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// ============================================================================
// Test verifyRemote
// ============================================================================

func TestVerifyRemote_ValidSignature(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.verifyResp = &client.VerifyResponse{
		Valid:   true,
		Message: "Signature valid",
	}

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	sigBase64 := base64.StdEncoding.EncodeToString([]byte("mock-signature"))
	verifyRemote(cfg, printer, "test-key", "original data", sigBase64, "SHA256")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from verifyRemote")
	}
}

func TestVerifyRemote_InvalidSignature(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.verifyResp = &client.VerifyResponse{
		Valid:   false,
		Message: "Signature invalid",
	}

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	sigBase64 := base64.StdEncoding.EncodeToString([]byte("bad-signature"))
	exitCode := captureExit(t, func() {
		verifyRemote(cfg, printer, "test-key", "tampered data", sigBase64, "SHA256")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestVerifyRemote_InvalidBase64(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	// Invalid base64 should be handled
	exitCode := captureExit(t, func() {
		verifyRemote(cfg, printer, "test-key", "data", "not-valid-base64!!!", "SHA256")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestVerifyRemote_Error(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.verifyErr = errors.New("verify failed")

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	sigBase64 := base64.StdEncoding.EncodeToString([]byte("signature"))
	exitCode := captureExit(t, func() {
		verifyRemote(cfg, printer, "test-key", "data", sigBase64, "SHA256")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// ============================================================================
// Test encryptRemote
// ============================================================================

func TestEncryptRemote_Success(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	encryptRemote(cfg, printer, "aes-key", "secret data", "")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from encryptRemote")
	}
}

func TestEncryptRemote_WithAAD(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	encryptRemote(cfg, printer, "aes-key", "secret data", "additional auth data")
}

func TestEncryptRemote_Error(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.encryptErr = errors.New("encryption failed")

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	exitCode := captureExit(t, func() {
		encryptRemote(cfg, printer, "bad-key", "data", "")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// ============================================================================
// Test decryptRemote
// ============================================================================

func TestDecryptRemote_Success(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	ciphertext := base64.StdEncoding.EncodeToString([]byte("encrypted-data"))
	nonce := base64.StdEncoding.EncodeToString([]byte("nonce"))
	tag := base64.StdEncoding.EncodeToString([]byte("tag"))

	decryptRemote(cfg, printer, "aes-key", ciphertext, "", nonce, tag)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from decryptRemote")
	}
}

func TestDecryptRemote_InvalidCiphertextBase64(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	exitCode := captureExit(t, func() {
		decryptRemote(cfg, printer, "aes-key", "invalid-base64!!!", "", "", "")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestDecryptRemote_InvalidNonceBase64(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	ciphertext := base64.StdEncoding.EncodeToString([]byte("encrypted-data"))
	exitCode := captureExit(t, func() {
		decryptRemote(cfg, printer, "aes-key", ciphertext, "", "invalid-base64!!!", "")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestDecryptRemote_InvalidTagBase64(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	ciphertext := base64.StdEncoding.EncodeToString([]byte("encrypted-data"))
	nonce := base64.StdEncoding.EncodeToString([]byte("nonce"))
	exitCode := captureExit(t, func() {
		decryptRemote(cfg, printer, "aes-key", ciphertext, "", nonce, "invalid-base64!!!")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestDecryptRemote_Error(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.decryptErr = errors.New("decryption failed")

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	ciphertext := base64.StdEncoding.EncodeToString([]byte("tampered"))
	exitCode := captureExit(t, func() {
		decryptRemote(cfg, printer, "aes-key", ciphertext, "", "", "")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// ============================================================================
// Test rotateKeyRemote
// ============================================================================

func TestRotateKeyRemote_Success(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	rotateKeyRemote(cfg, printer, "test-key")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from rotateKeyRemote")
	}
}

func TestRotateKeyRemote_Error(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.rotateKeyErr = errors.New("rotation failed")

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	exitCode := captureExit(t, func() {
		rotateKeyRemote(cfg, printer, "test-key")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// ============================================================================
// Test listBackendsRemote
// ============================================================================

func TestListBackendsRemote_Success(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	listBackendsRemote(cfg, printer)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from listBackendsRemote")
	}
}

func TestListBackendsRemote_Error(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.listBackendsErr = errors.New("list backends failed")

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	exitCode := captureExit(t, func() {
		listBackendsRemote(cfg, printer)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// ============================================================================
// Test backendInfoRemote
// ============================================================================

func TestBackendInfoRemote_Success(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	backendInfoRemote(cfg, printer, "software")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from backendInfoRemote")
	}
}

func TestBackendInfoRemote_Error(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.getBackendErr = errors.New("backend not found")

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	exitCode := captureExit(t, func() {
		backendInfoRemote(cfg, printer, "nonexistent")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// ============================================================================
// Test Certificate Remote operations
// ============================================================================

func TestSaveCertRemote_Success(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	certPEM := `-----BEGIN CERTIFICATE-----
test
-----END CERTIFICATE-----`

	saveCertRemote(cfg, printer, "test-key", certPEM)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from saveCertRemote")
	}
}

func TestSaveCertRemote_Error(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.saveCertErr = errors.New("save cert failed")

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	exitCode := captureExit(t, func() {
		saveCertRemote(cfg, printer, "test-key", "cert")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestGetCertRemote_Success(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	getCertRemote(cfg, printer, "test-key")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from getCertRemote")
	}
}

func TestGetCertRemote_Error(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.getCertErr = errors.New("cert not found")

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	exitCode := captureExit(t, func() {
		getCertRemote(cfg, printer, "nonexistent")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestDeleteCertRemote_Success(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	deleteCertRemote(cfg, printer, "test-key")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from deleteCertRemote")
	}
}

func TestDeleteCertRemote_Error(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.deleteCertErr = errors.New("delete cert failed")

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	exitCode := captureExit(t, func() {
		deleteCertRemote(cfg, printer, "test-key")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestListCertsRemote_Success(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	listCertsRemote(cfg, printer)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from listCertsRemote")
	}
}

func TestListCertsRemote_Error(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.listCertsErr = errors.New("list certs failed")

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	exitCode := captureExit(t, func() {
		listCertsRemote(cfg, printer)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestCertExistsRemote_Exists(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	certExistsRemote(cfg, printer, "test-key")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from certExistsRemote")
	}
}

func TestCertExistsRemote_NotExists(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.getCertErr = errors.New("not found")

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	// This should print that cert doesn't exist (not an error)
	certExistsRemote(cfg, printer, "nonexistent")
}

func TestSaveChainRemote_Success(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	chainPEMs := []string{"cert1-pem", "cert2-pem"}
	saveChainRemote(cfg, printer, "test-key", chainPEMs)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from saveChainRemote")
	}
}

func TestSaveChainRemote_Error(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.saveChainErr = errors.New("save chain failed")

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	exitCode := captureExit(t, func() {
		saveChainRemote(cfg, printer, "test-key", []string{})
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestGetChainRemote_Success(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	getChainRemote(cfg, printer, "test-key")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from getChainRemote")
	}
}

func TestGetChainRemote_Error(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.getChainErr = errors.New("get chain failed")

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	exitCode := captureExit(t, func() {
		getChainRemote(cfg, printer, "test-key")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// ============================================================================
// Test encryptAsymRemote
// ============================================================================

func TestEncryptAsymRemote_Success(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	encryptAsymRemote(cfg, printer, "rsa-key", "secret", "SHA256")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from encryptAsymRemote")
	}
}

func TestEncryptAsymRemote_Error(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.encryptAsymErr = errors.New("encrypt failed")

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	exitCode := captureExit(t, func() {
		encryptAsymRemote(cfg, printer, "rsa-key", "secret", "SHA256")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// ============================================================================
// Test importKeyRemote
// ============================================================================

func TestImportKeyRemote_Success(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-key-material"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	importKeyRemote(cfg, printer, "imported-key", wrapped)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from importKeyRemote")
	}
}

func TestImportKeyRemote_ClientCreateError(t *testing.T) {
	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactoryWithError(errors.New("client creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-key-material"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	exitCode := captureExit(t, func() {
		importKeyRemote(cfg, printer, "test-key", wrapped)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestImportKeyRemote_ConnectError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.shouldConnect = false
	mockClient.connectErr = errors.New("connection refused")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-key-material"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	exitCode := captureExit(t, func() {
		importKeyRemote(cfg, printer, "test-key", wrapped)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestImportKeyRemote_ImportError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.importKeyErr = errors.New("import failed")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-key-material"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	exitCode := captureExit(t, func() {
		importKeyRemote(cfg, printer, "test-key", wrapped)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// ============================================================================
// Test exportKeyRemote
// ============================================================================

func TestExportKeyRemote_Success(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	// Create temp file for output
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "exported-key.json")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	exportKeyRemote(cfg, printer, "test-key", outputFile, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from exportKeyRemote")
	}

	// Verify output file was created
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("Expected output file to be created")
	}
}

func TestExportKeyRemote_ClientCreateError(t *testing.T) {
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "exported-key.json")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactoryWithError(errors.New("client creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		exportKeyRemote(cfg, printer, "test-key", outputFile, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestExportKeyRemote_ConnectError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.shouldConnect = false
	mockClient.connectErr = errors.New("connection refused")

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "exported-key.json")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		exportKeyRemote(cfg, printer, "test-key", outputFile, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestExportKeyRemote_ExportError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.exportKeyErr = errors.New("export failed")

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "exported-key.json")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		exportKeyRemote(cfg, printer, "test-key", outputFile, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// ============================================================================
// Test copyKeyRemote
// ============================================================================

func TestCopyKeyRemote_Success(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	copyKeyRemote(cfg, printer, "source-key", "dest-key", "tpm2", "rsa", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from copyKeyRemote")
	}
}

func TestCopyKeyRemote_ClientCreateError(t *testing.T) {
	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactoryWithError(errors.New("client creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		copyKeyRemote(cfg, printer, "source-key", "dest-key", "tpm2", "rsa", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestCopyKeyRemote_ConnectError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.shouldConnect = false
	mockClient.connectErr = errors.New("connection refused")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		copyKeyRemote(cfg, printer, "source-key", "dest-key", "tpm2", "rsa", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestCopyKeyRemote_CopyError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.copyKeyErr = errors.New("copy failed")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		copyKeyRemote(cfg, printer, "source-key", "dest-key", "tpm2", "rsa", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestCopyKeyRemote_WithKeyAlgorithmFallback(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	// Test with empty keyAlgorithm to trigger fallback to keyType
	copyKeyRemote(cfg, printer, "source-key", "dest-key", "tpm2", "signing", "", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from copyKeyRemote")
	}
}

// ============================================================================
// Test getImportParamsRemote
// ============================================================================

func TestGetImportParamsRemote_Success(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	getImportParamsRemote(cfg, printer, "test-key", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from getImportParamsRemote")
	}
}

func TestGetImportParamsRemote_WithOutputFile(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "import-params.json")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	getImportParamsRemote(cfg, printer, "test-key", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, outputFile)

	// Verify output file was created
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("Expected output file to be created")
	}
}

func TestGetImportParamsRemote_ClientCreateError(t *testing.T) {
	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactoryWithError(errors.New("client creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		getImportParamsRemote(cfg, printer, "test-key", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestGetImportParamsRemote_ConnectError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.shouldConnect = false
	mockClient.connectErr = errors.New("connection refused")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		getImportParamsRemote(cfg, printer, "test-key", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestGetImportParamsRemote_GetParamsError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.getImportParsErr = errors.New("get import params failed")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		getImportParamsRemote(cfg, printer, "test-key", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestGetImportParamsRemote_WithKeyAlgorithmFallback(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	// Test with empty keyAlgorithm to trigger fallback to keyType
	getImportParamsRemote(cfg, printer, "test-key", "signing", "", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from getImportParamsRemote")
	}
}

func TestGetImportParamsRemote_WithExpiresAt(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.getImportParams = &client.GetImportParametersResponse{
		WrappingPublicKey: []byte("public-key-der"),
		Algorithm:         "RSA-OAEP",
		ExpiresAt:         "2024-12-31T23:59:59Z",
	}

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	getImportParamsRemote(cfg, printer, "test-key", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from getImportParamsRemote")
	}
}

// ============================================================================
// Test wrapKeyRemote
// ============================================================================

func TestWrapKeyRemote_Success(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "wrapped-key.json")

	// Generate a test RSA key for wrapping public key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	params := &backend.ImportParameters{
		WrappingPublicKey: &rsaKey.PublicKey,
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	keyMaterial := []byte("test-key-material-32-bytes-long!")
	wrapKeyRemote(cfg, printer, keyMaterial, params, outputFile)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from wrapKeyRemote")
	}

	// Verify output file was created
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("Expected output file to be created")
	}
}

func TestWrapKeyRemote_ClientCreateError(t *testing.T) {
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "wrapped-key.json")

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	params := &backend.ImportParameters{
		WrappingPublicKey: &rsaKey.PublicKey,
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactoryWithError(errors.New("client creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		wrapKeyRemote(cfg, printer, []byte("key-material"), params, outputFile)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestWrapKeyRemote_ConnectError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.shouldConnect = false
	mockClient.connectErr = errors.New("connection refused")

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "wrapped-key.json")

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	params := &backend.ImportParameters{
		WrappingPublicKey: &rsaKey.PublicKey,
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		wrapKeyRemote(cfg, printer, []byte("key-material"), params, outputFile)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestWrapKeyRemote_WrapError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.wrapKeyErr = errors.New("wrap failed")

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "wrapped-key.json")

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	params := &backend.ImportParameters{
		WrappingPublicKey: &rsaKey.PublicKey,
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		wrapKeyRemote(cfg, printer, []byte("key-material"), params, outputFile)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestWrapKeyRemote_NilPublicKey(t *testing.T) {
	mockClient := NewMockClient()

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "wrapped-key.json")

	// params with nil WrappingPublicKey should cause marshal error
	params := &backend.ImportParameters{
		WrappingPublicKey: nil,
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		wrapKeyRemote(cfg, printer, []byte("key-material"), params, outputFile)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// ============================================================================
// Test unwrapKeyRemote
// ============================================================================

func TestUnwrapKeyRemote_Success(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "unwrapped-key.bin")

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-key-material"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	params := &backend.ImportParameters{
		WrappingPublicKey: &rsaKey.PublicKey,
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	unwrapKeyRemote(cfg, printer, wrapped, params, outputFile)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from unwrapKeyRemote")
	}

	// Verify output file was created
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("Expected output file to be created")
	}
}

func TestUnwrapKeyRemote_ClientCreateError(t *testing.T) {
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "unwrapped-key.bin")

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-key-material"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	params := &backend.ImportParameters{
		WrappingPublicKey: &rsaKey.PublicKey,
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactoryWithError(errors.New("client creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		unwrapKeyRemote(cfg, printer, wrapped, params, outputFile)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestUnwrapKeyRemote_ConnectError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.shouldConnect = false
	mockClient.connectErr = errors.New("connection refused")

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "unwrapped-key.bin")

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-key-material"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	params := &backend.ImportParameters{
		WrappingPublicKey: &rsaKey.PublicKey,
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		unwrapKeyRemote(cfg, printer, wrapped, params, outputFile)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestUnwrapKeyRemote_UnwrapError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.unwrapKeyErr = errors.New("unwrap failed")

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "unwrapped-key.bin")

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-key-material"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	params := &backend.ImportParameters{
		WrappingPublicKey: &rsaKey.PublicKey,
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		unwrapKeyRemote(cfg, printer, wrapped, params, outputFile)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// ============================================================================
// Test ClientFactory injection
// ============================================================================

func TestClientFactory_InjectedClient(t *testing.T) {
	mockClient := NewMockClient()

	cfg := &Config{
		Backend:       "software",
		ClientFactory: createMockClientFactory(mockClient),
	}

	cl, err := cfg.CreateClient()
	if err != nil {
		t.Fatalf("CreateClient() error = %v", err)
	}

	if cl != mockClient {
		t.Error("CreateClient() should return the injected mock client")
	}
}

func TestClientFactory_InjectedError(t *testing.T) {
	expectedErr := errors.New("client creation failed")

	cfg := &Config{
		Backend:       "software",
		ClientFactory: createMockClientFactoryWithError(expectedErr),
	}

	_, err := cfg.CreateClient()
	if err == nil {
		t.Error("CreateClient() should return error from factory")
	}
	if err != expectedErr {
		t.Errorf("CreateClient() error = %v, want %v", err, expectedErr)
	}
}

func TestClientFactory_NilFactory(t *testing.T) {
	cfg := &Config{
		Backend:       "software",
		ClientFactory: nil,
		Server:        "", // Will use default Unix socket
	}

	// This will fail to connect, but the CreateClient should work
	_, err := cfg.CreateClient()
	// We expect this to succeed in creating the client (not connecting)
	if err != nil {
		t.Logf("CreateClient() returned: %v (expected since no server running)", err)
	}
}

// ============================================================================
// Verify MockClient implements client.Client interface
// ============================================================================

func TestMockClient_ImplementsInterface(t *testing.T) {
	var _ client.Client = (*MockClient)(nil)
}
