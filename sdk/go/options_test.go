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

package xkms

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"
)

// mockService implements XKMSServicer for testing.
type mockService struct{}

func (m *mockService) Health(ctx context.Context) (string, string, error) {
	return "healthy", "1.0.0", nil
}

func (m *mockService) ListBackends(ctx context.Context, opts ...ListOption) ([]BackendInfo, error) {
	return nil, nil
}

func (m *mockService) GetBackend(ctx context.Context, backendID string) (*BackendInfo, error) {
	return nil, nil
}

func (m *mockService) GenerateKey(ctx context.Context, req *GenerateKeyRequest) (*GenerateKeyResponse, error) {
	return nil, nil
}

func (m *mockService) ListKeys(ctx context.Context, backend string, opts ...ListOption) (*ListKeysResponse, error) {
	return nil, nil
}

func (m *mockService) GetKey(ctx context.Context, backend, keyID string) (*GetKeyResponse, error) {
	return nil, nil
}

func (m *mockService) DeleteKey(ctx context.Context, backend, keyID string) error {
	return nil
}

func (m *mockService) Sign(ctx context.Context, req *SignRequest) (*SignResponse, error) {
	return nil, nil
}

func (m *mockService) Verify(ctx context.Context, req *VerifyRequest) (*VerifyResponse, error) {
	return nil, nil
}

func (m *mockService) Encrypt(ctx context.Context, req *EncryptRequest) (*EncryptResponse, error) {
	return nil, nil
}

func (m *mockService) Decrypt(ctx context.Context, req *DecryptRequest) (*DecryptResponse, error) {
	return nil, nil
}

func (m *mockService) EncryptAsym(ctx context.Context, req *EncryptAsymRequest) (*EncryptAsymResponse, error) {
	return nil, nil
}

func (m *mockService) GetCertificate(ctx context.Context, backend, keyID string) (*GetCertificateResponse, error) {
	return nil, nil
}

func (m *mockService) SaveCertificate(ctx context.Context, req *SaveCertificateRequest) error {
	return nil
}

func (m *mockService) DeleteCertificate(ctx context.Context, backend, keyID string) error {
	return nil
}

func (m *mockService) CertificateExists(ctx context.Context, backend, keyID string) (bool, error) {
	return false, nil
}

func (m *mockService) ImportKey(ctx context.Context, req *ImportKeyRequest) (*ImportKeyResponse, error) {
	return nil, nil
}

func (m *mockService) ExportKey(ctx context.Context, req *ExportKeyRequest) (*ExportKeyResponse, error) {
	return nil, nil
}

func (m *mockService) RotateKey(ctx context.Context, req *RotateKeyRequest) (*RotateKeyResponse, error) {
	return nil, nil
}

func (m *mockService) GetImportParameters(ctx context.Context, req *GetImportParametersRequest) (*GetImportParametersResponse, error) {
	return nil, nil
}

func (m *mockService) WrapKey(ctx context.Context, req *WrapKeyRequest) (*WrapKeyResponse, error) {
	return nil, nil
}

func (m *mockService) UnwrapKey(ctx context.Context, req *UnwrapKeyRequest) (*UnwrapKeyResponse, error) {
	return nil, nil
}

func (m *mockService) CopyKey(ctx context.Context, req *CopyKeyRequest) (*CopyKeyResponse, error) {
	return nil, nil
}

func (m *mockService) ListCertificates(ctx context.Context, backend string, opts ...ListOption) (*ListCertificatesResponse, error) {
	return nil, nil
}

func (m *mockService) SaveCertificateChain(ctx context.Context, req *SaveCertificateChainRequest) error {
	return nil
}

func (m *mockService) GetCertificateChain(ctx context.Context, backend, keyID string) (*GetCertificateChainResponse, error) {
	return nil, nil
}

func (m *mockService) GetTLSCertificate(ctx context.Context, backend, keyID string) (*GetTLSCertificateResponse, error) {
	return nil, nil
}

func (m *mockService) Seal(ctx context.Context, req *SealRequest) (*SealResponse, error) {
	return nil, nil
}

func (m *mockService) Unseal(ctx context.Context, req *UnsealRequest) (*UnsealResponse, error) {
	return nil, nil
}

func (m *mockService) CanSeal(ctx context.Context, backend string) (*CanSealResponse, error) {
	return nil, nil
}

func (m *mockService) AttestKey(ctx context.Context, req *AttestKeyRequest) (*AttestKeyResponse, error) {
	return nil, nil
}

// User management methods

func (m *mockService) ListUsers(ctx context.Context, opts ...ListOption) (*ListUsersResponse, error) {
	return nil, nil
}

func (m *mockService) GetUser(ctx context.Context, username string) (*GetUserResponse, error) {
	return nil, nil
}

func (m *mockService) DeleteUser(ctx context.Context, username string) error {
	return nil
}

func (m *mockService) EnableUser(ctx context.Context, username string) error {
	return nil
}

func (m *mockService) DisableUser(ctx context.Context, username string) error {
	return nil
}

func (m *mockService) ListUserCredentials(ctx context.Context, username string) (*ListUserCredentialsResponse, error) {
	return nil, nil
}

// Authentication flow methods

func (m *mockService) BeginRegistration(ctx context.Context, req *BeginRegistrationRequest) (*BeginRegistrationResponse, error) {
	return nil, nil
}

func (m *mockService) FinishRegistration(ctx context.Context, req *FinishRegistrationRequest) (*FinishRegistrationResponse, error) {
	return nil, nil
}

func (m *mockService) BeginAuthentication(ctx context.Context, req *BeginAuthenticationRequest) (*BeginAuthenticationResponse, error) {
	return nil, nil
}

func (m *mockService) FinishAuthentication(ctx context.Context, req *FinishAuthenticationRequest) (*FinishAuthenticationResponse, error) {
	return nil, nil
}

func (m *mockService) DeriveKey(ctx context.Context, req *DeriveKeyRequest) (*DeriveKeyResponse, error) {
	return nil, nil
}

func (m *mockService) WrapKeyByID(ctx context.Context, req *WrapKeyByIDRequest) (*WrapKeyByIDResponse, error) {
	return nil, nil
}

func (m *mockService) UnwrapKeyByID(ctx context.Context, req *UnwrapKeyByIDRequest) (*UnwrapKeyByIDResponse, error) {
	return nil, nil
}

func (m *mockService) ExportKeyMaterial(ctx context.Context, req *ExportKeyMaterialRequest) (*ExportKeyMaterialResponse, error) {
	return nil, nil
}

func (m *mockService) DeriveKeyECDH(ctx context.Context, req *DeriveKeyECDHRequest) (*DeriveKeyECDHResponse, error) {
	return nil, nil
}

func (m *mockService) GetCABundle(ctx context.Context, req *GetCABundleRequest) (*GetCABundleResponse, error) {
	return nil, nil
}

func (m *mockService) GetCACertificate(ctx context.Context, req *GetCACertificateRequest) (*GetCACertificateResponse, error) {
	return nil, nil
}

func (m *mockService) SignCSR(ctx context.Context, req *SignCSRRequest) (*SignCSRResponse, error) {
	return nil, nil
}

func (m *mockService) IssueCertificate(ctx context.Context, req *IssueCertificateRequest) (*IssueCertificateResponse, error) {
	return nil, nil
}

func (m *mockService) RevokeCertificate(ctx context.Context, req *RevokeCertificateRequest) (*RevokeCertificateResponse, error) {
	return nil, nil
}

func (m *mockService) GenerateCRL(ctx context.Context, req *GenerateCRLRequest) (*GenerateCRLResponse, error) {
	return nil, nil
}

func (m *mockService) IsRevoked(ctx context.Context, req *IsRevokedRequest) (*IsRevokedResponse, error) {
	return nil, nil
}

func (m *mockService) IssueEKCertificate(ctx context.Context, req *IssueEKCertificateRequest) (*IssueEKCertificateResponse, error) {
	return nil, nil
}

func (m *mockService) IssueAKCertificate(ctx context.Context, req *IssueAKCertificateRequest) (*IssueAKCertificateResponse, error) {
	return nil, nil
}

func (m *mockService) SignTCGCSR(ctx context.Context, req *SignTCGCSRRequest) (*SignTCGCSRResponse, error) {
	return nil, nil
}

func (m *mockService) EnrollDevice(ctx context.Context, req *EnrollDeviceRequest) (*EnrollDeviceResponse, error) {
	return nil, nil
}

func (m *mockService) ListPIVSlots(ctx context.Context, req *ListPIVSlotsRequest) (*ListPIVSlotsResponse, error) {
	return nil, nil
}

func (m *mockService) GetPIVCertificate(ctx context.Context, req *GetPIVCertificateRequest) (*GetPIVCertificateResponse, error) {
	return nil, nil
}

func (m *mockService) StorePIVCertificate(ctx context.Context, req *StorePIVCertificateRequest) error {
	return nil
}

func (m *mockService) DeletePIVCertificate(ctx context.Context, req *DeletePIVCertificateRequest) error {
	return nil
}

func (m *mockService) GeneratePIVKey(ctx context.Context, req *GeneratePIVKeyRequest) (*GeneratePIVKeyResponse, error) {
	return nil, nil
}

func (m *mockService) ImportPIVCertificate(ctx context.Context, req *StorePIVCertificateRequest) error {
	return nil
}

func (m *mockService) ExportPIVCertificate(ctx context.Context, req *GetPIVCertificateRequest) (*GetPIVCertificateResponse, error) {
	return nil, nil
}

func (m *mockService) GeneratePIVCSR(ctx context.Context, req *GeneratePIVCSRRequest) (*GeneratePIVCSRResponse, error) {
	return nil, nil
}

// Password store methods

func (m *mockService) PasswordAdd(ctx context.Context, req *PasswordAddRequest) (*PasswordAddResponse, error) {
	return nil, nil
}

func (m *mockService) PasswordGet(ctx context.Context, req *PasswordGetRequest) (*PasswordGetResponse, error) {
	return nil, nil
}

func (m *mockService) PasswordList(ctx context.Context, req *PasswordListRequest) (*PasswordListResponse, error) {
	return nil, nil
}

func (m *mockService) PasswordUpdate(ctx context.Context, req *PasswordUpdateRequest) error {
	return nil
}

func (m *mockService) PasswordDelete(ctx context.Context, req *PasswordDeleteRequest) error {
	return nil
}

func (m *mockService) PasswordStoreUnlock(ctx context.Context, req *PasswordStoreUnlockRequest) error {
	return nil
}

func (m *mockService) PasswordStoreLock(ctx context.Context) error {
	return nil
}

func (m *mockService) PasswordStoreStatus(ctx context.Context) (*PasswordStoreStatusResponse, error) {
	return nil, nil
}

func (m *mockService) PasswordStoreSetAccessMode(ctx context.Context, req *PasswordStoreSetAccessModeRequest) error {
	return nil
}

func (m *mockService) PasswordGenerate(ctx context.Context, req *PasswordGenerateRequest) (*PasswordGenerateResponse, error) {
	return nil, nil
}

// Platform store methods

func (m *mockService) SealStorePut(ctx context.Context, req *SealStorePutRequest) error {
	return nil
}

func (m *mockService) SealStoreGet(ctx context.Context, req *SealStoreGetRequest) (*SealStoreGetResponse, error) {
	return nil, nil
}

func (m *mockService) SealStoreDelete(ctx context.Context, req *SealStoreDeleteRequest) error {
	return nil
}

func (m *mockService) SealStoreList(ctx context.Context) (*SealStoreListResponse, error) {
	return nil, nil
}

func (m *mockService) SealStoreReseal(ctx context.Context, req *SealStoreResealRequest) error {
	return nil
}

func (m *mockService) SealStoreStatus(ctx context.Context) (*SealStoreStatusResponse, error) {
	return nil, nil
}

// Policy methods

func (m *mockService) PolicyCreate(ctx context.Context, req *PolicyCreateRequest) (*PolicyCreateResponse, error) {
	return nil, nil
}

func (m *mockService) PolicyGet(ctx context.Context, req *PolicyGetRequest) (*PolicyGetResponse, error) {
	return nil, nil
}

func (m *mockService) PolicyList(ctx context.Context) (*PolicyListResponse, error) {
	return nil, nil
}

func (m *mockService) PolicyDelete(ctx context.Context, req *PolicyDeleteRequest) error {
	return nil
}

func (m *mockService) PolicyRefresh(ctx context.Context, req *PolicyRefreshRequest) (*PolicyGetResponse, error) {
	return nil, nil
}

func (m *mockService) PolicyVerify(ctx context.Context, req *PolicyVerifyRequest) (*PolicyVerifyResponse, error) {
	return nil, nil
}

func (m *mockService) PolicyExport(ctx context.Context, req *PolicyExportRequest) (*PolicyExportResponse, error) {
	return nil, nil
}

func TestWithProtocol(t *testing.T) {
	testCases := []struct {
		name     string
		protocol Protocol
	}{
		{"unix", ProtocolUnix},
		{"unix-grpc", ProtocolUnixGRPC},
		{"rest", ProtocolREST},
		{"grpc", ProtocolGRPC},
		{"quic", ProtocolQUIC},
		{"mcp", ProtocolMCP},
		{"embedded", ProtocolEmbedded},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := newDefaultClientOptions()
			opt := WithProtocol(tc.protocol)
			err := opt(opts)
			if err != nil {
				t.Errorf("WithProtocol(%s) returned error: %v", tc.protocol, err)
			}
			if opts.protocol != tc.protocol {
				t.Errorf("WithProtocol(%s) set protocol to %s", tc.protocol, opts.protocol)
			}
		})
	}
}

func TestWithAddress(t *testing.T) {
	t.Run("valid address", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opt := WithAddress("localhost:8080")
		err := opt(opts)
		if err != nil {
			t.Errorf("WithAddress returned unexpected error: %v", err)
		}
		if opts.address != "localhost:8080" {
			t.Errorf("expected address localhost:8080, got %s", opts.address)
		}
	})

	t.Run("empty address", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opt := WithAddress("")
		err := opt(opts)
		if !errors.Is(err, ErrInvalidAddress) {
			t.Errorf("expected ErrInvalidAddress, got %v", err)
		}
	})
}

func TestWithTLS(t *testing.T) {
	t.Run("with tls config", func(t *testing.T) {
		opts := newDefaultClientOptions()
		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		opt := WithTLS(tlsCfg)
		err := opt(opts)
		if err != nil {
			t.Errorf("WithTLS returned unexpected error: %v", err)
		}
		if opts.tlsConfig != tlsCfg {
			t.Error("WithTLS did not set tlsConfig correctly")
		}
		if !opts.tlsEnabled {
			t.Error("WithTLS should enable TLS")
		}
	})

	t.Run("with nil tls config preserves existing enabled state true", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opts.tlsEnabled = true
		opt := WithTLS(nil)
		err := opt(opts)
		if err != nil {
			t.Errorf("WithTLS(nil) returned unexpected error: %v", err)
		}
		if opts.tlsConfig != nil {
			t.Error("WithTLS(nil) should set tlsConfig to nil")
		}
		// When nil is passed, tlsEnabled is not modified, so it remains true.
		if !opts.tlsEnabled {
			t.Error("WithTLS(nil) should not change existing tlsEnabled=true state")
		}
	})

	t.Run("with nil tls config preserves existing enabled state false", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opts.tlsEnabled = false
		opt := WithTLS(nil)
		err := opt(opts)
		if err != nil {
			t.Errorf("WithTLS(nil) returned unexpected error: %v", err)
		}
		if opts.tlsEnabled {
			t.Error("WithTLS(nil) should not change existing tlsEnabled=false state")
		}
	})
}

func TestWithTLSEnabled(t *testing.T) {
	t.Run("enable TLS", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opt := WithTLSEnabled(true)
		err := opt(opts)
		if err != nil {
			t.Errorf("WithTLSEnabled(true) returned unexpected error: %v", err)
		}
		if !opts.tlsEnabled {
			t.Error("WithTLSEnabled(true) did not enable TLS")
		}
	})

	t.Run("disable TLS", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opts.tlsEnabled = true
		opt := WithTLSEnabled(false)
		err := opt(opts)
		if err != nil {
			t.Errorf("WithTLSEnabled(false) returned unexpected error: %v", err)
		}
		if opts.tlsEnabled {
			t.Error("WithTLSEnabled(false) did not disable TLS")
		}
	})
}

func TestWithTLSCertFile(t *testing.T) {
	opts := newDefaultClientOptions()
	opt := WithTLSCertFile("/path/to/cert.pem")
	err := opt(opts)
	if err != nil {
		t.Errorf("WithTLSCertFile returned unexpected error: %v", err)
	}
	if opts.tlsCertFile != "/path/to/cert.pem" {
		t.Errorf("expected cert file /path/to/cert.pem, got %s", opts.tlsCertFile)
	}
}

func TestWithTLSKeyFile(t *testing.T) {
	opts := newDefaultClientOptions()
	opt := WithTLSKeyFile("/path/to/key.pem")
	err := opt(opts)
	if err != nil {
		t.Errorf("WithTLSKeyFile returned unexpected error: %v", err)
	}
	if opts.tlsKeyFile != "/path/to/key.pem" {
		t.Errorf("expected key file /path/to/key.pem, got %s", opts.tlsKeyFile)
	}
}

func TestWithTLSCAFile(t *testing.T) {
	opts := newDefaultClientOptions()
	opt := WithTLSCAFile("/path/to/ca.pem")
	err := opt(opts)
	if err != nil {
		t.Errorf("WithTLSCAFile returned unexpected error: %v", err)
	}
	if opts.tlsCAFile != "/path/to/ca.pem" {
		t.Errorf("expected CA file /path/to/ca.pem, got %s", opts.tlsCAFile)
	}
}

func TestWithTimeout(t *testing.T) {
	t.Run("valid timeout", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opt := WithTimeout(60 * time.Second)
		err := opt(opts)
		if err != nil {
			t.Errorf("WithTimeout returned unexpected error: %v", err)
		}
		if opts.timeout != 60*time.Second {
			t.Errorf("expected timeout 60s, got %v", opts.timeout)
		}
	})

	t.Run("zero timeout", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opt := WithTimeout(0)
		err := opt(opts)
		if !errors.Is(err, ErrInvalidTimeout) {
			t.Errorf("expected ErrInvalidTimeout, got %v", err)
		}
	})

	t.Run("negative timeout", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opt := WithTimeout(-1 * time.Second)
		err := opt(opts)
		if !errors.Is(err, ErrInvalidTimeout) {
			t.Errorf("expected ErrInvalidTimeout, got %v", err)
		}
	})
}

func TestWithRetry(t *testing.T) {
	t.Run("valid retry config", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opt := WithRetry(5, 200*time.Millisecond)
		err := opt(opts)
		if err != nil {
			t.Errorf("WithRetry returned unexpected error: %v", err)
		}
		if opts.maxRetries != 5 {
			t.Errorf("expected maxRetries 5, got %d", opts.maxRetries)
		}
		if opts.retryBackoff != 200*time.Millisecond {
			t.Errorf("expected retryBackoff 200ms, got %v", opts.retryBackoff)
		}
	})

	t.Run("zero retries valid", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opt := WithRetry(0, 100*time.Millisecond)
		err := opt(opts)
		if err != nil {
			t.Errorf("WithRetry(0, ...) should be valid, got error: %v", err)
		}
	})

	t.Run("negative retries", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opt := WithRetry(-1, 100*time.Millisecond)
		err := opt(opts)
		if !errors.Is(err, ErrInvalidRetryConfig) {
			t.Errorf("expected ErrInvalidRetryConfig, got %v", err)
		}
	})

	t.Run("zero backoff", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opt := WithRetry(3, 0)
		err := opt(opts)
		if !errors.Is(err, ErrInvalidRetryConfig) {
			t.Errorf("expected ErrInvalidRetryConfig, got %v", err)
		}
	})

	t.Run("negative backoff", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opt := WithRetry(3, -1*time.Millisecond)
		err := opt(opts)
		if !errors.Is(err, ErrInvalidRetryConfig) {
			t.Errorf("expected ErrInvalidRetryConfig, got %v", err)
		}
	})
}

func TestWithConnectionPool(t *testing.T) {
	t.Run("valid pool config", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opt := WithConnectionPool(2, 20)
		err := opt(opts)
		if err != nil {
			t.Errorf("WithConnectionPool returned unexpected error: %v", err)
		}
		if opts.poolMinConns != 2 {
			t.Errorf("expected poolMinConns 2, got %d", opts.poolMinConns)
		}
		if opts.poolMaxConns != 20 {
			t.Errorf("expected poolMaxConns 20, got %d", opts.poolMaxConns)
		}
	})

	t.Run("zero min connections valid", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opt := WithConnectionPool(0, 10)
		err := opt(opts)
		if err != nil {
			t.Errorf("WithConnectionPool(0, 10) should be valid, got error: %v", err)
		}
	})

	t.Run("negative min connections", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opt := WithConnectionPool(-1, 10)
		err := opt(opts)
		if !errors.Is(err, ErrInvalidPoolConfig) {
			t.Errorf("expected ErrInvalidPoolConfig, got %v", err)
		}
	})

	t.Run("zero max connections", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opt := WithConnectionPool(0, 0)
		err := opt(opts)
		if !errors.Is(err, ErrInvalidPoolConfig) {
			t.Errorf("expected ErrInvalidPoolConfig, got %v", err)
		}
	})

	t.Run("max less than min", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opt := WithConnectionPool(10, 5)
		err := opt(opts)
		if !errors.Is(err, ErrInvalidPoolConfig) {
			t.Errorf("expected ErrInvalidPoolConfig, got %v", err)
		}
	})
}

func TestWithJWTToken(t *testing.T) {
	t.Run("valid token", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opt := WithJWTToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test")
		err := opt(opts)
		if err != nil {
			t.Errorf("WithJWTToken returned unexpected error: %v", err)
		}
		if opts.jwtToken != "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test" {
			t.Error("WithJWTToken did not set token correctly")
		}
	})

	t.Run("empty token", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opt := WithJWTToken("")
		err := opt(opts)
		if err != nil {
			t.Errorf("WithJWTToken('') returned unexpected error: %v", err)
		}
		if opts.jwtToken != "" {
			t.Error("WithJWTToken('') should set empty token")
		}
	})
}

func TestWithHeaders(t *testing.T) {
	t.Run("single call", func(t *testing.T) {
		opts := newDefaultClientOptions()
		headers := map[string]string{
			"X-Custom-Header": "value1",
			"Authorization":   "Bearer token",
		}
		opt := WithHeaders(headers)
		err := opt(opts)
		if err != nil {
			t.Errorf("WithHeaders returned unexpected error: %v", err)
		}
		if opts.headers["X-Custom-Header"] != "value1" {
			t.Error("WithHeaders did not set X-Custom-Header correctly")
		}
		if opts.headers["Authorization"] != "Bearer token" {
			t.Error("WithHeaders did not set Authorization correctly")
		}
	})

	t.Run("multiple calls merge", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opt1 := WithHeaders(map[string]string{"Header1": "value1"})
		opt2 := WithHeaders(map[string]string{"Header2": "value2"})
		_ = opt1(opts)
		_ = opt2(opts)
		if opts.headers["Header1"] != "value1" {
			t.Error("First headers call not preserved")
		}
		if opts.headers["Header2"] != "value2" {
			t.Error("Second headers call not merged")
		}
	})

	t.Run("later call overrides", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opt1 := WithHeaders(map[string]string{"Header": "value1"})
		opt2 := WithHeaders(map[string]string{"Header": "value2"})
		_ = opt1(opts)
		_ = opt2(opts)
		if opts.headers["Header"] != "value2" {
			t.Error("Later headers call should override earlier")
		}
	})

	t.Run("nil headers map initialization", func(t *testing.T) {
		opts := &clientOptions{}
		opt := WithHeaders(map[string]string{"Key": "Value"})
		err := opt(opts)
		if err != nil {
			t.Errorf("WithHeaders returned unexpected error: %v", err)
		}
		if opts.headers["Key"] != "Value" {
			t.Error("WithHeaders should initialize nil map")
		}
	})
}

func TestWithService(t *testing.T) {
	t.Run("valid service", func(t *testing.T) {
		opts := newDefaultClientOptions()
		svc := &mockService{}
		opt := WithService(svc)
		err := opt(opts)
		if err != nil {
			t.Errorf("WithService returned unexpected error: %v", err)
		}
		if opts.service != svc {
			t.Error("WithService did not set service correctly")
		}
	})

	t.Run("nil service", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opt := WithService(nil)
		err := opt(opts)
		if err != nil {
			t.Errorf("WithService(nil) returned unexpected error: %v", err)
		}
		if opts.service != nil {
			t.Error("WithService(nil) should set service to nil")
		}
	})
}

func TestNewWithOptions_DefaultValues(t *testing.T) {
	// We cannot actually create a working client without a server,
	// but we can test that the options are correctly applied.
	// This test verifies default options are set.
	opts := newDefaultClientOptions()

	if opts.protocol != ProtocolUnixGRPC {
		t.Errorf("default protocol should be unix-grpc, got %s", opts.protocol)
	}
	if opts.address != DefaultUnixSocketPath {
		t.Errorf("default address should be %s, got %s", DefaultUnixSocketPath, opts.address)
	}
	if opts.timeout != DefaultTimeout {
		t.Errorf("default timeout should be %v, got %v", DefaultTimeout, opts.timeout)
	}
	if opts.maxRetries != DefaultMaxRetries {
		t.Errorf("default maxRetries should be %d, got %d", DefaultMaxRetries, opts.maxRetries)
	}
	if opts.retryBackoff != DefaultRetryBackoff {
		t.Errorf("default retryBackoff should be %v, got %v", DefaultRetryBackoff, opts.retryBackoff)
	}
	if opts.poolMinConns != DefaultPoolMinConns {
		t.Errorf("default poolMinConns should be %d, got %d", DefaultPoolMinConns, opts.poolMinConns)
	}
	if opts.poolMaxConns != DefaultPoolMaxConns {
		t.Errorf("default poolMaxConns should be %d, got %d", DefaultPoolMaxConns, opts.poolMaxConns)
	}
}

func TestNewWithOptions_EmbeddedProtocol(t *testing.T) {
	t.Run("embedded with service", func(t *testing.T) {
		svc := &mockService{}
		client, err := NewWithOptions(
			WithProtocol(ProtocolEmbedded),
			WithService(svc),
		)
		if err != nil {
			t.Fatalf("NewWithOptions returned unexpected error: %v", err)
		}
		if client == nil {
			t.Fatal("NewWithOptions returned nil client")
		}
		defer client.Close()
	})

	t.Run("embedded without service", func(t *testing.T) {
		_, err := NewWithOptions(
			WithProtocol(ProtocolEmbedded),
		)
		if !errors.Is(err, ErrMissingService) {
			t.Errorf("expected ErrMissingService, got %v", err)
		}
	})

	t.Run("service with non-embedded protocol", func(t *testing.T) {
		svc := &mockService{}
		_, err := NewWithOptions(
			WithProtocol(ProtocolREST),
			WithService(svc),
		)
		if !errors.Is(err, ErrServiceNotAllowed) {
			t.Errorf("expected ErrServiceNotAllowed, got %v", err)
		}
	})
}

func TestNewWithOptions_OptionError(t *testing.T) {
	// Test that errors from options are properly propagated.
	_, err := NewWithOptions(
		WithTimeout(-1 * time.Second),
	)
	if !errors.Is(err, ErrInvalidTimeout) {
		t.Errorf("expected ErrInvalidTimeout, got %v", err)
	}
}

func TestNewWithOptions_MultipleOptions(t *testing.T) {
	// Test applying multiple options together.
	svc := &mockService{}
	client, err := NewWithOptions(
		WithProtocol(ProtocolEmbedded),
		WithService(svc),
		WithTimeout(60*time.Second),
		WithRetry(5, 500*time.Millisecond),
		WithJWTToken("test-token"),
		WithHeaders(map[string]string{"X-Test": "value"}),
	)
	if err != nil {
		t.Fatalf("NewWithOptions returned unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("NewWithOptions returned nil client")
	}
	defer client.Close()
}

func TestDefaultAddressForProtocol(t *testing.T) {
	testCases := []struct {
		protocol Protocol
		expected string
	}{
		{ProtocolUnix, DefaultUnixSocketPath},
		{ProtocolUnixGRPC, DefaultUnixSocketPath},
		{ProtocolREST, DefaultRESTAddress},
		{ProtocolGRPC, DefaultGRPCAddress},
		{ProtocolQUIC, DefaultQUICAddress},
		{ProtocolMCP, DefaultMCPAddress},
		{ProtocolEmbedded, ""},
		{Protocol("unknown"), ""},
	}

	for _, tc := range testCases {
		t.Run(string(tc.protocol), func(t *testing.T) {
			addr := defaultAddressForProtocol(tc.protocol)
			if addr != tc.expected {
				t.Errorf("defaultAddressForProtocol(%s) = %s, expected %s", tc.protocol, addr, tc.expected)
			}
		})
	}
}

func TestClientOptions_ToConfig(t *testing.T) {
	opts := &clientOptions{
		protocol:    ProtocolGRPC,
		address:     "localhost:9000",
		tlsEnabled:  true,
		tlsCertFile: "/cert.pem",
		tlsKeyFile:  "/key.pem",
		tlsCAFile:   "/ca.pem",
		jwtToken:    "token",
		headers:     map[string]string{"X-Key": "value"},
		service:     &mockService{},
	}

	cfg := opts.toConfig()

	if cfg.Protocol != ProtocolGRPC {
		t.Errorf("expected protocol grpc, got %s", cfg.Protocol)
	}
	if cfg.Address != "localhost:9000" {
		t.Errorf("expected address localhost:9000, got %s", cfg.Address)
	}
	if !cfg.TLSEnabled {
		t.Error("expected TLSEnabled true")
	}
	if cfg.TLSCertFile != "/cert.pem" {
		t.Errorf("expected TLSCertFile /cert.pem, got %s", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/key.pem" {
		t.Errorf("expected TLSKeyFile /key.pem, got %s", cfg.TLSKeyFile)
	}
	if cfg.TLSCAFile != "/ca.pem" {
		t.Errorf("expected TLSCAFile /ca.pem, got %s", cfg.TLSCAFile)
	}
	if cfg.JWTToken != "token" {
		t.Errorf("expected JWTToken token, got %s", cfg.JWTToken)
	}
	if cfg.Headers["X-Key"] != "value" {
		t.Error("expected Headers to contain X-Key")
	}
	if cfg.Service == nil {
		t.Error("expected Service to be set")
	}
}

func TestValidateOptions(t *testing.T) {
	t.Run("valid embedded with service", func(t *testing.T) {
		opts := &clientOptions{
			protocol: ProtocolEmbedded,
			service:  &mockService{},
		}
		err := validateOptions(opts)
		if err != nil {
			t.Errorf("validateOptions returned unexpected error: %v", err)
		}
	})

	t.Run("embedded without service", func(t *testing.T) {
		opts := &clientOptions{
			protocol: ProtocolEmbedded,
			service:  nil,
		}
		err := validateOptions(opts)
		if !errors.Is(err, ErrMissingService) {
			t.Errorf("expected ErrMissingService, got %v", err)
		}
	})

	t.Run("service with non-embedded protocol", func(t *testing.T) {
		opts := &clientOptions{
			protocol: ProtocolREST,
			service:  &mockService{},
		}
		err := validateOptions(opts)
		if !errors.Is(err, ErrServiceNotAllowed) {
			t.Errorf("expected ErrServiceNotAllowed, got %v", err)
		}
	})

	t.Run("non-embedded without service", func(t *testing.T) {
		opts := &clientOptions{
			protocol: ProtocolREST,
			service:  nil,
		}
		err := validateOptions(opts)
		if err != nil {
			t.Errorf("validateOptions returned unexpected error: %v", err)
		}
	})
}

func TestNewWithOptions_EquivalenceWithNew(t *testing.T) {
	// Test that NewWithOptions with equivalent options produces the same config.
	// We test this via the embedded protocol since it doesn't require network.

	svc := &mockService{}

	// Create with New.
	cfg := &BackendConfig{
		Protocol: ProtocolEmbedded,
		Service:  svc,
	}
	client1, err := New(cfg)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	defer client1.Close()

	// Create with NewWithOptions.
	client2, err := NewWithOptions(
		WithProtocol(ProtocolEmbedded),
		WithService(svc),
	)
	if err != nil {
		t.Fatalf("NewWithOptions returned error: %v", err)
	}
	defer client2.Close()

	// Both should be valid embedded clients.
	// We cannot compare them directly, but we can verify they both work.
	ctx := context.Background()

	resp1, err := client1.Health(ctx)
	if err != nil {
		t.Fatalf("client1.Health returned error: %v", err)
	}

	resp2, err := client2.Health(ctx)
	if err != nil {
		t.Fatalf("client2.Health returned error: %v", err)
	}

	if resp1.Status != resp2.Status {
		t.Errorf("Health responses differ: %s vs %s", resp1.Status, resp2.Status)
	}
}

func TestNewWithOptions_TLSOptions(t *testing.T) {
	// Test various TLS option combinations.
	svc := &mockService{}

	t.Run("all TLS options", func(t *testing.T) {
		// We use embedded to avoid network requirements.
		// The TLS options should be stored but not used for embedded.
		client, err := NewWithOptions(
			WithProtocol(ProtocolEmbedded),
			WithService(svc),
			WithTLSEnabled(true),
			WithTLSCertFile("/path/to/cert.pem"),
			WithTLSKeyFile("/path/to/key.pem"),
			WithTLSCAFile("/path/to/ca.pem"),
		)
		if err != nil {
			t.Fatalf("NewWithOptions returned error: %v", err)
		}
		defer client.Close()
	})

	t.Run("custom TLS config", func(t *testing.T) {
		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
		client, err := NewWithOptions(
			WithProtocol(ProtocolEmbedded),
			WithService(svc),
			WithTLS(tlsCfg),
		)
		if err != nil {
			t.Fatalf("NewWithOptions with custom TLS config returned error: %v", err)
		}
		defer client.Close()
	})
}

func TestClientOptionsClientOptions(t *testing.T) {
	opts := &clientOptions{
		protocol: ProtocolGRPC,
		address:  "test:1234",
		timeout:  5 * time.Second,
	}

	copy := opts.ClientOptions()

	if copy.protocol != opts.protocol {
		t.Error("ClientOptions() did not copy protocol")
	}
	if copy.address != opts.address {
		t.Error("ClientOptions() did not copy address")
	}
	if copy.timeout != opts.timeout {
		t.Error("ClientOptions() did not copy timeout")
	}
}

func TestNewDefaultClientOptions(t *testing.T) {
	opts := newDefaultClientOptions()

	if opts.protocol != ProtocolUnixGRPC {
		t.Errorf("expected default protocol %s, got %s", ProtocolUnixGRPC, opts.protocol)
	}
	if opts.address != DefaultUnixSocketPath {
		t.Errorf("expected default address %s, got %s", DefaultUnixSocketPath, opts.address)
	}
	if opts.timeout != DefaultTimeout {
		t.Errorf("expected default timeout %v, got %v", DefaultTimeout, opts.timeout)
	}
	if opts.maxRetries != DefaultMaxRetries {
		t.Errorf("expected default maxRetries %d, got %d", DefaultMaxRetries, opts.maxRetries)
	}
	if opts.retryBackoff != DefaultRetryBackoff {
		t.Errorf("expected default retryBackoff %v, got %v", DefaultRetryBackoff, opts.retryBackoff)
	}
	if opts.poolMinConns != DefaultPoolMinConns {
		t.Errorf("expected default poolMinConns %d, got %d", DefaultPoolMinConns, opts.poolMinConns)
	}
	if opts.poolMaxConns != DefaultPoolMaxConns {
		t.Errorf("expected default poolMaxConns %d, got %d", DefaultPoolMaxConns, opts.poolMaxConns)
	}
	if opts.headers == nil {
		t.Error("expected headers map to be initialized")
	}
}

func TestNewWithOptions_UnsupportedProtocol(t *testing.T) {
	// Test the unsupported protocol path by not setting a service
	// (which means validation will pass for non-embedded).
	_, err := NewWithOptions(
		WithProtocol(Protocol("invalid")),
	)
	if !errors.Is(err, ErrUnsupportedProtocol) {
		t.Errorf("expected ErrUnsupportedProtocol, got %v", err)
	}
}

func TestNewWithOptions_AllProtocols(t *testing.T) {
	// Test that each protocol can be set via options.
	// We only verify that the option is accepted, not that clients work
	// (since most require servers).

	protocols := []Protocol{
		ProtocolUnix,
		ProtocolUnixGRPC,
		ProtocolREST,
		ProtocolGRPC,
		ProtocolQUIC,
		ProtocolMCP,
	}

	for _, p := range protocols {
		t.Run(string(p), func(t *testing.T) {
			opts := newDefaultClientOptions()
			opt := WithProtocol(p)
			err := opt(opts)
			if err != nil {
				t.Errorf("WithProtocol(%s) returned error: %v", p, err)
			}
			if opts.protocol != p {
				t.Errorf("expected protocol %s, got %s", p, opts.protocol)
			}
		})
	}
}

func TestWithConnectionPool_EdgeCases(t *testing.T) {
	t.Run("min equals max", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opt := WithConnectionPool(5, 5)
		err := opt(opts)
		if err != nil {
			t.Errorf("WithConnectionPool(5, 5) should be valid, got error: %v", err)
		}
		if opts.poolMinConns != 5 || opts.poolMaxConns != 5 {
			t.Error("WithConnectionPool(5, 5) did not set values correctly")
		}
	})
}

func TestWithRetry_EdgeCases(t *testing.T) {
	t.Run("large values", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opt := WithRetry(100, 10*time.Second)
		err := opt(opts)
		if err != nil {
			t.Errorf("WithRetry with large values returned error: %v", err)
		}
		if opts.maxRetries != 100 {
			t.Errorf("expected maxRetries 100, got %d", opts.maxRetries)
		}
		if opts.retryBackoff != 10*time.Second {
			t.Errorf("expected retryBackoff 10s, got %v", opts.retryBackoff)
		}
	})
}

func TestWithTimeout_EdgeCases(t *testing.T) {
	t.Run("very small timeout", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opt := WithTimeout(1 * time.Nanosecond)
		err := opt(opts)
		if err != nil {
			t.Errorf("WithTimeout(1ns) returned error: %v", err)
		}
		if opts.timeout != 1*time.Nanosecond {
			t.Errorf("expected timeout 1ns, got %v", opts.timeout)
		}
	})

	t.Run("very large timeout", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opt := WithTimeout(24 * time.Hour)
		err := opt(opts)
		if err != nil {
			t.Errorf("WithTimeout(24h) returned error: %v", err)
		}
		if opts.timeout != 24*time.Hour {
			t.Errorf("expected timeout 24h, got %v", opts.timeout)
		}
	})
}

func TestWithSPKIPin(t *testing.T) {
	t.Run("sets pin and enables TLS", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opt := WithSPKIPin("abc123deadbeef")
		err := opt(opts)
		if err != nil {
			t.Fatalf("WithSPKIPin() returned error: %v", err)
		}
		if opts.spkiPin != "abc123deadbeef" {
			t.Errorf("spkiPin = %q, want %q", opts.spkiPin, "abc123deadbeef")
		}
		if !opts.tlsEnabled {
			t.Error("tlsEnabled should be true when SPKI pin is set")
		}
	})

	t.Run("empty pin still enables TLS", func(t *testing.T) {
		opts := newDefaultClientOptions()
		opt := WithSPKIPin("")
		err := opt(opts)
		if err != nil {
			t.Fatalf("WithSPKIPin() returned error: %v", err)
		}
		if opts.spkiPin != "" {
			t.Errorf("spkiPin = %q, want empty", opts.spkiPin)
		}
		if !opts.tlsEnabled {
			t.Error("tlsEnabled should be true even with empty pin")
		}
	})
}

// Barrier operations
func (m *mockService) BarrierInitialize(ctx context.Context, req *BarrierInitializeRequest) error {
	return nil
}

func (m *mockService) BarrierUnseal(ctx context.Context, req *BarrierUnsealRequest) error {
	return nil
}

func (m *mockService) BarrierSeal(ctx context.Context) error {
	return nil
}

func (m *mockService) BarrierStatus(ctx context.Context) (*BarrierStatusResponse, error) {
	return nil, nil
}

func (m *mockService) BarrierInitializeShamir(ctx context.Context, req *BarrierInitializeShamirRequest) (*BarrierInitializeShamirResponse, error) {
	return nil, nil
}

func (m *mockService) BarrierUnsealWithShare(ctx context.Context, req *BarrierUnsealShareRequest) (*BarrierUnsealShareResponse, error) {
	return nil, nil
}

func (m *mockService) BarrierUnsealWithShares(ctx context.Context, req *BarrierUnsealSharesRequest) error {
	return nil
}

// BarrierShamirListShares returns Shamir share metadata.
func (m *mockService) BarrierShamirListShares(_ context.Context) (*BarrierShamirSharesResponse, error) {
	return nil, nil
}

// BarrierShamirDeleteShare deletes a Shamir share by index.
func (m *mockService) BarrierShamirDeleteShare(_ context.Context, _ *BarrierShamirDeleteShareRequest) error {
	return nil
}

// BarrierShamirDeleteAllShares deletes all Shamir shares.
func (m *mockService) BarrierShamirDeleteAllShares(_ context.Context) error {
	return nil
}

// BarrierShamirVerify verifies Shamir share integrity.
func (m *mockService) BarrierShamirVerify(_ context.Context) error {
	return nil
}

// BarrierRekey re-encrypts the barrier with a new root key.
func (m *mockService) BarrierRekey(_ context.Context, _ *BarrierRekeyRequest) (*BarrierRekeyResponse, error) {
	return nil, nil
}

// BarrierGenerateRecoveryKeys generates recovery keys.
func (m *mockService) BarrierGenerateRecoveryKeys(_ context.Context, _ *BarrierGenerateRecoveryKeysRequest) (*BarrierRecoveryKeysResponse, error) {
	return nil, nil
}

// BarrierRecoverWithKeys recovers the barrier using recovery keys.
func (m *mockService) BarrierRecoverWithKeys(_ context.Context, _ *BarrierRecoverWithKeysRequest) error {
	return nil
}

// BarrierDeleteRecoveryKeys deletes all recovery keys.
func (m *mockService) BarrierDeleteRecoveryKeys(_ context.Context) error {
	return nil
}

// BarrierHasRecoveryKeys checks if recovery keys exist.
func (m *mockService) BarrierHasRecoveryKeys(_ context.Context) (*BarrierHasRecoveryKeysResponse, error) {
	return nil, nil
}

// BarrierGenerateRootToken generates a root token.
func (m *mockService) BarrierGenerateRootToken(_ context.Context, _ *BarrierGenerateRootTokenRequest) (*BarrierRootTokenResponse, error) {
	return nil, nil
}

// PIN operations
func (m *mockService) SetSOPIN(ctx context.Context, req *SetSOPINRequest) error {
	return nil
}

func (m *mockService) SetUserPIN(ctx context.Context, req *SetUserPINRequest) error {
	return nil
}

func (m *mockService) ChangeSOPIN(ctx context.Context, req *ChangeSOPINRequest) error {
	return nil
}

func (m *mockService) ChangeUserPIN(ctx context.Context, req *ChangeUserPINRequest) error {
	return nil
}

func (m *mockService) VerifySOPIN(ctx context.Context, req *VerifySOPINRequest) error {
	return nil
}

func (m *mockService) VerifyUserPIN(ctx context.Context, req *VerifyUserPINRequest) error {
	return nil
}

func (m *mockService) GetLockoutStatus(ctx context.Context) (*LockoutStatusResponse, error) {
	return nil, nil
}

func (m *mockService) ResetLockout(ctx context.Context, req *ResetLockoutRequest) error {
	return nil
}

func (m *mockService) CreateCustodianGroup(ctx context.Context, req *CreateCustodianGroupRequest) (*CreateCustodianGroupResponse, error) {
	return nil, nil
}

func (m *mockService) GetCustodianGroup(ctx context.Context, groupID string) (*GetCustodianGroupResponse, error) {
	return nil, nil
}

func (m *mockService) ListCustodianGroups(ctx context.Context) (*ListCustodianGroupsResponse, error) {
	return nil, nil
}

func (m *mockService) DeleteCustodianGroup(ctx context.Context, groupID string) error {
	return nil
}

func (m *mockService) AddCustodianMember(ctx context.Context, req *AddCustodianMemberRequest) (*AddCustodianMemberResponse, error) {
	return nil, nil
}

func (m *mockService) RemoveCustodianMember(ctx context.Context, req *RemoveCustodianMemberRequest) error {
	return nil
}

func (m *mockService) DistributeShares(ctx context.Context, req *DistributeSharesRequest) (*DistributeSharesResponse, error) {
	return nil, nil
}

func (m *mockService) SubmitShare(ctx context.Context, req *SubmitShareRequest) (*SubmitShareResponse, error) {
	return nil, nil
}

func (m *mockService) ListShares(ctx context.Context) (*ListSharesResponse, error) {
	return nil, nil
}

func (m *mockService) GetShareCollectionStatus(ctx context.Context, groupID string) (*ShareCollectionStatus, error) {
	return nil, nil
}

func (m *mockService) CreateTenant(ctx context.Context, req *CreateTenantRequest) (*CreateTenantResponse, error) {
	return nil, nil
}

func (m *mockService) GetTenant(ctx context.Context, tenantID string) (*GetTenantResponse, error) {
	return nil, nil
}

func (m *mockService) ListTenants(ctx context.Context) (*ListTenantsResponse, error) {
	return nil, nil
}

func (m *mockService) DeleteTenant(ctx context.Context, tenantID string) error {
	return nil
}

func (m *mockService) TenantBarrierInit(ctx context.Context, req *TenantBarrierInitRequest) error {
	return nil
}

func (m *mockService) TenantBarrierUnseal(ctx context.Context, req *TenantBarrierUnsealRequest) error {
	return nil
}

// InitCeremonyService methods

func (m *mockService) GetInitStatus(ctx context.Context) (*InitStatusResponse, error) {
	return nil, nil
}

func (m *mockService) ClaimCertBegin(ctx context.Context, req *ClaimCertBeginRequest) (*ClaimCertBeginResponse, error) {
	return nil, nil
}

func (m *mockService) ClaimCertComplete(ctx context.Context, req *ClaimCertCompleteRequest) (*ClaimCertCompleteResponse, error) {
	return nil, nil
}

func (m *mockService) ClaimShare(ctx context.Context, req *ClaimShareRequest) (*ClaimShareResponse, error) {
	return nil, nil
}

func (m *mockService) SignCSRInit(ctx context.Context, req *SignCSRInitRequest) (*SignCSRInitResponse, error) {
	return nil, nil
}

// CredentialManagementService methods

func (m *mockService) SubmitCredential(ctx context.Context, req *CredentialSubmitRequest) (*CredentialSubmitResponse, error) {
	return nil, nil
}

func (m *mockService) GetCredentialStrategy(ctx context.Context) (*CredentialStrategyResponse, error) {
	return nil, nil
}
