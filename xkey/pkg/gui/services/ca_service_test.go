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

package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errMockCA is a sentinel error for mock CA client failures.
var errMockCA = errors.New("mock CA error")

// mockCAClient implements the transport.Client interface for CA service tests.
// Only the CA-related methods are implemented; all others return nil/error.
type mockCAClient struct {
	getCACertificateResp  *transport.GetCACertificateResponse
	getCACertificateErr   error
	issueCertificateResp  *transport.IssueCertificateResponse
	issueCertificateErr   error
	signCSRResp           *transport.SignCSRResponse
	signCSRErr            error
	revokeCertificateResp *transport.RevokeCertificateResponse
	revokeCertificateErr  error
	generateCRLResp       *transport.GenerateCRLResponse
	generateCRLErr        error
	isRevokedResp         *transport.IsRevokedResponse
	isRevokedErr          error
	getCABundleResp       *transport.GetCABundleResponse
	getCABundleErr        error
}

func (m *mockCAClient) Connect(_ context.Context) error { return nil }
func (m *mockCAClient) Close() error                    { return nil }
func (m *mockCAClient) Health(_ context.Context) (*transport.HealthResponse, error) {
	return nil, nil
}
func (m *mockCAClient) ListBackends(_ context.Context, _ ...transport.ListOption) (*transport.ListBackendsResponse, error) {
	return nil, nil
}
func (m *mockCAClient) GetBackend(_ context.Context, _ string) (*transport.BackendInfo, error) {
	return nil, nil
}
func (m *mockCAClient) GenerateKey(_ context.Context, _ *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	return nil, nil
}
func (m *mockCAClient) ListKeys(_ context.Context, _ string, _ ...transport.ListOption) (*transport.ListKeysResponse, error) {
	return nil, nil
}
func (m *mockCAClient) GetKey(_ context.Context, _, _ string) (*transport.GetKeyResponse, error) {
	return nil, nil
}
func (m *mockCAClient) DeleteKey(_ context.Context, _, _ string) (*transport.DeleteKeyResponse, error) {
	return nil, nil
}
func (m *mockCAClient) Sign(_ context.Context, _ *transport.SignRequest) (*transport.SignResponse, error) {
	return nil, nil
}
func (m *mockCAClient) Verify(_ context.Context, _ *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	return nil, nil
}
func (m *mockCAClient) Encrypt(_ context.Context, _ *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	return nil, nil
}
func (m *mockCAClient) Decrypt(_ context.Context, _ *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	return nil, nil
}
func (m *mockCAClient) EncryptAsym(_ context.Context, _ *transport.EncryptAsymRequest) (*transport.EncryptAsymResponse, error) {
	return nil, nil
}
func (m *mockCAClient) DeriveKey(_ context.Context, _ *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	return nil, nil
}
func (m *mockCAClient) GetCertificate(_ context.Context, _, _ string) (*transport.GetCertificateResponse, error) {
	return nil, nil
}
func (m *mockCAClient) SaveCertificate(_ context.Context, _ *transport.SaveCertificateRequest) error {
	return nil
}
func (m *mockCAClient) DeleteCertificate(_ context.Context, _, _ string) error { return nil }
func (m *mockCAClient) CertificateExists(_ context.Context, _, _ string) (bool, error) {
	return false, nil
}
func (m *mockCAClient) ImportKey(_ context.Context, _ *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	return nil, nil
}
func (m *mockCAClient) ExportKey(_ context.Context, _ *transport.ExportKeyRequest) (*transport.ExportKeyResponse, error) {
	return nil, nil
}
func (m *mockCAClient) RotateKey(_ context.Context, _ *transport.RotateKeyRequest) (*transport.RotateKeyResponse, error) {
	return nil, nil
}
func (m *mockCAClient) GetImportParameters(_ context.Context, _ *transport.GetImportParametersRequest) (*transport.GetImportParametersResponse, error) {
	return nil, nil
}
func (m *mockCAClient) WrapKey(_ context.Context, _ *transport.WrapKeyRequest) (*transport.WrapKeyResponse, error) {
	return nil, nil
}
func (m *mockCAClient) UnwrapKey(_ context.Context, _ *transport.UnwrapKeyRequest) (*transport.UnwrapKeyResponse, error) {
	return nil, nil
}
func (m *mockCAClient) WrapKeyByID(_ context.Context, _ *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	return nil, nil
}
func (m *mockCAClient) UnwrapKeyByID(_ context.Context, _ *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	return nil, nil
}
func (m *mockCAClient) ExportKeyMaterial(_ context.Context, _ *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	return nil, nil
}
func (m *mockCAClient) DeriveKeyECDH(_ context.Context, _ *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	return nil, nil
}
func (m *mockCAClient) CopyKey(_ context.Context, _ *transport.CopyKeyRequest) (*transport.CopyKeyResponse, error) {
	return nil, nil
}
func (m *mockCAClient) ListCertificates(_ context.Context, _ string, _ ...transport.ListOption) (*transport.ListCertificatesResponse, error) {
	return nil, nil
}
func (m *mockCAClient) SaveCertificateChain(_ context.Context, _ *transport.SaveCertificateChainRequest) error {
	return nil
}
func (m *mockCAClient) GetCertificateChain(_ context.Context, _, _ string) (*transport.GetCertificateChainResponse, error) {
	return nil, nil
}
func (m *mockCAClient) GetTLSCertificate(_ context.Context, _, _ string) (*transport.GetTLSCertificateResponse, error) {
	return nil, nil
}
func (m *mockCAClient) Seal(_ context.Context, _ *transport.SealRequest) (*transport.SealResponse, error) {
	return nil, nil
}
func (m *mockCAClient) Unseal(_ context.Context, _ *transport.UnsealRequest) (*transport.UnsealResponse, error) {
	return nil, nil
}
func (m *mockCAClient) CanSeal(_ context.Context, _ string) (*transport.CanSealResponse, error) {
	return nil, nil
}
func (m *mockCAClient) AttestKey(_ context.Context, _ *transport.AttestKeyRequest) (*transport.AttestKeyResponse, error) {
	return nil, nil
}
func (m *mockCAClient) ListUsers(_ context.Context, _ ...transport.ListOption) (*transport.ListUsersResponse, error) {
	return nil, nil
}
func (m *mockCAClient) GetUser(_ context.Context, _ string) (*transport.GetUserResponse, error) {
	return nil, nil
}
func (m *mockCAClient) DeleteUser(_ context.Context, _ string) error  { return nil }
func (m *mockCAClient) EnableUser(_ context.Context, _ string) error  { return nil }
func (m *mockCAClient) DisableUser(_ context.Context, _ string) error { return nil }
func (m *mockCAClient) ListUserCredentials(_ context.Context, _ string) (*transport.ListUserCredentialsResponse, error) {
	return nil, nil
}
func (m *mockCAClient) BeginRegistration(_ context.Context, _ *transport.BeginRegistrationRequest) (*transport.BeginRegistrationResponse, error) {
	return nil, nil
}
func (m *mockCAClient) FinishRegistration(_ context.Context, _ *transport.FinishRegistrationRequest) (*transport.FinishRegistrationResponse, error) {
	return nil, nil
}
func (m *mockCAClient) BeginAuthentication(_ context.Context, _ *transport.BeginAuthenticationRequest) (*transport.BeginAuthenticationResponse, error) {
	return nil, nil
}
func (m *mockCAClient) FinishAuthentication(_ context.Context, _ *transport.FinishAuthenticationRequest) (*transport.FinishAuthenticationResponse, error) {
	return nil, nil
}

// CA-specific methods that the mock implements.
func (m *mockCAClient) GetCABundle(_ context.Context, _ *transport.GetCABundleRequest) (*transport.GetCABundleResponse, error) {
	return m.getCABundleResp, m.getCABundleErr
}
func (m *mockCAClient) GetCACertificate(_ context.Context, _ *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error) {
	return m.getCACertificateResp, m.getCACertificateErr
}
func (m *mockCAClient) SignCSR(_ context.Context, _ *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	return m.signCSRResp, m.signCSRErr
}
func (m *mockCAClient) IssueCertificate(_ context.Context, _ *transport.IssueCertificateRequest) (*transport.IssueCertificateResponse, error) {
	return m.issueCertificateResp, m.issueCertificateErr
}
func (m *mockCAClient) RevokeCertificate(_ context.Context, _ *transport.RevokeCertificateRequest) (*transport.RevokeCertificateResponse, error) {
	return m.revokeCertificateResp, m.revokeCertificateErr
}
func (m *mockCAClient) GenerateCRL(_ context.Context, _ *transport.GenerateCRLRequest) (*transport.GenerateCRLResponse, error) {
	return m.generateCRLResp, m.generateCRLErr
}
func (m *mockCAClient) IsRevoked(_ context.Context, _ *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error) {
	return m.isRevokedResp, m.isRevokedErr
}

// PIV method stubs for transport.Client interface compliance.
func (m *mockCAClient) ListPIVSlots(_ context.Context, _ *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	return nil, nil
}
func (m *mockCAClient) GetPIVCertificate(_ context.Context, _ *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return nil, nil
}
func (m *mockCAClient) StorePIVCertificate(_ context.Context, _ *transport.StorePIVCertificateRequest) error {
	return nil
}
func (m *mockCAClient) DeletePIVCertificate(_ context.Context, _ *transport.DeletePIVCertificateRequest) error {
	return nil
}
func (m *mockCAClient) GeneratePIVKey(_ context.Context, _ *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	return nil, nil
}
func (m *mockCAClient) ImportPIVCertificate(_ context.Context, _ *transport.StorePIVCertificateRequest) error {
	return nil
}
func (m *mockCAClient) ExportPIVCertificate(_ context.Context, _ *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return nil, nil
}
func (m *mockCAClient) GeneratePIVCSR(_ context.Context, _ *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	return nil, nil
}

// Barrier operations stub implementations
func (m *mockCAClient) BarrierInitialize(_ context.Context, _ *transport.BarrierInitializeRequest) error {
	return nil
}
func (m *mockCAClient) BarrierUnseal(_ context.Context, _ *transport.BarrierUnsealRequest) error {
	return nil
}
func (m *mockCAClient) BarrierSeal(_ context.Context) error {
	return nil
}
func (m *mockCAClient) BarrierStatus(_ context.Context) (*transport.BarrierStatusResponse, error) {
	return nil, nil
}
func (m *mockCAClient) BarrierInitializeShamir(_ context.Context, _ *transport.BarrierInitializeShamirRequest) (*transport.BarrierInitializeShamirResponse, error) {
	return nil, nil
}
func (m *mockCAClient) BarrierUnsealWithShare(_ context.Context, _ *transport.BarrierUnsealShareRequest) (*transport.BarrierUnsealShareResponse, error) {
	return nil, nil
}
func (m *mockCAClient) BarrierUnsealWithShares(_ context.Context, _ *transport.BarrierUnsealSharesRequest) error {
	return nil
}

// BarrierShamirListShares returns Shamir share metadata.
func (m *mockCAClient) BarrierShamirListShares(_ context.Context) (*transport.BarrierShamirSharesResponse, error) {
	return nil, nil
}

// BarrierShamirDeleteShare deletes a Shamir share by index.
func (m *mockCAClient) BarrierShamirDeleteShare(_ context.Context, _ *transport.BarrierShamirDeleteShareRequest) error {
	return nil
}

// BarrierShamirDeleteAllShares deletes all Shamir shares.
func (m *mockCAClient) BarrierShamirDeleteAllShares(_ context.Context) error {
	return nil
}

// BarrierShamirVerify verifies Shamir share integrity.
func (m *mockCAClient) BarrierShamirVerify(_ context.Context) error {
	return nil
}

// BarrierRekey re-encrypts the barrier with a new root key.
func (m *mockCAClient) BarrierRekey(_ context.Context, _ *transport.BarrierRekeyRequest) (*transport.BarrierRekeyResponse, error) {
	return nil, nil
}

// BarrierGenerateRecoveryKeys generates recovery keys.
func (m *mockCAClient) BarrierGenerateRecoveryKeys(_ context.Context, _ *transport.BarrierGenerateRecoveryKeysRequest) (*transport.BarrierRecoveryKeysResponse, error) {
	return nil, nil
}

// BarrierRecoverWithKeys recovers the barrier using recovery keys.
func (m *mockCAClient) BarrierRecoverWithKeys(_ context.Context, _ *transport.BarrierRecoverWithKeysRequest) error {
	return nil
}

// BarrierDeleteRecoveryKeys deletes all recovery keys.
func (m *mockCAClient) BarrierDeleteRecoveryKeys(_ context.Context) error {
	return nil
}

// BarrierHasRecoveryKeys checks if recovery keys exist.
func (m *mockCAClient) BarrierHasRecoveryKeys(_ context.Context) (*transport.BarrierHasRecoveryKeysResponse, error) {
	return nil, nil
}

// BarrierGenerateRootToken generates a root token.
func (m *mockCAClient) BarrierGenerateRootToken(_ context.Context, _ *transport.BarrierGenerateRootTokenRequest) (*transport.BarrierRootTokenResponse, error) {
	return nil, nil
}

// PIN operations stub implementations
func (m *mockCAClient) SetSOPIN(_ context.Context, _ *transport.SetSOPINRequest) error {
	return nil
}
func (m *mockCAClient) SetUserPIN(_ context.Context, _ *transport.SetUserPINRequest) error {
	return nil
}
func (m *mockCAClient) ChangeSOPIN(_ context.Context, _ *transport.ChangeSOPINRequest) error {
	return nil
}
func (m *mockCAClient) ChangeUserPIN(_ context.Context, _ *transport.ChangeUserPINRequest) error {
	return nil
}
func (m *mockCAClient) VerifySOPIN(_ context.Context, _ *transport.VerifySOPINRequest) error {
	return nil
}
func (m *mockCAClient) VerifyUserPIN(_ context.Context, _ *transport.VerifyUserPINRequest) error {
	return nil
}
func (m *mockCAClient) GetLockoutStatus(_ context.Context) (*transport.LockoutStatusResponse, error) {
	return nil, nil
}
func (m *mockCAClient) ResetLockout(_ context.Context, _ *transport.ResetLockoutRequest) error {
	return nil
}

// TCGCAService stub implementations
func (m *mockCAClient) IssueEKCertificate(_ context.Context, _ *transport.IssueEKCertificateRequest) (*transport.IssueEKCertificateResponse, error) {
	return nil, nil
}
func (m *mockCAClient) IssueAKCertificate(_ context.Context, _ *transport.IssueAKCertificateRequest) (*transport.IssueAKCertificateResponse, error) {
	return nil, nil
}
func (m *mockCAClient) SignTCGCSR(_ context.Context, _ *transport.SignTCGCSRRequest) (*transport.SignTCGCSRResponse, error) {
	return nil, nil
}
func (m *mockCAClient) EnrollDevice(_ context.Context, _ *transport.EnrollDeviceRequest) (*transport.EnrollDeviceResponse, error) {
	return nil, nil
}

// generateTestCertPEM creates a self-signed ECDSA P-256 certificate and returns
// the PEM-encoded certificate bytes.
func generateTestCertPEM(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		Issuer: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
}

// generateTestLeafCertPEM creates a leaf certificate signed by a test CA.
func generateTestLeafCertPEM(t *testing.T) (certPEM []byte, serial string) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafSerial := big.NewInt(12345)
	leafTmpl := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	leafPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafDER,
	})

	return leafPEM, leafSerial.String()
}

// Compile-time check that mockCAClient satisfies the Client interface.
var _ transport.Client = (*mockCAClient)(nil)

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

func TestNewCAService(t *testing.T) {
	mock := &mockCAClient{}
	svc := NewCAService(mock)
	require.NotNil(t, svc)
	assert.Equal(t, mock, svc.client)
}

func TestNewCAService_NilClient(t *testing.T) {
	svc := NewCAService(nil)
	require.NotNil(t, svc)
	assert.Nil(t, svc.client)
}

// ---------------------------------------------------------------------------
// GetCAInfo
// ---------------------------------------------------------------------------

func TestCAService_GetCAInfo_Success(t *testing.T) {
	certPEM := generateTestCertPEM(t)
	mock := &mockCAClient{
		getCACertificateResp: &transport.GetCACertificateResponse{
			CertificatePEM: certPEM,
			Subject:        "CN=Test CA,O=Test Org",
			Issuer:         "CN=Test CA,O=Test Org",
			SerialNumber:   "42",
			IsCA:           true,
		},
	}
	svc := NewCAService(mock)

	info, err := svc.GetCAInfo()
	require.NoError(t, err)
	require.NotNil(t, info)

	assert.Contains(t, info.Subject, "Test CA")
	assert.Contains(t, info.Issuer, "Test CA")
	assert.Equal(t, "42", info.Serial)
	assert.Equal(t, "ECDSA", info.Algorithm)
	assert.True(t, info.IsCA)
	assert.NotEmpty(t, info.NotBefore)
	assert.NotEmpty(t, info.NotAfter)
}

func TestCAService_GetCAInfo_FallbackOnInvalidPEM(t *testing.T) {
	mock := &mockCAClient{
		getCACertificateResp: &transport.GetCACertificateResponse{
			CertificatePEM: []byte("not-valid-pem"),
			Subject:        "CN=Fallback CA",
			Issuer:         "CN=Root CA",
			SerialNumber:   "99",
			NotBefore:      "2025-01-01T00:00:00Z",
			NotAfter:       "2026-01-01T00:00:00Z",
			IsCA:           true,
		},
	}
	svc := NewCAService(mock)

	info, err := svc.GetCAInfo()
	require.NoError(t, err)
	require.NotNil(t, info)

	assert.Equal(t, "CN=Fallback CA", info.Subject)
	assert.Equal(t, "CN=Root CA", info.Issuer)
	assert.Equal(t, "99", info.Serial)
	assert.True(t, info.IsCA)
	assert.Empty(t, info.Algorithm) // No parsed cert, so no algorithm
}

func TestCAService_GetCAInfo_NilClient(t *testing.T) {
	svc := NewCAService(nil)
	_, err := svc.GetCAInfo()
	assert.ErrorIs(t, err, ErrCAServiceNilClient)
}

func TestCAService_GetCAInfo_ClientError(t *testing.T) {
	mock := &mockCAClient{
		getCACertificateErr: errMockCA,
	}
	svc := NewCAService(mock)

	_, err := svc.GetCAInfo()
	assert.ErrorIs(t, err, errMockCA)
}

// ---------------------------------------------------------------------------
// IssueCertificate
// ---------------------------------------------------------------------------

func TestCAService_IssueCertificate_Success(t *testing.T) {
	leafPEM, serial := generateTestLeafCertPEM(t)
	chainPEM := generateTestCertPEM(t)

	mock := &mockCAClient{
		issueCertificateResp: &transport.IssueCertificateResponse{
			CertificatePEM: leafPEM,
			ChainPEM:       chainPEM,
			PrivateKeyPEM:  []byte("-----BEGIN EC PRIVATE KEY-----\nfake\n-----END EC PRIVATE KEY-----\n"),
			SerialNumber:   serial,
		},
	}
	svc := NewCAService(mock)

	info, err := svc.IssueCertificate("server", "test.example.com", "Test Org", "DNS:test.example.com, IP:127.0.0.1", 365, "ecdsa-p256")
	require.NoError(t, err)
	require.NotNil(t, info)

	assert.Equal(t, serial, info.Serial)
	assert.Contains(t, info.Subject, "test.example.com")
	assert.Equal(t, "ECDSA", info.Algorithm)
	assert.NotEmpty(t, info.CertificatePEM)
	assert.NotEmpty(t, info.ChainPEM)
	assert.NotEmpty(t, info.PrivateKeyPEM)
	assert.NotEmpty(t, info.NotBefore)
	assert.NotEmpty(t, info.NotAfter)
}

func TestCAService_IssueCertificate_WithSANsParsing(t *testing.T) {
	leafPEM, serial := generateTestLeafCertPEM(t)
	mock := &mockCAClient{
		issueCertificateResp: &transport.IssueCertificateResponse{
			CertificatePEM: leafPEM,
			SerialNumber:   serial,
		},
	}
	svc := NewCAService(mock)

	info, err := svc.IssueCertificate("server", "test.example.com", "", " DNS:a.com , DNS:b.com , ", 0, "")
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Equal(t, serial, info.Serial)
}

func TestCAService_IssueCertificate_EmptySANs(t *testing.T) {
	leafPEM, serial := generateTestLeafCertPEM(t)
	mock := &mockCAClient{
		issueCertificateResp: &transport.IssueCertificateResponse{
			CertificatePEM: leafPEM,
			SerialNumber:   serial,
		},
	}
	svc := NewCAService(mock)

	info, err := svc.IssueCertificate("client", "user@example.com", "", "", 365, "")
	require.NoError(t, err)
	require.NotNil(t, info)
}

func TestCAService_IssueCertificate_NilClient(t *testing.T) {
	svc := NewCAService(nil)
	_, err := svc.IssueCertificate("server", "test.example.com", "", "", 365, "")
	assert.ErrorIs(t, err, ErrCAServiceNilClient)
}

func TestCAService_IssueCertificate_EmptyCommonName(t *testing.T) {
	mock := &mockCAClient{}
	svc := NewCAService(mock)
	_, err := svc.IssueCertificate("server", "", "Org", "", 365, "")
	assert.ErrorIs(t, err, ErrCAServiceInvalidCommonName)
}

func TestCAService_IssueCertificate_ClientError(t *testing.T) {
	mock := &mockCAClient{
		issueCertificateErr: errMockCA,
	}
	svc := NewCAService(mock)

	_, err := svc.IssueCertificate("server", "test.example.com", "", "", 365, "")
	assert.ErrorIs(t, err, errMockCA)
}

// ---------------------------------------------------------------------------
// SignCSR
// ---------------------------------------------------------------------------

func TestCAService_SignCSR_Success(t *testing.T) {
	leafPEM, serial := generateTestLeafCertPEM(t)

	mock := &mockCAClient{
		signCSRResp: &transport.SignCSRResponse{
			CertificatePEM: leafPEM,
			ChainPEM:       generateTestCertPEM(t),
			SerialNumber:   serial,
		},
	}
	svc := NewCAService(mock)

	info, err := svc.SignCSR("-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----\n", "server")
	require.NoError(t, err)
	require.NotNil(t, info)

	assert.Equal(t, serial, info.Serial)
	assert.Contains(t, info.Subject, "test.example.com")
	assert.NotEmpty(t, info.CertificatePEM)
	assert.NotEmpty(t, info.ChainPEM)
}

func TestCAService_SignCSR_NilClient(t *testing.T) {
	svc := NewCAService(nil)
	_, err := svc.SignCSR("pem-data", "server")
	assert.ErrorIs(t, err, ErrCAServiceNilClient)
}

func TestCAService_SignCSR_EmptyCSR(t *testing.T) {
	mock := &mockCAClient{}
	svc := NewCAService(mock)
	_, err := svc.SignCSR("", "server")
	assert.ErrorIs(t, err, ErrCAServiceInvalidCSR)
}

func TestCAService_SignCSR_WhitespaceCSR(t *testing.T) {
	mock := &mockCAClient{}
	svc := NewCAService(mock)
	_, err := svc.SignCSR("   \n\t  ", "server")
	assert.ErrorIs(t, err, ErrCAServiceInvalidCSR)
}

func TestCAService_SignCSR_ClientError(t *testing.T) {
	mock := &mockCAClient{
		signCSRErr: errMockCA,
	}
	svc := NewCAService(mock)

	_, err := svc.SignCSR("-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----\n", "server")
	assert.ErrorIs(t, err, errMockCA)
}

// ---------------------------------------------------------------------------
// RevokeCertificate
// ---------------------------------------------------------------------------

func TestCAService_RevokeCertificate_Success(t *testing.T) {
	mock := &mockCAClient{
		revokeCertificateResp: &transport.RevokeCertificateResponse{
			Success: true,
		},
	}
	svc := NewCAService(mock)

	err := svc.RevokeCertificate("12345", 1)
	require.NoError(t, err)
}

func TestCAService_RevokeCertificate_NilClient(t *testing.T) {
	svc := NewCAService(nil)
	err := svc.RevokeCertificate("12345", 1)
	assert.ErrorIs(t, err, ErrCAServiceNilClient)
}

func TestCAService_RevokeCertificate_EmptySerial(t *testing.T) {
	mock := &mockCAClient{}
	svc := NewCAService(mock)
	err := svc.RevokeCertificate("", 1)
	assert.ErrorIs(t, err, ErrCAServiceInvalidSerial)
}

func TestCAService_RevokeCertificate_ClientError(t *testing.T) {
	mock := &mockCAClient{
		revokeCertificateErr: errMockCA,
	}
	svc := NewCAService(mock)

	err := svc.RevokeCertificate("12345", 1)
	assert.ErrorIs(t, err, errMockCA)
}

// ---------------------------------------------------------------------------
// GenerateCRL
// ---------------------------------------------------------------------------

func TestCAService_GenerateCRL_Success(t *testing.T) {
	crlPEM := []byte("-----BEGIN X509 CRL-----\nfake-crl-data\n-----END X509 CRL-----\n")
	mock := &mockCAClient{
		generateCRLResp: &transport.GenerateCRLResponse{
			CRLPEM: crlPEM,
		},
	}
	svc := NewCAService(mock)

	result, err := svc.GenerateCRL()
	require.NoError(t, err)
	assert.Equal(t, string(crlPEM), result)
}

func TestCAService_GenerateCRL_NilClient(t *testing.T) {
	svc := NewCAService(nil)
	_, err := svc.GenerateCRL()
	assert.ErrorIs(t, err, ErrCAServiceNilClient)
}

func TestCAService_GenerateCRL_ClientError(t *testing.T) {
	mock := &mockCAClient{
		generateCRLErr: errMockCA,
	}
	svc := NewCAService(mock)

	_, err := svc.GenerateCRL()
	assert.ErrorIs(t, err, errMockCA)
}

// ---------------------------------------------------------------------------
// IsRevoked
// ---------------------------------------------------------------------------

func TestCAService_IsRevoked_True(t *testing.T) {
	mock := &mockCAClient{
		isRevokedResp: &transport.IsRevokedResponse{
			Revoked: true,
			Reason:  1,
		},
	}
	svc := NewCAService(mock)

	revoked, err := svc.IsRevoked("12345")
	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestCAService_IsRevoked_False(t *testing.T) {
	mock := &mockCAClient{
		isRevokedResp: &transport.IsRevokedResponse{
			Revoked: false,
		},
	}
	svc := NewCAService(mock)

	revoked, err := svc.IsRevoked("12345")
	require.NoError(t, err)
	assert.False(t, revoked)
}

func TestCAService_IsRevoked_NilClient(t *testing.T) {
	svc := NewCAService(nil)
	_, err := svc.IsRevoked("12345")
	assert.ErrorIs(t, err, ErrCAServiceNilClient)
}

func TestCAService_IsRevoked_EmptySerial(t *testing.T) {
	mock := &mockCAClient{}
	svc := NewCAService(mock)
	_, err := svc.IsRevoked("")
	assert.ErrorIs(t, err, ErrCAServiceInvalidSerial)
}

func TestCAService_IsRevoked_ClientError(t *testing.T) {
	mock := &mockCAClient{
		isRevokedErr: errMockCA,
	}
	svc := NewCAService(mock)

	_, err := svc.IsRevoked("12345")
	assert.ErrorIs(t, err, errMockCA)
}

// ---------------------------------------------------------------------------
// GetCABundle
// ---------------------------------------------------------------------------

func TestCAService_GetCABundle_Success(t *testing.T) {
	bundlePEM := generateTestCertPEM(t)
	mock := &mockCAClient{
		getCABundleResp: &transport.GetCABundleResponse{
			BundlePEM: bundlePEM,
		},
	}
	svc := NewCAService(mock)

	result, err := svc.GetCABundle("software", "ECDSA")
	require.NoError(t, err)
	assert.Equal(t, string(bundlePEM), result)
}

func TestCAService_GetCABundle_EmptyFilters(t *testing.T) {
	bundlePEM := generateTestCertPEM(t)
	mock := &mockCAClient{
		getCABundleResp: &transport.GetCABundleResponse{
			BundlePEM: bundlePEM,
		},
	}
	svc := NewCAService(mock)

	result, err := svc.GetCABundle("", "")
	require.NoError(t, err)
	assert.NotEmpty(t, result)
}

func TestCAService_GetCABundle_NilClient(t *testing.T) {
	svc := NewCAService(nil)
	_, err := svc.GetCABundle("", "")
	assert.ErrorIs(t, err, ErrCAServiceNilClient)
}

func TestCAService_GetCABundle_ClientError(t *testing.T) {
	mock := &mockCAClient{
		getCABundleErr: errMockCA,
	}
	svc := NewCAService(mock)

	_, err := svc.GetCABundle("software", "RSA")
	assert.ErrorIs(t, err, errMockCA)
}

// ---------------------------------------------------------------------------
// parsePEMCertificate
// ---------------------------------------------------------------------------

func TestParsePEMCertificate_Valid(t *testing.T) {
	certPEM := generateTestCertPEM(t)
	cert, err := parsePEMCertificate(certPEM)
	require.NoError(t, err)
	assert.Equal(t, "Test CA", cert.Subject.CommonName)
	assert.True(t, cert.IsCA)
}

func TestParsePEMCertificate_InvalidPEM(t *testing.T) {
	_, err := parsePEMCertificate([]byte("not pem data"))
	assert.ErrorIs(t, err, ErrCAServiceInvalidPEM)
}

func TestParsePEMCertificate_InvalidDER(t *testing.T) {
	badPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("not valid DER"),
	})
	_, err := parsePEMCertificate(badPEM)
	assert.Error(t, err)
}

func TestParsePEMCertificate_EmptyInput(t *testing.T) {
	_, err := parsePEMCertificate(nil)
	assert.ErrorIs(t, err, ErrCAServiceInvalidPEM)
}

// ---------------------------------------------------------------------------
// parseSANs
// ---------------------------------------------------------------------------

func TestParseSANs_CommaSeparated(t *testing.T) {
	result := parseSANs("DNS:a.com, DNS:b.com, IP:127.0.0.1")
	assert.Equal(t, []string{"DNS:a.com", "DNS:b.com", "IP:127.0.0.1"}, result)
}

func TestParseSANs_WithWhitespace(t *testing.T) {
	result := parseSANs("  DNS:a.com , DNS:b.com  ")
	assert.Equal(t, []string{"DNS:a.com", "DNS:b.com"}, result)
}

func TestParseSANs_Empty(t *testing.T) {
	assert.Nil(t, parseSANs(""))
}

func TestParseSANs_OnlyCommas(t *testing.T) {
	assert.Nil(t, parseSANs(",,,"))
}

func TestParseSANs_SingleEntry(t *testing.T) {
	result := parseSANs("DNS:test.example.com")
	assert.Equal(t, []string{"DNS:test.example.com"}, result)
}

func TestParseSANs_TrailingComma(t *testing.T) {
	result := parseSANs("DNS:a.com,")
	assert.Equal(t, []string{"DNS:a.com"}, result)
}

// Password operations stub implementations

func (m *mockCAClient) PasswordAdd(_ context.Context, _ *transport.PasswordAddRequest) (*transport.PasswordAddResponse, error) {
	return nil, nil
}

func (m *mockCAClient) PasswordGet(_ context.Context, _ *transport.PasswordGetRequest) (*transport.PasswordGetResponse, error) {
	return nil, nil
}

func (m *mockCAClient) PasswordList(_ context.Context, _ *transport.PasswordListRequest) (*transport.PasswordListResponse, error) {
	return nil, nil
}

func (m *mockCAClient) PasswordUpdate(_ context.Context, _ *transport.PasswordUpdateRequest) error {
	return nil
}

func (m *mockCAClient) PasswordDelete(_ context.Context, _ *transport.PasswordDeleteRequest) error {
	return nil
}

func (m *mockCAClient) PasswordStoreUnlock(_ context.Context, _ *transport.PasswordStoreUnlockRequest) error {
	return nil
}

func (m *mockCAClient) PasswordStoreLock(_ context.Context) error {
	return nil
}

func (m *mockCAClient) PasswordStoreStatus(_ context.Context) (*transport.PasswordStoreStatusResponse, error) {
	return nil, nil
}

func (m *mockCAClient) PasswordStoreSetAccessMode(_ context.Context, _ *transport.PasswordStoreSetAccessModeRequest) error {
	return nil
}

func (m *mockCAClient) PasswordGenerate(_ context.Context, _ *transport.PasswordGenerateRequest) (*transport.PasswordGenerateResponse, error) {
	return nil, nil
}

// PlatformStore operations stub implementations

func (m *mockCAClient) SealStorePut(_ context.Context, _ *transport.SealStorePutRequest) error {
	return nil
}

func (m *mockCAClient) SealStoreGet(_ context.Context, _ *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error) {
	return nil, nil
}

func (m *mockCAClient) SealStoreDelete(_ context.Context, _ *transport.SealStoreDeleteRequest) error {
	return nil
}

func (m *mockCAClient) SealStoreList(_ context.Context) (*transport.SealStoreListResponse, error) {
	return nil, nil
}

func (m *mockCAClient) SealStoreReseal(_ context.Context, _ *transport.SealStoreResealRequest) error {
	return nil
}

func (m *mockCAClient) SealStoreStatus(_ context.Context) (*transport.SealStoreStatusResponse, error) {
	return nil, nil
}

// Policy operations stub implementations

func (m *mockCAClient) PolicyCreate(_ context.Context, _ *transport.PolicyCreateRequest) (*transport.PolicyCreateResponse, error) {
	return nil, nil
}

func (m *mockCAClient) PolicyGet(_ context.Context, _ *transport.PolicyGetRequest) (*transport.PolicyGetResponse, error) {
	return nil, nil
}

func (m *mockCAClient) PolicyList(_ context.Context) (*transport.PolicyListResponse, error) {
	return nil, nil
}

func (m *mockCAClient) PolicyDelete(_ context.Context, _ *transport.PolicyDeleteRequest) error {
	return nil
}

func (m *mockCAClient) PolicyRefresh(_ context.Context, _ *transport.PolicyRefreshRequest) (*transport.PolicyGetResponse, error) {
	return nil, nil
}

func (m *mockCAClient) PolicyVerify(_ context.Context, _ *transport.PolicyVerifyRequest) (*transport.PolicyVerifyResponse, error) {
	return nil, nil
}

func (m *mockCAClient) PolicyExport(_ context.Context, _ *transport.PolicyExportRequest) (*transport.PolicyExportResponse, error) {
	return nil, nil
}

func (m *mockCAClient) CreateCustodianGroup(_ context.Context, _ *transport.CreateCustodianGroupRequest) (*transport.CreateCustodianGroupResponse, error) {
	return nil, nil
}
func (m *mockCAClient) GetCustodianGroup(_ context.Context, _ string) (*transport.GetCustodianGroupResponse, error) {
	return nil, nil
}
func (m *mockCAClient) ListCustodianGroups(_ context.Context) (*transport.ListCustodianGroupsResponse, error) {
	return nil, nil
}
func (m *mockCAClient) DeleteCustodianGroup(_ context.Context, _ string) error { return nil }
func (m *mockCAClient) AddCustodianMember(_ context.Context, _ *transport.AddCustodianMemberRequest) (*transport.AddCustodianMemberResponse, error) {
	return nil, nil
}
func (m *mockCAClient) RemoveCustodianMember(_ context.Context, _ *transport.RemoveCustodianMemberRequest) error {
	return nil
}
func (m *mockCAClient) DistributeShares(_ context.Context, _ *transport.DistributeSharesRequest) (*transport.DistributeSharesResponse, error) {
	return nil, nil
}
func (m *mockCAClient) SubmitShare(_ context.Context, _ *transport.SubmitShareRequest) (*transport.SubmitShareResponse, error) {
	return nil, nil
}
func (m *mockCAClient) ListShares(_ context.Context) (*transport.ListSharesResponse, error) {
	return nil, nil
}
func (m *mockCAClient) GetShareCollectionStatus(_ context.Context, _ string) (*transport.ShareCollectionStatus, error) {
	return nil, nil
}
func (m *mockCAClient) CreateTenant(_ context.Context, _ *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error) {
	return nil, nil
}
func (m *mockCAClient) GetTenant(_ context.Context, _ string) (*transport.GetTenantResponse, error) {
	return nil, nil
}
func (m *mockCAClient) ListTenants(_ context.Context) (*transport.ListTenantsResponse, error) {
	return nil, nil
}
func (m *mockCAClient) DeleteTenant(_ context.Context, _ string) error { return nil }
func (m *mockCAClient) TenantBarrierInit(_ context.Context, _ *transport.TenantBarrierInitRequest) error {
	return nil
}
func (m *mockCAClient) TenantBarrierUnseal(_ context.Context, _ *transport.TenantBarrierUnsealRequest) error {
	return nil
}

// InitCeremonyService stub implementations
func (m *mockCAClient) GetInitStatus(_ context.Context) (*transport.InitStatusResponse, error) {
	return nil, nil
}
func (m *mockCAClient) ClaimCertBegin(_ context.Context, _ *transport.ClaimCertBeginRequest) (*transport.ClaimCertBeginResponse, error) {
	return nil, nil
}
func (m *mockCAClient) ClaimCertComplete(_ context.Context, _ *transport.ClaimCertCompleteRequest) (*transport.ClaimCertCompleteResponse, error) {
	return nil, nil
}
func (m *mockCAClient) ClaimShare(_ context.Context, _ *transport.ClaimShareRequest) (*transport.ClaimShareResponse, error) {
	return nil, nil
}
func (m *mockCAClient) SignCSRInit(_ context.Context, _ *transport.SignCSRInitRequest) (*transport.SignCSRInitResponse, error) {
	return nil, nil
}

// CredentialManagementService stub implementations
func (m *mockCAClient) SubmitCredential(_ context.Context, _ *transport.CredentialSubmitRequest) (*transport.CredentialSubmitResponse, error) {
	return nil, nil
}
func (m *mockCAClient) GetCredentialStrategy(_ context.Context) (*transport.CredentialStrategyResponse, error) {
	return nil, nil
}
