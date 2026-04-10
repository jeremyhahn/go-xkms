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

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	pivcertfile "github.com/jeremyhahn/go-xkms/pkg/pivcert/file"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backendregistry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPIVClient implements transport.Client with configurable PIV method responses.
// Non-PIV methods return errMockNotImplemented.
type mockPIVClient struct {
	listPIVSlotsResp *transport.ListPIVSlotsResponse
	listPIVSlotsErr  error

	getPIVCertResp *transport.GetPIVCertificateResponse
	getPIVCertErr  error

	storePIVCertErr error

	deletePIVCertErr error

	generatePIVKeyResp *transport.GeneratePIVKeyResponse
	generatePIVKeyErr  error

	importPIVCertErr error

	exportPIVCertResp *transport.GetPIVCertificateResponse
	exportPIVCertErr  error

	generatePIVCSRResp *transport.GeneratePIVCSRResponse
	generatePIVCSRErr  error
}

var errMockNotImplemented = errors.New("mock: not implemented")

func (m *mockPIVClient) Connect(_ context.Context) error { return errMockNotImplemented }
func (m *mockPIVClient) Close() error                    { return errMockNotImplemented }
func (m *mockPIVClient) Health(_ context.Context) (*transport.HealthResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) ListBackends(_ context.Context, _ ...transport.ListOption) (*transport.ListBackendsResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) GetBackend(_ context.Context, _ string) (*transport.BackendInfo, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) GenerateKey(_ context.Context, _ *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) ListKeys(_ context.Context, _ string, _ ...transport.ListOption) (*transport.ListKeysResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) GetKey(_ context.Context, _, _ string) (*transport.GetKeyResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) DeleteKey(_ context.Context, _, _ string) (*transport.DeleteKeyResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) Sign(_ context.Context, _ *transport.SignRequest) (*transport.SignResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) Verify(_ context.Context, _ *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) Encrypt(_ context.Context, _ *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) Decrypt(_ context.Context, _ *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) EncryptAsym(_ context.Context, _ *transport.EncryptAsymRequest) (*transport.EncryptAsymResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) DeriveKey(_ context.Context, _ *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) GetCertificate(_ context.Context, _, _ string) (*transport.GetCertificateResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) SaveCertificate(_ context.Context, _ *transport.SaveCertificateRequest) error {
	return errMockNotImplemented
}
func (m *mockPIVClient) DeleteCertificate(_ context.Context, _, _ string) error {
	return errMockNotImplemented
}
func (m *mockPIVClient) CertificateExists(_ context.Context, _, _ string) (bool, error) {
	return false, errMockNotImplemented
}
func (m *mockPIVClient) ImportKey(_ context.Context, _ *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) ExportKey(_ context.Context, _ *transport.ExportKeyRequest) (*transport.ExportKeyResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) RotateKey(_ context.Context, _ *transport.RotateKeyRequest) (*transport.RotateKeyResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) GetImportParameters(_ context.Context, _ *transport.GetImportParametersRequest) (*transport.GetImportParametersResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) WrapKey(_ context.Context, _ *transport.WrapKeyRequest) (*transport.WrapKeyResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) UnwrapKey(_ context.Context, _ *transport.UnwrapKeyRequest) (*transport.UnwrapKeyResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) WrapKeyByID(_ context.Context, _ *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) UnwrapKeyByID(_ context.Context, _ *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) ExportKeyMaterial(_ context.Context, _ *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) DeriveKeyECDH(_ context.Context, _ *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) CopyKey(_ context.Context, _ *transport.CopyKeyRequest) (*transport.CopyKeyResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) ListCertificates(_ context.Context, _ string, _ ...transport.ListOption) (*transport.ListCertificatesResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) SaveCertificateChain(_ context.Context, _ *transport.SaveCertificateChainRequest) error {
	return errMockNotImplemented
}
func (m *mockPIVClient) GetCertificateChain(_ context.Context, _, _ string) (*transport.GetCertificateChainResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) GetTLSCertificate(_ context.Context, _, _ string) (*transport.GetTLSCertificateResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) Seal(_ context.Context, _ *transport.SealRequest) (*transport.SealResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) Unseal(_ context.Context, _ *transport.UnsealRequest) (*transport.UnsealResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) CanSeal(_ context.Context, _ string) (*transport.CanSealResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) AttestKey(_ context.Context, _ *transport.AttestKeyRequest) (*transport.AttestKeyResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) ListUsers(_ context.Context, _ ...transport.ListOption) (*transport.ListUsersResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) GetUser(_ context.Context, _ string) (*transport.GetUserResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) DeleteUser(_ context.Context, _ string) error {
	return errMockNotImplemented
}
func (m *mockPIVClient) EnableUser(_ context.Context, _ string) error {
	return errMockNotImplemented
}
func (m *mockPIVClient) DisableUser(_ context.Context, _ string) error {
	return errMockNotImplemented
}
func (m *mockPIVClient) ListUserCredentials(_ context.Context, _ string) (*transport.ListUserCredentialsResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) BeginRegistration(_ context.Context, _ *transport.BeginRegistrationRequest) (*transport.BeginRegistrationResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) FinishRegistration(_ context.Context, _ *transport.FinishRegistrationRequest) (*transport.FinishRegistrationResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) BeginAuthentication(_ context.Context, _ *transport.BeginAuthenticationRequest) (*transport.BeginAuthenticationResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) FinishAuthentication(_ context.Context, _ *transport.FinishAuthenticationRequest) (*transport.FinishAuthenticationResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) GetCABundle(_ context.Context, _ *transport.GetCABundleRequest) (*transport.GetCABundleResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) GetCACertificate(_ context.Context, _ *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) SignCSR(_ context.Context, _ *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) IssueCertificate(_ context.Context, _ *transport.IssueCertificateRequest) (*transport.IssueCertificateResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) RevokeCertificate(_ context.Context, _ *transport.RevokeCertificateRequest) (*transport.RevokeCertificateResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) GenerateCRL(_ context.Context, _ *transport.GenerateCRLRequest) (*transport.GenerateCRLResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) IsRevoked(_ context.Context, _ *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error) {
	return nil, errMockNotImplemented
}

// TCGCAService stub implementations
func (m *mockPIVClient) IssueEKCertificate(_ context.Context, _ *transport.IssueEKCertificateRequest) (*transport.IssueEKCertificateResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) IssueAKCertificate(_ context.Context, _ *transport.IssueAKCertificateRequest) (*transport.IssueAKCertificateResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) SignTCGCSR(_ context.Context, _ *transport.SignTCGCSRRequest) (*transport.SignTCGCSRResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) EnrollDevice(_ context.Context, _ *transport.EnrollDeviceRequest) (*transport.EnrollDeviceResponse, error) {
	return nil, errMockNotImplemented
}

// PIV method implementations with configurable responses.

func (m *mockPIVClient) ListPIVSlots(_ context.Context, _ *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	return m.listPIVSlotsResp, m.listPIVSlotsErr
}

func (m *mockPIVClient) GetPIVCertificate(_ context.Context, _ *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return m.getPIVCertResp, m.getPIVCertErr
}

func (m *mockPIVClient) StorePIVCertificate(_ context.Context, _ *transport.StorePIVCertificateRequest) error {
	return m.storePIVCertErr
}

func (m *mockPIVClient) DeletePIVCertificate(_ context.Context, _ *transport.DeletePIVCertificateRequest) error {
	return m.deletePIVCertErr
}

func (m *mockPIVClient) GeneratePIVKey(_ context.Context, _ *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	return m.generatePIVKeyResp, m.generatePIVKeyErr
}

func (m *mockPIVClient) ImportPIVCertificate(_ context.Context, _ *transport.StorePIVCertificateRequest) error {
	return m.importPIVCertErr
}

func (m *mockPIVClient) ExportPIVCertificate(_ context.Context, _ *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return m.exportPIVCertResp, m.exportPIVCertErr
}

func (m *mockPIVClient) GeneratePIVCSR(_ context.Context, _ *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	return m.generatePIVCSRResp, m.generatePIVCSRErr
}

// Barrier operations stub implementations
func (m *mockPIVClient) BarrierInitialize(_ context.Context, _ *transport.BarrierInitializeRequest) error {
	return errMockNotImplemented
}
func (m *mockPIVClient) BarrierUnseal(_ context.Context, _ *transport.BarrierUnsealRequest) error {
	return errMockNotImplemented
}
func (m *mockPIVClient) BarrierSeal(_ context.Context) error {
	return errMockNotImplemented
}
func (m *mockPIVClient) BarrierStatus(_ context.Context) (*transport.BarrierStatusResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) BarrierInitializeShamir(_ context.Context, _ *transport.BarrierInitializeShamirRequest) (*transport.BarrierInitializeShamirResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) BarrierUnsealWithShare(_ context.Context, _ *transport.BarrierUnsealShareRequest) (*transport.BarrierUnsealShareResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) BarrierUnsealWithShares(_ context.Context, _ *transport.BarrierUnsealSharesRequest) error {
	return errMockNotImplemented
}
func (m *mockPIVClient) BarrierShamirListShares(_ context.Context) (*transport.BarrierShamirSharesResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) BarrierShamirDeleteShare(_ context.Context, _ *transport.BarrierShamirDeleteShareRequest) error {
	return errMockNotImplemented
}
func (m *mockPIVClient) BarrierShamirDeleteAllShares(_ context.Context) error {
	return errMockNotImplemented
}
func (m *mockPIVClient) BarrierShamirVerify(_ context.Context) error {
	return errMockNotImplemented
}
func (m *mockPIVClient) BarrierRekey(_ context.Context, _ *transport.BarrierRekeyRequest) (*transport.BarrierRekeyResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) BarrierGenerateRecoveryKeys(_ context.Context, _ *transport.BarrierGenerateRecoveryKeysRequest) (*transport.BarrierRecoveryKeysResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) BarrierRecoverWithKeys(_ context.Context, _ *transport.BarrierRecoverWithKeysRequest) error {
	return errMockNotImplemented
}
func (m *mockPIVClient) BarrierDeleteRecoveryKeys(_ context.Context) error {
	return errMockNotImplemented
}
func (m *mockPIVClient) BarrierHasRecoveryKeys(_ context.Context) (*transport.BarrierHasRecoveryKeysResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) BarrierGenerateRootToken(_ context.Context, _ *transport.BarrierGenerateRootTokenRequest) (*transport.BarrierRootTokenResponse, error) {
	return nil, errMockNotImplemented
}

// PIN operations stub implementations
func (m *mockPIVClient) SetSOPIN(_ context.Context, _ *transport.SetSOPINRequest) error {
	return errMockNotImplemented
}
func (m *mockPIVClient) SetUserPIN(_ context.Context, _ *transport.SetUserPINRequest) error {
	return errMockNotImplemented
}
func (m *mockPIVClient) ChangeSOPIN(_ context.Context, _ *transport.ChangeSOPINRequest) error {
	return errMockNotImplemented
}
func (m *mockPIVClient) ChangeUserPIN(_ context.Context, _ *transport.ChangeUserPINRequest) error {
	return errMockNotImplemented
}
func (m *mockPIVClient) VerifySOPIN(_ context.Context, _ *transport.VerifySOPINRequest) error {
	return errMockNotImplemented
}
func (m *mockPIVClient) VerifyUserPIN(_ context.Context, _ *transport.VerifyUserPINRequest) error {
	return errMockNotImplemented
}
func (m *mockPIVClient) GetLockoutStatus(_ context.Context) (*transport.LockoutStatusResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) ResetLockout(_ context.Context, _ *transport.ResetLockoutRequest) error {
	return errMockNotImplemented
}

// generatePIVCertPEM creates a self-signed ECDSA P-256 certificate PEM for testing.
func generatePIVCertPEM(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
}

// initTestPIVManager sets up the PIV manager singleton with an in-memory
// storage backend for unit testing. It registers a cleanup to reset the
// singleton after the test completes.
func initTestPIVManager(t *testing.T) {
	t.Helper()
	xkms.ResetPIV()

	memBackend := storage.NewMemory()
	pivStore, err := pivcertfile.NewFileBackend(&pivcert.FileStorageConfig{
		Backend:    memBackend,
		DEREnabled: true,
		PEMEnabled: true,
	})
	require.NoError(t, err)

	err = xkms.InitializePIV(&xkms.PIVManagerConfig{
		Stores: map[string]pivcert.PIVCertificateStorage{
			"software": pivStore,
		},
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		xkms.ResetPIV()
	})
}

// Compile-time check that mockPIVClient satisfies the Client interface.
var _ transport.Client = (*mockPIVClient)(nil)

// --- Constructor and SetContext ---

func TestNewPIVService(t *testing.T) {
	svc := NewPIVService(nil, "")
	assert.NotNil(t, svc)
	assert.Nil(t, svc.client)
	assert.Equal(t, "", svc.backend)
	assert.Equal(t, "software", svc.localBackend)
}

func TestNewPIVService_WithParams(t *testing.T) {
	client := &mockPIVClient{}
	svc := NewPIVService(client, "software")
	assert.NotNil(t, svc)
	assert.Equal(t, "software", svc.backend)
}

func TestPIVService_SetContext(t *testing.T) {
	svc := NewPIVService(nil, "")
	svc.SetContext(context.Background())
	assert.NotNil(t, svc.ctx)
}

func TestPIVService_SetClient(t *testing.T) {
	svc := NewPIVService(nil, "")
	assert.Nil(t, svc.client)

	client := &mockPIVClient{}
	svc.SetClient(client)
	assert.NotNil(t, svc.client)
}

func TestPIVService_SetLocalEnabled(t *testing.T) {
	svc := NewPIVService(nil, "")
	assert.False(t, svc.localEnabled)
	svc.SetLocalEnabled(true)
	assert.True(t, svc.localEnabled)
}

func TestPIVService_SetLocalBackend(t *testing.T) {
	svc := NewPIVService(nil, "")
	assert.Equal(t, "software", svc.localBackend)
	svc.SetLocalBackend("tpm2")
	assert.Equal(t, "tpm2", svc.localBackend)
}

// --- SetBackend ---

func TestPIVService_SetBackend_UpdatesBothBackends(t *testing.T) {
	svc := NewPIVService(nil, "software")
	svc.SetBackend("tpm2")
	assert.Equal(t, "tpm2", svc.backend)
	assert.Equal(t, "tpm2", svc.localBackend)
}

func TestPIVService_SetBackend_NotifiesCCID(t *testing.T) {
	svc := NewPIVService(nil, "software")

	var notified string
	svc.SetCCIDNotifier(func(backend string) {
		notified = backend
	})

	svc.SetBackend("pkcs11")
	assert.Equal(t, "pkcs11", notified)
}

func TestPIVService_SetBackend_NilNotifier(t *testing.T) {
	svc := NewPIVService(nil, "software")
	// No notifier set — should not panic.
	svc.SetBackend("tpm2")
	assert.Equal(t, "tpm2", svc.backend)
}

// --- IsConnected ---

func TestPIVService_IsConnected_NilClient_NoLocal(t *testing.T) {
	svc := NewPIVService(nil, "software")
	assert.False(t, svc.IsConnected())
}

func TestPIVService_IsConnected_WithClient(t *testing.T) {
	svc := NewPIVService(&mockPIVClient{}, "software")
	assert.True(t, svc.IsConnected())
}

func TestPIVService_IsConnected_LocalEnabled(t *testing.T) {
	svc := NewPIVService(nil, "software")
	svc.SetLocalEnabled(true)
	assert.True(t, svc.IsConnected())
}

func TestPIVService_IsConnected_AfterSetClient(t *testing.T) {
	svc := NewPIVService(nil, "software")
	assert.False(t, svc.IsConnected())
	svc.SetClient(&mockPIVClient{})
	assert.True(t, svc.IsConnected())
	svc.SetClient(nil)
	assert.False(t, svc.IsConnected())
}

// --- GetSlots ---

func TestPIVService_GetSlots_NilClient_NoLocal(t *testing.T) {
	svc := NewPIVService(nil, "")
	slots, err := svc.GetSlots()
	require.NoError(t, err)
	assert.Len(t, slots, 5)
	assert.Equal(t, "9a", slots[0].Slot)
	assert.Equal(t, "PIV Authentication", slots[0].Name)
	assert.False(t, slots[0].HasCert)
}

func TestPIVService_GetSlots_Success(t *testing.T) {
	client := &mockPIVClient{
		listPIVSlotsResp: &transport.ListPIVSlotsResponse{
			Slots: []transport.PIVSlotStatus{
				{
					Slot:        "9a",
					Name:        "PIV Authentication",
					HasCert:     true,
					Subject:     "CN=PIV Authentication",
					Algorithm:   "ECDSA",
					KeySize:     256,
					NotAfter:    "2026-01-01T00:00:00Z",
					Fingerprint: "abcdef",
				},
			},
		},
	}
	svc := NewPIVService(client, "software")
	svc.SetContext(context.Background())

	slots, err := svc.GetSlots()
	require.NoError(t, err)
	assert.Len(t, slots, 5)

	// Slot 9a should have cert info.
	assert.True(t, slots[0].HasCert)
	assert.Equal(t, "CN=PIV Authentication", slots[0].Subject)
	assert.Equal(t, "ECDSA", slots[0].Algorithm)
	assert.Equal(t, 256, slots[0].KeySize)
	assert.Equal(t, "abcdef", slots[0].Fingerprint)

	// Other slots should have no cert.
	assert.False(t, slots[1].HasCert)
	assert.False(t, slots[2].HasCert)
	assert.False(t, slots[3].HasCert)
}

func TestPIVService_GetSlots_ListError(t *testing.T) {
	client := &mockPIVClient{
		listPIVSlotsErr: errors.New("list failed"),
	}
	svc := NewPIVService(client, "software")
	svc.SetContext(context.Background())

	_, err := svc.GetSlots()
	assert.Error(t, err)
}

// --- GetCertificate ---

func TestPIVService_GetCertificate_EmptySlot(t *testing.T) {
	svc := NewPIVService(nil, "")
	_, err := svc.GetCertificate("")
	assert.True(t, errors.Is(err, ErrPIVInvalidSlot))
}

func TestPIVService_GetCertificate_NilClient_NoLocal(t *testing.T) {
	svc := NewPIVService(nil, "")
	_, err := svc.GetCertificate("9a")
	assert.True(t, errors.Is(err, ErrPIVClientNotSet))
}

func TestPIVService_GetCertificate_NoCert(t *testing.T) {
	client := &mockPIVClient{
		getPIVCertErr: errors.New("not found"),
	}
	svc := NewPIVService(client, "software")
	svc.SetContext(context.Background())

	_, err := svc.GetCertificate("9a")
	assert.True(t, errors.Is(err, ErrPIVNoCertificate))
}

func TestPIVService_GetCertificate_InvalidPEM(t *testing.T) {
	client := &mockPIVClient{
		getPIVCertResp: &transport.GetPIVCertificateResponse{
			Slot:        "9a",
			Certificate: []byte("not valid PEM"),
			Format:      "pem",
		},
	}
	svc := NewPIVService(client, "software")
	svc.SetContext(context.Background())

	_, err := svc.GetCertificate("9a")
	assert.True(t, errors.Is(err, ErrPIVNoCertificate))
}

func TestPIVService_GetCertificate_InvalidDER(t *testing.T) {
	// Valid PEM envelope but garbage DER bytes inside.
	badPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("garbage DER content"),
	})
	client := &mockPIVClient{
		getPIVCertResp: &transport.GetPIVCertificateResponse{
			Slot:        "9a",
			Certificate: badPEM,
			Format:      "pem",
		},
	}
	svc := NewPIVService(client, "software")
	svc.SetContext(context.Background())

	_, err := svc.GetCertificate("9a")
	assert.True(t, errors.Is(err, ErrPIVNoCertificate))
}

func TestPIVService_GetCertificate_Success(t *testing.T) {
	certPEM := generatePIVCertPEM(t, "PIV Authentication")
	client := &mockPIVClient{
		getPIVCertResp: &transport.GetPIVCertificateResponse{
			Slot:        "9a",
			Certificate: certPEM,
			Format:      "pem",
		},
	}
	svc := NewPIVService(client, "software")
	svc.SetContext(context.Background())

	cert, err := svc.GetCertificate("9A") // uppercase should be normalized
	require.NoError(t, err)
	assert.Equal(t, "9a", cert.Slot)
	assert.Contains(t, cert.Subject, "PIV Authentication")
	assert.Equal(t, "ECDSA", cert.Algorithm)
	assert.NotEmpty(t, cert.PEM)
	assert.NotEmpty(t, cert.Fingerprint)
	assert.NotEmpty(t, cert.SerialNumber)
}

// --- GenerateKey: validation errors ---

func TestPIVService_GenerateKey_EmptySlot(t *testing.T) {
	svc := NewPIVService(nil, "")
	result, err := svc.GenerateKey("", "ECCP256")
	assert.Nil(t, result)
	assert.True(t, errors.Is(err, ErrPIVInvalidSlot))
}

func TestPIVService_GenerateKey_InvalidAlgorithm(t *testing.T) {
	svc := NewPIVService(nil, "")
	result, err := svc.GenerateKey("9a", "INVALID")
	assert.Nil(t, result)
	assert.True(t, errors.Is(err, ErrPIVInvalidAlgorithm))
}

func TestPIVService_GenerateKey_NilClient_NoLocal(t *testing.T) {
	svc := NewPIVService(nil, "")
	result, err := svc.GenerateKey("9a", "ECCP256")
	assert.Nil(t, result)
	assert.True(t, errors.Is(err, ErrPIVClientNotSet))
}

func TestPIVService_GenerateKey_ServerError(t *testing.T) {
	client := &mockPIVClient{
		generatePIVKeyErr: errors.New("server error"),
	}
	svc := NewPIVService(client, "software")
	svc.SetContext(context.Background())

	result, err := svc.GenerateKey("9a", "ECCP256")
	assert.Nil(t, result)
	assert.Error(t, err)
}

func TestPIVService_GenerateKey_Success(t *testing.T) {
	certPEM := generatePIVCertPEM(t, "PIV Authentication")
	client := &mockPIVClient{
		generatePIVKeyResp: &transport.GeneratePIVKeyResponse{
			Slot:        "9a",
			Certificate: certPEM,
			PublicKey:   []byte("public-key-data"),
		},
	}
	svc := NewPIVService(client, "software")
	svc.SetContext(context.Background())

	result, err := svc.GenerateKey("9a", "ECCP256")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "9a", result.Slot)
	assert.Equal(t, "ECCP256", result.Algorithm)
	assert.Contains(t, result.Subject, "PIV Authentication")
	assert.Contains(t, result.Message, "9a")
	assert.Contains(t, result.Message, "ECCP256")
}

func TestPIVService_GenerateKey_UnknownSlotName(t *testing.T) {
	certPEM := generatePIVCertPEM(t, "PIV Key 82")
	client := &mockPIVClient{
		generatePIVKeyResp: &transport.GeneratePIVKeyResponse{
			Slot:        "82",
			Certificate: certPEM,
		},
	}
	svc := NewPIVService(client, "software")
	svc.SetContext(context.Background())

	result, err := svc.GenerateKey("82", "ECCP256")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "82", result.Slot)
	assert.Contains(t, result.Subject, "PIV Key 82")
}

func TestPIVService_GenerateKey_EmptyCertResponse(t *testing.T) {
	// Server returns empty certificate (edge case).
	client := &mockPIVClient{
		generatePIVKeyResp: &transport.GeneratePIVKeyResponse{
			Slot:        "9a",
			Certificate: nil,
		},
	}
	svc := NewPIVService(client, "software")
	svc.SetContext(context.Background())

	result, err := svc.GenerateKey("9a", "ECCP256")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "9a", result.Slot)
	assert.Equal(t, 0, result.KeySize)
	assert.Empty(t, result.Subject)
}

func TestPIVService_GenerateKey_AllAlgorithms(t *testing.T) {
	algorithms := []string{"RSA2048", "RSA4096", "ECCP256", "ECCP384", "Ed25519"}
	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			certPEM := generatePIVCertPEM(t, "PIV Authentication")
			client := &mockPIVClient{
				generatePIVKeyResp: &transport.GeneratePIVKeyResponse{
					Slot:        "9a",
					Certificate: certPEM,
				},
			}
			svc := NewPIVService(client, "software")
			svc.SetContext(context.Background())

			result, err := svc.GenerateKey("9a", alg)
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, alg, result.Algorithm)
		})
	}
}

// --- ImportCertificate ---

func TestPIVService_ImportCertificate_EmptySlot(t *testing.T) {
	svc := NewPIVService(nil, "")
	err := svc.ImportCertificate("", []byte("data"))
	assert.True(t, errors.Is(err, ErrPIVInvalidSlot))
}

func TestPIVService_ImportCertificate_EmptyPEM(t *testing.T) {
	svc := NewPIVService(nil, "")
	err := svc.ImportCertificate("9a", nil)
	assert.True(t, errors.Is(err, ErrPIVInvalidPEM))
}

func TestPIVService_ImportCertificate_NilClient_NoLocal(t *testing.T) {
	svc := NewPIVService(nil, "")
	err := svc.ImportCertificate("9a", []byte("data"))
	assert.True(t, errors.Is(err, ErrPIVClientNotSet))
}

func TestPIVService_ImportCertificate_Success(t *testing.T) {
	client := &mockPIVClient{}
	svc := NewPIVService(client, "software")
	svc.SetContext(context.Background())

	err := svc.ImportCertificate("9a", []byte("cert-data"))
	require.NoError(t, err)
}

func TestPIVService_ImportCertificate_ServerError(t *testing.T) {
	client := &mockPIVClient{
		importPIVCertErr: errors.New("import failed"),
	}
	svc := NewPIVService(client, "software")
	svc.SetContext(context.Background())

	err := svc.ImportCertificate("9a", []byte("cert-data"))
	assert.Error(t, err)
}

// --- ExportCertificate ---

func TestPIVService_ExportCertificate_EmptySlot(t *testing.T) {
	svc := NewPIVService(nil, "")
	_, err := svc.ExportCertificate("")
	assert.True(t, errors.Is(err, ErrPIVInvalidSlot))
}

func TestPIVService_ExportCertificate_NilClient_NoLocal(t *testing.T) {
	svc := NewPIVService(nil, "")
	_, err := svc.ExportCertificate("9a")
	assert.True(t, errors.Is(err, ErrPIVClientNotSet))
}

func TestPIVService_ExportCertificate_NoCert(t *testing.T) {
	client := &mockPIVClient{
		exportPIVCertErr: errors.New("not found"),
	}
	svc := NewPIVService(client, "software")
	svc.SetContext(context.Background())

	_, err := svc.ExportCertificate("9a")
	assert.True(t, errors.Is(err, ErrPIVNoCertificate))
}

func TestPIVService_ExportCertificate_Success(t *testing.T) {
	certPEM := generatePIVCertPEM(t, "PIV Authentication")
	client := &mockPIVClient{
		exportPIVCertResp: &transport.GetPIVCertificateResponse{
			Slot:        "9a",
			Certificate: certPEM,
			Format:      "pem",
		},
	}
	svc := NewPIVService(client, "software")
	svc.SetContext(context.Background())

	data, err := svc.ExportCertificate("9a")
	require.NoError(t, err)
	assert.Equal(t, certPEM, data)
}

// --- GenerateCSR ---

func TestPIVService_GenerateCSR_EmptySlot(t *testing.T) {
	svc := NewPIVService(nil, "")
	_, err := svc.GenerateCSR("", &CSRSubject{CommonName: "test"})
	assert.True(t, errors.Is(err, ErrPIVInvalidSlot))
}

func TestPIVService_GenerateCSR_NilSubject(t *testing.T) {
	svc := NewPIVService(nil, "")
	_, err := svc.GenerateCSR("9a", nil)
	assert.True(t, errors.Is(err, ErrPIVInvalidSubject))
}

func TestPIVService_GenerateCSR_EmptyCommonName(t *testing.T) {
	svc := NewPIVService(nil, "")
	_, err := svc.GenerateCSR("9a", &CSRSubject{})
	assert.True(t, errors.Is(err, ErrPIVInvalidSubject))
}

func TestPIVService_GenerateCSR_NilClient_NoLocal(t *testing.T) {
	svc := NewPIVService(nil, "")
	_, err := svc.GenerateCSR("9a", &CSRSubject{CommonName: "test"})
	assert.True(t, errors.Is(err, ErrPIVClientNotSet))
}

func TestPIVService_GenerateCSR_Success(t *testing.T) {
	csrPEM := []byte("-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----\n")
	client := &mockPIVClient{
		generatePIVCSRResp: &transport.GeneratePIVCSRResponse{
			Slot: "9a",
			CSR:  csrPEM,
		},
	}
	svc := NewPIVService(client, "software")
	svc.SetContext(context.Background())

	data, err := svc.GenerateCSR("9a", &CSRSubject{
		CommonName:   "test.example.com",
		Organization: "Test Org",
	})
	require.NoError(t, err)
	assert.Equal(t, csrPEM, data)
}

func TestPIVService_GenerateCSR_ServerError(t *testing.T) {
	client := &mockPIVClient{
		generatePIVCSRErr: errors.New("csr failed"),
	}
	svc := NewPIVService(client, "software")
	svc.SetContext(context.Background())

	_, err := svc.GenerateCSR("9a", &CSRSubject{CommonName: "test"})
	assert.Error(t, err)
}

// --- DeleteCertificate ---

func TestPIVService_DeleteCertificate_EmptySlot(t *testing.T) {
	svc := NewPIVService(nil, "")
	err := svc.DeleteCertificate("")
	assert.True(t, errors.Is(err, ErrPIVInvalidSlot))
}

func TestPIVService_DeleteCertificate_NilClient_NoLocal(t *testing.T) {
	svc := NewPIVService(nil, "")
	err := svc.DeleteCertificate("9a")
	assert.True(t, errors.Is(err, ErrPIVClientNotSet))
}

func TestPIVService_DeleteCertificate_NoCert(t *testing.T) {
	client := &mockPIVClient{
		deletePIVCertErr: errors.New("not found"),
	}
	svc := NewPIVService(client, "software")
	svc.SetContext(context.Background())

	err := svc.DeleteCertificate("9a")
	assert.True(t, errors.Is(err, ErrPIVNoCertificate))
}

func TestPIVService_DeleteCertificate_Success(t *testing.T) {
	client := &mockPIVClient{}
	svc := NewPIVService(client, "software")
	svc.SetContext(context.Background())

	err := svc.DeleteCertificate("9a")
	require.NoError(t, err)
}

// --- certAlgorithmName ---

func TestCertAlgorithmName(t *testing.T) {
	tests := []struct {
		name string
		algo x509.PublicKeyAlgorithm
		want string
	}{
		{"RSA", x509.RSA, "RSA"},
		{"ECDSA", x509.ECDSA, "ECDSA"},
		{"Ed25519", x509.Ed25519, "Ed25519"},
		{"Unknown", x509.PublicKeyAlgorithm(99), "Unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{PublicKeyAlgorithm: tt.algo}
			assert.Equal(t, tt.want, certAlgorithmName(cert))
		})
	}
}

// --- Sentinel error values ---

func TestPIVServiceErrors(t *testing.T) {
	sentinels := map[string]error{
		"ErrPIVInvalidSlot":      ErrPIVInvalidSlot,
		"ErrPIVInvalidAlgorithm": ErrPIVInvalidAlgorithm,
		"ErrPIVNoCertificate":    ErrPIVNoCertificate,
		"ErrPIVInvalidPEM":       ErrPIVInvalidPEM,
		"ErrPIVInvalidSubject":   ErrPIVInvalidSubject,
		"ErrPIVClientNotSet":     ErrPIVClientNotSet,
		"ErrPIVLocalUnavailable": ErrPIVLocalUnavailable,
	}
	for name, err := range sentinels {
		t.Run(name, func(t *testing.T) {
			assert.NotNil(t, err)
			assert.NotEmpty(t, err.Error())
			assert.Contains(t, err.Error(), "piv_service:")
		})
	}
}

// --- Integration: GenerateKey then GetCertificate ---

func TestPIVService_GenerateKeyThenGetCertificate(t *testing.T) {
	certPEM := generatePIVCertPEM(t, "PIV Authentication")
	client := &mockPIVClient{
		generatePIVKeyResp: &transport.GeneratePIVKeyResponse{
			Slot:        "9a",
			Certificate: certPEM,
		},
		getPIVCertResp: &transport.GetPIVCertificateResponse{
			Slot:        "9a",
			Certificate: certPEM,
			Format:      "pem",
		},
	}
	svc := NewPIVService(client, "software")
	svc.SetContext(context.Background())

	result, err := svc.GenerateKey("9a", "ECCP256")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "9a", result.Slot)

	cert, err := svc.GetCertificate("9a")
	require.NoError(t, err)
	assert.Equal(t, "9a", cert.Slot)
	assert.Contains(t, cert.Subject, "PIV Authentication")
	assert.Equal(t, "ECDSA", cert.Algorithm)
	assert.NotEmpty(t, cert.PEM)
	assert.NotEmpty(t, cert.Fingerprint)
}

// --- Integration: GetSlots with certificate present ---

func TestPIVService_GetSlots_WithCert(t *testing.T) {
	client := &mockPIVClient{
		listPIVSlotsResp: &transport.ListPIVSlotsResponse{
			Slots: []transport.PIVSlotStatus{
				{
					Slot:    "9a",
					HasCert: true,
					Subject: "CN=PIV Authentication",
				},
			},
		},
	}
	svc := NewPIVService(client, "software")
	svc.SetContext(context.Background())

	slots, err := svc.GetSlots()
	require.NoError(t, err)
	require.Len(t, slots, 5)

	assert.True(t, slots[0].HasCert)
	assert.False(t, slots[1].HasCert)
	assert.False(t, slots[2].HasCert)
	assert.False(t, slots[3].HasCert)
}

// --- Local PIV operation tests ---

func TestPIVService_LocalGetSlots(t *testing.T) {
	initTestPIVManager(t)

	svc := NewPIVService(nil, "software")
	svc.SetLocalEnabled(true)
	svc.SetContext(context.Background())

	slots, err := svc.GetSlots()
	require.NoError(t, err)
	assert.Len(t, slots, 5)
	assert.Equal(t, "9a", slots[0].Slot)
	assert.Equal(t, "PIV Authentication", slots[0].Name)
	// No certificates stored yet.
	for _, slot := range slots {
		assert.False(t, slot.HasCert)
	}
}

func TestPIVService_LocalGenerateKey(t *testing.T) {
	initTestPIVManager(t)

	svc := NewPIVService(nil, "software")
	svc.SetLocalEnabled(true)
	svc.SetContext(context.Background())

	result, err := svc.GenerateKey("9a", "ECCP256")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "9a", result.Slot)
	assert.Equal(t, "ECCP256", result.Algorithm)
	assert.NotEmpty(t, result.Subject)
	assert.Contains(t, result.Message, "9a")
	assert.Contains(t, result.Message, "ECCP256")
	assert.Greater(t, result.KeySize, 0)
}

func TestPIVService_LocalGenerateKey_InvalidAlgorithm(t *testing.T) {
	initTestPIVManager(t)

	svc := NewPIVService(nil, "software")
	svc.SetLocalEnabled(true)
	svc.SetContext(context.Background())

	result, err := svc.GenerateKey("9a", "INVALID")
	assert.Nil(t, result)
	assert.True(t, errors.Is(err, ErrPIVInvalidAlgorithm))
}

func TestPIVService_LocalGetCertificate_NoCert(t *testing.T) {
	initTestPIVManager(t)

	svc := NewPIVService(nil, "software")
	svc.SetLocalEnabled(true)
	svc.SetContext(context.Background())

	_, err := svc.GetCertificate("9a")
	assert.True(t, errors.Is(err, ErrPIVNoCertificate))
}

func TestPIVService_LocalGenerateKeyThenGetCertificate(t *testing.T) {
	initTestPIVManager(t)

	svc := NewPIVService(nil, "software")
	svc.SetLocalEnabled(true)
	svc.SetContext(context.Background())

	// Generate key in slot 9a.
	result, err := svc.GenerateKey("9a", "ECCP256")
	require.NoError(t, err)
	require.NotNil(t, result)

	// Retrieve the certificate from slot 9a.
	cert, err := svc.GetCertificate("9a")
	require.NoError(t, err)
	assert.Equal(t, "9a", cert.Slot)
	assert.Equal(t, "ECDSA", cert.Algorithm)
	assert.NotEmpty(t, cert.PEM)
	assert.NotEmpty(t, cert.Fingerprint)
	assert.NotEmpty(t, cert.Subject)
}

func TestPIVService_LocalExportCertificate(t *testing.T) {
	initTestPIVManager(t)

	svc := NewPIVService(nil, "software")
	svc.SetLocalEnabled(true)
	svc.SetContext(context.Background())

	// Generate a key first.
	_, err := svc.GenerateKey("9c", "ECCP256")
	require.NoError(t, err)

	// Export the certificate.
	data, err := svc.ExportCertificate("9c")
	require.NoError(t, err)
	assert.NotEmpty(t, data)
	assert.Contains(t, string(data), "BEGIN CERTIFICATE")
}

func TestPIVService_LocalExportCertificate_NoCert(t *testing.T) {
	initTestPIVManager(t)

	svc := NewPIVService(nil, "software")
	svc.SetLocalEnabled(true)
	svc.SetContext(context.Background())

	_, err := svc.ExportCertificate("9d")
	assert.True(t, errors.Is(err, ErrPIVNoCertificate))
}

func TestPIVService_LocalDeleteCertificate(t *testing.T) {
	initTestPIVManager(t)

	svc := NewPIVService(nil, "software")
	svc.SetLocalEnabled(true)
	svc.SetContext(context.Background())

	// Generate a key first.
	_, err := svc.GenerateKey("9a", "ECCP256")
	require.NoError(t, err)

	// Delete the certificate.
	err = svc.DeleteCertificate("9a")
	require.NoError(t, err)

	// Verify it is gone.
	_, err = svc.GetCertificate("9a")
	assert.True(t, errors.Is(err, ErrPIVNoCertificate))
}

func TestPIVService_LocalDeleteCertificate_NoCert(t *testing.T) {
	initTestPIVManager(t)

	svc := NewPIVService(nil, "software")
	svc.SetLocalEnabled(true)
	svc.SetContext(context.Background())

	err := svc.DeleteCertificate("9a")
	assert.True(t, errors.Is(err, ErrPIVNoCertificate))
}

func TestPIVService_LocalGenerateCSR(t *testing.T) {
	initTestPIVManager(t)

	svc := NewPIVService(nil, "software")
	svc.SetLocalEnabled(true)
	svc.SetContext(context.Background())

	// Generate a key first so a signer exists for CSR generation.
	// Set a persistent resolver so the same generator (and its signer map)
	// is used for both GenerateKey and GenerateCSR.
	gen := xkms.NewSoftwarePIVKeyGenerator()
	err := xkms.SetPIVBackendResolver(func(_ string) (xkms.PIVKeyGenerator, error) {
		return gen, nil
	})
	require.NoError(t, err)

	_, err = svc.GenerateKey("9a", "ECCP256")
	require.NoError(t, err)

	data, err := svc.GenerateCSR("9a", &CSRSubject{CommonName: "test.local"})
	require.NoError(t, err)
	assert.NotEmpty(t, data)
	assert.Contains(t, string(data), "BEGIN CERTIFICATE REQUEST")
}

func TestPIVService_LocalImportCertificate(t *testing.T) {
	initTestPIVManager(t)

	svc := NewPIVService(nil, "software")
	svc.SetLocalEnabled(true)
	svc.SetContext(context.Background())

	certPEM := generatePIVCertPEM(t, "imported cert")
	err := svc.ImportCertificate("9e", certPEM)
	require.NoError(t, err)

	// Verify we can retrieve it.
	cert, err := svc.GetCertificate("9e")
	require.NoError(t, err)
	assert.Equal(t, "9e", cert.Slot)
	assert.Contains(t, cert.Subject, "imported cert")
}

func TestPIVService_RemoteOverridesLocal(t *testing.T) {
	initTestPIVManager(t)

	// Set up a remote client that returns specific data.
	client := &mockPIVClient{
		listPIVSlotsResp: &transport.ListPIVSlotsResponse{
			Slots: []transport.PIVSlotStatus{
				{
					Slot:    "9a",
					HasCert: true,
					Subject: "CN=Remote PIV",
				},
			},
		},
	}

	svc := NewPIVService(client, "software")
	svc.SetLocalEnabled(true)
	svc.SetContext(context.Background())

	// Even though local is enabled, remote client takes precedence.
	slots, err := svc.GetSlots()
	require.NoError(t, err)
	assert.Len(t, slots, 5)
	assert.True(t, slots[0].HasCert)
	assert.Equal(t, "CN=Remote PIV", slots[0].Subject)
}

func TestPIVService_FallbackToLocal(t *testing.T) {
	initTestPIVManager(t)

	// Start with a remote client.
	client := &mockPIVClient{
		listPIVSlotsResp: &transport.ListPIVSlotsResponse{
			Slots: []transport.PIVSlotStatus{
				{Slot: "9a", HasCert: true, Subject: "CN=Remote"},
			},
		},
	}

	svc := NewPIVService(client, "software")
	svc.SetLocalEnabled(true)
	svc.SetContext(context.Background())

	// Generate a local key for later verification.
	svc.SetClient(nil) // temporarily go local
	_, err := svc.GenerateKey("9a", "ECCP256")
	require.NoError(t, err)

	// Restore client - remote should be used.
	svc.SetClient(client)
	slots, err := svc.GetSlots()
	require.NoError(t, err)
	assert.Equal(t, "CN=Remote", slots[0].Subject)

	// Remove client - should fall back to local.
	svc.SetClient(nil)
	slots, err = svc.GetSlots()
	require.NoError(t, err)
	assert.True(t, slots[0].HasCert)
	assert.NotEqual(t, "CN=Remote", slots[0].Subject)
}

func TestPIVService_LocalGetSlots_DegradedMode(t *testing.T) {
	// Do NOT initialize the PIV manager - simulates degraded mode.
	xkms.ResetPIV()
	t.Cleanup(func() { xkms.ResetPIV() })

	svc := NewPIVService(nil, "software")
	svc.SetLocalEnabled(true)
	svc.SetContext(context.Background())

	// Should return empty slots without error in degraded mode.
	slots, err := svc.GetSlots()
	require.NoError(t, err)
	assert.Len(t, slots, 5)
	for _, slot := range slots {
		assert.False(t, slot.HasCert)
	}
}

// --- Algorithm name mapping ---

func TestAlgorithmToLocalName(t *testing.T) {
	expected := map[string]string{
		"RSA2048": "rsa2048",
		"RSA4096": "rsa4096",
		"ECCP256": "ecdsap256",
		"ECCP384": "ecdsap384",
		"Ed25519": "ed25519",
	}
	for gui, local := range expected {
		t.Run(gui, func(t *testing.T) {
			got, ok := algorithmToLocalName[gui]
			assert.True(t, ok)
			assert.Equal(t, local, got)
		})
	}

	// Unknown algorithm should not be present.
	_, ok := algorithmToLocalName["INVALID"]
	assert.False(t, ok)
}

// Password operations stub implementations for mockPIVClient

func (m *mockPIVClient) PasswordAdd(_ context.Context, _ *transport.PasswordAddRequest) (*transport.PasswordAddResponse, error) {
	return nil, errMockNotImplemented
}

func (m *mockPIVClient) PasswordGet(_ context.Context, _ *transport.PasswordGetRequest) (*transport.PasswordGetResponse, error) {
	return nil, errMockNotImplemented
}

func (m *mockPIVClient) PasswordList(_ context.Context, _ *transport.PasswordListRequest) (*transport.PasswordListResponse, error) {
	return nil, errMockNotImplemented
}

func (m *mockPIVClient) PasswordUpdate(_ context.Context, _ *transport.PasswordUpdateRequest) error {
	return errMockNotImplemented
}

func (m *mockPIVClient) PasswordDelete(_ context.Context, _ *transport.PasswordDeleteRequest) error {
	return errMockNotImplemented
}

func (m *mockPIVClient) PasswordStoreUnlock(_ context.Context, _ *transport.PasswordStoreUnlockRequest) error {
	return errMockNotImplemented
}

func (m *mockPIVClient) PasswordStoreLock(_ context.Context) error {
	return errMockNotImplemented
}

func (m *mockPIVClient) PasswordStoreStatus(_ context.Context) (*transport.PasswordStoreStatusResponse, error) {
	return nil, errMockNotImplemented
}

func (m *mockPIVClient) PasswordStoreSetAccessMode(_ context.Context, _ *transport.PasswordStoreSetAccessModeRequest) error {
	return errMockNotImplemented
}

func (m *mockPIVClient) PasswordGenerate(_ context.Context, _ *transport.PasswordGenerateRequest) (*transport.PasswordGenerateResponse, error) {
	return nil, errMockNotImplemented
}

// PlatformStore operations stub implementations for mockPIVClient

func (m *mockPIVClient) SealStorePut(_ context.Context, _ *transport.SealStorePutRequest) error {
	return errMockNotImplemented
}

func (m *mockPIVClient) SealStoreGet(_ context.Context, _ *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error) {
	return nil, errMockNotImplemented
}

func (m *mockPIVClient) SealStoreDelete(_ context.Context, _ *transport.SealStoreDeleteRequest) error {
	return errMockNotImplemented
}

func (m *mockPIVClient) SealStoreList(_ context.Context) (*transport.SealStoreListResponse, error) {
	return nil, errMockNotImplemented
}

func (m *mockPIVClient) SealStoreReseal(_ context.Context, _ *transport.SealStoreResealRequest) error {
	return errMockNotImplemented
}

func (m *mockPIVClient) SealStoreStatus(_ context.Context) (*transport.SealStoreStatusResponse, error) {
	return nil, errMockNotImplemented
}

// Policy operations stub implementations for mockPIVClient

func (m *mockPIVClient) PolicyCreate(_ context.Context, _ *transport.PolicyCreateRequest) (*transport.PolicyCreateResponse, error) {
	return nil, errMockNotImplemented
}

func (m *mockPIVClient) PolicyGet(_ context.Context, _ *transport.PolicyGetRequest) (*transport.PolicyGetResponse, error) {
	return nil, errMockNotImplemented
}

func (m *mockPIVClient) PolicyList(_ context.Context) (*transport.PolicyListResponse, error) {
	return nil, errMockNotImplemented
}

func (m *mockPIVClient) PolicyDelete(_ context.Context, _ *transport.PolicyDeleteRequest) error {
	return errMockNotImplemented
}

func (m *mockPIVClient) PolicyRefresh(_ context.Context, _ *transport.PolicyRefreshRequest) (*transport.PolicyGetResponse, error) {
	return nil, errMockNotImplemented
}

func (m *mockPIVClient) PolicyVerify(_ context.Context, _ *transport.PolicyVerifyRequest) (*transport.PolicyVerifyResponse, error) {
	return nil, errMockNotImplemented
}

func (m *mockPIVClient) PolicyExport(_ context.Context, _ *transport.PolicyExportRequest) (*transport.PolicyExportResponse, error) {
	return nil, errMockNotImplemented
}

func (m *mockPIVClient) CreateCustodianGroup(_ context.Context, _ *transport.CreateCustodianGroupRequest) (*transport.CreateCustodianGroupResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) GetCustodianGroup(_ context.Context, _ string) (*transport.GetCustodianGroupResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) ListCustodianGroups(_ context.Context) (*transport.ListCustodianGroupsResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) DeleteCustodianGroup(_ context.Context, _ string) error {
	return errMockNotImplemented
}
func (m *mockPIVClient) AddCustodianMember(_ context.Context, _ *transport.AddCustodianMemberRequest) (*transport.AddCustodianMemberResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) RemoveCustodianMember(_ context.Context, _ *transport.RemoveCustodianMemberRequest) error {
	return errMockNotImplemented
}
func (m *mockPIVClient) DistributeShares(_ context.Context, _ *transport.DistributeSharesRequest) (*transport.DistributeSharesResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) SubmitShare(_ context.Context, _ *transport.SubmitShareRequest) (*transport.SubmitShareResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) ListShares(_ context.Context) (*transport.ListSharesResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) GetShareCollectionStatus(_ context.Context, _ string) (*transport.ShareCollectionStatus, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) CreateTenant(_ context.Context, _ *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) GetTenant(_ context.Context, _ string) (*transport.GetTenantResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) ListTenants(_ context.Context) (*transport.ListTenantsResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) DeleteTenant(_ context.Context, _ string) error {
	return errMockNotImplemented
}
func (m *mockPIVClient) TenantBarrierInit(_ context.Context, _ *transport.TenantBarrierInitRequest) error {
	return errMockNotImplemented
}
func (m *mockPIVClient) TenantBarrierUnseal(_ context.Context, _ *transport.TenantBarrierUnsealRequest) error {
	return errMockNotImplemented
}

// InitCeremonyService stub implementations
func (m *mockPIVClient) GetInitStatus(_ context.Context) (*transport.InitStatusResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) ClaimCertBegin(_ context.Context, _ *transport.ClaimCertBeginRequest) (*transport.ClaimCertBeginResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) ClaimCertComplete(_ context.Context, _ *transport.ClaimCertCompleteRequest) (*transport.ClaimCertCompleteResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) ClaimShare(_ context.Context, _ *transport.ClaimShareRequest) (*transport.ClaimShareResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) SignCSRInit(_ context.Context, _ *transport.SignCSRInitRequest) (*transport.SignCSRInitResponse, error) {
	return nil, errMockNotImplemented
}

// CredentialManagementService stub implementations
func (m *mockPIVClient) SubmitCredential(_ context.Context, _ *transport.CredentialSubmitRequest) (*transport.CredentialSubmitResponse, error) {
	return nil, errMockNotImplemented
}
func (m *mockPIVClient) GetCredentialStrategy(_ context.Context) (*transport.CredentialStrategyResponse, error) {
	return nil, errMockNotImplemented
}

// --- BackendDisplayName tests ---

func TestPIVService_GetSlots_BackendDisplayName(t *testing.T) {
	// Create a real MemoryRegistry with a backend that has a display name.
	reg := backendregistry.NewMemoryRegistry()
	t.Cleanup(func() { reg.Close() })

	err := reg.Register(&backendregistry.RegisteredBackend{
		ID:          "software",
		Location:    backendregistry.LocationLocal,
		Category:    backendregistry.CategorySoftware,
		DisplayName: "Local Software",
	})
	require.NoError(t, err)

	// Test with remote client — slots come from mapTransportSlots.
	client := &mockPIVClient{
		listPIVSlotsResp: &transport.ListPIVSlotsResponse{
			Slots: []transport.PIVSlotStatus{
				{
					Slot:    "9a",
					Name:    "PIV Authentication",
					HasCert: true,
					Backend: "software",
				},
			},
		},
	}
	svc := NewPIVService(client, "software")
	svc.SetContext(context.Background())
	svc.SetRegistry(reg)

	slots, err := svc.GetSlots()
	require.NoError(t, err)
	require.NotEmpty(t, slots)

	// The slot with cert data should have the resolved display name.
	assert.Equal(t, "Local Software", slots[0].BackendDisplayName)
}

func TestPIVService_GetSlots_BackendDisplayName_EmptySlots(t *testing.T) {
	// Create a registry with the local backend display name.
	reg := backendregistry.NewMemoryRegistry()
	t.Cleanup(func() { reg.Close() })

	err := reg.Register(&backendregistry.RegisteredBackend{
		ID:          "software",
		Location:    backendregistry.LocationLocal,
		Category:    backendregistry.CategorySoftware,
		DisplayName: "Software",
	})
	require.NoError(t, err)

	// No client and no local — emptySlots path uses localBackend ("software").
	svc := NewPIVService(nil, "")
	svc.SetLocalBackend("software")
	svc.SetRegistry(reg)

	slots, err := svc.GetSlots()
	require.NoError(t, err)
	require.Len(t, slots, 5)

	// All empty slots should have the local backend display name.
	for _, slot := range slots {
		assert.Equal(t, "Software", slot.BackendDisplayName)
	}
}

func TestPIVService_GetSlots_BackendDisplayName_NoRegistry(t *testing.T) {
	// Without a registry, BackendDisplayName should be empty.
	svc := NewPIVService(nil, "")
	slots, err := svc.GetSlots()
	require.NoError(t, err)
	require.Len(t, slots, 5)

	for _, slot := range slots {
		assert.Empty(t, slot.BackendDisplayName)
	}
}

func TestPIVService_GetSlots_BackendDisplayName_UnknownBackend(t *testing.T) {
	// Registry exists but backend ID is not registered.
	reg := backendregistry.NewMemoryRegistry()
	t.Cleanup(func() { reg.Close() })

	client := &mockPIVClient{
		listPIVSlotsResp: &transport.ListPIVSlotsResponse{
			Slots: []transport.PIVSlotStatus{
				{
					Slot:    "9a",
					Name:    "PIV Authentication",
					HasCert: true,
					Backend: "unknown-backend",
				},
			},
		},
	}
	svc := NewPIVService(client, "unknown-backend")
	svc.SetContext(context.Background())
	svc.SetRegistry(reg)

	slots, err := svc.GetSlots()
	require.NoError(t, err)

	// Unknown backend should resolve to empty display name.
	assert.Empty(t, slots[0].BackendDisplayName)
}

func TestPIVService_SetRegistry(t *testing.T) {
	svc := NewPIVService(nil, "")
	assert.Nil(t, svc.registry)

	reg := backendregistry.NewMemoryRegistry()
	t.Cleanup(func() { reg.Close() })

	svc.SetRegistry(reg)
	assert.NotNil(t, svc.registry)
}

// --- ResolveXKMSBackendName tests ---

func TestPIVService_ResolveXKMSBackendName_WithRegistry(t *testing.T) {
	reg := backendregistry.NewMemoryRegistry()
	t.Cleanup(func() { reg.Close() })

	err := reg.Register(&backendregistry.RegisteredBackend{
		ID:       "tpm2-default",
		Location: backendregistry.LocationLocal,
		Category: backendregistry.CategoryTPM2,
	})
	require.NoError(t, err)

	svc := NewPIVService(nil, "")
	svc.SetRegistry(reg)

	// Registry resolves "tpm2-default" to the category "tpm2".
	assert.Equal(t, "tpm2", svc.resolveXKMSBackendName("tpm2-default"))
}

func TestPIVService_ResolveXKMSBackendName_WithoutRegistry(t *testing.T) {
	svc := NewPIVService(nil, "")

	// No registry set — returns the raw ID unchanged.
	assert.Equal(t, "tpm2-default", svc.resolveXKMSBackendName("tpm2-default"))
}

func TestPIVService_ResolveXKMSBackendName_NotInRegistry(t *testing.T) {
	reg := backendregistry.NewMemoryRegistry()
	t.Cleanup(func() { reg.Close() })

	svc := NewPIVService(nil, "")
	svc.SetRegistry(reg)

	// ID not in registry — returns the raw ID unchanged.
	assert.Equal(t, "unknown-backend", svc.resolveXKMSBackendName("unknown-backend"))
}

func TestPIVService_ResolveXKMSBackendName_SameIDAndCategory(t *testing.T) {
	reg := backendregistry.NewMemoryRegistry()
	t.Cleanup(func() { reg.Close() })

	err := reg.Register(&backendregistry.RegisteredBackend{
		ID:       "software",
		Location: backendregistry.LocationLocal,
		Category: backendregistry.CategorySoftware,
	})
	require.NoError(t, err)

	svc := NewPIVService(nil, "")
	svc.SetRegistry(reg)

	// When ID and category match, no translation needed.
	assert.Equal(t, "software", svc.resolveXKMSBackendName("software"))
}
