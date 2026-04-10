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

//go:build ble

package cmd

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errNotImplemented is returned by mock methods that are not implemented.
var errNotImplemented = errors.New("not implemented")

// mockCloserTransport implements phone.Transport for testing.
type mockCloserTransport struct {
	closed bool
}

func (m *mockCloserTransport) Send(ctx context.Context, data []byte) error {
	return nil
}

func (m *mockCloserTransport) Receive(ctx context.Context) ([]byte, error) {
	return nil, nil
}

func (m *mockCloserTransport) SendAndReceive(ctx context.Context, data []byte) ([]byte, error) {
	return nil, nil
}

func (m *mockCloserTransport) IsConnected() bool {
	return false
}

func (m *mockCloserTransport) Close() error {
	m.closed = true
	return nil
}

// baseSDKClient provides default "not implemented" stubs for every method
// on the transport.Client interface. Test mocks embed this and override
// only the methods they need.
type baseSDKClient struct{}

func (b *baseSDKClient) Connect(ctx context.Context) error {
	return errNotImplemented
}

func (b *baseSDKClient) Close() error {
	return errNotImplemented
}

func (b *baseSDKClient) Health(ctx context.Context) (*transport.HealthResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) ListBackends(ctx context.Context, _ ...transport.ListOption) (*transport.ListBackendsResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) GetBackend(ctx context.Context, backendID string) (*transport.BackendInfo, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) GenerateKey(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) ListKeys(ctx context.Context, backend string, _ ...transport.ListOption) (*transport.ListKeysResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) GetKey(ctx context.Context, backend, keyID string) (*transport.GetKeyResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) DeleteKey(ctx context.Context, backend, keyID string) (*transport.DeleteKeyResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) Sign(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) Verify(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) Encrypt(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) Decrypt(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) EncryptAsym(ctx context.Context, req *transport.EncryptAsymRequest) (*transport.EncryptAsymResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) DeriveKey(ctx context.Context, req *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) GetCertificate(ctx context.Context, backend, keyID string) (*transport.GetCertificateResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) SaveCertificate(ctx context.Context, req *transport.SaveCertificateRequest) error {
	return errNotImplemented
}

func (b *baseSDKClient) DeleteCertificate(ctx context.Context, backend, keyID string) error {
	return errNotImplemented
}

func (b *baseSDKClient) CertificateExists(ctx context.Context, backend, keyID string) (bool, error) {
	return false, errNotImplemented
}

func (b *baseSDKClient) ImportKey(ctx context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) ExportKey(ctx context.Context, req *transport.ExportKeyRequest) (*transport.ExportKeyResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) RotateKey(ctx context.Context, req *transport.RotateKeyRequest) (*transport.RotateKeyResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) GetImportParameters(ctx context.Context, req *transport.GetImportParametersRequest) (*transport.GetImportParametersResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) WrapKey(ctx context.Context, req *transport.WrapKeyRequest) (*transport.WrapKeyResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) UnwrapKey(ctx context.Context, req *transport.UnwrapKeyRequest) (*transport.UnwrapKeyResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) WrapKeyByID(ctx context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) UnwrapKeyByID(ctx context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) ExportKeyMaterial(ctx context.Context, req *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) DeriveKeyECDH(ctx context.Context, req *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) CopyKey(ctx context.Context, req *transport.CopyKeyRequest) (*transport.CopyKeyResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) ListCertificates(ctx context.Context, backend string, _ ...transport.ListOption) (*transport.ListCertificatesResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) SaveCertificateChain(ctx context.Context, req *transport.SaveCertificateChainRequest) error {
	return errNotImplemented
}

func (b *baseSDKClient) GetCertificateChain(ctx context.Context, backend, keyID string) (*transport.GetCertificateChainResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) GetTLSCertificate(ctx context.Context, backend, keyID string) (*transport.GetTLSCertificateResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) Seal(ctx context.Context, req *transport.SealRequest) (*transport.SealResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) Unseal(ctx context.Context, req *transport.UnsealRequest) (*transport.UnsealResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) CanSeal(ctx context.Context, backend string) (*transport.CanSealResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) AttestKey(ctx context.Context, req *transport.AttestKeyRequest) (*transport.AttestKeyResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) ListUsers(ctx context.Context, _ ...transport.ListOption) (*transport.ListUsersResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) GetUser(ctx context.Context, username string) (*transport.GetUserResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) DeleteUser(ctx context.Context, username string) error {
	return errNotImplemented
}

func (b *baseSDKClient) EnableUser(ctx context.Context, username string) error {
	return errNotImplemented
}

func (b *baseSDKClient) DisableUser(ctx context.Context, username string) error {
	return errNotImplemented
}

func (b *baseSDKClient) ListUserCredentials(ctx context.Context, username string) (*transport.ListUserCredentialsResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) BeginRegistration(ctx context.Context, req *transport.BeginRegistrationRequest) (*transport.BeginRegistrationResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) FinishRegistration(ctx context.Context, req *transport.FinishRegistrationRequest) (*transport.FinishRegistrationResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) BeginAuthentication(ctx context.Context, req *transport.BeginAuthenticationRequest) (*transport.BeginAuthenticationResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) FinishAuthentication(ctx context.Context, req *transport.FinishAuthenticationRequest) (*transport.FinishAuthenticationResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) GetCABundle(ctx context.Context, req *transport.GetCABundleRequest) (*transport.GetCABundleResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) GetCACertificate(ctx context.Context, req *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) SignCSR(ctx context.Context, req *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) IssueCertificate(ctx context.Context, req *transport.IssueCertificateRequest) (*transport.IssueCertificateResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) RevokeCertificate(ctx context.Context, req *transport.RevokeCertificateRequest) (*transport.RevokeCertificateResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) GenerateCRL(ctx context.Context, req *transport.GenerateCRLRequest) (*transport.GenerateCRLResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) IsRevoked(ctx context.Context, req *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error) {
	return nil, errNotImplemented
}

// PIV operations

func (b *baseSDKClient) ListPIVSlots(ctx context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) GetPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) StorePIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return errNotImplemented
}

func (b *baseSDKClient) DeletePIVCertificate(ctx context.Context, req *transport.DeletePIVCertificateRequest) error {
	return errNotImplemented
}

func (b *baseSDKClient) GeneratePIVKey(ctx context.Context, req *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) ImportPIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return errNotImplemented
}

func (b *baseSDKClient) ExportPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) GeneratePIVCSR(ctx context.Context, req *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	return nil, errNotImplemented
}

// Barrier operations

func (b *baseSDKClient) BarrierInitialize(ctx context.Context, req *transport.BarrierInitializeRequest) error {
	return errNotImplemented
}

func (b *baseSDKClient) BarrierUnseal(ctx context.Context, req *transport.BarrierUnsealRequest) error {
	return errNotImplemented
}

func (b *baseSDKClient) BarrierSeal(ctx context.Context) error {
	return errNotImplemented
}

func (b *baseSDKClient) BarrierStatus(ctx context.Context) (*transport.BarrierStatusResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) BarrierInitializeShamir(ctx context.Context, req *transport.BarrierInitializeShamirRequest) (*transport.BarrierInitializeShamirResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) BarrierUnsealWithShare(ctx context.Context, req *transport.BarrierUnsealShareRequest) (*transport.BarrierUnsealShareResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) BarrierUnsealWithShares(ctx context.Context, req *transport.BarrierUnsealSharesRequest) error {
	return errNotImplemented
}

func (b *baseSDKClient) BarrierShamirListShares(_ context.Context) (*transport.BarrierShamirSharesResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) BarrierShamirDeleteShare(_ context.Context, _ *transport.BarrierShamirDeleteShareRequest) error {
	return errNotImplemented
}

func (b *baseSDKClient) BarrierShamirDeleteAllShares(_ context.Context) error {
	return errNotImplemented
}

func (b *baseSDKClient) BarrierShamirVerify(_ context.Context) error {
	return errNotImplemented
}

func (b *baseSDKClient) BarrierRekey(_ context.Context, _ *transport.BarrierRekeyRequest) (*transport.BarrierRekeyResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) BarrierGenerateRecoveryKeys(_ context.Context, _ *transport.BarrierGenerateRecoveryKeysRequest) (*transport.BarrierRecoveryKeysResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) BarrierRecoverWithKeys(_ context.Context, _ *transport.BarrierRecoverWithKeysRequest) error {
	return errNotImplemented
}

func (b *baseSDKClient) BarrierDeleteRecoveryKeys(_ context.Context) error {
	return errNotImplemented
}

func (b *baseSDKClient) BarrierHasRecoveryKeys(_ context.Context) (*transport.BarrierHasRecoveryKeysResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) BarrierGenerateRootToken(_ context.Context, _ *transport.BarrierGenerateRootTokenRequest) (*transport.BarrierRootTokenResponse, error) {
	return nil, errNotImplemented
}

// PIN operations

func (b *baseSDKClient) SetSOPIN(ctx context.Context, req *transport.SetSOPINRequest) error {
	return errNotImplemented
}

func (b *baseSDKClient) SetUserPIN(ctx context.Context, req *transport.SetUserPINRequest) error {
	return errNotImplemented
}

func (b *baseSDKClient) ChangeSOPIN(ctx context.Context, req *transport.ChangeSOPINRequest) error {
	return errNotImplemented
}

func (b *baseSDKClient) ChangeUserPIN(ctx context.Context, req *transport.ChangeUserPINRequest) error {
	return errNotImplemented
}

func (b *baseSDKClient) VerifySOPIN(ctx context.Context, req *transport.VerifySOPINRequest) error {
	return errNotImplemented
}

func (b *baseSDKClient) VerifyUserPIN(ctx context.Context, req *transport.VerifyUserPINRequest) error {
	return errNotImplemented
}

func (b *baseSDKClient) GetLockoutStatus(ctx context.Context) (*transport.LockoutStatusResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) ResetLockout(ctx context.Context, req *transport.ResetLockoutRequest) error {
	return errNotImplemented
}

// Password operations

func (b *baseSDKClient) PasswordAdd(_ context.Context, _ *transport.PasswordAddRequest) (*transport.PasswordAddResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) PasswordGet(_ context.Context, _ *transport.PasswordGetRequest) (*transport.PasswordGetResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) PasswordList(_ context.Context, _ *transport.PasswordListRequest) (*transport.PasswordListResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) PasswordUpdate(_ context.Context, _ *transport.PasswordUpdateRequest) error {
	return errNotImplemented
}

func (b *baseSDKClient) PasswordDelete(_ context.Context, _ *transport.PasswordDeleteRequest) error {
	return errNotImplemented
}

func (b *baseSDKClient) PasswordStoreUnlock(_ context.Context, _ *transport.PasswordStoreUnlockRequest) error {
	return errNotImplemented
}

func (b *baseSDKClient) PasswordStoreLock(_ context.Context) error {
	return errNotImplemented
}

func (b *baseSDKClient) PasswordStoreStatus(_ context.Context) (*transport.PasswordStoreStatusResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) PasswordStoreSetAccessMode(_ context.Context, _ *transport.PasswordStoreSetAccessModeRequest) error {
	return errNotImplemented
}

func (b *baseSDKClient) PasswordGenerate(_ context.Context, _ *transport.PasswordGenerateRequest) (*transport.PasswordGenerateResponse, error) {
	return nil, errNotImplemented
}

// Platform store operations

func (b *baseSDKClient) SealStorePut(_ context.Context, _ *transport.SealStorePutRequest) error {
	return errNotImplemented
}

func (b *baseSDKClient) SealStoreGet(_ context.Context, _ *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) SealStoreDelete(_ context.Context, _ *transport.SealStoreDeleteRequest) error {
	return errNotImplemented
}

func (b *baseSDKClient) SealStoreList(_ context.Context) (*transport.SealStoreListResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) SealStoreReseal(_ context.Context, _ *transport.SealStoreResealRequest) error {
	return errNotImplemented
}

func (b *baseSDKClient) SealStoreStatus(_ context.Context) (*transport.SealStoreStatusResponse, error) {
	return nil, errNotImplemented
}

// Policy operations

func (b *baseSDKClient) PolicyCreate(_ context.Context, _ *transport.PolicyCreateRequest) (*transport.PolicyCreateResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) PolicyGet(_ context.Context, _ *transport.PolicyGetRequest) (*transport.PolicyGetResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) PolicyList(_ context.Context) (*transport.PolicyListResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) PolicyDelete(_ context.Context, _ *transport.PolicyDeleteRequest) error {
	return errNotImplemented
}

func (b *baseSDKClient) PolicyRefresh(_ context.Context, _ *transport.PolicyRefreshRequest) (*transport.PolicyGetResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) PolicyVerify(_ context.Context, _ *transport.PolicyVerifyRequest) (*transport.PolicyVerifyResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) PolicyExport(_ context.Context, _ *transport.PolicyExportRequest) (*transport.PolicyExportResponse, error) {
	return nil, errNotImplemented
}

// Custodian group operations

func (b *baseSDKClient) CreateCustodianGroup(_ context.Context, _ *transport.CreateCustodianGroupRequest) (*transport.CreateCustodianGroupResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) GetCustodianGroup(_ context.Context, _ string) (*transport.GetCustodianGroupResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) ListCustodianGroups(_ context.Context) (*transport.ListCustodianGroupsResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) DeleteCustodianGroup(_ context.Context, _ string) error {
	return errNotImplemented
}

func (b *baseSDKClient) AddCustodianMember(_ context.Context, _ *transport.AddCustodianMemberRequest) (*transport.AddCustodianMemberResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) RemoveCustodianMember(_ context.Context, _ *transport.RemoveCustodianMemberRequest) error {
	return errNotImplemented
}

func (b *baseSDKClient) DistributeShares(_ context.Context, _ *transport.DistributeSharesRequest) (*transport.DistributeSharesResponse, error) {
	return nil, errNotImplemented
}

// Share operations

func (b *baseSDKClient) SubmitShare(_ context.Context, _ *transport.SubmitShareRequest) (*transport.SubmitShareResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) ListShares(_ context.Context) (*transport.ListSharesResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) GetShareCollectionStatus(_ context.Context, _ string) (*transport.ShareCollectionStatus, error) {
	return nil, errNotImplemented
}

// Tenant operations

func (b *baseSDKClient) CreateTenant(_ context.Context, _ *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) GetTenant(_ context.Context, _ string) (*transport.GetTenantResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) ListTenants(_ context.Context) (*transport.ListTenantsResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) DeleteTenant(_ context.Context, _ string) error {
	return errNotImplemented
}

func (b *baseSDKClient) TenantBarrierInit(_ context.Context, _ *transport.TenantBarrierInitRequest) error {
	return errNotImplemented
}

func (b *baseSDKClient) TenantBarrierUnseal(_ context.Context, _ *transport.TenantBarrierUnsealRequest) error {
	return errNotImplemented
}

// Init ceremony operations

func (b *baseSDKClient) GetInitStatus(_ context.Context) (*transport.InitStatusResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) ClaimCertBegin(_ context.Context, _ *transport.ClaimCertBeginRequest) (*transport.ClaimCertBeginResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) ClaimCertComplete(_ context.Context, _ *transport.ClaimCertCompleteRequest) (*transport.ClaimCertCompleteResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) ClaimShare(_ context.Context, _ *transport.ClaimShareRequest) (*transport.ClaimShareResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) SignCSRInit(_ context.Context, _ *transport.SignCSRInitRequest) (*transport.SignCSRInitResponse, error) {
	return nil, errNotImplemented
}

// Credential management operations

func (b *baseSDKClient) SubmitCredential(_ context.Context, _ *transport.CredentialSubmitRequest) (*transport.CredentialSubmitResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) GetCredentialStrategy(_ context.Context) (*transport.CredentialStrategyResponse, error) {
	return nil, errNotImplemented
}

// mockSDKClient embeds baseSDKClient and overrides Close() to record calls.
type mockSDKClient struct {
	baseSDKClient
	closed bool
}

func (m *mockSDKClient) Close() error {
	m.closed = true
	return nil
}

// Compile-time interface assertions.
var (
	_ phone.Transport  = (*mockCloserTransport)(nil)
	_ transport.Client = (*mockSDKClient)(nil)
)

// newTestLogger creates a no-op logger for testing.
func newTestLogger() *slog.Logger {
	return slog.Default()
}

// newTestPhoneBackend creates a PhoneKeyBackend with the given mock transport.
// It uses default configuration with TrustNewDevices enabled to allow
// backend creation without a pre-configured expected remote static key,
// simulating an initial pairing scenario.
func newTestPhoneBackend(t *testing.T, tr phone.Transport) *phone.PhoneKeyBackend {
	t.Helper()
	cfg := phone.DefaultPhoneKeyBackendConfig()
	cfg.TrustNewDevices = true
	backend, err := phone.NewPhoneKeyBackendWithTransport(cfg, tr)
	require.NoError(t, err)
	return backend
}

func TestLoadXKMSdBridgeConfig_Defaults(t *testing.T) {
	viper.Reset()
	t.Cleanup(func() { viper.Reset() })

	// Load config with no viper values set.
	cfg := loadXKMSdBridgeConfig()

	// All fields should be zero values.
	assert.False(t, cfg.Enabled)
	assert.Empty(t, cfg.Protocol)
	assert.Empty(t, cfg.Address)
	assert.Equal(t, time.Duration(0), cfg.ConnectTimeout)
	assert.Equal(t, time.Duration(0), cfg.RequestTimeout)
	assert.False(t, cfg.TLSEnabled)
	assert.Empty(t, cfg.TLSCAFile)
	assert.Empty(t, cfg.AllowedBackends)
	assert.Empty(t, cfg.DeniedBackends)

	// Apply defaults and verify.
	cfg.applyDefaults()

	assert.Equal(t, "unix", cfg.Protocol)
	assert.Equal(t, "xkms-data/xkms.sock", cfg.Address)
	assert.Equal(t, 10*time.Second, cfg.ConnectTimeout)
	assert.Equal(t, 30*time.Second, cfg.RequestTimeout)
}

func TestLoadXKMSdBridgeConfig_FromViper(t *testing.T) {
	viper.Reset()
	t.Cleanup(func() { viper.Reset() })

	viper.Set("xkmsd.enabled", true)
	viper.Set("xkmsd.protocol", "unix")
	viper.Set("xkmsd.address", "/tmp/test.sock")
	viper.Set("xkmsd.sharing.allowed_backends", []string{"tpm2", "software"})
	viper.Set("xkmsd.sharing.denied_backends", []string{"vault"})
	viper.Set("xkmsd.request_timeout", "45s")

	cfg := loadXKMSdBridgeConfig()

	assert.True(t, cfg.Enabled)
	assert.Equal(t, "unix", cfg.Protocol)
	assert.Equal(t, "/tmp/test.sock", cfg.Address)
	assert.Equal(t, 45*time.Second, cfg.RequestTimeout)
	assert.Equal(t, []string{"tpm2", "software"}, cfg.AllowedBackends)
	assert.Equal(t, []string{"vault"}, cfg.DeniedBackends)
}

func TestPhoneBackendWithBridge_Close(t *testing.T) {
	mockTransport := &mockCloserTransport{}
	backend := newTestPhoneBackend(t, mockTransport)

	mockClient := &mockSDKClient{}
	wrapper := &phoneBackendWithBridge{
		PhoneKeyBackend: backend,
		xkmsdClient:     mockClient,
		logger:          newTestLogger(),
	}

	err := wrapper.Close()
	require.NoError(t, err)

	// Both the phone backend transport and the SDK client should be closed.
	assert.True(t, mockTransport.closed, "phone backend transport should be closed")
	assert.True(t, mockClient.closed, "xkmsd SDK client should be closed")
}

func TestPhoneBackendWithBridge_Close_NilClient(t *testing.T) {
	mockTransport := &mockCloserTransport{}
	backend := newTestPhoneBackend(t, mockTransport)

	wrapper := &phoneBackendWithBridge{
		PhoneKeyBackend: backend,
		xkmsdClient:     nil,
		logger:          newTestLogger(),
	}

	// Should not panic with nil xkmsdClient.
	err := wrapper.Close()
	require.NoError(t, err)

	assert.True(t, mockTransport.closed, "phone backend transport should be closed")
}

func TestConnectXKMSdBridge_Disabled(t *testing.T) {
	viper.Reset()
	t.Cleanup(func() { viper.Reset() })

	viper.Set("xkmsd.enabled", false)

	mockTransport := &mockCloserTransport{}
	backend := newTestPhoneBackend(t, mockTransport)
	logger := newTestLogger()

	result, err := connectXKMSdBridge(backend, logger)

	assert.Nil(t, result, "should return nil when xkmsd is disabled")
	assert.NoError(t, err, "should return nil error when xkmsd is disabled")
}

func TestCreateXKMSdClient_Unix(t *testing.T) {
	cfg := &XKMSdBridgeConfig{
		Protocol: "unix",
		Address:  "/tmp/test.sock",
	}

	client, err := createXKMSdClient(cfg)
	require.NoError(t, err)
	require.NotNil(t, client)

	// Clean up the client.
	_ = client.Close()
}

func TestCreateXKMSdClient_UnsupportedProtocol(t *testing.T) {
	cfg := &XKMSdBridgeConfig{
		Protocol: "websocket",
		Address:  "ws://localhost:8080",
	}

	client, err := createXKMSdClient(cfg)
	assert.Nil(t, client)
	assert.ErrorIs(t, err, ErrXKMSdUnsupportedProtocol)
}

func TestXKMSdBridgeConfig_ApplyDefaults_CustomValues(t *testing.T) {
	cfg := &XKMSdBridgeConfig{
		Protocol:       "unix",
		Address:        "/custom.sock",
		RequestTimeout: 60 * time.Second,
	}

	cfg.applyDefaults()

	// Custom values should be preserved.
	assert.Equal(t, "unix", cfg.Protocol)
	assert.Equal(t, "/custom.sock", cfg.Address)
	assert.Equal(t, 60*time.Second, cfg.RequestTimeout)

	// Only ConnectTimeout had a zero value and should get the default.
	assert.Equal(t, 10*time.Second, cfg.ConnectTimeout)
}
