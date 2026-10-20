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

package cmd

import (
	"context"
	"errors"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/xkey/internal/tpmpolicyfake"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// errNotImplemented is returned by mock methods that are not implemented.
var errNotImplemented = errors.New("not implemented")

// mockCloserTransport implements pairingproto.Transport for testing.
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
type baseSDKClient struct {
	// Fake serves the TPM policy API, which these tests do not exercise.
	*tpmpolicyfake.Fake

	// OIDCCredentialService is never called by these tests; a nil embed
	// completes the client's method set.
	transport.OIDCCredentialService

	// TrustRootService completes transport.Client; these tests never call
	// it.
	transport.TrustRootService
}

func (b *baseSDKClient) ListKeyVersions(context.Context, *transport.ListKeyVersionsRequest) (*transport.ListKeyVersionsResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) EnableKeyVersion(context.Context, *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) DisableKeyVersion(context.Context, *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) RetireKeyVersion(context.Context, *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) EnableAllKeyVersions(context.Context, *transport.AllKeyVersionsRequest) (*transport.AllKeyVersionsResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) DisableAllKeyVersions(context.Context, *transport.AllKeyVersionsRequest) (*transport.AllKeyVersionsResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) RotateScopeKeys(context.Context, *transport.RotateScopeKeysRequest) (*transport.RotateScopeKeysResponse, error) {
	return nil, errNotImplemented
}

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

func (b *baseSDKClient) Algorithms(ctx context.Context) (*transport.AlgorithmsResponse, error) {
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

func (b *baseSDKClient) CreateOTAImageKey(ctx context.Context, req *transport.OTAImageKeyRequest) (*transport.GenerateKeyResponse, error) {
	return nil, nil
}

func (b *baseSDKClient) RotateOTAImageKey(ctx context.Context, req *transport.OTAImageKeyRequest) (*transport.RotateKeyResponse, error) {
	return nil, nil
}

func (b *baseSDKClient) SignOTAImage(ctx context.Context, req *transport.OTAImageSignRequest) (*transport.SignResponse, error) {
	return nil, nil
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

func (b *baseSDKClient) BindUserCert(ctx context.Context, username, thumbprint string, notAfterUnix int64) error {
	return errNotImplemented
}

func (b *baseSDKClient) CreateUser(ctx context.Context, req *transport.CreateUserRequest) (*transport.GetUserResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) IssueEKCertificate(ctx context.Context, req *transport.IssueEKCertificateRequest) (*transport.IssueEKCertificateResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) IssueAKCertificate(ctx context.Context, req *transport.IssueAKCertificateRequest) (*transport.IssueAKCertificateResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) SignTCGCSR(ctx context.Context, req *transport.SignTCGCSRRequest) (*transport.SignTCGCSRResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) EnrollDevice(ctx context.Context, req *transport.EnrollDeviceRequest) (*transport.EnrollDeviceResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) IssueLAKCertificate(ctx context.Context, req *transport.IssueLAKCertificateRequest) (*transport.IssueLAKCertificateResponse, error) {
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

func (b *baseSDKClient) GetInvite(ctx context.Context, req *transport.GetInviteRequest) (*transport.GetInviteResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) BeginInviteRegistration(ctx context.Context, req *transport.BeginInviteRegistrationRequest) (*transport.BeginInviteRegistrationResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) FinishInviteRegistration(ctx context.Context, req *transport.FinishInviteRegistrationRequest) (*transport.FinishInviteRegistrationResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) ActivateInvitePIV(ctx context.Context, req *transport.ActivateInvitePIVRequest) (*transport.ActivateInvitePIVResponse, error) {
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

func (b *baseSDKClient) BootstrapListenerKeys(ctx context.Context) (*transport.BootstrapListenerKeysResponse, error) {
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

func (b *baseSDKClient) PasswordVaultStatus(context.Context) (*transport.PasswordVaultStatusResponse, error) {
	return nil, nil
}

func (b *baseSDKClient) PasswordVaultEnroll(context.Context, *transport.PasswordVaultEnrollRequest) (*transport.PasswordVaultEnrollResponse, error) {
	return nil, nil
}

func (b *baseSDKClient) PasswordVaultRotate(context.Context, *transport.PasswordVaultRotateRequest) (*transport.PasswordVaultEnrollResponse, error) {
	return nil, nil
}

func (b *baseSDKClient) PasswordVaultRemoveFactor(context.Context, *transport.PasswordVaultRemoveFactorRequest) error {
	return nil
}

func (b *baseSDKClient) PasswordVaultRecover(context.Context, *transport.PasswordVaultRecoverRequest) (*transport.PasswordVaultEnrollResponse, error) {
	return nil, nil
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

func (b *baseSDKClient) EscrowKey(_ context.Context, _ *transport.EscrowRequest) ([]*transport.EscrowReceipt, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) RecoverKey(_ context.Context, _ *transport.RecoverRequest) (*transport.RecoverResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) ListEscrowed(_ context.Context) ([]transport.EscrowRecord, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) RevokeEscrow(_ context.Context, _ string) error {
	return errNotImplemented
}

// Backup operations (go-xkms#728)

// Policy operations

// Share operations

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

func (b *baseSDKClient) UpdateTenantEntitlements(_ context.Context, _ *transport.UpdateTenantEntitlementsRequest) (*transport.UpdateTenantEntitlementsResponse, error) {
	return nil, errNotImplemented
}

func (b *baseSDKClient) UpdateTenantQuotas(_ context.Context, _ *transport.UpdateTenantQuotasRequest) (*transport.UpdateTenantQuotasResponse, error) {
	return nil, errNotImplemented
}

// Init ceremony operations

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
	_ pairingproto.Transport = (*mockCloserTransport)(nil)
	_ transport.Client       = (*mockSDKClient)(nil)
)

// newTestLogger creates a no-op logger for testing.
func newTestLogger() *slog.Logger {
	return slog.Default()
}
