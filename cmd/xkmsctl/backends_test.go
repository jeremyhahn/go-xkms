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

package main

import (
	"bytes"
	"context"
	"errors"
	"testing"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// mockBackendsClient is a mock client for testing backend operations
type mockBackendsClient struct {
	listBackendsResp *client.ListBackendsResponse
	listBackendsErr  error
	getBackendResp   *client.BackendInfo
	getBackendErr    error
	connectErr       error
}

func (m *mockBackendsClient) Connect(ctx context.Context) error {
	return m.connectErr
}

func (m *mockBackendsClient) Close() error {
	return nil
}

func (m *mockBackendsClient) Health(ctx context.Context) (*client.HealthResponse, error) {
	return &client.HealthResponse{Status: "ok"}, nil
}

func (m *mockBackendsClient) ListBackends(ctx context.Context, _ ...transport.ListOption) (*client.ListBackendsResponse, error) {
	return m.listBackendsResp, m.listBackendsErr
}

func (m *mockBackendsClient) GetBackend(ctx context.Context, backendID string) (*client.BackendInfo, error) {
	return m.getBackendResp, m.getBackendErr
}

func (m *mockBackendsClient) GenerateKey(ctx context.Context, req *client.GenerateKeyRequest) (*client.GenerateKeyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) ListKeys(ctx context.Context, backend string, _ ...transport.ListOption) (*client.ListKeysResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) GetKey(ctx context.Context, backend, keyID string) (*client.GetKeyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) DeleteKey(ctx context.Context, backend, keyID string) (*client.DeleteKeyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) Sign(ctx context.Context, req *client.SignRequest) (*client.SignResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) Verify(ctx context.Context, req *client.VerifyRequest) (*client.VerifyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) Encrypt(ctx context.Context, req *client.EncryptRequest) (*client.EncryptResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) Decrypt(ctx context.Context, req *client.DecryptRequest) (*client.DecryptResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) EncryptAsym(ctx context.Context, req *client.EncryptAsymRequest) (*client.EncryptAsymResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) GetCertificate(ctx context.Context, backend, keyID string) (*client.GetCertificateResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) SaveCertificate(ctx context.Context, req *client.SaveCertificateRequest) error {
	return nil
}

func (m *mockBackendsClient) DeleteCertificate(ctx context.Context, backend, keyID string) error {
	return nil
}

func (m *mockBackendsClient) CertificateExists(ctx context.Context, backend, keyID string) (bool, error) {
	return false, nil
}

func (m *mockBackendsClient) ImportKey(ctx context.Context, req *client.ImportKeyRequest) (*client.ImportKeyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) ExportKey(ctx context.Context, req *client.ExportKeyRequest) (*client.ExportKeyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) RotateKey(ctx context.Context, req *client.RotateKeyRequest) (*client.RotateKeyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) CreateOTAImageKey(ctx context.Context, req *client.OTAImageKeyRequest) (*client.GenerateKeyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) RotateOTAImageKey(ctx context.Context, req *client.OTAImageKeyRequest) (*client.RotateKeyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) SignOTAImage(ctx context.Context, req *client.OTAImageSignRequest) (*client.SignResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) GetImportParameters(ctx context.Context, req *client.GetImportParametersRequest) (*client.GetImportParametersResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) WrapKey(ctx context.Context, req *client.WrapKeyRequest) (*client.WrapKeyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) UnwrapKey(ctx context.Context, req *client.UnwrapKeyRequest) (*client.UnwrapKeyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) CopyKey(ctx context.Context, req *client.CopyKeyRequest) (*client.CopyKeyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) ListCertificates(ctx context.Context, backend string, _ ...transport.ListOption) (*client.ListCertificatesResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) SaveCertificateChain(ctx context.Context, req *client.SaveCertificateChainRequest) error {
	return nil
}

func (m *mockBackendsClient) GetCertificateChain(ctx context.Context, backend, keyID string) (*client.GetCertificateChainResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) GetTLSCertificate(ctx context.Context, backend, keyID string) (*client.GetTLSCertificateResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) Seal(ctx context.Context, req *client.SealRequest) (*client.SealResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) Unseal(ctx context.Context, req *client.UnsealRequest) (*client.UnsealResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) CanSeal(ctx context.Context, backend string) (*client.CanSealResponse, error) {
	return nil, nil
}

// Authentication flow stub implementations
func (m *mockBackendsClient) BeginRegistration(ctx context.Context, req *client.BeginRegistrationRequest) (*client.BeginRegistrationResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockBackendsClient) FinishRegistration(ctx context.Context, req *client.FinishRegistrationRequest) (*client.FinishRegistrationResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockBackendsClient) BeginAuthentication(ctx context.Context, req *client.BeginAuthenticationRequest) (*client.BeginAuthenticationResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockBackendsClient) FinishAuthentication(ctx context.Context, req *client.FinishAuthenticationRequest) (*client.FinishAuthenticationResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockBackendsClient) GetInvite(ctx context.Context, req *client.GetInviteRequest) (*client.GetInviteResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockBackendsClient) BeginInviteRegistration(ctx context.Context, req *client.BeginInviteRegistrationRequest) (*client.BeginInviteRegistrationResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockBackendsClient) FinishInviteRegistration(ctx context.Context, req *client.FinishInviteRegistrationRequest) (*client.FinishInviteRegistrationResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockBackendsClient) ActivateInvitePIV(ctx context.Context, req *client.ActivateInvitePIVRequest) (*client.ActivateInvitePIVResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockBackendsClient) DeriveKey(ctx context.Context, req *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) DeriveKeyECDH(ctx context.Context, req *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) WrapKeyByID(ctx context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) UnwrapKeyByID(ctx context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) ExportKeyMaterial(ctx context.Context, req *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) AttestKey(ctx context.Context, req *transport.AttestKeyRequest) (*transport.AttestKeyResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockBackendsClient) GetCABundle(ctx context.Context, req *transport.GetCABundleRequest) (*transport.GetCABundleResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) GetCACertificate(ctx context.Context, req *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) SignCSR(ctx context.Context, req *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) IssueCertificate(ctx context.Context, req *transport.IssueCertificateRequest) (*transport.IssueCertificateResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) RevokeCertificate(ctx context.Context, req *transport.RevokeCertificateRequest) (*transport.RevokeCertificateResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) GenerateCRL(ctx context.Context, req *transport.GenerateCRLRequest) (*transport.GenerateCRLResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) IsRevoked(ctx context.Context, req *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error) {
	return nil, nil
}

// TCG CA operations stub implementations
func (m *mockBackendsClient) IssueEKCertificate(ctx context.Context, req *transport.IssueEKCertificateRequest) (*transport.IssueEKCertificateResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) IssueAKCertificate(ctx context.Context, req *transport.IssueAKCertificateRequest) (*transport.IssueAKCertificateResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) SignTCGCSR(ctx context.Context, req *transport.SignTCGCSRRequest) (*transport.SignTCGCSRResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) EnrollDevice(ctx context.Context, req *transport.EnrollDeviceRequest) (*transport.EnrollDeviceResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) IssueLAKCertificate(ctx context.Context, req *transport.IssueLAKCertificateRequest) (*transport.IssueLAKCertificateResponse, error) {
	return nil, nil
}

// PIV operations stub implementations
func (m *mockBackendsClient) ListPIVSlots(ctx context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockBackendsClient) GetPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockBackendsClient) StorePIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return client.ErrNotSupported
}

func (m *mockBackendsClient) DeletePIVCertificate(ctx context.Context, req *transport.DeletePIVCertificateRequest) error {
	return client.ErrNotSupported
}

func (m *mockBackendsClient) GeneratePIVKey(ctx context.Context, req *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockBackendsClient) ImportPIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return client.ErrNotSupported
}

func (m *mockBackendsClient) ExportPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockBackendsClient) GeneratePIVCSR(ctx context.Context, req *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	return nil, client.ErrNotSupported
}

func TestListBackends_ClientCreateError(t *testing.T) {
	// Override exitFunc to prevent actual exit
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return nil, errors.New("client create failed")
		},
	}

	// Should not panic
	listBackends(cfg, printer)
}

func TestListBackends_ConnectError(t *testing.T) {
	// Override exitFunc to prevent actual exit
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockBackendsClient{
		connectErr: errors.New("connect failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	// Should not panic
	listBackends(cfg, printer)
}

func TestListBackends_ListBackendsError(t *testing.T) {
	// Override exitFunc to prevent actual exit
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockBackendsClient{
		listBackendsErr: errors.New("list backends failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	// Should not panic
	listBackends(cfg, printer)
}

func TestListBackends_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			mockClient := &mockBackendsClient{
				listBackendsResp: &client.ListBackendsResponse{
					Backends: []client.BackendInfo{
						{ID: "software", Type: "software"},
					},
				},
			}

			buf := new(bytes.Buffer)
			printer := NewPrinter(format, buf)

			cfg := &Config{
				ClientFactory: func(cfg *Config) (client.Client, error) {
					return mockClient, nil
				},
			}

			listBackends(cfg, printer)

			if buf.Len() == 0 {
				t.Errorf("listBackends with %s format should produce output", format)
			}
		})
	}
}

func TestBackendInfo_ClientCreateError(t *testing.T) {
	// Override exitFunc to prevent actual exit
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return nil, errors.New("client create failed")
		},
	}

	// Should not panic
	backendInfo(cfg, printer, "software")
}

func TestBackendInfo_ConnectError(t *testing.T) {
	// Override exitFunc to prevent actual exit
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockBackendsClient{
		connectErr: errors.New("connect failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	// Should not panic
	backendInfo(cfg, printer, "software")
}

func TestBackendInfo_GetBackendError(t *testing.T) {
	// Override exitFunc to prevent actual exit
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mockClient := &mockBackendsClient{
		getBackendErr: errors.New("get backend failed"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mockClient, nil
		},
	}

	// Should not panic
	backendInfo(cfg, printer, "unknown")
}

func TestBackendInfo_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			mockClient := &mockBackendsClient{
				getBackendResp: &client.BackendInfo{
					ID:             "software",
					Type:           "software",
					HardwareBacked: false,
					Capabilities: transport.BackendCapabilities{
						Keys:    true,
						Signing: true,
					},
				},
			}

			buf := new(bytes.Buffer)
			printer := NewPrinter(format, buf)

			cfg := &Config{
				ClientFactory: func(cfg *Config) (client.Client, error) {
					return mockClient, nil
				},
			}

			backendInfo(cfg, printer, "software")

			if buf.Len() == 0 {
				t.Errorf("backendInfo with %s format should produce output", format)
			}
		})
	}
}

func (m *mockBackendsClient) BarrierSeal(ctx context.Context) error {
	return nil
}

func (m *mockBackendsClient) BootstrapListenerKeys(ctx context.Context) (*transport.BootstrapListenerKeysResponse, error) {
	return nil, nil
}

// BarrierDeleteRecoveryKeys deletes all recovery keys.
func (m *mockBackendsClient) BarrierDeleteRecoveryKeys(_ context.Context) error {
	return nil
}

// PIN operations stub implementations
func (m *mockBackendsClient) SetSOPIN(ctx context.Context, req *transport.SetSOPINRequest) error {
	return nil
}

func (m *mockBackendsClient) SetUserPIN(ctx context.Context, req *transport.SetUserPINRequest) error {
	return nil
}

func (m *mockBackendsClient) ChangeSOPIN(ctx context.Context, req *transport.ChangeSOPINRequest) error {
	return nil
}

func (m *mockBackendsClient) ChangeUserPIN(ctx context.Context, req *transport.ChangeUserPINRequest) error {
	return nil
}

func (m *mockBackendsClient) VerifySOPIN(ctx context.Context, req *transport.VerifySOPINRequest) error {
	return nil
}

func (m *mockBackendsClient) VerifyUserPIN(ctx context.Context, req *transport.VerifyUserPINRequest) error {
	return nil
}

func (m *mockBackendsClient) GetLockoutStatus(ctx context.Context) (*transport.LockoutStatusResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) ResetLockout(ctx context.Context, req *transport.ResetLockoutRequest) error {
	return nil
}

// PasswordService stub implementations
func (m *mockBackendsClient) PasswordAdd(ctx context.Context, req *transport.PasswordAddRequest) (*transport.PasswordAddResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) PasswordGet(ctx context.Context, req *transport.PasswordGetRequest) (*transport.PasswordGetResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) PasswordList(ctx context.Context, req *transport.PasswordListRequest) (*transport.PasswordListResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) PasswordUpdate(ctx context.Context, req *transport.PasswordUpdateRequest) error {
	return nil
}

func (m *mockBackendsClient) PasswordDelete(ctx context.Context, req *transport.PasswordDeleteRequest) error {
	return nil
}

func (m *mockBackendsClient) PasswordStoreUnlock(ctx context.Context, req *transport.PasswordStoreUnlockRequest) error {
	return nil
}

func (m *mockBackendsClient) PasswordStoreLock(ctx context.Context) error {
	return nil
}

func (m *mockBackendsClient) PasswordVaultStatus(ctx context.Context) (*transport.PasswordVaultStatusResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) PasswordVaultEnroll(ctx context.Context, req *transport.PasswordVaultEnrollRequest) (*transport.PasswordVaultEnrollResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) PasswordVaultRotate(ctx context.Context, req *transport.PasswordVaultRotateRequest) (*transport.PasswordVaultEnrollResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) PasswordVaultRemoveFactor(ctx context.Context, req *transport.PasswordVaultRemoveFactorRequest) error {
	return nil
}

func (m *mockBackendsClient) PasswordVaultRecover(ctx context.Context, req *transport.PasswordVaultRecoverRequest) (*transport.PasswordVaultEnrollResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) PasswordStoreStatus(ctx context.Context) (*transport.PasswordStoreStatusResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) PasswordStoreSetAccessMode(ctx context.Context, req *transport.PasswordStoreSetAccessModeRequest) error {
	return nil
}

func (m *mockBackendsClient) PasswordGenerate(ctx context.Context, req *transport.PasswordGenerateRequest) (*transport.PasswordGenerateResponse, error) {
	return nil, nil
}

// SealStoreService stub implementations
func (m *mockBackendsClient) SealStorePut(ctx context.Context, req *transport.SealStorePutRequest) error {
	return nil
}

func (m *mockBackendsClient) SealStoreGet(ctx context.Context, req *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) SealStoreDelete(ctx context.Context, req *transport.SealStoreDeleteRequest) error {
	return nil
}

func (m *mockBackendsClient) SealStoreList(ctx context.Context) (*transport.SealStoreListResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) SealStoreReseal(ctx context.Context, req *transport.SealStoreResealRequest) error {
	return nil
}

func (m *mockBackendsClient) SealStoreStatus(ctx context.Context) (*transport.SealStoreStatusResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) EscrowKey(ctx context.Context, req *transport.EscrowRequest) ([]*transport.EscrowReceipt, error) {
	return nil, nil
}

func (m *mockBackendsClient) RecoverKey(ctx context.Context, req *transport.RecoverRequest) (*transport.RecoverResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) ListEscrowed(ctx context.Context) ([]transport.EscrowRecord, error) {
	return nil, nil
}

func (m *mockBackendsClient) RevokeEscrow(ctx context.Context, escrowID string) error {
	return nil
}

func (m *mockBackendsClient) ListKeyVersions(context.Context, *transport.ListKeyVersionsRequest) (*transport.ListKeyVersionsResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) EnableKeyVersion(context.Context, *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) DisableKeyVersion(context.Context, *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) RetireKeyVersion(context.Context, *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) EnableAllKeyVersions(context.Context, *transport.AllKeyVersionsRequest) (*transport.AllKeyVersionsResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) DisableAllKeyVersions(context.Context, *transport.AllKeyVersionsRequest) (*transport.AllKeyVersionsResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) RotateScopeKeys(context.Context, *transport.RotateScopeKeysRequest) (*transport.RotateScopeKeysResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) TPMPolicyCreate(context.Context, *transport.TPMPolicyCreateRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

func (m *mockBackendsClient) TPMPolicyGet(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

func (m *mockBackendsClient) TPMPolicyList(context.Context, *transport.TPMPolicyListRequest) (*transport.TPMPolicyListResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) TPMPolicyUpdate(context.Context, *transport.TPMPolicyUpdateRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

func (m *mockBackendsClient) TPMPolicyRevoke(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

func (m *mockBackendsClient) TPMPolicyVerify(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicyVerifyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) TPMPolicyDelete(context.Context, *transport.TPMPolicyDeleteRequest) error {
	return nil
}

func (m *mockBackendsClient) TPMPolicyObjects(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicyObjectsResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) TPMPolicySetAutoUnseal(context.Context, *transport.TPMPolicyAutoUnsealRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

func (m *mockBackendsClient) TPMPolicySetDescription(context.Context, *transport.TPMPolicyDescriptionRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

// OIDC credential operations are not exercised by this double.
func (*mockBackendsClient) OIDCCredentialCreate(context.Context, *transport.OIDCCredentialCreateRequest) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*mockBackendsClient) OIDCCredentialImport(context.Context, *transport.OIDCCredentialImportRequest) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*mockBackendsClient) OIDCCredentialGet(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*mockBackendsClient) OIDCCredentialList(context.Context, *transport.OIDCCredentialListRequest) (*transport.OIDCCredentialListResponse, error) {
	return nil, nil
}
func (*mockBackendsClient) TrustRootList(context.Context, *transport.TrustRootListRequest) (*transport.TrustRootListResponse, error) {
	return nil, nil
}
func (*mockBackendsClient) TrustRootGet(context.Context, *transport.TrustRootRequest) (*transport.TrustRoot, error) {
	return nil, nil
}
func (*mockBackendsClient) TrustRootImport(context.Context, *transport.TrustRootImportRequest) (*transport.TrustRootImportResponse, error) {
	return nil, nil
}
func (*mockBackendsClient) TrustRootQuarantine(context.Context, *transport.TrustRootRequest) (*transport.TrustRoot, error) {
	return nil, nil
}
func (*mockBackendsClient) TrustRootRemove(context.Context, *transport.TrustRootRequest) error {
	return nil
}
func (*mockBackendsClient) OIDCCredentialDelete(context.Context, *transport.OIDCCredentialRef) error {
	return nil
}
func (*mockBackendsClient) OIDCCredentialRefresh(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*mockBackendsClient) OIDCCredentialGetAccessToken(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCAccessToken, error) {
	return nil, nil
}
func (*mockBackendsClient) OIDCCredentialDeviceStart(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*mockBackendsClient) OIDCCredentialDevicePoll(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, nil
}

func (m *mockBackendsClient) TPMObjectPolicy(context.Context, *transport.TPMObjectPolicyRequest) (*transport.TPMObjectPolicyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) TPMPolicyRotateAuthority(context.Context, *transport.TPMAuthorityRotateRequest) (*transport.TPMAuthorityRotateResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) GetTenantTPMMode(context.Context, string) (*transport.TenantTPMModeResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) SetTenantTPMMode(context.Context, *transport.SetTenantTPMModeRequest) (*transport.TenantTPMModeResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) TenantVTPMStatus(context.Context, string) (*transport.TenantVTPMStatusResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) TenantVTPMStart(context.Context, string) (*transport.TenantVTPMStatusResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) TenantVTPMStop(context.Context, string) (*transport.TenantVTPMStatusResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) DeleteBackup(_ context.Context, _ string) error {
	return nil
}

func (m *mockBackendsClient) DeleteCustodianGroup(_ context.Context, _ string) error {
	return nil
}

func (m *mockBackendsClient) Algorithms(_ context.Context) (*transport.AlgorithmsResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) DeleteShare(_ context.Context, _, _ string, _ int) error {
	return nil
}

// TenantService stub implementations
func (m *mockBackendsClient) CreateTenant(_ context.Context, _ *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) GetTenant(_ context.Context, _ string) (*transport.GetTenantResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) ListTenants(_ context.Context) (*transport.ListTenantsResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) DeleteTenant(_ context.Context, _ string) error {
	return nil
}

func (m *mockBackendsClient) UpdateTenantEntitlements(_ context.Context, _ *transport.UpdateTenantEntitlementsRequest) (*transport.UpdateTenantEntitlementsResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) UpdateTenantQuotas(_ context.Context, _ *transport.UpdateTenantQuotasRequest) (*transport.UpdateTenantQuotasResponse, error) {
	return nil, nil
}

// CredentialManagementService stub implementations
func (m *mockBackendsClient) SubmitCredential(_ context.Context, _ *transport.CredentialSubmitRequest) (*transport.CredentialSubmitResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) GetCredentialStrategy(_ context.Context) (*transport.CredentialStrategyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) CreateUser(_ context.Context, _ *transport.CreateUserRequest) (*transport.GetUserResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) ListUsers(_ context.Context, _ ...transport.ListOption) (*transport.ListUsersResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) GetUser(_ context.Context, _ string) (*transport.GetUserResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) DeleteUser(_ context.Context, _ string) error {
	return nil
}

func (m *mockBackendsClient) EnableUser(_ context.Context, _ string) error {
	return nil
}

func (m *mockBackendsClient) DisableUser(_ context.Context, _ string) error {
	return nil
}

func (m *mockBackendsClient) BindUserCert(_ context.Context, _, _ string, _ int64) error {
	return nil
}

func (m *mockBackendsClient) ListUserCredentials(_ context.Context, _ string) (*transport.ListUserCredentialsResponse, error) {
	return nil, nil
}

func (*mockBackendsClient) SetSigningKeyBinding(context.Context, *transport.SetSigningKeyBindingRequest) (*transport.SigningKeyBinding, error) {
	return nil, nil
}
func (*mockBackendsClient) GetSigningKeyBinding(context.Context, *transport.GetSigningKeyBindingRequest) (*transport.SigningKeyBinding, error) {
	return nil, nil
}
func (*mockBackendsClient) ListSigningKeyBindings(context.Context) (*transport.ListSigningKeyBindingsResponse, error) {
	return nil, nil
}
func (*mockBackendsClient) DeleteSigningKeyBinding(context.Context, *transport.DeleteSigningKeyBindingRequest) error {
	return nil
}
func (*mockBackendsClient) ResolveSigningKey(context.Context, *transport.ResolveSigningKeyRequest) (*transport.SigningKeyResolution, error) {
	return nil, nil
}
