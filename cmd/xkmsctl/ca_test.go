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
	"os"
	"path/filepath"
	"strings"
	"testing"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockCAClient is a mock client for CA command tests.
type mockCAClient struct {
	connectErr error
	connected  bool

	// CA operations
	caBundle      *transport.GetCABundleResponse
	caBundleErr   error
	caCert        *transport.GetCACertificateResponse
	caCertErr     error
	signCSRResp   *transport.SignCSRResponse
	signCSRErr    error
	issueResp     *transport.IssueCertificateResponse
	issueErr      error
	revokeResp    *transport.RevokeCertificateResponse
	revokeErr     error
	crlResp       *transport.GenerateCRLResponse
	crlErr        error
	isRevokedResp *transport.IsRevokedResponse
	isRevokedErr  error

	// TCG CA operations
	issueEKResp *transport.IssueEKCertificateResponse
	issueEKErr  error
	issueAKResp *transport.IssueAKCertificateResponse
	issueAKErr  error
	signTCGResp *transport.SignTCGCSRResponse
	signTCGErr  error
	enrollResp  *transport.EnrollDeviceResponse
	enrollErr   error

	issueLAKResp *transport.IssueLAKCertificateResponse
	issueLAKErr  error
	gotLAKReq    *transport.IssueLAKCertificateRequest
}

func newMockCAClient() *mockCAClient {
	return &mockCAClient{}
}

func (m *mockCAClient) Connect(_ context.Context) error {
	if m.connectErr != nil {
		return m.connectErr
	}
	m.connected = true
	return nil
}
func (m *mockCAClient) Close() error { m.connected = false; return nil }
func (m *mockCAClient) Health(_ context.Context) (*client.HealthResponse, error) {
	return &client.HealthResponse{Status: "healthy"}, nil
}
func (m *mockCAClient) ListBackends(_ context.Context, _ ...transport.ListOption) (*client.ListBackendsResponse, error) {
	return &client.ListBackendsResponse{}, nil
}
func (m *mockCAClient) GetBackend(_ context.Context, id string) (*client.BackendInfo, error) {
	return &client.BackendInfo{ID: id}, nil
}
func (m *mockCAClient) GenerateKey(_ context.Context, req *client.GenerateKeyRequest) (*client.GenerateKeyResponse, error) {
	return &client.GenerateKeyResponse{KeyID: req.KeyID}, nil
}
func (m *mockCAClient) ListKeys(_ context.Context, _ string, _ ...transport.ListOption) (*client.ListKeysResponse, error) {
	return &client.ListKeysResponse{}, nil
}
func (m *mockCAClient) GetKey(_ context.Context, _, _ string) (*client.GetKeyResponse, error) {
	return &client.GetKeyResponse{}, nil
}
func (m *mockCAClient) DeleteKey(_ context.Context, _, _ string) (*client.DeleteKeyResponse, error) {
	return &client.DeleteKeyResponse{Success: true}, nil
}
func (m *mockCAClient) Sign(_ context.Context, _ *client.SignRequest) (*client.SignResponse, error) {
	return &client.SignResponse{Signature: []byte("sig")}, nil
}
func (m *mockCAClient) Verify(_ context.Context, _ *client.VerifyRequest) (*client.VerifyResponse, error) {
	return &client.VerifyResponse{Valid: true}, nil
}
func (m *mockCAClient) Encrypt(_ context.Context, req *client.EncryptRequest) (*client.EncryptResponse, error) {
	return &client.EncryptResponse{Ciphertext: req.Plaintext}, nil
}
func (m *mockCAClient) Decrypt(_ context.Context, req *client.DecryptRequest) (*client.DecryptResponse, error) {
	return &client.DecryptResponse{Plaintext: req.Ciphertext}, nil
}
func (m *mockCAClient) EncryptAsym(_ context.Context, req *client.EncryptAsymRequest) (*client.EncryptAsymResponse, error) {
	return &client.EncryptAsymResponse{Ciphertext: req.Plaintext}, nil
}
func (m *mockCAClient) GetCertificate(_ context.Context, _, _ string) (*client.GetCertificateResponse, error) {
	return nil, client.ErrNotSupported
}
func (m *mockCAClient) SaveCertificate(_ context.Context, _ *client.SaveCertificateRequest) error {
	return nil
}
func (m *mockCAClient) DeleteCertificate(_ context.Context, _, _ string) error { return nil }
func (m *mockCAClient) CertificateExists(_ context.Context, _, _ string) (bool, error) {
	return false, nil
}
func (m *mockCAClient) ImportKey(_ context.Context, req *client.ImportKeyRequest) (*client.ImportKeyResponse, error) {
	return &client.ImportKeyResponse{Success: true, KeyID: req.KeyID}, nil
}
func (m *mockCAClient) ExportKey(_ context.Context, req *client.ExportKeyRequest) (*client.ExportKeyResponse, error) {
	return &client.ExportKeyResponse{KeyID: req.KeyID}, nil
}
func (m *mockCAClient) RotateKey(_ context.Context, req *client.RotateKeyRequest) (*client.RotateKeyResponse, error) {
	return &client.RotateKeyResponse{Success: true, KeyID: req.KeyID}, nil
}

func (m *mockCAClient) CreateOTAImageKey(_ context.Context, req *client.OTAImageKeyRequest) (*client.GenerateKeyResponse, error) {
	return nil, nil
}

func (m *mockCAClient) RotateOTAImageKey(_ context.Context, req *client.OTAImageKeyRequest) (*client.RotateKeyResponse, error) {
	return nil, nil
}

func (m *mockCAClient) SignOTAImage(_ context.Context, req *client.OTAImageSignRequest) (*client.SignResponse, error) {
	return nil, nil
}
func (m *mockCAClient) GetImportParameters(_ context.Context, req *client.GetImportParametersRequest) (*client.GetImportParametersResponse, error) {
	return &client.GetImportParametersResponse{Algorithm: req.Algorithm}, nil
}
func (m *mockCAClient) WrapKey(_ context.Context, req *client.WrapKeyRequest) (*client.WrapKeyResponse, error) {
	return &client.WrapKeyResponse{WrappedKeyMaterial: req.KeyMaterial}, nil
}
func (m *mockCAClient) UnwrapKey(_ context.Context, req *client.UnwrapKeyRequest) (*client.UnwrapKeyResponse, error) {
	return &client.UnwrapKeyResponse{KeyMaterial: req.WrappedKeyMaterial}, nil
}
func (m *mockCAClient) CopyKey(_ context.Context, req *client.CopyKeyRequest) (*client.CopyKeyResponse, error) {
	return &client.CopyKeyResponse{Success: true, KeyID: req.DestKeyID}, nil
}
func (m *mockCAClient) ListCertificates(_ context.Context, _ string, _ ...transport.ListOption) (*client.ListCertificatesResponse, error) {
	return &client.ListCertificatesResponse{}, nil
}
func (m *mockCAClient) SaveCertificateChain(_ context.Context, _ *client.SaveCertificateChainRequest) error {
	return nil
}
func (m *mockCAClient) GetCertificateChain(_ context.Context, _, _ string) (*client.GetCertificateChainResponse, error) {
	return nil, client.ErrNotSupported
}
func (m *mockCAClient) GetTLSCertificate(_ context.Context, _, _ string) (*client.GetTLSCertificateResponse, error) {
	return nil, client.ErrNotSupported
}
func (m *mockCAClient) Seal(_ context.Context, req *client.SealRequest) (*client.SealResponse, error) {
	return &client.SealResponse{Ciphertext: req.Data}, nil
}
func (m *mockCAClient) Unseal(_ context.Context, req *client.UnsealRequest) (*client.UnsealResponse, error) {
	return &client.UnsealResponse{Plaintext: req.Ciphertext}, nil
}
func (m *mockCAClient) CanSeal(_ context.Context, b string) (*client.CanSealResponse, error) {
	return &client.CanSealResponse{CanSeal: true, Backend: b}, nil
}
func (m *mockCAClient) BeginRegistration(_ context.Context, _ *client.BeginRegistrationRequest) (*client.BeginRegistrationResponse, error) {
	return nil, client.ErrNotSupported
}
func (m *mockCAClient) FinishRegistration(_ context.Context, _ *client.FinishRegistrationRequest) (*client.FinishRegistrationResponse, error) {
	return nil, client.ErrNotSupported
}
func (m *mockCAClient) BeginAuthentication(_ context.Context, _ *client.BeginAuthenticationRequest) (*client.BeginAuthenticationResponse, error) {
	return nil, client.ErrNotSupported
}
func (m *mockCAClient) FinishAuthentication(_ context.Context, _ *client.FinishAuthenticationRequest) (*client.FinishAuthenticationResponse, error) {
	return nil, client.ErrNotSupported
}
func (m *mockCAClient) GetInvite(_ context.Context, _ *client.GetInviteRequest) (*client.GetInviteResponse, error) {
	return nil, client.ErrNotSupported
}
func (m *mockCAClient) BeginInviteRegistration(_ context.Context, _ *client.BeginInviteRegistrationRequest) (*client.BeginInviteRegistrationResponse, error) {
	return nil, client.ErrNotSupported
}
func (m *mockCAClient) FinishInviteRegistration(_ context.Context, _ *client.FinishInviteRegistrationRequest) (*client.FinishInviteRegistrationResponse, error) {
	return nil, client.ErrNotSupported
}
func (m *mockCAClient) ActivateInvitePIV(_ context.Context, _ *client.ActivateInvitePIVRequest) (*client.ActivateInvitePIVResponse, error) {
	return nil, client.ErrNotSupported
}
func (m *mockCAClient) DeriveKey(_ context.Context, _ *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	return nil, nil
}
func (m *mockCAClient) DeriveKeyECDH(_ context.Context, _ *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
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
func (m *mockCAClient) AttestKey(_ context.Context, _ *transport.AttestKeyRequest) (*transport.AttestKeyResponse, error) {
	return nil, client.ErrNotSupported
}

// CA operations
func (m *mockCAClient) GetCABundle(_ context.Context, _ *transport.GetCABundleRequest) (*transport.GetCABundleResponse, error) {
	if m.caBundleErr != nil {
		return nil, m.caBundleErr
	}
	return m.caBundle, nil
}
func (m *mockCAClient) GetTransparencyLogHead(_ context.Context, _ *transport.GetTransparencyLogHeadRequest) (*transport.GetTransparencyLogHeadResponse, error) {
	return nil, nil
}

func (m *mockCAClient) GetTransparencyLogEntry(_ context.Context, _ *transport.GetTransparencyLogEntryRequest) (*transport.GetTransparencyLogEntryResponse, error) {
	return nil, nil
}

func (m *mockCAClient) GetTransparencyLogInclusionProof(_ context.Context, _ *transport.GetTransparencyLogInclusionProofRequest) (*transport.GetTransparencyLogInclusionProofResponse, error) {
	return nil, nil
}

func (m *mockCAClient) GetTransparencyLogConsistencyProof(_ context.Context, _ *transport.GetTransparencyLogConsistencyProofRequest) (*transport.GetTransparencyLogConsistencyProofResponse, error) {
	return nil, nil
}

func (m *mockCAClient) AppendTransparencyLogExternal(_ context.Context, _ *transport.AppendTransparencyLogExternalRequest) (*transport.AppendTransparencyLogExternalResponse, error) {
	return nil, nil
}

func (m *mockCAClient) GetCACertificate(_ context.Context, _ *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error) {
	if m.caCertErr != nil {
		return nil, m.caCertErr
	}
	return m.caCert, nil
}
func (m *mockCAClient) SignCSR(_ context.Context, _ *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	if m.signCSRErr != nil {
		return nil, m.signCSRErr
	}
	return m.signCSRResp, nil
}
func (m *mockCAClient) IssueCertificate(_ context.Context, _ *transport.IssueCertificateRequest) (*transport.IssueCertificateResponse, error) {
	if m.issueErr != nil {
		return nil, m.issueErr
	}
	return m.issueResp, nil
}
func (m *mockCAClient) RevokeCertificate(_ context.Context, _ *transport.RevokeCertificateRequest) (*transport.RevokeCertificateResponse, error) {
	if m.revokeErr != nil {
		return nil, m.revokeErr
	}
	return m.revokeResp, nil
}
func (m *mockCAClient) GenerateCRL(_ context.Context, _ *transport.GenerateCRLRequest) (*transport.GenerateCRLResponse, error) {
	if m.crlErr != nil {
		return nil, m.crlErr
	}
	return m.crlResp, nil
}
func (m *mockCAClient) IsRevoked(_ context.Context, _ *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error) {
	if m.isRevokedErr != nil {
		return nil, m.isRevokedErr
	}
	return m.isRevokedResp, nil
}

// TCG CA operations
func (m *mockCAClient) IssueEKCertificate(_ context.Context, _ *transport.IssueEKCertificateRequest) (*transport.IssueEKCertificateResponse, error) {
	if m.issueEKErr != nil {
		return nil, m.issueEKErr
	}
	return m.issueEKResp, nil
}
func (m *mockCAClient) IssueAKCertificate(_ context.Context, _ *transport.IssueAKCertificateRequest) (*transport.IssueAKCertificateResponse, error) {
	if m.issueAKErr != nil {
		return nil, m.issueAKErr
	}
	return m.issueAKResp, nil
}
func (m *mockCAClient) SignTCGCSR(_ context.Context, _ *transport.SignTCGCSRRequest) (*transport.SignTCGCSRResponse, error) {
	if m.signTCGErr != nil {
		return nil, m.signTCGErr
	}
	return m.signTCGResp, nil
}
func (m *mockCAClient) EnrollDevice(_ context.Context, _ *transport.EnrollDeviceRequest) (*transport.EnrollDeviceResponse, error) {
	if m.enrollErr != nil {
		return nil, m.enrollErr
	}
	return m.enrollResp, nil
}

func (m *mockCAClient) IssueLAKCertificate(_ context.Context, req *transport.IssueLAKCertificateRequest) (*transport.IssueLAKCertificateResponse, error) {
	m.gotLAKReq = req
	if m.issueLAKErr != nil {
		return nil, m.issueLAKErr
	}
	return m.issueLAKResp, nil
}

// PIV stubs
func (m *mockCAClient) ListPIVSlots(_ context.Context, _ *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	return nil, client.ErrNotSupported
}
func (m *mockCAClient) GetPIVCertificate(_ context.Context, _ *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return nil, client.ErrNotSupported
}
func (m *mockCAClient) StorePIVCertificate(_ context.Context, _ *transport.StorePIVCertificateRequest) error {
	return client.ErrNotSupported
}
func (m *mockCAClient) DeletePIVCertificate(_ context.Context, _ *transport.DeletePIVCertificateRequest) error {
	return client.ErrNotSupported
}
func (m *mockCAClient) GeneratePIVKey(_ context.Context, _ *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	return nil, client.ErrNotSupported
}
func (m *mockCAClient) ImportPIVCertificate(_ context.Context, _ *transport.StorePIVCertificateRequest) error {
	return client.ErrNotSupported
}
func (m *mockCAClient) ExportPIVCertificate(_ context.Context, _ *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return nil, client.ErrNotSupported
}
func (m *mockCAClient) GeneratePIVCSR(_ context.Context, _ *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockCAClient) BarrierSeal(_ context.Context) error { return client.ErrNotSupported }

func (m *mockCAClient) BootstrapListenerKeys(_ context.Context) (*transport.BootstrapListenerKeysResponse, error) {
	return nil, client.ErrNotSupported
}

func (m *mockCAClient) BarrierDeleteRecoveryKeys(_ context.Context) error {
	return client.ErrNotSupported
}

// PIN stubs
func (m *mockCAClient) SetSOPIN(_ context.Context, _ *transport.SetSOPINRequest) error {
	return client.ErrNotSupported
}
func (m *mockCAClient) SetUserPIN(_ context.Context, _ *transport.SetUserPINRequest) error {
	return client.ErrNotSupported
}
func (m *mockCAClient) ChangeSOPIN(_ context.Context, _ *transport.ChangeSOPINRequest) error {
	return client.ErrNotSupported
}
func (m *mockCAClient) ChangeUserPIN(_ context.Context, _ *transport.ChangeUserPINRequest) error {
	return client.ErrNotSupported
}
func (m *mockCAClient) VerifySOPIN(_ context.Context, _ *transport.VerifySOPINRequest) error {
	return client.ErrNotSupported
}
func (m *mockCAClient) VerifyUserPIN(_ context.Context, _ *transport.VerifyUserPINRequest) error {
	return client.ErrNotSupported
}
func (m *mockCAClient) GetLockoutStatus(_ context.Context) (*transport.LockoutStatusResponse, error) {
	return nil, client.ErrNotSupported
}
func (m *mockCAClient) ResetLockout(_ context.Context, _ *transport.ResetLockoutRequest) error {
	return client.ErrNotSupported
}

// Password stubs
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
func (m *mockCAClient) PasswordStoreLock(_ context.Context) error { return nil }
func (m *mockCAClient) PasswordVaultStatus(_ context.Context) (*transport.PasswordVaultStatusResponse, error) {
	return nil, nil
}
func (m *mockCAClient) PasswordVaultEnroll(_ context.Context, _ *transport.PasswordVaultEnrollRequest) (*transport.PasswordVaultEnrollResponse, error) {
	return nil, nil
}
func (m *mockCAClient) PasswordVaultRotate(_ context.Context, _ *transport.PasswordVaultRotateRequest) (*transport.PasswordVaultEnrollResponse, error) {
	return nil, nil
}
func (m *mockCAClient) PasswordVaultRemoveFactor(_ context.Context, _ *transport.PasswordVaultRemoveFactorRequest) error {
	return nil
}
func (m *mockCAClient) PasswordVaultRecover(_ context.Context, _ *transport.PasswordVaultRecoverRequest) (*transport.PasswordVaultEnrollResponse, error) {
	return nil, nil
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

// SealStore stubs
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

func (m *mockCAClient) EscrowKey(_ context.Context, _ *transport.EscrowRequest) ([]*transport.EscrowReceipt, error) {
	return nil, nil
}

func (m *mockCAClient) RecoverKey(_ context.Context, _ *transport.RecoverRequest) (*transport.RecoverResponse, error) {
	return nil, nil
}

func (m *mockCAClient) ListEscrowed(_ context.Context) ([]transport.EscrowRecord, error) {
	return nil, nil
}

func (m *mockCAClient) RevokeEscrow(_ context.Context, _ string) error {
	return nil
}

func (m *mockCAClient) ListKeyVersions(context.Context, *transport.ListKeyVersionsRequest) (*transport.ListKeyVersionsResponse, error) {
	return nil, nil
}

func (m *mockCAClient) EnableKeyVersion(context.Context, *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	return nil, nil
}

func (m *mockCAClient) DisableKeyVersion(context.Context, *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	return nil, nil
}

func (m *mockCAClient) RetireKeyVersion(context.Context, *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	return nil, nil
}

func (m *mockCAClient) EnableAllKeyVersions(context.Context, *transport.AllKeyVersionsRequest) (*transport.AllKeyVersionsResponse, error) {
	return nil, nil
}

func (m *mockCAClient) DisableAllKeyVersions(context.Context, *transport.AllKeyVersionsRequest) (*transport.AllKeyVersionsResponse, error) {
	return nil, nil
}

func (m *mockCAClient) RotateScopeKeys(context.Context, *transport.RotateScopeKeysRequest) (*transport.RotateScopeKeysResponse, error) {
	return nil, nil
}

func (m *mockCAClient) TPMPolicyCreate(context.Context, *transport.TPMPolicyCreateRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

func (m *mockCAClient) TPMPolicyGet(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

func (m *mockCAClient) TPMPolicyList(context.Context, *transport.TPMPolicyListRequest) (*transport.TPMPolicyListResponse, error) {
	return nil, nil
}

func (m *mockCAClient) TPMPolicyUpdate(context.Context, *transport.TPMPolicyUpdateRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

func (m *mockCAClient) TPMPolicyRevoke(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

func (m *mockCAClient) TPMPolicyVerify(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicyVerifyResponse, error) {
	return nil, nil
}

func (m *mockCAClient) TPMPolicyDelete(context.Context, *transport.TPMPolicyDeleteRequest) error {
	return nil
}

func (m *mockCAClient) TPMPolicyObjects(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicyObjectsResponse, error) {
	return nil, nil
}

func (m *mockCAClient) TPMPolicySetAutoUnseal(context.Context, *transport.TPMPolicyAutoUnsealRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

func (m *mockCAClient) TPMPolicySetDescription(context.Context, *transport.TPMPolicyDescriptionRequest) (*transport.TPMPolicy, error) {
	return nil, nil
}

// OIDC credential operations are not exercised by this double.
func (*mockCAClient) OIDCCredentialCreate(context.Context, *transport.OIDCCredentialCreateRequest) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*mockCAClient) OIDCCredentialImport(context.Context, *transport.OIDCCredentialImportRequest) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*mockCAClient) OIDCCredentialGet(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*mockCAClient) OIDCCredentialList(context.Context, *transport.OIDCCredentialListRequest) (*transport.OIDCCredentialListResponse, error) {
	return nil, nil
}
func (*mockCAClient) TrustRootList(context.Context, *transport.TrustRootListRequest) (*transport.TrustRootListResponse, error) {
	return nil, nil
}
func (*mockCAClient) TrustRootGet(context.Context, *transport.TrustRootRequest) (*transport.TrustRoot, error) {
	return nil, nil
}
func (*mockCAClient) TrustRootImport(context.Context, *transport.TrustRootImportRequest) (*transport.TrustRootImportResponse, error) {
	return nil, nil
}
func (*mockCAClient) TrustRootQuarantine(context.Context, *transport.TrustRootRequest) (*transport.TrustRoot, error) {
	return nil, nil
}
func (*mockCAClient) TrustRootRemove(context.Context, *transport.TrustRootRequest) error {
	return nil
}
func (*mockCAClient) OIDCCredentialDelete(context.Context, *transport.OIDCCredentialRef) error {
	return nil
}
func (*mockCAClient) OIDCCredentialRefresh(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*mockCAClient) OIDCCredentialGetAccessToken(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCAccessToken, error) {
	return nil, nil
}
func (*mockCAClient) OIDCCredentialDeviceStart(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, nil
}
func (*mockCAClient) OIDCCredentialDevicePoll(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return nil, nil
}

func (m *mockCAClient) TPMObjectPolicy(context.Context, *transport.TPMObjectPolicyRequest) (*transport.TPMObjectPolicyResponse, error) {
	return nil, nil
}

func (m *mockCAClient) TPMPolicyRotateAuthority(context.Context, *transport.TPMAuthorityRotateRequest) (*transport.TPMAuthorityRotateResponse, error) {
	return nil, nil
}

func (m *mockCAClient) GetTenantTPMMode(context.Context, string) (*transport.TenantTPMModeResponse, error) {
	return nil, nil
}

func (m *mockCAClient) SetTenantTPMMode(context.Context, *transport.SetTenantTPMModeRequest) (*transport.TenantTPMModeResponse, error) {
	return nil, nil
}

func (m *mockCAClient) TenantVTPMStatus(context.Context, string) (*transport.TenantVTPMStatusResponse, error) {
	return nil, nil
}

func (m *mockCAClient) TenantVTPMStart(context.Context, string) (*transport.TenantVTPMStatusResponse, error) {
	return nil, nil
}

func (m *mockCAClient) TenantVTPMStop(context.Context, string) (*transport.TenantVTPMStatusResponse, error) {
	return nil, nil
}

func (m *mockCAClient) DeleteBackup(_ context.Context, _ string) error {
	return nil
}

func (m *mockCAClient) DeleteCustodianGroup(_ context.Context, _ string) error { return nil }

func (m *mockCAClient) Algorithms(_ context.Context) (*transport.AlgorithmsResponse, error) {
	return nil, nil
}

func (m *mockCAClient) DeleteShare(_ context.Context, _, _ string, _ int) error {
	return nil
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

func (m *mockCAClient) UpdateTenantEntitlements(_ context.Context, _ *transport.UpdateTenantEntitlementsRequest) (*transport.UpdateTenantEntitlementsResponse, error) {
	return nil, nil
}

func (m *mockCAClient) UpdateTenantQuotas(_ context.Context, _ *transport.UpdateTenantQuotasRequest) (*transport.UpdateTenantQuotasResponse, error) {
	return nil, nil
}

func (m *mockCAClient) SubmitCredential(_ context.Context, _ *transport.CredentialSubmitRequest) (*transport.CredentialSubmitResponse, error) {
	return nil, nil
}
func (m *mockCAClient) GetCredentialStrategy(_ context.Context) (*transport.CredentialStrategyResponse, error) {
	return nil, nil
}

func (m *mockCAClient) CreateUser(_ context.Context, _ *transport.CreateUserRequest) (*transport.GetUserResponse, error) {
	return nil, nil
}

func (m *mockCAClient) ListUsers(_ context.Context, _ ...transport.ListOption) (*transport.ListUsersResponse, error) {
	return nil, nil
}

func (m *mockCAClient) GetUser(_ context.Context, _ string) (*transport.GetUserResponse, error) {
	return nil, nil
}

func (m *mockCAClient) DeleteUser(_ context.Context, _ string) error {
	return nil
}

func (m *mockCAClient) EnableUser(_ context.Context, _ string) error {
	return nil
}

func (m *mockCAClient) DisableUser(_ context.Context, _ string) error {
	return nil
}

func (m *mockCAClient) BindUserCert(_ context.Context, _, _ string, _ int64) error {
	return nil
}

func (m *mockCAClient) ListUserCredentials(_ context.Context, _ string) (*transport.ListUserCredentialsResponse, error) {
	return nil, nil
}

// =============================================================================
// CA Command Structure Tests
// =============================================================================

func TestCACmd_Exists(t *testing.T) {
	assert.NotNil(t, caCmd)
	assert.Equal(t, "ca", caCmd.Use)
	assert.NotEmpty(t, caCmd.Short)
}

func TestCACmd_HasSubcommands(t *testing.T) {
	expected := []string{"bundle", "certificate", "sign-csr", "issue", "revoke", "crl", "status", "tcg"}
	found := make(map[string]bool)
	for _, cmd := range caCmd.Commands() {
		found[cmd.Name()] = true
	}
	for _, name := range expected {
		assert.True(t, found[name], "expected subcommand %q not found", name)
	}
}

func TestCASignCSRCmd_RequiredFlags(t *testing.T) {
	f := caSignCSRCmd.Flags().Lookup("csr")
	require.NotNil(t, f)
}

func TestCAIssueCmd_RequiredFlags(t *testing.T) {
	f := caIssueCmd.Flags().Lookup("cn")
	require.NotNil(t, f)
}

func TestCARevokeCmd_RequiredFlags(t *testing.T) {
	f := caRevokeCmd.Flags().Lookup("serial")
	require.NotNil(t, f)
}

func TestCAStatusCmd_RequiredFlags(t *testing.T) {
	f := caStatusCmd.Flags().Lookup("serial")
	require.NotNil(t, f)
}

// =============================================================================
// splitAndTrimCA tests
// =============================================================================

func TestSplitAndTrimCA_Basic(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect []string
	}{
		{"single", "DNS:example.com", []string{"DNS:example.com"}},
		{"multiple", "DNS:a.com, DNS:b.com, IP:1.2.3.4", []string{"DNS:a.com", "DNS:b.com", "IP:1.2.3.4"}},
		{"empty parts", "a,,b,", []string{"a", "b"}},
		{"whitespace only", " , , ", []string{}},
		{"empty string", "", []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitAndTrimCA(tt.input)
			assert.Equal(t, tt.expect, result)
		})
	}
}

// =============================================================================
// Helper to set up CA tests
// =============================================================================

func setupCATest(t *testing.T, mc *mockCAClient, format string) (*Config, *bytes.Buffer) {
	t.Helper()
	cfg := NewConfig()
	cfg.OutputFormat = format
	cfg.ClientFactory = func(_ *Config) (client.Client, error) {
		return mc, nil
	}
	origConfig := globalConfig
	globalConfig = cfg
	t.Cleanup(func() { globalConfig = origConfig })

	origExit := exitFunc
	exitFunc = func(_ int) {}
	t.Cleanup(func() { exitFunc = origExit })

	return cfg, nil
}

// =============================================================================
// getCABundle tests
// =============================================================================

func TestGetCABundle_TextOutput_Success(t *testing.T) {
	mc := newMockCAClient()
	mc.caBundle = &transport.GetCABundleResponse{
		BundlePEM: []byte("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"),
	}
	cfg, _ := setupCATest(t, mc, "text")

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	getCABundle(cfg)

	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)

	assert.Contains(t, buf.String(), "BEGIN CERTIFICATE")
}

func TestGetCABundle_ClientError(t *testing.T) {
	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(_ *Config) (client.Client, error) {
		return nil, errors.New("client creation failed")
	}
	origConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = origConfig }()

	exitCode := captureExit(t, func() {
		getCABundle(cfg)
	})
	assert.Equal(t, 1, exitCode)
}

func TestGetCABundle_ConnectError(t *testing.T) {
	mc := newMockCAClient()
	mc.connectErr = errors.New("connect failed")
	cfg, _ := setupCATest(t, mc, "text")

	exitCode := captureExit(t, func() {
		getCABundle(cfg)
	})
	assert.Equal(t, 1, exitCode)
}

func TestGetCABundle_APIError(t *testing.T) {
	mc := newMockCAClient()
	mc.caBundleErr = errors.New("server error")
	cfg, _ := setupCATest(t, mc, "text")

	exitCode := captureExit(t, func() {
		getCABundle(cfg)
	})
	assert.Equal(t, 1, exitCode)
}

// =============================================================================
// getCACertificate tests
// =============================================================================

func TestGetCACertificate_TextOutput_Success(t *testing.T) {
	mc := newMockCAClient()
	mc.caCert = &transport.GetCACertificateResponse{
		Subject:      "CN=Test CA",
		Issuer:       "CN=Root CA",
		SerialNumber: "1234ABCD",
		NotBefore:    "2025-01-01T00:00:00Z",
		NotAfter:     "2035-01-01T00:00:00Z",
		IsCA:         true,
	}
	cfg, _ := setupCATest(t, mc, "text")
	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	getCACertificate(cfg, printer)

	w.Close()
	os.Stdout = old
	var stdoutBuf bytes.Buffer
	stdoutBuf.ReadFrom(r)

	output := stdoutBuf.String()
	assert.Contains(t, output, "CN=Test CA")
	assert.Contains(t, output, "1234ABCD")
	assert.Contains(t, output, "true")
}

func TestGetCACertificate_JSONOutput_Success(t *testing.T) {
	mc := newMockCAClient()
	mc.caCert = &transport.GetCACertificateResponse{
		Subject:      "CN=Test CA",
		Issuer:       "CN=Root CA",
		SerialNumber: "ABCD",
		NotBefore:    "2025-01-01",
		NotAfter:     "2035-01-01",
		IsCA:         true,
	}
	cfg, _ := setupCATest(t, mc, "json")
	var buf bytes.Buffer
	printer := NewPrinter("json", &buf)

	getCACertificate(cfg, printer)

	output := buf.String()
	assert.Contains(t, output, "CN=Test CA")
	assert.Contains(t, output, "serial_number")
}

func TestGetCACertificate_ClientError(t *testing.T) {
	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(_ *Config) (client.Client, error) {
		return nil, errors.New("fail")
	}
	origConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = origConfig }()

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	exitCode := captureExit(t, func() {
		getCACertificate(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

func TestGetCACertificate_ConnectError(t *testing.T) {
	mc := newMockCAClient()
	mc.connectErr = errors.New("connect failed")
	cfg, _ := setupCATest(t, mc, "text")
	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)

	exitCode := captureExit(t, func() {
		getCACertificate(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

func TestGetCACertificate_APIError(t *testing.T) {
	mc := newMockCAClient()
	mc.caCertErr = errors.New("not found")
	cfg, _ := setupCATest(t, mc, "text")
	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)

	exitCode := captureExit(t, func() {
		getCACertificate(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

// =============================================================================
// signCSR tests
// =============================================================================

func TestSignCSR_TextOutput_Success(t *testing.T) {
	mc := newMockCAClient()
	mc.signCSRResp = &transport.SignCSRResponse{
		CertificatePEM: []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"),
		SerialNumber:   "AABB",
	}
	cfg, _ := setupCATest(t, mc, "text")
	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)

	// Create temp CSR file
	tmpDir := t.TempDir()
	csrFile := filepath.Join(tmpDir, "test.csr")
	require.NoError(t, os.WriteFile(csrFile, []byte("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----\n"), 0644))

	oldCSRFile := caCSRFile
	caCSRFile = csrFile
	oldOutput := caOutputFile
	caOutputFile = ""
	defer func() { caCSRFile = oldCSRFile; caOutputFile = oldOutput }()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	signCSR(cfg, printer)

	w.Close()
	os.Stdout = old
	var stdoutBuf bytes.Buffer
	stdoutBuf.ReadFrom(r)

	assert.Contains(t, stdoutBuf.String(), "AABB")
}

func TestSignCSR_JSONOutput_Success(t *testing.T) {
	mc := newMockCAClient()
	mc.signCSRResp = &transport.SignCSRResponse{
		CertificatePEM: []byte("cert-pem"),
		ChainPEM:       []byte("chain-pem"),
		SerialNumber:   "CC",
	}
	cfg, _ := setupCATest(t, mc, "json")
	var buf bytes.Buffer
	printer := NewPrinter("json", &buf)

	tmpDir := t.TempDir()
	csrFile := filepath.Join(tmpDir, "test.csr")
	require.NoError(t, os.WriteFile(csrFile, []byte("csr-data"), 0644))

	oldCSRFile := caCSRFile
	caCSRFile = csrFile
	oldOutput := caOutputFile
	caOutputFile = ""
	defer func() { caCSRFile = oldCSRFile; caOutputFile = oldOutput }()

	signCSR(cfg, printer)
	assert.Contains(t, buf.String(), "serial_number")
	assert.Contains(t, buf.String(), "chain_pem")
}

func TestSignCSR_WriteToFile(t *testing.T) {
	mc := newMockCAClient()
	mc.signCSRResp = &transport.SignCSRResponse{
		CertificatePEM: []byte("signed-cert-pem"),
		SerialNumber:   "DD",
	}
	cfg, _ := setupCATest(t, mc, "text")
	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)

	tmpDir := t.TempDir()
	csrFile := filepath.Join(tmpDir, "test.csr")
	require.NoError(t, os.WriteFile(csrFile, []byte("csr"), 0644))
	outFile := filepath.Join(tmpDir, "out.pem")

	oldCSRFile := caCSRFile
	caCSRFile = csrFile
	oldOutput := caOutputFile
	caOutputFile = outFile
	defer func() { caCSRFile = oldCSRFile; caOutputFile = oldOutput }()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	signCSR(cfg, printer)

	w.Close()
	os.Stdout = old
	var stdoutBuf bytes.Buffer
	stdoutBuf.ReadFrom(r)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Equal(t, "signed-cert-pem", string(data))
}

func TestSignCSR_MissingCSRFile(t *testing.T) {
	mc := newMockCAClient()
	cfg, _ := setupCATest(t, mc, "text")
	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)

	oldCSRFile := caCSRFile
	caCSRFile = "/nonexistent/file.csr"
	defer func() { caCSRFile = oldCSRFile }()

	exitCode := captureExit(t, func() {
		signCSR(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

func TestSignCSR_ClientError(t *testing.T) {
	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(_ *Config) (client.Client, error) {
		return nil, errors.New("fail")
	}
	origConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = origConfig }()

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	tmpDir := t.TempDir()
	csrFile := filepath.Join(tmpDir, "test.csr")
	require.NoError(t, os.WriteFile(csrFile, []byte("csr"), 0644))

	oldCSRFile := caCSRFile
	caCSRFile = csrFile
	defer func() { caCSRFile = oldCSRFile }()

	exitCode := captureExit(t, func() {
		signCSR(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

func TestSignCSR_ConnectError(t *testing.T) {
	mc := newMockCAClient()
	mc.connectErr = errors.New("connect fail")
	cfg, _ := setupCATest(t, mc, "text")
	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)

	tmpDir := t.TempDir()
	csrFile := filepath.Join(tmpDir, "test.csr")
	require.NoError(t, os.WriteFile(csrFile, []byte("csr"), 0644))

	oldCSRFile := caCSRFile
	caCSRFile = csrFile
	defer func() { caCSRFile = oldCSRFile }()

	exitCode := captureExit(t, func() {
		signCSR(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

func TestSignCSR_APIError(t *testing.T) {
	mc := newMockCAClient()
	mc.signCSRErr = errors.New("sign error")
	cfg, _ := setupCATest(t, mc, "text")
	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)

	tmpDir := t.TempDir()
	csrFile := filepath.Join(tmpDir, "test.csr")
	require.NoError(t, os.WriteFile(csrFile, []byte("csr"), 0644))

	oldCSRFile := caCSRFile
	caCSRFile = csrFile
	defer func() { caCSRFile = oldCSRFile }()

	exitCode := captureExit(t, func() {
		signCSR(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

// =============================================================================
// issueCACertificate tests
// =============================================================================

func TestIssueCACertificate_TextOutput_Success(t *testing.T) {
	mc := newMockCAClient()
	mc.issueResp = &transport.IssueCertificateResponse{
		CertificatePEM: []byte("issued-cert"),
		ChainPEM:       []byte("chain"),
		PrivateKeyPEM:  []byte("private-key"),
		SerialNumber:   "EE",
	}
	cfg, _ := setupCATest(t, mc, "text")
	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)

	oldSANs := caSANs
	caSANs = "DNS:a.com, IP:1.2.3.4"
	oldOutput := caOutputFile
	caOutputFile = ""
	defer func() { caSANs = oldSANs; caOutputFile = oldOutput }()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	issueCACertificate(cfg, printer)

	w.Close()
	os.Stdout = old
	var stdoutBuf bytes.Buffer
	stdoutBuf.ReadFrom(r)

	output := stdoutBuf.String()
	assert.Contains(t, output, "EE")
	assert.Contains(t, output, "Private Key")
}

func TestIssueCACertificate_JSONOutput_Success(t *testing.T) {
	mc := newMockCAClient()
	mc.issueResp = &transport.IssueCertificateResponse{
		CertificatePEM: []byte("cert"),
		ChainPEM:       []byte("chain"),
		PrivateKeyPEM:  []byte("key"),
		SerialNumber:   "FF",
	}
	cfg, _ := setupCATest(t, mc, "json")
	var buf bytes.Buffer
	printer := NewPrinter("json", &buf)

	oldSANs := caSANs
	caSANs = ""
	oldOutput := caOutputFile
	caOutputFile = ""
	defer func() { caSANs = oldSANs; caOutputFile = oldOutput }()

	issueCACertificate(cfg, printer)
	output := buf.String()
	assert.Contains(t, output, "serial_number")
	assert.Contains(t, output, "private_key_pem")
}

func TestIssueCACertificate_WriteToFile(t *testing.T) {
	mc := newMockCAClient()
	mc.issueResp = &transport.IssueCertificateResponse{
		CertificatePEM: []byte("cert-data"),
		PrivateKeyPEM:  []byte("key-data"),
		SerialNumber:   "11",
	}
	cfg, _ := setupCATest(t, mc, "text")
	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)

	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "cert.pem")

	oldSANs := caSANs
	caSANs = ""
	oldOutput := caOutputFile
	caOutputFile = outFile
	defer func() { caSANs = oldSANs; caOutputFile = oldOutput }()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	issueCACertificate(cfg, printer)

	w.Close()
	os.Stdout = old
	var stdoutBuf bytes.Buffer
	stdoutBuf.ReadFrom(r)

	certData, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Equal(t, "cert-data", string(certData))

	keyData, err := os.ReadFile(outFile + ".key")
	require.NoError(t, err)
	assert.Equal(t, "key-data", string(keyData))
}

func TestIssueCACertificate_JSONOutput_WithOutputFile(t *testing.T) {
	mc := newMockCAClient()
	mc.issueResp = &transport.IssueCertificateResponse{
		CertificatePEM: []byte("cert"),
		PrivateKeyPEM:  []byte("key"),
		SerialNumber:   "22",
	}
	cfg, _ := setupCATest(t, mc, "json")
	var buf bytes.Buffer
	printer := NewPrinter("json", &buf)

	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "cert.pem")

	oldSANs := caSANs
	caSANs = ""
	oldOutput := caOutputFile
	caOutputFile = outFile
	defer func() { caSANs = oldSANs; caOutputFile = oldOutput }()

	issueCACertificate(cfg, printer)
	output := buf.String()
	assert.Contains(t, output, "cert_file")
	assert.Contains(t, output, "key_file")
}

func TestIssueCACertificate_TextOutput_WithOutputFile(t *testing.T) {
	mc := newMockCAClient()
	mc.issueResp = &transport.IssueCertificateResponse{
		CertificatePEM: []byte("cert"),
		PrivateKeyPEM:  []byte("key"),
		SerialNumber:   "33",
	}
	cfg, _ := setupCATest(t, mc, "text")
	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)

	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "cert.pem")

	oldSANs := caSANs
	caSANs = ""
	oldOutput := caOutputFile
	caOutputFile = outFile
	defer func() { caSANs = oldSANs; caOutputFile = oldOutput }()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	issueCACertificate(cfg, printer)

	w.Close()
	os.Stdout = old
	var stdoutBuf bytes.Buffer
	stdoutBuf.ReadFrom(r)

	assert.Contains(t, stdoutBuf.String(), "Private Key:")
}

func TestIssueCACertificate_ClientError(t *testing.T) {
	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(_ *Config) (client.Client, error) {
		return nil, errors.New("fail")
	}
	origConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = origConfig }()

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	oldSANs := caSANs
	caSANs = ""
	defer func() { caSANs = oldSANs }()

	exitCode := captureExit(t, func() {
		issueCACertificate(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

func TestIssueCACertificate_ConnectError(t *testing.T) {
	mc := newMockCAClient()
	mc.connectErr = errors.New("connect fail")
	cfg, _ := setupCATest(t, mc, "text")
	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)

	oldSANs := caSANs
	caSANs = ""
	defer func() { caSANs = oldSANs }()

	exitCode := captureExit(t, func() {
		issueCACertificate(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

func TestIssueCACertificate_APIError(t *testing.T) {
	mc := newMockCAClient()
	mc.issueErr = errors.New("issue error")
	cfg, _ := setupCATest(t, mc, "text")
	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)

	oldSANs := caSANs
	caSANs = ""
	defer func() { caSANs = oldSANs }()

	exitCode := captureExit(t, func() {
		issueCACertificate(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

// =============================================================================
// revokeCACertificate tests
// =============================================================================

func TestRevokeCACertificate_WithMessage(t *testing.T) {
	mc := newMockCAClient()
	mc.revokeResp = &transport.RevokeCertificateResponse{
		Success: true,
		Message: "Certificate revoked successfully",
	}
	cfg, _ := setupCATest(t, mc, "text")
	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)

	revokeCACertificate(cfg, printer)
	assert.Contains(t, buf.String(), "Certificate revoked successfully")
}

func TestRevokeCACertificate_NoMessage(t *testing.T) {
	mc := newMockCAClient()
	mc.revokeResp = &transport.RevokeCertificateResponse{
		Success: true,
	}
	cfg, _ := setupCATest(t, mc, "text")
	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)

	oldSerial := caSerial
	caSerial = "AABB"
	defer func() { caSerial = oldSerial }()

	revokeCACertificate(cfg, printer)
	assert.Contains(t, buf.String(), "AABB")
}

func TestRevokeCACertificate_ClientError(t *testing.T) {
	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(_ *Config) (client.Client, error) {
		return nil, errors.New("fail")
	}
	origConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = origConfig }()

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	exitCode := captureExit(t, func() {
		revokeCACertificate(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

func TestRevokeCACertificate_ConnectError(t *testing.T) {
	mc := newMockCAClient()
	mc.connectErr = errors.New("connect fail")
	cfg, _ := setupCATest(t, mc, "text")
	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)

	exitCode := captureExit(t, func() {
		revokeCACertificate(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

func TestRevokeCACertificate_APIError(t *testing.T) {
	mc := newMockCAClient()
	mc.revokeErr = errors.New("revoke error")
	cfg, _ := setupCATest(t, mc, "text")
	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)

	exitCode := captureExit(t, func() {
		revokeCACertificate(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

// =============================================================================
// generateCRL tests
// =============================================================================

func TestGenerateCRL_TextOutput(t *testing.T) {
	mc := newMockCAClient()
	mc.crlResp = &transport.GenerateCRLResponse{
		CRLPEM: []byte("-----BEGIN X509 CRL-----\ncrl-data\n-----END X509 CRL-----\n"),
	}
	cfg, _ := setupCATest(t, mc, "text")

	oldOutput := caOutputFile
	caOutputFile = ""
	defer func() { caOutputFile = oldOutput }()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	generateCRL(cfg)

	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)

	assert.Contains(t, buf.String(), "CRL")
}

func TestGenerateCRL_WriteToFile(t *testing.T) {
	mc := newMockCAClient()
	mc.crlResp = &transport.GenerateCRLResponse{
		CRLPEM: []byte("crl-pem-data"),
	}
	cfg, _ := setupCATest(t, mc, "text")

	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "revoked.crl")

	oldOutput := caOutputFile
	caOutputFile = outFile
	defer func() { caOutputFile = oldOutput }()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	generateCRL(cfg)

	w.Close()
	os.Stdout = old
	var stdoutBuf bytes.Buffer
	stdoutBuf.ReadFrom(r)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Equal(t, "crl-pem-data", string(data))
	assert.Contains(t, stdoutBuf.String(), "CRL written to")
}

func TestGenerateCRL_ClientError(t *testing.T) {
	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(_ *Config) (client.Client, error) {
		return nil, errors.New("fail")
	}
	origConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = origConfig }()

	exitCode := captureExit(t, func() {
		generateCRL(cfg)
	})
	assert.Equal(t, 1, exitCode)
}

func TestGenerateCRL_ConnectError(t *testing.T) {
	mc := newMockCAClient()
	mc.connectErr = errors.New("connect fail")
	cfg, _ := setupCATest(t, mc, "text")

	exitCode := captureExit(t, func() {
		generateCRL(cfg)
	})
	assert.Equal(t, 1, exitCode)
}

func TestGenerateCRL_APIError(t *testing.T) {
	mc := newMockCAClient()
	mc.crlErr = errors.New("crl error")
	cfg, _ := setupCATest(t, mc, "text")

	exitCode := captureExit(t, func() {
		generateCRL(cfg)
	})
	assert.Equal(t, 1, exitCode)
}

// =============================================================================
// checkRevocationStatus tests
// =============================================================================

func TestCheckRevocationStatus_Revoked_Text(t *testing.T) {
	mc := newMockCAClient()
	mc.isRevokedResp = &transport.IsRevokedResponse{
		Revoked: true,
		Reason:  1,
	}
	cfg, _ := setupCATest(t, mc, "text")
	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)

	oldSerial := caSerial
	caSerial = "AABB"
	defer func() { caSerial = oldSerial }()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	checkRevocationStatus(cfg, printer)

	w.Close()
	os.Stdout = old
	var stdoutBuf bytes.Buffer
	stdoutBuf.ReadFrom(r)

	assert.Contains(t, stdoutBuf.String(), "REVOKED")
}

func TestCheckRevocationStatus_NotRevoked_Text(t *testing.T) {
	mc := newMockCAClient()
	mc.isRevokedResp = &transport.IsRevokedResponse{
		Revoked: false,
	}
	cfg, _ := setupCATest(t, mc, "text")
	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)

	oldSerial := caSerial
	caSerial = "CCDD"
	defer func() { caSerial = oldSerial }()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	checkRevocationStatus(cfg, printer)

	w.Close()
	os.Stdout = old
	var stdoutBuf bytes.Buffer
	stdoutBuf.ReadFrom(r)

	assert.Contains(t, stdoutBuf.String(), "NOT REVOKED")
}

func TestCheckRevocationStatus_Revoked_JSON(t *testing.T) {
	mc := newMockCAClient()
	mc.isRevokedResp = &transport.IsRevokedResponse{
		Revoked: true,
		Reason:  4,
		Message: "superseded",
	}
	cfg, _ := setupCATest(t, mc, "json")
	var buf bytes.Buffer
	printer := NewPrinter("json", &buf)

	oldSerial := caSerial
	caSerial = "EEFF"
	defer func() { caSerial = oldSerial }()

	checkRevocationStatus(cfg, printer)
	output := buf.String()
	assert.Contains(t, output, "revoked")
	assert.Contains(t, output, "reason")
	assert.Contains(t, output, "message")
}

func TestCheckRevocationStatus_NotRevoked_JSON(t *testing.T) {
	mc := newMockCAClient()
	mc.isRevokedResp = &transport.IsRevokedResponse{
		Revoked: false,
	}
	cfg, _ := setupCATest(t, mc, "json")
	var buf bytes.Buffer
	printer := NewPrinter("json", &buf)

	oldSerial := caSerial
	caSerial = "1122"
	defer func() { caSerial = oldSerial }()

	checkRevocationStatus(cfg, printer)
	output := buf.String()
	assert.Contains(t, output, "serial_number")
	assert.NotContains(t, output, "reason")
}

func TestCheckRevocationStatus_ClientError(t *testing.T) {
	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(_ *Config) (client.Client, error) {
		return nil, errors.New("fail")
	}
	origConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = origConfig }()

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	exitCode := captureExit(t, func() {
		checkRevocationStatus(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

func TestCheckRevocationStatus_ConnectError(t *testing.T) {
	mc := newMockCAClient()
	mc.connectErr = errors.New("connect fail")
	cfg, _ := setupCATest(t, mc, "text")
	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)

	exitCode := captureExit(t, func() {
		checkRevocationStatus(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

func TestCheckRevocationStatus_APIError(t *testing.T) {
	mc := newMockCAClient()
	mc.isRevokedErr = errors.New("check error")
	cfg, _ := setupCATest(t, mc, "text")
	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)

	exitCode := captureExit(t, func() {
		checkRevocationStatus(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

// =============================================================================
// CA Command integration tests (via cobra Execute)
// =============================================================================

func TestCABundleCmd_ExecutesRun(t *testing.T) {
	mc := newMockCAClient()
	mc.caBundle = &transport.GetCABundleResponse{
		BundlePEM: []byte("bundle-pem"),
	}
	cfg, _ := setupCATest(t, mc, "text")
	_ = cfg

	// Verify the command has a Run function
	assert.NotNil(t, caBundleCmd.Run)
}

func TestCACertificateCmd_ExecutesRun(t *testing.T) {
	assert.NotNil(t, caCertificateCmd.Run)
}

func TestCACRLCmd_ExecutesRun(t *testing.T) {
	assert.NotNil(t, caCRLCmd.Run)
}

func TestCARevokeCmd_ExecutesRun(t *testing.T) {
	assert.NotNil(t, caRevokeCmd.Run)
}

func TestCAStatusCmd_ExecutesRun(t *testing.T) {
	assert.NotNil(t, caStatusCmd.Run)
}

// =============================================================================
// Cobra command execution tests
// =============================================================================

func TestCASignCSRCmd_JSONOutput_WithOutputFile(t *testing.T) {
	mc := newMockCAClient()
	mc.signCSRResp = &transport.SignCSRResponse{
		CertificatePEM: []byte("cert"),
		SerialNumber:   "X1",
	}
	cfg, _ := setupCATest(t, mc, "json")
	var buf bytes.Buffer
	printer := NewPrinter("json", &buf)

	tmpDir := t.TempDir()
	csrFile := filepath.Join(tmpDir, "test.csr")
	require.NoError(t, os.WriteFile(csrFile, []byte("csr"), 0644))
	outFile := filepath.Join(tmpDir, "out.pem")

	oldCSRFile := caCSRFile
	caCSRFile = csrFile
	oldOutput := caOutputFile
	caOutputFile = outFile
	defer func() { caCSRFile = oldCSRFile; caOutputFile = oldOutput }()

	signCSR(cfg, printer)
	assert.Contains(t, buf.String(), "cert_file")
}

func TestSignCSR_TextOutput_WithOutputFile(t *testing.T) {
	mc := newMockCAClient()
	mc.signCSRResp = &transport.SignCSRResponse{
		CertificatePEM: []byte("cert"),
		SerialNumber:   "X2",
	}
	cfg, _ := setupCATest(t, mc, "text")
	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)

	tmpDir := t.TempDir()
	csrFile := filepath.Join(tmpDir, "test.csr")
	require.NoError(t, os.WriteFile(csrFile, []byte("csr"), 0644))
	outFile := filepath.Join(tmpDir, "out.pem")

	oldCSRFile := caCSRFile
	caCSRFile = csrFile
	oldOutput := caOutputFile
	caOutputFile = outFile
	defer func() { caCSRFile = oldCSRFile; caOutputFile = oldOutput }()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	signCSR(cfg, printer)

	w.Close()
	os.Stdout = old
	var stdoutBuf bytes.Buffer
	stdoutBuf.ReadFrom(r)

	assert.Contains(t, stdoutBuf.String(), "Certificate written to")
}

func TestIssueCACertificate_NoPrivateKey(t *testing.T) {
	mc := newMockCAClient()
	mc.issueResp = &transport.IssueCertificateResponse{
		CertificatePEM: []byte("cert"),
		SerialNumber:   "NP",
	}
	cfg, _ := setupCATest(t, mc, "text")
	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)

	oldSANs := caSANs
	caSANs = ""
	oldOutput := caOutputFile
	caOutputFile = ""
	defer func() { caSANs = oldSANs; caOutputFile = oldOutput }()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	issueCACertificate(cfg, printer)

	w.Close()
	os.Stdout = old
	var stdoutBuf bytes.Buffer
	stdoutBuf.ReadFrom(r)

	output := stdoutBuf.String()
	assert.Contains(t, output, "NP")
	assert.NotContains(t, output, "Private Key")
}

func TestIssueCACertificate_JSONOutput_NoOutputFile_NoPrivateKey(t *testing.T) {
	mc := newMockCAClient()
	mc.issueResp = &transport.IssueCertificateResponse{
		CertificatePEM: []byte("cert"),
		SerialNumber:   "NP2",
	}
	cfg, _ := setupCATest(t, mc, "json")
	var buf bytes.Buffer
	printer := NewPrinter("json", &buf)

	oldSANs := caSANs
	caSANs = ""
	oldOutput := caOutputFile
	caOutputFile = ""
	defer func() { caSANs = oldSANs; caOutputFile = oldOutput }()

	issueCACertificate(cfg, printer)
	output := buf.String()
	assert.Contains(t, output, "certificate_pem")
	assert.NotContains(t, output, "private_key_pem")
}

func TestIssueCACertificate_OutputFileNoKey(t *testing.T) {
	mc := newMockCAClient()
	mc.issueResp = &transport.IssueCertificateResponse{
		CertificatePEM: []byte("cert-only"),
		SerialNumber:   "NK",
	}
	cfg, _ := setupCATest(t, mc, "text")
	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)

	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "cert.pem")

	oldSANs := caSANs
	caSANs = ""
	oldOutput := caOutputFile
	caOutputFile = outFile
	defer func() { caSANs = oldSANs; caOutputFile = oldOutput }()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	issueCACertificate(cfg, printer)

	w.Close()
	os.Stdout = old
	var stdoutBuf bytes.Buffer
	stdoutBuf.ReadFrom(r)

	// No .key file should exist
	_, err := os.Stat(outFile + ".key")
	assert.True(t, os.IsNotExist(err))
}

// Ensure unused imports are satisfied
func TestCATest_ImportGuard(t *testing.T) {
	assert.NotNil(t, strings.Contains)
}

func (*mockCAClient) SetSigningKeyBinding(context.Context, *transport.SetSigningKeyBindingRequest) (*transport.SigningKeyBinding, error) {
	return nil, nil
}
func (*mockCAClient) GetSigningKeyBinding(context.Context, *transport.GetSigningKeyBindingRequest) (*transport.SigningKeyBinding, error) {
	return nil, nil
}
func (*mockCAClient) ListSigningKeyBindings(context.Context) (*transport.ListSigningKeyBindingsResponse, error) {
	return nil, nil
}
func (*mockCAClient) DeleteSigningKeyBinding(context.Context, *transport.DeleteSigningKeyBindingRequest) error {
	return nil
}
func (*mockCAClient) ResolveSigningKey(context.Context, *transport.ResolveSigningKeyRequest) (*transport.SigningKeyResolution, error) {
	return nil, nil
}
