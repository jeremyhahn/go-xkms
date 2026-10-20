// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package embedded

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errMock is a reusable mock error.
var errMock = errors.New("mock error")

// mockService implements XKMSServicer with minimal stubs to test the
// embedded transport delegation pattern. Every method returns a
// deterministic response or errMock based on the shouldFail field.
type mockService struct {
	shouldFail bool
}

func (m *mockService) Health(_ context.Context) (string, string, error) {
	if m.shouldFail {
		return "", "", errMock
	}
	return "healthy", "1.0.0", nil
}

func (m *mockService) ListBackends(_ context.Context, _ ...transport.ListOption) ([]transport.BackendInfo, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return []transport.BackendInfo{{ID: "software"}}, nil
}

func (m *mockService) GetBackend(_ context.Context, id string) (*transport.BackendInfo, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.BackendInfo{ID: id}, nil
}

func (m *mockService) GenerateKey(_ context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.GenerateKeyResponse{KeyID: req.KeyID}, nil
}

func (m *mockService) ListKeys(_ context.Context, _ string, _ ...transport.ListOption) (*transport.ListKeysResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.ListKeysResponse{}, nil
}

func (m *mockService) GetKey(_ context.Context, _, keyID string) (*transport.GetKeyResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.GetKeyResponse{KeyInfo: transport.KeyInfo{KeyID: keyID}}, nil
}

func (m *mockService) DeleteKey(_ context.Context, _, _ string) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) ImportKey(_ context.Context, _ *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.ImportKeyResponse{Success: true}, nil
}

func (m *mockService) ExportKey(_ context.Context, _ *transport.ExportKeyRequest) (*transport.ExportKeyResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.ExportKeyResponse{}, nil
}

func (m *mockService) RotateKey(_ context.Context, _ *transport.RotateKeyRequest) (*transport.RotateKeyResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.RotateKeyResponse{Success: true}, nil
}

func (m *mockService) CreateOTAImageKey(_ context.Context, req *transport.OTAImageKeyRequest) (*transport.GenerateKeyResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.GenerateKeyResponse{KeyID: "ota-image-" + req.BoardID}, nil
}

func (m *mockService) RotateOTAImageKey(_ context.Context, req *transport.OTAImageKeyRequest) (*transport.RotateKeyResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.RotateKeyResponse{Success: true, KeyID: "ota-image-" + req.BoardID, KeyVersion: 2}, nil
}

func (m *mockService) SignOTAImage(_ context.Context, _ *transport.OTAImageSignRequest) (*transport.SignResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.SignResponse{Signature: []byte("sig"), KeyVersion: 2}, nil
}

func (m *mockService) GetImportParameters(_ context.Context, _ *transport.GetImportParametersRequest) (*transport.GetImportParametersResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.GetImportParametersResponse{}, nil
}

func (m *mockService) CopyKey(_ context.Context, _ *transport.CopyKeyRequest) (*transport.CopyKeyResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.CopyKeyResponse{Success: true}, nil
}

func (m *mockService) ExportKeyMaterial(_ context.Context, _ *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.ExportKeyMaterialResponse{}, nil
}

func (m *mockService) WrapKey(_ context.Context, _ *transport.WrapKeyRequest) (*transport.WrapKeyResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.WrapKeyResponse{}, nil
}

func (m *mockService) UnwrapKey(_ context.Context, _ *transport.UnwrapKeyRequest) (*transport.UnwrapKeyResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.UnwrapKeyResponse{}, nil
}

func (m *mockService) WrapKeyByID(_ context.Context, _ *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.WrapKeyByIDResponse{}, nil
}

func (m *mockService) UnwrapKeyByID(_ context.Context, _ *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.UnwrapKeyByIDResponse{}, nil
}

func (m *mockService) Sign(_ context.Context, _ *transport.SignRequest) (*transport.SignResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.SignResponse{Signature: []byte("sig")}, nil
}

func (m *mockService) Verify(_ context.Context, _ *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.VerifyResponse{Valid: true}, nil
}

func (m *mockService) Encrypt(_ context.Context, _ *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.EncryptResponse{Ciphertext: []byte("ct")}, nil
}

func (m *mockService) Decrypt(_ context.Context, _ *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.DecryptResponse{Plaintext: []byte("pt")}, nil
}

func (m *mockService) EncryptAsym(_ context.Context, _ *transport.EncryptAsymRequest) (*transport.EncryptAsymResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.EncryptAsymResponse{}, nil
}

func (m *mockService) DeriveKey(_ context.Context, _ *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.DeriveKeyResponse{}, nil
}

func (m *mockService) DeriveKeyECDH(_ context.Context, _ *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.DeriveKeyECDHResponse{}, nil
}

func (m *mockService) AttestKey(_ context.Context, _ *transport.AttestKeyRequest) (*transport.AttestKeyResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.AttestKeyResponse{}, nil
}

func (m *mockService) GetCertificate(_ context.Context, _, _ string) (*transport.GetCertificateResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.GetCertificateResponse{}, nil
}

func (m *mockService) SaveCertificate(_ context.Context, _ *transport.SaveCertificateRequest) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) DeleteCertificate(_ context.Context, _, _ string) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) CertificateExists(_ context.Context, _, _ string) (bool, error) {
	if m.shouldFail {
		return false, errMock
	}
	return true, nil
}

func (m *mockService) ListCertificates(_ context.Context, _ string, _ ...transport.ListOption) (*transport.ListCertificatesResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.ListCertificatesResponse{}, nil
}

func (m *mockService) SaveCertificateChain(_ context.Context, _ *transport.SaveCertificateChainRequest) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) GetCertificateChain(_ context.Context, _, _ string) (*transport.GetCertificateChainResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.GetCertificateChainResponse{}, nil
}

func (m *mockService) GetTLSCertificate(_ context.Context, _, _ string) (*transport.GetTLSCertificateResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.GetTLSCertificateResponse{}, nil
}

func (m *mockService) Seal(_ context.Context, _ *transport.SealRequest) (*transport.SealResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.SealResponse{}, nil
}

func (m *mockService) Unseal(_ context.Context, _ *transport.UnsealRequest) (*transport.UnsealResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.UnsealResponse{Plaintext: []byte("data")}, nil
}

func (m *mockService) CanSeal(_ context.Context, _ string) (*transport.CanSealResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.CanSealResponse{CanSeal: true}, nil
}

func (m *mockService) BeginRegistration(_ context.Context, _ *transport.BeginRegistrationRequest) (*transport.BeginRegistrationResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.BeginRegistrationResponse{}, nil
}

func (m *mockService) FinishRegistration(_ context.Context, _ *transport.FinishRegistrationRequest) (*transport.FinishRegistrationResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.FinishRegistrationResponse{}, nil
}

func (m *mockService) BeginAuthentication(_ context.Context, _ *transport.BeginAuthenticationRequest) (*transport.BeginAuthenticationResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.BeginAuthenticationResponse{}, nil
}

func (m *mockService) FinishAuthentication(_ context.Context, _ *transport.FinishAuthenticationRequest) (*transport.FinishAuthenticationResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.FinishAuthenticationResponse{}, nil
}

func (m *mockService) GetInvite(_ context.Context, _ *transport.GetInviteRequest) (*transport.GetInviteResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.GetInviteResponse{}, nil
}

func (m *mockService) BeginInviteRegistration(_ context.Context, _ *transport.BeginInviteRegistrationRequest) (*transport.BeginInviteRegistrationResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.BeginInviteRegistrationResponse{}, nil
}

func (m *mockService) FinishInviteRegistration(_ context.Context, _ *transport.FinishInviteRegistrationRequest) (*transport.FinishInviteRegistrationResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.FinishInviteRegistrationResponse{}, nil
}

func (m *mockService) ActivateInvitePIV(_ context.Context, _ *transport.ActivateInvitePIVRequest) (*transport.ActivateInvitePIVResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.ActivateInvitePIVResponse{}, nil
}

func (m *mockService) GetCABundle(_ context.Context, _ *transport.GetCABundleRequest) (*transport.GetCABundleResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.GetCABundleResponse{}, nil
}

func (m *mockService) GetCACertificate(_ context.Context, _ *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.GetCACertificateResponse{}, nil
}

func (m *mockService) SignCSR(_ context.Context, _ *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.SignCSRResponse{}, nil
}

func (m *mockService) IssueCertificate(_ context.Context, _ *transport.IssueCertificateRequest) (*transport.IssueCertificateResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.IssueCertificateResponse{}, nil
}

func (m *mockService) RevokeCertificate(_ context.Context, _ *transport.RevokeCertificateRequest) (*transport.RevokeCertificateResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.RevokeCertificateResponse{}, nil
}

func (m *mockService) GenerateCRL(_ context.Context, _ *transport.GenerateCRLRequest) (*transport.GenerateCRLResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.GenerateCRLResponse{}, nil
}

func (m *mockService) IsRevoked(_ context.Context, _ *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.IsRevokedResponse{}, nil
}

func (m *mockService) IssueEKCertificate(_ context.Context, _ *transport.IssueEKCertificateRequest) (*transport.IssueEKCertificateResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.IssueEKCertificateResponse{}, nil
}

func (m *mockService) IssueAKCertificate(_ context.Context, _ *transport.IssueAKCertificateRequest) (*transport.IssueAKCertificateResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.IssueAKCertificateResponse{}, nil
}

func (m *mockService) SignTCGCSR(_ context.Context, _ *transport.SignTCGCSRRequest) (*transport.SignTCGCSRResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.SignTCGCSRResponse{}, nil
}

func (m *mockService) EnrollDevice(_ context.Context, _ *transport.EnrollDeviceRequest) (*transport.EnrollDeviceResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.EnrollDeviceResponse{}, nil
}

func (m *mockService) IssueLAKCertificate(_ context.Context, _ *transport.IssueLAKCertificateRequest) (*transport.IssueLAKCertificateResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.IssueLAKCertificateResponse{}, nil
}

func (m *mockService) ListPIVSlots(_ context.Context, _ *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.ListPIVSlotsResponse{}, nil
}

func (m *mockService) GetPIVCertificate(_ context.Context, _ *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.GetPIVCertificateResponse{}, nil
}

func (m *mockService) StorePIVCertificate(_ context.Context, _ *transport.StorePIVCertificateRequest) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) DeletePIVCertificate(_ context.Context, _ *transport.DeletePIVCertificateRequest) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) GeneratePIVKey(_ context.Context, _ *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.GeneratePIVKeyResponse{}, nil
}

func (m *mockService) ImportPIVCertificate(_ context.Context, _ *transport.StorePIVCertificateRequest) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) ExportPIVCertificate(_ context.Context, _ *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.GetPIVCertificateResponse{}, nil
}

func (m *mockService) GeneratePIVCSR(_ context.Context, _ *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.GeneratePIVCSRResponse{}, nil
}

func (m *mockService) BarrierSeal(_ context.Context) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) BootstrapListenerKeys(_ context.Context) (*transport.BootstrapListenerKeysResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.BootstrapListenerKeysResponse{}, nil
}

func (m *mockService) BarrierDeleteRecoveryKeys(_ context.Context) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) SetSOPIN(_ context.Context, _ *transport.SetSOPINRequest) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) SetUserPIN(_ context.Context, _ *transport.SetUserPINRequest) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) ChangeSOPIN(_ context.Context, _ *transport.ChangeSOPINRequest) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) ChangeUserPIN(_ context.Context, _ *transport.ChangeUserPINRequest) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) VerifySOPIN(_ context.Context, _ *transport.VerifySOPINRequest) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) VerifyUserPIN(_ context.Context, _ *transport.VerifyUserPINRequest) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) GetLockoutStatus(_ context.Context) (*transport.LockoutStatusResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.LockoutStatusResponse{}, nil
}

func (m *mockService) ResetLockout(_ context.Context, _ *transport.ResetLockoutRequest) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) PasswordAdd(_ context.Context, _ *transport.PasswordAddRequest) (*transport.PasswordAddResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.PasswordAddResponse{}, nil
}

func (m *mockService) PasswordGet(_ context.Context, _ *transport.PasswordGetRequest) (*transport.PasswordGetResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.PasswordGetResponse{}, nil
}

func (m *mockService) PasswordList(_ context.Context, _ *transport.PasswordListRequest) (*transport.PasswordListResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.PasswordListResponse{}, nil
}

func (m *mockService) PasswordUpdate(_ context.Context, req *transport.PasswordUpdateRequest) (*transport.PasswordGetResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.PasswordGetResponse{ID: req.ID}, nil
}

func (m *mockService) PasswordDelete(_ context.Context, _ *transport.PasswordDeleteRequest) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) PasswordStoreUnlock(_ context.Context, _ *transport.PasswordStoreUnlockRequest) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) PasswordStoreLock(_ context.Context) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) PasswordStoreStatus(_ context.Context) (*transport.PasswordStoreStatusResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.PasswordStoreStatusResponse{}, nil
}

func (m *mockService) PasswordStoreSetAccessMode(_ context.Context, _ *transport.PasswordStoreSetAccessModeRequest) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) PasswordGenerate(_ context.Context, _ *transport.PasswordGenerateRequest) (*transport.PasswordGenerateResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.PasswordGenerateResponse{}, nil
}

func (m *mockService) PasswordVaultStatus(_ context.Context) (*transport.PasswordVaultStatusResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.PasswordVaultStatusResponse{}, nil
}

func (m *mockService) PasswordVaultEnroll(_ context.Context, _ *transport.PasswordVaultEnrollRequest) (*transport.PasswordVaultEnrollResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.PasswordVaultEnrollResponse{}, nil
}

func (m *mockService) PasswordVaultRotate(_ context.Context, _ *transport.PasswordVaultRotateRequest) (*transport.PasswordVaultEnrollResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.PasswordVaultEnrollResponse{}, nil
}

func (m *mockService) PasswordVaultRemoveFactor(_ context.Context, _ *transport.PasswordVaultRemoveFactorRequest) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) PasswordVaultRecover(_ context.Context, _ *transport.PasswordVaultRecoverRequest) (*transport.PasswordVaultEnrollResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.PasswordVaultEnrollResponse{}, nil
}

func (m *mockService) SealStorePut(_ context.Context, _ *transport.SealStorePutRequest) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) SealStoreGet(_ context.Context, _ *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.SealStoreGetResponse{}, nil
}

func (m *mockService) SealStoreDelete(_ context.Context, _ *transport.SealStoreDeleteRequest) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) SealStoreList(_ context.Context) (*transport.SealStoreListResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.SealStoreListResponse{}, nil
}

func (m *mockService) SealStoreReseal(_ context.Context, _ *transport.SealStoreResealRequest) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) SealStoreStatus(_ context.Context) (*transport.SealStoreStatusResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.SealStoreStatusResponse{}, nil
}

func (m *mockService) EscrowKey(_ context.Context, _ *transport.EscrowRequest) ([]*transport.EscrowReceipt, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return []*transport.EscrowReceipt{{}}, nil
}

func (m *mockService) RecoverKey(_ context.Context, _ *transport.RecoverRequest) (*transport.RecoverResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.RecoverResponse{}, nil
}

func (m *mockService) ListEscrowed(_ context.Context) ([]transport.EscrowRecord, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return nil, nil
}

func (m *mockService) RevokeEscrow(_ context.Context, _ string) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) ListKeyVersions(context.Context, *transport.ListKeyVersionsRequest) (*transport.ListKeyVersionsResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.ListKeyVersionsResponse{}, nil
}

func (m *mockService) EnableKeyVersion(context.Context, *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.KeyVersionStateResponse{}, nil
}

func (m *mockService) DisableKeyVersion(context.Context, *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.KeyVersionStateResponse{}, nil
}

func (m *mockService) RetireKeyVersion(context.Context, *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.KeyVersionStateResponse{}, nil
}

func (m *mockService) EnableAllKeyVersions(context.Context, *transport.AllKeyVersionsRequest) (*transport.AllKeyVersionsResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.AllKeyVersionsResponse{}, nil
}

func (m *mockService) DisableAllKeyVersions(context.Context, *transport.AllKeyVersionsRequest) (*transport.AllKeyVersionsResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.AllKeyVersionsResponse{}, nil
}

func (m *mockService) RotateScopeKeys(context.Context, *transport.RotateScopeKeysRequest) (*transport.RotateScopeKeysResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.RotateScopeKeysResponse{}, nil
}

func (m *mockService) TPMPolicyCreate(context.Context, *transport.TPMPolicyCreateRequest) (*transport.TPMPolicy, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.TPMPolicy{}, nil
}

func (m *mockService) TPMPolicyGet(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.TPMPolicy{}, nil
}

func (m *mockService) TPMPolicyList(context.Context, *transport.TPMPolicyListRequest) (*transport.TPMPolicyListResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.TPMPolicyListResponse{}, nil
}

func (m *mockService) TPMPolicyUpdate(context.Context, *transport.TPMPolicyUpdateRequest) (*transport.TPMPolicy, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.TPMPolicy{}, nil
}

func (m *mockService) TPMPolicyRevoke(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.TPMPolicy{}, nil
}

func (m *mockService) TPMPolicyVerify(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicyVerifyResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.TPMPolicyVerifyResponse{}, nil
}

func (m *mockService) TPMPolicyDelete(context.Context, *transport.TPMPolicyDeleteRequest) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) TPMPolicyObjects(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicyObjectsResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.TPMPolicyObjectsResponse{}, nil
}

func (m *mockService) TPMPolicySetAutoUnseal(context.Context, *transport.TPMPolicyAutoUnsealRequest) (*transport.TPMPolicy, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.TPMPolicy{}, nil
}

func (m *mockService) TPMPolicySetDescription(context.Context, *transport.TPMPolicyDescriptionRequest) (*transport.TPMPolicy, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.TPMPolicy{}, nil
}

func (m *mockService) TPMObjectPolicy(context.Context, *transport.TPMObjectPolicyRequest) (*transport.TPMObjectPolicyResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.TPMObjectPolicyResponse{}, nil
}

func (m *mockService) TPMPolicyRotateAuthority(context.Context, *transport.TPMAuthorityRotateRequest) (*transport.TPMAuthorityRotateResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.TPMAuthorityRotateResponse{}, nil
}

func (m *mockService) GetTenantTPMMode(context.Context, string) (*transport.TenantTPMModeResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.TenantTPMModeResponse{}, nil
}

func (m *mockService) SetTenantTPMMode(context.Context, *transport.SetTenantTPMModeRequest) (*transport.TenantTPMModeResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.TenantTPMModeResponse{}, nil
}

func (m *mockService) TenantVTPMStatus(context.Context, string) (*transport.TenantVTPMStatusResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.TenantVTPMStatusResponse{}, nil
}

func (m *mockService) TenantVTPMStart(context.Context, string) (*transport.TenantVTPMStatusResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.TenantVTPMStatusResponse{}, nil
}

func (m *mockService) TenantVTPMStop(context.Context, string) (*transport.TenantVTPMStatusResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.TenantVTPMStatusResponse{}, nil
}

func (m *mockService) DeleteBackup(_ context.Context, _ string) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) DeleteCustodianGroup(_ context.Context, _ string) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) Algorithms(_ context.Context) (*transport.AlgorithmsResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.AlgorithmsResponse{}, nil
}

func (m *mockService) DeleteShare(_ context.Context, _, _ string, _ int) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) CreateTenant(_ context.Context, _ *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.CreateTenantResponse{}, nil
}

func (m *mockService) GetTenant(_ context.Context, _ string) (*transport.GetTenantResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.GetTenantResponse{}, nil
}

func (m *mockService) ListTenants(_ context.Context) (*transport.ListTenantsResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.ListTenantsResponse{}, nil
}

func (m *mockService) DeleteTenant(_ context.Context, _ string) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) UpdateTenantEntitlements(_ context.Context, _ *transport.UpdateTenantEntitlementsRequest) (*transport.UpdateTenantEntitlementsResponse, error) {
	return nil, nil
}

func (m *mockService) UpdateTenantQuotas(_ context.Context, _ *transport.UpdateTenantQuotasRequest) (*transport.UpdateTenantQuotasResponse, error) {
	return nil, nil
}

func (m *mockService) SubmitCredential(_ context.Context, _ *transport.CredentialSubmitRequest) (*transport.CredentialSubmitResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.CredentialSubmitResponse{Status: "accepted"}, nil
}

func (m *mockService) GetCredentialStrategy(_ context.Context) (*transport.CredentialStrategyResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.CredentialStrategyResponse{Strategy: "manual"}, nil
}

func (m *mockService) CreateUser(_ context.Context, _ *transport.CreateUserRequest) (*transport.GetUserResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.GetUserResponse{}, nil
}

func (m *mockService) ListUsers(_ context.Context, _ ...transport.ListOption) (*transport.ListUsersResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.ListUsersResponse{}, nil
}

func (m *mockService) GetUser(_ context.Context, _ string) (*transport.GetUserResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.GetUserResponse{}, nil
}

func (m *mockService) DeleteUser(_ context.Context, _ string) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) EnableUser(_ context.Context, _ string) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) DisableUser(_ context.Context, _ string) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) BindUserCert(_ context.Context, _, _ string, _ int64) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) ListUserCredentials(_ context.Context, _ string) (*transport.ListUserCredentialsResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.ListUserCredentialsResponse{}, nil
}

// --- Constructor tests ---

func TestNew_NilService(t *testing.T) {
	_, err := New(nil)
	require.ErrorIs(t, err, ErrNilService)
}

func TestNew_ValidService(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NotNil(t, tr)
	assert.NotNil(t, tr.Service())
	assert.NotNil(t, tr.Config())
}

func TestNew_WithOptions(t *testing.T) {
	tr, err := New(&mockService{}, transport.WithAddress("test:8080"))
	require.NoError(t, err)
	assert.Equal(t, "test:8080", tr.Config().Address)
}

func TestNew_InvalidOption(t *testing.T) {
	_, err := New(&mockService{}, transport.WithAddress(""))
	require.Error(t, err)
}

func TestNewWithConfig_NilConfig(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	require.NotNil(t, tr)
	assert.NotNil(t, tr.Config())
}

func TestNewWithConfig_CustomConfig(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "custom:9090"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	assert.Equal(t, "custom:9090", tr.Config().Address)
	// Not connected until service is set
	_, err = tr.Health(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestNewWithService(t *testing.T) {
	tr, err := NewWithService(&mockService{})
	require.NoError(t, err)
	require.NotNil(t, tr)
}

func TestSetService_Valid(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)

	err = tr.SetService(&mockService{})
	require.NoError(t, err)
	assert.NotNil(t, tr.Service())
}

func TestSetService_Nil(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)

	err = tr.SetService(nil)
	assert.ErrorIs(t, err, ErrNilService)
}

// --- Connect / Close ---

func TestConnect_NoService(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	assert.ErrorIs(t, tr.Connect(context.Background()), ErrNilService)
}

func TestConnect_WithService(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)

	// Already connected via New, but Connect should still succeed
	assert.NoError(t, tr.Connect(context.Background()))
}

func TestClose(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)

	assert.NoError(t, tr.Close())
	// After close, methods should return ErrNotConnected
	_, err = tr.Health(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

// --- Health ---

func TestHealth_Connected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)

	resp, err := tr.Health(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "healthy", resp.Status)
	assert.Equal(t, "1.0.0", resp.Version)
}

func TestHealth_ServiceError(t *testing.T) {
	tr, err := New(&mockService{shouldFail: true})
	require.NoError(t, err)

	_, err = tr.Health(context.Background())
	assert.ErrorIs(t, err, errMock)
}

func TestHealth_NotConnected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.Close())

	_, err = tr.Health(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

// --- Delegation tests: connected success + not-connected error ---

func TestListBackends_Connected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	resp, err := tr.ListBackends(context.Background())
	require.NoError(t, err)
	assert.Len(t, resp.Backends, 1)
}

func TestListBackends_NotConnected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.Close())
	_, err = tr.ListBackends(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGetBackend_Connected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	resp, err := tr.GetBackend(context.Background(), "software")
	require.NoError(t, err)
	assert.Equal(t, "software", resp.ID)
}

func TestGetBackend_NotConnected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.Close())
	_, err = tr.GetBackend(context.Background(), "software")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGenerateKey_Connected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	resp, err := tr.GenerateKey(context.Background(), &transport.GenerateKeyRequest{KeyID: "test-key"})
	require.NoError(t, err)
	assert.Equal(t, "test-key", resp.KeyID)
}

func TestGenerateKey_NotConnected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.Close())
	_, err = tr.GenerateKey(context.Background(), &transport.GenerateKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDeleteKey_Connected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	resp, err := tr.DeleteKey(context.Background(), "software", "key1")
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestDeleteKey_NotConnected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.Close())
	_, err = tr.DeleteKey(context.Background(), "software", "key1")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDeleteKey_ServiceError(t *testing.T) {
	tr, err := New(&mockService{shouldFail: true})
	require.NoError(t, err)
	_, err = tr.DeleteKey(context.Background(), "software", "key1")
	assert.ErrorIs(t, err, errMock)
}
