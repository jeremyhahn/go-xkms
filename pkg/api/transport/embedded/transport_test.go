// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package embedded

import (
	"context"
	"encoding/json"
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

func (m *mockService) BarrierInitialize(_ context.Context, _ *transport.BarrierInitializeRequest) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) BarrierUnseal(_ context.Context, _ *transport.BarrierUnsealRequest) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) BarrierSeal(_ context.Context) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) BarrierStatus(_ context.Context) (*transport.BarrierStatusResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.BarrierStatusResponse{}, nil
}

func (m *mockService) BootstrapListenerKeys(_ context.Context) (*transport.BootstrapListenerKeysResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.BootstrapListenerKeysResponse{}, nil
}

func (m *mockService) BarrierInitializeShamir(_ context.Context, _ *transport.BarrierInitializeShamirRequest) (*transport.BarrierInitializeShamirResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.BarrierInitializeShamirResponse{}, nil
}

func (m *mockService) BarrierUnsealWithShare(_ context.Context, _ *transport.BarrierUnsealShareRequest) (*transport.BarrierUnsealShareResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.BarrierUnsealShareResponse{}, nil
}

func (m *mockService) BarrierUnsealWithShares(_ context.Context, _ *transport.BarrierUnsealSharesRequest) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) BarrierRekey(_ context.Context, _ *transport.BarrierRekeyRequest) (*transport.BarrierRekeyResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.BarrierRekeyResponse{}, nil
}

func (m *mockService) BarrierGenerateRecoveryKeys(_ context.Context, _ *transport.BarrierGenerateRecoveryKeysRequest) (*transport.BarrierRecoveryKeysResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.BarrierRecoveryKeysResponse{}, nil
}

func (m *mockService) BarrierEnableEncryption(_ context.Context, _ *transport.BarrierEnableEncryptionRequest) (*transport.BarrierEnableEncryptionResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.BarrierEnableEncryptionResponse{}, nil
}

func (m *mockService) BarrierRecoverWithKeys(_ context.Context, _ *transport.BarrierRecoverWithKeysRequest) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) BarrierDeleteRecoveryKeys(_ context.Context) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) BarrierHasRecoveryKeys(_ context.Context) (*transport.BarrierHasRecoveryKeysResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.BarrierHasRecoveryKeysResponse{}, nil
}

func (m *mockService) BarrierGenerateRootToken(_ context.Context, _ *transport.BarrierGenerateRootTokenRequest) (*transport.BarrierRootTokenResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.BarrierRootTokenResponse{}, nil
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

func (m *mockService) PasswordUpdate(_ context.Context, _ *transport.PasswordUpdateRequest) error {
	if m.shouldFail {
		return errMock
	}
	return nil
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

func (m *mockService) TPMPolicyUpdate(context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
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

func (m *mockService) CreateCustodianGroup(_ context.Context, _ *transport.CreateCustodianGroupRequest) (*transport.CreateCustodianGroupResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.CreateCustodianGroupResponse{}, nil
}

func (m *mockService) GetCustodianGroup(_ context.Context, _ string) (*transport.GetCustodianGroupResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.GetCustodianGroupResponse{}, nil
}

func (m *mockService) ListCustodianGroups(_ context.Context) (*transport.ListCustodianGroupsResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.ListCustodianGroupsResponse{}, nil
}

func (m *mockService) DeleteCustodianGroup(_ context.Context, _ string) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) AddCustodianMember(_ context.Context, _ *transport.AddCustodianMemberRequest) (*transport.AddCustodianMemberResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.AddCustodianMemberResponse{}, nil
}

func (m *mockService) RemoveCustodianMember(_ context.Context, _ *transport.RemoveCustodianMemberRequest) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) DistributeShares(_ context.Context, _ *transport.DistributeSharesRequest) (*transport.DistributeSharesResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.DistributeSharesResponse{}, nil
}

func (m *mockService) SubmitShare(_ context.Context, _ *transport.SubmitShareRequest) (*transport.SubmitShareResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.SubmitShareResponse{}, nil
}

func (m *mockService) ListShares(_ context.Context) (*transport.ListSharesResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.ListSharesResponse{}, nil
}

func (m *mockService) Algorithms(_ context.Context) (*transport.AlgorithmsResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.AlgorithmsResponse{}, nil
}

func (m *mockService) GetShare(_ context.Context, _, _ string, _ int) (*transport.ShareInfo, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.ShareInfo{}, nil
}

func (m *mockService) DeleteShare(_ context.Context, _, _ string, _ int) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) GetShareCollectionStatus(_ context.Context, _ string) (*transport.ShareCollectionStatus, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.ShareCollectionStatus{}, nil
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

func (m *mockService) TenantBarrierInit(_ context.Context, _ *transport.TenantBarrierInitRequest) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) TenantBarrierUnseal(_ context.Context, _ *transport.TenantBarrierUnsealRequest) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) TenantBarrierStatus(_ context.Context, _ string) (*transport.TenantBarrierStatusResponse, error) {
	return nil, nil
}

func (m *mockService) UpdateTenantEntitlements(_ context.Context, _ *transport.UpdateTenantEntitlementsRequest) (*transport.UpdateTenantEntitlementsResponse, error) {
	return nil, nil
}

func (m *mockService) UpdateTenantQuotas(_ context.Context, _ *transport.UpdateTenantQuotasRequest) (*transport.UpdateTenantQuotasResponse, error) {
	return nil, nil
}

func (m *mockService) GetInitStatus(_ context.Context) (*transport.InitStatusResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.InitStatusResponse{State: "ready"}, nil
}

func (m *mockService) ClaimCertBegin(_ context.Context, _ *transport.ClaimCertBeginRequest) (*transport.ClaimCertBeginResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.ClaimCertBeginResponse{}, nil
}

func (m *mockService) ClaimCertComplete(_ context.Context, _ *transport.ClaimCertCompleteRequest) (*transport.ClaimCertCompleteResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.ClaimCertCompleteResponse{}, nil
}

func (m *mockService) ClaimShareBegin(_ context.Context, _ *transport.ClaimShareBeginRequest) (*transport.ClaimShareBeginResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.ClaimShareBeginResponse{Nonce: "abcd", Username: "officer"}, nil
}

func (m *mockService) ClaimShareComplete(_ context.Context, _ *transport.ClaimShareCompleteRequest) (*transport.ClaimShareCompleteResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.ClaimShareCompleteResponse{ShareIndex: 1, Share: json.RawMessage(`{}`)}, nil
}

func (m *mockService) SignCSRInit(_ context.Context, _ *transport.SignCSRInitRequest) (*transport.SignCSRInitResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.SignCSRInitResponse{}, nil
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

func (m *mockService) QueryAudit(_ context.Context, filter *transport.AuditFilter) (*transport.AuditPage, error) {
	if m.shouldFail {
		return nil, errMock
	}
	if filter == nil {
		return nil, transport.ErrInvalidRequest
	}
	return &transport.AuditPage{
		Events: []transport.AuditEvent{{Actor: filter.Actor}},
		Total:  1,
	}, nil
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

func TestQueryAudit_Connected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	resp, err := tr.QueryAudit(context.Background(), &transport.AuditFilter{Actor: "alice"})
	require.NoError(t, err)
	require.Len(t, resp.Events, 1)
	assert.Equal(t, "alice", resp.Events[0].Actor)
	assert.Equal(t, 1, resp.Total)
}

func TestQueryAudit_NotConnected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.Close())
	_, err = tr.QueryAudit(context.Background(), &transport.AuditFilter{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestQueryAudit_NilFilterRejected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	resp, err := tr.QueryAudit(context.Background(), nil)
	assert.ErrorIs(t, err, transport.ErrInvalidRequest)
	assert.Nil(t, resp)
}

func TestQueryAudit_ServiceError(t *testing.T) {
	tr, err := New(&mockService{shouldFail: true})
	require.NoError(t, err)
	resp, err := tr.QueryAudit(context.Background(), &transport.AuditFilter{})
	assert.ErrorIs(t, err, errMock)
	assert.Nil(t, resp)
}

func TestDeleteKey_ServiceError(t *testing.T) {
	tr, err := New(&mockService{shouldFail: true})
	require.NoError(t, err)
	_, err = tr.DeleteKey(context.Background(), "software", "key1")
	assert.ErrorIs(t, err, errMock)
}

// Test all not-connected paths for comprehensive coverage.
func TestAllMethods_NotConnected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.Close())
	ctx := context.Background()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"ListKeys", func() error { _, e := tr.ListKeys(ctx, "sw"); return e }},
		{"GetKey", func() error { _, e := tr.GetKey(ctx, "sw", "k"); return e }},
		{"Sign", func() error { _, e := tr.Sign(ctx, &transport.SignRequest{}); return e }},
		{"Verify", func() error { _, e := tr.Verify(ctx, &transport.VerifyRequest{}); return e }},
		{"Encrypt", func() error { _, e := tr.Encrypt(ctx, &transport.EncryptRequest{}); return e }},
		{"Decrypt", func() error { _, e := tr.Decrypt(ctx, &transport.DecryptRequest{}); return e }},
		{"EncryptAsym", func() error { _, e := tr.EncryptAsym(ctx, &transport.EncryptAsymRequest{}); return e }},
		{"DeriveKey", func() error { _, e := tr.DeriveKey(ctx, &transport.DeriveKeyRequest{}); return e }},
		{"DeriveKeyECDH", func() error { _, e := tr.DeriveKeyECDH(ctx, &transport.DeriveKeyECDHRequest{}); return e }},
		{"AttestKey", func() error { _, e := tr.AttestKey(ctx, &transport.AttestKeyRequest{}); return e }},
		{"GetCertificate", func() error { _, e := tr.GetCertificate(ctx, "sw", "k"); return e }},
		{"SaveCertificate", func() error { return tr.SaveCertificate(ctx, &transport.SaveCertificateRequest{}) }},
		{"DeleteCertificate", func() error { return tr.DeleteCertificate(ctx, "sw", "k") }},
		{"CertificateExists", func() error { _, e := tr.CertificateExists(ctx, "sw", "k"); return e }},
		{"ListCertificates", func() error { _, e := tr.ListCertificates(ctx, "sw"); return e }},
		{"SaveCertificateChain", func() error { return tr.SaveCertificateChain(ctx, &transport.SaveCertificateChainRequest{}) }},
		{"GetCertificateChain", func() error { _, e := tr.GetCertificateChain(ctx, "sw", "k"); return e }},
		{"GetTLSCertificate", func() error { _, e := tr.GetTLSCertificate(ctx, "sw", "k"); return e }},
		{"ImportKey", func() error { _, e := tr.ImportKey(ctx, &transport.ImportKeyRequest{}); return e }},
		{"ExportKey", func() error { _, e := tr.ExportKey(ctx, &transport.ExportKeyRequest{}); return e }},
		{"RotateKey", func() error { _, e := tr.RotateKey(ctx, &transport.RotateKeyRequest{}); return e }},
		{"GetImportParameters", func() error { _, e := tr.GetImportParameters(ctx, &transport.GetImportParametersRequest{}); return e }},
		{"WrapKey", func() error { _, e := tr.WrapKey(ctx, &transport.WrapKeyRequest{}); return e }},
		{"UnwrapKey", func() error { _, e := tr.UnwrapKey(ctx, &transport.UnwrapKeyRequest{}); return e }},
		{"CopyKey", func() error { _, e := tr.CopyKey(ctx, &transport.CopyKeyRequest{}); return e }},
		{"ExportKeyMaterial", func() error { _, e := tr.ExportKeyMaterial(ctx, &transport.ExportKeyMaterialRequest{}); return e }},
		{"WrapKeyByID", func() error { _, e := tr.WrapKeyByID(ctx, &transport.WrapKeyByIDRequest{}); return e }},
		{"UnwrapKeyByID", func() error { _, e := tr.UnwrapKeyByID(ctx, &transport.UnwrapKeyByIDRequest{}); return e }},
		{"Seal", func() error { _, e := tr.Seal(ctx, &transport.SealRequest{}); return e }},
		{"Unseal", func() error { _, e := tr.Unseal(ctx, &transport.UnsealRequest{}); return e }},
		{"CanSeal", func() error { _, e := tr.CanSeal(ctx, "sw"); return e }},
		{"BeginRegistration", func() error { _, e := tr.BeginRegistration(ctx, &transport.BeginRegistrationRequest{}); return e }},
		{"FinishRegistration", func() error { _, e := tr.FinishRegistration(ctx, &transport.FinishRegistrationRequest{}); return e }},
		{"BeginAuthentication", func() error { _, e := tr.BeginAuthentication(ctx, &transport.BeginAuthenticationRequest{}); return e }},
		{"FinishAuthentication", func() error { _, e := tr.FinishAuthentication(ctx, &transport.FinishAuthenticationRequest{}); return e }},
		{"GetCABundle", func() error { _, e := tr.GetCABundle(ctx, &transport.GetCABundleRequest{}); return e }},
		{"GetCACertificate", func() error { _, e := tr.GetCACertificate(ctx, &transport.GetCACertificateRequest{}); return e }},
		{"SignCSR", func() error { _, e := tr.SignCSR(ctx, &transport.SignCSRRequest{}); return e }},
		{"IssueCertificate", func() error { _, e := tr.IssueCertificate(ctx, &transport.IssueCertificateRequest{}); return e }},
		{"RevokeCertificate", func() error { _, e := tr.RevokeCertificate(ctx, &transport.RevokeCertificateRequest{}); return e }},
		{"GenerateCRL", func() error { _, e := tr.GenerateCRL(ctx, &transport.GenerateCRLRequest{}); return e }},
		{"IsRevoked", func() error { _, e := tr.IsRevoked(ctx, &transport.IsRevokedRequest{}); return e }},
		{"IssueEKCertificate", func() error { _, e := tr.IssueEKCertificate(ctx, &transport.IssueEKCertificateRequest{}); return e }},
		{"IssueAKCertificate", func() error { _, e := tr.IssueAKCertificate(ctx, &transport.IssueAKCertificateRequest{}); return e }},
		{"SignTCGCSR", func() error { _, e := tr.SignTCGCSR(ctx, &transport.SignTCGCSRRequest{}); return e }},
		{"EnrollDevice", func() error { _, e := tr.EnrollDevice(ctx, &transport.EnrollDeviceRequest{}); return e }},
		{"ListPIVSlots", func() error { _, e := tr.ListPIVSlots(ctx, &transport.ListPIVSlotsRequest{}); return e }},
		{"GetPIVCertificate", func() error { _, e := tr.GetPIVCertificate(ctx, &transport.GetPIVCertificateRequest{}); return e }},
		{"StorePIVCertificate", func() error { return tr.StorePIVCertificate(ctx, &transport.StorePIVCertificateRequest{}) }},
		{"DeletePIVCertificate", func() error { return tr.DeletePIVCertificate(ctx, &transport.DeletePIVCertificateRequest{}) }},
		{"GeneratePIVKey", func() error { _, e := tr.GeneratePIVKey(ctx, &transport.GeneratePIVKeyRequest{}); return e }},
		{"ImportPIVCertificate", func() error { return tr.ImportPIVCertificate(ctx, &transport.StorePIVCertificateRequest{}) }},
		{"ExportPIVCertificate", func() error { _, e := tr.ExportPIVCertificate(ctx, &transport.GetPIVCertificateRequest{}); return e }},
		{"GeneratePIVCSR", func() error { _, e := tr.GeneratePIVCSR(ctx, &transport.GeneratePIVCSRRequest{}); return e }},
		{"BarrierInitialize", func() error { return tr.BarrierInitialize(ctx, &transport.BarrierInitializeRequest{}) }},
		{"BarrierUnseal", func() error { return tr.BarrierUnseal(ctx, &transport.BarrierUnsealRequest{}) }},
		{"BarrierSeal", func() error { return tr.BarrierSeal(ctx) }},
		{"BarrierStatus", func() error { _, e := tr.BarrierStatus(ctx); return e }},
		{"BootstrapListenerKeys", func() error { _, e := tr.BootstrapListenerKeys(ctx); return e }},
		{"BarrierInitializeShamir", func() error {
			_, e := tr.BarrierInitializeShamir(ctx, &transport.BarrierInitializeShamirRequest{})
			return e
		}},
		{"BarrierUnsealWithShare", func() error { _, e := tr.BarrierUnsealWithShare(ctx, &transport.BarrierUnsealShareRequest{}); return e }},
		{"BarrierUnsealWithShares", func() error { return tr.BarrierUnsealWithShares(ctx, &transport.BarrierUnsealSharesRequest{}) }},
		{"BarrierRekey", func() error { _, e := tr.BarrierRekey(ctx, &transport.BarrierRekeyRequest{}); return e }},
		{"BarrierGenerateRecoveryKeys", func() error {
			_, e := tr.BarrierGenerateRecoveryKeys(ctx, &transport.BarrierGenerateRecoveryKeysRequest{})
			return e
		}},
		{"BarrierRecoverWithKeys", func() error { return tr.BarrierRecoverWithKeys(ctx, &transport.BarrierRecoverWithKeysRequest{}) }},
		{"BarrierDeleteRecoveryKeys", func() error { return tr.BarrierDeleteRecoveryKeys(ctx) }},
		{"BarrierHasRecoveryKeys", func() error { _, e := tr.BarrierHasRecoveryKeys(ctx); return e }},
		{"BarrierGenerateRootToken", func() error {
			_, e := tr.BarrierGenerateRootToken(ctx, &transport.BarrierGenerateRootTokenRequest{})
			return e
		}},
		{"SetSOPIN", func() error { return tr.SetSOPIN(ctx, &transport.SetSOPINRequest{}) }},
		{"SetUserPIN", func() error { return tr.SetUserPIN(ctx, &transport.SetUserPINRequest{}) }},
		{"ChangeSOPIN", func() error { return tr.ChangeSOPIN(ctx, &transport.ChangeSOPINRequest{}) }},
		{"ChangeUserPIN", func() error { return tr.ChangeUserPIN(ctx, &transport.ChangeUserPINRequest{}) }},
		{"VerifySOPIN", func() error { return tr.VerifySOPIN(ctx, &transport.VerifySOPINRequest{}) }},
		{"VerifyUserPIN", func() error { return tr.VerifyUserPIN(ctx, &transport.VerifyUserPINRequest{}) }},
		{"GetLockoutStatus", func() error { _, e := tr.GetLockoutStatus(ctx); return e }},
		{"ResetLockout", func() error { return tr.ResetLockout(ctx, &transport.ResetLockoutRequest{}) }},
		{"PasswordAdd", func() error { _, e := tr.PasswordAdd(ctx, &transport.PasswordAddRequest{}); return e }},
		{"PasswordGet", func() error { _, e := tr.PasswordGet(ctx, &transport.PasswordGetRequest{}); return e }},
		{"PasswordList", func() error { _, e := tr.PasswordList(ctx, &transport.PasswordListRequest{}); return e }},
		{"PasswordUpdate", func() error { return tr.PasswordUpdate(ctx, &transport.PasswordUpdateRequest{}) }},
		{"PasswordDelete", func() error { return tr.PasswordDelete(ctx, &transport.PasswordDeleteRequest{}) }},
		{"PasswordStoreUnlock", func() error { return tr.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{}) }},
		{"PasswordStoreLock", func() error { return tr.PasswordStoreLock(ctx) }},
		{"PasswordStoreStatus", func() error { _, e := tr.PasswordStoreStatus(ctx); return e }},
		{"PasswordStoreSetAccessMode", func() error {
			return tr.PasswordStoreSetAccessMode(ctx, &transport.PasswordStoreSetAccessModeRequest{})
		}},
		{"PasswordGenerate", func() error { _, e := tr.PasswordGenerate(ctx, &transport.PasswordGenerateRequest{}); return e }},
		{"SealStorePut", func() error { return tr.SealStorePut(ctx, &transport.SealStorePutRequest{}) }},
		{"SealStoreGet", func() error { _, e := tr.SealStoreGet(ctx, &transport.SealStoreGetRequest{}); return e }},
		{"SealStoreDelete", func() error { return tr.SealStoreDelete(ctx, &transport.SealStoreDeleteRequest{}) }},
		{"SealStoreList", func() error { _, e := tr.SealStoreList(ctx); return e }},
		{"SealStoreReseal", func() error { return tr.SealStoreReseal(ctx, &transport.SealStoreResealRequest{}) }},
		{"SealStoreStatus", func() error { _, e := tr.SealStoreStatus(ctx); return e }},
		{"ListKeyVersions", func() error { _, e := tr.ListKeyVersions(ctx, &transport.ListKeyVersionsRequest{}); return e }},
		{"EnableKeyVersion", func() error { _, e := tr.EnableKeyVersion(ctx, &transport.KeyVersionRequest{}); return e }},
		{"DisableKeyVersion", func() error { _, e := tr.DisableKeyVersion(ctx, &transport.KeyVersionRequest{}); return e }},
		{"RetireKeyVersion", func() error { _, e := tr.RetireKeyVersion(ctx, &transport.KeyVersionRequest{}); return e }},
		{"EnableAllKeyVersions", func() error { _, e := tr.EnableAllKeyVersions(ctx, &transport.AllKeyVersionsRequest{}); return e }},
		{"DisableAllKeyVersions", func() error { _, e := tr.DisableAllKeyVersions(ctx, &transport.AllKeyVersionsRequest{}); return e }},
		{"RotateScopeKeys", func() error { _, e := tr.RotateScopeKeys(ctx, &transport.RotateScopeKeysRequest{}); return e }},
		{"TPMPolicyCreate", func() error { _, e := tr.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{}); return e }},
		{"TPMPolicyGet", func() error { _, e := tr.TPMPolicyGet(ctx, &transport.TPMPolicyRequest{}); return e }},
		{"TPMPolicyList", func() error { _, e := tr.TPMPolicyList(ctx, &transport.TPMPolicyListRequest{}); return e }},
		{"TPMPolicyUpdate", func() error { _, e := tr.TPMPolicyUpdate(ctx, &transport.TPMPolicyRequest{}); return e }},
		{"TPMPolicyRevoke", func() error { _, e := tr.TPMPolicyRevoke(ctx, &transport.TPMPolicyRequest{}); return e }},
		{"TPMPolicyVerify", func() error { _, e := tr.TPMPolicyVerify(ctx, &transport.TPMPolicyRequest{}); return e }},
		{"TPMPolicyDelete", func() error { return tr.TPMPolicyDelete(ctx, &transport.TPMPolicyDeleteRequest{}) }},
		{"TPMPolicyObjects", func() error { _, e := tr.TPMPolicyObjects(ctx, &transport.TPMPolicyRequest{}); return e }},
		{"TPMPolicySetAutoUnseal", func() error {
			_, e := tr.TPMPolicySetAutoUnseal(ctx, &transport.TPMPolicyAutoUnsealRequest{})
			return e
		}},
		{"TPMObjectPolicy", func() error { _, e := tr.TPMObjectPolicy(ctx, &transport.TPMObjectPolicyRequest{}); return e }},
		{"TPMPolicyRotateAuthority", func() error {
			_, e := tr.TPMPolicyRotateAuthority(ctx, &transport.TPMAuthorityRotateRequest{})
			return e
		}},
		{"GetTenantTPMMode", func() error { _, e := tr.GetTenantTPMMode(ctx, "tenant-a"); return e }},
		{"SetTenantTPMMode", func() error { _, e := tr.SetTenantTPMMode(ctx, &transport.SetTenantTPMModeRequest{}); return e }},
		{"TenantVTPMStatus", func() error { _, e := tr.TenantVTPMStatus(ctx, "tenant-a"); return e }},
		{"TenantVTPMStart", func() error { _, e := tr.TenantVTPMStart(ctx, "tenant-a"); return e }},
		{"TenantVTPMStop", func() error { _, e := tr.TenantVTPMStop(ctx, "tenant-a"); return e }},
		{"CreateCustodianGroup", func() error { _, e := tr.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{}); return e }},
		{"GetCustodianGroup", func() error { _, e := tr.GetCustodianGroup(ctx, "g1"); return e }},
		{"ListCustodianGroups", func() error { _, e := tr.ListCustodianGroups(ctx); return e }},
		{"DeleteCustodianGroup", func() error { return tr.DeleteCustodianGroup(ctx, "g1") }},
		{"AddCustodianMember", func() error { _, e := tr.AddCustodianMember(ctx, &transport.AddCustodianMemberRequest{}); return e }},
		{"RemoveCustodianMember", func() error { return tr.RemoveCustodianMember(ctx, &transport.RemoveCustodianMemberRequest{}) }},
		{"DistributeShares", func() error { _, e := tr.DistributeShares(ctx, &transport.DistributeSharesRequest{}); return e }},
		{"SubmitShare", func() error { _, e := tr.SubmitShare(ctx, &transport.SubmitShareRequest{}); return e }},
		{"ListShares", func() error { _, e := tr.ListShares(ctx); return e }},
		{"GetShareCollectionStatus", func() error { _, e := tr.GetShareCollectionStatus(ctx, "g1"); return e }},
		{"CreateTenant", func() error { _, e := tr.CreateTenant(ctx, &transport.CreateTenantRequest{}); return e }},
		{"GetTenant", func() error { _, e := tr.GetTenant(ctx, "t1"); return e }},
		{"ListTenants", func() error { _, e := tr.ListTenants(ctx); return e }},
		{"DeleteTenant", func() error { return tr.DeleteTenant(ctx, "t1") }},
		{"TenantBarrierInit", func() error { return tr.TenantBarrierInit(ctx, &transport.TenantBarrierInitRequest{}) }},
		{"TenantBarrierUnseal", func() error { return tr.TenantBarrierUnseal(ctx, &transport.TenantBarrierUnsealRequest{}) }},
		{"GetInitStatus", func() error { _, e := tr.GetInitStatus(ctx); return e }},
		{"ClaimCertBegin", func() error { _, e := tr.ClaimCertBegin(ctx, &transport.ClaimCertBeginRequest{}); return e }},
		{"ClaimCertComplete", func() error { _, e := tr.ClaimCertComplete(ctx, &transport.ClaimCertCompleteRequest{}); return e }},
		{"ClaimShareBegin", func() error { _, e := tr.ClaimShareBegin(ctx, &transport.ClaimShareBeginRequest{}); return e }},
		{"SignCSRInit", func() error { _, e := tr.SignCSRInit(ctx, &transport.SignCSRInitRequest{}); return e }},
		{"SubmitCredential", func() error { _, e := tr.SubmitCredential(ctx, &transport.CredentialSubmitRequest{}); return e }},
		{"GetCredentialStrategy", func() error { _, e := tr.GetCredentialStrategy(ctx); return e }},
		{"QueryAudit", func() error { _, e := tr.QueryAudit(ctx, &transport.AuditFilter{}); return e }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			assert.ErrorIs(t, err, ErrNotConnected, "expected ErrNotConnected for %s", tt.name)
		})
	}
}

// TestAllMethods_Connected verifies that every method delegates to the
// underlying service when connected.
func TestAllMethods_Connected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	ctx := context.Background()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"ListKeys", func() error { _, e := tr.ListKeys(ctx, "sw"); return e }},
		{"GetKey", func() error { _, e := tr.GetKey(ctx, "sw", "k"); return e }},
		{"Sign", func() error { _, e := tr.Sign(ctx, &transport.SignRequest{}); return e }},
		{"Verify", func() error { _, e := tr.Verify(ctx, &transport.VerifyRequest{}); return e }},
		{"Encrypt", func() error { _, e := tr.Encrypt(ctx, &transport.EncryptRequest{}); return e }},
		{"Decrypt", func() error { _, e := tr.Decrypt(ctx, &transport.DecryptRequest{}); return e }},
		{"EncryptAsym", func() error { _, e := tr.EncryptAsym(ctx, &transport.EncryptAsymRequest{}); return e }},
		{"DeriveKey", func() error { _, e := tr.DeriveKey(ctx, &transport.DeriveKeyRequest{}); return e }},
		{"DeriveKeyECDH", func() error { _, e := tr.DeriveKeyECDH(ctx, &transport.DeriveKeyECDHRequest{}); return e }},
		{"AttestKey", func() error { _, e := tr.AttestKey(ctx, &transport.AttestKeyRequest{}); return e }},
		{"GetCertificate", func() error { _, e := tr.GetCertificate(ctx, "sw", "k"); return e }},
		{"SaveCertificate", func() error { return tr.SaveCertificate(ctx, &transport.SaveCertificateRequest{}) }},
		{"DeleteCertificate", func() error { return tr.DeleteCertificate(ctx, "sw", "k") }},
		{"CertificateExists", func() error { _, e := tr.CertificateExists(ctx, "sw", "k"); return e }},
		{"ListCertificates", func() error { _, e := tr.ListCertificates(ctx, "sw"); return e }},
		{"SaveCertificateChain", func() error { return tr.SaveCertificateChain(ctx, &transport.SaveCertificateChainRequest{}) }},
		{"GetCertificateChain", func() error { _, e := tr.GetCertificateChain(ctx, "sw", "k"); return e }},
		{"GetTLSCertificate", func() error { _, e := tr.GetTLSCertificate(ctx, "sw", "k"); return e }},
		{"ImportKey", func() error { _, e := tr.ImportKey(ctx, &transport.ImportKeyRequest{}); return e }},
		{"ExportKey", func() error { _, e := tr.ExportKey(ctx, &transport.ExportKeyRequest{}); return e }},
		{"RotateKey", func() error { _, e := tr.RotateKey(ctx, &transport.RotateKeyRequest{}); return e }},
		{"GetImportParameters", func() error { _, e := tr.GetImportParameters(ctx, &transport.GetImportParametersRequest{}); return e }},
		{"WrapKey", func() error { _, e := tr.WrapKey(ctx, &transport.WrapKeyRequest{}); return e }},
		{"UnwrapKey", func() error { _, e := tr.UnwrapKey(ctx, &transport.UnwrapKeyRequest{}); return e }},
		{"CopyKey", func() error { _, e := tr.CopyKey(ctx, &transport.CopyKeyRequest{}); return e }},
		{"ExportKeyMaterial", func() error { _, e := tr.ExportKeyMaterial(ctx, &transport.ExportKeyMaterialRequest{}); return e }},
		{"WrapKeyByID", func() error { _, e := tr.WrapKeyByID(ctx, &transport.WrapKeyByIDRequest{}); return e }},
		{"UnwrapKeyByID", func() error { _, e := tr.UnwrapKeyByID(ctx, &transport.UnwrapKeyByIDRequest{}); return e }},
		{"Seal", func() error { _, e := tr.Seal(ctx, &transport.SealRequest{}); return e }},
		{"Unseal", func() error { _, e := tr.Unseal(ctx, &transport.UnsealRequest{}); return e }},
		{"CanSeal", func() error { _, e := tr.CanSeal(ctx, "sw"); return e }},
		{"BeginRegistration", func() error { _, e := tr.BeginRegistration(ctx, &transport.BeginRegistrationRequest{}); return e }},
		{"FinishRegistration", func() error { _, e := tr.FinishRegistration(ctx, &transport.FinishRegistrationRequest{}); return e }},
		{"BeginAuthentication", func() error { _, e := tr.BeginAuthentication(ctx, &transport.BeginAuthenticationRequest{}); return e }},
		{"FinishAuthentication", func() error { _, e := tr.FinishAuthentication(ctx, &transport.FinishAuthenticationRequest{}); return e }},
		{"GetCABundle", func() error { _, e := tr.GetCABundle(ctx, &transport.GetCABundleRequest{}); return e }},
		{"GetCACertificate", func() error { _, e := tr.GetCACertificate(ctx, &transport.GetCACertificateRequest{}); return e }},
		{"SignCSR", func() error { _, e := tr.SignCSR(ctx, &transport.SignCSRRequest{}); return e }},
		{"IssueCertificate", func() error { _, e := tr.IssueCertificate(ctx, &transport.IssueCertificateRequest{}); return e }},
		{"RevokeCertificate", func() error { _, e := tr.RevokeCertificate(ctx, &transport.RevokeCertificateRequest{}); return e }},
		{"GenerateCRL", func() error { _, e := tr.GenerateCRL(ctx, &transport.GenerateCRLRequest{}); return e }},
		{"IsRevoked", func() error { _, e := tr.IsRevoked(ctx, &transport.IsRevokedRequest{}); return e }},
		{"IssueEKCertificate", func() error { _, e := tr.IssueEKCertificate(ctx, &transport.IssueEKCertificateRequest{}); return e }},
		{"IssueAKCertificate", func() error { _, e := tr.IssueAKCertificate(ctx, &transport.IssueAKCertificateRequest{}); return e }},
		{"SignTCGCSR", func() error { _, e := tr.SignTCGCSR(ctx, &transport.SignTCGCSRRequest{}); return e }},
		{"EnrollDevice", func() error { _, e := tr.EnrollDevice(ctx, &transport.EnrollDeviceRequest{}); return e }},
		{"ListPIVSlots", func() error { _, e := tr.ListPIVSlots(ctx, &transport.ListPIVSlotsRequest{}); return e }},
		{"GetPIVCertificate", func() error { _, e := tr.GetPIVCertificate(ctx, &transport.GetPIVCertificateRequest{}); return e }},
		{"StorePIVCertificate", func() error { return tr.StorePIVCertificate(ctx, &transport.StorePIVCertificateRequest{}) }},
		{"DeletePIVCertificate", func() error { return tr.DeletePIVCertificate(ctx, &transport.DeletePIVCertificateRequest{}) }},
		{"GeneratePIVKey", func() error { _, e := tr.GeneratePIVKey(ctx, &transport.GeneratePIVKeyRequest{}); return e }},
		{"ImportPIVCertificate", func() error { return tr.ImportPIVCertificate(ctx, &transport.StorePIVCertificateRequest{}) }},
		{"ExportPIVCertificate", func() error { _, e := tr.ExportPIVCertificate(ctx, &transport.GetPIVCertificateRequest{}); return e }},
		{"GeneratePIVCSR", func() error { _, e := tr.GeneratePIVCSR(ctx, &transport.GeneratePIVCSRRequest{}); return e }},
		{"BarrierInitialize", func() error { return tr.BarrierInitialize(ctx, &transport.BarrierInitializeRequest{}) }},
		{"BarrierUnseal", func() error { return tr.BarrierUnseal(ctx, &transport.BarrierUnsealRequest{}) }},
		{"BarrierSeal", func() error { return tr.BarrierSeal(ctx) }},
		{"BarrierStatus", func() error { _, e := tr.BarrierStatus(ctx); return e }},
		{"BootstrapListenerKeys", func() error { _, e := tr.BootstrapListenerKeys(ctx); return e }},
		{"BarrierInitializeShamir", func() error {
			_, e := tr.BarrierInitializeShamir(ctx, &transport.BarrierInitializeShamirRequest{})
			return e
		}},
		{"BarrierUnsealWithShare", func() error { _, e := tr.BarrierUnsealWithShare(ctx, &transport.BarrierUnsealShareRequest{}); return e }},
		{"BarrierUnsealWithShares", func() error { return tr.BarrierUnsealWithShares(ctx, &transport.BarrierUnsealSharesRequest{}) }},
		{"BarrierRekey", func() error { _, e := tr.BarrierRekey(ctx, &transport.BarrierRekeyRequest{}); return e }},
		{"BarrierGenerateRecoveryKeys", func() error {
			_, e := tr.BarrierGenerateRecoveryKeys(ctx, &transport.BarrierGenerateRecoveryKeysRequest{})
			return e
		}},
		{"BarrierRecoverWithKeys", func() error { return tr.BarrierRecoverWithKeys(ctx, &transport.BarrierRecoverWithKeysRequest{}) }},
		{"BarrierDeleteRecoveryKeys", func() error { return tr.BarrierDeleteRecoveryKeys(ctx) }},
		{"BarrierHasRecoveryKeys", func() error { _, e := tr.BarrierHasRecoveryKeys(ctx); return e }},
		{"BarrierGenerateRootToken", func() error {
			_, e := tr.BarrierGenerateRootToken(ctx, &transport.BarrierGenerateRootTokenRequest{})
			return e
		}},
		{"SetSOPIN", func() error { return tr.SetSOPIN(ctx, &transport.SetSOPINRequest{}) }},
		{"SetUserPIN", func() error { return tr.SetUserPIN(ctx, &transport.SetUserPINRequest{}) }},
		{"ChangeSOPIN", func() error { return tr.ChangeSOPIN(ctx, &transport.ChangeSOPINRequest{}) }},
		{"ChangeUserPIN", func() error { return tr.ChangeUserPIN(ctx, &transport.ChangeUserPINRequest{}) }},
		{"VerifySOPIN", func() error { return tr.VerifySOPIN(ctx, &transport.VerifySOPINRequest{}) }},
		{"VerifyUserPIN", func() error { return tr.VerifyUserPIN(ctx, &transport.VerifyUserPINRequest{}) }},
		{"GetLockoutStatus", func() error { _, e := tr.GetLockoutStatus(ctx); return e }},
		{"ResetLockout", func() error { return tr.ResetLockout(ctx, &transport.ResetLockoutRequest{}) }},
		{"PasswordAdd", func() error { _, e := tr.PasswordAdd(ctx, &transport.PasswordAddRequest{}); return e }},
		{"PasswordGet", func() error { _, e := tr.PasswordGet(ctx, &transport.PasswordGetRequest{}); return e }},
		{"PasswordList", func() error { _, e := tr.PasswordList(ctx, &transport.PasswordListRequest{}); return e }},
		{"PasswordUpdate", func() error { return tr.PasswordUpdate(ctx, &transport.PasswordUpdateRequest{}) }},
		{"PasswordDelete", func() error { return tr.PasswordDelete(ctx, &transport.PasswordDeleteRequest{}) }},
		{"PasswordStoreUnlock", func() error { return tr.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{}) }},
		{"PasswordStoreLock", func() error { return tr.PasswordStoreLock(ctx) }},
		{"PasswordStoreStatus", func() error { _, e := tr.PasswordStoreStatus(ctx); return e }},
		{"PasswordStoreSetAccessMode", func() error {
			return tr.PasswordStoreSetAccessMode(ctx, &transport.PasswordStoreSetAccessModeRequest{})
		}},
		{"PasswordGenerate", func() error { _, e := tr.PasswordGenerate(ctx, &transport.PasswordGenerateRequest{}); return e }},
		{"SealStorePut", func() error { return tr.SealStorePut(ctx, &transport.SealStorePutRequest{}) }},
		{"SealStoreGet", func() error { _, e := tr.SealStoreGet(ctx, &transport.SealStoreGetRequest{}); return e }},
		{"SealStoreDelete", func() error { return tr.SealStoreDelete(ctx, &transport.SealStoreDeleteRequest{}) }},
		{"SealStoreList", func() error { _, e := tr.SealStoreList(ctx); return e }},
		{"SealStoreReseal", func() error { return tr.SealStoreReseal(ctx, &transport.SealStoreResealRequest{}) }},
		{"SealStoreStatus", func() error { _, e := tr.SealStoreStatus(ctx); return e }},
		{"ListKeyVersions", func() error { _, e := tr.ListKeyVersions(ctx, &transport.ListKeyVersionsRequest{}); return e }},
		{"EnableKeyVersion", func() error { _, e := tr.EnableKeyVersion(ctx, &transport.KeyVersionRequest{}); return e }},
		{"DisableKeyVersion", func() error { _, e := tr.DisableKeyVersion(ctx, &transport.KeyVersionRequest{}); return e }},
		{"RetireKeyVersion", func() error { _, e := tr.RetireKeyVersion(ctx, &transport.KeyVersionRequest{}); return e }},
		{"EnableAllKeyVersions", func() error { _, e := tr.EnableAllKeyVersions(ctx, &transport.AllKeyVersionsRequest{}); return e }},
		{"DisableAllKeyVersions", func() error { _, e := tr.DisableAllKeyVersions(ctx, &transport.AllKeyVersionsRequest{}); return e }},
		{"RotateScopeKeys", func() error { _, e := tr.RotateScopeKeys(ctx, &transport.RotateScopeKeysRequest{}); return e }},
		{"TPMPolicyCreate", func() error { _, e := tr.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{}); return e }},
		{"TPMPolicyGet", func() error { _, e := tr.TPMPolicyGet(ctx, &transport.TPMPolicyRequest{}); return e }},
		{"TPMPolicyList", func() error { _, e := tr.TPMPolicyList(ctx, &transport.TPMPolicyListRequest{}); return e }},
		{"TPMPolicyUpdate", func() error { _, e := tr.TPMPolicyUpdate(ctx, &transport.TPMPolicyRequest{}); return e }},
		{"TPMPolicyRevoke", func() error { _, e := tr.TPMPolicyRevoke(ctx, &transport.TPMPolicyRequest{}); return e }},
		{"TPMPolicyVerify", func() error { _, e := tr.TPMPolicyVerify(ctx, &transport.TPMPolicyRequest{}); return e }},
		{"TPMPolicyDelete", func() error { return tr.TPMPolicyDelete(ctx, &transport.TPMPolicyDeleteRequest{}) }},
		{"TPMPolicyObjects", func() error { _, e := tr.TPMPolicyObjects(ctx, &transport.TPMPolicyRequest{}); return e }},
		{"TPMPolicySetAutoUnseal", func() error {
			_, e := tr.TPMPolicySetAutoUnseal(ctx, &transport.TPMPolicyAutoUnsealRequest{})
			return e
		}},
		{"TPMObjectPolicy", func() error { _, e := tr.TPMObjectPolicy(ctx, &transport.TPMObjectPolicyRequest{}); return e }},
		{"TPMPolicyRotateAuthority", func() error {
			_, e := tr.TPMPolicyRotateAuthority(ctx, &transport.TPMAuthorityRotateRequest{})
			return e
		}},
		{"GetTenantTPMMode", func() error { _, e := tr.GetTenantTPMMode(ctx, "tenant-a"); return e }},
		{"SetTenantTPMMode", func() error { _, e := tr.SetTenantTPMMode(ctx, &transport.SetTenantTPMModeRequest{}); return e }},
		{"TenantVTPMStatus", func() error { _, e := tr.TenantVTPMStatus(ctx, "tenant-a"); return e }},
		{"TenantVTPMStart", func() error { _, e := tr.TenantVTPMStart(ctx, "tenant-a"); return e }},
		{"TenantVTPMStop", func() error { _, e := tr.TenantVTPMStop(ctx, "tenant-a"); return e }},
		{"CreateCustodianGroup", func() error { _, e := tr.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{}); return e }},
		{"GetCustodianGroup", func() error { _, e := tr.GetCustodianGroup(ctx, "g1"); return e }},
		{"ListCustodianGroups", func() error { _, e := tr.ListCustodianGroups(ctx); return e }},
		{"DeleteCustodianGroup", func() error { return tr.DeleteCustodianGroup(ctx, "g1") }},
		{"AddCustodianMember", func() error { _, e := tr.AddCustodianMember(ctx, &transport.AddCustodianMemberRequest{}); return e }},
		{"RemoveCustodianMember", func() error { return tr.RemoveCustodianMember(ctx, &transport.RemoveCustodianMemberRequest{}) }},
		{"DistributeShares", func() error { _, e := tr.DistributeShares(ctx, &transport.DistributeSharesRequest{}); return e }},
		{"SubmitShare", func() error { _, e := tr.SubmitShare(ctx, &transport.SubmitShareRequest{}); return e }},
		{"ListShares", func() error { _, e := tr.ListShares(ctx); return e }},
		{"GetShareCollectionStatus", func() error { _, e := tr.GetShareCollectionStatus(ctx, "g1"); return e }},
		{"CreateTenant", func() error { _, e := tr.CreateTenant(ctx, &transport.CreateTenantRequest{}); return e }},
		{"GetTenant", func() error { _, e := tr.GetTenant(ctx, "t1"); return e }},
		{"ListTenants", func() error { _, e := tr.ListTenants(ctx); return e }},
		{"DeleteTenant", func() error { return tr.DeleteTenant(ctx, "t1") }},
		{"TenantBarrierInit", func() error { return tr.TenantBarrierInit(ctx, &transport.TenantBarrierInitRequest{}) }},
		{"TenantBarrierUnseal", func() error { return tr.TenantBarrierUnseal(ctx, &transport.TenantBarrierUnsealRequest{}) }},
		{"GetInitStatus", func() error { _, e := tr.GetInitStatus(ctx); return e }},
		{"ClaimCertBegin", func() error { _, e := tr.ClaimCertBegin(ctx, &transport.ClaimCertBeginRequest{}); return e }},
		{"ClaimCertComplete", func() error { _, e := tr.ClaimCertComplete(ctx, &transport.ClaimCertCompleteRequest{}); return e }},
		{"ClaimShareBegin", func() error { _, e := tr.ClaimShareBegin(ctx, &transport.ClaimShareBeginRequest{}); return e }},
		{"SignCSRInit", func() error { _, e := tr.SignCSRInit(ctx, &transport.SignCSRInitRequest{}); return e }},
		{"SubmitCredential", func() error { _, e := tr.SubmitCredential(ctx, &transport.CredentialSubmitRequest{}); return e }},
		{"GetCredentialStrategy", func() error { _, e := tr.GetCredentialStrategy(ctx); return e }},
		{"QueryAudit", func() error { _, e := tr.QueryAudit(ctx, &transport.AuditFilter{}); return e }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			assert.NoError(t, err, "expected no error for %s when connected", tt.name)
		})
	}
}
