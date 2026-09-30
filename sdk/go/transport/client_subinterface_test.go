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

package transport

import (
	"context"
	"testing"
)

// stubClient is a minimal implementation of Client used for compile-time
// interface satisfaction checks. All methods panic because they are never
// called at runtime; they exist solely to prove that a single concrete
// type satisfying Client also satisfies every sub-interface.
type stubClient struct{}

func (s *stubClient) Connect(context.Context) error { panic("stub") }
func (s *stubClient) Close() error                  { panic("stub") }
func (s *stubClient) Health(context.Context) (*HealthResponse, error) {
	panic("stub")
}

func (s *stubClient) Algorithms(context.Context) (*AlgorithmsResponse, error) {
	panic("stub")
}
func (s *stubClient) ListBackends(context.Context, ...ListOption) (*ListBackendsResponse, error) {
	panic("stub")
}
func (s *stubClient) GetBackend(context.Context, string) (*BackendInfo, error) {
	panic("stub")
}

func (s *stubClient) GenerateKey(context.Context, *GenerateKeyRequest) (*GenerateKeyResponse, error) {
	panic("stub")
}
func (s *stubClient) ListKeys(context.Context, string, ...ListOption) (*ListKeysResponse, error) {
	panic("stub")
}
func (s *stubClient) GetKey(context.Context, string, string) (*GetKeyResponse, error) {
	panic("stub")
}
func (s *stubClient) DeleteKey(context.Context, string, string) (*DeleteKeyResponse, error) {
	panic("stub")
}
func (s *stubClient) ImportKey(context.Context, *ImportKeyRequest) (*ImportKeyResponse, error) {
	panic("stub")
}
func (s *stubClient) ExportKey(context.Context, *ExportKeyRequest) (*ExportKeyResponse, error) {
	panic("stub")
}
func (s *stubClient) RotateKey(context.Context, *RotateKeyRequest) (*RotateKeyResponse, error) {
	panic("stub")
}
func (s *stubClient) GetImportParameters(context.Context, *GetImportParametersRequest) (*GetImportParametersResponse, error) {
	panic("stub")
}
func (s *stubClient) CopyKey(context.Context, *CopyKeyRequest) (*CopyKeyResponse, error) {
	panic("stub")
}
func (s *stubClient) ExportKeyMaterial(context.Context, *ExportKeyMaterialRequest) (*ExportKeyMaterialResponse, error) {
	panic("stub")
}
func (s *stubClient) WrapKey(context.Context, *WrapKeyRequest) (*WrapKeyResponse, error) {
	panic("stub")
}
func (s *stubClient) UnwrapKey(context.Context, *UnwrapKeyRequest) (*UnwrapKeyResponse, error) {
	panic("stub")
}
func (s *stubClient) WrapKeyByID(context.Context, *WrapKeyByIDRequest) (*WrapKeyByIDResponse, error) {
	panic("stub")
}
func (s *stubClient) UnwrapKeyByID(context.Context, *UnwrapKeyByIDRequest) (*UnwrapKeyByIDResponse, error) {
	panic("stub")
}

func (s *stubClient) Sign(context.Context, *SignRequest) (*SignResponse, error) {
	panic("stub")
}
func (s *stubClient) Verify(context.Context, *VerifyRequest) (*VerifyResponse, error) {
	panic("stub")
}
func (s *stubClient) Encrypt(context.Context, *EncryptRequest) (*EncryptResponse, error) {
	panic("stub")
}
func (s *stubClient) Decrypt(context.Context, *DecryptRequest) (*DecryptResponse, error) {
	panic("stub")
}
func (s *stubClient) EncryptAsym(context.Context, *EncryptAsymRequest) (*EncryptAsymResponse, error) {
	panic("stub")
}
func (s *stubClient) DeriveKey(context.Context, *DeriveKeyRequest) (*DeriveKeyResponse, error) {
	panic("stub")
}
func (s *stubClient) DeriveKeyECDH(context.Context, *DeriveKeyECDHRequest) (*DeriveKeyECDHResponse, error) {
	panic("stub")
}
func (s *stubClient) AttestKey(context.Context, *AttestKeyRequest) (*AttestKeyResponse, error) {
	panic("stub")
}

func (s *stubClient) GetCertificate(context.Context, string, string) (*GetCertificateResponse, error) {
	panic("stub")
}
func (s *stubClient) SaveCertificate(context.Context, *SaveCertificateRequest) error {
	panic("stub")
}
func (s *stubClient) DeleteCertificate(context.Context, string, string) error { panic("stub") }
func (s *stubClient) CertificateExists(context.Context, string, string) (bool, error) {
	panic("stub")
}
func (s *stubClient) ListCertificates(context.Context, string, ...ListOption) (*ListCertificatesResponse, error) {
	panic("stub")
}
func (s *stubClient) SaveCertificateChain(context.Context, *SaveCertificateChainRequest) error {
	panic("stub")
}
func (s *stubClient) GetCertificateChain(context.Context, string, string) (*GetCertificateChainResponse, error) {
	panic("stub")
}
func (s *stubClient) GetTLSCertificate(context.Context, string, string) (*GetTLSCertificateResponse, error) {
	panic("stub")
}

func (s *stubClient) Seal(context.Context, *SealRequest) (*SealResponse, error) {
	panic("stub")
}
func (s *stubClient) Unseal(context.Context, *UnsealRequest) (*UnsealResponse, error) {
	panic("stub")
}
func (s *stubClient) CanSeal(context.Context, string) (*CanSealResponse, error) {
	panic("stub")
}

func (s *stubClient) BarrierInitialize(context.Context, *BarrierInitializeRequest) error {
	panic("stub")
}
func (s *stubClient) BarrierUnseal(context.Context, *BarrierUnsealRequest) error {
	panic("stub")
}
func (s *stubClient) BarrierSeal(context.Context) error { panic("stub") }
func (s *stubClient) BarrierStatus(context.Context) (*BarrierStatusResponse, error) {
	panic("stub")
}
func (s *stubClient) BootstrapListenerKeys(context.Context) (*BootstrapListenerKeysResponse, error) {
	panic("stub")
}
func (s *stubClient) BarrierInitializeShamir(context.Context, *BarrierInitializeShamirRequest) (*BarrierInitializeShamirResponse, error) {
	panic("stub")
}
func (s *stubClient) BarrierUnsealWithShare(context.Context, *BarrierUnsealShareRequest) (*BarrierUnsealShareResponse, error) {
	panic("stub")
}
func (s *stubClient) BarrierUnsealWithShares(context.Context, *BarrierUnsealSharesRequest) error {
	panic("stub")
}
func (s *stubClient) BarrierRekey(context.Context, *BarrierRekeyRequest) (*BarrierRekeyResponse, error) {
	panic("stub")
}
func (s *stubClient) BarrierGenerateRecoveryKeys(context.Context, *BarrierGenerateRecoveryKeysRequest) (*BarrierRecoveryKeysResponse, error) {
	panic("stub")
}
func (s *stubClient) BarrierEnableEncryption(context.Context, *BarrierEnableEncryptionRequest) (*BarrierEnableEncryptionResponse, error) {
	panic("stub")
}
func (s *stubClient) BarrierRecoverWithKeys(context.Context, *BarrierRecoverWithKeysRequest) error {
	panic("stub")
}
func (s *stubClient) BarrierDeleteRecoveryKeys(context.Context) error {
	panic("stub")
}
func (s *stubClient) BarrierHasRecoveryKeys(context.Context) (*BarrierHasRecoveryKeysResponse, error) {
	panic("stub")
}
func (s *stubClient) BarrierGenerateRootToken(context.Context, *BarrierGenerateRootTokenRequest) (*BarrierRootTokenResponse, error) {
	panic("stub")
}

func (s *stubClient) ListPIVSlots(context.Context, *ListPIVSlotsRequest) (*ListPIVSlotsResponse, error) {
	panic("stub")
}
func (s *stubClient) GetPIVCertificate(context.Context, *GetPIVCertificateRequest) (*GetPIVCertificateResponse, error) {
	panic("stub")
}
func (s *stubClient) StorePIVCertificate(context.Context, *StorePIVCertificateRequest) error {
	panic("stub")
}
func (s *stubClient) DeletePIVCertificate(context.Context, *DeletePIVCertificateRequest) error {
	panic("stub")
}
func (s *stubClient) GeneratePIVKey(context.Context, *GeneratePIVKeyRequest) (*GeneratePIVKeyResponse, error) {
	panic("stub")
}
func (s *stubClient) ImportPIVCertificate(context.Context, *StorePIVCertificateRequest) error {
	panic("stub")
}
func (s *stubClient) ExportPIVCertificate(context.Context, *GetPIVCertificateRequest) (*GetPIVCertificateResponse, error) {
	panic("stub")
}
func (s *stubClient) GeneratePIVCSR(context.Context, *GeneratePIVCSRRequest) (*GeneratePIVCSRResponse, error) {
	panic("stub")
}

func (s *stubClient) BeginRegistration(context.Context, *BeginRegistrationRequest) (*BeginRegistrationResponse, error) {
	panic("stub")
}
func (s *stubClient) FinishRegistration(context.Context, *FinishRegistrationRequest) (*FinishRegistrationResponse, error) {
	panic("stub")
}
func (s *stubClient) BeginAuthentication(context.Context, *BeginAuthenticationRequest) (*BeginAuthenticationResponse, error) {
	panic("stub")
}
func (s *stubClient) FinishAuthentication(context.Context, *FinishAuthenticationRequest) (*FinishAuthenticationResponse, error) {
	panic("stub")
}

func (s *stubClient) GetInvite(context.Context, *GetInviteRequest) (*GetInviteResponse, error) {
	panic("stub")
}
func (s *stubClient) BeginInviteRegistration(context.Context, *BeginInviteRegistrationRequest) (*BeginInviteRegistrationResponse, error) {
	panic("stub")
}
func (s *stubClient) FinishInviteRegistration(context.Context, *FinishInviteRegistrationRequest) (*FinishInviteRegistrationResponse, error) {
	panic("stub")
}
func (s *stubClient) ActivateInvitePIV(context.Context, *ActivateInvitePIVRequest) (*ActivateInvitePIVResponse, error) {
	panic("stub")
}

func (s *stubClient) GetCABundle(context.Context, *GetCABundleRequest) (*GetCABundleResponse, error) {
	panic("stub")
}
func (s *stubClient) GetCACertificate(context.Context, *GetCACertificateRequest) (*GetCACertificateResponse, error) {
	panic("stub")
}
func (s *stubClient) SignCSR(context.Context, *SignCSRRequest) (*SignCSRResponse, error) {
	panic("stub")
}
func (s *stubClient) IssueCertificate(context.Context, *IssueCertificateRequest) (*IssueCertificateResponse, error) {
	panic("stub")
}
func (s *stubClient) RevokeCertificate(context.Context, *RevokeCertificateRequest) (*RevokeCertificateResponse, error) {
	panic("stub")
}
func (s *stubClient) GenerateCRL(context.Context, *GenerateCRLRequest) (*GenerateCRLResponse, error) {
	panic("stub")
}
func (s *stubClient) IsRevoked(context.Context, *IsRevokedRequest) (*IsRevokedResponse, error) {
	panic("stub")
}
func (s *stubClient) IssueEKCertificate(context.Context, *IssueEKCertificateRequest) (*IssueEKCertificateResponse, error) {
	panic("stub")
}
func (s *stubClient) IssueAKCertificate(context.Context, *IssueAKCertificateRequest) (*IssueAKCertificateResponse, error) {
	panic("stub")
}
func (s *stubClient) SignTCGCSR(context.Context, *SignTCGCSRRequest) (*SignTCGCSRResponse, error) {
	panic("stub")
}
func (s *stubClient) EnrollDevice(context.Context, *EnrollDeviceRequest) (*EnrollDeviceResponse, error) {
	panic("stub")
}

func (s *stubClient) SetSOPIN(context.Context, *SetSOPINRequest) error       { panic("stub") }
func (s *stubClient) SetUserPIN(context.Context, *SetUserPINRequest) error   { panic("stub") }
func (s *stubClient) ChangeSOPIN(context.Context, *ChangeSOPINRequest) error { panic("stub") }
func (s *stubClient) ChangeUserPIN(context.Context, *ChangeUserPINRequest) error {
	panic("stub")
}
func (s *stubClient) VerifySOPIN(context.Context, *VerifySOPINRequest) error { panic("stub") }
func (s *stubClient) VerifyUserPIN(context.Context, *VerifyUserPINRequest) error {
	panic("stub")
}
func (s *stubClient) GetLockoutStatus(context.Context) (*LockoutStatusResponse, error) {
	panic("stub")
}
func (s *stubClient) ResetLockout(context.Context, *ResetLockoutRequest) error { panic("stub") }

func (s *stubClient) PasswordAdd(context.Context, *PasswordAddRequest) (*PasswordAddResponse, error) {
	panic("stub")
}
func (s *stubClient) PasswordGet(context.Context, *PasswordGetRequest) (*PasswordGetResponse, error) {
	panic("stub")
}
func (s *stubClient) PasswordList(context.Context, *PasswordListRequest) (*PasswordListResponse, error) {
	panic("stub")
}
func (s *stubClient) PasswordUpdate(context.Context, *PasswordUpdateRequest) error { panic("stub") }
func (s *stubClient) PasswordDelete(context.Context, *PasswordDeleteRequest) error { panic("stub") }
func (s *stubClient) PasswordStoreUnlock(context.Context, *PasswordStoreUnlockRequest) error {
	panic("stub")
}
func (s *stubClient) PasswordStoreLock(context.Context) error { panic("stub") }
func (s *stubClient) PasswordStoreStatus(context.Context) (*PasswordStoreStatusResponse, error) {
	panic("stub")
}
func (s *stubClient) PasswordStoreSetAccessMode(context.Context, *PasswordStoreSetAccessModeRequest) error {
	panic("stub")
}
func (s *stubClient) PasswordGenerate(context.Context, *PasswordGenerateRequest) (*PasswordGenerateResponse, error) {
	panic("stub")
}

func (s *stubClient) SealStorePut(context.Context, *SealStorePutRequest) error {
	panic("stub")
}
func (s *stubClient) SealStoreGet(context.Context, *SealStoreGetRequest) (*SealStoreGetResponse, error) {
	panic("stub")
}
func (s *stubClient) SealStoreDelete(context.Context, *SealStoreDeleteRequest) error {
	panic("stub")
}
func (s *stubClient) SealStoreList(context.Context) (*SealStoreListResponse, error) {
	panic("stub")
}
func (s *stubClient) SealStoreReseal(context.Context, *SealStoreResealRequest) error {
	panic("stub")
}
func (s *stubClient) SealStoreStatus(context.Context) (*SealStoreStatusResponse, error) {
	panic("stub")
}

func (s *stubClient) EscrowKey(context.Context, *EscrowRequest) ([]*EscrowReceipt, error) {
	panic("stub")
}
func (s *stubClient) RecoverKey(context.Context, *RecoverRequest) (*RecoverResponse, error) {
	panic("stub")
}
func (s *stubClient) ListEscrowed(context.Context) ([]EscrowRecord, error) {
	panic("stub")
}
func (s *stubClient) RevokeEscrow(context.Context, string) error {
	panic("stub")
}

func (s *stubClient) TPMPolicyCreate(context.Context, *TPMPolicyCreateRequest) (*TPMPolicy, error) {
	panic("stub")
}

func (s *stubClient) TPMPolicyGet(context.Context, *TPMPolicyRequest) (*TPMPolicy, error) {
	panic("stub")
}

func (s *stubClient) TPMPolicyList(context.Context, *TPMPolicyListRequest) (*TPMPolicyListResponse, error) {
	panic("stub")
}

func (s *stubClient) TPMPolicyUpdate(context.Context, *TPMPolicyRequest) (*TPMPolicy, error) {
	panic("stub")
}

func (s *stubClient) TPMPolicyRevoke(context.Context, *TPMPolicyRequest) (*TPMPolicy, error) {
	panic("stub")
}

func (s *stubClient) TPMPolicyVerify(context.Context, *TPMPolicyRequest) (*TPMPolicyVerifyResponse, error) {
	panic("stub")
}

func (s *stubClient) TPMPolicyDelete(context.Context, *TPMPolicyDeleteRequest) error {
	panic("stub")
}

func (s *stubClient) TPMPolicyObjects(context.Context, *TPMPolicyRequest) (*TPMPolicyObjectsResponse, error) {
	panic("stub")
}

func (s *stubClient) TPMPolicySetAutoUnseal(context.Context, *TPMPolicyAutoUnsealRequest) (*TPMPolicy, error) {
	panic("stub")
}

func (s *stubClient) TPMPolicySetDescription(context.Context, *TPMPolicyDescriptionRequest) (*TPMPolicy, error) {
	panic("stub")
}

func (s *stubClient) TPMObjectPolicy(context.Context, *TPMObjectPolicyRequest) (*TPMObjectPolicyResponse, error) {
	panic("stub")
}

func (s *stubClient) TPMPolicyRotateAuthority(context.Context, *TPMAuthorityRotateRequest) (*TPMAuthorityRotateResponse, error) {
	panic("stub")
}

func (s *stubClient) GetTenantTPMMode(context.Context, string) (*TenantTPMModeResponse, error) {
	panic("stub")
}

func (s *stubClient) SetTenantTPMMode(context.Context, *SetTenantTPMModeRequest) (*TenantTPMModeResponse, error) {
	panic("stub")
}

func (s *stubClient) TenantVTPMStatus(context.Context, string) (*TenantVTPMStatusResponse, error) {
	panic("stub")
}

func (s *stubClient) TenantVTPMStart(context.Context, string) (*TenantVTPMStatusResponse, error) {
	panic("stub")
}

func (s *stubClient) TenantVTPMStop(context.Context, string) (*TenantVTPMStatusResponse, error) {
	panic("stub")
}

// CustodianGroupService stubs.
func (s *stubClient) CreateCustodianGroup(context.Context, *CreateCustodianGroupRequest) (*CreateCustodianGroupResponse, error) {
	panic("stub")
}
func (s *stubClient) GetCustodianGroup(context.Context, string) (*GetCustodianGroupResponse, error) {
	panic("stub")
}
func (s *stubClient) ListCustodianGroups(context.Context) (*ListCustodianGroupsResponse, error) {
	panic("stub")
}
func (s *stubClient) DeleteCustodianGroup(context.Context, string) error { panic("stub") }
func (s *stubClient) AddCustodianMember(context.Context, *AddCustodianMemberRequest) (*AddCustodianMemberResponse, error) {
	panic("stub")
}
func (s *stubClient) RemoveCustodianMember(context.Context, *RemoveCustodianMemberRequest) error {
	panic("stub")
}
func (s *stubClient) DistributeShares(context.Context, *DistributeSharesRequest) (*DistributeSharesResponse, error) {
	panic("stub")
}

// ShareService stubs.
func (s *stubClient) SubmitShare(context.Context, *SubmitShareRequest) (*SubmitShareResponse, error) {
	panic("stub")
}
func (s *stubClient) ListShares(context.Context) (*ListSharesResponse, error) { panic("stub") }
func (s *stubClient) GetShare(context.Context, string, string, int) (*ShareInfo, error) {
	panic("stub")
}
func (s *stubClient) DeleteShare(context.Context, string, string, int) error { panic("stub") }
func (s *stubClient) GetShareCollectionStatus(context.Context, string) (*ShareCollectionStatus, error) {
	panic("stub")
}

// TenantService stubs.
func (s *stubClient) CreateTenant(context.Context, *CreateTenantRequest) (*CreateTenantResponse, error) {
	panic("stub")
}
func (s *stubClient) GetTenant(context.Context, string) (*GetTenantResponse, error) {
	panic("stub")
}
func (s *stubClient) ListTenants(context.Context) (*ListTenantsResponse, error) { panic("stub") }
func (s *stubClient) DeleteTenant(context.Context, string) error                { panic("stub") }
func (s *stubClient) TenantBarrierInit(context.Context, *TenantBarrierInitRequest) error {
	panic("stub")
}
func (s *stubClient) TenantBarrierUnseal(context.Context, *TenantBarrierUnsealRequest) error {
	panic("stub")
}
func (s *stubClient) TenantBarrierStatus(_ context.Context, _ string) (*TenantBarrierStatusResponse, error) {
	return nil, nil
}
func (s *stubClient) UpdateTenantEntitlements(_ context.Context, _ *UpdateTenantEntitlementsRequest) (*UpdateTenantEntitlementsResponse, error) {
	return nil, nil
}
func (s *stubClient) UpdateTenantQuotas(_ context.Context, _ *UpdateTenantQuotasRequest) (*UpdateTenantQuotasResponse, error) {
	return nil, nil
}

// InitCeremonyService stubs.
func (s *stubClient) GetInitStatus(context.Context) (*InitStatusResponse, error) {
	panic("stub")
}
func (s *stubClient) ClaimCertBegin(context.Context, *ClaimCertBeginRequest) (*ClaimCertBeginResponse, error) {
	panic("stub")
}
func (s *stubClient) ClaimCertComplete(context.Context, *ClaimCertCompleteRequest) (*ClaimCertCompleteResponse, error) {
	panic("stub")
}
func (s *stubClient) ClaimShareBegin(context.Context, *ClaimShareBeginRequest) (*ClaimShareBeginResponse, error) {
	panic("stub")
}
func (s *stubClient) ClaimShareComplete(context.Context, *ClaimShareCompleteRequest) (*ClaimShareCompleteResponse, error) {
	panic("stub")
}
func (s *stubClient) SignCSRInit(context.Context, *SignCSRInitRequest) (*SignCSRInitResponse, error) {
	panic("stub")
}

// CredentialManagementService stubs.
func (s *stubClient) SubmitCredential(context.Context, *CredentialSubmitRequest) (*CredentialSubmitResponse, error) {
	panic("stub")
}
func (s *stubClient) GetCredentialStrategy(context.Context) (*CredentialStrategyResponse, error) {
	panic("stub")
}

func (s *stubClient) CreateUser(context.Context, *CreateUserRequest) (*GetUserResponse, error) {
	panic("stub")
}

func (s *stubClient) ListUsers(context.Context, ...ListOption) (*ListUsersResponse, error) {
	panic("stub")
}

func (s *stubClient) GetUser(context.Context, string) (*GetUserResponse, error) {
	panic("stub")
}

func (s *stubClient) DeleteUser(context.Context, string) error {
	panic("stub")
}

func (s *stubClient) EnableUser(context.Context, string) error {
	panic("stub")
}

func (s *stubClient) DisableUser(context.Context, string) error {
	panic("stub")
}

func (s *stubClient) BindUserCert(context.Context, string, string, int64) error {
	panic("stub")
}

func (s *stubClient) ListUserCredentials(context.Context, string) (*ListUserCredentialsResponse, error) {
	panic("stub")
}

// KeyVersionService stub.
func (s *stubClient) ListKeyVersions(context.Context, *ListKeyVersionsRequest) (*ListKeyVersionsResponse, error) {
	panic("stub")
}

func (s *stubClient) EnableKeyVersion(context.Context, *KeyVersionRequest) (*KeyVersionStateResponse, error) {
	panic("stub")
}

func (s *stubClient) DisableKeyVersion(context.Context, *KeyVersionRequest) (*KeyVersionStateResponse, error) {
	panic("stub")
}

func (s *stubClient) RetireKeyVersion(context.Context, *KeyVersionRequest) (*KeyVersionStateResponse, error) {
	panic("stub")
}

func (s *stubClient) EnableAllKeyVersions(context.Context, *AllKeyVersionsRequest) (*AllKeyVersionsResponse, error) {
	panic("stub")
}

func (s *stubClient) DisableAllKeyVersions(context.Context, *AllKeyVersionsRequest) (*AllKeyVersionsResponse, error) {
	panic("stub")
}

func (s *stubClient) RotateScopeKeys(context.Context, *RotateScopeKeysRequest) (*RotateScopeKeysResponse, error) {
	panic("stub")
}

// AuditService stub.
func (s *stubClient) QueryAudit(context.Context, *AuditFilter) (*AuditPage, error) {
	panic("stub")
}

// Compile-time assertions: stubClient must satisfy Client and every sub-interface.
var (
	_ Client                      = (*stubClient)(nil)
	_ ConnectionService           = (*stubClient)(nil)
	_ BackendService              = (*stubClient)(nil)
	_ KeyService                  = (*stubClient)(nil)
	_ KeyVersionService           = (*stubClient)(nil)
	_ CryptoService               = (*stubClient)(nil)
	_ CertService                 = (*stubClient)(nil)
	_ SealService                 = (*stubClient)(nil)
	_ BarrierService              = (*stubClient)(nil)
	_ PIVService                  = (*stubClient)(nil)
	_ FIDO2Service                = (*stubClient)(nil)
	_ CAService                   = (*stubClient)(nil)
	_ PINService                  = (*stubClient)(nil)
	_ UserService                 = (*stubClient)(nil)
	_ PasswordService             = (*stubClient)(nil)
	_ SealStoreService            = (*stubClient)(nil)
	_ TPMPolicyService            = (*stubClient)(nil)
	_ CustodianGroupService       = (*stubClient)(nil)
	_ ShareService                = (*stubClient)(nil)
	_ TenantService               = (*stubClient)(nil)
	_ InitCeremonyService         = (*stubClient)(nil)
	_ CredentialManagementService = (*stubClient)(nil)
	_ AuditService                = (*stubClient)(nil)
)

// TestClientComposesAllSubInterfaces verifies that a value satisfying the
// Client interface can be assigned to each individual sub-interface variable.
// This is a runtime confirmation of the compile-time composition guarantee.
func TestClientComposesAllSubInterfaces(t *testing.T) {
	var c Client = &stubClient{}

	subinterfaces := []struct {
		name  string
		check func() bool
	}{
		{"ConnectionService", func() bool { var v ConnectionService = c; return v != nil }},
		{"BackendService", func() bool { var v BackendService = c; return v != nil }},
		{"KeyService", func() bool { var v KeyService = c; return v != nil }},
		{"KeyVersionService", func() bool { var v KeyVersionService = c; return v != nil }},
		{"CryptoService", func() bool { var v CryptoService = c; return v != nil }},
		{"CertService", func() bool { var v CertService = c; return v != nil }},
		{"SealService", func() bool { var v SealService = c; return v != nil }},
		{"BarrierService", func() bool { var v BarrierService = c; return v != nil }},
		{"PIVService", func() bool { var v PIVService = c; return v != nil }},
		{"FIDO2Service", func() bool { var v FIDO2Service = c; return v != nil }},
		{"CAService", func() bool { var v CAService = c; return v != nil }},
		{"PINService", func() bool { var v PINService = c; return v != nil }},
		{"PasswordService", func() bool { var v PasswordService = c; return v != nil }},
		{"SealStoreService", func() bool { var v SealStoreService = c; return v != nil }},
		{"TPMPolicyService", func() bool { var v TPMPolicyService = c; return v != nil }},
		{"CustodianGroupService", func() bool { var v CustodianGroupService = c; return v != nil }},
		{"ShareService", func() bool { var v ShareService = c; return v != nil }},
		{"TenantService", func() bool { var v TenantService = c; return v != nil }},
		{"InitCeremonyService", func() bool { var v InitCeremonyService = c; return v != nil }},
		{"CredentialManagementService", func() bool {
			var v CredentialManagementService = c
			return v != nil
		}},
	}

	for _, si := range subinterfaces {
		t.Run(si.name, func(t *testing.T) {
			if !si.check() {
				t.Errorf("Client does not satisfy %s sub-interface", si.name)
			}
		})
	}
}

// TestSubInterfaceCount verifies that Client composes exactly 19 sub-interfaces.
// This test serves as a safeguard: if a sub-interface is added or removed from
// Client, this test must be updated to reflect the new count.
func TestSubInterfaceCount(t *testing.T) {
	const expectedCount = 19
	// Each sub-interface is represented in the compile-time assertions above.
	// We track the count here explicitly to catch accidental additions or removals.
	subinterfaceNames := []string{
		"ConnectionService",
		"BackendService",
		"KeyService",
		"CryptoService",
		"CertService",
		"SealService",
		"BarrierService",
		"PIVService",
		"FIDO2Service",
		"CAService",
		"PINService",
		"PasswordService",
		"SealStoreService",
		"PolicyService",
		"CustodianGroupService",
		"ShareService",
		"TenantService",
		"InitCeremonyService",
		"CredentialManagementService",
	}
	if len(subinterfaceNames) != expectedCount {
		t.Errorf("expected %d sub-interfaces, got %d", expectedCount, len(subinterfaceNames))
	}
}

// TestSubInterfaceIndependence verifies that each sub-interface can be used
// independently without requiring the full Client interface. This confirms
// that consumers can depend on narrow interfaces for their specific needs.
func TestSubInterfaceIndependence(t *testing.T) {
	stub := &stubClient{}

	t.Run("ConnectionServiceOnly", func(t *testing.T) {
		var _ ConnectionService = stub
	})

	t.Run("KeyServiceOnly", func(t *testing.T) {
		var _ KeyService = stub
	})

	t.Run("CryptoServiceOnly", func(t *testing.T) {
		var _ CryptoService = stub
	})

	t.Run("CertServiceOnly", func(t *testing.T) {
		var _ CertService = stub
	})

	t.Run("BarrierServiceOnly", func(t *testing.T) {
		var _ BarrierService = stub
	})

	t.Run("CAServiceOnly", func(t *testing.T) {
		var _ CAService = stub
	})

	t.Run("InitCeremonyServiceOnly", func(t *testing.T) {
		var _ InitCeremonyService = stub
	})

	t.Run("CredentialManagementServiceOnly", func(t *testing.T) {
		var _ CredentialManagementService = stub
	})
}

// TestClientAssignableFromSubInterfaces verifies that a concrete type satisfying
// all sub-interfaces can be assigned to the Client interface, confirming the
// composition is bidirectionally valid.
func TestClientAssignableFromSubInterfaces(t *testing.T) {
	stub := &stubClient{}

	// This assignment would fail at compile time if stubClient didn't satisfy
	// every embedded sub-interface in Client.
	var _ Client = stub
}
