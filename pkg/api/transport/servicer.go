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
)

// XKMSServicer defines the interface for the xkms service.
// This is used by the embedded transport to make direct calls.
//
// XKMSServicer composes all servicer sub-interfaces into a unified interface.
// This is fully backward compatible: any type that implements all methods
// still satisfies XKMSServicer, and the sub-interfaces can be used
// independently for interface segregation and targeted test mocks.
//
// EscrowServicer is deliberately NOT part of this composition (go-xkms#692).
// External key escrow's RBAC model is undecided, so it stays an
// embedded-only capability: embedded.XKMSServicer composes XKMSServicer with
// EscrowServicer for the one transport that reaches it, and no network
// transport (rest, grpc, quic, unix, mcp, usb) carries Escrow methods at
// all. A caller that genuinely needs escrow type-asserts its transport.Client
// to EscrowService, or is handed the embedded transport's wider interface
// explicitly — never through this composition.
type XKMSServicer interface {
	HealthServicer
	BackendServicer
	KeyServicer
	CryptoServicer
	CertServicer
	SealServicer
	BarrierServicer
	PIVServicer
	FIDO2Servicer
	CAServicer
	TCGCAServicer
	PINServicer
	UserServicer
	PasswordServicer
	SealStoreServicer
	TPMPolicyServicer
	CustodianGroupServicer
	ShareServicer
	TenantServicer
	InitCeremonyServicer
	CredentialManagementServicer
	AuditServicer
	BootstrapServicer
}

// HealthServicer handles health checks.
// Note: Unlike ConnectionService, Connect/Close are transport-level
// concerns and not part of the servicer interface. The Health method returns
// (status, version, error) rather than *HealthResponse since the embedded
// transport constructs the response wrapper.
type HealthServicer interface {
	Health(ctx context.Context) (string, string, error)
}

// BackendServicer provides backend discovery and information.
// Note: ListBackends returns a raw slice rather than *ListBackendsResponse
// since the embedded transport constructs the response wrapper.
type BackendServicer interface {
	ListBackends(ctx context.Context, opts ...ListOption) ([]BackendInfo, error)
	GetBackend(ctx context.Context, backendID string) (*BackendInfo, error)

	// Algorithms reports the cryptographic algorithms this build supports and
	// which backends provide each one.
	Algorithms(ctx context.Context) (*AlgorithmsResponse, error)
}

// KeyServicer handles key lifecycle management.
// Note: DeleteKey returns error rather than *DeleteKeyResponse since the
// embedded transport constructs the response wrapper.
type KeyServicer interface {
	GenerateKey(ctx context.Context, req *GenerateKeyRequest) (*GenerateKeyResponse, error)
	ListKeys(ctx context.Context, backend string, opts ...ListOption) (*ListKeysResponse, error)
	GetKey(ctx context.Context, backend, keyID string) (*GetKeyResponse, error)
	DeleteKey(ctx context.Context, backend, keyID string) error
	ImportKey(ctx context.Context, req *ImportKeyRequest) (*ImportKeyResponse, error)
	ExportKey(ctx context.Context, req *ExportKeyRequest) (*ExportKeyResponse, error)
	RotateKey(ctx context.Context, req *RotateKeyRequest) (*RotateKeyResponse, error)
	GetImportParameters(ctx context.Context, req *GetImportParametersRequest) (*GetImportParametersResponse, error)
	CopyKey(ctx context.Context, req *CopyKeyRequest) (*CopyKeyResponse, error)
	ExportKeyMaterial(ctx context.Context, req *ExportKeyMaterialRequest) (*ExportKeyMaterialResponse, error)
	WrapKey(ctx context.Context, req *WrapKeyRequest) (*WrapKeyResponse, error)
	UnwrapKey(ctx context.Context, req *UnwrapKeyRequest) (*UnwrapKeyResponse, error)
	WrapKeyByID(ctx context.Context, req *WrapKeyByIDRequest) (*WrapKeyByIDResponse, error)
	UnwrapKeyByID(ctx context.Context, req *UnwrapKeyByIDRequest) (*UnwrapKeyByIDResponse, error)
}

// CryptoServicer provides cryptographic operations.
type CryptoServicer interface {
	Sign(ctx context.Context, req *SignRequest) (*SignResponse, error)
	Verify(ctx context.Context, req *VerifyRequest) (*VerifyResponse, error)
	Encrypt(ctx context.Context, req *EncryptRequest) (*EncryptResponse, error)
	Decrypt(ctx context.Context, req *DecryptRequest) (*DecryptResponse, error)
	EncryptAsym(ctx context.Context, req *EncryptAsymRequest) (*EncryptAsymResponse, error)
	DeriveKey(ctx context.Context, req *DeriveKeyRequest) (*DeriveKeyResponse, error)
	DeriveKeyECDH(ctx context.Context, req *DeriveKeyECDHRequest) (*DeriveKeyECDHResponse, error)
	AttestKey(ctx context.Context, req *AttestKeyRequest) (*AttestKeyResponse, error)
}

// CertServicer handles certificate management.
type CertServicer interface {
	GetCertificate(ctx context.Context, backend, keyID string) (*GetCertificateResponse, error)
	SaveCertificate(ctx context.Context, req *SaveCertificateRequest) error
	DeleteCertificate(ctx context.Context, backend, keyID string) error
	CertificateExists(ctx context.Context, backend, keyID string) (bool, error)
	ListCertificates(ctx context.Context, backend string, opts ...ListOption) (*ListCertificatesResponse, error)
	SaveCertificateChain(ctx context.Context, req *SaveCertificateChainRequest) error
	GetCertificateChain(ctx context.Context, backend, keyID string) (*GetCertificateChainResponse, error)
	GetTLSCertificate(ctx context.Context, backend, keyID string) (*GetTLSCertificateResponse, error)
}

// SealServicer handles data sealing and unsealing.
type SealServicer interface {
	Seal(ctx context.Context, req *SealRequest) (*SealResponse, error)
	Unseal(ctx context.Context, req *UnsealRequest) (*UnsealResponse, error)
	CanSeal(ctx context.Context, backend string) (*CanSealResponse, error)
}

// BarrierServicer manages the cryptographic barrier.
type BarrierServicer interface {
	BarrierInitialize(ctx context.Context, req *BarrierInitializeRequest) error
	BarrierUnseal(ctx context.Context, req *BarrierUnsealRequest) error
	BarrierSeal(ctx context.Context) error
	BarrierStatus(ctx context.Context) (*BarrierStatusResponse, error)
	BarrierInitializeShamir(ctx context.Context, req *BarrierInitializeShamirRequest) (*BarrierInitializeShamirResponse, error)
	BarrierUnsealWithShare(ctx context.Context, req *BarrierUnsealShareRequest) (*BarrierUnsealShareResponse, error)
	BarrierUnsealWithShares(ctx context.Context, req *BarrierUnsealSharesRequest) error
	BarrierRekey(ctx context.Context, req *BarrierRekeyRequest) (*BarrierRekeyResponse, error)
	BarrierGenerateRecoveryKeys(ctx context.Context, req *BarrierGenerateRecoveryKeysRequest) (*BarrierRecoveryKeysResponse, error)
	BarrierRecoverWithKeys(ctx context.Context, req *BarrierRecoverWithKeysRequest) error
	BarrierDeleteRecoveryKeys(ctx context.Context) error
	BarrierHasRecoveryKeys(ctx context.Context) (*BarrierHasRecoveryKeysResponse, error)
	BarrierGenerateRootToken(ctx context.Context, req *BarrierGenerateRootTokenRequest) (*BarrierRootTokenResponse, error)
	BarrierEnableEncryption(ctx context.Context, req *BarrierEnableEncryptionRequest) (*BarrierEnableEncryptionResponse, error)
}

// BootstrapServicer reports the running trust-bootstrap listener's public
// static keys (go-xkms#632).
type BootstrapServicer interface {
	// BootstrapListenerKeys returns the listener's public keys. Returns a
	// typed "not enabled" error when no bootstrap listener has published
	// its keys yet.
	BootstrapListenerKeys(ctx context.Context) (*BootstrapListenerKeysResponse, error)
}

// PIVServicer handles Personal Identity Verification operations.
type PIVServicer interface {
	ListPIVSlots(ctx context.Context, req *ListPIVSlotsRequest) (*ListPIVSlotsResponse, error)
	GetPIVCertificate(ctx context.Context, req *GetPIVCertificateRequest) (*GetPIVCertificateResponse, error)
	StorePIVCertificate(ctx context.Context, req *StorePIVCertificateRequest) error
	DeletePIVCertificate(ctx context.Context, req *DeletePIVCertificateRequest) error
	GeneratePIVKey(ctx context.Context, req *GeneratePIVKeyRequest) (*GeneratePIVKeyResponse, error)
	ImportPIVCertificate(ctx context.Context, req *StorePIVCertificateRequest) error
	ExportPIVCertificate(ctx context.Context, req *GetPIVCertificateRequest) (*GetPIVCertificateResponse, error)
	GeneratePIVCSR(ctx context.Context, req *GeneratePIVCSRRequest) (*GeneratePIVCSRResponse, error)
}

// FIDO2Servicer handles FIDO2/WebAuthn operations.
type FIDO2Servicer interface {
	BeginRegistration(ctx context.Context, req *BeginRegistrationRequest) (*BeginRegistrationResponse, error)
	FinishRegistration(ctx context.Context, req *FinishRegistrationRequest) (*FinishRegistrationResponse, error)
	BeginAuthentication(ctx context.Context, req *BeginAuthenticationRequest) (*BeginAuthenticationResponse, error)
	FinishAuthentication(ctx context.Context, req *FinishAuthenticationRequest) (*FinishAuthenticationResponse, error)
}

// CAServicer handles Certificate Authority operations.
type CAServicer interface {
	GetCABundle(ctx context.Context, req *GetCABundleRequest) (*GetCABundleResponse, error)
	GetCACertificate(ctx context.Context, req *GetCACertificateRequest) (*GetCACertificateResponse, error)
	SignCSR(ctx context.Context, req *SignCSRRequest) (*SignCSRResponse, error)
	IssueCertificate(ctx context.Context, req *IssueCertificateRequest) (*IssueCertificateResponse, error)
	RevokeCertificate(ctx context.Context, req *RevokeCertificateRequest) (*RevokeCertificateResponse, error)
	GenerateCRL(ctx context.Context, req *GenerateCRLRequest) (*GenerateCRLResponse, error)
	IsRevoked(ctx context.Context, req *IsRevokedRequest) (*IsRevokedResponse, error)
}

// TCGCAServicer handles TCG-specific Certificate Authority operations.
type TCGCAServicer interface {
	IssueEKCertificate(ctx context.Context, req *IssueEKCertificateRequest) (*IssueEKCertificateResponse, error)
	IssueAKCertificate(ctx context.Context, req *IssueAKCertificateRequest) (*IssueAKCertificateResponse, error)
	SignTCGCSR(ctx context.Context, req *SignTCGCSRRequest) (*SignTCGCSRResponse, error)
	EnrollDevice(ctx context.Context, req *EnrollDeviceRequest) (*EnrollDeviceResponse, error)
}

// PINServicer handles PIN management operations.
type PINServicer interface {
	SetSOPIN(ctx context.Context, req *SetSOPINRequest) error
	SetUserPIN(ctx context.Context, req *SetUserPINRequest) error
	ChangeSOPIN(ctx context.Context, req *ChangeSOPINRequest) error
	ChangeUserPIN(ctx context.Context, req *ChangeUserPINRequest) error
	VerifySOPIN(ctx context.Context, req *VerifySOPINRequest) error
	VerifyUserPIN(ctx context.Context, req *VerifyUserPINRequest) error
	GetLockoutStatus(ctx context.Context) (*LockoutStatusResponse, error)
	ResetLockout(ctx context.Context, req *ResetLockoutRequest) error
}

// UserServicer handles xkms user management. xkms presents its own user
// model and API; the backing store is the embedded qrdb node.
type UserServicer interface {
	CreateUser(ctx context.Context, req *CreateUserRequest) (*GetUserResponse, error)
	ListUsers(ctx context.Context, opts ...ListOption) (*ListUsersResponse, error)
	GetUser(ctx context.Context, username string) (*GetUserResponse, error)
	DeleteUser(ctx context.Context, username string) error
	EnableUser(ctx context.Context, username string) error
	DisableUser(ctx context.Context, username string) error
	BindUserCert(ctx context.Context, username, thumbprint string, notAfterUnix int64) error
	ListUserCredentials(ctx context.Context, username string) (*ListUserCredentialsResponse, error)
}

// PasswordServicer handles static password management.
type PasswordServicer interface {
	PasswordAdd(ctx context.Context, req *PasswordAddRequest) (*PasswordAddResponse, error)
	PasswordGet(ctx context.Context, req *PasswordGetRequest) (*PasswordGetResponse, error)
	PasswordList(ctx context.Context, req *PasswordListRequest) (*PasswordListResponse, error)
	PasswordUpdate(ctx context.Context, req *PasswordUpdateRequest) error
	PasswordDelete(ctx context.Context, req *PasswordDeleteRequest) error
	PasswordStoreUnlock(ctx context.Context, req *PasswordStoreUnlockRequest) error
	PasswordStoreLock(ctx context.Context) error
	PasswordStoreStatus(ctx context.Context) (*PasswordStoreStatusResponse, error)
	PasswordStoreSetAccessMode(ctx context.Context, req *PasswordStoreSetAccessModeRequest) error
	PasswordGenerate(ctx context.Context, req *PasswordGenerateRequest) (*PasswordGenerateResponse, error)
}

// SealStoreServicer handles the local machine sealed credential store.
type SealStoreServicer interface {
	SealStorePut(ctx context.Context, req *SealStorePutRequest) error
	SealStoreGet(ctx context.Context, req *SealStoreGetRequest) (*SealStoreGetResponse, error)
	SealStoreDelete(ctx context.Context, req *SealStoreDeleteRequest) error
	SealStoreList(ctx context.Context) (*SealStoreListResponse, error)
	SealStoreReseal(ctx context.Context, req *SealStoreResealRequest) error
	SealStoreStatus(ctx context.Context) (*SealStoreStatusResponse, error)
}

// TPMPolicyServicer manages named TPM policies and tenant TPM modes. Its
// method set is TPMPolicyService's: every transport calls through it
// unchanged.
type TPMPolicyServicer interface {
	TPMPolicyService
}

// EscrowServicer provides external key-escrow operations (pkg/escrow):
// replicating already-wrapped key material to configured escrow agents,
// recovering it, listing what is escrowed, and revoking an escrowed key.
//
// It is embedded-only (go-xkms#692): XKMSServicer does not embed it, so no
// network transport is required to carry Escrow methods. embedded.XKMSServicer
// composes it in for the one transport that reaches escrow; a caller elsewhere
// in the stack type-asserts to this interface (or EscrowService in client.go,
// its SDK-facing counterpart) rather than finding it on XKMSServicer/Client.
type EscrowServicer interface {
	EscrowKey(ctx context.Context, req *EscrowRequest) ([]*EscrowReceipt, error)
	RecoverKey(ctx context.Context, req *RecoverRequest) (*RecoverResponse, error)
	ListEscrowed(ctx context.Context) ([]EscrowRecord, error)
	RevokeEscrow(ctx context.Context, escrowID string) error
}

// CustodianGroupServicer provides custodian group management operations.
type CustodianGroupServicer interface {
	CreateCustodianGroup(ctx context.Context, req *CreateCustodianGroupRequest) (*CreateCustodianGroupResponse, error)
	GetCustodianGroup(ctx context.Context, groupID string) (*GetCustodianGroupResponse, error)
	ListCustodianGroups(ctx context.Context) (*ListCustodianGroupsResponse, error)
	DeleteCustodianGroup(ctx context.Context, groupID string) error
	AddCustodianMember(ctx context.Context, req *AddCustodianMemberRequest) (*AddCustodianMemberResponse, error)
	RemoveCustodianMember(ctx context.Context, req *RemoveCustodianMemberRequest) error
	DistributeShares(ctx context.Context, req *DistributeSharesRequest) (*DistributeSharesResponse, error)
}

// ShareServicer provides share management operations. A share is addressed
// by the triple (serverURL, groupID, shareIndex); sensitive share material
// is never returned by GetShare.
type ShareServicer interface {
	SubmitShare(ctx context.Context, req *SubmitShareRequest) (*SubmitShareResponse, error)
	ListShares(ctx context.Context) (*ListSharesResponse, error)
	GetShare(ctx context.Context, serverURL, groupID string, shareIndex int) (*ShareInfo, error)
	DeleteShare(ctx context.Context, serverURL, groupID string, shareIndex int) error
	GetShareCollectionStatus(ctx context.Context, groupID string) (*ShareCollectionStatus, error)
}

// AuditServicer provides read access to the audit chain. Emission is not part
// of this contract: events are written through pkg/audit's Logger seam as a
// side effect of the operation being audited, never by an API caller.
type AuditServicer interface {
	QueryAudit(ctx context.Context, filter *AuditFilter) (*AuditPage, error)
}

// TenantServicer provides tenant management operations.
type TenantServicer interface {
	CreateTenant(ctx context.Context, req *CreateTenantRequest) (*CreateTenantResponse, error)
	GetTenant(ctx context.Context, tenantID string) (*GetTenantResponse, error)
	ListTenants(ctx context.Context) (*ListTenantsResponse, error)
	DeleteTenant(ctx context.Context, tenantID string) error
	TenantBarrierInit(ctx context.Context, req *TenantBarrierInitRequest) error
	TenantBarrierUnseal(ctx context.Context, req *TenantBarrierUnsealRequest) error
	TenantBarrierStatus(ctx context.Context, tenantID string) (*TenantBarrierStatusResponse, error)
	UpdateTenantEntitlements(ctx context.Context, req *UpdateTenantEntitlementsRequest) (*UpdateTenantEntitlementsResponse, error)
	UpdateTenantQuotas(ctx context.Context, req *UpdateTenantQuotasRequest) (*UpdateTenantQuotasResponse, error)
}

// InitCeremonyServicer provides init ceremony operations.
type InitCeremonyServicer interface {
	GetInitStatus(ctx context.Context) (*InitStatusResponse, error)
	ClaimCertBegin(ctx context.Context, req *ClaimCertBeginRequest) (*ClaimCertBeginResponse, error)
	ClaimCertComplete(ctx context.Context, req *ClaimCertCompleteRequest) (*ClaimCertCompleteResponse, error)
	ClaimShareBegin(ctx context.Context, req *ClaimShareBeginRequest) (*ClaimShareBeginResponse, error)
	ClaimShareComplete(ctx context.Context, req *ClaimShareCompleteRequest) (*ClaimShareCompleteResponse, error)
	SignCSRInit(ctx context.Context, req *SignCSRInitRequest) (*SignCSRInitResponse, error)
}

// CredentialManagementServicer provides credential management operations.
type CredentialManagementServicer interface {
	SubmitCredential(ctx context.Context, req *CredentialSubmitRequest) (*CredentialSubmitResponse, error)
	GetCredentialStrategy(ctx context.Context) (*CredentialStrategyResponse, error)
}
