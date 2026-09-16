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

// ConnectionService handles connection lifecycle and health checks.
type ConnectionService interface {
	// Connect establishes a connection to the xkms server.
	Connect(ctx context.Context) error

	// Close closes the connection to the server.
	Close() error

	// Health checks the health of the server.
	Health(ctx context.Context) (*HealthResponse, error)
}

// BackendService provides backend discovery and information.
type BackendService interface {
	// ListBackends returns a list of available backends.
	ListBackends(ctx context.Context, opts ...ListOption) (*ListBackendsResponse, error)

	// GetBackend returns information about a specific backend.
	GetBackend(ctx context.Context, backendID string) (*BackendInfo, error)

	// Algorithms reports the cryptographic algorithms the server supports and
	// which backends provide each one. It reflects compiled-in capability and
	// reads no state, so it is served without authentication.
	Algorithms(ctx context.Context) (*AlgorithmsResponse, error)
}

// KeyService handles key lifecycle management.
type KeyService interface {
	// GenerateKey generates a new key.
	GenerateKey(ctx context.Context, req *GenerateKeyRequest) (*GenerateKeyResponse, error)

	// ListKeys returns a list of keys in the specified backend.
	ListKeys(ctx context.Context, backend string, opts ...ListOption) (*ListKeysResponse, error)

	// GetKey returns information about a specific key.
	GetKey(ctx context.Context, backend, keyID string) (*GetKeyResponse, error)

	// DeleteKey deletes a key.
	DeleteKey(ctx context.Context, backend, keyID string) (*DeleteKeyResponse, error)

	// ImportKey imports a key.
	ImportKey(ctx context.Context, req *ImportKeyRequest) (*ImportKeyResponse, error)

	// ExportKey exports a key.
	ExportKey(ctx context.Context, req *ExportKeyRequest) (*ExportKeyResponse, error)

	// RotateKey rotates a key by generating a new version.
	RotateKey(ctx context.Context, req *RotateKeyRequest) (*RotateKeyResponse, error)

	// GetImportParameters gets the parameters needed to import a key.
	GetImportParameters(ctx context.Context, req *GetImportParametersRequest) (*GetImportParametersResponse, error)

	// CopyKey copies a key from one backend to another.
	CopyKey(ctx context.Context, req *CopyKeyRequest) (*CopyKeyResponse, error)

	// ExportKeyMaterial exports raw symmetric key bytes for extractable keys.
	// SECURITY WARNING: This returns plaintext key material. Use with extreme caution.
	ExportKeyMaterial(ctx context.Context, req *ExportKeyMaterialRequest) (*ExportKeyMaterialResponse, error)

	// WrapKey wraps key material for secure transport.
	WrapKey(ctx context.Context, req *WrapKeyRequest) (*WrapKeyResponse, error)

	// UnwrapKey unwraps key material.
	UnwrapKey(ctx context.Context, req *UnwrapKeyRequest) (*UnwrapKeyResponse, error)

	// WrapKeyByID wraps a target key using a wrapping key, both identified by key IDs.
	// This enables PKCS#11 C_WrapKey functionality with server-side keys.
	WrapKeyByID(ctx context.Context, req *WrapKeyByIDRequest) (*WrapKeyByIDResponse, error)

	// UnwrapKeyByID unwraps key material and imports it as a new key.
	// This enables PKCS#11 C_UnwrapKey functionality with server-side keys.
	UnwrapKeyByID(ctx context.Context, req *UnwrapKeyByIDRequest) (*UnwrapKeyByIDResponse, error)
}

// CryptoService provides cryptographic operations.
type CryptoService interface {
	// Sign signs data with the specified key.
	Sign(ctx context.Context, req *SignRequest) (*SignResponse, error)

	// Verify verifies a signature.
	Verify(ctx context.Context, req *VerifyRequest) (*VerifyResponse, error)

	// Encrypt encrypts data with the specified key.
	Encrypt(ctx context.Context, req *EncryptRequest) (*EncryptResponse, error)

	// Decrypt decrypts data with the specified key.
	Decrypt(ctx context.Context, req *DecryptRequest) (*DecryptResponse, error)

	// EncryptAsym encrypts data with RSA public key (asymmetric encryption).
	EncryptAsym(ctx context.Context, req *EncryptAsymRequest) (*EncryptAsymResponse, error)

	// DeriveKey derives a key using the specified algorithm and parameters.
	// Supports HKDF, ECDH, DH, SP800-108, PBKDF2, and other key derivation mechanisms.
	// The derivation is performed by the backend to ensure key material never leaves
	// the secure boundary.
	DeriveKey(ctx context.Context, req *DeriveKeyRequest) (*DeriveKeyResponse, error)

	// DeriveKeyECDH performs ECDH key agreement and derives a symmetric key.
	// This operation combines ECDH shared secret computation with a KDF to produce
	// a derived key suitable for symmetric encryption.
	DeriveKeyECDH(ctx context.Context, req *DeriveKeyECDHRequest) (*DeriveKeyECDHResponse, error)

	// AttestKey requests key attestation from a backend, proving the key
	// is stored in hardware (TPM2, Android TEE/StrongBox, etc.).
	AttestKey(ctx context.Context, req *AttestKeyRequest) (*AttestKeyResponse, error)
}

// CertService handles certificate management.
type CertService interface {
	// GetCertificate returns the certificate for a key.
	GetCertificate(ctx context.Context, backend, keyID string) (*GetCertificateResponse, error)

	// SaveCertificate saves a certificate for a key.
	SaveCertificate(ctx context.Context, req *SaveCertificateRequest) error

	// DeleteCertificate deletes a certificate.
	DeleteCertificate(ctx context.Context, backend, keyID string) error

	// CertificateExists checks if a certificate exists for a key.
	CertificateExists(ctx context.Context, backend, keyID string) (bool, error)

	// ListCertificates lists all certificates in the specified backend.
	ListCertificates(ctx context.Context, backend string, opts ...ListOption) (*ListCertificatesResponse, error)

	// SaveCertificateChain saves a certificate chain for a key.
	SaveCertificateChain(ctx context.Context, req *SaveCertificateChainRequest) error

	// GetCertificateChain returns the certificate chain for a key.
	GetCertificateChain(ctx context.Context, backend, keyID string) (*GetCertificateChainResponse, error)

	// GetTLSCertificate returns the TLS certificate bundle for a key.
	GetTLSCertificate(ctx context.Context, backend, keyID string) (*GetTLSCertificateResponse, error)
}

// SealService handles data sealing and unsealing.
type SealService interface {
	// Seal seals data using the backend's sealing mechanism (e.g., TPM2).
	Seal(ctx context.Context, req *SealRequest) (*SealResponse, error)

	// Unseal unseals previously sealed data.
	Unseal(ctx context.Context, req *UnsealRequest) (*UnsealResponse, error)

	// CanSeal checks if the backend supports sealing operations.
	CanSeal(ctx context.Context, backend string) (*CanSealResponse, error)
}

// BarrierService manages the cryptographic barrier.
type BarrierService interface {
	// BarrierInitialize initializes the barrier with a single master key.
	BarrierInitialize(ctx context.Context, req *BarrierInitializeRequest) error

	// BarrierUnseal unseals the barrier using the master key.
	BarrierUnseal(ctx context.Context, req *BarrierUnsealRequest) error

	// BarrierSeal seals the barrier, preventing further data access until unsealed.
	BarrierSeal(ctx context.Context) error

	// BarrierStatus returns the current state of the cryptographic barrier.
	BarrierStatus(ctx context.Context) (*BarrierStatusResponse, error)

	// BarrierInitializeShamir initializes the barrier using Shamir secret sharing.
	BarrierInitializeShamir(ctx context.Context, req *BarrierInitializeShamirRequest) (*BarrierInitializeShamirResponse, error)

	// BarrierUnsealWithShare submits a single Shamir share toward the unseal threshold.
	BarrierUnsealWithShare(ctx context.Context, req *BarrierUnsealShareRequest) (*BarrierUnsealShareResponse, error)

	// BarrierUnsealWithShares submits multiple Shamir shares to unseal in a single request.
	BarrierUnsealWithShares(ctx context.Context, req *BarrierUnsealSharesRequest) error

	// BarrierRekey generates new Shamir shares, replacing the existing ones.
	BarrierRekey(ctx context.Context, req *BarrierRekeyRequest) (*BarrierRekeyResponse, error)

	// BarrierGenerateRecoveryKeys generates recovery keys for disaster recovery.
	BarrierGenerateRecoveryKeys(ctx context.Context, req *BarrierGenerateRecoveryKeysRequest) (*BarrierRecoveryKeysResponse, error)

	// BarrierRecoverWithKeys unseals the barrier using recovery keys.
	BarrierRecoverWithKeys(ctx context.Context, req *BarrierRecoverWithKeysRequest) error

	// BarrierDeleteRecoveryKeys deletes all stored recovery keys.
	BarrierDeleteRecoveryKeys(ctx context.Context) error

	// BarrierHasRecoveryKeys checks whether recovery keys have been generated.
	BarrierHasRecoveryKeys(ctx context.Context) (*BarrierHasRecoveryKeysResponse, error)

	// BarrierGenerateRootToken generates a new root token using Shamir shares.
	BarrierGenerateRootToken(ctx context.Context, req *BarrierGenerateRootTokenRequest) (*BarrierRootTokenResponse, error)

	// BarrierEnableEncryption migrates a previously-unencrypted barrier to a
	// keyed strategy in place. The migration runs asynchronously; the response
	// acknowledges the start and clients poll BarrierStatus for completion.
	BarrierEnableEncryption(ctx context.Context, req *BarrierEnableEncryptionRequest) (*BarrierEnableEncryptionResponse, error)
}

// PIVService handles Personal Identity Verification operations.
type PIVService interface {
	// ListPIVSlots returns the status of all PIV slots in the specified backend.
	ListPIVSlots(ctx context.Context, req *ListPIVSlotsRequest) (*ListPIVSlotsResponse, error)

	// GetPIVCertificate retrieves the certificate from a PIV slot.
	GetPIVCertificate(ctx context.Context, req *GetPIVCertificateRequest) (*GetPIVCertificateResponse, error)

	// StorePIVCertificate stores a certificate in a PIV slot.
	StorePIVCertificate(ctx context.Context, req *StorePIVCertificateRequest) error

	// DeletePIVCertificate removes the certificate from a PIV slot.
	DeletePIVCertificate(ctx context.Context, req *DeletePIVCertificateRequest) error

	// GeneratePIVKey generates a new key pair in a PIV slot with a self-signed certificate.
	GeneratePIVKey(ctx context.Context, req *GeneratePIVKeyRequest) (*GeneratePIVKeyResponse, error)

	// ImportPIVCertificate imports a certificate into a PIV slot.
	ImportPIVCertificate(ctx context.Context, req *StorePIVCertificateRequest) error

	// ExportPIVCertificate exports the certificate from a PIV slot.
	ExportPIVCertificate(ctx context.Context, req *GetPIVCertificateRequest) (*GetPIVCertificateResponse, error)

	// GeneratePIVCSR generates a certificate signing request for a PIV slot key.
	GeneratePIVCSR(ctx context.Context, req *GeneratePIVCSRRequest) (*GeneratePIVCSRResponse, error)
}

// FIDO2Service handles FIDO2/WebAuthn operations.
type FIDO2Service interface {
	// BeginRegistration begins a WebAuthn registration flow.
	BeginRegistration(ctx context.Context, req *BeginRegistrationRequest) (*BeginRegistrationResponse, error)

	// FinishRegistration completes a WebAuthn registration flow.
	FinishRegistration(ctx context.Context, req *FinishRegistrationRequest) (*FinishRegistrationResponse, error)

	// BeginAuthentication begins a WebAuthn authentication flow.
	BeginAuthentication(ctx context.Context, req *BeginAuthenticationRequest) (*BeginAuthenticationResponse, error)

	// FinishAuthentication completes a WebAuthn authentication flow.
	FinishAuthentication(ctx context.Context, req *FinishAuthenticationRequest) (*FinishAuthenticationResponse, error)
}

// CAService handles Certificate Authority operations.
type CAService interface {
	// GetCABundle retrieves the CA certificate bundle.
	GetCABundle(ctx context.Context, req *GetCABundleRequest) (*GetCABundleResponse, error)

	// GetCACertificate retrieves the CA certificate.
	GetCACertificate(ctx context.Context, req *GetCACertificateRequest) (*GetCACertificateResponse, error)

	// SignCSR signs a certificate signing request.
	SignCSR(ctx context.Context, req *SignCSRRequest) (*SignCSRResponse, error)

	// IssueCertificate issues a new certificate.
	IssueCertificate(ctx context.Context, req *IssueCertificateRequest) (*IssueCertificateResponse, error)

	// RevokeCertificate revokes a certificate.
	RevokeCertificate(ctx context.Context, req *RevokeCertificateRequest) (*RevokeCertificateResponse, error)

	// GenerateCRL generates a certificate revocation list.
	GenerateCRL(ctx context.Context, req *GenerateCRLRequest) (*GenerateCRLResponse, error)

	// IsRevoked checks if a certificate is revoked.
	IsRevoked(ctx context.Context, req *IsRevokedRequest) (*IsRevokedResponse, error)
}

// TCGCAService handles TCG-specific Certificate Authority operations
// for TPM device enrollment and identity certificates.
type TCGCAService interface {
	// IssueEKCertificate issues an Endorsement Key certificate.
	IssueEKCertificate(ctx context.Context, req *IssueEKCertificateRequest) (*IssueEKCertificateResponse, error)

	// IssueAKCertificate issues an Attestation Key certificate.
	IssueAKCertificate(ctx context.Context, req *IssueAKCertificateRequest) (*IssueAKCertificateResponse, error)

	// SignTCGCSR signs a TCG-CSR-IDEVID for device identity enrollment.
	SignTCGCSR(ctx context.Context, req *SignTCGCSRRequest) (*SignTCGCSRResponse, error)

	// EnrollDevice performs complete TCG device enrollment.
	EnrollDevice(ctx context.Context, req *EnrollDeviceRequest) (*EnrollDeviceResponse, error)
}

// PINService handles PIN management operations.
type PINService interface {
	// SetSOPIN sets the Security Officer PIN. If the SO PIN is already set,
	// CurrentSOPIN must match the existing PIN.
	SetSOPIN(ctx context.Context, req *SetSOPINRequest) error

	// SetUserPIN sets the user PIN. Requires SO PIN authorization.
	SetUserPIN(ctx context.Context, req *SetUserPINRequest) error

	// ChangeSOPIN changes the SO PIN.
	ChangeSOPIN(ctx context.Context, req *ChangeSOPINRequest) error

	// ChangeUserPIN changes the user PIN.
	ChangeUserPIN(ctx context.Context, req *ChangeUserPINRequest) error

	// VerifySOPIN verifies the SO PIN.
	VerifySOPIN(ctx context.Context, req *VerifySOPINRequest) error

	// VerifyUserPIN verifies the user PIN.
	VerifyUserPIN(ctx context.Context, req *VerifyUserPINRequest) error

	// GetLockoutStatus returns the current PIN lockout status.
	GetLockoutStatus(ctx context.Context) (*LockoutStatusResponse, error)

	// ResetLockout resets the PIN lockout counter using SO PIN authorization.
	ResetLockout(ctx context.Context, req *ResetLockoutRequest) error
}

// UserService handles xkms user management operations. xkms presents its own
// user model; the backing store is the embedded qrdb node.
type UserService interface {
	// CreateUser creates a new xkms user.
	CreateUser(ctx context.Context, req *CreateUserRequest) (*GetUserResponse, error)

	// ListUsers returns a list of all users.
	ListUsers(ctx context.Context, opts ...ListOption) (*ListUsersResponse, error)

	// GetUser returns information about a specific user.
	GetUser(ctx context.Context, username string) (*GetUserResponse, error)

	// DeleteUser deletes a user.
	DeleteUser(ctx context.Context, username string) error

	// EnableUser enables a user account.
	EnableUser(ctx context.Context, username string) error

	// DisableUser disables a user account.
	DisableUser(ctx context.Context, username string) error

	// BindUserCert binds an mTLS certificate's SPKI thumbprint to a user.
	BindUserCert(ctx context.Context, username, thumbprint string, notAfterUnix int64) error

	// ListUserCredentials returns a list of credentials for a user.
	ListUserCredentials(ctx context.Context, username string) (*ListUserCredentialsResponse, error)
}

// PasswordService handles static password management.
type PasswordService interface {
	// PasswordAdd adds a new static password.
	PasswordAdd(ctx context.Context, req *PasswordAddRequest) (*PasswordAddResponse, error)

	// PasswordGet retrieves a password entry.
	PasswordGet(ctx context.Context, req *PasswordGetRequest) (*PasswordGetResponse, error)

	// PasswordList lists password entries.
	PasswordList(ctx context.Context, req *PasswordListRequest) (*PasswordListResponse, error)

	// PasswordUpdate updates a password entry.
	PasswordUpdate(ctx context.Context, req *PasswordUpdateRequest) error

	// PasswordDelete deletes a password entry.
	PasswordDelete(ctx context.Context, req *PasswordDeleteRequest) error

	// PasswordStoreUnlock unlocks the password store.
	PasswordStoreUnlock(ctx context.Context, req *PasswordStoreUnlockRequest) error

	// PasswordStoreLock locks the password store.
	PasswordStoreLock(ctx context.Context) error

	// PasswordStoreStatus returns the password store status.
	PasswordStoreStatus(ctx context.Context) (*PasswordStoreStatusResponse, error)

	// PasswordStoreSetAccessMode sets the password store access mode.
	PasswordStoreSetAccessMode(ctx context.Context, req *PasswordStoreSetAccessModeRequest) error

	// PasswordGenerate generates a random password.
	PasswordGenerate(ctx context.Context, req *PasswordGenerateRequest) (*PasswordGenerateResponse, error)
}

// SealStoreService handles the local machine sealed credential store.
type SealStoreService interface {
	// SealStorePut stores a secret in the platform store.
	SealStorePut(ctx context.Context, req *SealStorePutRequest) error

	// SealStoreGet retrieves a secret from the platform store.
	SealStoreGet(ctx context.Context, req *SealStoreGetRequest) (*SealStoreGetResponse, error)

	// SealStoreDelete deletes a secret from the platform store.
	SealStoreDelete(ctx context.Context, req *SealStoreDeleteRequest) error

	// SealStoreList lists all stored secret names.
	SealStoreList(ctx context.Context) (*SealStoreListResponse, error)

	// SealStoreReseal reseals a secret with the current sealing key.
	SealStoreReseal(ctx context.Context, req *SealStoreResealRequest) error

	// SealStoreStatus returns the platform store status.
	SealStoreStatus(ctx context.Context) (*SealStoreStatusResponse, error)
}

// PolicyService handles PCR policy management.
type PolicyService interface {
	// PolicyCreate creates a new PCR policy.
	PolicyCreate(ctx context.Context, req *PolicyCreateRequest) (*PolicyCreateResponse, error)

	// PolicyGet retrieves a policy by name.
	PolicyGet(ctx context.Context, req *PolicyGetRequest) (*PolicyGetResponse, error)

	// PolicyList lists all policies.
	PolicyList(ctx context.Context) (*PolicyListResponse, error)

	// PolicyDelete deletes a policy.
	PolicyDelete(ctx context.Context, req *PolicyDeleteRequest) error

	// PolicyRefresh refreshes a policy with current PCR values.
	PolicyRefresh(ctx context.Context, req *PolicyRefreshRequest) (*PolicyGetResponse, error)

	// PolicyVerify verifies a policy against current PCR values.
	PolicyVerify(ctx context.Context, req *PolicyVerifyRequest) (*PolicyVerifyResponse, error)

	// PolicyExport exports a policy.
	PolicyExport(ctx context.Context, req *PolicyExportRequest) (*PolicyExportResponse, error)
}

// InitCeremonyService handles init ceremony operations.
type InitCeremonyService interface {
	// GetInitStatus returns the current init ceremony state.
	GetInitStatus(ctx context.Context) (*InitStatusResponse, error)

	// ClaimCertBegin begins the certificate claim process for an officer.
	ClaimCertBegin(ctx context.Context, req *ClaimCertBeginRequest) (*ClaimCertBeginResponse, error)

	// ClaimCertComplete completes the certificate claim by verifying the officer's signature.
	ClaimCertComplete(ctx context.Context, req *ClaimCertCompleteRequest) (*ClaimCertCompleteResponse, error)

	// ClaimShareBegin starts the Shamir share claim handshake for the named
	// officer. The caller must present an mTLS client certificate matching the
	// officer's enrolment record; the server derives the thumbprint from the
	// verified peer chain, never from the request body.
	ClaimShareBegin(ctx context.Context, req *ClaimShareBeginRequest) (*ClaimShareBeginResponse, error)

	// ClaimShareComplete completes the Shamir share claim handshake by
	// submitting a signature over the challenge nonce. The share is released
	// exactly once.
	ClaimShareComplete(ctx context.Context, req *ClaimShareCompleteRequest) (*ClaimShareCompleteResponse, error)

	// SignCSRInit signs a CSR during initialization with SO authorization.
	SignCSRInit(ctx context.Context, req *SignCSRInitRequest) (*SignCSRInitResponse, error)
}

// CredentialManagementService handles credential management operations.
type CredentialManagementService interface {
	// SubmitCredential submits a credential for manual mode.
	SubmitCredential(ctx context.Context, req *CredentialSubmitRequest) (*CredentialSubmitResponse, error)

	// GetCredentialStrategy returns the configured credential strategy.
	GetCredentialStrategy(ctx context.Context) (*CredentialStrategyResponse, error)
}

// CustodianGroupService handles custodian group management for Shamir
// secret sharing ceremonies.
type CustodianGroupService interface {
	// CreateCustodianGroup creates a new custodian group.
	CreateCustodianGroup(ctx context.Context, req *CreateCustodianGroupRequest) (*CreateCustodianGroupResponse, error)

	// GetCustodianGroup retrieves a custodian group by ID.
	GetCustodianGroup(ctx context.Context, groupID string) (*GetCustodianGroupResponse, error)

	// ListCustodianGroups lists all custodian groups.
	ListCustodianGroups(ctx context.Context) (*ListCustodianGroupsResponse, error)

	// DeleteCustodianGroup deletes a custodian group.
	DeleteCustodianGroup(ctx context.Context, groupID string) error

	// AddCustodianMember adds a member to a custodian group.
	AddCustodianMember(ctx context.Context, req *AddCustodianMemberRequest) (*AddCustodianMemberResponse, error)

	// RemoveCustodianMember removes a member from a custodian group.
	RemoveCustodianMember(ctx context.Context, req *RemoveCustodianMemberRequest) error

	// DistributeShares distributes Shamir shares to custodian group members.
	DistributeShares(ctx context.Context, req *DistributeSharesRequest) (*DistributeSharesResponse, error)
}

// AuditService reads the tamper-evident audit chain owned by the embedded
// qrdb node. There is deliberately no emit method: audit events are written
// by the server as a side effect of the audited operation, never on a
// caller's request, so a client cannot forge a record.
type AuditService interface {
	// QueryAudit returns one page of audit events matching the filter. Pass
	// AuditPage.Next back as AuditFilter.Cursor to continue; an empty Next
	// means the last page.
	QueryAudit(ctx context.Context, filter *AuditFilter) (*AuditPage, error)
}

// ShareService handles Shamir share submission and status tracking.
type ShareService interface {
	// SubmitShare submits a received Shamir share back to the server.
	SubmitShare(ctx context.Context, req *SubmitShareRequest) (*SubmitShareResponse, error)

	// ListShares lists shares available for the authenticated user.
	ListShares(ctx context.Context) (*ListSharesResponse, error)

	// GetShare returns a single share addressed by the triple
	// (serverURL, groupID, shareIndex). Sensitive share material is never
	// included in the response — only the share's metadata.
	GetShare(ctx context.Context, serverURL, groupID string, shareIndex int) (*ShareInfo, error)

	// DeleteShare removes a single share addressed by the triple
	// (serverURL, groupID, shareIndex).
	DeleteShare(ctx context.Context, serverURL, groupID string, shareIndex int) error

	// GetShareCollectionStatus returns the collection status for a group.
	GetShareCollectionStatus(ctx context.Context, groupID string) (*ShareCollectionStatus, error)
}

// TenantService handles multi-tenant management and per-tenant barriers.
type TenantService interface {
	// CreateTenant creates a new tenant.
	CreateTenant(ctx context.Context, req *CreateTenantRequest) (*CreateTenantResponse, error)

	// GetTenant retrieves a tenant by ID.
	GetTenant(ctx context.Context, tenantID string) (*GetTenantResponse, error)

	// ListTenants lists all tenants.
	ListTenants(ctx context.Context) (*ListTenantsResponse, error)

	// DeleteTenant deletes a tenant.
	DeleteTenant(ctx context.Context, tenantID string) error

	// TenantBarrierInit initializes a per-tenant barrier.
	TenantBarrierInit(ctx context.Context, req *TenantBarrierInitRequest) error

	// TenantBarrierUnseal unseals a per-tenant barrier.
	TenantBarrierUnseal(ctx context.Context, req *TenantBarrierUnsealRequest) error

	// TenantBarrierStatus reports the current state of a per-tenant barrier.
	TenantBarrierStatus(ctx context.Context, tenantID string) (*TenantBarrierStatusResponse, error)

	// UpdateTenantEntitlements updates a tenant's feature entitlements.
	UpdateTenantEntitlements(ctx context.Context, req *UpdateTenantEntitlementsRequest) (*UpdateTenantEntitlementsResponse, error)

	// UpdateTenantQuotas updates a tenant's resource quotas.
	UpdateTenantQuotas(ctx context.Context, req *UpdateTenantQuotasRequest) (*UpdateTenantQuotasResponse, error)
}

// EscrowService provides external key-escrow operations (pkg/escrow):
// replicating already-wrapped key material to configured escrow agents,
// recovering it, listing what is escrowed, and revoking an escrowed key.
// The key material carried in every request and response here is always
// already wrapped (AES-KW or RSA-OAEP) by the caller — no escrow agent, and
// no transport carrying these calls, ever sees plaintext key material.
type EscrowService interface {
	// EscrowKey sends wrapped key material to every configured escrow agent.
	EscrowKey(ctx context.Context, req *EscrowRequest) ([]*EscrowReceipt, error)

	// RecoverKey retrieves wrapped key material from the first configured
	// escrow agent that has it.
	RecoverKey(ctx context.Context, req *RecoverRequest) (*RecoverResponse, error)

	// ListEscrowed returns the aggregated escrow records across every
	// configured escrow agent.
	ListEscrowed(ctx context.Context) ([]EscrowRecord, error)

	// RevokeEscrow removes an escrowed key, identified by its escrow-assigned
	// ID, from every configured escrow agent.
	RevokeEscrow(ctx context.Context, escrowID string) error
}

// Client composes all service sub-interfaces into a unified client.
// All transport implementations (gRPC, REST, QUIC, MCP, Unix, Embedded)
// must implement this interface.
//
// This is fully backward compatible: any type that satisfies Client
// also satisfies all sub-interfaces, and any type that satisfies all
// sub-interfaces also satisfies Client.
type Client interface {
	ConnectionService
	BackendService
	KeyService
	CryptoService
	CertService
	SealService
	BarrierService
	PIVService
	FIDO2Service
	CAService
	TCGCAService
	PINService
	UserService
	PasswordService
	SealStoreService
	PolicyService
	CustodianGroupService
	ShareService
	TenantService
	InitCeremonyService
	CredentialManagementService
	AuditService
	EscrowService
}
