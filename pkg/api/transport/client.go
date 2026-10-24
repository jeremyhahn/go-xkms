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

	// CreateOTAImageKey creates the ES256 OTA image-signing key of one
	// trusted-firmware board.
	CreateOTAImageKey(ctx context.Context, req *OTAImageKeyRequest) (*GenerateKeyResponse, error)

	// RotateOTAImageKey creates the next version of a board's OTA
	// image-signing key and makes it current.
	RotateOTAImageKey(ctx context.Context, req *OTAImageKeyRequest) (*RotateKeyResponse, error)

	// SignOTAImage signs an OTA image with the current version of its
	// board's key.
	SignOTAImage(ctx context.Context, req *OTAImageSignRequest) (*SignResponse, error)

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

// KeyVersionService manages key versions. A version is its own backend key:
// version 1 is the key as generated, and RotateKey creates the next version
// and makes it current. Sign and encrypt use the current version; verify and
// decrypt accept an explicit version (see VerifyRequest.KeyVersion and
// DecryptRequest.KeyVersion).
//
// Every call acts on the caller's own tenant, as the other key operations do.
type KeyVersionService interface {
	// ListKeyVersions lists a key's versions and marks the current one.
	ListKeyVersions(ctx context.Context, req *ListKeyVersionsRequest) (*ListKeyVersionsResponse, error)

	// EnableKeyVersion enables a disabled version. A retired version cannot
	// be enabled.
	EnableKeyVersion(ctx context.Context, req *KeyVersionRequest) (*KeyVersionStateResponse, error)

	// DisableKeyVersion disables a version; the current version cannot be
	// disabled.
	DisableKeyVersion(ctx context.Context, req *KeyVersionRequest) (*KeyVersionStateResponse, error)

	// RetireKeyVersion deletes a version's key material for good; the
	// current version cannot be retired.
	RetireKeyVersion(ctx context.Context, req *KeyVersionRequest) (*KeyVersionStateResponse, error)

	// EnableAllKeyVersions enables every disabled version.
	EnableAllKeyVersions(ctx context.Context, req *AllKeyVersionsRequest) (*AllKeyVersionsResponse, error)

	// DisableAllKeyVersions disables every enabled version except the
	// current one.
	DisableAllKeyVersions(ctx context.Context, req *AllKeyVersionsRequest) (*AllKeyVersionsResponse, error)

	// RotateScopeKeys rotates every key of a tenant and reports each key's
	// result.
	RotateScopeKeys(ctx context.Context, req *RotateScopeKeysRequest) (*RotateScopeKeysResponse, error)
}

// CryptoUtilityService defines the envelope, batch, HMAC, random and hash
// operations.
type CryptoUtilityService interface {
	// Rewrap decrypts a ciphertext under its source key and encrypts the
	// plaintext under a target key; the plaintext is never returned.
	Rewrap(ctx context.Context, req *RewrapRequest) (*RewrapResponse, error)

	// EncryptBatch encrypts up to MaxBatchItems plaintexts with one key and
	// reports each item's result.
	EncryptBatch(ctx context.Context, req *EncryptBatchRequest) (*EncryptBatchResponse, error)

	// DecryptBatch decrypts up to MaxBatchItems ciphertexts with one key and
	// reports each item's result.
	DecryptBatch(ctx context.Context, req *DecryptBatchRequest) (*DecryptBatchResponse, error)

	// GenerateDataKey returns a random data key in plaintext and wrapped
	// under the named key.
	GenerateDataKey(ctx context.Context, req *GenerateDataKeyRequest) (*GenerateDataKeyResponse, error)

	// GenerateWrappedDataKey returns a random data key only wrapped under
	// the named key.
	GenerateWrappedDataKey(ctx context.Context, req *GenerateDataKeyRequest) (*GenerateWrappedDataKeyResponse, error)

	// GenerateHMAC computes an HMAC (RFC 2104) with a symmetric key.
	GenerateHMAC(ctx context.Context, req *GenerateHMACRequest) (*GenerateHMACResponse, error)

	// VerifyHMAC verifies an HMAC (RFC 2104) with a symmetric key.
	VerifyHMAC(ctx context.Context, req *VerifyHMACRequest) (*VerifyHMACResponse, error)

	// GenerateRandom returns up to MaxRandomBytes random bytes.
	GenerateRandom(ctx context.Context, req *GenerateRandomRequest) (*GenerateRandomResponse, error)

	// Hash computes the digest of data with a named hash function.
	Hash(ctx context.Context, req *HashRequest) (*HashResponse, error)
}

// KeyManagementService manages keys without using them: their public keys,
// status, metadata, access and rotation policies, AEAD usage limits, and the
// backends that hold them.
type KeyManagementService interface {
	// GetPublicKey returns the PKIX, DER-encoded public key of an asymmetric
	// key.
	GetPublicKey(ctx context.Context, req *GetPublicKeyRequest) (*GetPublicKeyResponse, error)

	// RevokeKey revokes a key for good.
	RevokeKey(ctx context.Context, req *RevokeKeyRequest) (*RevokeKeyResponse, error)

	// UpdateKeyStatus enables or disables a key or one of its versions.
	UpdateKeyStatus(ctx context.Context, req *UpdateKeyStatusRequest) (*UpdateKeyStatusResponse, error)

	// GetKeyMetadata returns a key's metadata.
	GetKeyMetadata(ctx context.Context, req *KeyManagementRequest) (*KeyMetadataResponse, error)

	// UpdateKeyMetadata changes a key's mutable metadata.
	UpdateKeyMetadata(ctx context.Context, req *UpdateKeyMetadataRequest) (*KeyMetadataResponse, error)

	// SetKeyPolicy sets a key's access policy.
	SetKeyPolicy(ctx context.Context, req *SetKeyPolicyRequest) (*SetKeyPolicyResponse, error)

	// GetKeyPolicy returns a key's access policy.
	GetKeyPolicy(ctx context.Context, req *KeyManagementRequest) (*GetKeyPolicyResponse, error)

	// DeleteKeyPolicy removes a key's access policy; the key falls back to
	// RBAC alone.
	DeleteKeyPolicy(ctx context.Context, req *KeyManagementRequest) (*KeyManagementResponse, error)

	// SetKeyRotationPolicy sets a key's rotation policy.
	SetKeyRotationPolicy(ctx context.Context, req *SetKeyRotationPolicyRequest) (*KeyRotationPolicyResponse, error)

	// GetKeyRotationPolicy returns a key's rotation policy.
	GetKeyRotationPolicy(ctx context.Context, req *KeyManagementRequest) (*KeyRotationPolicyResponse, error)

	// DeleteKeyRotationPolicy removes a key's rotation policy.
	DeleteKeyRotationPolicy(ctx context.Context, req *KeyManagementRequest) (*KeyManagementResponse, error)

	// GetSupportedAlgorithms lists the algorithms a backend supports.
	GetSupportedAlgorithms(ctx context.Context, req *BackendRequest) (*GetSupportedAlgorithmsResponse, error)

	// BackendStatus reports a backend's type, health and capabilities.
	BackendStatus(ctx context.Context, req *BackendRequest) (*BackendStatusResponse, error)

	// BackendTest runs a non-destructive seal and unseal round trip on a
	// backend.
	BackendTest(ctx context.Context, req *BackendRequest) (*BackendTestResponse, error)

	// SetKeySafety sets a symmetric AEAD key's usage limits.
	SetKeySafety(ctx context.Context, req *SetKeySafetyRequest) (*KeyManagementResponse, error)

	// ClearKeySafety removes a key's usage limits.
	ClearKeySafety(ctx context.Context, req *KeyManagementRequest) (*KeyManagementResponse, error)

	// SafetyCheck lists the keys at or past their warning threshold.
	SafetyCheck(ctx context.Context, req *SafetyCheckRequest) (*SafetyCheckResponse, error)

	// SafetyReport reports the usage of every key with usage limits.
	SafetyReport(ctx context.Context, req *SafetyReportRequest) (*SafetyReportResponse, error)
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

// BootstrapService reports the running trust-bootstrap listener's public
// static keys (go-xkms#632).
type BootstrapService interface {
	// BootstrapListenerKeys returns the listener's public keys. Returns a
	// typed "not enabled" error when no bootstrap listener has published
	// its keys yet.
	BootstrapListenerKeys(ctx context.Context) (*BootstrapListenerKeysResponse, error)
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

	// IssueLAKCertificate issues a Local Attestation Key certificate in the
	// WebAuthn Level 2 §8.3.1 profile (go-xkms#715).
	IssueLAKCertificate(ctx context.Context, req *IssueLAKCertificateRequest) (*IssueLAKCertificateResponse, error)
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

	// PasswordStoreUnlock opens the caller's personal session with one of the
	// caller's own vault factors (a passphrase or a passkey).
	PasswordStoreUnlock(ctx context.Context, req *PasswordStoreUnlockRequest) error

	// PasswordStoreLock closes the caller's personal session.
	PasswordStoreLock(ctx context.Context) error

	// PasswordVaultStatus describes the caller's personal vault: whether a
	// factor is enrolled, whether the session is open, and the factors (a
	// passkey's credential ID and PRF salt are what a client evaluates
	// hmac-secret with before unlocking).
	PasswordVaultStatus(ctx context.Context) (*PasswordVaultStatusResponse, error)

	// PasswordVaultEnroll enrolls a passphrase or passkey. The first
	// enrollment initializes the vault and returns the one-time recovery
	// code; later enrollments need the caller's session open.
	PasswordVaultEnroll(ctx context.Context, req *PasswordVaultEnrollRequest) (*PasswordVaultEnrollResponse, error)

	// PasswordVaultRotate re-wraps the caller's key under a new secret for a
	// factor of the same type.
	PasswordVaultRotate(ctx context.Context, req *PasswordVaultRotateRequest) (*PasswordVaultEnrollResponse, error)

	// PasswordVaultRemoveFactor removes one of the caller's factors.
	PasswordVaultRemoveFactor(ctx context.Context, req *PasswordVaultRemoveFactorRequest) error

	// PasswordVaultRecover uses the caller's one-time recovery code to enroll
	// a new factor, and returns the replacement code.
	PasswordVaultRecover(ctx context.Context, req *PasswordVaultRecoverRequest) (*PasswordVaultEnrollResponse, error)

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

// TPMPolicyService manages named TPM policies, the registry of which TPM
// object uses which policy, and each tenant's TPM mode (pkg/tpmpolicy).
//
// Policy operations act on the caller's own tenant, and naming another tenant
// in the request's TenantID is refused to every caller, the system tenant's
// included. The tenant TPM mode and vTPM operations are system-scope only.
type TPMPolicyService interface {
	// TPMPolicyCreate creates a named policy of branches, capturing the
	// values of its pcr conditions from the tenant's TPM.
	TPMPolicyCreate(ctx context.Context, req *TPMPolicyCreateRequest) (*TPMPolicy, error)

	// TPMPolicyGet returns a named policy.
	TPMPolicyGet(ctx context.Context, req *TPMPolicyRequest) (*TPMPolicy, error)

	// TPMPolicyList returns the tenant's named policies.
	TPMPolicyList(ctx context.Context, req *TPMPolicyListRequest) (*TPMPolicyListResponse, error)

	// TPMPolicyUpdate re-captures a policy's PCR values, or updates one
	// branch from signed reference values, and re-approves it. No object is
	// re-keyed.
	TPMPolicyUpdate(ctx context.Context, req *TPMPolicyUpdateRequest) (*TPMPolicy, error)

	// TPMPolicyRevoke withdraws a policy's current approval.
	TPMPolicyRevoke(ctx context.Context, req *TPMPolicyRequest) (*TPMPolicy, error)

	// TPMPolicyVerify compares a policy's captured PCR values with the
	// live ones, branch by branch.
	TPMPolicyVerify(ctx context.Context, req *TPMPolicyRequest) (*TPMPolicyVerifyResponse, error)

	// TPMPolicyDelete deletes a policy no object is assigned to.
	TPMPolicyDelete(ctx context.Context, req *TPMPolicyDeleteRequest) error

	// TPMPolicyObjects lists the objects assigned to a policy.
	TPMPolicyObjects(ctx context.Context, req *TPMPolicyRequest) (*TPMPolicyObjectsResponse, error)

	// TPMPolicySetAutoUnseal sets or clears a policy's auto-unseal mark.
	TPMPolicySetAutoUnseal(ctx context.Context, req *TPMPolicyAutoUnsealRequest) (*TPMPolicy, error)

	// TPMPolicySetDescription replaces a policy's description.
	TPMPolicySetDescription(ctx context.Context, req *TPMPolicyDescriptionRequest) (*TPMPolicy, error)

	// TPMObjectPolicy returns the policy a TPM key or sealed object was
	// created under.
	TPMObjectPolicy(ctx context.Context, req *TPMObjectPolicyRequest) (*TPMObjectPolicyResponse, error)

	// TPMPolicyRotateAuthority replaces the tenant's policy authority.
	TPMPolicyRotateAuthority(ctx context.Context, req *TPMAuthorityRotateRequest) (*TPMAuthorityRotateResponse, error)

	// GetTenantTPMMode returns a tenant's TPM mode.
	GetTenantTPMMode(ctx context.Context, tenantID string) (*TenantTPMModeResponse, error)

	// SetTenantTPMMode changes a tenant's TPM mode.
	SetTenantTPMMode(ctx context.Context, req *SetTenantTPMModeRequest) (*TenantTPMModeResponse, error)

	// TenantVTPMStatus reports a tenant's virtual TPM.
	TenantVTPMStatus(ctx context.Context, tenantID string) (*TenantVTPMStatusResponse, error)

	// TenantVTPMStart starts a vtpm-mode tenant's virtual TPM.
	TenantVTPMStart(ctx context.Context, tenantID string) (*TenantVTPMStatusResponse, error)

	// TenantVTPMStop stops a vtpm-mode tenant's virtual TPM.
	TenantVTPMStop(ctx context.Context, tenantID string) (*TenantVTPMStatusResponse, error)
}

// TrustRootService manages the platform's purpose-classified trust-root
// store (pkg/attestation/truststore). The store is process-wide, so every
// operation is system-scope only.
type TrustRootService interface {
	// TrustRootList lists the roots, optionally of one purpose.
	TrustRootList(ctx context.Context, req *TrustRootListRequest) (*TrustRootListResponse, error)

	// TrustRootGet returns one root, its PEM included.
	TrustRootGet(ctx context.Context, req *TrustRootRequest) (*TrustRoot, error)

	// TrustRootImport adds the certificates of a PEM bundle, skipping the
	// ones the store already holds.
	TrustRootImport(ctx context.Context, req *TrustRootImportRequest) (*TrustRootImportResponse, error)

	// TrustRootQuarantine reclassifies a root as "synced": it stays listed
	// but no longer anchors any verification.
	TrustRootQuarantine(ctx context.Context, req *TrustRootRequest) (*TrustRoot, error)

	// TrustRootRemove deletes a root.
	TrustRootRemove(ctx context.Context, req *TrustRootRequest) error
}

// CredentialManagementService handles credential management operations.
type CredentialManagementService interface {
	// SubmitCredential submits a credential for manual mode.
	SubmitCredential(ctx context.Context, req *CredentialSubmitRequest) (*CredentialSubmitResponse, error)

	// GetCredentialStrategy returns the configured credential strategy.
	GetCredentialStrategy(ctx context.Context) (*CredentialStrategyResponse, error)
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
//
// It is embedded-only (go-xkms#692) and deliberately NOT part of Client:
// Escrow's RBAC model is undecided, so no network transport (gRPC, REST,
// QUIC, Unix, MCP, USB) implements it. A caller that needs escrow
// type-asserts its Client to EscrowService — the embedded transport is the
// only implementation — rather than finding it on Client itself.
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
//
// EscrowService is deliberately NOT part of this composition (go-xkms#692):
// see its doc comment. Only the embedded transport implements it.
type Client interface {
	ConnectionService
	BackendService
	KeyService
	KeyVersionService
	CryptoUtilityService
	KeyManagementService
	CryptoService
	CertService
	SealService
	PIVService
	FIDO2Service
	CAService
	TCGCAService
	PINService
	UserService
	PasswordService
	SealStoreService
	TPMPolicyService
	SigningKeyService
	TrustRootService
	OIDCCredentialService
	TenantService
	CredentialManagementService
	BootstrapService
	InviteService
}

// InviteService redeems administrator-issued account-activation
// invitations; see InviteServicer's doc comment (servicer.go) for the
// contract every transport implementing this must honor.
type InviteService interface {
	GetInvite(ctx context.Context, req *GetInviteRequest) (*GetInviteResponse, error)
	BeginInviteRegistration(ctx context.Context, req *BeginInviteRegistrationRequest) (*BeginInviteRegistrationResponse, error)
	FinishInviteRegistration(ctx context.Context, req *FinishInviteRegistrationRequest) (*FinishInviteRegistrationResponse, error)
	ActivateInvitePIV(ctx context.Context, req *ActivateInvitePIVRequest) (*ActivateInvitePIVResponse, error)
}
