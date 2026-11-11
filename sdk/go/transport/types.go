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

// Package transport re-exports types from the canonical pkg/transport package
// to maintain backward compatibility for SDK consumers.
package transport

import (
	pkgtransport "github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// Health and backend types.
type HealthResponse = pkgtransport.HealthResponse
type BackendCapabilities = pkgtransport.BackendCapabilities
type BackendInfo = pkgtransport.BackendInfo
type ListBackendsResponse = pkgtransport.ListBackendsResponse

// Algorithm discovery types.
type AlgorithmInfo = pkgtransport.AlgorithmInfo
type AlgorithmsResponse = pkgtransport.AlgorithmsResponse

// Key management types.
type GenerateKeyRequest = pkgtransport.GenerateKeyRequest
type GenerateKeyResponse = pkgtransport.GenerateKeyResponse
type KeyInfo = pkgtransport.KeyInfo
type ListKeysResponse = pkgtransport.ListKeysResponse
type GetKeyResponse = pkgtransport.GetKeyResponse
type DeleteKeyResponse = pkgtransport.DeleteKeyResponse
type ImportKeyRequest = pkgtransport.ImportKeyRequest
type ImportKeyResponse = pkgtransport.ImportKeyResponse
type ExportKeyRequest = pkgtransport.ExportKeyRequest
type ExportKeyResponse = pkgtransport.ExportKeyResponse
type RotateKeyRequest = pkgtransport.RotateKeyRequest
type RotateKeyResponse = pkgtransport.RotateKeyResponse
type OTAImageKeyRequest = pkgtransport.OTAImageKeyRequest
type OTAImageSignRequest = pkgtransport.OTAImageSignRequest
type GetImportParametersRequest = pkgtransport.GetImportParametersRequest
type GetImportParametersResponse = pkgtransport.GetImportParametersResponse
type CopyKeyRequest = pkgtransport.CopyKeyRequest
type CopyKeyResponse = pkgtransport.CopyKeyResponse
type ExportKeyMaterialRequest = pkgtransport.ExportKeyMaterialRequest
type ExportKeyMaterialResponse = pkgtransport.ExportKeyMaterialResponse
type WrapKeyRequest = pkgtransport.WrapKeyRequest
type WrapKeyResponse = pkgtransport.WrapKeyResponse
type UnwrapKeyRequest = pkgtransport.UnwrapKeyRequest
type UnwrapKeyResponse = pkgtransport.UnwrapKeyResponse
type WrapKeyByIDRequest = pkgtransport.WrapKeyByIDRequest
type WrapKeyByIDResponse = pkgtransport.WrapKeyByIDResponse
type UnwrapKeyByIDRequest = pkgtransport.UnwrapKeyByIDRequest
type UnwrapKeyByIDResponse = pkgtransport.UnwrapKeyByIDResponse

// Crypto operation types.
type SignRequest = pkgtransport.SignRequest
type SignResponse = pkgtransport.SignResponse
type VerifyRequest = pkgtransport.VerifyRequest
type VerifyResponse = pkgtransport.VerifyResponse
type EncryptRequest = pkgtransport.EncryptRequest
type EncryptResponse = pkgtransport.EncryptResponse
type DecryptRequest = pkgtransport.DecryptRequest
type DecryptResponse = pkgtransport.DecryptResponse
type EncryptAsymRequest = pkgtransport.EncryptAsymRequest
type EncryptAsymResponse = pkgtransport.EncryptAsymResponse
type DeriveKeyRequest = pkgtransport.DeriveKeyRequest
type DeriveKeyResponse = pkgtransport.DeriveKeyResponse
type DeriveKeyECDHRequest = pkgtransport.DeriveKeyECDHRequest
type DeriveKeyECDHResponse = pkgtransport.DeriveKeyECDHResponse
type AttestKeyRequest = pkgtransport.AttestKeyRequest
type AttestKeyResponse = pkgtransport.AttestKeyResponse

// Seal operation types.
type SealRequest = pkgtransport.SealRequest
type SealResponse = pkgtransport.SealResponse
type UnsealRequest = pkgtransport.UnsealRequest
type UnsealResponse = pkgtransport.UnsealResponse
type CanSealResponse = pkgtransport.CanSealResponse

// Trust bootstrap listener types (re-exported from pkg/api/transport).
type BootstrapListenerKeysResponse = pkgtransport.BootstrapListenerKeysResponse

// Certificate types.
type GetCertificateResponse = pkgtransport.GetCertificateResponse
type SaveCertificateRequest = pkgtransport.SaveCertificateRequest
type ListCertificatesResponse = pkgtransport.ListCertificatesResponse
type CertificateInfo = pkgtransport.CertificateInfo
type SaveCertificateChainRequest = pkgtransport.SaveCertificateChainRequest
type GetCertificateChainResponse = pkgtransport.GetCertificateChainResponse
type GetTLSCertificateResponse = pkgtransport.GetTLSCertificateResponse

// PIV types.
type ListPIVSlotsRequest = pkgtransport.ListPIVSlotsRequest
type ListPIVSlotsResponse = pkgtransport.ListPIVSlotsResponse
type PIVSlotStatus = pkgtransport.PIVSlotStatus
type GetPIVCertificateRequest = pkgtransport.GetPIVCertificateRequest
type GetPIVCertificateResponse = pkgtransport.GetPIVCertificateResponse
type StorePIVCertificateRequest = pkgtransport.StorePIVCertificateRequest
type DeletePIVCertificateRequest = pkgtransport.DeletePIVCertificateRequest
type GeneratePIVKeyRequest = pkgtransport.GeneratePIVKeyRequest
type GeneratePIVKeyResponse = pkgtransport.GeneratePIVKeyResponse
type GeneratePIVCSRRequest = pkgtransport.GeneratePIVCSRRequest
type GeneratePIVCSRResponse = pkgtransport.GeneratePIVCSRResponse

// FIDO2/WebAuthn types.
type BeginRegistrationRequest = pkgtransport.BeginRegistrationRequest
type BeginRegistrationResponse = pkgtransport.BeginRegistrationResponse
type FinishRegistrationRequest = pkgtransport.FinishRegistrationRequest
type FinishRegistrationResponse = pkgtransport.FinishRegistrationResponse
type BeginAuthenticationRequest = pkgtransport.BeginAuthenticationRequest
type BeginAuthenticationResponse = pkgtransport.BeginAuthenticationResponse
type FinishAuthenticationRequest = pkgtransport.FinishAuthenticationRequest
type FinishAuthenticationResponse = pkgtransport.FinishAuthenticationResponse

// CA types.
type GetCABundleRequest = pkgtransport.GetCABundleRequest
type GetCABundleResponse = pkgtransport.GetCABundleResponse
type GetCACertificateRequest = pkgtransport.GetCACertificateRequest
type GetCACertificateResponse = pkgtransport.GetCACertificateResponse
type SignCSRRequest = pkgtransport.SignCSRRequest
type SignCSRResponse = pkgtransport.SignCSRResponse
type IssueCertificateRequest = pkgtransport.IssueCertificateRequest
type IssueCertificateResponse = pkgtransport.IssueCertificateResponse
type RevokeCertificateRequest = pkgtransport.RevokeCertificateRequest
type RevokeCertificateResponse = pkgtransport.RevokeCertificateResponse
type GenerateCRLRequest = pkgtransport.GenerateCRLRequest
type GenerateCRLResponse = pkgtransport.GenerateCRLResponse
type IsRevokedRequest = pkgtransport.IsRevokedRequest
type IsRevokedResponse = pkgtransport.IsRevokedResponse

// TCG CA types.
type IssueEKCertificateRequest = pkgtransport.IssueEKCertificateRequest
type IssueEKCertificateResponse = pkgtransport.IssueEKCertificateResponse
type IssueAKCertificateRequest = pkgtransport.IssueAKCertificateRequest
type IssueAKCertificateResponse = pkgtransport.IssueAKCertificateResponse
type SignTCGCSRRequest = pkgtransport.SignTCGCSRRequest
type SignTCGCSRResponse = pkgtransport.SignTCGCSRResponse
type EnrollDeviceRequest = pkgtransport.EnrollDeviceRequest
type EnrollDeviceResponse = pkgtransport.EnrollDeviceResponse
type IssueLAKCertificateRequest = pkgtransport.IssueLAKCertificateRequest
type IssueLAKCertificateResponse = pkgtransport.IssueLAKCertificateResponse

// PIN types.
type SetSOPINRequest = pkgtransport.SetSOPINRequest
type SetUserPINRequest = pkgtransport.SetUserPINRequest
type ChangeSOPINRequest = pkgtransport.ChangeSOPINRequest
type ChangeUserPINRequest = pkgtransport.ChangeUserPINRequest
type VerifySOPINRequest = pkgtransport.VerifySOPINRequest
type VerifyUserPINRequest = pkgtransport.VerifyUserPINRequest
type LockoutStatusResponse = pkgtransport.LockoutStatusResponse
type ResetLockoutRequest = pkgtransport.ResetLockoutRequest

// User types.
type UserInfo = pkgtransport.UserInfo
type CredentialInfo = pkgtransport.CredentialInfo
type CreateUserRequest = pkgtransport.CreateUserRequest
type ListUsersResponse = pkgtransport.ListUsersResponse
type GetUserResponse = pkgtransport.GetUserResponse
type ListUserCredentialsResponse = pkgtransport.ListUserCredentialsResponse

// InviteInfo is the one-time account-activation invitation CreateUser mints
// for an account with an email login key (go-xkms#1294 part B).
type InviteInfo = pkgtransport.InviteInfo

// Invite redemption types. These are public, unauthenticated capabilities
// available on every transport (go-xkms#1294 part B).
type GetInviteRequest = pkgtransport.GetInviteRequest
type GetInviteResponse = pkgtransport.GetInviteResponse
type BeginInviteRegistrationRequest = pkgtransport.BeginInviteRegistrationRequest
type BeginInviteRegistrationResponse = pkgtransport.BeginInviteRegistrationResponse
type FinishInviteRegistrationRequest = pkgtransport.FinishInviteRegistrationRequest
type FinishInviteRegistrationResponse = pkgtransport.FinishInviteRegistrationResponse
type ActivateInvitePIVRequest = pkgtransport.ActivateInvitePIVRequest
type ActivateInvitePIVResponse = pkgtransport.ActivateInvitePIVResponse

// Password types.
type PasswordAddRequest = pkgtransport.PasswordAddRequest
type PasswordAddResponse = pkgtransport.PasswordAddResponse
type PasswordGetRequest = pkgtransport.PasswordGetRequest
type PasswordGetResponse = pkgtransport.PasswordGetResponse
type PasswordListRequest = pkgtransport.PasswordListRequest
type PasswordListResponse = pkgtransport.PasswordListResponse
type PasswordUpdateRequest = pkgtransport.PasswordUpdateRequest
type PasswordDeleteRequest = pkgtransport.PasswordDeleteRequest
type PasswordStoreUnlockRequest = pkgtransport.PasswordStoreUnlockRequest
type PasswordStoreStatusResponse = pkgtransport.PasswordStoreStatusResponse
type PasswordStoreSetAccessModeRequest = pkgtransport.PasswordStoreSetAccessModeRequest
type PasswordGenerateRequest = pkgtransport.PasswordGenerateRequest
type PasswordGenerateResponse = pkgtransport.PasswordGenerateResponse

// Personal password vault types.
type PasswordVaultCredential = pkgtransport.PasswordVaultCredential
type PasswordVaultFactor = pkgtransport.PasswordVaultFactor
type PasswordVaultKeyRef = pkgtransport.PasswordVaultKeyRef
type PasswordVaultStatusResponse = pkgtransport.PasswordVaultStatusResponse
type PasswordVaultEnrollRequest = pkgtransport.PasswordVaultEnrollRequest
type PasswordVaultEnrollResponse = pkgtransport.PasswordVaultEnrollResponse
type PasswordVaultRotateRequest = pkgtransport.PasswordVaultRotateRequest
type PasswordVaultRemoveFactorRequest = pkgtransport.PasswordVaultRemoveFactorRequest
type PasswordVaultRecoverRequest = pkgtransport.PasswordVaultRecoverRequest

// Platform store types.
type SealStorePutRequest = pkgtransport.SealStorePutRequest
type SealStoreGetRequest = pkgtransport.SealStoreGetRequest
type SealStoreGetResponse = pkgtransport.SealStoreGetResponse
type SealStoreDeleteRequest = pkgtransport.SealStoreDeleteRequest
type SealStoreListResponse = pkgtransport.SealStoreListResponse
type SealStoreResealRequest = pkgtransport.SealStoreResealRequest
type SealStoreStatusResponse = pkgtransport.SealStoreStatusResponse

// Key version types.
type KeyVersionInfo = pkgtransport.KeyVersionInfo
type ListKeyVersionsRequest = pkgtransport.ListKeyVersionsRequest
type ListKeyVersionsResponse = pkgtransport.ListKeyVersionsResponse
type KeyVersionRequest = pkgtransport.KeyVersionRequest
type KeyVersionStateResponse = pkgtransport.KeyVersionStateResponse
type AllKeyVersionsRequest = pkgtransport.AllKeyVersionsRequest
type AllKeyVersionsResponse = pkgtransport.AllKeyVersionsResponse
type RotateScopeKeysRequest = pkgtransport.RotateScopeKeysRequest
type RotateScopeKeysResponse = pkgtransport.RotateScopeKeysResponse
type KeyRotationResult = pkgtransport.KeyRotationResult

// Crypto utility types
type RewrapRequest = pkgtransport.RewrapRequest
type RewrapResponse = pkgtransport.RewrapResponse
type EncryptBatchItem = pkgtransport.EncryptBatchItem
type EncryptBatchRequest = pkgtransport.EncryptBatchRequest
type EncryptBatchResult = pkgtransport.EncryptBatchResult
type EncryptBatchResponse = pkgtransport.EncryptBatchResponse
type DecryptBatchItem = pkgtransport.DecryptBatchItem
type DecryptBatchRequest = pkgtransport.DecryptBatchRequest
type DecryptBatchResult = pkgtransport.DecryptBatchResult
type DecryptBatchResponse = pkgtransport.DecryptBatchResponse
type GenerateDataKeyRequest = pkgtransport.GenerateDataKeyRequest
type GenerateDataKeyResponse = pkgtransport.GenerateDataKeyResponse
type GenerateWrappedDataKeyResponse = pkgtransport.GenerateWrappedDataKeyResponse
type GenerateHMACRequest = pkgtransport.GenerateHMACRequest
type GenerateHMACResponse = pkgtransport.GenerateHMACResponse
type VerifyHMACRequest = pkgtransport.VerifyHMACRequest
type VerifyHMACResponse = pkgtransport.VerifyHMACResponse
type GenerateRandomRequest = pkgtransport.GenerateRandomRequest
type GenerateRandomResponse = pkgtransport.GenerateRandomResponse
type HashRequest = pkgtransport.HashRequest
type HashResponse = pkgtransport.HashResponse

// Key management types
type KeyStatus = pkgtransport.KeyStatus
type KeyUsage = pkgtransport.KeyUsage
type KeyAlgorithm = pkgtransport.KeyAlgorithm
type KeyManagementRequest = pkgtransport.KeyManagementRequest
type KeyManagementResponse = pkgtransport.KeyManagementResponse
type GetPublicKeyRequest = pkgtransport.GetPublicKeyRequest
type GetPublicKeyResponse = pkgtransport.GetPublicKeyResponse
type RevokeKeyRequest = pkgtransport.RevokeKeyRequest
type RevokeKeyResponse = pkgtransport.RevokeKeyResponse
type UpdateKeyStatusRequest = pkgtransport.UpdateKeyStatusRequest
type UpdateKeyStatusResponse = pkgtransport.UpdateKeyStatusResponse
type KeyMetadata = pkgtransport.KeyMetadata
type KeyMetadataResponse = pkgtransport.KeyMetadataResponse
type UpdateKeyMetadataRequest = pkgtransport.UpdateKeyMetadataRequest
type KeyPolicy = pkgtransport.KeyPolicy
type SetKeyPolicyRequest = pkgtransport.SetKeyPolicyRequest
type SetKeyPolicyResponse = pkgtransport.SetKeyPolicyResponse
type GetKeyPolicyResponse = pkgtransport.GetKeyPolicyResponse
type RotationPolicy = pkgtransport.RotationPolicy
type SetKeyRotationPolicyRequest = pkgtransport.SetKeyRotationPolicyRequest
type KeyRotationPolicyResponse = pkgtransport.KeyRotationPolicyResponse
type BackendRequest = pkgtransport.BackendRequest
type GetSupportedAlgorithmsResponse = pkgtransport.GetSupportedAlgorithmsResponse
type BackendStatusResponse = pkgtransport.BackendStatusResponse
type BackendTestResponse = pkgtransport.BackendTestResponse
type SetKeySafetyRequest = pkgtransport.SetKeySafetyRequest
type SafetyWarning = pkgtransport.SafetyWarning
type SafetyCheckRequest = pkgtransport.SafetyCheckRequest
type SafetyCheckResponse = pkgtransport.SafetyCheckResponse
type SafetyReportRequest = pkgtransport.SafetyReportRequest
type SafetyReportResponse = pkgtransport.SafetyReportResponse

// Key statuses.
const (
	KeyStatusEnabled         = pkgtransport.KeyStatusEnabled
	KeyStatusDisabled        = pkgtransport.KeyStatusDisabled
	KeyStatusPendingDeletion = pkgtransport.KeyStatusPendingDeletion
	KeyStatusDeleted         = pkgtransport.KeyStatusDeleted
	KeyStatusRotating        = pkgtransport.KeyStatusRotating
	KeyStatusCompromised     = pkgtransport.KeyStatusCompromised
)

// Key usages a key policy allows.
const (
	KeyUsageEncrypt     = pkgtransport.KeyUsageEncrypt
	KeyUsageDecrypt     = pkgtransport.KeyUsageDecrypt
	KeyUsageSign        = pkgtransport.KeyUsageSign
	KeyUsageVerify      = pkgtransport.KeyUsageVerify
	KeyUsageWrapKey     = pkgtransport.KeyUsageWrapKey
	KeyUsageDeriveKey   = pkgtransport.KeyUsageDeriveKey
	KeyUsageGenerateMAC = pkgtransport.KeyUsageGenerateMAC
	KeyUsageVerifyMAC   = pkgtransport.KeyUsageVerifyMAC
)

// Crypto utility limits
const (
	MaxBatchItems  = pkgtransport.MaxBatchItems
	MaxRandomBytes = pkgtransport.MaxRandomBytes
)

// Key version states.
const (
	KeyVersionEnabled  = pkgtransport.KeyVersionEnabled
	KeyVersionDisabled = pkgtransport.KeyVersionDisabled
	KeyVersionRetired  = pkgtransport.KeyVersionRetired
)

// Key rotation result states.
const (
	KeyRotationRotated = pkgtransport.KeyRotationRotated
	KeyRotationSkipped = pkgtransport.KeyRotationSkipped
	KeyRotationFailed  = pkgtransport.KeyRotationFailed
)

// TPM policy types.
type TPMPolicy = pkgtransport.TPMPolicy
type TPMPolicyBranch = pkgtransport.TPMPolicyBranch
type TPMPolicyCondition = pkgtransport.TPMPolicyCondition
type TPMPolicyCreateRequest = pkgtransport.TPMPolicyCreateRequest
type TPMPolicyDescriptionRequest = pkgtransport.TPMPolicyDescriptionRequest
type TPMPolicyBranchVerification = pkgtransport.TPMPolicyBranchVerification
type TPMPolicyRequest = pkgtransport.TPMPolicyRequest
type TPMPolicyUpdateRequest = pkgtransport.TPMPolicyUpdateRequest
type TPMPolicyReference = pkgtransport.TPMPolicyReference
type TPMPolicyListRequest = pkgtransport.TPMPolicyListRequest
type TPMPolicyListResponse = pkgtransport.TPMPolicyListResponse
type TPMPolicyDeleteRequest = pkgtransport.TPMPolicyDeleteRequest
type TPMPolicyVerifyResponse = pkgtransport.TPMPolicyVerifyResponse
type TPMPolicyObjectsResponse = pkgtransport.TPMPolicyObjectsResponse
type TPMPolicyAutoUnsealRequest = pkgtransport.TPMPolicyAutoUnsealRequest
type TPMObjectPolicyRequest = pkgtransport.TPMObjectPolicyRequest
type TPMObjectPolicyResponse = pkgtransport.TPMObjectPolicyResponse
type TPMAuthorityRotateRequest = pkgtransport.TPMAuthorityRotateRequest
type TPMAuthorityRotateResponse = pkgtransport.TPMAuthorityRotateResponse
type TenantTPMModeResponse = pkgtransport.TenantTPMModeResponse
type SetTenantTPMModeRequest = pkgtransport.SetTenantTPMModeRequest
type TenantVTPMStatusResponse = pkgtransport.TenantVTPMStatusResponse

// OIDC credential types (server-side OIDC credentials).
type OIDCCredential = pkgtransport.OIDCCredential
type OIDCCredentialRef = pkgtransport.OIDCCredentialRef
type OIDCCredentialConfig = pkgtransport.OIDCCredentialConfig
type OIDCCredentialTokens = pkgtransport.OIDCCredentialTokens
type OIDCCredentialCreateRequest = pkgtransport.OIDCCredentialCreateRequest
type OIDCCredentialImportRequest = pkgtransport.OIDCCredentialImportRequest
type OIDCCredentialListRequest = pkgtransport.OIDCCredentialListRequest
type OIDCCredentialListResponse = pkgtransport.OIDCCredentialListResponse

// Attestation Verifier types (go-xkms#1608).
type AttestationEndorsementKind = pkgtransport.AttestationEndorsementKind
type AttestationEndorsement = pkgtransport.AttestationEndorsement
type PutAttestationEndorsementRequest = pkgtransport.PutAttestationEndorsementRequest
type ListAttestationEndorsementsRequest = pkgtransport.ListAttestationEndorsementsRequest
type ListAttestationEndorsementsResponse = pkgtransport.ListAttestationEndorsementsResponse
type DeleteAttestationEndorsementRequest = pkgtransport.DeleteAttestationEndorsementRequest
type AttestationReferenceValues = pkgtransport.AttestationReferenceValues
type PutAttestationReferenceValuesRequest = pkgtransport.PutAttestationReferenceValuesRequest
type GetAttestationReferenceValuesRequest = pkgtransport.GetAttestationReferenceValuesRequest
type ListAttestationReferenceValuesResponse = pkgtransport.ListAttestationReferenceValuesResponse
type DeleteAttestationReferenceValuesRequest = pkgtransport.DeleteAttestationReferenceValuesRequest
type AppraiseAttestationQuoteRequest = pkgtransport.AppraiseAttestationQuoteRequest
type AttestationResult = pkgtransport.AttestationResult
type AttestationAppraisalCheck = pkgtransport.AttestationAppraisalCheck
type AttestationAppraisalOutcome = pkgtransport.AttestationAppraisalOutcome

// Repository signing-key binding types (go-xkms#1697).
type SigningKeyBinding = pkgtransport.SigningKeyBinding
type SetSigningKeyBindingRequest = pkgtransport.SetSigningKeyBindingRequest
type GetSigningKeyBindingRequest = pkgtransport.GetSigningKeyBindingRequest
type ListSigningKeyBindingsResponse = pkgtransport.ListSigningKeyBindingsResponse
type DeleteSigningKeyBindingRequest = pkgtransport.DeleteSigningKeyBindingRequest
type ResolveSigningKeyRequest = pkgtransport.ResolveSigningKeyRequest
type SigningKeyResolution = pkgtransport.SigningKeyResolution
type SignCoRIMRequest = pkgtransport.SignCoRIMRequest
type SignedCoRIM = pkgtransport.SignedCoRIM
type SignImageRequest = pkgtransport.SignImageRequest
type ImageRegistryCredentials = pkgtransport.ImageRegistryCredentials
type SignedImage = pkgtransport.SignedImage
type OIDCDeviceLogin = pkgtransport.OIDCDeviceLogin
type OIDCAccessToken = pkgtransport.OIDCAccessToken

// Trust root types (the platform trust-root store).
type TrustRoot = pkgtransport.TrustRoot
type TrustRootRequest = pkgtransport.TrustRootRequest
type TrustRootListRequest = pkgtransport.TrustRootListRequest
type TrustRootListResponse = pkgtransport.TrustRootListResponse
type TrustRootImportRequest = pkgtransport.TrustRootImportRequest
type TrustRootImportResponse = pkgtransport.TrustRootImportResponse

// OIDC credential scopes and statuses.
const (
	OIDCCredentialScopeTenant           = pkgtransport.OIDCCredentialScopeTenant
	OIDCCredentialScopeUser             = pkgtransport.OIDCCredentialScopeUser
	OIDCCredentialStatusPending         = pkgtransport.OIDCCredentialStatusPending
	OIDCCredentialStatusActive          = pkgtransport.OIDCCredentialStatusActive
	OIDCCredentialStatusReloginRequired = pkgtransport.OIDCCredentialStatusReloginRequired
	OIDCCredentialStatusExpired         = pkgtransport.OIDCCredentialStatusExpired
)

// TPM object kinds a policy is assigned to.
const (
	TPMObjectKindKey    = pkgtransport.TPMObjectKindKey
	TPMObjectKindSealed = pkgtransport.TPMObjectKindSealed
)

// TPM policy condition types and the bank a branch spec's pcr condition
// selects when it names none.
const (
	TPMPolicyConditionPCR       = pkgtransport.TPMPolicyConditionPCR
	TPMPolicyConditionAuthValue = pkgtransport.TPMPolicyConditionAuthValue
	TPMPolicyConditionLocality  = pkgtransport.TPMPolicyConditionLocality
	DefaultTPMPolicyBank        = pkgtransport.DefaultTPMPolicyBank
)

// TPMPolicyBranchSpecError reports the condition of a branch spec that could
// not be parsed.
type TPMPolicyBranchSpecError = pkgtransport.TPMPolicyBranchSpecError

// TPM policy branch helpers and branch spec errors.
var (
	// TPMPolicyPCRBranch returns a branch holding one pcr condition.
	TPMPolicyPCRBranch = pkgtransport.TPMPolicyPCRBranch

	// ParseTPMPolicyBranch parses a branch spec such as
	// "name=next;pcr=sha256:0,7;auth_value;locality=0".
	ParseTPMPolicyBranch = pkgtransport.ParseTPMPolicyBranch

	ErrTPMPolicyBranchEmpty      = pkgtransport.ErrTPMPolicyBranchEmpty
	ErrTPMPolicyBranchName       = pkgtransport.ErrTPMPolicyBranchName
	ErrTPMPolicyConditionUnknown = pkgtransport.ErrTPMPolicyConditionUnknown
	ErrTPMPolicyConditionValue   = pkgtransport.ErrTPMPolicyConditionValue
	ErrTPMPolicyNoSelection      = pkgtransport.ErrTPMPolicyNoSelection
	ErrTPMPolicyPCRsAndBranches  = pkgtransport.ErrTPMPolicyPCRsAndBranches

	// TPMPolicyBranches returns the parsed branch specs, or the one pcr
	// branch of a PCR selection.
	TPMPolicyBranches = pkgtransport.TPMPolicyBranches
)

// Pagination types and functional options.
type PageRequest = pkgtransport.PageRequest
type PageResponse = pkgtransport.PageResponse
type ListOption = pkgtransport.ListOption

// WithPage sets the 1-based page number to retrieve.
var WithPage = pkgtransport.WithPage

// WithPageSize sets the maximum number of items to return per page.
var WithPageSize = pkgtransport.WithPageSize

// WithSortField sets the field name to sort results by.
var WithSortField = pkgtransport.WithSortField

// WithSortDesc sets the sort order to descending.
var WithSortDesc = pkgtransport.WithSortDesc

// WithSortAsc sets the sort order to ascending.
var WithSortAsc = pkgtransport.WithSortAsc

// BuildPageRequest constructs a PageRequest from the given list options.
var BuildPageRequest = pkgtransport.BuildPageRequest
