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

// Barrier types (re-exported from qrdb via pkg/transport).
type BarrierInitializeRequest = pkgtransport.BarrierInitializeRequest
type BarrierUnsealRequest = pkgtransport.BarrierUnsealRequest
type BarrierStatusResponse = pkgtransport.BarrierStatusResponse
type BarrierInitializeShamirRequest = pkgtransport.BarrierInitializeShamirRequest
type BarrierInitializeShamirResponse = pkgtransport.BarrierInitializeShamirResponse
type BarrierUnsealShareRequest = pkgtransport.BarrierUnsealShareRequest
type BarrierUnsealShareResponse = pkgtransport.BarrierUnsealShareResponse
type BarrierUnsealSharesRequest = pkgtransport.BarrierUnsealSharesRequest
type BarrierShamirSharesResponse = pkgtransport.BarrierShamirSharesResponse
type BarrierShamirDeleteShareRequest = pkgtransport.BarrierShamirDeleteShareRequest
type BarrierRekeyRequest = pkgtransport.BarrierRekeyRequest
type BarrierRekeyResponse = pkgtransport.BarrierRekeyResponse
type BarrierGenerateRecoveryKeysRequest = pkgtransport.BarrierGenerateRecoveryKeysRequest
type BarrierRecoveryKeysResponse = pkgtransport.BarrierRecoveryKeysResponse
type BarrierRecoverWithKeysRequest = pkgtransport.BarrierRecoverWithKeysRequest
type BarrierHasRecoveryKeysResponse = pkgtransport.BarrierHasRecoveryKeysResponse
type BarrierGenerateRootTokenRequest = pkgtransport.BarrierGenerateRootTokenRequest
type BarrierRootTokenResponse = pkgtransport.BarrierRootTokenResponse

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
type ListUsersResponse = pkgtransport.ListUsersResponse
type GetUserResponse = pkgtransport.GetUserResponse
type CredentialInfo = pkgtransport.CredentialInfo
type ListUserCredentialsResponse = pkgtransport.ListUserCredentialsResponse

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

// Platform store types.
type SealStorePutRequest = pkgtransport.SealStorePutRequest
type SealStoreGetRequest = pkgtransport.SealStoreGetRequest
type SealStoreGetResponse = pkgtransport.SealStoreGetResponse
type SealStoreDeleteRequest = pkgtransport.SealStoreDeleteRequest
type SealStoreListResponse = pkgtransport.SealStoreListResponse
type SealStoreResealRequest = pkgtransport.SealStoreResealRequest
type SealStoreStatusResponse = pkgtransport.SealStoreStatusResponse

// Policy types.
type PolicyCreateRequest = pkgtransport.PolicyCreateRequest
type PolicyCreateResponse = pkgtransport.PolicyCreateResponse
type PolicyGetRequest = pkgtransport.PolicyGetRequest
type PolicyGetResponse = pkgtransport.PolicyGetResponse
type PolicyListResponse = pkgtransport.PolicyListResponse
type PolicyDeleteRequest = pkgtransport.PolicyDeleteRequest
type PolicyRefreshRequest = pkgtransport.PolicyRefreshRequest
type PolicyVerifyRequest = pkgtransport.PolicyVerifyRequest
type PolicyVerifyResponse = pkgtransport.PolicyVerifyResponse
type PolicyExportRequest = pkgtransport.PolicyExportRequest
type PolicyExportResponse = pkgtransport.PolicyExportResponse

// Credential types.
type CredentialParam = pkgtransport.CredentialParam

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
