// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package apierrors

import (
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/aead"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/seal/policy"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// SealStoreSentinelClasses classifies the errors the machine-local
// platform-sealed credential store (pkg/xkms's SealStoreServicer,
// pkg/seal's Store) returns. Both pkg/api/grpc/service_seal_store.go's
// mapSealStoreError and pkg/api/mcp's mirror of it read this table
// (go-xkms#921).
var SealStoreSentinelClasses = []SentinelClass{
	{xkms.ErrNotConfigured, ClassUnavailable},
	{xkms.ErrNilRequest, ClassInvalidArgument},
	{seal.ErrSecretNotFound, ClassNotFound},
	{seal.ErrInvalidSecretName, ClassInvalidArgument},
	{seal.ErrResealFailed, ClassInternal},
}

// ImportExportSentinelClasses classifies the backend-layer capability
// sentinels a direct backend.ImportBackend / backend.ExportBackend call can
// return: WrapKey, UnwrapKey, GetImportParameters, ImportKey, ExportKey and
// CopyKey call these backend methods directly rather than through the xkms
// service layer, so the general key-op sentinel tables do not apply to them.
// Both pkg/api/grpc's mapImportExportError and pkg/api/mcp's mirror of it
// read this table (go-xkms#912); it used to be two independently maintained
// copies.
var ImportExportSentinelClasses = []SentinelClass{
	{backend.ErrExportNotSupported, ClassUnimplemented},
	{backend.ErrImportNotSupported, ClassUnimplemented},
	{backend.ErrAsymmetricKeyExportNotAllowed, ClassInvalidArgument},
	{backend.ErrKeyNotExportable, ClassPermissionDenied},
	// ErrCallerNonceNotSupported is a malformed request against a backend
	// whose remote encryption service manages its own nonces (AWS KMS, GCP
	// KMS, Vault Transit, the paired phone): the caller asked for a
	// guarantee this backend cannot give, not a capability the backend
	// categorically lacks the way export/import are (go-xkms#1223).
	{backend.ErrCallerNonceNotSupported, ClassInvalidArgument},
}

// AEADSentinelClasses classifies the pkg/crypto/aead nonce-safety domain
// errors that reach the key and crypto operations (Encrypt, WrapKeyByID)
// through pkg/xkms's process-wide AEAD nonce guard (claimAEADNonce,
// claimGeneratedAEADNonce): a nonce this process has already consumed under
// this key is the caller's request repeating a value that must never repeat,
// not a fault in the server, and a full guard is a resource limit reached
// rather than a permanent refusal. Both pkg/api/grpc's mapKeyOpError and
// pkg/api/mcp's mirror of it read this table (go-xkms#1223), mirroring
// pkg/api/rest/errors_keyops.go's keyOpSentinelStatus entries for the same
// two sentinels.
var AEADSentinelClasses = []SentinelClass{
	{aead.ErrNonceReuse, ClassAlreadyExists},
	{aead.ErrNonceTrackerFull, ClassResourceExhausted},
}

// PIVSentinelClasses classifies the PIV domain errors pkg/xkms's PIV
// operations (ListPIVSlots, GetPIVCertificate, GeneratePIVKey, ...) return.
// Both pkg/api/grpc's mapPIVError and pkg/api/mcp's mirror of it read this
// table (go-xkms#912).
var PIVSentinelClasses = []SentinelClass{
	{xkms.ErrPIVNotInitialized, ClassFailedPrecondition},
	{xkms.ErrPIVBackendNotFound, ClassNotFound},
	{xkms.ErrPIVInvalidAlgorithm, ClassInvalidArgument},
	{xkms.ErrPIVInvalidSlot, ClassInvalidArgument},
	{xkms.ErrPIVInvalidFormat, ClassInvalidArgument},
	{xkms.ErrPIVKeyNotFound, ClassNotFound},
}

// PINSentinelClasses classifies the go-qrdb PIN backend domain errors
// (qrdbsdk.ErrPINNotSet, ErrPINLocked, ...) pkg/xkms's PIN operations
// (SetSOPIN, SetUserPIN, ChangeSOPIN, ChangeUserPIN, VerifySOPIN,
// VerifyUserPIN, GetLockoutStatus, ResetLockout) return, plus the
// xkms.ErrNotConfigured every one of those operations returns when no
// qrdbsdk.PINBackend is composed. Both pkg/api/grpc/service_barrier_pin.go's
// mapPINError and pkg/api/mcp's mirror of it read this table (go-xkms#773,
// following the go-xkms#912 precedent set for PIV and barrier).
var PINSentinelClasses = []SentinelClass{
	{xkms.ErrNotConfigured, ClassUnavailable},
	{qrdbsdk.ErrPINNotSet, ClassFailedPrecondition},
	{qrdbsdk.ErrPINLocked, ClassResourceExhausted},
	{qrdbsdk.ErrPINInvalid, ClassUnauthenticated},
	{qrdbsdk.ErrSOPINRequired, ClassUnauthenticated},
	{qrdbsdk.ErrPINTooShort, ClassInvalidArgument},
	{qrdbsdk.ErrPINAlreadySet, ClassAlreadyExists},
	{qrdbsdk.ErrInvalidCurrentPIN, ClassUnauthenticated},
	{qrdbsdk.ErrPINStateCorrupted, ClassDataLoss},
	{qrdbsdk.ErrPINStrategyNotSet, ClassFailedPrecondition},
}

// CustodianSentinelClasses classifies the go-qrdb custodian-group domain
// errors (qrdbsdk.ErrCeremonyGroupNotFound, ErrCeremonyGroupAlreadyExists,
// ...) surfaced by the embedded node's CustodianGroupClient, via
// pkg/xkms/servicer_custodian.go's CreateCustodianGroup et al., plus the
// xkms.ErrNotConfigured / xkms.ErrNilRequest sentinels those same operations
// return when no client is composed or the request is nil. Both
// pkg/api/grpc/service_custodian_share_tenant.go's mapCustodianError and
// pkg/api/mcp's mirror of it read this table (go-xkms#773, following the
// go-xkms#912 precedent set for PIV and barrier).
var CustodianSentinelClasses = []SentinelClass{
	{xkms.ErrNotConfigured, ClassUnavailable},
	{xkms.ErrNilRequest, ClassInvalidArgument},
	{qrdbsdk.ErrCeremonyGroupNotFound, ClassNotFound},
	{qrdbsdk.ErrCeremonyMemberNotFound, ClassNotFound},
	{qrdbsdk.ErrCeremonyUserNotFound, ClassNotFound},
	{qrdbsdk.ErrCeremonyGroupAlreadyExists, ClassAlreadyExists},
	{qrdbsdk.ErrCeremonyMemberAlreadyExists, ClassAlreadyExists},
	{qrdbsdk.ErrCeremonyGroupFull, ClassFailedPrecondition},
	{qrdbsdk.ErrCeremonyInsufficientMembers, ClassFailedPrecondition},
	{qrdbsdk.ErrCeremonyEmptyGroupID, ClassInvalidArgument},
	{qrdbsdk.ErrCeremonyEmptyGroupName, ClassInvalidArgument},
	{qrdbsdk.ErrCeremonyInvalidThreshold, ClassInvalidArgument},
	{qrdbsdk.ErrCeremonyInvalidTotal, ClassInvalidArgument},
}

// BarrierSentinelClasses classifies the pkg/seal barrier and Shamir
// domain errors. Both pkg/api/grpc's mapBarrierError and pkg/api/mcp's
// mirror of it read this table (go-xkms#912).
var BarrierSentinelClasses = []SentinelClass{
	// Core barrier errors.
	{seal.ErrSealed, ClassFailedPrecondition},
	{seal.ErrAlreadyUnsealed, ClassAlreadyExists},
	{seal.ErrAlreadyInitialized, ClassAlreadyExists},
	{seal.ErrNotInitialized, ClassFailedPrecondition},
	{seal.ErrInvalidCredentials, ClassUnauthenticated},
	// Software strategies report a wrong passphrase as ErrDecryptionFailed;
	// hardware ones raise ErrInvalidCredentials. Both are Unauthenticated.
	{seal.ErrDecryptionFailed, ClassUnauthenticated},
	{seal.ErrNoAvailableStrategy, ClassUnavailable},
	{seal.ErrStrategyNotFound, ClassNotFound},
	{seal.ErrStrategyMismatch, ClassFailedPrecondition},
	{seal.ErrCorruptRootKey, ClassDataLoss},
	{seal.ErrEncryptorNotAvailable, ClassFailedPrecondition},
	// BarrierEnableEncryption's target tenant is caller-supplied; XKMSService's
	// tenant binding refuses a foreign one with an error that unwraps to
	// go-qrdb's unknown-tenant sentinel (xkms.TenantBindingError).
	{qrdbsdk.ErrTenantMissing, ClassNotFound},

	// Shamir secret sharing errors.
	{seal.ErrShamirNotConfigured, ClassFailedPrecondition},
	{seal.ErrShamirThresholdInvalid, ClassInvalidArgument},
	{seal.ErrShamirQuorumIncomplete, ClassFailedPrecondition},
	{seal.ErrShamirQuorumExpired, ClassDeadlineExceeded},
	{seal.ErrShamirDuplicateShare, ClassAlreadyExists},
	{seal.ErrShamirCombineFailed, ClassInternal},
	{seal.ErrShamirShareNotFound, ClassNotFound},
	{seal.ErrShamirNoSharesFound, ClassNotFound},
	{seal.ErrShamirVerificationFailed, ClassDataLoss},
	{seal.ErrShamirStorageFailed, ClassInternal},

	// Recovery and root token errors.
	{seal.ErrRecoveryKeysNotFound, ClassNotFound},
	{seal.ErrRootTokenVerificationFailed, ClassUnauthenticated},
}

// PolicySentinelClasses classifies the TPM 2.0 PCR-bank sealed-secret
// authorization policy domain errors pkg/seal/policy's Manager operations
// (CreatePolicy, GetPolicy, RefreshPolicy, VerifyPolicy, DeletePolicy,
// ListPolicies, ExportPolicy) return, plus the xkms.ErrNotConfigured /
// xkms.ErrNilRequest sentinels pkg/xkms's Policy* servicer methods return
// when no policy manager is composed or the request is nil. Both
// pkg/api/grpc/service_policy.go's mapPolicyError and pkg/api/mcp's mirror
// of it read this table (go-xkms#691, following the go-xkms#912 precedent
// set for PIV and barrier).
var PolicySentinelClasses = []SentinelClass{
	{xkms.ErrNotConfigured, ClassUnavailable},
	{xkms.ErrNilRequest, ClassInvalidArgument},
	{policy.ErrPolicyNotFound, ClassNotFound},
	{policy.ErrPolicyExists, ClassAlreadyExists},
	{policy.ErrInvalidName, ClassInvalidArgument},
	{policy.ErrInvalidBank, ClassInvalidArgument},
	{policy.ErrUnsupportedBank, ClassInvalidArgument},
	{policy.ErrNoPCRsSelected, ClassInvalidArgument},
	{policy.ErrPCRIndexOutOfRange, ClassInvalidArgument},
	{policy.ErrDuplicatePCRIndex, ClassInvalidArgument},
	{policy.ErrExportFailed, ClassInternal},
}
