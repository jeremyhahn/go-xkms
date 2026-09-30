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
	"errors"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/aead"
	"github.com/jeremyhahn/go-xkms/pkg/keyversion"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/tpmpolicy"
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
	// Every operation on this platform-global state is platform-scoped: a
	// tenant-scoped caller is refused with xkms.TenantBindingError, which
	// unwraps to go-qrdb's unknown-tenant sentinel (go-xkms#1226).
	{qrdbsdk.ErrTenantMissing, ClassNotFound},
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
	// Every operation on this platform-global state is platform-scoped: a
	// tenant-scoped caller is refused with xkms.TenantBindingError, which
	// unwraps to go-qrdb's unknown-tenant sentinel (go-xkms#1227).
	{qrdbsdk.ErrTenantMissing, ClassNotFound},
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
	// Every operation on this platform-global state is platform-scoped: a
	// tenant-scoped caller is refused with xkms.TenantBindingError, which
	// unwraps to go-qrdb's unknown-tenant sentinel (go-xkms#1227).
	{qrdbsdk.ErrTenantMissing, ClassNotFound},
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
	// tenant binding refuses a foreign one, and every system-barrier operation
	// refuses a tenant-scoped caller outright (go-xkms#1227), with an error
	// that unwraps to go-qrdb's unknown-tenant sentinel
	// (xkms.TenantBindingError).
	{qrdbsdk.ErrTenantMissing, ClassNotFound},
	// XKMSService returns ErrNotConfigured when no system barrier is composed.
	{xkms.ErrNotConfigured, ClassUnavailable},

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

// TPMPolicySentinelClasses classifies the sentinel errors of the TPM policy
// API (pkg/xkms's TPMPolicy* servicer methods over pkg/tpmpolicy) and of TPM2
// key operations routed to a tenant's TPM scope (pkg/backend/tpm2). The typed
// errors of the same domain are classified by TPMPolicyClassOf, which every
// transport reads: the gRPC and MCP servers' TPM policy handlers, the REST
// TPM policy handlers, and each transport's key-operation mapper for the
// scope errors a key operation surfaces.
var TPMPolicySentinelClasses = []SentinelClass{
	{xkms.ErrNotConfigured, ClassUnavailable},
	{xkms.ErrNilRequest, ClassInvalidArgument},
	{xkms.ErrTenantIDRequired, ClassInvalidArgument},
	{xkms.ErrTPMPolicyNotSupported, ClassInvalidArgument},
	// A tenant-scoped caller naming another tenant, or any tenant-scoped
	// caller of a system-scope operation, is refused with
	// xkms.TenantBindingError, which unwraps to go-qrdb's unknown-tenant
	// sentinel: the target reads as not found.
	{qrdbsdk.ErrTenantMissing, ClassNotFound},
	{tpmpolicy.ErrPolicyNotFound, ClassNotFound},
	{tpmpolicy.ErrScopeNotFound, ClassNotFound},
	{tpmpolicy.ErrNotAssigned, ClassNotFound},
	{tpmpolicy.ErrPolicyExists, ClassAlreadyExists},
	{tpmpolicy.ErrReservedPolicy, ClassInvalidArgument},
	{tpmpolicy.ErrEmptyPCRSelection, ClassInvalidArgument},
	{tpmpolicy.ErrSystemScopeMode, ClassInvalidArgument},
	{tpmpolicy.ErrTPMModeNone, ClassFailedPrecondition},
	{tpmpolicy.ErrVTPMUnavailable, ClassFailedPrecondition},
	{tpmpolicy.ErrNotVTPMMode, ClassFailedPrecondition},
	{tpmpolicy.ErrPolicyRevoked, ClassFailedPrecondition},
	{tpm2backend.ErrReservedObject, ClassInvalidArgument},
	{tpm2backend.ErrSymmetricKeysUnsupported, ClassUnimplemented},
	{tpm2backend.ErrTenantImportUnsupported, ClassUnimplemented},
}

// TypedClass classifies a typed error: Match reports whether an error's
// chain holds the type.
type TypedClass struct {
	// Match reports whether err's chain holds an error of the class's type.
	Match func(err error) bool
	// Class is the classification the type carries.
	Class Class
}

// As reports whether err's chain holds an error of type T.
func As[T error](err error) bool {
	var target T
	return errors.As(err, &target)
}

// TPMPolicyTypedClasses classifies the typed errors of the TPM policy API.
// A policy still assigned to objects, and a scope still holding objects or
// policies, are refusals of the current state (their messages list the
// objects), not faults in the request.
var TPMPolicyTypedClasses = []TypedClass{
	{As[*tpmpolicy.PolicyInUseError], ClassFailedPrecondition},
	{As[*tpmpolicy.ScopeInUseError], ClassFailedPrecondition},
	{As[*tpmpolicy.PCRBankUnavailableError], ClassFailedPrecondition},
	{As[*tpmpolicy.InvalidNameError], ClassInvalidArgument},
	{As[*tpmpolicy.InvalidModeError], ClassInvalidArgument},
	{As[*tpmpolicy.InvalidTenantError], ClassInvalidArgument},
	{As[*tpmpolicy.InvalidPCRBankError], ClassInvalidArgument},
	{As[*tpmpolicy.InvalidPCRError], ClassInvalidArgument},
	{As[*xkms.InvalidTPMObjectKindError], ClassInvalidArgument},
	{As[*xkms.ErrKeyIDParse], ClassInvalidArgument},
}

// TPMPolicyClassOf classifies an error of the TPM policy API: its typed
// errors first, then its sentinels.
func TPMPolicyClassOf(err error) (Class, bool) {
	if err == nil {
		return ClassInternal, false
	}
	for _, entry := range TPMPolicyTypedClasses {
		if entry.Match(err) {
			return entry.Class, true
		}
	}
	return ClassOf(TPMPolicySentinelClasses, err)
}

// KeyVersionTypedClasses classifies the errors of the key-version model
// (pkg/keyversion, and pkg/xkms's version-aware key operations). Every
// transport's key-operation mapper reads it through KeyVersionClassOf before
// its own tables, because the service wraps some of these errors in a
// role-lookup error that would otherwise read as a missing key:
//
//   - A ciphertext that cannot be matched to a version safely, a reserved or
//     invalid version name, is a fault in the request.
//   - A version the key does not have, or whose backend key is gone, is not
//     found.
//   - Disabling or retiring the current version, using a disabled or retired
//     one, or changing a retired one conflicts with the key's current state.
var KeyVersionTypedClasses = []TypedClass{
	{As[*keyversion.KeyVersionRequiredError], ClassInvalidArgument},
	{As[*keyversion.ReservedKeyIDError], ClassInvalidArgument},
	{As[*keyversion.InvalidVersionError], ClassInvalidArgument},
	{As[*keyversion.InvalidRecordKeyError], ClassInvalidArgument},
	{As[*keyversion.VersionNotFoundError], ClassNotFound},
	{As[*xkms.KeyVersionMissingError], ClassNotFound},
	{As[*keyversion.CurrentVersionError], ClassFailedPrecondition},
	{As[*keyversion.RetiredVersionError], ClassFailedPrecondition},
	{As[*keyversion.VersionUnavailableError], ClassFailedPrecondition},
	{As[*xkms.KeyExistsError], ClassAlreadyExists},
	{As[*xkms.KeyRotationUnsupportedError], ClassUnimplemented},
}

// KeyVersionSentinelClasses classifies the key-version model's sentinels.
var KeyVersionSentinelClasses = []SentinelClass{
	{xkms.ErrKeyVersionsNotConfigured, ClassUnavailable},
}

// KeyVersionClassOf classifies an error of the key-version model: its typed
// errors first, then its sentinels.
func KeyVersionClassOf(err error) (Class, bool) {
	if err == nil {
		return ClassInternal, false
	}
	for _, entry := range KeyVersionTypedClasses {
		if entry.Match(err) {
			return entry.Class, true
		}
	}
	return ClassOf(KeyVersionSentinelClasses, err)
}
