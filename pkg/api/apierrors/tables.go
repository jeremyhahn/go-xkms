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

	"github.com/jeremyhahn/go-xkms/pkg/attestation/peer"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/peergate"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/aead"
	"github.com/jeremyhahn/go-xkms/pkg/keypolicy"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/symmetric"
	"github.com/jeremyhahn/go-xkms/pkg/keyversion"
	"github.com/jeremyhahn/go-xkms/pkg/oidc"
	"github.com/jeremyhahn/go-xkms/pkg/oidc/credential"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	tpmpolicy "github.com/jeremyhahn/go-xkms/pkg/tpm2/policy"
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
	// The backend-credential namespace is not part of platform secrets: a
	// credential's value is write-only (go-xkms#1465).
	{xkms.ErrReservedSecretName, ClassPermissionDenied},
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
	{xkms.ErrWrapTargetNotSymmetric, ClassInvalidArgument},
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
// through the process-wide AEAD nonce guard every backend's Encrypt path
// claims (pkg/backend's ClaimAEADNonce/ClaimGeneratedAEADNonce): a nonce
// this process has already consumed under this key is the caller's request
// repeating a value that must never repeat, not a fault in the server, and
// a full guard is a resource limit reached rather than a permanent refusal.
//
// It also classifies the AES-GCM parameter refusals. Under
// GODEBUG=fips140=only the stdlib refuses an AES-GCM AEAD over a
// caller-supplied nonce or a truncated tag, which pkg/crypto/aead and
// pkg/keyprovider/symmetric report as ErrArbitraryIVGCMUnavailable; a tag
// length NIST SP 800-38D section 5.2.1.2 does not approve is refused in any
// mode. Each is the caller asking for a parameter this process cannot honour
// and can correct by omitting the nonce or the tag length, the same request
// fault as ImportExportSentinelClasses' backend.ErrCallerNonceNotSupported,
// so it is ClassInvalidArgument rather than a server fault (go-xkms#23).
//
// pkg/api/grpc's mapKeyOpError, pkg/api/mcp's mirror of it and
// pkg/api/rest's mapKeyOpError all read this table (go-xkms#1223); REST
// answers the two nonce-guard sentinels from its own keyOpSentinelStatus
// first.
var AEADSentinelClasses = []SentinelClass{
	{aead.ErrNonceReuse, ClassAlreadyExists},
	{aead.ErrNonceTrackerFull, ClassResourceExhausted},
	{aead.ErrArbitraryIVGCMUnavailable, ClassInvalidArgument},
	{symmetric.ErrArbitraryIVGCMUnavailable, ClassInvalidArgument},
	{aead.ErrInvalidGCMTagSize, ClassInvalidArgument},
	{symmetric.ErrInvalidTagSize, ClassInvalidArgument},
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

// TrustRootSentinelClasses classifies the errors of the platform trust-root
// store (pkg/attestation/truststore) the TrustRoot* verbs return.
var TrustRootSentinelClasses = []SentinelClass{
	{xkms.ErrNotConfigured, ClassUnavailable},
	{xkms.ErrNilRequest, ClassInvalidArgument},
	{truststore.ErrCertificateNotFound, ClassNotFound},
	{truststore.ErrCertificateExists, ClassAlreadyExists},
	{truststore.ErrInvalidCertificate, ClassInvalidArgument},
	{truststore.ErrInvalidFingerprint, ClassInvalidArgument},
	{truststore.ErrInvalidPurpose, ClassInvalidArgument},
	{truststore.ErrStoreClosed, ClassUnavailable},
	// Every operation on this platform-global state is platform-scoped: a
	// tenant-scoped caller is refused with xkms.TenantBindingError, which
	// unwraps to go-qrdb's unknown-tenant sentinel.
	{qrdbsdk.ErrTenantMissing, ClassNotFound},
}

// PINSentinelClasses classifies the go-qrdb PIN backend domain errors
// (qrdbsdk.ErrPINNotSet, ErrPINLocked, ...) pkg/xkms's PIN operations
// (SetSOPIN, SetUserPIN, ChangeSOPIN, ChangeUserPIN, VerifySOPIN,
// VerifyUserPIN, GetLockoutStatus, ResetLockout) return, plus the
// xkms.ErrNotConfigured every one of those operations returns when no
// qrdbsdk.PINBackend is composed. Both pkg/api/grpc/service_pin.go's
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
	{xkms.ErrTPMPolicyBranchUpdate, ClassInvalidArgument},
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
	{tpmpolicy.ErrEmptyLocalitySelection, ClassInvalidArgument},
	{tpmpolicy.ErrNoBranches, ClassInvalidArgument},
	{tpmpolicy.ErrEmptyBranch, ClassInvalidArgument},
	{tpmpolicy.ErrPCRValuesSupplied, ClassInvalidArgument},
	{tpmpolicy.ErrNoSuchBranch, ClassInvalidArgument},
	{tpmpolicy.ErrInvalidBranchName, ClassInvalidArgument},
	{tpmpolicy.ErrDuplicateBranch, ClassInvalidArgument},
	{tpmpolicy.ErrNoPCRCondition, ClassInvalidArgument},
	// A branch update from reference values needs a configured signer.
	{tpmpolicy.ErrNoReferenceSigner, ClassFailedPrecondition},
	// A key or sealed object without a password cannot be bound to a policy
	// with an auth_value condition.
	{pkgtpm2.ErrPolicyAuthValueRequired, ClassInvalidArgument},
	{tpmpolicy.ErrSystemScopeMode, ClassInvalidArgument},
	{tpmpolicy.ErrTPMModeNone, ClassFailedPrecondition},
	{tpmpolicy.ErrVTPMUnavailable, ClassFailedPrecondition},
	{tpmpolicy.ErrNotVTPMMode, ClassFailedPrecondition},
	{tpmpolicy.ErrPolicyRevoked, ClassFailedPrecondition},
	{tpm2backend.ErrReservedObject, ClassInvalidArgument},
	{tpm2backend.ErrSymmetricKeysUnsupported, ClassUnimplemented},
	{tpm2backend.ErrTenantImportUnsupported, ClassUnimplemented},
}

// OIDCCredentialSentinelClasses classifies the sentinel errors of the OIDC
// credential API (pkg/xkms's OIDCCredential* servicer methods over
// pkg/oidc/credential). Its typed errors are classified by
// OIDCCredentialClassOf, which every transport reads.
var OIDCCredentialSentinelClasses = []SentinelClass{
	{xkms.ErrNotConfigured, ClassUnavailable},
	{xkms.ErrNilRequest, ClassInvalidArgument},
	{credential.ErrNotFound, ClassNotFound},
	{credential.ErrExists, ClassAlreadyExists},
	{credential.ErrInvalidName, ClassInvalidArgument},
	{credential.ErrScopeUnsupported, ClassInvalidArgument},
	{credential.ErrInvalidConfig, ClassInvalidArgument},
	{credential.ErrInvalidTokens, ClassInvalidArgument},
	{scope.ErrRefused, ClassPermissionDenied},
	// A rejected refresh token is the credential's state, not a fault in
	// the request: the caller re-logs in or imports.
	{credential.ErrReloginRequired, ClassFailedPrecondition},
	{credential.ErrNoLogin, ClassFailedPrecondition},
	{credential.ErrTokenExpired, ClassFailedPrecondition},
	{credential.ErrNotRefreshable, ClassFailedPrecondition},
	{credential.ErrNoDeviceLogin, ClassFailedPrecondition},
	{credential.ErrFlowUnsupported, ClassFailedPrecondition},
	{credential.ErrConcurrentUpdate, ClassFailedPrecondition},
	{credential.ErrCorruptRecord, ClassDataLoss},
	{oidc.ErrDeviceFlowUnsupported, ClassFailedPrecondition},
	{oidc.ErrDeviceAccessDenied, ClassFailedPrecondition},
	{oidc.ErrDeviceCodeExpired, ClassFailedPrecondition},
	{oidc.ErrDeviceAuthorizationFailed, ClassUnavailable},
	{seal.ErrSealed, ClassUnavailable},
	// The tenant has no barrier registered: the target reads as not found.
	{qrdbsdk.ErrTenantMissing, ClassNotFound},
}

// OIDCCredentialTypedClasses classifies the typed errors of the OIDC
// credential API. A refresh the provider failed for a reason a retry may
// overcome is the upstream being unavailable; a configuration or a path
// segment the service refused is the request's fault.
var OIDCCredentialTypedClasses = []TypedClass{
	{As[*credential.ConfigError], ClassInvalidArgument},
	{As[*scope.InvalidSegmentError], ClassInvalidArgument},
	{As[*scope.InvalidScopeError], ClassInvalidArgument},
	{func(err error) bool {
		var refresh *credential.RefreshError
		return errors.As(err, &refresh) && !refresh.Relogin
	}, ClassUnavailable},
}

// OIDCCredentialClassOf classifies an error of the OIDC credential API: its
// typed errors first, then its sentinels.
func OIDCCredentialClassOf(err error) (Class, bool) {
	if err == nil {
		return ClassInternal, false
	}
	for _, entry := range OIDCCredentialTypedClasses {
		if entry.Match(err) {
			return entry.Class, true
		}
	}
	return ClassOf(OIDCCredentialSentinelClasses, err)
}

// PeerAttestationSentinelClasses classifies the sentinel errors of the
// attested-caller verbs (pkg/xkms's PeerAttestation servicer methods over
// pkg/attestation/peergate). A server without the gate has nothing to
// answer with. Its typed errors are classified by PeerAttestationClassOf,
// which every transport reads.
var PeerAttestationSentinelClasses = []SentinelClass{
	{xkms.ErrNotConfigured, ClassUnavailable},
	{xkms.ErrNilRequest, ClassInvalidArgument},
}

// PeerAttestationTypedClasses classifies the typed errors of the
// attested-caller verbs:
//
//   - A request whose connection carries no verified client certificate names
//     no peer to attest.
//   - A submission without an outstanding, unexpired challenge, or one whose
//     connection cannot be bound (no TLS 1.3 exporter), is refused for the
//     connection's state, not for its content.
//   - A full challenge table is a capacity limit, a failing evidence store
//     or nonce source a fault a retry may overcome.
var PeerAttestationTypedClasses = []TypedClass{
	{As[*peergate.PeerCertificateError], ClassUnauthenticated},
	{As[*peergate.ChallengeError], ClassFailedPrecondition},
	{As[*peer.ChannelBindingError], ClassFailedPrecondition},
	{As[*peergate.CapacityError], ClassResourceExhausted},
	{As[*peergate.StoreError], ClassUnavailable},
	{As[*peergate.NonceError], ClassUnavailable},
}

// PeerAttestationClassOf classifies an error of the attested-caller verbs:
// its typed errors first, then its sentinels.
func PeerAttestationClassOf(err error) (Class, bool) {
	if err == nil {
		return ClassInternal, false
	}
	for _, entry := range PeerAttestationTypedClasses {
		if entry.Match(err) {
			return entry.Class, true
		}
	}
	return ClassOf(PeerAttestationSentinelClasses, err)
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
	{As[*tpmpolicy.InvalidLocalityError], ClassInvalidArgument},
	{As[*tpmpolicy.UnknownConditionTypeError], ClassInvalidArgument},
	{As[*tpmpolicy.DuplicateConditionError], ClassInvalidArgument},
	{As[*tpmpolicy.ConditionOperandError], ClassInvalidArgument},
	{As[*tpmpolicy.DescriptionTooLongError], ClassInvalidArgument},
	{As[*tpmpolicy.ReferenceValuesError], ClassInvalidArgument},
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

// KeyPolicyTypedClasses classifies the typed errors of the key management
// API (pkg/xkms's key management operations over pkg/keypolicy) and of the
// policy gate every key operation passes. Every transport's key-operation
// mapper reads it through KeyPolicyClassOf:
//
//   - A field the service cannot store, an operation the key's kind does not
//     support, or a record key that cannot be named is a fault in the request.
//   - A policy field the service cannot enforce (per-operation MFA, automatic
//     rotation) and a backend BackendTest cannot round-trip are capabilities
//     the service lacks.
//   - A revoked key changing status, and a disabled or revoked key used for
//     an operation, conflict with the key's current state.
//   - An operation the key's policy refuses is the caller's lack of
//     permission; a key past its AEAD usage limit (NIST SP 800-38D §8.3) has
//     used up a resource and must be rotated.
var KeyPolicyTypedClasses = []TypedClass{
	{As[*xkms.InvalidKeyPolicyError], ClassInvalidArgument},
	{As[*xkms.KeyKindError], ClassInvalidArgument},
	{As[*keypolicy.InvalidRecordKeyError], ClassInvalidArgument},
	{As[*xkms.UnenforceablePolicyError], ClassUnimplemented},
	{As[*xkms.BackendTestUnsupportedError], ClassUnimplemented},
	{As[*xkms.KeyStatusTransitionError], ClassFailedPrecondition},
	{As[*keypolicy.KeyUnavailableError], ClassFailedPrecondition},
	{As[*keypolicy.PolicyDeniedError], ClassPermissionDenied},
	{As[*keypolicy.SafetyLimitError], ClassResourceExhausted},
}

// KeyPolicySentinelClasses classifies the key management API's sentinels.
var KeyPolicySentinelClasses = []SentinelClass{
	{xkms.ErrKeyPoliciesNotConfigured, ClassUnavailable},
}

// KeyPolicyClassOf classifies an error of the key management API: its typed
// errors first, then its sentinels.
func KeyPolicyClassOf(err error) (Class, bool) {
	if err == nil {
		return ClassInternal, false
	}
	for _, entry := range KeyPolicyTypedClasses {
		if entry.Match(err) {
			return entry.Class, true
		}
	}
	return ClassOf(KeyPolicySentinelClasses, err)
}
