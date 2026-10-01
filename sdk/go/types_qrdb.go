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

// This file re-exports the closed set of go-qrdb/sdk/go types that go-xkms's
// own crypto and identity surface is expressed in: ceremony and barrier
// types, seal/strategy types, and error plumbing shared with them. It does
// NOT re-export the qrdb database surface (KV, MVCC, SQL, vector,
// time-series, index, collections, lock, lease, transaction, batch, watch,
// or volume-pool types) — see
// ../../../handbook/software/docs/00-ownership-and-sdk-boundary.md L5.
// Consumers needing the database surface import
// github.com/jeremyhahn/go-qrdb/sdk/go directly.
//
// Every alias is prefixed with QRDB to avoid name collisions with
// go-xkms's own types.

package xkms

import (
	qrdb "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// ==========================================================================
// Ceremony types (from types_ceremony.go)
// ==========================================================================

// QRDBCeremonyState represents the current state of the initialization ceremony.
type QRDBCeremonyState = qrdb.CeremonyState

// QRDBCeremonyState constants.
const (
	QRDBStateAwaitingInit = qrdb.StateAwaitingInit
	QRDBStateEnrolling    = qrdb.StateEnrolling
	QRDBStateOperational  = qrdb.StateOperational
)

// QRDBOfficerConfig holds the configuration for an SO officer in M-of-N mode.
type QRDBOfficerConfig = qrdb.OfficerConfig

// QRDBCeremonyConfig holds the full ceremony configuration.
type QRDBCeremonyConfig = qrdb.CeremonyConfig

// QRDBInitResult holds the result of a ceremony initialization.
type QRDBInitResult = qrdb.InitResult

// QRDBChallengeResponse holds the nonce challenge for officer cert claims.
type QRDBChallengeResponse = qrdb.ChallengeResponse

// QRDBClaimCertResult holds the result of an officer certificate claim.
type QRDBClaimCertResult = qrdb.ClaimCertResult

// QRDBSignCSRInitResult holds the result of a CSR signing during init.
type QRDBSignCSRInitResult = qrdb.SignCSRInitResult

// QRDBPendingCert holds a certificate pending officer claim.
type QRDBPendingCert = qrdb.PendingCert

// QRDBCeremonyCA is the interface the ceremony uses to issue certificates.
type QRDBCeremonyCA = qrdb.CeremonyCA

// QRDBSignCSROptions configures CSR signing behavior.
type QRDBSignCSROptions = qrdb.SignCSROptions

// QRDBIssueCertRequest holds a certificate issuance request.
type QRDBIssueCertRequest = qrdb.IssueCertRequest

// QRDBIssuedCert holds a newly issued certificate.
type QRDBIssuedCert = qrdb.IssuedCert

// QRDBCeremonyService manages the initialization ceremony lifecycle.
type QRDBCeremonyService = qrdb.CeremonyService

// QRDBCredentialServicer persists sealed credentials.
type QRDBCredentialServicer = qrdb.CredentialServicer

// QRDBThresholdOptions configures HSM threshold initialization.
type QRDBThresholdOptions = qrdb.ThresholdOptions

// QRDBThresholdStatus reports the status of HSM threshold operations.
type QRDBThresholdStatus = qrdb.ThresholdStatus

// QRDBThresholdInitializer is the interface for HSM threshold implementations.
type QRDBThresholdInitializer = qrdb.ThresholdInitializer

// QRDBNoopThresholdInitializer is a no-op threshold initializer for non-HSM modes.
type QRDBNoopThresholdInitializer = qrdb.NoopThresholdInitializer

// QRDBThresholdFactory creates ThresholdInitializer instances.
type QRDBThresholdFactory = qrdb.ThresholdFactory

// QRDBThresholdRegistry manages vendor-specific threshold implementations.
type QRDBThresholdRegistry = qrdb.ThresholdRegistry

// QRDBCustodianGroupServicer manages custodian groups for Shamir shares.
type QRDBCustodianGroupServicer = qrdb.CustodianGroupServicer

// QRDBCustodianGroupService is the concrete custodian group service.
type QRDBCustodianGroupService = qrdb.CustodianGroupService

// QRDBShareServicer manages Shamir share submission and tracking.
type QRDBShareServicer = qrdb.ShareServicer

// QRDBShareService is the concrete share service.
type QRDBShareService = qrdb.ShareService

// Ceremony constructors.
var (
	QRDBNewCeremonyService       = qrdb.NewCeremonyService
	QRDBNewThresholdRegistry     = qrdb.NewThresholdRegistry
	QRDBNewCustodianGroupService = qrdb.NewCustodianGroupService
	QRDBNewShareService          = qrdb.NewShareService
)

// ==========================================================================
// Ceremony error types (from types_ceremony_errors.go)
// ==========================================================================

// Ceremony sentinel errors.
var (
	QRDBErrCeremonyNilConfig                   = qrdb.ErrCeremonyNilConfig
	QRDBErrCeremonyNilBarrier                  = qrdb.ErrCeremonyNilBarrier
	QRDBErrCeremonyNilLogger                   = qrdb.ErrCeremonyNilLogger
	QRDBErrCeremonyNilStore                    = qrdb.ErrCeremonyNilStore
	QRDBErrCeremonyAlreadyInitialized          = qrdb.ErrCeremonyAlreadyInitialized
	QRDBErrCeremonyNotInEnrollingState         = qrdb.ErrCeremonyNotInEnrollingState
	QRDBErrCeremonyNotInOperationalState       = qrdb.ErrCeremonyNotInOperationalState
	QRDBErrCeremonyInvalidSOPIN                = qrdb.ErrCeremonyInvalidSOPIN
	QRDBErrCeremonyInvalidUserPIN              = qrdb.ErrCeremonyInvalidUserPIN
	QRDBErrCeremonyInvalidThreshold            = qrdb.ErrCeremonyInvalidThreshold
	QRDBErrCeremonyNoOfficers                  = qrdb.ErrCeremonyNoOfficers
	QRDBErrCeremonyInvalidCSR                  = qrdb.ErrCeremonyInvalidCSR
	QRDBErrCeremonyDuplicateUsername           = qrdb.ErrCeremonyDuplicateUsername
	QRDBErrCeremonyPendingCertNotFound         = qrdb.ErrCeremonyPendingCertNotFound
	QRDBErrCeremonyCertAlreadyClaimed          = qrdb.ErrCeremonyCertAlreadyClaimed
	QRDBErrCeremonyShareAlreadyClaimed         = qrdb.ErrCeremonyShareAlreadyClaimed
	QRDBErrCeremonyShareNotFound               = qrdb.ErrCeremonyShareNotFound
	QRDBErrCeremonyChallengeVerificationFailed = qrdb.ErrCeremonyChallengeVerificationFailed
	QRDBErrCeremonyUserNotFound                = qrdb.ErrCeremonyUserNotFound
	QRDBErrCeremonyThresholdNotSupported       = qrdb.ErrCeremonyThresholdNotSupported
	QRDBErrCeremonyVendorNotRegistered         = qrdb.ErrCeremonyVendorNotRegistered
	QRDBErrCeremonyVendorNotAvailable          = qrdb.ErrCeremonyVendorNotAvailable
	QRDBErrCeremonyInitFailed                  = qrdb.ErrCeremonyInitFailed
	QRDBErrCeremonyNotImplemented              = qrdb.ErrCeremonyNotImplemented
	QRDBErrCeremonySOPINMismatch               = qrdb.ErrCeremonySOPINMismatch
	QRDBErrCeremonyCANotInitialized            = qrdb.ErrCeremonyCANotInitialized
	QRDBErrCeremonyMissingCSRPEM               = qrdb.ErrCeremonyMissingCSRPEM
	QRDBErrCeremonyMissingUsername             = qrdb.ErrCeremonyMissingUsername
	QRDBErrCeremonyMissingRole                 = qrdb.ErrCeremonyMissingRole
	QRDBErrCeremonyInvalidRole                 = qrdb.ErrCeremonyInvalidRole
	QRDBErrCeremonyCSRSigningFailed            = qrdb.ErrCeremonyCSRSigningFailed
	QRDBErrCeremonyNotInitializedOrEnrolling   = qrdb.ErrCeremonyNotInitializedOrEnrolling
	QRDBErrCeremonyNilCredentialService        = qrdb.ErrCeremonyNilCredentialService
	QRDBErrCeremonyChallengeExpired            = qrdb.ErrCeremonyChallengeExpired
	QRDBErrCeremonyChallengeNotFound           = qrdb.ErrCeremonyChallengeNotFound
	QRDBErrCeremonyGroupNotFound               = qrdb.ErrCeremonyGroupNotFound
	QRDBErrCeremonyGroupAlreadyExists          = qrdb.ErrCeremonyGroupAlreadyExists
	QRDBErrCeremonyGroupFull                   = qrdb.ErrCeremonyGroupFull
	QRDBErrCeremonyMemberNotFound              = qrdb.ErrCeremonyMemberNotFound
	QRDBErrCeremonyMemberAlreadyExists         = qrdb.ErrCeremonyMemberAlreadyExists
	QRDBErrCeremonyEmptyGroupID                = qrdb.ErrCeremonyEmptyGroupID
	QRDBErrCeremonyShareAlreadySubmitted       = qrdb.ErrCeremonyShareAlreadySubmitted
	QRDBErrCeremonyEmptyShareData              = qrdb.ErrCeremonyEmptyShareData
	QRDBErrCeremonyInsufficientMembers         = qrdb.ErrCeremonyInsufficientMembers
	QRDBErrCeremonyEmptyGroupName              = qrdb.ErrCeremonyEmptyGroupName
	QRDBErrCeremonyInvalidTotal                = qrdb.ErrCeremonyInvalidTotal
)

// Ceremony error types.
type (
	QRDBCeremonyShamirSplitError  = qrdb.CeremonyShamirSplitError
	QRDBCeremonyCSRParseError     = qrdb.CeremonyCSRParseError
	QRDBCeremonyCertEncodeError   = qrdb.CeremonyCertEncodeError
	QRDBCeremonyShareStoreError   = qrdb.CeremonyShareStoreError
	QRDBCeremonyCABundleError     = qrdb.CeremonyCABundleError
	QRDBCeremonySPKIPinError      = qrdb.CeremonySPKIPinError
	QRDBCeremonyGroupStoreError   = qrdb.CeremonyGroupStoreError
	QRDBCeremonyShareServiceError = qrdb.CeremonyShareServiceError
)

// ==========================================================================
// Error types (from types_errors.go)
// ==========================================================================

// QRDBErrorCode classifies database errors into categories.
type QRDBErrorCode = qrdb.ErrorCode

// QRDBErrorCode constants.
const (
	QRDBErrCodeNotFound          = qrdb.ErrCodeNotFound
	QRDBErrCodeInternal          = qrdb.ErrCodeInternal
	QRDBErrCodeConflict          = qrdb.ErrCodeConflict
	QRDBErrCodeTimeout           = qrdb.ErrCodeTimeout
	QRDBErrCodeUnavailable       = qrdb.ErrCodeUnavailable
	QRDBErrCodeInvalidInput      = qrdb.ErrCodeInvalidInput
	QRDBErrCodeAlreadyExists     = qrdb.ErrCodeAlreadyExists
	QRDBErrCodeResourceExhausted = qrdb.ErrCodeResourceExhausted
	QRDBErrCodeCanceled          = qrdb.ErrCodeCanceled
	QRDBErrCodeNotImplemented    = qrdb.ErrCodeNotImplemented
	QRDBErrCodeCircuitOpen       = qrdb.ErrCodeCircuitOpen
)

// QRDB structured error types.
type (
	QRDBError                  = qrdb.QRDBError
	QRDBQuotaExceededError     = qrdb.QuotaExceededError
	QRDBMessageError           = qrdb.MessageError
	QRDBWrappedMessageError    = qrdb.WrappedMessageError
	QRDBParameterNotFoundError = qrdb.ParameterNotFoundError
)

// QRDB error constructors.
var (
	QRDBNewError   = qrdb.NewError
	QRDBNewErrorf  = qrdb.NewErrorf
	QRDBWrapError  = qrdb.WrapError
	QRDBWrapErrorf = qrdb.WrapErrorf
)

// QRDB error query helpers.
var (
	QRDBIsErrorCode                    = qrdb.IsErrorCode
	QRDBAsError                        = qrdb.AsError
	QRDBErrorCodeOf                    = qrdb.ErrorCodeOf
	QRDBErrorOperationOf               = qrdb.ErrorOperationOf
	QRDBIsRetryableError               = qrdb.IsRetryableError
	QRDBErrorContext                   = qrdb.ErrorContext
	QRDBIsErrorNotFound                = qrdb.IsErrorNotFound
	QRDBIsErrorCanceled                = qrdb.IsErrorCanceled
	QRDBIsErrorInvalidInput            = qrdb.IsErrorInvalidInput
	QRDBIsErrorResourceExhausted       = qrdb.IsErrorResourceExhausted
	QRDBIsErrorSystemKeyspaceViolation = qrdb.IsErrorSystemKeyspaceViolation
	QRDBIsErrorCrossTenantAccess       = qrdb.IsErrorCrossTenantAccess
	QRDBIsErrorMissingTenantContext    = qrdb.IsErrorMissingTenantContext
	QRDBIsErrorQuotaExceeded           = qrdb.IsErrorQuotaExceeded
	QRDBIsErrorMissingJustification    = qrdb.IsErrorMissingJustification
	QRDBIsErrorMissingUserContext      = qrdb.IsErrorMissingUserContext
	QRDBIsErrorCircuitOpen             = qrdb.IsErrorCircuitOpen
)

// QRDB convenience error constructors.
var (
	QRDBErrorNotFound                   = qrdb.ErrorNotFound
	QRDBErrorAlreadyExists              = qrdb.ErrorAlreadyExists
	QRDBErrorInvalidInput               = qrdb.ErrorInvalidInput
	QRDBErrorInvalidInputf              = qrdb.ErrorInvalidInputf
	QRDBErrorTimeout                    = qrdb.ErrorTimeout
	QRDBErrorInternal                   = qrdb.ErrorInternal
	QRDBErrorInternalf                  = qrdb.ErrorInternalf
	QRDBErrorUnavailable                = qrdb.ErrorUnavailable
	QRDBErrorUnavailablef               = qrdb.ErrorUnavailablef
	QRDBErrorNotImplemented             = qrdb.ErrorNotImplemented
	QRDBErrorCircuitOpen                = qrdb.ErrorCircuitOpen
	QRDBNewQuotaExceededError           = qrdb.NewQuotaExceededError
	QRDBNewSystemKeyspaceViolationError = qrdb.NewSystemKeyspaceViolationError
	QRDBNewCrossTenantAccessError       = qrdb.NewCrossTenantAccessError
	QRDBNewMissingTenantContextError    = qrdb.NewMissingTenantContextError
	QRDBNewMissingJustificationError    = qrdb.NewMissingJustificationError
	QRDBNewMissingUserContextError      = qrdb.NewMissingUserContextError
)

// ==========================================================================
// Interface types (from types_interfaces.go)
// ==========================================================================

// QRDBLogger is the logging interface used throughout go-qrdb.
type QRDBLogger = qrdb.Logger

// QRDBLogLevel identifies the severity of a log message.
type QRDBLogLevel = qrdb.LogLevel

// QRDBLogLevel constants.
const (
	QRDBLogLevelDebug = qrdb.LogLevelDebug
	QRDBLogLevelInfo  = qrdb.LogLevelInfo
	QRDBLogLevelWarn  = qrdb.LogLevelWarn
	QRDBLogLevelError = qrdb.LogLevelError
	QRDBLogLevelFatal = qrdb.LogLevelFatal
)

// QRDBRaftNode is the interface for Raft consensus node operations.
type QRDBRaftNode = qrdb.RaftNode

// ==========================================================================
// Seal types (from types_seal.go)
// ==========================================================================

// QRDBSealMode identifies the sealing mode (auto vs Shamir).
type QRDBSealMode = qrdb.SealMode

// QRDBSealMode constants.
const (
	QRDBSealModeAuto   = qrdb.SealModeAuto
	QRDBSealModeShamir = qrdb.SealModeShamir
)

// Seal core interfaces.
type (
	QRDBEncryptionBarrier = qrdb.EncryptionBarrier
)

// Seal strategy types.
type (
	QRDBStrategyID           = qrdb.StrategyID
	QRDBSealingStrategy      = qrdb.SealingStrategy
	QRDBSymmetricEncrypter   = qrdb.SymmetricEncrypter
	QRDBStorageBackend       = qrdb.StorageBackend
	QRDBCredentials          = qrdb.Credentials
	QRDBSealedRootKey        = qrdb.SealedRootKey
	QRDBShareAccumulator     = qrdb.ShareAccumulator
	QRDBShareSplitter        = qrdb.ShareSplitter
	QRDBQuorumProgress       = qrdb.QuorumProgress
	QRDBShamirInitResult     = qrdb.ShamirInitResult
	QRDBShamirConfig         = qrdb.ShamirConfig
	QRDBSoftwareStrategy     = qrdb.SoftwareStrategy
	QRDBEpochBarrier         = qrdb.EpochBarrier
	QRDBEpochBarrierConfig   = qrdb.EpochBarrierConfig
	QRDBInvocationCounter    = qrdb.InvocationCounter
	QRDBNonceTrackerProvider = qrdb.NonceTrackerProvider
	QRDBAEADProvider         = qrdb.AEADProvider
	QRDBSymmetricAlgorithm   = qrdb.SymmetricAlgorithm
)

// Seal barrier types.
type (
	QRDBStorageBarrier      = qrdb.StorageBarrier
	QRDBBarrier             = qrdb.Barrier
	QRDBBarrierConfig       = qrdb.BarrierConfig
	QRDBBarrierStatus       = qrdb.BarrierStatus
	QRDBBarrierRegistry     = qrdb.BarrierRegistry
	QRDBTenantBarrier       = qrdb.TenantBarrier
	QRDBTenantBarrierConfig = qrdb.TenantBarrierConfig
	QRDBMemoryBackend       = qrdb.MemoryBackend
	QRDBNamespacedBackend   = qrdb.NamespacedBackend
)

// QRDBShamirStrategy implements Shamir secret sharing as a sealing strategy.
type QRDBShamirStrategy = qrdb.ShamirStrategy

// Seal store types.
type (
	QRDBSealStore       = qrdb.SealStore
	QRDBSealStoreStatus = qrdb.SealStoreStatus
)

// Seal storage adapter types.
type (
	QRDBLegacyStorage  = qrdb.LegacyStorage
	QRDBStorageAdapter = qrdb.StorageAdapter
)

// Recovery and root token types.
type (
	QRDBRecoveryKeyResult = qrdb.RecoveryKeyResult
	QRDBRootToken         = qrdb.RootToken
)

// Seal audit types.
type (
	QRDBAuditEvent  = qrdb.AuditEvent
	QRDBAuditLogger = qrdb.AuditLogger
)

// Seal strategy ID constants are exported from the xkms SDK's seal.go
// (StrategyTPM2/PKCS11/AWSKMS/GCPKMS/AzureKV/Vault/Shamir/Passphrase). The
// former QRDBStrategy* re-exports here were redundant and unused; removed.

// QRDBDefaultQuorumTTL is the default time-to-live for a Shamir quorum session.
const QRDBDefaultQuorumTTL = qrdb.DefaultQuorumTTL

// Seal constructors.
var (
	QRDBNewStorageBarrier         = qrdb.NewStorageBarrier
	QRDBNewBarrier                = qrdb.NewBarrier
	QRDBNewBarrierRegistry        = qrdb.NewBarrierRegistry
	QRDBNewTenantBarrier          = qrdb.NewTenantBarrier
	QRDBNewMemoryBackend          = qrdb.NewMemoryBackend
	QRDBNewNamespacedBackend      = qrdb.NewNamespacedBackend
	QRDBNewShamirStrategy         = qrdb.NewShamirStrategy
	QRDBNewSoftwareStrategy       = qrdb.NewSoftwareStrategy
	QRDBNewSealStore              = qrdb.NewSealStore
	QRDBNewStorageAdapter         = qrdb.NewStorageAdapter
	QRDBNewShamirShareAccumulator = qrdb.NewShamirShareAccumulator
	QRDBNewInvocationCounter      = qrdb.NewInvocationCounter
	QRDBNewNonceTracker           = qrdb.NewNonceTracker
	QRDBNewSoftwareAEADProvider   = qrdb.NewSoftwareAEADProvider
	QRDBDefaultEpochBarrierConfig = qrdb.DefaultEpochBarrierConfig
)

// ==========================================================================
// Seal error types (from types_seal_errors.go)
// ==========================================================================

// Seal sentinel errors.
var (
	QRDBErrSealed                      = qrdb.ErrSealed
	QRDBErrAlreadyUnsealed             = qrdb.ErrAlreadyUnsealed
	QRDBErrAlreadyInitialized          = qrdb.ErrAlreadyInitialized
	QRDBErrNotInitialized              = qrdb.ErrNotInitialized
	QRDBErrInvalidCredentials          = qrdb.ErrInvalidCredentials
	QRDBErrNoAvailableStrategy         = qrdb.ErrNoAvailableStrategy
	QRDBErrStrategyNotFound            = qrdb.ErrStrategyNotFound
	QRDBErrStrategyMismatch            = qrdb.ErrStrategyMismatch
	QRDBErrCorruptRootKey              = qrdb.ErrCorruptRootKey
	QRDBErrNilSealedData               = qrdb.ErrNilSealedData
	QRDBErrEncryptorNotAvailable       = qrdb.ErrEncryptorNotAvailable
	QRDBErrHardwareEncryptorRequired   = qrdb.ErrHardwareEncryptorRequired
	QRDBErrShamirNotConfigured         = qrdb.ErrShamirNotConfigured
	QRDBErrShamirThresholdInvalid      = qrdb.ErrShamirThresholdInvalid
	QRDBErrShamirDuplicateShare        = qrdb.ErrShamirDuplicateShare
	QRDBErrShamirQuorumExpired         = qrdb.ErrShamirQuorumExpired
	QRDBErrShamirQuorumIncomplete      = qrdb.ErrShamirQuorumIncomplete
	QRDBErrShamirNoQuorum              = qrdb.ErrShamirNoQuorum
	QRDBErrShamirCombineFailed         = qrdb.ErrShamirCombineFailed
	QRDBErrShamirShareNotFound         = qrdb.ErrShamirShareNotFound
	QRDBErrShamirVerificationFailed    = qrdb.ErrShamirVerificationFailed
	QRDBErrShamirNoSharesFound         = qrdb.ErrShamirNoSharesFound
	QRDBErrShamirStorageFailed         = qrdb.ErrShamirStorageFailed
	QRDBErrShamirNilStorage            = qrdb.ErrShamirNilStorage
	QRDBErrShamirSplitFailed           = qrdb.ErrShamirSplitFailed
	QRDBErrShamirSerializationFailed   = qrdb.ErrShamirSerializationFailed
	QRDBErrNilSealedBackend            = qrdb.ErrNilSealedBackend
	QRDBErrSecretNotFound              = qrdb.ErrSecretNotFound
	QRDBErrInvalidSecretName           = qrdb.ErrInvalidSecretName
	QRDBErrResealFailed                = qrdb.ErrResealFailed
	QRDBErrRecoveryKeysNotFound        = qrdb.ErrRecoveryKeysNotFound
	QRDBErrRootTokenVerificationFailed = qrdb.ErrRootTokenVerificationFailed
	QRDBErrTenantNotFound              = qrdb.ErrTenantNotFound
	QRDBErrTenantAlreadyExists         = qrdb.ErrTenantAlreadyExists
	QRDBErrEmptyTenantID               = qrdb.ErrEmptyTenantID
	QRDBErrNilSystemBarrier            = qrdb.ErrNilSystemBarrier
	QRDBErrTenantSealed                = qrdb.ErrTenantSealed
	QRDBErrTenantAlreadyInitialized    = qrdb.ErrTenantAlreadyInitialized
	QRDBErrTenantNotInitialized        = qrdb.ErrTenantNotInitialized
	QRDBErrTenantAlreadyUnsealed       = qrdb.ErrTenantAlreadyUnsealed
	QRDBErrNoStrategy                  = qrdb.ErrNoStrategy
	QRDBErrNilStorageBackend           = qrdb.ErrNilStorageBackend
	QRDBErrInvalidPassphrase           = qrdb.ErrInvalidPassphrase
	QRDBErrSealStoreSecretNotFound     = qrdb.ErrSealStoreSecretNotFound
	QRDBErrSealStoreBarrierSealed      = qrdb.ErrSealStoreBarrierSealed
	QRDBErrInvocationLimitExceeded     = qrdb.ErrInvocationLimitExceeded
	QRDBErrNonceReuse                  = qrdb.ErrNonceReuse
)

// Seal error types.
type (
	QRDBSealGetError               = qrdb.SealGetError
	QRDBSealPutError               = qrdb.SealPutError
	QRDBSealStoreError             = qrdb.SealStoreError
	QRDBSealInvalidShareError      = qrdb.SealInvalidShareError
	QRDBSealBarrierSealedError     = qrdb.SealBarrierSealedError
	QRDBSealDEKDerivationError     = qrdb.SealDEKDerivationError
	QRDBSealInvalidConfigError     = qrdb.SealInvalidConfigError
	QRDBSealTenantDEKNotFoundError = qrdb.SealTenantDEKNotFoundError
)

// ==========================================================================
// System types (from types_system.go)
// ==========================================================================

// QRDBOpenSSLConfig holds parsed OpenSSL configuration from the host system.
type QRDBOpenSSLConfig = qrdb.OpenSSLConfig

// QRDBLoadOpenSSLConfig reads and parses the system OpenSSL configuration.
var QRDBLoadOpenSSLConfig = qrdb.LoadOpenSSLConfig

// The DAO, database manager/service, and time-series re-exports formerly
// below this line (QRDBKVStore, QRDBAtomicKVStore, QRDBEntity,
// QRDBGenericDAO, QRDBManager, QRDBDatabaseServicer, QRDBTimeSeriesStorage,
// and their siblings) were the qrdb database-plane surface. go-xkms MUST NOT
// re-export it (handbook 00-ownership-and-sdk-boundary.md L5); consumers
// that need it import github.com/jeremyhahn/go-qrdb/sdk/go directly.
