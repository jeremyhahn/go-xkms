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

// This file re-exports ALL public types from go-qrdb/sdk/go so that
// downstream consumers (e.g., go-trusted-ca) can depend solely on the
// go-xkms SDK without importing go-qrdb directly.
//
// Every alias is prefixed with QRDB to avoid name collisions with
// go-xkms's own types.

package xkms

import (
	qrdb "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// ==========================================================================
// Backend types (from types_backend.go)
// ==========================================================================

// QRDBSMAdapter is the state machine adapter interface used by LocalBackend.
type QRDBSMAdapter = qrdb.SMAdapter

// QRDBLocalBackend wraps a state machine as a local (non-Raft) backend.
type QRDBLocalBackend = qrdb.LocalBackend

// QRDBSimpleStateMachine is a simple state machine implementation backed by
// a storage engine.
type QRDBSimpleStateMachine = qrdb.SimpleStateMachine

// QRDBBackendClusterOperationError is returned when a cluster operation fails.
type QRDBBackendClusterOperationError = qrdb.BackendClusterOperationError

// QRDBBackendUnsupportedOperationError is returned when an operation is not
// supported by the backend.
type QRDBBackendUnsupportedOperationError = qrdb.BackendUnsupportedOperationError

// QRDBBackendClosedError is returned when an operation is attempted on a
// closed backend.
type QRDBBackendClosedError = qrdb.BackendClosedError

// QRDBBackendLookupTypeError is returned when a lookup query has an unexpected type.
type QRDBBackendLookupTypeError = qrdb.BackendLookupTypeError

// QRDBNewLocalBackend creates a new LocalBackend wrapping the given state machine.
var QRDBNewLocalBackend = qrdb.NewLocalBackend

// QRDBNewSimpleStateMachine creates a new SimpleStateMachine backed by storage.
var QRDBNewSimpleStateMachine = qrdb.NewSimpleStateMachine

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
	QRDBNewCeremonyService    = qrdb.NewCeremonyService
	QRDBNewThresholdRegistry  = qrdb.NewThresholdRegistry
	QRDBNewCustodianGroupService = qrdb.NewCustodianGroupService
	QRDBNewShareService       = qrdb.NewShareService
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
	QRDBErrCeremonyDuplicateUsername            = qrdb.ErrCeremonyDuplicateUsername
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
// DAO types (from types_dao.go)
// ==========================================================================

// QRDBCodec is the serialization interface used by DAOs.
type QRDBCodec[E any] = qrdb.Codec[E]

// QRDBCodecType identifies a serialization format (JSON, CBOR, Avro, etc.).
type QRDBCodecType = qrdb.CodecType

// QRDBSupportedCodecs returns the list of codec types compiled into the binary.
var QRDBSupportedCodecs = qrdb.SupportedCodecs

// QRDBIsCodecSupported reports whether the given codec type is available.
var QRDBIsCodecSupported = qrdb.IsCodecSupported

// QRDBNewCodec creates a new Codec for the given CodecType.
func QRDBNewCodec[E any](ct QRDBCodecType) (QRDBCodec[E], error) {
	return qrdb.NewCodec[E](ct)
}

// QRDBPager provides paginated listing of entities.
type QRDBPager[E any] = qrdb.Pager[E]

// QRDBDynamicEntity is a schema-less entity backed by a map of fields.
type QRDBDynamicEntity = qrdb.DynamicEntity

// QRDBDynamicFieldHashGenerator generates entity IDs by hashing a named field.
type QRDBDynamicFieldHashGenerator = qrdb.DynamicFieldHashGenerator

// QRDBNewDynamicFieldHashGenerator creates a new DynamicFieldHashGenerator.
var QRDBNewDynamicFieldHashGenerator = qrdb.NewDynamicFieldHashGenerator

// QRDBDAOFactory manages DAO creation with shared KVStore providers.
type QRDBDAOFactory = qrdb.DAOFactory

// QRDBDAOFactoryConfig holds configuration for a DAOFactory.
type QRDBDAOFactoryConfig = qrdb.DAOFactoryConfig

// QRDBKVStoreProvider returns a KVStore for the given shard ID.
type QRDBKVStoreProvider = qrdb.KVStoreProvider

// QRDBPartitionedKVStoreProvider returns a KVStore for a named partition and shard.
type QRDBPartitionedKVStoreProvider = qrdb.PartitionedKVStoreProvider

// QRDBEntityPartitionMapping maps entity types to partition names.
type QRDBEntityPartitionMapping = qrdb.EntityPartitionMapping

// QRDBNewDAOFactory creates a new DAOFactory with a single KVStore provider.
var QRDBNewDAOFactory = qrdb.NewDAOFactory

// QRDBNewDAOFactoryWithConfig creates a new DAOFactory from a FactoryConfig.
var QRDBNewDAOFactoryWithConfig = qrdb.NewDAOFactoryWithConfig

// DAO error types.
type (
	QRDBDAONotFoundError              = qrdb.DAONotFoundError
	QRDBDAOSerializationFailedError   = qrdb.DAOSerializationFailedError
	QRDBDAODeserializationFailedError = qrdb.DAODeserializationFailedError
	QRDBDAOInvalidEntityIDError       = qrdb.DAOInvalidEntityIDError
	QRDBDAOCodecCreationError         = qrdb.DAOCodecCreationError
	QRDBDAOInvalidConfigError         = qrdb.DAOInvalidConfigError
	QRDBDAOTransactionClosedError     = qrdb.DAOTransactionClosedError
	QRDBDAOTransactionCommitError     = qrdb.DAOTransactionCommitError
	QRDBDAOInvalidEntityError         = qrdb.DAOInvalidEntityError
	QRDBDAOInvalidConditionError      = qrdb.DAOInvalidConditionError
	QRDBDAOConditionFailedError       = qrdb.DAOConditionFailedError
	QRDBDAOUnitOfWorkClosedError      = qrdb.DAOUnitOfWorkClosedError
	QRDBDAOUnitOfWorkCommitError      = qrdb.DAOUnitOfWorkCommitError
)

// DAO error query helpers.
var (
	QRDBIsDAOTransactionClosed    = qrdb.IsDAOTransactionClosed
	QRDBIsDAOTransactionCommitError = qrdb.IsDAOTransactionCommitError
	QRDBIsDAOInvalidEntity        = qrdb.IsDAOInvalidEntity
	QRDBIsDAOInvalidCondition     = qrdb.IsDAOInvalidCondition
	QRDBIsDAOConditionFailed      = qrdb.IsDAOConditionFailed
	QRDBIsDAOUnitOfWorkClosed     = qrdb.IsDAOUnitOfWorkClosed
	QRDBIsDAOUnitOfWorkCommitError = qrdb.IsDAOUnitOfWorkCommitError
)

// ==========================================================================
// Database types (from types_database.go)
// ==========================================================================

// QRDBEngineType identifies the state machine engine.
type QRDBEngineType = qrdb.EngineType

// QRDBEngineType constants.
const (
	QRDBEngineKV         = qrdb.EngineKV
	QRDBEngineTimeSeries = qrdb.EngineTimeSeries
	QRDBEngineVector     = qrdb.EngineVector
)

// QRDBBackendType identifies the storage/consensus backend.
type QRDBBackendType = qrdb.BackendType

// QRDBBackendType constants.
const (
	QRDBBackendMemory = qrdb.BackendMemory
	QRDBBackendFile   = qrdb.BackendFile
	QRDBBackendPebble = qrdb.BackendPebble
	QRDBBackendRaft   = qrdb.BackendRaft
)

// QRDBDatabaseMode identifies the operational mode.
type QRDBDatabaseMode = qrdb.DatabaseMode

// QRDBDatabaseMode constants.
const (
	QRDBModeEmbedded = qrdb.ModeEmbedded
	QRDBModeRemote   = qrdb.ModeRemote
)

// QRDBStatusType identifies the status of a database.
type QRDBStatusType = qrdb.StatusType

// QRDBStatusType constants.
const (
	QRDBStatusOpen   = qrdb.StatusOpen
	QRDBStatusClosed = qrdb.StatusClosed
	QRDBStatusError  = qrdb.StatusError
	QRDBStatusSealed = qrdb.StatusSealed
)

// QRDBRaftClusterMode identifies the Raft cluster mode.
type QRDBRaftClusterMode = qrdb.RaftClusterMode

// QRDBRaftClusterMode constants.
const (
	QRDBRaftNone        = qrdb.RaftNone
	QRDBRaftLocal       = qrdb.RaftLocal
	QRDBRaftDistributed = qrdb.RaftDistributed
)

// QRDBDiscoveryMethod identifies the Raft node discovery method.
type QRDBDiscoveryMethod = qrdb.DiscoveryMethod

// QRDBDiscoveryMethod constants.
const (
	QRDBDiscoveryStatic    = qrdb.DiscoveryStatic
	QRDBDiscoveryMulticast = qrdb.DiscoveryMulticast
	QRDBDiscoveryDNS       = qrdb.DiscoveryDNS
	QRDBDiscoveryToken     = qrdb.DiscoveryToken
)

// Database configuration types.
type (
	QRDBDatabaseConfig           = qrdb.DatabaseConfig
	QRDBDatabaseRaftConfig       = qrdb.DatabaseRaftConfig
	QRDBDatabaseBarrierConfig    = qrdb.DatabaseBarrierConfig
	QRDBDatabaseConnectionConfig = qrdb.DatabaseConnectionConfig
	QRDBProtocolConfig           = qrdb.ProtocolConfig
	QRDBEtcdConfig               = qrdb.EtcdConfig
	QRDBStaticDiscoveryConfig    = qrdb.StaticDiscoveryConfig
	QRDBMulticastDiscoveryConfig = qrdb.MulticastDiscoveryConfig
	QRDBDNSDiscoveryConfig       = qrdb.DNSDiscoveryConfig
	QRDBTokenDiscoveryConfig     = qrdb.TokenDiscoveryConfig
)

// Database info and metadata types.
type (
	QRDBDatabaseMeta = qrdb.DatabaseMeta
	QRDBDatabaseInfo = qrdb.DatabaseInfo
	QRDBDatabase     = qrdb.Database
)

// Database backend types.
type (
	QRDBDatabaseBackend        = qrdb.DatabaseBackend
	QRDBKeyValue               = qrdb.KeyValue
	QRDBBatchOp                = qrdb.BatchOp
	QRDBBatchOpType            = qrdb.BatchOpType
	QRDBStandaloneBackend      = qrdb.StandaloneBackend
	QRDBBarrierEncryptor       = qrdb.BarrierEncryptor
	QRDBBarrierBackend         = qrdb.BarrierBackend
	QRDBBackendStorageAdapter  = qrdb.BackendStorageAdapter
	QRDBDatabaseBarrierManager = qrdb.DatabaseBarrierManager
)

// QRDBBatchOpType constants.
const (
	QRDBBatchOpPut    = qrdb.BatchOpPut
	QRDBBatchOpDelete = qrdb.BatchOpDelete
)

// Database constructors.
var (
	QRDBNewDatabase              = qrdb.NewDatabase
	QRDBNewStandaloneBackend     = qrdb.NewStandaloneBackend
	QRDBNewBarrierBackend        = qrdb.NewBarrierBackend
	QRDBNewBackendStorageAdapter = qrdb.NewBackendStorageAdapter
	QRDBNewDatabaseBarrierManager = qrdb.NewDatabaseBarrierManager
)

// Database error types.
type (
	QRDBDBInvalidNameError           = qrdb.DBInvalidNameError
	QRDBDBInvalidEngineError         = qrdb.DBInvalidEngineError
	QRDBDBInvalidBackendError        = qrdb.DBInvalidBackendError
	QRDBDBAlreadyExistsError         = qrdb.DBAlreadyExistsError
	QRDBDBNotFoundError              = qrdb.DBNotFoundError
	QRDBDBNotOpenError               = qrdb.DBNotOpenError
	QRDBDBOpenError                  = qrdb.DBOpenError
	QRDBDBCloseError                 = qrdb.DBCloseError
	QRDBDBMetaReadError              = qrdb.DBMetaReadError
	QRDBDBMetaWriteError             = qrdb.DBMetaWriteError
	QRDBDBDropError                  = qrdb.DBDropError
	QRDBDBStorageCreateError         = qrdb.DBStorageCreateError
	QRDBDBInvalidModeError           = qrdb.DBInvalidModeError
	QRDBDBConnectionRequiredError    = qrdb.DBConnectionRequiredError
	QRDBDBInvalidRaftClusterModeError = qrdb.DBInvalidRaftClusterModeError
	QRDBDBInvalidDiscoveryMethodError = qrdb.DBInvalidDiscoveryMethodError
	QRDBDBRangeIteratorError         = qrdb.DBRangeIteratorError
	QRDBDBBarrierCreateError         = qrdb.DBBarrierCreateError
	QRDBDBBarrierSealError           = qrdb.DBBarrierSealError
	QRDBDBBarrierUnsealError         = qrdb.DBBarrierUnsealError
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
	QRDBError                = qrdb.QRDBError
	QRDBQuotaExceededError   = qrdb.QuotaExceededError
	QRDBMessageError         = qrdb.MessageError
	QRDBWrappedMessageError  = qrdb.WrappedMessageError
	QRDBParameterNotFoundError = qrdb.ParameterNotFoundError
)

// QRDB error constructors.
var (
	QRDBNewError  = qrdb.NewError
	QRDBNewErrorf = qrdb.NewErrorf
	QRDBWrapError  = qrdb.WrapError
	QRDBWrapErrorf = qrdb.WrapErrorf
)

// QRDB error query helpers.
var (
	QRDBIsErrorCode             = qrdb.IsErrorCode
	QRDBAsError                 = qrdb.AsError
	QRDBErrorCodeOf             = qrdb.ErrorCodeOf
	QRDBErrorOperationOf        = qrdb.ErrorOperationOf
	QRDBIsRetryableError        = qrdb.IsRetryableError
	QRDBErrorContext            = qrdb.ErrorContext
	QRDBIsErrorNotFound         = qrdb.IsErrorNotFound
	QRDBIsErrorCanceled         = qrdb.IsErrorCanceled
	QRDBIsErrorInvalidInput     = qrdb.IsErrorInvalidInput
	QRDBIsErrorResourceExhausted = qrdb.IsErrorResourceExhausted
	QRDBIsErrorSystemKeyspaceViolation = qrdb.IsErrorSystemKeyspaceViolation
	QRDBIsErrorCrossTenantAccess      = qrdb.IsErrorCrossTenantAccess
	QRDBIsErrorMissingTenantContext   = qrdb.IsErrorMissingTenantContext
	QRDBIsErrorQuotaExceeded          = qrdb.IsErrorQuotaExceeded
	QRDBIsErrorMissingJustification   = qrdb.IsErrorMissingJustification
	QRDBIsErrorMissingUserContext     = qrdb.IsErrorMissingUserContext
	QRDBIsErrorCircuitOpen            = qrdb.IsErrorCircuitOpen
)

// QRDB convenience error constructors.
var (
	QRDBErrorNotFound      = qrdb.ErrorNotFound
	QRDBErrorAlreadyExists = qrdb.ErrorAlreadyExists
	QRDBErrorInvalidInput  = qrdb.ErrorInvalidInput
	QRDBErrorInvalidInputf = qrdb.ErrorInvalidInputf
	QRDBErrorTimeout       = qrdb.ErrorTimeout
	QRDBErrorInternal      = qrdb.ErrorInternal
	QRDBErrorInternalf     = qrdb.ErrorInternalf
	QRDBErrorUnavailable   = qrdb.ErrorUnavailable
	QRDBErrorUnavailablef  = qrdb.ErrorUnavailablef
	QRDBErrorNotImplemented = qrdb.ErrorNotImplemented
	QRDBErrorCircuitOpen    = qrdb.ErrorCircuitOpen
	QRDBNewQuotaExceededError          = qrdb.NewQuotaExceededError
	QRDBNewSystemKeyspaceViolationError = qrdb.NewSystemKeyspaceViolationError
	QRDBNewCrossTenantAccessError      = qrdb.NewCrossTenantAccessError
	QRDBNewMissingTenantContextError   = qrdb.NewMissingTenantContextError
	QRDBNewMissingJustificationError   = qrdb.NewMissingJustificationError
	QRDBNewMissingUserContextError     = qrdb.NewMissingUserContextError
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

// QRDBHNSWIndex is the interface for HNSW approximate nearest-neighbor indexes.
type QRDBHNSWIndex = qrdb.HNSWIndex

// QRDBHNSWSearchResult holds a single search result from an HNSW index.
type QRDBHNSWSearchResult = qrdb.HNSWSearchResult

// QRDBHNSWStats holds statistics about an HNSW index.
type QRDBHNSWStats = qrdb.HNSWStats

// QRDBHNSWIndexFactory creates HNSW index instances.
type QRDBHNSWIndexFactory = qrdb.HNSWIndexFactory

// QRDBHNSWConfig configures HNSW index parameters.
type QRDBHNSWConfig = qrdb.HNSWConfig

// QRDBDefaultHNSWConfig returns the default HNSW configuration.
var QRDBDefaultHNSWConfig = qrdb.DefaultHNSWConfig

// QRDBRaftNode is the interface for Raft consensus node operations.
type QRDBRaftNode = qrdb.RaftNode

// ==========================================================================
// KVStore types (from types_kvstore.go)
// ==========================================================================

// QRDBEntityIndex defines a secondary index on a DAO entity field.
type QRDBEntityIndex = qrdb.EntityIndex

// QRDBEntityRegisterer allows entity types to register their secondary indexes.
type QRDBEntityRegisterer = qrdb.EntityRegisterer

// QRDBLookupFunc is a callback used for custom index lookups.
type QRDBLookupFunc = qrdb.LookupFunc

// KVStore error types.
type (
	QRDBKVSealedError            = qrdb.KVSealedError
	QRDBKVPutError               = qrdb.KVPutError
	QRDBKVGetError               = qrdb.KVGetError
	QRDBKVDeleteError            = qrdb.KVDeleteError
	QRDBKVScanError              = qrdb.KVScanError
	QRDBKVListError              = qrdb.KVListError
	QRDBKVExistsError            = qrdb.KVExistsError
	QRDBKVIndexQueryError        = qrdb.KVIndexQueryError
	QRDBKVIndexScanError         = qrdb.KVIndexScanError
	QRDBKVIndexRegistrationError = qrdb.KVIndexRegistrationError
)

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
	QRDBTenantKeyManager  = qrdb.TenantKeyManager
)

// Seal strategy types.
type (
	QRDBStrategyID         = qrdb.StrategyID
	QRDBSealingStrategy    = qrdb.SealingStrategy
	QRDBSymmetricEncrypter = qrdb.SymmetricEncrypter
	QRDBStorageBackend     = qrdb.StorageBackend
	QRDBCredentials        = qrdb.Credentials
	QRDBSealedRootKey      = qrdb.SealedRootKey
	QRDBShareAccumulator   = qrdb.ShareAccumulator
	QRDBShareSplitter      = qrdb.ShareSplitter
	QRDBQuorumProgress     = qrdb.QuorumProgress
	QRDBShamirInitResult   = qrdb.ShamirInitResult
	QRDBShamirConfig       = qrdb.ShamirConfig
	QRDBSoftwareStrategy   = qrdb.SoftwareStrategy
	QRDBEpochBarrier       = qrdb.EpochBarrier
	QRDBEpochBarrierConfig = qrdb.EpochBarrierConfig
	QRDBInvocationCounter  = qrdb.InvocationCounter
	QRDBNonceTrackerProvider = qrdb.NonceTrackerProvider
	QRDBAEADProvider         = qrdb.AEADProvider
	QRDBSymmetricAlgorithm   = qrdb.SymmetricAlgorithm
)

// Seal barrier types.
type (
	QRDBStorageBarrier    = qrdb.StorageBarrier
	QRDBBarrier           = qrdb.Barrier
	QRDBBarrierConfig     = qrdb.BarrierConfig
	QRDBBarrierStatus     = qrdb.BarrierStatus
	QRDBBarrierRegistry   = qrdb.BarrierRegistry
	QRDBTenantBarrier     = qrdb.TenantBarrier
	QRDBTenantBarrierConfig = qrdb.TenantBarrierConfig
	QRDBMemoryBackend     = qrdb.MemoryBackend
	QRDBNamespacedBackend = qrdb.NamespacedBackend
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

// Seal strategy ID constants.
const (
	QRDBStrategyTPM2     = qrdb.StrategyTPM2
	QRDBStrategyPKCS11   = qrdb.StrategyPKCS11
	QRDBStrategyAWSKMS   = qrdb.StrategyAWSKMS
	QRDBStrategyGCPKMS   = qrdb.StrategyGCPKMS
	QRDBStrategyAzureKV  = qrdb.StrategyAzureKV
	QRDBStrategyVault    = qrdb.StrategyVault
	QRDBStrategyShamir   = qrdb.StrategyShamir
	QRDBStrategySoftware = qrdb.StrategySoftware
)

// QRDBDefaultQuorumTTL is the default time-to-live for a Shamir quorum session.
const QRDBDefaultQuorumTTL = qrdb.DefaultQuorumTTL

// Seal constructors.
var (
	QRDBNewStorageBarrier        = qrdb.NewStorageBarrier
	QRDBNewBarrier               = qrdb.NewBarrier
	QRDBNewBarrierRegistry       = qrdb.NewBarrierRegistry
	QRDBNewTenantBarrier         = qrdb.NewTenantBarrier
	QRDBNewMemoryBackend         = qrdb.NewMemoryBackend
	QRDBNewNamespacedBackend     = qrdb.NewNamespacedBackend
	QRDBNewShamirStrategy        = qrdb.NewShamirStrategy
	QRDBNewSoftwareStrategy      = qrdb.NewSoftwareStrategy
	QRDBNewSealStore             = qrdb.NewSealStore
	QRDBNewStorageAdapter        = qrdb.NewStorageAdapter
	QRDBNewShamirShareAccumulator = qrdb.NewShamirShareAccumulator
	QRDBNewInvocationCounter     = qrdb.NewInvocationCounter
	QRDBNewNonceTracker          = qrdb.NewNonceTracker
	QRDBNewSoftwareAEADProvider  = qrdb.NewSoftwareAEADProvider
	QRDBDefaultEpochBarrierConfig = qrdb.DefaultEpochBarrierConfig
	QRDBDefaultPreferenceOrder   = qrdb.DefaultPreferenceOrder
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
	QRDBSealGetError           = qrdb.SealGetError
	QRDBSealPutError           = qrdb.SealPutError
	QRDBSealStoreError         = qrdb.SealStoreError
	QRDBSealInvalidShareError  = qrdb.SealInvalidShareError
	QRDBSealBarrierSealedError = qrdb.SealBarrierSealedError
	QRDBSealDEKDerivationError = qrdb.SealDEKDerivationError
	QRDBSealInvalidConfigError = qrdb.SealInvalidConfigError
	QRDBSealTenantDEKNotFoundError = qrdb.SealTenantDEKNotFoundError
)

// ==========================================================================
// Service types (from types_service.go)
// ==========================================================================

// Service interfaces.
type (
	QRDBKVServicer    = qrdb.KVServicer
	QRDBAdminServicer = qrdb.AdminServicer
	QRDBHost          = qrdb.Host
)

// Service implementations.
type (
	QRDBKVService          = qrdb.KVService
	QRDBKVServiceOption    = qrdb.KVServiceOption
	QRDBAdminService       = qrdb.AdminService
	QRDBAdminServiceOption = qrdb.AdminServiceOption
	QRDBBackendKVService   = qrdb.BackendKVService
)

// Service info types.
type (
	QRDBHealthStatus = qrdb.HealthStatus
	QRDBStatusInfo   = qrdb.StatusInfo
	QRDBPeerInfo     = qrdb.PeerInfo
	QRDBShardPeers   = qrdb.ShardPeers
	QRDBPeersInfo    = qrdb.PeersInfo
)

// Service constructors.
var (
	QRDBNewKVService        = qrdb.NewKVService
	QRDBNewAdminService     = qrdb.NewAdminService
	QRDBNewBackendKVService = qrdb.NewBackendKVService
)

// ==========================================================================
// State machine types (from types_statemachine.go)
// ==========================================================================

// QRDBSMBackend is the storage interface used by state machine implementations.
type QRDBSMBackend = qrdb.SMBackend

// State machine implementations.
type (
	QRDBFastStateMachine = qrdb.FastStateMachine
	QRDBConcurrentBackend = qrdb.ConcurrentBackend
	QRDBStandardBackend   = qrdb.StandardBackend
	QRDBDiskBackend       = qrdb.DiskBackend
	QRDBCachedDiskBackend = qrdb.CachedDiskBackend
	QRDBFastBackend       = qrdb.FastBackend
	QRDBKVStateMachine    = qrdb.KVStateMachine
)

// State machine options.
type QRDBSMOption = qrdb.SMOption

var (
	QRDBWithWatchManager    = qrdb.WithWatchManager
	QRDBWithSMLogger        = qrdb.WithSMLogger
	QRDBWithIndexManager    = qrdb.WithIndexManager
	QRDBWithLeaseManager    = qrdb.WithLeaseManager
	QRDBWithTimeSeriesStore = qrdb.WithTimeSeriesStore
	QRDBWithMVCCStore       = qrdb.WithMVCCStore
)

// State machine type interfaces.
type (
	QRDBWatchManager    = qrdb.WatchManager
	QRDBPrefixQuery     = qrdb.PrefixQuery
	QRDBLeaseManager    = qrdb.LeaseManager
	QRDBIndexManager    = qrdb.IndexManager
	QRDBTimeSeriesStore = qrdb.TimeSeriesStore
	QRDBMVCCStore       = qrdb.MVCCStore
)

// State machine registry types.
type (
	QRDBSMFactory         = qrdb.SMFactory
	QRDBSMPersistenceType = qrdb.SMPersistenceType
	QRDBSMKind            = qrdb.SMKind
	QRDBSMCapability      = qrdb.SMCapability
	QRDBSMDescriptor      = qrdb.SMDescriptor
	QRDBSMRegistry        = qrdb.SMRegistry
)

// QRDBSMPersistenceType constants.
const (
	QRDBSMPersistenceMemory = qrdb.SMPersistenceMemory
	QRDBSMPersistenceDisk   = qrdb.SMPersistenceDisk
	QRDBSMPersistenceHybrid = qrdb.SMPersistenceHybrid
)

// QRDBSMKind constants.
const (
	QRDBSMKindRegular    = qrdb.SMKindRegular
	QRDBSMKindDisk       = qrdb.SMKindDisk
	QRDBSMKindConcurrent = qrdb.SMKindConcurrent
)

// QRDBSMCapability constants.
const (
	QRDBSMCapKV          = qrdb.SMCapKV
	QRDBSMCapMVCC        = qrdb.SMCapMVCC
	QRDBSMCapTimeSeries  = qrdb.SMCapTimeSeries
	QRDBSMCapVector      = qrdb.SMCapVector
	QRDBSMCapIndex       = qrdb.SMCapIndex
	QRDBSMCapLease       = qrdb.SMCapLease
	QRDBSMCapWatch       = qrdb.SMCapWatch
	QRDBSMCapTransaction = qrdb.SMCapTransaction
	QRDBSMCapBatch       = qrdb.SMCapBatch
)

// QRDBNewSMRegistry creates a new state machine Registry.
var QRDBNewSMRegistry = qrdb.NewSMRegistry

// State machine error types.
type (
	QRDBSMInvalidOpcodeError       = qrdb.SMInvalidOpcodeError
	QRDBSMIncompleteDataError      = qrdb.SMIncompleteDataError
	QRDBSMSnapshotError            = qrdb.SMSnapshotError
	QRDBSMStorageError             = qrdb.SMStorageError
	QRDBSMServiceNotConfiguredError = qrdb.SMServiceNotConfiguredError
	QRDBSMUnknownSMTypeError       = qrdb.SMUnknownSMTypeError
)

// State machine constructors.
var (
	QRDBNewFastStateMachine = qrdb.NewFastStateMachine
	QRDBNewConcurrentBackend = qrdb.NewConcurrentBackend
	QRDBNewStandardBackend   = qrdb.NewStandardBackend
	QRDBNewDiskBackend       = qrdb.NewDiskBackend
	QRDBNewCachedDiskBackend = qrdb.NewCachedDiskBackend
	QRDBNewFastBackend       = qrdb.NewFastBackend
	QRDBNewKVStateMachine    = qrdb.NewKVStateMachine
)

// ==========================================================================
// Storage types (from types_storage.go)
// ==========================================================================

// QRDBStorage is the low-level storage engine interface.
type QRDBStorage = qrdb.Storage

// QRDBStorageBatch is a batch of writes applied atomically.
type QRDBStorageBatch = qrdb.StorageBatch

// QRDBStorageIterator iterates over key-value pairs in a storage engine.
type QRDBStorageIterator = qrdb.StorageIterator

// QRDBStorageSnapshot is a consistent point-in-time view of storage.
type QRDBStorageSnapshot = qrdb.StorageSnapshot

// QRDBStorageIteratorOptions configures iterator behavior.
type QRDBStorageIteratorOptions = qrdb.StorageIteratorOptions

// Storage error types.
type (
	QRDBStorageError         = qrdb.StorageError
	QRDBStorageOpError       = qrdb.StorageOpError
	QRDBStorageKeyNotFoundError = qrdb.StorageKeyNotFoundError
	QRDBStorageClosedError   = qrdb.StorageClosedError
	QRDBStorageBatchError    = qrdb.StorageBatchError
	QRDBStorageIteratorError = qrdb.StorageIteratorError
	QRDBStorageSnapshotError = qrdb.StorageSnapshotError
)

// Storage implementations.
type (
	QRDBMemoryStorage       = qrdb.MemoryStorage
	QRDBFileEngine          = qrdb.FileEngine
	QRDBPebbleStorage       = qrdb.PebbleStorage
	QRDBPebbleConfig        = qrdb.PebbleConfig
	QRDBPebbleCompressionType = qrdb.PebbleCompressionType
)

// QRDBPebbleCompressionType constants.
const (
	QRDBPebbleCompressionNone   = qrdb.PebbleCompressionNone
	QRDBPebbleCompressionSnappy = qrdb.PebbleCompressionSnappy
	QRDBPebbleCompressionZstd   = qrdb.PebbleCompressionZstd
)

// Storage constructors.
var (
	QRDBNewMemoryStorage     = qrdb.NewMemoryStorage
	QRDBNewFileStorage       = qrdb.NewFileStorage
	QRDBNewPebbleStorage     = qrdb.NewPebbleStorage
	QRDBNewPebbleStorageFromDB = qrdb.NewPebbleStorageFromDB
	QRDBDefaultPebbleConfig  = qrdb.DefaultPebbleConfig
	QRDBTestPebbleConfig     = qrdb.TestPebbleConfig
)

// ==========================================================================
// System types (from types_system.go)
// ==========================================================================

// QRDBOpenSSLConfig holds parsed OpenSSL configuration from the host system.
type QRDBOpenSSLConfig = qrdb.OpenSSLConfig

// QRDBLoadOpenSSLConfig reads and parses the system OpenSSL configuration.
var QRDBLoadOpenSSLConfig = qrdb.LoadOpenSSLConfig

// ==========================================================================
// DAO types from dao.go (non-types_* file, but key SDK exports)
// ==========================================================================

// QRDBKVStore is the core key-value store interface.
type QRDBKVStore = qrdb.KVStore

// QRDBEntity is the base entity interface for all DAO entities.
type QRDBEntity = qrdb.Entity

// QRDBGenericDAO is the generic data access object interface.
type QRDBGenericDAO[E qrdb.Entity] = qrdb.GenericDAO[E]

// QRDBDAOOption configures a DAO at construction time.
type QRDBDAOOption = qrdb.DAOOption

// QRDBPageQuery holds pagination parameters for DAO queries.
type QRDBPageQuery = qrdb.PageQuery

// QRDBPageResult holds a page of results from a DAO query.
type QRDBPageResult[E any] = qrdb.PageResult[E]

// QRDBNewDAO creates a new GenericDAO for the given entity type.
func QRDBNewDAO[E qrdb.Entity](store QRDBKVStore, entityType string, newEntity func() E, opts ...QRDBDAOOption) (QRDBGenericDAO[E], error) {
	return qrdb.NewDAO[E](store, entityType, newEntity, opts...)
}

// QRDBIsDAONotFound reports whether the error is a DAO not-found error.
var QRDBIsDAONotFound = qrdb.IsDAONotFound

// QRDBDatabaseError is the structured database error type.
type QRDBDatabaseError = qrdb.DatabaseError

// QRDBDatabaseErrorCode is the error code type for database errors.
type QRDBDatabaseErrorCode = qrdb.DatabaseErrorCode

// QRDBNewDatabaseError creates a new structured database error.
var QRDBNewDatabaseError = qrdb.NewDatabaseError

// QRDBIsDatabaseError checks if the error is a DatabaseError.
var QRDBIsDatabaseError = qrdb.IsDatabaseError

// QRDBIsDatabaseErrorCode checks if the error has the given DatabaseErrorCode.
var QRDBIsDatabaseErrorCode = qrdb.IsDatabaseErrorCode

// ==========================================================================
// Database manager types (from types_database.go)
// ==========================================================================

// QRDBManager manages the lifecycle of tenant databases.
type QRDBManager = qrdb.Manager

// QRDBManagerOption configures a Manager at construction time.
type QRDBManagerOption = qrdb.ManagerOption

// QRDBNewManager creates a new database Manager.
var QRDBNewManager = qrdb.NewManager

// QRDBBackendFactory creates database backends.
type QRDBBackendFactory = qrdb.BackendFactory

// ==========================================================================
// Database service types (from types_service.go)
// ==========================================================================

// QRDBDatabaseServicer defines CRUD operations for database management.
type QRDBDatabaseServicer = qrdb.DatabaseServicer

// QRDBDatabaseServiceImpl is the concrete database service implementation.
type QRDBDatabaseServiceImpl = qrdb.DatabaseService

// QRDBDatabaseServiceOption configures optional DatabaseService behavior.
type QRDBDatabaseServiceOption = qrdb.DatabaseServiceOption

// QRDBNewDatabaseService creates a new DatabaseService backed by the given manager.
var QRDBNewDatabaseService = qrdb.NewDatabaseService

// ==========================================================================
// Vector storage types (from types_vector.go)
// ==========================================================================

// QRDBPebbleVectorStorage is a PebbleDB-backed vector storage engine.
type QRDBPebbleVectorStorage = qrdb.PebbleVectorStorage

// QRDBNewPebbleVectorStorage creates a new PebbleDB-backed vector storage.
var QRDBNewPebbleVectorStorage = qrdb.NewPebbleVectorStorage

// QRDBVectorStorageConfig configures PebbleDB vector storage.
type QRDBVectorStorageConfig = qrdb.VectorStorageConfig

// QRDBDefaultVectorStorageConfig returns a default configuration for vector storage.
var QRDBDefaultVectorStorageConfig = qrdb.DefaultVectorStorageConfig

// QRDBVectorValue holds a single vector with metadata.
type QRDBVectorValue = qrdb.VectorValue

// QRDBVectorNamespaceInfo holds metadata about a vector namespace.
type QRDBVectorNamespaceInfo = qrdb.VectorNamespaceInfo

// QRDBVectorScanOptions configures vector scan operations.
type QRDBVectorScanOptions = qrdb.VectorScanOptions

// QRDBVectorMetadataFilter describes a metadata filter for vector queries.
type QRDBVectorMetadataFilter = qrdb.VectorMetadataFilter

// QRDBVectorFilterOperator defines the comparison operator for metadata filters.
type QRDBVectorFilterOperator = qrdb.VectorFilterOperator

// QRDBVectorFilterOperator constants.
const (
	QRDBVectorFilterEqual    = qrdb.VectorFilterEqual
	QRDBVectorFilterNotEqual = qrdb.VectorFilterNotEqual
	QRDBVectorFilterIn       = qrdb.VectorFilterIn
	QRDBVectorFilterNotIn    = qrdb.VectorFilterNotIn
)

// ==========================================================================
// Time series types (from types_timeseries.go)
// ==========================================================================

// QRDBTimeSeriesStorage is a PebbleDB-backed time series storage engine.
type QRDBTimeSeriesStorage = qrdb.TimeSeriesStorage

// QRDBNewTimeSeriesStorageWithDir creates a new time series storage at the given directory.
var QRDBNewTimeSeriesStorageWithDir = qrdb.NewTimeSeriesStorageWithDir

// QRDBTimeSeriesDataPoint holds a single time series data point.
type QRDBTimeSeriesDataPoint = qrdb.TimeSeriesDataPoint

// QRDBTimeSeriesQueryRequest describes a time series query.
type QRDBTimeSeriesQueryRequest = qrdb.TimeSeriesQueryRequest

// QRDBTimeSeriesQueryResult holds the result of a time series query.
type QRDBTimeSeriesQueryResult = qrdb.TimeSeriesQueryResult

// QRDBTimeSeriesGroupedResult holds a grouped time series result.
type QRDBTimeSeriesGroupedResult = qrdb.TimeSeriesGroupedResult

// QRDBTimeSeriesDeleteRequest describes a time series deletion request.
type QRDBTimeSeriesDeleteRequest = qrdb.TimeSeriesDeleteRequest

// QRDBTimeSeriesRetentionPolicy configures data retention for a metric.
type QRDBTimeSeriesRetentionPolicy = qrdb.TimeSeriesRetentionPolicy

// QRDBTimeSeriesAggFunc identifies an aggregation function.
type QRDBTimeSeriesAggFunc = qrdb.TimeSeriesAggFunc
