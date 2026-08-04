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

package trustedca

import (
	"github.com/jeremyhahn/go-xkms/pkg/acme/qrdb"
)

// =============================================================================
// QRDB Interfaces
// =============================================================================

// CAQRDBService defines the interface for QRDB integration within go-xkms.
// It provides typed accessors for all QRDB subsystems including key-value
// storage, cluster administration, watches, leases, batch operations,
// transactions, and secondary indexes.
type CAQRDBService = qrdb.Service

// =============================================================================
// QRDB Configuration Types
// =============================================================================

// CAQRDBConfig holds the QRDB service configuration including mode,
// protocol, address, and cluster settings.
type CAQRDBConfig = qrdb.Config

// CAQRDBRaftConfig holds Raft consensus configuration for distributed
// replication mode.
type CAQRDBRaftConfig = qrdb.RaftConfig

// CAQRDBTLSClientConfig holds TLS configuration for QRDB client connections.
type CAQRDBTLSClientConfig = qrdb.TLSClientConfig

// CAQRDBShutdownConfig holds graceful shutdown configuration for the
// QRDB service.
type CAQRDBShutdownConfig = qrdb.ShutdownConfig

// =============================================================================
// QRDB Protocol and Mode Types
// =============================================================================

// CAQRDBProtocol identifies the transport protocol used to connect to QRDB.
type CAQRDBProtocol = qrdb.Protocol

// CAQRDBMode identifies the QRDB operating mode (standalone or raft).
type CAQRDBMode = qrdb.Mode

// =============================================================================
// QRDB Protocol Constants
// =============================================================================

const (
	// CAQRDBProtocolEmbedded runs QRDB in-process via the embedded transport.
	CAQRDBProtocolEmbedded = qrdb.ProtocolEmbedded

	// CAQRDBProtocolGRPC connects to QRDB via gRPC.
	CAQRDBProtocolGRPC = qrdb.ProtocolGRPC

	// CAQRDBProtocolREST connects to QRDB via HTTP/2 REST.
	CAQRDBProtocolREST = qrdb.ProtocolREST

	// CAQRDBProtocolQUIC connects to QRDB via QUIC.
	CAQRDBProtocolQUIC = qrdb.ProtocolQUIC

	// CAQRDBProtocolUnix connects to QRDB via a Unix domain socket.
	CAQRDBProtocolUnix = qrdb.ProtocolUnix

	// CAQRDBProtocolMCP connects to QRDB via the MCP protocol.
	CAQRDBProtocolMCP = qrdb.ProtocolMCP
)

// =============================================================================
// QRDB Mode Constants
// =============================================================================

const (
	// CAQRDBModeStandalone runs a single QRDB node without Raft consensus.
	CAQRDBModeStandalone = qrdb.ModeStandalone

	// CAQRDBModeRaft runs QRDB with Raft consensus for distributed replication.
	CAQRDBModeRaft = qrdb.ModeRaft
)

// =============================================================================
// QRDB Error Types
// =============================================================================

// CAQRDBError is a typed error for QRDB operations carrying an error code,
// message, optional cause, and key-value context for debugging.
type CAQRDBError = qrdb.Error

// CAQRDBErrorCode identifies the category of a QRDB error.
type CAQRDBErrorCode = qrdb.ErrorCode

// =============================================================================
// QRDB Error Code Constants
// =============================================================================

const (
	// CAQRDBErrorCodeInvalidConfig indicates invalid configuration.
	CAQRDBErrorCodeInvalidConfig = qrdb.ErrorCodeInvalidConfig

	// CAQRDBErrorCodeConnection indicates a connection failure.
	CAQRDBErrorCodeConnection = qrdb.ErrorCodeConnection

	// CAQRDBErrorCodeNotFound indicates the requested resource was not found.
	CAQRDBErrorCodeNotFound = qrdb.ErrorCodeNotFound

	// CAQRDBErrorCodeAlreadyExists indicates the resource already exists.
	CAQRDBErrorCodeAlreadyExists = qrdb.ErrorCodeAlreadyExists

	// CAQRDBErrorCodeInvalidInput indicates invalid input parameters.
	CAQRDBErrorCodeInvalidInput = qrdb.ErrorCodeInvalidInput

	// CAQRDBErrorCodeInternal indicates an internal error.
	CAQRDBErrorCodeInternal = qrdb.ErrorCodeInternal

	// CAQRDBErrorCodeSealed indicates the service is sealed.
	CAQRDBErrorCodeSealed = qrdb.ErrorCodeSealed

	// CAQRDBErrorCodeNotInitialized indicates the service is not initialized.
	CAQRDBErrorCodeNotInitialized = qrdb.ErrorCodeNotInitialized

	// CAQRDBErrorCodePermissionDenied indicates insufficient permissions.
	CAQRDBErrorCodePermissionDenied = qrdb.ErrorCodePermissionDenied

	// CAQRDBErrorCodeSerialization indicates a serialization failure.
	CAQRDBErrorCodeSerialization = qrdb.ErrorCodeSerialization

	// CAQRDBErrorCodeShutdown indicates the service has shut down.
	CAQRDBErrorCodeShutdown = qrdb.ErrorCodeShutdown

	// CAQRDBErrorCodeShutdownInProgress indicates a shutdown is in progress.
	CAQRDBErrorCodeShutdownInProgress = qrdb.ErrorCodeShutdownInProgress

	// CAQRDBErrorCodeNoLeader indicates no Raft leader is available.
	CAQRDBErrorCodeNoLeader = qrdb.ErrorCodeNoLeader

	// CAQRDBErrorCodeNotLeader indicates the node is not the Raft leader.
	CAQRDBErrorCodeNotLeader = qrdb.ErrorCodeNotLeader
)

// =============================================================================
// QRDB Option Type
// =============================================================================

// CAQRDBServiceOption configures the QRDB service using the functional
// options pattern.
type CAQRDBServiceOption = qrdb.ServiceOption

// =============================================================================
// QRDB Constructor Functions
// =============================================================================

// NewCAQRDBService creates a new QRDB service instance using functional options.
var NewCAQRDBService = qrdb.New

// CAQRDBWithConfig sets the QRDB configuration option.
var CAQRDBWithConfig = qrdb.WithConfig

// CAQRDBWithClient sets a pre-configured QRDB SDK client option.
var CAQRDBWithClient = qrdb.WithQRDBClient

// CAQRDBWithKVStore sets the KVStore for embedded mode DAO access.
var CAQRDBWithKVStore = qrdb.WithKVStore

// CAQRDBDefaultConfig returns a Config with sensible defaults for embedded
// standalone mode.
var CAQRDBDefaultConfig = qrdb.DefaultConfig

// =============================================================================
// QRDB Error Constructor and Helper Functions
// =============================================================================

// NewCAQRDBError creates a new QRDB error with the given code and message.
var NewCAQRDBError = qrdb.NewError

// CAQRDBIsNotFound reports whether err is a NotFound error.
var CAQRDBIsNotFound = qrdb.IsNotFound

// CAQRDBIsAlreadyExists reports whether err is an AlreadyExists error.
var CAQRDBIsAlreadyExists = qrdb.IsAlreadyExists

// CAQRDBIsInvalidConfig reports whether err is an InvalidConfig error.
var CAQRDBIsInvalidConfig = qrdb.IsInvalidConfig

// CAQRDBIsConnection reports whether err is a Connection error.
var CAQRDBIsConnection = qrdb.IsConnection

// CAQRDBIsInvalidInput reports whether err is an InvalidInput error.
var CAQRDBIsInvalidInput = qrdb.IsInvalidInput

// CAQRDBIsInternal reports whether err is an Internal error.
var CAQRDBIsInternal = qrdb.IsInternal

// CAQRDBIsSealed reports whether err is a Sealed error.
var CAQRDBIsSealed = qrdb.IsSealed

// CAQRDBIsNotInitialized reports whether err is a NotInitialized error.
var CAQRDBIsNotInitialized = qrdb.IsNotInitialized

// CAQRDBIsPermissionDenied reports whether err is a PermissionDenied error.
var CAQRDBIsPermissionDenied = qrdb.IsPermissionDenied

// CAQRDBIsSerialization reports whether err is a Serialization error.
var CAQRDBIsSerialization = qrdb.IsSerialization

// CAQRDBIsShutdown reports whether err is a Shutdown error.
var CAQRDBIsShutdown = qrdb.IsShutdown

// CAQRDBIsShutdownInProgress reports whether err is a ShutdownInProgress error.
var CAQRDBIsShutdownInProgress = qrdb.IsShutdownInProgress

// CAQRDBIsNoLeader reports whether err is a NoLeader error.
var CAQRDBIsNoLeader = qrdb.IsNoLeader

// CAQRDBIsNotLeader reports whether err is a NotLeader error.
var CAQRDBIsNotLeader = qrdb.IsNotLeader
