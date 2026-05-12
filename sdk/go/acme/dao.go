// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package trustedca

// This file re-exports generic DAO types from go-qrdb/sdk/go for SDK consumers
// that implement storage backends (e.g., go-trusted-platform). By sourcing these
// types from the go-trusted-ca SDK rather than go-qrdb directly, Layer 5 callers
// avoid a direct dependency on the Layer 2 go-qrdb module.

import (
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// =============================================================================
// DAO Entity interface
// =============================================================================

// DAOEntity is the base interface for all DAO-managed entities.
// Any struct stored via GenericDAO must implement this interface.
type DAOEntity = qrdbsdk.Entity

// =============================================================================
// GenericDAO interface and supporting types
// =============================================================================

// GenericDAO provides typed CRUD operations over a KVStore for a given entity type.
type GenericDAO[E qrdbsdk.Entity] = qrdbsdk.GenericDAO[E]

// DAOPageQuery specifies pagination parameters for DAO list operations.
type DAOPageQuery = qrdbsdk.PageQuery

// DAOPageResult holds a page of entities returned by a DAO list operation.
type DAOPageResult[E any] = qrdbsdk.PageResult[E]

// DAOPagerFunc is a callback invoked for each page during DAO pagination.
type DAOPagerFunc[E any] = qrdbsdk.PagerFunc[E]

// DAOQueryBuilder provides a fluent query interface for DAO entities.
type DAOQueryBuilder[E qrdbsdk.Entity] = qrdbsdk.QueryBuilder[E]

// =============================================================================
// DAO Condition types
// =============================================================================

// DAOCondition represents a conditional check for DAO write operations.
type DAOCondition = qrdbsdk.Condition

// DAOConditionTarget specifies what property to check in a condition.
type DAOConditionTarget = qrdbsdk.ConditionTarget

// DAOConditionOp specifies the comparison operator for a condition.
type DAOConditionOp = qrdbsdk.ConditionOp

// DAOCondition target constants.
const (
	DAOConditionVersion = qrdbsdk.ConditionVersion
	DAOConditionCreate  = qrdbsdk.ConditionCreate
	DAOConditionMod     = qrdbsdk.ConditionMod
	DAOConditionValue   = qrdbsdk.ConditionValue
)

// DAOCondition operator constants.
const (
	DAOOpEqual        = qrdbsdk.OpEqual
	DAOOpNotEqual     = qrdbsdk.OpNotEqual
	DAOOpGreater      = qrdbsdk.OpGreater
	DAOOpLess         = qrdbsdk.OpLess
	DAOOpGreaterEqual = qrdbsdk.OpGreaterEqual
	DAOOpLessEqual    = qrdbsdk.OpLessEqual
)

// =============================================================================
// DAO error types
// =============================================================================

// DAONotFoundError is returned when a DAO entity lookup finds no result.
type DAONotFoundError = qrdbsdk.DAONotFoundError

// DAOSerializationFailedError is returned when entity serialization fails.
type DAOSerializationFailedError = qrdbsdk.DAOSerializationFailedError

// DAODeserializationFailedError is returned when entity deserialization fails.
type DAODeserializationFailedError = qrdbsdk.DAODeserializationFailedError

// DAOInvalidEntityIDError is returned when an entity ID is invalid.
type DAOInvalidEntityIDError = qrdbsdk.DAOInvalidEntityIDError

// DAOConditionFailedError is returned when a conditional write fails.
type DAOConditionFailedError = qrdbsdk.DAOConditionFailedError

// =============================================================================
// DAO sentinel errors and helper functions
// =============================================================================

// ErrDAOStopIteration is returned to signal early termination of page iteration.
var ErrDAOStopIteration = qrdbsdk.ErrDAOStopIteration

// IsDAONotFound reports whether the error indicates an entity was not found.
var IsDAONotFound = qrdbsdk.IsDAONotFound

// IsDAOConditionFailed reports whether the error is a ConditionFailedError.
var IsDAOConditionFailed = qrdbsdk.IsDAOConditionFailed
