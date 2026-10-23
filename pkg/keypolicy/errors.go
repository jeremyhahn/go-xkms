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

package keypolicy

import (
	"errors"
	"fmt"
)

var (
	// ErrNilDAOFactory is returned by NewStore without a DAO factory.
	ErrNilDAOFactory = errors.New("keypolicy: a DAO factory is required")

	// ErrNilRecord is returned by Store.Put for a nil record.
	ErrNilRecord = errors.New("keypolicy: record is nil")
)

// KeyUnavailableError reports a key whose record is disabled or revoked, so
// it is refused for every operation.
type KeyUnavailableError struct {
	KeyID  string
	Status Status
}

// Error implements the error interface.
func (e *KeyUnavailableError) Error() string {
	return fmt.Sprintf("keypolicy: key %q is %s", e.KeyID, e.Status)
}

// PolicyDeniedError reports an operation the key's policy refuses.
type PolicyDeniedError struct {
	KeyID     string
	Operation Operation
	Reason    string
}

// Error implements the error interface.
func (e *PolicyDeniedError) Error() string {
	return fmt.Sprintf("keypolicy: policy of key %q refuses %s: %s", e.KeyID, e.Operation, e.Reason)
}

// SafetyLimitError reports an authenticated encryption the key's AEAD usage
// limits refuse: the key has used up its operations or bytes and must be
// rotated (NIST SP 800-38D §8.3).
type SafetyLimitError struct {
	KeyID string
	// Limit is "operations" or "bytes".
	Limit string
}

// Error implements the error interface.
func (e *SafetyLimitError) Error() string {
	return fmt.Sprintf("keypolicy: key %q has reached its AEAD %s limit; rotate the key", e.KeyID, e.Limit)
}

// StoreError wraps a failure of the record store.
type StoreError struct {
	Op  string
	Key string
	Err error
}

// Error implements the error interface.
func (e *StoreError) Error() string {
	return fmt.Sprintf("keypolicy: %s %q: %v", e.Op, e.Key, e.Err)
}

// Unwrap returns the underlying cause.
func (e *StoreError) Unwrap() error { return e.Err }

// InvalidRecordKeyError reports a tenant, backend or key ID that cannot be a
// single segment of a record's name.
type InvalidRecordKeyError struct {
	Field string
	Value string
}

// Error implements the error interface.
func (e *InvalidRecordKeyError) Error() string {
	return fmt.Sprintf("keypolicy: invalid %s %q for a key policy record", e.Field, e.Value)
}
