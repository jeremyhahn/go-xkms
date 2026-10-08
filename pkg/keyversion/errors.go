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

package keyversion

import (
	"errors"
	"fmt"
)

var (
	// ErrNilDAOFactory is returned by NewStore without a DAO factory.
	ErrNilDAOFactory = errors.New("keyversion: a DAO factory is required")

	// ErrNilRecord is returned by Store.Put for a nil record.
	ErrNilRecord = errors.New("keyversion: record is nil")
)

// ReservedKeyIDError reports a key ID ending in the reserved version suffix
// "--v<digits>". Version n > 1 of key K is the backend key "K--v<n>", so a
// caller may never create a key under such a name.
type ReservedKeyIDError struct {
	KeyID string
}

// Error implements the error interface.
func (e *ReservedKeyIDError) Error() string {
	return fmt.Sprintf("keyversion: key ID %q ends in the reserved version suffix %q<digits>", e.KeyID, versionSeparator)
}

// InvalidVersionError reports a version number that cannot name a version:
// versions are numbered from 1.
type InvalidVersionError struct {
	Version uint32
}

// Error implements the error interface.
func (e *InvalidVersionError) Error() string {
	return fmt.Sprintf("keyversion: invalid key version %d (versions are numbered from 1)", e.Version)
}

// VersionNotFoundError reports a version the key's record does not hold.
type VersionNotFoundError struct {
	KeyID   string
	Version uint32
}

// Error implements the error interface.
func (e *VersionNotFoundError) Error() string {
	return fmt.Sprintf("keyversion: key %q has no version %d", e.KeyID, e.Version)
}

// VersionUnavailableError reports a version that exists but is not enabled,
// so it cannot be used for an operation. A retired version never can be
// again; a disabled one can once it is re-enabled.
type VersionUnavailableError struct {
	KeyID   string
	Version uint32
	State   State
}

// Error implements the error interface.
func (e *VersionUnavailableError) Error() string {
	return fmt.Sprintf("keyversion: version %d of key %q is %s", e.Version, e.KeyID, e.State)
}

// CurrentVersionError reports an attempt to disable or retire a key's
// current version. The current version is the one sign and encrypt use; a
// caller rotates first, which makes a new version current.
type CurrentVersionError struct {
	KeyID     string
	Version   uint32
	Operation string
}

// Error implements the error interface.
func (e *CurrentVersionError) Error() string {
	return fmt.Sprintf("keyversion: cannot %s version %d of key %q: it is the current version; rotate the key first", e.Operation, e.Version, e.KeyID)
}

// RetiredVersionError reports an attempt to change the state of a retired
// version. Retiring deletes the version's backend key, so it is final.
type RetiredVersionError struct {
	KeyID   string
	Version uint32
}

// Error implements the error interface.
func (e *RetiredVersionError) Error() string {
	return fmt.Sprintf("keyversion: version %d of key %q is retired; a retired version is gone for good", e.Version, e.KeyID)
}

// KeyVersionRequiredError reports a decryption whose ciphertext cannot be
// matched to a version safely: AES-CBC and RSA PKCS#1 v1.5 carry no
// integrity check a wrong key reliably fails, so with more than one enabled
// version the caller must name the version the encrypt response reported.
type KeyVersionRequiredError struct {
	KeyID string
	// Enabled lists the key's enabled versions, newest first.
	Enabled []uint32
}

// Error implements the error interface.
func (e *KeyVersionRequiredError) Error() string {
	return fmt.Sprintf("keyversion: key %q has %d enabled versions %v; this ciphertext (AES-CBC or RSA PKCS#1 v1.5) cannot be matched to a version safely, so key_version is required: pass the key_version the encrypt response returned", e.KeyID, len(e.Enabled), e.Enabled)
}

// StoreError wraps a failure of the record store.
type StoreError struct {
	Op  string
	Key string
	Err error
}

// Error implements the error interface.
func (e *StoreError) Error() string {
	return fmt.Sprintf("keyversion: %s %q: %v", e.Op, e.Key, e.Err)
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
	return fmt.Sprintf("keyversion: invalid %s %q for a version record", e.Field, e.Value)
}
