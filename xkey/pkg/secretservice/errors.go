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

// Package secretservice implements the org.freedesktop.secrets D-Bus API,
// exposing go-xkms password storage to applications like Firefox, Chrome,
// git-credential-libsecret, and other Secret Service consumers.
package secretservice

import (
	"errors"

	"github.com/godbus/dbus/v5"
)

// D-Bus error names from the org.freedesktop.Secret.Error interface. libsecret
// and secret-tool inspect these specific names -- not just the generic
// org.freedesktop.DBus.Error.Failed -- to decide whether to retry after a
// prompt (IsLocked) or report a hard miss (NoSuchObject), so mapping our
// sentinel errors onto them is required for real client interop, not cosmetic.
const (
	dbusErrIsLocked     = "org.freedesktop.Secret.Error.IsLocked"
	dbusErrNoSuchObject = "org.freedesktop.Secret.Error.NoSuchObject"
)

// dbusIsLockedError reports err as org.freedesktop.Secret.Error.IsLocked.
func dbusIsLockedError(err error) *dbus.Error {
	return dbus.NewError(dbusErrIsLocked, []any{err.Error()})
}

// dbusNoSuchObjectError reports err as org.freedesktop.Secret.Error.NoSuchObject.
func dbusNoSuchObjectError(err error) *dbus.Error {
	return dbus.NewError(dbusErrNoSuchObject, []any{err.Error()})
}

var (
	// ErrDBusUnavailable is returned when the D-Bus session bus cannot be reached.
	ErrDBusUnavailable = errors.New("secretservice: D-Bus session bus unavailable")

	// ErrServiceAlreadyRunning is returned when attempting to start an already running service.
	ErrServiceAlreadyRunning = errors.New("secretservice: service already running")

	// ErrServiceNotRunning is returned when attempting operations on a stopped service.
	ErrServiceNotRunning = errors.New("secretservice: service not running")

	// ErrSessionNotFound is returned when a session path does not exist.
	ErrSessionNotFound = errors.New("secretservice: session not found")

	// ErrCollectionNotFound is returned when a collection path does not exist.
	ErrCollectionNotFound = errors.New("secretservice: collection not found")

	// ErrItemNotFound is returned when an item path does not exist.
	ErrItemNotFound = errors.New("secretservice: item not found")

	// ErrCollectionLocked is returned when accessing a locked collection.
	ErrCollectionLocked = errors.New("secretservice: collection is locked")

	// ErrInvalidSession is returned when a session is invalid or expired.
	ErrInvalidSession = errors.New("secretservice: invalid session")

	// ErrInvalidAlgorithm is returned when an unsupported encryption algorithm is requested.
	ErrInvalidAlgorithm = errors.New("secretservice: unsupported algorithm")

	// ErrNilPasswordStore is returned when the password store is nil.
	ErrNilPasswordStore = errors.New("secretservice: password store is nil")

	// ErrDHKeyExchangeFailed is returned when Diffie-Hellman key exchange fails.
	ErrDHKeyExchangeFailed = errors.New("secretservice: DH key exchange failed")

	// ErrEncryptionFailed is returned when session encryption fails.
	ErrEncryptionFailed = errors.New("secretservice: encryption failed")

	// ErrDecryptionFailed is returned when session decryption fails.
	ErrDecryptionFailed = errors.New("secretservice: decryption failed")

	// ErrPromptDismissed is returned when a user dismisses a prompt.
	ErrPromptDismissed = errors.New("secretservice: prompt dismissed")

	// ErrNameConflict is returned when an item with the same attributes already exists.
	ErrNameConflict = errors.New("secretservice: item with same attributes exists")

	// ErrPromptNotFound is returned when a prompt path does not exist.
	ErrPromptNotFound = errors.New("secretservice: prompt not found")

	// ErrPromptAlreadyResolved is returned when Prompt or Dismiss is called
	// on a prompt that has already completed.
	ErrPromptAlreadyResolved = errors.New("secretservice: prompt already resolved")

	// ErrNilBarrier is returned when the barrier is nil.
	ErrNilBarrier = errors.New("secretservice: barrier is nil")

	// ErrSecretValueEmpty is returned when a secret's value is empty.
	ErrSecretValueEmpty = errors.New("secretservice: secret value is empty")

	// ErrLabelRequired is returned when CreateItem is called without a label.
	ErrLabelRequired = errors.New("secretservice: item label is required")

	// ErrAlgorithmNotFIPSApproved is returned when a client requests the
	// dh-ietf1024-sha256-aes128-cbc-pkcs7 session algorithm while this
	// process is running under FIPS 140 enforcement (crypto/fips140.Enabled).
	// Only the plain algorithm, safe because the Secret Service bus is a
	// local, kernel-mediated channel rather than a network one, is offered
	// in that mode.
	ErrAlgorithmNotFIPSApproved = errors.New("secretservice: dh-ietf1024-sha256-aes128-cbc-pkcs7 is not FIPS-approved; use the plain algorithm")

	// ErrInterfaceNotFound is returned by the Properties Get/GetAll/Set
	// methods when the requested D-Bus interface is not the one the object
	// implements.
	ErrInterfaceNotFound = errors.New("secretservice: unknown interface")

	// ErrPropertyNotFound is returned when the requested property name is
	// not defined on the object.
	ErrPropertyNotFound = errors.New("secretservice: unknown property")

	// ErrPropertyReadOnly is returned when Properties.Set targets a
	// property this daemon does not allow a client to change.
	ErrPropertyReadOnly = errors.New("secretservice: property is read-only")

	// ErrPropertyInvalidValue is returned when Properties.Set is given a
	// value whose D-Bus type does not match the property being set.
	ErrPropertyInvalidValue = errors.New("secretservice: property value has the wrong type")
)

// WrappedError wraps an underlying cause with a contextual message while
// preserving errors.Is / errors.As matching through Unwrap. It replaces
// inline formatted-error constructions that wrap another error.
type WrappedError struct {
	Msg string
	Err error
}

// Error implements the error interface.
func (e *WrappedError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}

// Unwrap returns the wrapped cause.
func (e *WrappedError) Unwrap() error {
	return e.Err
}
