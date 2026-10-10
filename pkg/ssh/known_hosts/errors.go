// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package known_hosts

// NilInputError is returned when a required argument is nil or zero.
// Field names the offending argument so callers can surface precise
// diagnostics.
type NilInputError struct {
	Field string
}

// Error implements the error interface.
func (e *NilInputError) Error() string {
	return "ssh/known_hosts: nil input: " + e.Field
}

// NoPublicKeyError is returned by Emit when a pin carries no PublicKey and
// therefore cannot be rendered as an OpenSSH known_hosts line.
type NoPublicKeyError struct {
	Host string
}

// Error implements the error interface.
func (e *NoPublicKeyError) Error() string {
	return "ssh/known_hosts: pin for host " + e.Host + " has no public key to emit"
}

// NotFoundError is returned by Get / Verify / Remove when no pin exists
// for the requested (scope, owner, host).
type NotFoundError struct {
	Scope string
	Owner string
	Host  string
}

// Error implements the error interface.
func (e *NotFoundError) Error() string {
	return "ssh/known_hosts: pin not found: " + e.Scope + "/" + e.Owner + "/" + e.Host
}

// DuplicateError is returned by Store.Add when a pin already exists for
// (scope, owner, host). Callers who intend to overwrite must Remove
// first — Add is deliberately non-idempotent so an accidental re-pin
// (often a symptom of a forgotten rotation) surfaces instead of being
// silently accepted.
type DuplicateError struct {
	Scope string
	Owner string
	Host  string
}

// Error implements the error interface.
func (e *DuplicateError) Error() string {
	return "ssh/known_hosts: pin already exists: " + e.Scope + "/" + e.Owner + "/" + e.Host
}

// MismatchError is returned by Verify when the server's public key
// fingerprint does not match the stored pin. Expected and Received are
// the two OpenSSH "SHA256:..." strings — both are safe to log because
// fingerprints are public material.
type MismatchError struct {
	Host     string
	Expected string
	Received string
}

// Error implements the error interface.
func (e *MismatchError) Error() string {
	return "ssh/known_hosts: host key mismatch for " + e.Host +
		": expected " + e.Expected + ", got " + e.Received
}

// RejectedError is returned by CallbackWithConfirm when a Confirmer declines
// to trust an unpinned host key (a Confirmer explicitly returning
// (false, nil)). Host is the bare hostname (post stripPort); Fingerprint is
// the OpenSSH "SHA256:..." form of the declined key — both are safe to log.
type RejectedError struct {
	Host        string
	Fingerprint string
}

// Error implements the error interface.
func (e *RejectedError) Error() string {
	return "ssh/known_hosts: host key rejected for " + e.Host + ": " + e.Fingerprint
}

// InvalidHostError is returned when a host string cannot be used as a
// storage path component (empty, contains a path separator, or contains
// a NUL byte). Reason documents which rule failed.
type InvalidHostError struct {
	Value  string
	Reason string
}

// Error implements the error interface.
func (e *InvalidHostError) Error() string {
	return "ssh/known_hosts: invalid host: " + e.Reason
}

// PublicKeyRequiredError is returned by Store.Add when pin carries no
// PublicKey. Every new pin must carry the full SSH wire-format host key —
// fingerprint-only pins can no longer be created.
type PublicKeyRequiredError struct {
	Host string
}

// Error implements the error interface.
func (e *PublicKeyRequiredError) Error() string {
	return "ssh/known_hosts: pin for host " + e.Host + " requires a public key"
}

// InvalidFingerprintError is returned when a fingerprint string does not
// match the OpenSSH "SHA256:<base64>" form. Callers that receive an
// ssh.PublicKey and compute the fingerprint via keys.Fingerprint never
// trigger this — it exists for API inputs that accept a raw string.
type InvalidFingerprintError struct {
	Value  string
	Reason string
}

// Error implements the error interface.
func (e *InvalidFingerprintError) Error() string {
	return "ssh/known_hosts: invalid fingerprint: " + e.Reason
}

// StorageError wraps an underlying storage-backend failure.
type StorageError struct {
	Op  string
	Err error
}

// Error implements the error interface.
func (e *StorageError) Error() string {
	return "ssh/known_hosts: storage " + e.Op + ": " + e.Err.Error()
}

// Unwrap returns the underlying storage error.
func (e *StorageError) Unwrap() error { return e.Err }

// SerializationError is returned by Emit when a pin's PublicKey is not a
// valid SSH wire-format key.
type SerializationError struct {
	Op  string
	Err error
}

// Error implements the error interface.
func (e *SerializationError) Error() string {
	return "ssh/known_hosts: serialize " + e.Op + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *SerializationError) Unwrap() error { return e.Err }
