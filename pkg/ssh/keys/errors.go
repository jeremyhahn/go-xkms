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

package keys

import "strconv"

// BackendKeyIDTooLongError is returned by backendKeyID when the encoded CN
// for a backend-backed SSH key would exceed Max bytes. It is refused rather
// than truncated: a truncated CN could collide with another key's, and
// truncation silently narrows the identity the caller asked to address.
type BackendKeyIDTooLongError struct {
	Length int
	Max    int
}

// Error implements the error interface.
func (e *BackendKeyIDTooLongError) Error() string {
	return "ssh/keys: backend key id too long: " + strconv.Itoa(e.Length) +
		" bytes exceeds max " + strconv.Itoa(e.Max)
}

// NilInputError is returned when a required argument is nil or zero.
// Field names the offending argument so callers can surface precise
// diagnostics.
type NilInputError struct {
	Field string
}

// Error implements the error interface.
func (e *NilInputError) Error() string {
	return "ssh/keys: nil input: " + e.Field
}

// UnsupportedAlgorithmError is returned when Generate is asked for a
// key algorithm the package does not implement.
type UnsupportedAlgorithmError struct {
	Algorithm string
}

// Error implements the error interface.
func (e *UnsupportedAlgorithmError) Error() string {
	return "ssh/keys: unsupported algorithm: " + e.Algorithm
}

// SignatureAlgorithmError is returned by SignWithAlgorithm when the
// requested signature algorithm is not one the signing key's type allows:
// ssh-rsa, rsa-sha2-256 or rsa-sha2-512 for RSA (RFC 8332 §3), and the key's
// own type for every other key.
type SignatureAlgorithmError struct {
	Algorithm string
	KeyType   string
}

// Error implements the error interface.
func (e *SignatureAlgorithmError) Error() string {
	return "ssh/keys: signature algorithm " + e.Algorithm + " not allowed for key type " + e.KeyType
}

// AlgorithmSignerError is returned by SignWithAlgorithm when a signature
// algorithm is requested but the key's signer cannot select one (it is not
// an ssh.AlgorithmSigner).
type AlgorithmSignerError struct {
	KeyType string
}

// Error implements the error interface.
func (e *AlgorithmSignerError) Error() string {
	return "ssh/keys: signer for key type " + e.KeyType + " cannot select a signature algorithm"
}

// InvalidKeySizeError is returned when a key-generation request
// specifies a size that is not valid for the chosen algorithm (e.g.,
// RSA outside [types.RSAKeySize2048, types.RSAKeySize4096]).
type InvalidKeySizeError struct {
	Algorithm string
	Size      int
}

// Error implements the error interface.
func (e *InvalidKeySizeError) Error() string {
	return "ssh/keys: invalid key size for " + e.Algorithm
}

// PassphraseRequiredError is returned by ParsePEM when the PEM is
// encrypted but no PassphraseProvider was supplied.
type PassphraseRequiredError struct{}

// Error implements the error interface.
func (e *PassphraseRequiredError) Error() string {
	return "ssh/keys: passphrase required but no provider supplied"
}

// PEMParseError wraps an underlying x/crypto/ssh parse failure.
type PEMParseError struct {
	Err error
}

// Error implements the error interface.
func (e *PEMParseError) Error() string {
	return "ssh/keys: failed to parse PEM: " + e.Err.Error()
}

// Unwrap returns the underlying ssh parse error so callers can inspect
// the specific x/crypto/ssh error type if they need to.
func (e *PEMParseError) Unwrap() error { return e.Err }

// KeyMaterialError wraps an unexpected failure to serialize or read key
// material. It signals an internal inconsistency — callers generally
// treat it as a fatal programming error.
type KeyMaterialError struct {
	Op  string
	Err error
}

// Error implements the error interface.
func (e *KeyMaterialError) Error() string {
	return "ssh/keys: " + e.Op + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *KeyMaterialError) Unwrap() error { return e.Err }

// KeyNotFoundError is returned by Store implementations when the
// requested key ID does not exist.
type KeyNotFoundError struct {
	ID string
}

// Error implements the error interface.
func (e *KeyNotFoundError) Error() string {
	return "ssh/keys: key not found: " + e.ID
}

// OwnerConflictError is returned by Put when a tenant-scoped key of the
// requested name is already held by another owner. A tenant-scoped storage
// path carries no owner, so overwriting would silently hand the record to
// the new owner. ID is the requested "<scope>/<owner>/<name>"; the holder is
// deliberately not named.
type OwnerConflictError struct {
	ID string
}

// Error implements the error interface.
func (e *OwnerConflictError) Error() string {
	return "ssh/keys: key held by another owner: " + e.ID
}

// StorageError wraps an underlying storage-backend failure.
type StorageError struct {
	Op  string
	Err error
}

// Error implements the error interface.
func (e *StorageError) Error() string {
	return "ssh/keys: storage " + e.Op + ": " + e.Err.Error()
}

// Unwrap returns the underlying storage error.
func (e *StorageError) Unwrap() error { return e.Err }

// ClosedSignerError is returned by Sign on a persistentSigner whose
// closer has already run. Callers MUST NOT reuse a signer after closing
// it; the returned error signals a programming mistake.
type ClosedSignerError struct{}

// Error implements the error interface.
func (e *ClosedSignerError) Error() string {
	return "ssh/keys: signer closed"
}
