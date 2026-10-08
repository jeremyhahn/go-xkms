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

package preseal

import "errors"

var (
	// ErrTPMRequired is returned when a Store is built without a TPM.
	ErrTPMRequired = errors.New("preseal: a TPM is required")

	// ErrRecordsRequired is returned when a Store is built without record
	// storage.
	ErrRecordsRequired = errors.New("preseal: record storage is required")

	// ErrDirRequired is returned when Open is given no directory.
	ErrDirRequired = errors.New("preseal: a record directory is required")
)

// OpenError is returned when the record storage cannot be opened or
// wrapped.
type OpenError struct {
	// Dir is the record directory, when one was given.
	Dir string
	// Err is the underlying error.
	Err error
}

// Error implements the error interface.
func (e *OpenError) Error() string {
	msg := "preseal: open store"
	if e.Dir != "" {
		msg += " at " + e.Dir
	}
	return msg + ": " + e.Err.Error()
}

// Unwrap exposes Err.
func (e *OpenError) Unwrap() error { return e.Err }

// PlatformSRKError is returned when the TPM's Platform SRK is not enrolled.
// go-xkms seals only under the Platform SRK, never the Shared SRK, so there
// is no other parent to fall back to.
type PlatformSRKError struct {
	// Err is the TPM's error.
	Err error
}

// Error implements the error interface.
func (e *PlatformSRKError) Error() string {
	return "preseal: the Platform SRK is not enrolled: " + e.Err.Error()
}

// Unwrap exposes Err.
func (e *PlatformSRKError) Unwrap() error { return e.Err }

// EmptySecretError is returned when Put is given an empty secret.
type EmptySecretError struct {
	// Name is the secret's name.
	Name string
}

// Error implements the error interface.
func (e *EmptySecretError) Error() string {
	return "preseal: secret " + e.Name + " is empty"
}

// SealError is returned when a secret cannot be sealed or stored.
type SealError struct {
	// Name is the secret's name.
	Name string
	// Err is the underlying error.
	Err error
}

// Error implements the error interface.
func (e *SealError) Error() string {
	return "preseal: seal " + e.Name + ": " + e.Err.Error()
}

// Unwrap exposes Err.
func (e *SealError) Unwrap() error { return e.Err }

// NotFoundError is returned when no secret is stored under a name.
type NotFoundError struct {
	// Name is the secret's name.
	Name string
}

// Error implements the error interface.
func (e *NotFoundError) Error() string {
	return "preseal: no secret is sealed under " + e.Name
}

// RefusedError is returned when the TPM refuses to release a secret: the
// platform PCRs no longer match the state it was sealed under, or the
// record was sealed by another TPM.
type RefusedError struct {
	// Name is the secret's name.
	Name string
	// Err is the TPM's refusal.
	Err error
}

// Error implements the error interface.
func (e *RefusedError) Error() string {
	return "preseal: the TPM refused to release " + e.Name + ": " + e.Err.Error()
}

// Unwrap exposes Err.
func (e *RefusedError) Unwrap() error { return e.Err }

// UnsealError is returned when a secret cannot be read for any reason other
// than its absence or a TPM refusal.
type UnsealError struct {
	// Name is the secret's name.
	Name string
	// Err is the underlying error.
	Err error
}

// Error implements the error interface.
func (e *UnsealError) Error() string {
	return "preseal: unseal " + e.Name + ": " + e.Err.Error()
}

// Unwrap exposes Err.
func (e *UnsealError) Unwrap() error { return e.Err }
