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

package backend

import "fmt"

// NilInputError indicates a required constructor/argument was nil or empty.
type NilInputError struct {
	Field string
}

func (e *NilInputError) Error() string {
	return fmt.Sprintf("ssh/backend: nil or empty %s", e.Field)
}

// BackendNotFoundError indicates the resolver returned no KeyProvider for the
// requested backend ID.
type BackendNotFoundError struct {
	BackendID string
}

func (e *BackendNotFoundError) Error() string {
	return fmt.Sprintf("ssh/backend: no key provider for backend %q", e.BackendID)
}

// UnsupportedAlgorithmError indicates an SSH algorithm with no xkms mapping.
type UnsupportedAlgorithmError struct {
	Algorithm string
}

func (e *UnsupportedAlgorithmError) Error() string {
	return fmt.Sprintf("ssh/backend: unsupported algorithm %q", e.Algorithm)
}

// GenerateError wraps a backend key-generation failure.
type GenerateError struct {
	BackendID string
	KeyID     string
	Err       error
}

func (e *GenerateError) Error() string {
	return fmt.Sprintf("ssh/backend: generate key %q on %q: %v", e.KeyID, e.BackendID, e.Err)
}

func (e *GenerateError) Unwrap() error { return e.Err }

// SignerError wraps a backend signer-resolution failure.
type SignerError struct {
	BackendID string
	KeyID     string
	Err       error
}

func (e *SignerError) Error() string {
	return fmt.Sprintf("ssh/backend: resolve signer %q on %q: %v", e.KeyID, e.BackendID, e.Err)
}

func (e *SignerError) Unwrap() error { return e.Err }

// DeleteError wraps a backend key-deletion failure.
type DeleteError struct {
	BackendID string
	KeyID     string
	Err       error
}

func (e *DeleteError) Error() string {
	return fmt.Sprintf("ssh/backend: delete key %q on %q: %v", e.KeyID, e.BackendID, e.Err)
}

func (e *DeleteError) Unwrap() error { return e.Err }
