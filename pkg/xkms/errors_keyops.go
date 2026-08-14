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

package xkms

import (
	"errors"
	"fmt"
)

// Sentinel errors for the hardware-capability key operations implemented by the
// service layer: key attestation, ECDH key agreement, raw key-material export,
// and wrap/unwrap by key ID. Transports map these sentinels onto their own
// status vocabulary (gRPC codes, HTTP statuses) without re-deriving the
// business logic that produced them.
var (
	// ErrMissingRequiredField indicates a required request field was empty.
	// The enclosing ErrValidation carries the field name in its Detail so
	// transports can surface the exact field to the caller.
	ErrMissingRequiredField = errors.New("keystore: missing required field")

	// ErrExportKeyMaterialFailed indicates the backend refused to release raw
	// key material. This is a precondition failure rather than an internal
	// fault: the key is not marked exportable, is asymmetric, or backend
	// policy forbids extraction.
	ErrExportKeyMaterialFailed = errors.New("keystore: export key material failed")

	// ErrKeySensitive indicates the key's record marks it sensitive, so its
	// plaintext is never released through the API. It mirrors PKCS#11
	// CKA_SENSITIVE and is distinct from a key that is merely not exportable:
	// a sensitive key may still be wrapped out under another key.
	ErrKeySensitive = errors.New("keystore: key is sensitive and cannot be revealed")

	// ErrAttestationFailed indicates the backend produced no usable
	// attestation statement for the requested key.
	ErrAttestationFailed = errors.New("keystore: attestation failed")

	// ErrKeyAgreementFailed indicates ECDH key agreement or the subsequent key
	// derivation failed inside the backend.
	ErrKeyAgreementFailed = errors.New("keystore: ECDH key derivation failed")
)

// ErrRoleLookup reports that a named participant of a multi-key or
// multi-backend operation could not be resolved. Role names the participant and
// what was being looked up ("target key backend", "unwrapping key"), Name is
// the identifier that failed to resolve, and Err is the underlying lookup error
// whose sentinel (ErrBackendNotFound, ErrKeyNotFound) stays reachable through
// errors.Is.
type ErrRoleLookup struct {
	Role string
	Name string
	Err  error
}

// Error returns the error message.
func (e *ErrRoleLookup) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s not found: %s: %v", e.Role, e.Name, e.Err)
	}
	return fmt.Sprintf("%s not found: %s", e.Role, e.Name)
}

// Unwrap returns the underlying lookup error.
func (e *ErrRoleLookup) Unwrap() error { return e.Err }

// requiredField builds the validation error returned when a required request
// field is empty. Field is the wire-level field name (snake_case) so every
// transport reports the same identifier the caller sent.
func requiredField(field string) error {
	return &ErrValidation{Sentinel: ErrMissingRequiredField, Detail: field + " is required"}
}

// roleLookupError qualifies a backend or key resolution failure with the role
// the resolved object plays in the operation. Request-validation failures (an
// invalid tenant ID, for example) are returned unchanged so they keep their own
// semantics instead of being reported as a missing object.
func roleLookupError(role, name string, err error) error {
	var validation *ErrValidation
	if errors.As(err, &validation) {
		return err
	}
	return &ErrRoleLookup{Role: role, Name: name, Err: err}
}
