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

package validation

import (
	"fmt"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// Constraint enumerates the specific validation rule that was violated.
// It aliases the shared stack-wide constraint vocabulary exported by the
// qrdb SDK so all layers report validation failures uniformly.
type Constraint = qrdbsdk.ValidationConstraint

// Constraint values re-exported from the shared qrdb SDK validation
// framework. The names and messages are identical to the pre-unification
// local definitions, so error strings are unchanged.
const (
	// ConstraintEmpty indicates the value was empty.
	ConstraintEmpty = qrdbsdk.ValidationConstraintEmpty
	// ConstraintNullByte indicates the value contains a null byte.
	ConstraintNullByte = qrdbsdk.ValidationConstraintNullByte
	// ConstraintTooLong indicates the value exceeds the maximum length.
	ConstraintTooLong = qrdbsdk.ValidationConstraintTooLong
	// ConstraintAbsolutePath indicates the value is an absolute filesystem path.
	ConstraintAbsolutePath = qrdbsdk.ValidationConstraintAbsolutePath
	// ConstraintPathTraversal indicates the value contains a path traversal sequence.
	ConstraintPathTraversal = qrdbsdk.ValidationConstraintPathTraversal
	// ConstraintControlChars indicates the value contains control characters.
	ConstraintControlChars = qrdbsdk.ValidationConstraintControlChars
	// ConstraintInvalidChars indicates the value contains disallowed characters.
	ConstraintInvalidChars = qrdbsdk.ValidationConstraintInvalidChars
	// ConstraintInvalidFormat indicates the value does not match the required format.
	ConstraintInvalidFormat = qrdbsdk.ValidationConstraintInvalidFormat
	// ConstraintInvalidKeyType indicates the key type is not recognized.
	ConstraintInvalidKeyType = qrdbsdk.ValidationConstraintInvalidKeyType
	// ConstraintInvalidAlgorithm indicates the algorithm is not recognized.
	ConstraintInvalidAlgorithm = qrdbsdk.ValidationConstraintInvalidAlgorithm
)

// ErrValidation is the base validation error carrying the field name and
// violated constraint. It aliases the shared qrdb SDK ValidationError, whose
// promoted As method lets errors.As with a **ErrValidation target match any
// domain error type that embeds it.
type ErrValidation = qrdbsdk.ValidationError

// ErrKeyID is returned when a key identifier fails validation.
type ErrKeyID struct {
	ErrValidation
}

// ErrKeyReference is returned when a 4-part key reference fails validation.
// It may wrap an underlying error from component validation.
type ErrKeyReference struct {
	ErrValidation
	// Component is the specific part of the reference that failed (e.g. "backend", "keyname").
	// Empty when the error applies to the entire reference.
	Component string
	// Cause is the underlying validation error from a component, if any.
	Cause error
}

// Error returns a human-readable error message with component context.
func (e *ErrKeyReference) Error() string {
	if e.Component != "" && e.Cause != nil {
		return fmt.Sprintf("invalid %s in key reference: %s", e.Component, e.Cause)
	}
	if e.Component != "" {
		base := fmt.Sprintf("invalid %s in key reference", e.Component)
		if e.Detail != "" {
			return fmt.Sprintf("%s: %s", base, e.Detail)
		}
		return base
	}
	return e.ErrValidation.Error()
}

// Unwrap returns the underlying cause, supporting errors.Is and errors.As.
func (e *ErrKeyReference) Unwrap() error {
	return e.Cause
}

// ErrBackendName is returned when a backend name fails validation.
type ErrBackendName struct {
	ErrValidation
}

// newErrKeyID creates an ErrKeyID for the given constraint with optional detail.
func newErrKeyID(constraint Constraint, detail string) *ErrKeyID {
	return &ErrKeyID{
		ErrValidation: ErrValidation{
			Field:      "key ID",
			Constraint: constraint,
			Detail:     detail,
		},
	}
}

// newErrBackendName creates an ErrBackendName for the given constraint with optional detail.
func newErrBackendName(constraint Constraint, detail string) *ErrBackendName {
	return &ErrBackendName{
		ErrValidation: ErrValidation{
			Field:      "backend name",
			Constraint: constraint,
			Detail:     detail,
		},
	}
}

// newErrKeyReference creates an ErrKeyReference for the given constraint with optional detail.
func newErrKeyReference(constraint Constraint, detail string) *ErrKeyReference {
	return &ErrKeyReference{
		ErrValidation: ErrValidation{
			Field:      "key reference",
			Constraint: constraint,
			Detail:     detail,
		},
	}
}

// newErrKeyReferenceComponent creates an ErrKeyReference for a specific component failure.
func newErrKeyReferenceComponent(component string, cause error) *ErrKeyReference {
	return &ErrKeyReference{
		ErrValidation: ErrValidation{
			Field: "key reference",
		},
		Component: component,
		Cause:     cause,
	}
}

// newErrKeyReferenceComponentDetail creates an ErrKeyReference for a component with detail but no cause.
func newErrKeyReferenceComponentDetail(component string, constraint Constraint, detail string) *ErrKeyReference {
	return &ErrKeyReference{
		ErrValidation: ErrValidation{
			Field:      "key reference",
			Constraint: constraint,
			Detail:     detail,
		},
		Component: component,
	}
}
