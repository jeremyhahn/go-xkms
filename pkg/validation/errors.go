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

import "fmt"

// Constraint enumerates the specific validation rule that was violated.
type Constraint int

const (
	// ConstraintEmpty indicates the value was empty.
	ConstraintEmpty Constraint = iota
	// ConstraintNullByte indicates the value contains a null byte.
	ConstraintNullByte
	// ConstraintTooLong indicates the value exceeds the maximum length.
	ConstraintTooLong
	// ConstraintAbsolutePath indicates the value is an absolute filesystem path.
	ConstraintAbsolutePath
	// ConstraintPathTraversal indicates the value contains a path traversal sequence.
	ConstraintPathTraversal
	// ConstraintControlChars indicates the value contains control characters.
	ConstraintControlChars
	// ConstraintInvalidChars indicates the value contains disallowed characters.
	ConstraintInvalidChars
	// ConstraintInvalidFormat indicates the value does not match the required format.
	ConstraintInvalidFormat
	// ConstraintInvalidKeyType indicates the key type is not recognized.
	ConstraintInvalidKeyType
	// ConstraintInvalidAlgorithm indicates the algorithm is not recognized.
	ConstraintInvalidAlgorithm
)

// constraintMessages maps each constraint to a human-readable explanation.
var constraintMessages = map[Constraint]string{
	ConstraintEmpty:            "cannot be empty",
	ConstraintNullByte:         "contains null byte",
	ConstraintTooLong:          "exceeds maximum length",
	ConstraintAbsolutePath:     "cannot be an absolute path",
	ConstraintPathTraversal:    "contains path traversal attempt",
	ConstraintControlChars:     "contains control characters",
	ConstraintInvalidChars:     "contains invalid characters",
	ConstraintInvalidFormat:    "invalid format",
	ConstraintInvalidKeyType:   "invalid key type",
	ConstraintInvalidAlgorithm: "invalid algorithm",
}

// String returns the human-readable name for a Constraint.
func (c Constraint) String() string {
	if msg, ok := constraintMessages[c]; ok {
		return msg
	}
	return "unknown constraint"
}

// ErrValidation is the base validation error carrying the field name and violated constraint.
type ErrValidation struct {
	// Field is the name of the field that failed validation (e.g. "key ID", "backend name").
	Field string
	// Constraint is the specific rule that was violated.
	Constraint Constraint
	// Detail provides additional context (e.g. max length, allowed characters).
	Detail string
}

// Error returns a human-readable error message.
func (e *ErrValidation) Error() string {
	base := fmt.Sprintf("%s %s", e.Field, e.Constraint)
	if e.Detail != "" {
		return fmt.Sprintf("%s: %s", base, e.Detail)
	}
	return base
}

// ErrKeyID is returned when a key identifier fails validation.
type ErrKeyID struct {
	ErrValidation
}

// As supports errors.As by allowing ErrKeyID to match *ErrValidation targets.
func (e *ErrKeyID) As(target any) bool {
	if t, ok := target.(**ErrValidation); ok {
		*t = &e.ErrValidation
		return true
	}
	return false
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

// As supports errors.As by allowing ErrKeyReference to match *ErrValidation targets.
func (e *ErrKeyReference) As(target any) bool {
	if t, ok := target.(**ErrValidation); ok {
		*t = &e.ErrValidation
		return true
	}
	return false
}

// ErrBackendName is returned when a backend name fails validation.
type ErrBackendName struct {
	ErrValidation
}

// As supports errors.As by allowing ErrBackendName to match *ErrValidation targets.
func (e *ErrBackendName) As(target any) bool {
	if t, ok := target.(**ErrValidation); ok {
		*t = &e.ErrValidation
		return true
	}
	return false
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
