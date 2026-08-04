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

package issuance

import (
	"errors"
	"fmt"
)

// Sentinel errors for issuance operations.
var (
	// ErrNilInput indicates a nil or empty input was provided.
	ErrNilInput = errors.New("issuance: nil or empty input")

	// ErrInvalidCSR indicates the CSR is invalid or malformed.
	ErrInvalidCSR = errors.New("issuance: invalid CSR")

	// ErrInvalidTemplate indicates the certificate template is invalid.
	ErrInvalidTemplate = errors.New("issuance: invalid certificate template")

	// ErrInvalidConfig indicates invalid issuer configuration.
	ErrInvalidConfig = errors.New("issuance: invalid configuration")

	// ErrKeyValidationFailed indicates key validation failed.
	ErrKeyValidationFailed = errors.New("issuance: key validation failed")

	// ErrSerialGenerationFailed indicates serial number generation failed.
	ErrSerialGenerationFailed = errors.New("issuance: serial generation failed")

	// ErrSerialPersistenceFailed indicates serial persistence failed.
	ErrSerialPersistenceFailed = errors.New("issuance: serial persistence failed")

	// ErrLintFailed indicates certificate linting failed.
	ErrLintFailed = errors.New("issuance: certificate linting failed")

	// ErrPrecertSigningFailed indicates precertificate signing failed.
	ErrPrecertSigningFailed = errors.New("issuance: precertificate signing failed")

	// ErrFinalCertSigningFailed indicates final certificate signing failed.
	ErrFinalCertSigningFailed = errors.New("issuance: final certificate signing failed")

	// ErrTBSDeterminismFailed indicates TBS determinism check failed.
	ErrTBSDeterminismFailed = errors.New("issuance: TBS determinism verification failed")

	// ErrCTSubmissionFailed indicates CT log submission failed.
	ErrCTSubmissionFailed = errors.New("issuance: CT submission failed")

	// ErrCertificatePersistenceFailed indicates certificate storage failed.
	ErrCertificatePersistenceFailed = errors.New("issuance: certificate persistence failed")

	// ErrProfileNotFound indicates the requested profile was not found.
	ErrProfileNotFound = errors.New("issuance: profile not found")

	// ErrIssuanceDisabled indicates issuance is disabled.
	ErrIssuanceDisabled = errors.New("issuance: issuance is disabled")

	// ErrAuditFailed indicates audit logging failed.
	ErrAuditFailed = errors.New("issuance: audit logging failed")

	// ErrValidityPeriodInvalid indicates the validity period is invalid.
	ErrValidityPeriodInvalid = errors.New("issuance: validity period invalid")

	// ErrCTDisabled indicates CT is disabled but required.
	ErrCTDisabled = errors.New("issuance: CT is disabled")
)

// IssuanceError wraps an issuance error with additional context.
type IssuanceError struct {
	Phase   IssuancePhase
	Message string
	Cause   error
}

// IssuancePhase identifies the phase of issuance where an error occurred.
type IssuancePhase string

const (
	// PhaseCSRValidation is the CSR validation phase.
	PhaseCSRValidation IssuancePhase = "csr_validation"

	// PhaseKeyValidation is the key validation phase.
	PhaseKeyValidation IssuancePhase = "key_validation"

	// PhaseSerialGeneration is the serial generation phase.
	PhaseSerialGeneration IssuancePhase = "serial_generation"

	// PhaseSerialPersistence is the serial persistence phase.
	PhaseSerialPersistence IssuancePhase = "serial_persistence"

	// PhaseLinting is the certificate linting phase.
	PhaseLinting IssuancePhase = "linting"

	// PhasePrecertSigning is the precertificate signing phase.
	PhasePrecertSigning IssuancePhase = "precert_signing"

	// PhaseTBSVerification is the TBS verification phase.
	PhaseTBSVerification IssuancePhase = "tbs_verification"

	// PhaseCTSubmission is the CT submission phase.
	PhaseCTSubmission IssuancePhase = "ct_submission"

	// PhaseFinalSigning is the final certificate signing phase.
	PhaseFinalSigning IssuancePhase = "final_signing"

	// PhasePersistence is the certificate persistence phase.
	PhasePersistence IssuancePhase = "persistence"

	// PhaseAudit is the audit logging phase.
	PhaseAudit IssuancePhase = "audit"
)

// Error implements the error interface.
func (e *IssuanceError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("issuance: %s: %s: %v", e.Phase, e.Message, e.Cause)
	}
	return fmt.Sprintf("issuance: %s: %s", e.Phase, e.Message)
}

// Unwrap returns the underlying cause.
func (e *IssuanceError) Unwrap() error {
	return e.Cause
}

// NewIssuanceError creates a new IssuanceError.
func NewIssuanceError(phase IssuancePhase, message string, cause error) *IssuanceError {
	return &IssuanceError{
		Phase:   phase,
		Message: message,
		Cause:   cause,
	}
}

// LintError wraps lint failures with details.
type LintError struct {
	Errors   []string
	Warnings []string
	Summary  string
}

// Error implements the error interface.
func (e *LintError) Error() string {
	return fmt.Sprintf("issuance: linting failed: %s", e.Summary)
}

// NewLintError creates a new LintError.
func NewLintError(summary string, errors, warnings []string) *LintError {
	return &LintError{
		Summary:  summary,
		Errors:   errors,
		Warnings: warnings,
	}
}

// CSRValidationError wraps CSR validation failures.
type CSRValidationError struct {
	Field   string
	Message string
}

// Error implements the error interface.
func (e *CSRValidationError) Error() string {
	return fmt.Sprintf("issuance: CSR validation failed: %s: %s", e.Field, e.Message)
}

// NewCSRValidationError creates a new CSRValidationError.
func NewCSRValidationError(field, message string) *CSRValidationError {
	return &CSRValidationError{
		Field:   field,
		Message: message,
	}
}
