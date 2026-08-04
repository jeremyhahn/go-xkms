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

package ct

import (
	"errors"
	"fmt"
)

// Sentinel errors for CT operations.
var (
	// ErrNilInput indicates a nil or empty input was provided.
	ErrNilInput = errors.New("ct: nil or empty input")

	// ErrInvalidSCT indicates an invalid SCT structure.
	ErrInvalidSCT = errors.New("ct: invalid SCT structure")

	// ErrSCTEncodingFailed indicates SCT encoding failed.
	ErrSCTEncodingFailed = errors.New("ct: SCT encoding failed")

	// ErrSCTDecodingFailed indicates SCT decoding failed.
	ErrSCTDecodingFailed = errors.New("ct: SCT decoding failed")

	// ErrInvalidLogConfig indicates invalid CT log configuration.
	ErrInvalidLogConfig = errors.New("ct: invalid log configuration")

	// ErrNoLogsConfigured indicates no CT logs are configured.
	ErrNoLogsConfigured = errors.New("ct: no logs configured")

	// ErrNoEligibleLogs indicates no logs are eligible for the certificate.
	ErrNoEligibleLogs = errors.New("ct: no eligible logs for certificate expiry")

	// ErrInsufficientSCTs indicates not enough SCTs were obtained.
	ErrInsufficientSCTs = errors.New("ct: insufficient SCTs obtained")

	// ErrInsufficientOperators indicates SCTs from insufficient operators.
	ErrInsufficientOperators = errors.New("ct: insufficient operator diversity")

	// ErrNoRFC6962Log indicates no RFC6962-compliant log returned an SCT.
	ErrNoRFC6962Log = errors.New("ct: no RFC6962-compliant log SCT obtained")

	// ErrCTSubmissionFailed indicates CT log submission failed.
	ErrCTSubmissionFailed = errors.New("ct: log submission failed")

	// ErrCTSubmissionTimeout indicates CT log submission timed out.
	ErrCTSubmissionTimeout = errors.New("ct: log submission timed out")

	// ErrInvalidPolicyConfig indicates invalid CT policy configuration.
	ErrInvalidPolicyConfig = errors.New("ct: invalid policy configuration")

	// ErrLogTemporalMismatch indicates certificate expiry is outside log's temporal window.
	ErrLogTemporalMismatch = errors.New("ct: certificate expiry outside log temporal window")

	// ErrInvalidSignature indicates SCT signature verification failed.
	ErrInvalidSignature = errors.New("ct: SCT signature verification failed")

	// ErrPrecertPoisonMissing indicates the precert poison extension is missing.
	ErrPrecertPoisonMissing = errors.New("ct: precert poison extension missing")

	// ErrPrecertPoisonInvalid indicates the precert poison extension is invalid.
	ErrPrecertPoisonInvalid = errors.New("ct: precert poison extension invalid")
)

// CTSubmissionError wraps a CT log submission error with additional context.
type CTSubmissionError struct {
	LogURL  string
	LogName string
	Cause   error
}

// Error implements the error interface.
func (e *CTSubmissionError) Error() string {
	return fmt.Sprintf("ct: submission to log %s (%s) failed: %v", e.LogName, e.LogURL, e.Cause)
}

// Unwrap returns the underlying cause.
func (e *CTSubmissionError) Unwrap() error {
	return e.Cause
}

// NewCTSubmissionError creates a new CTSubmissionError.
func NewCTSubmissionError(logName, logURL string, cause error) *CTSubmissionError {
	return &CTSubmissionError{
		LogName: logName,
		LogURL:  logURL,
		Cause:   cause,
	}
}

// PolicyViolationError indicates a CT policy requirement was not met.
type PolicyViolationError struct {
	Requirement string
	Obtained    int
	Required    int
}

// Error implements the error interface.
func (e *PolicyViolationError) Error() string {
	return fmt.Sprintf("ct: policy violation - %s: obtained %d, required %d",
		e.Requirement, e.Obtained, e.Required)
}

// NewPolicyViolationError creates a new PolicyViolationError.
func NewPolicyViolationError(requirement string, obtained, required int) *PolicyViolationError {
	return &PolicyViolationError{
		Requirement: requirement,
		Obtained:    obtained,
		Required:    required,
	}
}
