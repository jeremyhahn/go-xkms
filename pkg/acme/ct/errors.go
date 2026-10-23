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

	// ErrNoLogsConfigured indicates no CT log is enabled, so CT is off.
	ErrNoLogsConfigured = errors.New("ct: no enabled logs configured")

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

	// ErrPrecertMalformed indicates the precertificate is not a parseable
	// X.509 certificate or its TBSCertificate cannot be re-encoded.
	ErrPrecertMalformed = errors.New("ct: precertificate malformed")

	// ErrPrecertIssuerMissing indicates the chain carries no certificate
	// that issues the precertificate (RFC 6962 §3.2 issuer_key_hash).
	ErrPrecertIssuerMissing = errors.New("ct: precertificate issuer missing from chain")

	// ErrSCTLogIDMismatch indicates the SCT's log ID is not the SHA-256 hash
	// of the log's public key (RFC 6962 §3.2).
	ErrSCTLogIDMismatch = errors.New("ct: SCT log ID does not match the log's public key")

	// ErrUnsupportedSCTAlgorithm indicates the SCT's hash or signature
	// algorithm is not one RFC 6962 §2.1.4 allows for the log's key.
	ErrUnsupportedSCTAlgorithm = errors.New("ct: unsupported SCT hash or signature algorithm")

	// ErrLogURLInvalid indicates a log URL that is not an absolute http or
	// https URL.
	ErrLogURLInvalid = errors.New("ct: log URL must be an absolute http or https URL")

	// ErrLogPublicKeyMissing indicates a log without a public key.
	ErrLogPublicKeyMissing = errors.New("ct: log public key missing")

	// ErrLogPublicKeyUnsupported indicates a log key that is neither ECDSA
	// P-256 nor RSA of at least 2048 bits (RFC 6962 §2.1.4).
	ErrLogPublicKeyUnsupported = errors.New("ct: log public key must be ECDSA P-256 or RSA of at least 2048 bits")

	// ErrLogIDMismatch indicates a configured log ID that is not the SHA-256
	// hash of the log's public key (RFC 6962 §3.2).
	ErrLogIDMismatch = errors.New("ct: configured log ID does not match the log's public key")

	// ErrDuplicateLog indicates two configured logs share a URL or log ID.
	ErrDuplicateLog = errors.New("ct: duplicate log")
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

// LogConfigError reports a CT log entry that failed validation. It matches
// ErrInvalidLogConfig under errors.Is, and Cause names the defect.
type LogConfigError struct {
	LogName string
	LogURL  string
	Cause   error
}

// Error implements the error interface.
func (e *LogConfigError) Error() string {
	return fmt.Sprintf("ct: invalid configuration for log %s (%s): %v", e.LogName, e.LogURL, e.Cause)
}

// Unwrap returns the defect that failed validation.
func (e *LogConfigError) Unwrap() error {
	return e.Cause
}

// Is reports whether target is ErrInvalidLogConfig.
func (e *LogConfigError) Is(target error) bool {
	return target == ErrInvalidLogConfig
}

// NewLogConfigError creates a LogConfigError for log.
func NewLogConfigError(log LogGroup, cause error) *LogConfigError {
	return &LogConfigError{
		LogName: log.Name,
		LogURL:  log.URL,
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
