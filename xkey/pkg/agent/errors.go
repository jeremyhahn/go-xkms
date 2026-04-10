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

// Package agent implements a network agent that enables remote machines to
// use xKey services (PKCS#11, FIDO2, PIV, crypto, SSH) from the master
// machine where xKey runs. All key material stays on the master.
//
// The agent uses mTLS for transport security and supports four enrollment
// methods: one-time codes, admin approval, enterprise CA, and Noise direct
// pairing. Enrollment is governed by a policy set by the security officer.
package agent

import "errors"

// Server lifecycle errors.
var (
	// ErrServerNotStarted is returned when an operation requires a running
	// server but the server has not been started.
	ErrServerNotStarted = errors.New("agent: server not started")

	// ErrServerAlreadyRunning is returned when Start is called on a server
	// that is already listening.
	ErrServerAlreadyRunning = errors.New("agent: server already running")
)

// Client lifecycle errors.
var (
	// ErrClientNotConnected is returned when an operation requires an active
	// connection but the client is not connected to the master.
	ErrClientNotConnected = errors.New("agent: client not connected")

	// ErrClientAlreadyConnected is returned when Connect is called on a
	// client that already has an active connection.
	ErrClientAlreadyConnected = errors.New("agent: client already connected")
)

// Enrollment errors.
var (
	// ErrEnrollmentFailed is returned when the enrollment process fails.
	ErrEnrollmentFailed = errors.New("agent: enrollment failed")

	// ErrEnrollmentCodeExpired is returned when a one-time enrollment code
	// has passed its expiration time.
	ErrEnrollmentCodeExpired = errors.New("agent: enrollment code expired")

	// ErrEnrollmentCodeInvalid is returned when the provided enrollment
	// code does not match any known code.
	ErrEnrollmentCodeInvalid = errors.New("agent: enrollment code invalid")

	// ErrEnrollmentPending is returned when an enrollment request has been
	// submitted but not yet approved by an administrator.
	ErrEnrollmentPending = errors.New("agent: enrollment pending admin approval")

	// ErrEnrollmentRejected is returned when an administrator has rejected
	// the enrollment request.
	ErrEnrollmentRejected = errors.New("agent: enrollment rejected")

	// ErrEnrollmentMethodNotAllowed is returned when the requested enrollment
	// method is not permitted by the current policy.
	ErrEnrollmentMethodNotAllowed = errors.New("agent: enrollment method not allowed by policy")

	// ErrMaxAgentsReached is returned when the maximum number of enrolled
	// agents has been reached.
	ErrMaxAgentsReached = errors.New("agent: maximum number of enrolled agents reached")
)

// Certificate errors.
var (
	// ErrCertificateInvalid is returned when a presented certificate fails
	// validation checks.
	ErrCertificateInvalid = errors.New("agent: certificate invalid")

	// ErrCertificateExpired is returned when a certificate has passed its
	// NotAfter date.
	ErrCertificateExpired = errors.New("agent: certificate expired")

	// ErrCertificateRevoked is returned when a certificate has been revoked
	// by the CA.
	ErrCertificateRevoked = errors.New("agent: certificate revoked")
)

// Policy errors.
var (
	// ErrPolicyViolation is returned when a requested operation violates
	// the current security policy.
	ErrPolicyViolation = errors.New("agent: policy violation")

	// ErrTouchRequired is returned when a signing operation requires touch
	// confirmation from the user.
	ErrTouchRequired = errors.New("agent: touch confirmation required")
)

// Configuration errors.
var (
	// ErrNilConfig is returned when a nil configuration is passed.
	ErrNilConfig = errors.New("agent: configuration is required")

	// ErrNilLogger is returned when a nil logger is passed.
	ErrNilLogger = errors.New("agent: logger is required")

	// ErrNilCAService is returned when a nil CA service is passed.
	ErrNilCAService = errors.New("agent: CA service is required")

	// ErrNilEnrollmentStore is returned when a nil enrollment store is passed.
	ErrNilEnrollmentStore = errors.New("agent: enrollment store is required")

	// ErrNilEnrollmentService is returned when a nil enrollment service is passed.
	ErrNilEnrollmentService = errors.New("agent: enrollment service is required")

	// ErrNilClient is returned when a nil client is passed.
	ErrNilClient = errors.New("agent: client is required")

	// ErrInvalidAddress is returned when a listen or connect address is empty.
	ErrInvalidAddress = errors.New("agent: address is required")

	// ErrInvalidCSR is returned when a CSR is empty or malformed.
	ErrInvalidCSR = errors.New("agent: CSR is required")

	// ErrInvalidRequestID is returned when a request ID is empty.
	ErrInvalidRequestID = errors.New("agent: request ID is required")

	// ErrRequestNotFound is returned when an enrollment request ID is not found.
	ErrRequestNotFound = errors.New("agent: enrollment request not found")

	// ErrAgentNotFound is returned when an agent ID is not found in the store.
	ErrAgentNotFound = errors.New("agent: agent not found")

	// ErrStoreDir is returned when the store directory cannot be created.
	ErrStoreDir = errors.New("agent: failed to create store directory")

	// ErrStoreMarshal is returned when agent data cannot be serialized.
	ErrStoreMarshal = errors.New("agent: failed to marshal agent data")

	// ErrStoreUnmarshal is returned when agent data cannot be deserialized.
	ErrStoreUnmarshal = errors.New("agent: failed to unmarshal agent data")

	// ErrStoreWrite is returned when agent data cannot be written to disk.
	ErrStoreWrite = errors.New("agent: failed to write agent data")

	// ErrStoreRead is returned when agent data cannot be read from disk.
	ErrStoreRead = errors.New("agent: failed to read agent data")

	// ErrStoreDelete is returned when agent data cannot be deleted from disk.
	ErrStoreDelete = errors.New("agent: failed to delete agent data")

	// ErrSocketPath is returned when the SSH proxy socket path is invalid.
	ErrSocketPath = errors.New("agent: invalid socket path")
)

// AgentError represents an error that occurred during an agent operation.
// It wraps an underlying error with the operation context.
type AgentError struct {
	// Operation describes the operation that failed (e.g., "enroll", "connect").
	Operation string

	// Err is the underlying error.
	Err error
}

// Error returns a formatted error string including the operation context.
func (e *AgentError) Error() string {
	return "agent: " + e.Operation + ": " + e.Err.Error()
}

// Unwrap returns the underlying error for use with errors.Is and errors.As.
func (e *AgentError) Unwrap() error {
	return e.Err
}
