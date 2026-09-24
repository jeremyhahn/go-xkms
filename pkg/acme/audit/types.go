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

package audit

import (
	"errors"
	"time"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

var (
	// ErrInvalidConfig is returned when audit configuration is invalid
	ErrInvalidConfig = errors.New("audit: invalid configuration")

	// ErrLoggerClosed is returned when attempting to log to a closed logger
	ErrLoggerClosed = errors.New("audit: logger is closed")

	// ErrInvalidEvent is returned when an audit event is invalid
	ErrInvalidEvent = errors.New("audit: invalid event")

	// ErrRotationFailed is returned when log rotation fails
	ErrRotationFailed = errors.New("audit: log rotation failed")

	// ErrWriteFailed is returned when writing an audit event fails
	ErrWriteFailed = errors.New("audit: write failed")
)

// EventType represents the type of auditable event
type EventType string

const (
	// ACME Account Events
	EventAccountCreated     EventType = "ACCOUNT_CREATED"
	EventAccountUpdated     EventType = "ACCOUNT_UPDATED"
	EventAccountDeactivated EventType = "ACCOUNT_DEACTIVATED"
	EventAccountKeyChanged  EventType = "ACCOUNT_KEY_CHANGED"

	// ACME Order Events
	EventOrderCreated   EventType = "ORDER_CREATED"
	EventOrderFinalized EventType = "ORDER_FINALIZED"
	EventOrderCanceled  EventType = "ORDER_CANCELED"

	// ACME Authorization Events
	EventAuthorizationCreated     EventType = "AUTHORIZATION_CREATED"
	EventAuthorizationValidated   EventType = "AUTHORIZATION_VALIDATED"
	EventAuthorizationDeactivated EventType = "AUTHORIZATION_DEACTIVATED"

	// ACME Challenge Events
	EventChallengeInitiated EventType = "CHALLENGE_INITIATED"
	EventChallengeCompleted EventType = "CHALLENGE_COMPLETED"
	EventChallengeFailed    EventType = "CHALLENGE_FAILED"
	EventChallengeValidated EventType = "CHALLENGE_VALIDATED"

	// Certificate Authority Events
	EventCertificateIssued  EventType = "CERTIFICATE_ISSUED"
	EventCertificateRevoked EventType = "CERTIFICATE_REVOKED"
	EventCertificateRenewed EventType = "CERTIFICATE_RENEWED"
	EventCertificateSigned  EventType = "CERTIFICATE_SIGNED"

	// CA Lifecycle Events
	//
	// EventCAKeyRotated was removed (issue #688): go-xkms has no CA signing
	// key rotation operation anywhere in the codebase (pkg/ca/ca.go issues
	// and signs certificates and generates CRLs, but never rotates its own
	// key), so there was no call site to emit it from. If CA key rotation is
	// added later, add the event back alongside it rather than reserving it
	// unused.
	EventCAInitialized  EventType = "CA_INITIALIZED"
	EventCACRLGenerated EventType = "CA_CRL_GENERATED"
	EventCACrossSign    EventType = "CA_CROSS_SIGN"

	// Security Events
	EventAuthenticationFailed EventType = "AUTHENTICATION_FAILED"
	EventAuthorizationFailed  EventType = "AUTHORIZATION_FAILED"
	EventInvalidSignature     EventType = "INVALID_SIGNATURE"
	EventInvalidNonce         EventType = "INVALID_NONCE"
	EventRateLimitExceeded    EventType = "RATE_LIMIT_EXCEEDED"

	// TPM and Attestation Events
	EventTPMEnrollment       EventType = "TPM_ENROLLMENT"
	EventTPMAttestation      EventType = "TPM_ATTESTATION"
	EventDeviceAttestation   EventType = "DEVICE_ATTESTATION"
	EventEndorsementVerified EventType = "ENDORSEMENT_VERIFIED"
)

// Result represents the outcome of an audited operation
type Result string

const (
	ResultSuccess Result = "success"
	ResultFailure Result = "failure"
	ResultPending Result = "pending"
)

// AuditEvent represents a single auditable event in the system.
// All events are immutable once created and contain comprehensive
// context about what happened, who did it, and when.
type AuditEvent struct {
	// Timestamp is when the event occurred (UTC)
	Timestamp time.Time `json:"timestamp"`

	// EventType categorizes the type of event
	EventType EventType `json:"event_type"`

	// Actor identifies who/what performed the action
	// Examples: "account:12345", "system", "admin:user@example.com"
	Actor string `json:"actor"`

	// Resource identifies what was acted upon
	// Examples: "order:xyz789", "certificate:abc123", "account:12345"
	Resource string `json:"resource"`

	// Action describes the specific action taken
	// Examples: "create", "update", "delete", "finalize", "validate"
	Action string `json:"action"`

	// Result indicates success or failure
	Result Result `json:"result"`

	// RequestID ties the event to a specific request for correlation
	RequestID string `json:"request_id,omitempty"`

	// SourceIP is the IP address of the client that initiated the action
	SourceIP string `json:"source_ip,omitempty"`

	// UserAgent is the HTTP User-Agent header from the request
	UserAgent string `json:"user_agent,omitempty"`

	// Details contains additional event-specific context
	// Examples: {"common_name": "example.com", "validity_days": 90}
	Details map[string]interface{} `json:"details,omitempty"`

	// ErrorMessage contains error details if Result is failure
	ErrorMessage string `json:"error_message,omitempty"`

	// Duration is how long the operation took (in milliseconds)
	Duration int64 `json:"duration_ms,omitempty"`
}

// Config contains configuration for the audit logging system
type Config struct {
	// Enabled determines if audit logging is active
	Enabled bool `yaml:"enabled" json:"enabled"`

	// LogPath is the path to the audit log file
	LogPath string `yaml:"logPath" json:"logPath"`

	// MaxSizeMB is the maximum size of the log file before rotation (in MB)
	MaxSizeMB int `yaml:"maxSizeMB" json:"maxSizeMB"`

	// MaxAgeDays is the maximum number of days to retain audit logs
	MaxAgeDays int `yaml:"maxAgeDays" json:"maxAgeDays"`

	// MaxBackups is the maximum number of old log files to retain
	MaxBackups int `yaml:"maxBackups" json:"maxBackups"`

	// Format specifies the log format (currently only "json" is supported)
	Format string `yaml:"format" json:"format"`

	// BufferSize is the number of events to buffer before flushing to disk
	// Higher values improve performance but increase risk of data loss
	BufferSize int `yaml:"bufferSize" json:"bufferSize"`

	// FlushIntervalSeconds is how often to flush buffered events to disk
	FlushIntervalSeconds int `yaml:"flushIntervalSeconds" json:"flushIntervalSeconds"`

	// Compress determines if rotated log files should be compressed
	Compress bool `yaml:"compress" json:"compress"`
}

// Validate validates the audit configuration
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}

	if c.LogPath == "" {
		return caerrors.MalformedError("audit: logPath is required when enabled")
	}

	if c.MaxSizeMB <= 0 {
		c.MaxSizeMB = 100 // Default to 100MB
	}

	if c.MaxAgeDays <= 0 {
		c.MaxAgeDays = 365 // Default to 1 year
	}

	if c.MaxBackups <= 0 {
		c.MaxBackups = 10 // Default to 10 backups
	}

	if c.Format != "json" && c.Format != "" {
		return caerrors.MalformedError("audit: only 'json' format is currently supported")
	}
	c.Format = "json"

	if c.BufferSize <= 0 {
		c.BufferSize = 100 // Default to 100 events
	}

	if c.FlushIntervalSeconds <= 0 {
		c.FlushIntervalSeconds = 5 // Default to 5 seconds
	}

	return nil
}

// Validate validates an audit event
func (e *AuditEvent) Validate() error {
	if e.Timestamp.IsZero() {
		return caerrors.MalformedError("audit: timestamp is required")
	}

	if e.EventType == "" {
		return caerrors.MalformedError("audit: event_type is required")
	}

	if e.Actor == "" {
		return caerrors.MalformedError("audit: actor is required")
	}

	if e.Resource == "" {
		return caerrors.MalformedError("audit: resource is required")
	}

	if e.Action == "" {
		return caerrors.MalformedError("audit: action is required")
	}

	if e.Result != ResultSuccess && e.Result != ResultFailure && e.Result != ResultPending {
		return caerrors.MalformedError("audit: result must be success, failure, or pending")
	}

	return nil
}
