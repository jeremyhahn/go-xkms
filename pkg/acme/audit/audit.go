// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package audit provides production-grade audit logging for security-relevant
// operations in the go-trusted-ca Certificate Authority and ACME server.
//
// The audit system tracks who/what/when/why for all critical operations including:
// - Certificate issuance and revocation
// - Account creation and management
// - Authorization and challenge completion
// - Key changes and rotations
// - Authentication failures
// - TPM enrollment and attestation
//
// All audit events are logged as structured JSON with automatic log rotation
// and configurable retention policies.
package audit

import (
	"context"
)

// AuditLogger defines the interface for audit logging operations.
// Implementations must be thread-safe and support concurrent logging.
type AuditLogger interface {
	// Log records an audit event. Events are validated before logging.
	// Returns an error if the event is invalid or if logging fails.
	Log(ctx context.Context, event *AuditEvent) error

	// LogWithContext is a convenience method that logs an event with
	// context extracted from the provided context.Context (request ID, etc.)
	LogWithContext(ctx context.Context, eventType EventType, actor, resource, action string, result Result, details map[string]interface{}) error

	// Flush ensures all buffered events are written to storage
	Flush() error

	// Close flushes remaining events and closes the logger
	Close() error

	// Enabled returns true if audit logging is enabled
	Enabled() bool
}

// NoOpLogger is a no-op implementation of AuditLogger for when audit logging is disabled
type NoOpLogger struct{}

// NewNoOpLogger creates a new no-op audit logger
func NewNoOpLogger() AuditLogger {
	return &NoOpLogger{}
}

// Log does nothing
func (n *NoOpLogger) Log(ctx context.Context, event *AuditEvent) error {
	return nil
}

// LogWithContext does nothing
func (n *NoOpLogger) LogWithContext(ctx context.Context, eventType EventType, actor, resource, action string, result Result, details map[string]interface{}) error {
	return nil
}

// Flush does nothing
func (n *NoOpLogger) Flush() error {
	return nil
}

// Close does nothing
func (n *NoOpLogger) Close() error {
	return nil
}

// Enabled always returns false
func (n *NoOpLogger) Enabled() bool {
	return false
}

// EventBuilder provides a fluent interface for constructing audit events
type EventBuilder struct {
	event *AuditEvent
}

// NewEventBuilder creates a new event builder
func NewEventBuilder(eventType EventType) *EventBuilder {
	return &EventBuilder{
		event: &AuditEvent{
			EventType: eventType,
			Details:   make(map[string]interface{}),
		},
	}
}

// WithActor sets the actor who performed the action
func (b *EventBuilder) WithActor(actor string) *EventBuilder {
	b.event.Actor = actor
	return b
}

// WithResource sets the resource that was acted upon
func (b *EventBuilder) WithResource(resource string) *EventBuilder {
	b.event.Resource = resource
	return b
}

// WithAction sets the action that was performed
func (b *EventBuilder) WithAction(action string) *EventBuilder {
	b.event.Action = action
	return b
}

// WithResult sets the result of the operation
func (b *EventBuilder) WithResult(result Result) *EventBuilder {
	b.event.Result = result
	return b
}

// WithRequestID sets the request ID for correlation
func (b *EventBuilder) WithRequestID(requestID string) *EventBuilder {
	b.event.RequestID = requestID
	return b
}

// WithSourceIP sets the source IP address
func (b *EventBuilder) WithSourceIP(ip string) *EventBuilder {
	b.event.SourceIP = ip
	return b
}

// WithUserAgent sets the user agent
func (b *EventBuilder) WithUserAgent(userAgent string) *EventBuilder {
	b.event.UserAgent = userAgent
	return b
}

// WithDetail adds a key-value pair to the event details
func (b *EventBuilder) WithDetail(key string, value interface{}) *EventBuilder {
	b.event.Details[key] = value
	return b
}

// WithDetails sets multiple details at once
func (b *EventBuilder) WithDetails(details map[string]interface{}) *EventBuilder {
	for k, v := range details {
		b.event.Details[k] = v
	}
	return b
}

// WithError sets the error message for failed operations
func (b *EventBuilder) WithError(err error) *EventBuilder {
	if err != nil {
		b.event.ErrorMessage = err.Error()
		b.event.Result = ResultFailure
	}
	return b
}

// WithDuration sets the operation duration in milliseconds
func (b *EventBuilder) WithDuration(durationMs int64) *EventBuilder {
	b.event.Duration = durationMs
	return b
}

// Build constructs the final audit event
func (b *EventBuilder) Build() *AuditEvent {
	// Set timestamp if not already set
	if b.event.Timestamp.IsZero() {
		b.event.Timestamp = getCurrentTime()
	}
	return b.event
}
