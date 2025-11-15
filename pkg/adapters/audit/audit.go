// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package audit provides an adapter interface for audit logging,
// allowing calling applications to implement custom audit trail strategies.
//
// This follows the same pattern as auth and logger adapters - providing
// a clean interface that applications can implement while offering sensible
// defaults for common use cases.
package audit

import (
	"context"
	"time"
)

// EventType represents the type of audit event
type EventType string

const (
	// Key Management Events
	EventKeyGenerate EventType = "key.generate"
	EventKeyImport   EventType = "key.import"
	EventKeyExport   EventType = "key.export"
	EventKeyRotate   EventType = "key.rotate"
	EventKeyDelete   EventType = "key.delete"
	EventKeyList     EventType = "key.list"
	EventKeyGet      EventType = "key.get"

	// Cryptographic Operation Events
	EventSign    EventType = "crypto.sign"
	EventVerify  EventType = "crypto.verify"
	EventEncrypt EventType = "crypto.encrypt"
	EventDecrypt EventType = "crypto.decrypt"

	// Certificate Events
	EventCertCreate EventType = "cert.create"
	EventCertSign   EventType = "cert.sign"
	EventCertRevoke EventType = "cert.revoke"
	EventCertRenew  EventType = "cert.renew"
	EventCertImport EventType = "cert.import"
	EventCertExport EventType = "cert.export"
	EventCertDelete EventType = "cert.delete"
	EventCertList   EventType = "cert.list"
	EventCertGet    EventType = "cert.get"
	EventCertVerify EventType = "cert.verify"

	// Authentication Events
	EventAuthSuccess EventType = "auth.success"
	EventAuthFailure EventType = "auth.failure"
	EventAuthLogout  EventType = "auth.logout"

	// Authorization Events
	EventAuthzAllow EventType = "authz.allow"
	EventAuthzDeny  EventType = "authz.deny"

	// Administrative Events
	EventConfigChange  EventType = "admin.config_change"
	EventBackendAdd    EventType = "admin.backend_add"
	EventBackendRemove EventType = "admin.backend_remove"
	EventPolicyChange  EventType = "admin.policy_change"

	// System Events
	EventSystemStart EventType = "system.start"
	EventSystemStop  EventType = "system.stop"
	EventSystemError EventType = "system.error"
)

// EventSeverity indicates the importance level of an audit event
type EventSeverity string

const (
	SeverityInfo     EventSeverity = "info"
	SeverityWarn     EventSeverity = "warn"
	SeverityError    EventSeverity = "error"
	SeverityCritical EventSeverity = "critical"
)

// EventOutcome indicates the result of an operation
type EventOutcome string

const (
	OutcomeSuccess EventOutcome = "success"
	OutcomeFailure EventOutcome = "failure"
	OutcomeDenied  EventOutcome = "denied"
)

// AuditEvent represents a single audit log entry
type AuditEvent struct {
	// ID is a unique identifier for this audit event
	ID string

	// Timestamp when the event occurred
	Timestamp time.Time

	// EventType categorizes the event
	EventType EventType

	// Severity indicates the importance level
	Severity EventSeverity

	// Outcome indicates whether the operation succeeded
	Outcome EventOutcome

	// Principal is the identity of the user/service that initiated the event
	Principal *Principal

	// Resource identifies what was accessed or modified
	Resource *Resource

	// Action describes what was attempted
	Action string

	// Result contains the outcome or error message
	Result string

	// Metadata stores additional context
	Metadata map[string]interface{}

	// RequestID correlates this event with a request
	RequestID string

	// SessionID correlates this event with a session
	SessionID string

	// SourceIP is the IP address of the client
	SourceIP string

	// UserAgent is the user agent string
	UserAgent string
}

// Principal represents the identity performing an action
type Principal struct {
	// Type indicates the kind of principal (user, service, system)
	Type string

	// ID is the unique identifier for this principal
	ID string

	// Name is a human-readable name
	Name string

	// Attributes stores additional principal information
	Attributes map[string]interface{}
}

// Resource represents the target of an action
type Resource struct {
	// Type indicates the kind of resource (key, certificate, secret)
	Type string

	// ID is the unique identifier for this resource
	ID string

	// Backend indicates which backend the resource belongs to
	Backend string

	// Attributes stores additional resource information
	Attributes map[string]interface{}
}

// AuditAdapter provides audit logging capabilities.
//
// Applications can implement this interface to provide custom audit logging
// strategies (e.g., database-backed, SIEM integration, distributed tracing).
type AuditAdapter interface {
	// LogEvent records an audit event
	LogEvent(ctx context.Context, event *AuditEvent) error

	// GetEvents retrieves audit events based on query parameters
	GetEvents(ctx context.Context, query *EventQuery) ([]*AuditEvent, error)

	// GetEvent retrieves a specific audit event by ID
	GetEvent(ctx context.Context, eventID string) (*AuditEvent, error)

	// DeleteEvent removes an audit event (typically for GDPR compliance)
	DeleteEvent(ctx context.Context, eventID string) error

	// DeleteEvents removes multiple audit events matching a query
	DeleteEvents(ctx context.Context, query *EventQuery) (int, error)

	// GetStatistics returns audit statistics
	GetStatistics(ctx context.Context, query *StatisticsQuery) (*Statistics, error)
}

// EventQuery provides parameters for querying audit events
type EventQuery struct {
	// EventTypes filters by event type
	EventTypes []EventType

	// Severities filters by severity
	Severities []EventSeverity

	// Outcomes filters by outcome
	Outcomes []EventOutcome

	// PrincipalID filters by principal ID
	PrincipalID string

	// ResourceID filters by resource ID
	ResourceID string

	// Backend filters by backend name
	Backend string

	// StartTime filters events after this time
	StartTime *time.Time

	// EndTime filters events before this time
	EndTime *time.Time

	// RequestID filters by request ID
	RequestID string

	// SessionID filters by session ID
	SessionID string

	// Limit limits the number of results
	Limit int

	// Offset skips the first N results
	Offset int

	// OrderBy specifies the field to order by (default: timestamp desc)
	OrderBy string
}

// StatisticsQuery provides parameters for audit statistics
type StatisticsQuery struct {
	// GroupBy specifies how to group statistics (event_type, principal, resource, backend)
	GroupBy []string

	// StartTime for statistics window
	StartTime *time.Time

	// EndTime for statistics window
	EndTime *time.Time
}

// Statistics contains audit statistics
type Statistics struct {
	// TotalEvents is the total number of events
	TotalEvents int64

	// EventsByType breaks down events by type
	EventsByType map[EventType]int64

	// EventsBySeverity breaks down events by severity
	EventsBySeverity map[EventSeverity]int64

	// EventsByOutcome breaks down events by outcome
	EventsByOutcome map[EventOutcome]int64

	// TopPrincipals lists the most active principals
	TopPrincipals []PrincipalStats

	// TopResources lists the most accessed resources
	TopResources []ResourceStats
}

// PrincipalStats contains statistics for a principal
type PrincipalStats struct {
	PrincipalID string
	EventCount  int64
}

// ResourceStats contains statistics for a resource
type ResourceStats struct {
	ResourceID string
	EventCount int64
}
