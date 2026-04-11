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
	"context"
	"time"
)

// Logger defines the audit logging interface for xkmsd.
// Standalone xkmsd uses file-based logging. go-qrdb replaces
// with HMAC-signed, SIEM-integrated audit logging.
type Logger interface {
	// Log records an audit event.
	Log(ctx context.Context, event *Event) error
	// Close releases resources.
	Close() error
}

// Event represents an audit log entry.
type Event struct {
	Timestamp  time.Time         `json:"timestamp"`
	Subject    string            `json:"subject"`     // Who performed the action
	Action     string            `json:"action"`      // What action was performed
	Resource   string            `json:"resource"`    // Resource type (keys, certs, users, etc.)
	ResourceID string            `json:"resource_id"` // Specific resource identifier
	Outcome    string            `json:"outcome"`     // "allow" or "deny"
	Details    map[string]string `json:"details,omitempty"`
}

// Outcome constants for the Logger interface
const (
	OutcomeAllow = "allow"
	OutcomeDeny  = "deny"
)

// NoOpLogger is a Logger implementation that discards all events.
// Use when audit logging is disabled.
type NoOpLogger struct{}

// Log discards the event and returns nil.
func (n *NoOpLogger) Log(ctx context.Context, event *Event) error {
	return nil
}

// Close is a no-op and returns nil.
func (n *NoOpLogger) Close() error {
	return nil
}

// Compile-time interface compliance checks
var _ Logger = (*NoOpLogger)(nil)
