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

import "time"

// AuditEntryEntity is the DAO entity representation of an audit log entry.
// It mirrors the Entry type with DAO-compatible field tags for indexed
// persistence via go-qrdb.
type AuditEntryEntity struct {
	// ID is the auto-assigned DAO entity identifier.
	ID uint64 `json:"id"`

	// Timestamp is when the audit event occurred.
	Timestamp time.Time `json:"timestamp"`

	// Operation is the type of operation that was audited.
	Operation OperationType `json:"operation" index:"true"`

	// Backend is the backend that handled the operation (e.g., "software", "tpm2").
	Backend string `json:"backend" index:"true"`

	// KeyID is the identifier of the key involved in the operation.
	KeyID string `json:"key_id" index:"true"`

	// DeviceID is the device identifier involved in the operation.
	DeviceID string `json:"device_id"`

	// DeviceName is the human-readable device name.
	DeviceName string `json:"device_name"`

	// Success indicates whether the operation completed successfully.
	Success bool `json:"success" index:"true"`

	// Error contains the error message if the operation failed.
	Error string `json:"error"`

	// DurationMs is the operation duration in milliseconds.
	DurationMs int64 `json:"duration_ms"`

	// Details contains additional key-value metadata for the event.
	Details map[string]any `json:"details"`
}

// EntityID returns the DAO entity identifier.
func (e *AuditEntryEntity) EntityID() uint64 { return e.ID }

// SetEntityID sets the DAO entity identifier.
func (e *AuditEntryEntity) SetEntityID(id uint64) { e.ID = id }
