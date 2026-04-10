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

package sharestore

import (
	"context"
	"fmt"
	"time"
)

// ShareEntry stores a Shamir share with metadata about its source.
// Implements dao.Entity for DAO-based persistence.
type ShareEntry struct {
	// ID is the unique entity identifier for DAO persistence.
	ID uint64 `json:"id"`

	// ServerURL is the xkms server this share came from.
	ServerURL string `json:"server_url"`

	// GroupID is the custodian group this share belongs to.
	GroupID string `json:"group_id"`

	// GroupName is the human-readable group name.
	GroupName string `json:"group_name,omitempty"`

	// ShareIndex is the 1-based index of this share within the group.
	ShareIndex int `json:"share_index"`

	// ShareData holds the raw share bytes (base64 when serialized).
	ShareData []byte `json:"share_data"`

	// Purpose describes what the share is for ("barrier", "signing-key", "backup").
	Purpose string `json:"purpose,omitempty"`

	// ReceivedAt is when the share was received.
	ReceivedAt time.Time `json:"received_at"`

	// TenantID is the tenant scope (empty = system-level).
	TenantID string `json:"tenant_id,omitempty"`
}

// EntityID returns the unique identifier for this entity.
func (e *ShareEntry) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's unique identifier.
func (e *ShareEntry) SetEntityID(id uint64) { e.ID = id }

// Validate checks the share entry for required fields.
func (e *ShareEntry) Validate() error {
	if e.ServerURL == "" {
		return ErrInvalidServerURL
	}
	if e.GroupID == "" {
		return ErrInvalidGroupID
	}
	if len(e.ShareData) == 0 {
		return ErrEmptyShare
	}
	return nil
}

// Key returns the composite key for this share entry (serverURL/groupID/shareIndex).
func (e *ShareEntry) Key() string {
	return fmt.Sprintf("%s/%s/%d", e.ServerURL, e.GroupID, e.ShareIndex)
}

// CompositeKey returns the composite key used for deterministic ID generation.
// Format: ServerURL + "/" + GroupID + "/" + ShareIndex.
func (e *ShareEntry) CompositeKey() string {
	return fmt.Sprintf("%s/%s/%d", e.ServerURL, e.GroupID, e.ShareIndex)
}

// ShareStore defines the persistence interface for Shamir shares.
type ShareStore interface {
	// Save stores a share entry. Returns ErrShareExists if a share for
	// the same server+group+shareIndex already exists.
	Save(ctx context.Context, entry *ShareEntry) error

	// Load retrieves a share by server URL, group ID, and share index.
	Load(ctx context.Context, serverURL, groupID string, shareIndex int) (*ShareEntry, error)

	// Delete removes a share by server URL, group ID, and share index.
	Delete(ctx context.Context, serverURL, groupID string, shareIndex int) error

	// List returns all stored shares.
	List(ctx context.Context) ([]*ShareEntry, error)

	// ListByServer returns all shares for a specific server.
	ListByServer(ctx context.Context, serverURL string) ([]*ShareEntry, error)

	// ListByGroup returns all shares for a specific group ID.
	ListByGroup(ctx context.Context, groupID string) ([]*ShareEntry, error)

	// Close closes the store.
	Close() error
}
