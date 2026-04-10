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

package serverregistry

import "time"

// ServerEntity is the DAO entity representation of a ServerEntry.
// It implements the go-qrdb Entity interface for persistent storage.
type ServerEntity struct {
	ID              uint64    `json:"id"`
	URL             string    `json:"url" index:"unique,ci"`
	Name            string    `json:"name"`
	CAFingerprint   string    `json:"ca_fingerprint"`
	Protocol        string    `json:"protocol" index:"true"`
	RegisteredAt    time.Time `json:"registered_at"`
	LastConnectedAt time.Time `json:"last_connected_at"`
}

// EntityID returns the entity's unique identifier.
func (e *ServerEntity) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's unique identifier.
func (e *ServerEntity) SetEntityID(id uint64) { e.ID = id }

// ToServerEntry converts the entity to a ServerEntry domain type.
func (e *ServerEntity) ToServerEntry() *ServerEntry {
	return &ServerEntry{
		URL:             e.URL,
		Name:            e.Name,
		CAFingerprint:   e.CAFingerprint,
		Protocol:        e.Protocol,
		RegisteredAt:    e.RegisteredAt,
		LastConnectedAt: e.LastConnectedAt,
	}
}

// ServerEntityFromEntry creates a ServerEntity from a ServerEntry domain type.
func ServerEntityFromEntry(entry *ServerEntry) *ServerEntity {
	return &ServerEntity{
		URL:             entry.URL,
		Name:            entry.Name,
		CAFingerprint:   entry.CAFingerprint,
		Protocol:        entry.Protocol,
		RegisteredAt:    entry.RegisteredAt,
		LastConnectedAt: entry.LastConnectedAt,
	}
}
