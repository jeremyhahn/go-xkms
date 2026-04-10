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

package staticpw

import "time"

// PasswordEntity is the DAO entity representation of a static password entry.
// It implements the go-qrdb Entity interface for persistent storage.
type PasswordEntity struct {
	ID            uint64    `json:"id"`
	Name          string    `json:"name" index:"unique,ci"`
	Title         string    `json:"title"`
	Username      string    `json:"username"`
	Password      string    `json:"password"`
	URL           string    `json:"url"`
	MatchPatterns []string  `json:"match_patterns,omitempty"`
	Notes         string    `json:"notes,omitempty"`
	FolderPath    string    `json:"folder_path" index:"true"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	OwnerID       string    `json:"owner_id" index:"true"`
	Shared        bool      `json:"shared" index:"true"`
	TenantID      string    `json:"tenant_id" index:"true"`
}

// EntityID returns the entity's unique identifier.
func (e *PasswordEntity) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's unique identifier.
func (e *PasswordEntity) SetEntityID(id uint64) { e.ID = id }
