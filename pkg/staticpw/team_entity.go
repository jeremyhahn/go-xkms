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

// TeamEntity is the DAO entity representation of a team for password sharing.
// It implements the go-qrdb Entity interface for persistent storage.
type TeamEntity struct {
	ID        uint64    `json:"id"`
	Name      string    `json:"name" index:"unique"`
	TenantID  string    `json:"tenant_id" index:"true"`
	OwnerID   string    `json:"owner_id" index:"true"`
	Members   []string  `json:"members"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// EntityID returns the entity's unique identifier.
func (e *TeamEntity) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's unique identifier.
func (e *TeamEntity) SetEntityID(id uint64) { e.ID = id }
