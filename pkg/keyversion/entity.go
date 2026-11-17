// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package keyversion

import "time"

// Entity is the DAO entity of one key's version record. Name, the record's
// "{tenant}/{backend}/{keyID}" triple, is its natural key: the entity ID is
// derived from it, so a record is read and written by name.
type Entity struct {
	ID   uint64 `json:"id"`
	Name string `json:"name"`
	Record

	// Claim is the rotation that owns the backend key name of the record's
	// next version, if any (Store.Claim).
	Claim *rotationClaim `json:"rotation_claim,omitempty"`
}

// rotationClaim marks a version record as claimed by one rotation: only its
// holder creates or removes the backend key under the next version's name,
// and records that version.
type rotationClaim struct {
	Token   string    `json:"token"`
	Expires time.Time `json:"expires"`

	// Version is the version number reserved for the claim: only its holder
	// creates, removes or records the backend key under that version's
	// name. Every later claim reserves a higher number, so a holder whose
	// claim was taken over never touches its successor's key. A released
	// claim keeps an empty Token and its Version as the floor for the next.
	Version uint32 `json:"version,omitempty"`
}

// EntityID returns the entity's unique identifier.
func (e *Entity) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's unique identifier.
func (e *Entity) SetEntityID(id uint64) { e.ID = id }

func newEntity() *Entity { return &Entity{} }
