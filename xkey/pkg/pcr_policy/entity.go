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

// Package pcrpolicy provides named PCR policy management for TPM2 barrier
// auto-unseal. Each policy captures the expected PCR digests and hash bank
// so the barrier can verify platform state before releasing the DEK.
package pcrpolicy

import "time"

// PCRPolicyEntity is the DAO entity representation of a named PCR policy.
// It implements the go-qrdb Entity interface for persistent storage.
type PCRPolicyEntity struct {
	ID         uint64          `json:"id"`
	Name       string          `json:"name" index:"unique"`
	Bank       string          `json:"bank"`
	PCRs       map[uint][]byte `json:"pcrs"`
	AutoUnseal bool            `json:"auto_unseal" index:"true"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

// EntityID returns the entity's unique identifier.
func (e *PCRPolicyEntity) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's unique identifier.
func (e *PCRPolicyEntity) SetEntityID(id uint64) { e.ID = id }
