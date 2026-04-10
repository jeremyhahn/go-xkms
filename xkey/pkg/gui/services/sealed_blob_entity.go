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

package services

import "time"

// SealedBlobEntity is the DAO entity representation of a sealed data blob.
// It captures the metadata and ciphertext for blobs sealed by the barrier
// or TPM2 backends. It implements the go-qrdb Entity interface for
// persistent storage.
type SealedBlobEntity struct {
	ID          uint64    `json:"id"`
	Label       string    `json:"label" index:"unique"`
	BackendID   string    `json:"backend_id" index:"true"`
	PolicyType  string    `json:"policy_type" index:"true"`
	PolicyName  string    `json:"policy_name"`
	StorageType string    `json:"storage_type"`
	Category    string    `json:"category" index:"true"`
	SizeBytes   int       `json:"size_bytes"`
	PCRBound    bool      `json:"pcr_bound"`
	SealedData  []byte    `json:"sealed_data"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// EntityID returns the entity's unique identifier.
func (e *SealedBlobEntity) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's unique identifier.
func (e *SealedBlobEntity) SetEntityID(id uint64) { e.ID = id }
