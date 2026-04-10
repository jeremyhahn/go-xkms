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

package custodian

import "time"

// Purpose constants for custodian groups.
const (
	PurposeBarrier    = "barrier"
	PurposeSigningKey = "signing-key"
	PurposeBackup     = "backup"
)

// Method constants for share delivery.
const (
	MethodFIDO2  = "fido2"
	MethodPKCS11 = "pkcs11"
	MethodManual = "manual"
)

// CustodianGroup represents an M-of-N custodian group for key ceremonies.
type CustodianGroup struct {
	ID        string            `json:"id"`
	TenantID  string            `json:"tenant_id,omitempty"` // empty = system-level
	Name      string            `json:"name"`
	Purpose   string            `json:"purpose"`   // "barrier", "signing-key", "backup"
	Threshold int               `json:"threshold"` // M
	Total     int               `json:"total"`     // N
	Members   []CustodianMember `json:"members"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// CustodianMember represents a member of a custodian group.
type CustodianMember struct {
	ShareIndex int        `json:"share_index"`
	UserID     string     `json:"user_id"`
	Username   string     `json:"username"`
	AssignedAt time.Time  `json:"assigned_at"`
	ReceivedAt *time.Time `json:"received_at,omitempty"` // nil if not yet picked up
	Method     string     `json:"method"`                // "fido2", "pkcs11", "manual"
}

// HasReceived reports whether this member has received their share.
func (m *CustodianMember) HasReceived() bool {
	return m.ReceivedAt != nil
}

// IsFull reports whether the group has reached its maximum number of members.
func (g *CustodianGroup) IsFull() bool {
	return len(g.Members) >= g.Total
}

// ReceivedCount returns the number of members who have received their share.
func (g *CustodianGroup) ReceivedCount() int {
	count := 0
	for _, m := range g.Members {
		if m.HasReceived() {
			count++
		}
	}
	return count
}

// HasMember checks if a user is a member of the group.
func (g *CustodianGroup) HasMember(userID string) bool {
	for _, m := range g.Members {
		if m.UserID == userID {
			return true
		}
	}
	return false
}

// GetMember returns a pointer to the member with the given userID, or nil.
func (g *CustodianGroup) GetMember(userID string) *CustodianMember {
	for i := range g.Members {
		if g.Members[i].UserID == userID {
			return &g.Members[i]
		}
	}
	return nil
}

// Validate checks the group configuration for correctness.
func (g *CustodianGroup) Validate() error {
	if g.ID == "" {
		return ErrEmptyGroupID
	}
	if g.Name == "" {
		return ErrEmptyGroupName
	}
	if g.Purpose == "" {
		return ErrInvalidPurpose
	}
	if g.Threshold < 2 {
		return ErrInvalidThreshold
	}
	if g.Total < g.Threshold {
		return ErrInvalidTotalShares
	}
	return nil
}
