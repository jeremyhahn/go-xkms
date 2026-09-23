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

package agent

import "time"

// AgentEntity is the DAO entity representation of an AgentInfo.
// It implements the go-qrdb Entity interface for persistent storage.
type AgentEntity struct {
	ID              uint64    `json:"id"`
	DeviceID        string    `json:"device_id" index:"unique"`
	Name            string    `json:"name"`
	Address         string    `json:"address"`
	CertFingerprint string    `json:"cert_fingerprint"`
	CertSerial      string    `json:"cert_serial"`
	Status          string    `json:"status"`
	EnrolledAt      time.Time `json:"enrolled_at"`
	LastSeenAt      time.Time `json:"last_seen_at"`
}

// EntityID returns the entity's unique identifier.
func (e *AgentEntity) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's unique identifier.
func (e *AgentEntity) SetEntityID(id uint64) { e.ID = id }

// ToAgentInfo converts the entity to an AgentInfo domain type.
func (e *AgentEntity) ToAgentInfo() *AgentInfo {
	return &AgentInfo{
		ID:                     e.DeviceID,
		Name:                   e.Name,
		Address:                e.Address,
		CertificateFingerprint: e.CertFingerprint,
		CertificateSerial:      e.CertSerial,
		Status:                 e.Status,
		EnrolledAt:             e.EnrolledAt,
		LastSeen:               e.LastSeenAt,
	}
}

// AgentEntityFromInfo creates an AgentEntity from an AgentInfo domain type.
func AgentEntityFromInfo(info *AgentInfo) *AgentEntity {
	return &AgentEntity{
		DeviceID:        info.ID,
		Name:            info.Name,
		Address:         info.Address,
		CertFingerprint: info.CertificateFingerprint,
		CertSerial:      info.CertificateSerial,
		Status:          info.Status,
		EnrolledAt:      info.EnrolledAt,
		LastSeenAt:      info.LastSeen,
	}
}

// CodeEntity is the DAO entity representation of a one-time enrollment
// code. Only the code's hash is stored; the plaintext code value never
// reaches persistent storage.
type CodeEntity struct {
	ID        uint64    `json:"id"`
	Hash      string    `json:"hash" index:"unique"`
	ExpiresAt time.Time `json:"expires_at"`
}

// EntityID returns the entity's unique identifier.
func (e *CodeEntity) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's unique identifier.
func (e *CodeEntity) SetEntityID(id uint64) { e.ID = id }

// PendingEntity is the DAO entity representation of a PendingEnrollment.
type PendingEntity struct {
	ID          uint64    `json:"id"`
	RequestID   string    `json:"request_id" index:"unique"`
	CSR         []byte    `json:"csr"`
	Fingerprint string    `json:"fingerprint"`
	RequestedAt time.Time `json:"requested_at"`
	Status      string    `json:"status"`
}

// EntityID returns the entity's unique identifier.
func (e *PendingEntity) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's unique identifier.
func (e *PendingEntity) SetEntityID(id uint64) { e.ID = id }

// ToPendingEnrollment converts the entity to a PendingEnrollment domain type.
func (e *PendingEntity) ToPendingEnrollment() *PendingEnrollment {
	return &PendingEnrollment{
		ID:          e.RequestID,
		CSR:         e.CSR,
		Fingerprint: e.Fingerprint,
		RequestedAt: e.RequestedAt,
		Status:      e.Status,
	}
}

// PendingEntityFromDomain creates a PendingEntity from a PendingEnrollment
// domain type.
func PendingEntityFromDomain(p *PendingEnrollment) *PendingEntity {
	return &PendingEntity{
		RequestID:   p.ID,
		CSR:         p.CSR,
		Fingerprint: p.Fingerprint,
		RequestedAt: p.RequestedAt,
		Status:      p.Status,
	}
}
