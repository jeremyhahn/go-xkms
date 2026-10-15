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

package truststore

import "time"

// TrustCertEntity is the DAO entity representation of a trusted certificate.
// It implements the go-qrdb Entity interface for persistent storage.
type TrustCertEntity struct {
	ID          uint64    `json:"id"`
	Fingerprint string    `json:"fingerprint" index:"unique"`
	Purpose     string    `json:"purpose" index:"true"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	Algorithm   string    `json:"algorithm"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	PEM         string    `json:"pem"`
	Source      string    `json:"source"`
	AddedAt     time.Time `json:"added_at"`
}

// EntityID returns the entity's unique identifier.
func (e *TrustCertEntity) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's unique identifier.
func (e *TrustCertEntity) SetEntityID(id uint64) { e.ID = id }

// TrustCertEntityFromMetadata creates a TrustCertEntity from CertMetadata
// and the PEM-encoded certificate data.
func TrustCertEntityFromMetadata(meta *CertMetadata, pemData string) *TrustCertEntity {
	return &TrustCertEntity{
		Fingerprint: meta.Fingerprint,
		Purpose:     string(meta.Purpose),
		Subject:     meta.Subject,
		Issuer:      meta.Issuer,
		Algorithm:   meta.Algorithm,
		NotBefore:   meta.NotBefore,
		NotAfter:    meta.NotAfter,
		PEM:         pemData,
		Source:      meta.Source,
		AddedAt:     meta.AddedAt,
	}
}
