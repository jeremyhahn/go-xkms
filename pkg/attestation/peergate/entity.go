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

package peergate

import (
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/peer"
)

// evidenceEntity is the DAO entity of one peer's latest evidence. Thumbprint
// is its natural key: the entity ID is derived from it, so a peer holds at
// most one record and a new submission replaces the old one.
type evidenceEntity struct {
	ID               uint64         `json:"id"`
	Thumbprint       string         `json:"thumbprint"`
	Quote            []byte         `json:"quote"`
	Signature        []byte         `json:"signature"`
	Nonce            []byte         `json:"nonce"`
	PCRs             map[int][]byte `json:"pcrs"`
	AKCertificatePEM []byte         `json:"ak_certificate_pem"`
	CollectedAt      time.Time      `json:"collected_at"`
	ChannelBinding   []byte         `json:"channel_binding"`
}

// EntityID returns the entity's unique identifier.
func (e *evidenceEntity) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's unique identifier.
func (e *evidenceEntity) SetEntityID(id uint64) { e.ID = id }

func newEvidenceEntity() *evidenceEntity { return &evidenceEntity{} }

func entityFromRecord(r Record) *evidenceEntity {
	return &evidenceEntity{
		Thumbprint:       r.Thumbprint,
		Quote:            r.Evidence.Quote,
		Signature:        r.Evidence.Signature,
		Nonce:            r.Evidence.Nonce,
		PCRs:             r.Evidence.PCRs,
		AKCertificatePEM: r.Evidence.AKCertificatePEM,
		CollectedAt:      r.Evidence.CollectedAt,
		ChannelBinding:   r.ChannelBinding,
	}
}

func (e *evidenceEntity) record() Record {
	return Record{
		Thumbprint: e.Thumbprint,
		Evidence: peer.Evidence{
			Quote:            e.Quote,
			Signature:        e.Signature,
			Nonce:            e.Nonce,
			PCRs:             e.PCRs,
			AKCertificatePEM: e.AKCertificatePEM,
			CollectedAt:      e.CollectedAt,
		},
		ChannelBinding: e.ChannelBinding,
	}
}
