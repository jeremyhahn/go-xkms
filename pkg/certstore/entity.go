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

package certstore

// DatabaseName is the go-qrdb database the CA's certificate DAOs live in.
// The composition root opens it on its datastore (xkmsd) or serves it from
// an in-memory store (a one-shot CA such as the init ceremony's) before
// calling New; this package only names it.
const DatabaseName = "ca"

// Entity types of the certificate store's DAOs.
const (
	certificateEntityType = "certificates"
	chainEntityType       = "certificate_chains"
)

// naturalKeyField is the field every certificate store entity's ID is
// derived from.
const naturalKeyField = "Key"

// certificateEntity is one stored certificate. Key is the certificate's
// CertificateKey; DER is its ASN.1 DER encoding.
type certificateEntity struct {
	ID  uint64 `json:"id"`
	Key string `json:"key"`
	DER []byte `json:"der"`
}

// EntityID returns the entity's ID.
func (e *certificateEntity) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's ID.
func (e *certificateEntity) SetEntityID(id uint64) { e.ID = id }

// chainEntity is one stored certificate chain, leaf first. Key is the
// leaf's CertificateKey; DER holds each certificate's DER encoding.
type chainEntity struct {
	ID  uint64   `json:"id"`
	Key string   `json:"key"`
	DER [][]byte `json:"der"`
}

// EntityID returns the entity's ID.
func (e *chainEntity) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's ID.
func (e *chainEntity) SetEntityID(id uint64) { e.ID = id }
