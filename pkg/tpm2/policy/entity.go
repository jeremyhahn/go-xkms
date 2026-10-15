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

package policy

// DatabaseName is the go-qrdb database the registry's DAOs live in. The
// composition root opens it on its datastore (xkmsd) or serves it from its
// own store (xkey's local mode) before calling NewRegistry; this package
// only names it.
const DatabaseName = "tpmpolicy"

// Entity types of the registry's DAOs.
const (
	scopeEntityType      = "tpm_scopes"
	policyEntityType     = "tpm_policies"
	assignmentEntityType = "tpm_assignments"
)

// naturalKeyField is the field every registry entity's ID is derived from.
const naturalKeyField = "Key"

// scopeEntity is a tenant's Scope record. Key is the tenant's root
// ("<tenant>/").
type scopeEntity struct {
	ID     uint64 `json:"id"`
	Key    string `json:"key"`
	Node   uint64 `json:"node"`
	Tenant string `json:"tenant"`
	Scope  Scope  `json:"scope"`
}

// EntityID returns the entity's ID.
func (e *scopeEntity) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's ID.
func (e *scopeEntity) SetEntityID(id uint64) { e.ID = id }

// policyEntity is a tenant's named Policy and its current approval. Key is
// "<tenant>/<policy name>".
type policyEntity struct {
	ID     uint64 `json:"id"`
	Key    string `json:"key"`
	Node   uint64 `json:"node"`
	Tenant string `json:"tenant"`
	Policy Policy `json:"policy"`
}

// EntityID returns the entity's ID.
func (e *policyEntity) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's ID.
func (e *policyEntity) SetEntityID(id uint64) { e.ID = id }

// assignmentEntity records the policy an object of a tenant uses. Key is
// "<tenant>/<object ID>".
type assignmentEntity struct {
	ID         uint64     `json:"id"`
	Key        string     `json:"key"`
	Node       uint64     `json:"node"`
	Tenant     string     `json:"tenant"`
	Assignment Assignment `json:"assignment"`
}

// EntityID returns the entity's ID.
func (e *assignmentEntity) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's ID.
func (e *assignmentEntity) SetEntityID(id uint64) { e.ID = id }
