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

package pkcs11state

// Record is the DAO entity of one opaque module record. Name,
// "{tenant}/{token}/{key}", is its natural key: the entity ID is derived from
// it. Scope, "{tenant}/{token}/", names the token namespace List filters by,
// and Key is the record's namespace-relative key.
type Record struct {
	ID    uint64 `json:"id"`
	Name  string `json:"name"`
	Scope string `json:"scope"`
	Key   string `json:"key"`
	Value []byte `json:"value"`
}

// EntityID returns the entity's unique identifier.
func (r *Record) EntityID() uint64 { return r.ID }

// SetEntityID sets the entity's unique identifier.
func (r *Record) SetEntityID(id uint64) { r.ID = id }

func newRecord() *Record { return &Record{} }
