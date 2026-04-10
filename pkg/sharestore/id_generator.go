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

package sharestore

import (
	"github.com/cespare/xxhash/v2"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// shareEntryIDGenerator generates deterministic IDs by hashing the composite
// key (ServerURL/GroupID/ShareIndex) of a ShareEntry using xxhash64.
type shareEntryIDGenerator struct{}

// Compile-time interface compliance check.
var _ qrdbsdk.IDGenerator = (*shareEntryIDGenerator)(nil)

// NextID computes the xxhash64 of the ShareEntry's composite key.
// Returns 0 if the entity is not a *ShareEntry.
func (g *shareEntryIDGenerator) NextID(entity qrdbsdk.Entity) uint64 {
	entry, ok := entity.(*ShareEntry)
	if !ok {
		return 0
	}
	return xxhash.Sum64String(entry.CompositeKey())
}
