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

package entities

import "hash/fnv"

// StringToEntityID converts a string identifier to a uint64 entity ID
// using FNV-1a hashing. This enables string-keyed entities like
// ExternalAccountBinding (kid) and Tenant (id) to implement the
// qrdbsdk.Entity interface which requires uint64 IDs.
func StringToEntityID(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64()
}
