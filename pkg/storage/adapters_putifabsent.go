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

package storage

import "context"

// SaveKeyIfAbsent stores key data for id only when no key already exists at
// KeyPath(id). Returns stored=false when the key was already present.
// Returns ErrInvalidID if the ID is empty.
func SaveKeyIfAbsent(ctx context.Context, backend Backend, id string, keyData []byte) (bool, error) {
	if id == "" {
		return false, ErrInvalidID
	}
	return backend.PutIfAbsent(ctx, KeyPath(id), keyData)
}
