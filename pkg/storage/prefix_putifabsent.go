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

// PutIfAbsent prefixes the key and delegates to the wrapped backend's
// PutIfAbsent. The atomicity guarantee is exactly that of the wrapped backend:
// PrefixBackend adds no writer of its own, it only namespaces the key.
func (p *PrefixBackend) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	return p.inner.PutIfAbsent(ctx, p.prefix+key, value)
}
