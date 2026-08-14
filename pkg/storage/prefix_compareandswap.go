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

var _ CompareAndSwapper = (*PrefixBackend)(nil)

// CompareAndSwap prefixes the key and delegates to the wrapped backend's
// CompareAndSwap. The atomicity guarantee is exactly that of the wrapped backend:
// PrefixBackend adds no writer of its own, it only namespaces the key. It errors
// if the wrapped backend does not implement CompareAndSwapper.
func (p *PrefixBackend) CompareAndSwap(ctx context.Context, key string, expected, newValue []byte) (bool, []byte, error) {
	cas, ok := p.inner.(CompareAndSwapper)
	if !ok {
		return false, nil, ErrCompareAndSwapUnsupported
	}
	return cas.CompareAndSwap(ctx, p.prefix+key, expected, newValue)
}
