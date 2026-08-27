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

var _ CompareAndDeleter = (*PrefixBackend)(nil)

// CompareAndDelete prefixes the key and delegates to the wrapped backend's
// CompareAndDelete. The atomicity guarantee is exactly that of the wrapped
// backend: PrefixBackend adds no writer of its own, it only namespaces the key.
// It errors if the wrapped backend does not implement CompareAndDeleter.
//
// The guard value is passed through untouched — PrefixBackend transforms keys,
// never values — so the wrapped backend compares the exact bytes it holds.
func (p *PrefixBackend) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	cad, ok := p.inner.(CompareAndDeleter)
	if !ok {
		return false, ErrCompareAndDeleteUnsupported
	}
	return cad.CompareAndDelete(ctx, p.prefix+key, expected)
}
