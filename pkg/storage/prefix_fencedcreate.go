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

package storage

import "context"

var _ FencedCreator = (*PrefixBackend)(nil)

// PutIfAllAbsent prefixes the key and every fence and delegates to the
// wrapped backend's PutIfAllAbsent; the atomicity is exactly the wrapped
// backend's. It reports ErrFencedCreateUnsupported when the wrapped backend
// does not implement FencedCreator.
func (p *PrefixBackend) PutIfAllAbsent(ctx context.Context, key string, value []byte, fences ...string) (bool, error) {
	fc, ok := p.inner.(FencedCreator)
	if !ok {
		return false, ErrFencedCreateUnsupported
	}
	prefixed := make([]string, len(fences))
	for i, f := range fences {
		prefixed[i] = p.prefix + f
	}
	return fc.PutIfAllAbsent(ctx, p.prefix+key, value, prefixed...)
}
