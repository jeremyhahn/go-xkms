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

package luks

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

var _ storage.FencedCreator = (*Backend)(nil)

// PutIfAllAbsent delegates to the unlocked delegate backend's PutIfAllAbsent;
// the atomicity is exactly the delegate's. A locked volume is an error, and a
// delegate without the capability reports storage.ErrFencedCreateUnsupported.
func (b *Backend) PutIfAllAbsent(ctx context.Context, key string, value []byte, fences ...string) (bool, error) {
	delegate, err := b.getDelegate()
	if err != nil {
		return false, err
	}
	fc, ok := delegate.(storage.FencedCreator)
	if !ok {
		return false, storage.ErrFencedCreateUnsupported
	}
	return fc.PutIfAllAbsent(ctx, key, value, fences...)
}
