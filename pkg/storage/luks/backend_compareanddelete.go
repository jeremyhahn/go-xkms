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

package luks

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

var _ storage.CompareAndDeleter = (*Backend)(nil)

// CompareAndDelete delegates to the unlocked delegate backend's
// CompareAndDelete, mirroring Delete. Returns ErrVolumeLocked if the volume is
// not unlocked, and ErrCompareAndDeleteUnsupported if the delegate does not
// implement storage.CompareAndDeleter. The atomicity guarantee is exactly that
// of the delegate (the file engine): LUKS adds no writer of its own.
//
// A locked volume is reported as an ERROR, not as deleted=false. The store may
// well still hold the key — the volume being unavailable says nothing about the
// guard — and deleted=false would tell the caller its release was evaluated and
// refused, which is a different fact.
func (b *Backend) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	delegate, err := b.getDelegate()
	if err != nil {
		return false, err
	}
	cad, ok := delegate.(storage.CompareAndDeleter)
	if !ok {
		return false, storage.ErrCompareAndDeleteUnsupported
	}
	return cad.CompareAndDelete(ctx, key, expected)
}
