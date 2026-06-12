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

import "context"

// PutIfAbsent delegates to the unlocked delegate backend's PutIfAbsent,
// mirroring Put. Returns ErrVolumeLocked if the volume is not unlocked. The
// atomicity guarantee is exactly that of the delegate (the file engine):
// LUKS adds no writer of its own.
func (b *Backend) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	delegate, err := b.getDelegate()
	if err != nil {
		return false, err
	}
	return delegate.PutIfAbsent(ctx, key, value)
}
