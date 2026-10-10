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

package seal

import (
	"context"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// And the guarded swap, adapted below from the barrier's two-value shape.
var _ storage.CompareAndSwapper = (*BarrierBackend)(nil)

// CompareAndSwap gives BarrierBackend the storage.CompareAndSwapper shape over
// the embedded barrier's swap, which compares the DECRYPTED stored value with
// expected and guards the write on the ciphertext it read.
//
// The barrier reports only whether it swapped. On a refusal the contract also
// owes the caller the value that is present, so it is read back through the
// barrier and therefore decrypted. That read is not part of the swap: a writer
// may land between the two, in which case the caller sees the newer value,
// which is still the right value to recompute against and retry.
//
// As in CompareAndDelete, an absent key reaches the barrier as
// storage.ErrNotFound, which it does not recognise; it is translated into the
// ordinary refusal with a nil current value. Every other failure is an error.
func (b *BarrierBackend) CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, []byte, error) {
	swapped, err := b.Barrier.CompareAndSwap(ctx, key, expected, next)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return false, nil, nil
		}
		return false, nil, err
	}
	if swapped {
		return true, nil, nil
	}
	current, err := b.Get(ctx, key)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return false, nil, nil
		}
		return false, nil, err
	}
	return false, current, nil
}
