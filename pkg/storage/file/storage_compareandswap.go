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

package file

import (
	"context"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// CompareAndSwap validates the key, delegates the atomic compare-and-swap to the
// underlying engine under this store's cross-process advisory lock (lock.go,
// #1157) — the same shape as PutIfAbsent. It errors if the engine does not implement
// CompareAndSwapper.
func (f *FileStorage) CompareAndSwap(ctx context.Context, key string, expected, newValue []byte) (bool, []byte, error) {
	if err := validateStorageKey(key); err != nil {
		return false, nil, &errs.Wrapped{Msg: fmt.Sprintf("file storage: invalid key %q", key), Err: err}
	}
	cas, ok := f.backend.(storage.CompareAndSwapper)
	if !ok {
		return false, nil, storage.ErrCompareAndSwapUnsupported
	}

	var swapped bool
	var current []byte
	err := withCrossProcessLock(ctx, f.rootDir, func() error {
		var casErr error
		swapped, current, casErr = cas.CompareAndSwap(ctx, key, expected, newValue)
		if casErr != nil || !swapped {
			return casErr
		}
		current = nil
		return nil
	})
	return swapped, current, err
}
