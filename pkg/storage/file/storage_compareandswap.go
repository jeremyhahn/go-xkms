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
	"os"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// CompareAndSwap validates the key, delegates the atomic compare-and-swap to the
// underlying engine, and widens the file permissions on a successful swap — the
// same shape as PutIfAbsent. It errors if the engine does not implement
// CompareAndSwapper.
func (f *FileStorage) CompareAndSwap(ctx context.Context, key string, expected, newValue []byte) (bool, []byte, error) {
	if err := validateStorageKey(key); err != nil {
		return false, nil, &errs.Wrapped{Msg: fmt.Sprintf("file storage: invalid key %q", key), Err: err}
	}
	cas, ok := f.backend.(storage.CompareAndSwapper)
	if !ok {
		return false, nil, storage.ErrCompareAndSwapUnsupported
	}
	swapped, current, err := cas.CompareAndSwap(ctx, key, expected, newValue)
	if err != nil || !swapped {
		return swapped, current, err
	}
	// The engine writes 0600; widen only the prefixes that require it. The value
	// is already persisted, so a chmod failure must still report swapped=true.
	if perm := filePermissionsForKey(key); perm != defaultPerms {
		if err := os.Chmod(f.keyPath(key), perm); err != nil {
			return true, nil, &errs.Wrapped{Msg: fmt.Sprintf("file storage: failed to set permissions for key %q", key), Err: err}
		}
	}
	return true, nil, nil
}
