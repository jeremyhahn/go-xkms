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

var _ storage.CompareAndDeleter = (*FileStorage)(nil)

// CompareAndDelete validates the key, then delegates the guarded delete to the
// wrapped go-qrdb file engine under this store's cross-process advisory lock
// (lock.go), holding out both the engineBackend mutex that serializes the
// get-compare-delete within the process AND every other process guarding or
// writing the same store directory (#1157).
//
// It needs none of the chmod handling PutIfAbsent and CompareAndSwap carry:
// those widen the permissions of a file they just wrote, and a successful
// guarded delete leaves no file to widen.
//
// Like CompareAndSwap, it errors if the engine does not implement
// storage.CompareAndDeleter.
func (f *FileStorage) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	if err := validateStorageKey(key); err != nil {
		return false, &errs.Wrapped{Msg: fmt.Sprintf("file storage: invalid key %q", key), Err: err}
	}
	cad, ok := f.backend.(storage.CompareAndDeleter)
	if !ok {
		return false, storage.ErrCompareAndDeleteUnsupported
	}
	var deleted bool
	err := withCrossProcessLock(ctx, f.rootDir, func() error {
		var cadErr error
		deleted, cadErr = cad.CompareAndDelete(ctx, key, expected)
		return cadErr
	})
	return deleted, err
}
