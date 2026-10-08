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

package file

import (
	"context"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

var _ storage.FencedCreator = (*FileStorage)(nil)

// PutIfAllAbsent validates the key and every fence, then delegates the fenced
// create to the wrapped go-qrdb file engine under this store's cross-process
// advisory lock, as PutIfAbsent does, so other processes writing the same
// directory are held out too. It reports storage.ErrFencedCreateUnsupported when
// the engine does not implement storage.FencedCreator.
func (f *FileStorage) PutIfAllAbsent(ctx context.Context, key string, value []byte, fences ...string) (bool, error) {
	for _, k := range append([]string{key}, fences...) {
		if err := validateStorageKey(k); err != nil {
			return false, &errs.Wrapped{Msg: fmt.Sprintf("file storage: invalid key %q", k), Err: err}
		}
	}
	fc, ok := f.backend.(storage.FencedCreator)
	if !ok {
		return false, storage.ErrFencedCreateUnsupported
	}
	var created bool
	err := withCrossProcessLock(ctx, f.rootDir, func() error {
		var fcErr error
		created, fcErr = fc.PutIfAllAbsent(ctx, key, value, fences...)
		return fcErr
	})
	return created, err
}
