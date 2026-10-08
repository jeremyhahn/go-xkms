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
)

// PutIfAbsent validates the key, then delegates the atomic check-then-write to
// the wrapped go-qrdb file engine under this store's cross-process advisory
// lock (lock.go), holding out both the engineBackend mutex that makes this
// genuinely atomic within the process AND every other process guarding or
// writing the same store directory (#1157).
func (f *FileStorage) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	if err := validateStorageKey(key); err != nil {
		return false, &errs.Wrapped{Msg: fmt.Sprintf("file storage: invalid key %q", key), Err: err}
	}
	var stored bool
	err := withCrossProcessLock(ctx, f.rootDir, func() error {
		var piaErr error
		stored, piaErr = f.backend.PutIfAbsent(ctx, key, value)
		return piaErr
	})
	return stored, err
}
