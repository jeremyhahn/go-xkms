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
)

// PutIfAbsent validates the key, then delegates the atomic check-then-write to
// the wrapped go-qrdb file engine under this store's cross-process advisory
// lock (lock.go), holding out both the engineBackend mutex that makes this
// genuinely atomic within the process AND every other process guarding or
// writing the same store directory (#1157). When the value is newly written
// it applies the same prefix-based file permissions Put does (keys/* = 0600,
// certs/* = 0644).
func (f *FileStorage) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	if err := validateStorageKey(key); err != nil {
		return false, &errs.Wrapped{Msg: fmt.Sprintf("file storage: invalid key %q", key), Err: err}
	}
	var stored bool
	err := withCrossProcessLock(ctx, f.lockPath, func() error {
		var piaErr error
		stored, piaErr = f.backend.PutIfAbsent(ctx, key, value)
		if piaErr != nil {
			return piaErr
		}
		if !stored {
			return nil
		}
		// The engine writes 0600; widen only the prefixes that require it.
		// The value is already persisted at this point, so a chmod failure
		// must still report stored=true — returning false would tell the
		// caller the store is unchanged when it is not, and a retry would
		// then see ErrKeyAlreadyExists for a key it "never stored".
		if perm := filePermissionsForKey(key); perm != defaultPerms {
			if err := os.Chmod(f.keyPath(key), perm); err != nil {
				return &errs.Wrapped{Msg: fmt.Sprintf("file storage: failed to set permissions for key %q", key), Err: err}
			}
		}
		return nil
	})
	return stored, err
}
