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
	"path/filepath"
)

// PutIfAbsent validates the key, then delegates the atomic check-then-write to
// the wrapped go-qrdb file engine (whose engineBackend serializes the
// Exists+Set under a mutex, making it genuinely atomic for this single-writer
// process). When the value is newly written it applies the same prefix-based
// file permissions Put does (keys/* = 0600, certs/* = 0644).
func (f *FileStorage) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	if err := validateStorageKey(key); err != nil {
		return false, fmt.Errorf("file storage: invalid key %q: %w", key, err)
	}
	stored, err := f.backend.PutIfAbsent(ctx, key, value)
	if err != nil {
		return false, err
	}
	if !stored {
		return false, nil
	}
	// The engine writes 0600; widen only the prefixes that require it.
	// The value is already persisted at this point, so a chmod failure
	// must still report stored=true — returning false would tell the
	// caller the store is unchanged when it is not, and a retry would
	// then see ErrKeyAlreadyExists for a key it "never stored".
	if perm := filePermissionsForKey(key); perm != defaultPerms {
		path := filepath.Join(f.rootDir, filepath.FromSlash(key))
		if err := os.Chmod(path, perm); err != nil {
			return true, fmt.Errorf("file storage: failed to set permissions for key %q: %w", key, err)
		}
	}
	return true, nil
}
