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

package serverregistry

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// MigrateToDAO migrates server entries from the legacy BackendServerRegistry
// (prefix-keyed JSON blobs) to the DAO-backed DAOStore. It scans all keys
// matching the given prefix in the old backend, deserializes each entry,
// registers it in the DAOStore, and deletes the old key.
//
// Entries that already exist in the DAOStore are skipped (idempotent).
// Returns the number of entries migrated and any error encountered.
func MigrateToDAO(ctx context.Context, oldBackend storage.Backend, prefix string, newStore *DAOStore) (int, error) {
	if oldBackend == nil {
		return 0, ErrMigration{Cause: ErrNilBackend}
	}
	if newStore == nil {
		return 0, ErrMigration{Cause: ErrNilKVStore}
	}

	keys, err := oldBackend.List(ctx, prefix)
	if err != nil {
		return 0, ErrMigration{Cause: err}
	}

	migrated := 0
	for _, key := range keys {
		data, err := oldBackend.Get(ctx, key)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				// Entry disappeared between List and Get; skip.
				continue
			}
			return migrated, ErrMigration{Cause: err}
		}

		var entry ServerEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			slog.Warn("serverregistry: skipping malformed entry during migration",
				"key", key, "error", err)
			continue
		}

		if err := entry.Validate(); err != nil {
			slog.Warn("serverregistry: skipping invalid entry during migration",
				"key", key, "error", err)
			continue
		}

		// Register in the new store. ErrServerExists means already migrated.
		if err := newStore.Register(ctx, &entry); err != nil {
			if errors.Is(err, ErrServerExists) {
				// Already migrated; delete old key.
				_ = oldBackend.Delete(ctx, key)
				continue
			}
			return migrated, ErrMigration{Cause: err}
		}

		// Remove old key after successful migration.
		if err := oldBackend.Delete(ctx, key); err != nil {
			slog.Warn("serverregistry: failed to delete old key after migration",
				"key", key, "error", err)
		}

		migrated++
	}

	return migrated, nil
}
