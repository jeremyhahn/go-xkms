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

package audit

import (
	"context"
	"encoding/json"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// MigrateFromBackend scans old prefix-keyed audit entries from a
// storage.Backend and saves them into the DAOAuditStore. Entries are
// read chronologically (sorted by key), converted to entities, and
// persisted via the DAO. After each entry is migrated successfully,
// the old key is deleted from the source backend. Entries that fail
// to unmarshal are skipped and reported as ErrMigration errors.
func MigrateFromBackend(ctx context.Context, backend storage.Backend, daoStore *DAOAuditStore) []error {
	if backend == nil || daoStore == nil {
		return nil
	}

	keys, err := backend.List(ctx, keyPrefix)
	if err != nil {
		return []error{ErrMigration{Key: keyPrefix, Cause: err}}
	}

	var migrationErrors []error

	for _, key := range keys {
		data, getErr := backend.Get(ctx, key)
		if getErr != nil {
			migrationErrors = append(migrationErrors, ErrMigration{Key: key, Cause: getErr})
			continue
		}

		var entry Entry
		if unmarshalErr := json.Unmarshal(data, &entry); unmarshalErr != nil {
			migrationErrors = append(migrationErrors, ErrMigration{Key: key, Cause: unmarshalErr})
			continue
		}

		entity := entryToEntity(entry)
		if saveErr := daoStore.dao.Save(ctx, entity); saveErr != nil {
			migrationErrors = append(migrationErrors, ErrMigration{Key: key, Cause: saveErr})
			continue
		}

		// Add to ring buffer cache.
		daoStore.mu.Lock()
		if len(daoStore.cache) >= daoStore.maxSize {
			daoStore.cache = daoStore.cache[1:]
		}
		daoStore.cache = append(daoStore.cache, entry)
		daoStore.mu.Unlock()

		// Delete the old key after successful migration.
		if delErr := backend.Delete(ctx, key); delErr != nil {
			migrationErrors = append(migrationErrors, ErrMigration{Key: key, Cause: delErr})
		}
	}

	return migrationErrors
}
