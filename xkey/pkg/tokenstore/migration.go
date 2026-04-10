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

package tokenstore

import (
	"context"
	"encoding/json"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// MigrateFromBackend scans old prefix-keyed token entries from a
// storage.Backend and saves them into the DAOStore. After each entry
// is migrated successfully, the old key is deleted. Entries that fail
// to unmarshal are skipped and reported via ErrMigration (collected).
//
// The prefix should match the original BackendTokenStore prefix
// (e.g., "tokens/").
func MigrateFromBackend(ctx context.Context, backend storage.Backend, daoStore *DAOStore, prefix string) []error {
	if backend == nil || daoStore == nil {
		return nil
	}

	keys, err := backend.List(ctx, prefix)
	if err != nil {
		return []error{ErrMigration{Key: prefix, Cause: err}}
	}

	var migrationErrors []error

	for _, key := range keys {
		data, getErr := backend.Get(ctx, key)
		if getErr != nil {
			migrationErrors = append(migrationErrors, ErrMigration{Key: key, Cause: getErr})
			continue
		}

		var entry TokenEntry
		if unmarshalErr := json.Unmarshal(data, &entry); unmarshalErr != nil {
			migrationErrors = append(migrationErrors, ErrMigration{Key: key, Cause: unmarshalErr})
			continue
		}

		if saveErr := daoStore.Save(ctx, &entry); saveErr != nil {
			migrationErrors = append(migrationErrors, ErrMigration{Key: key, Cause: saveErr})
			continue
		}

		// Delete the old key after successful migration.
		if delErr := backend.Delete(ctx, key); delErr != nil {
			migrationErrors = append(migrationErrors, ErrMigration{Key: key, Cause: delErr})
		}
	}

	return migrationErrors
}
