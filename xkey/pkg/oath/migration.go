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

package oath

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// ErrMigrationFailed is returned when migration from the legacy backend fails.
type ErrMigrationFailed struct {
	Key   string
	Cause error
}

// Error implements the error interface.
func (e ErrMigrationFailed) Error() string {
	return fmt.Sprintf("oath: migration failed for key %q: %v", e.Key, e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrMigrationFailed) Unwrap() error {
	return e.Cause
}

// MigrateFromBackend migrates all OATH credentials from a legacy
// storage.Backend (flat key/value store) to a DAOStore. Each credential
// stored under the given prefix is unmarshaled, converted to an entity,
// and saved via the DAO. Successfully migrated keys are deleted from the
// legacy backend.
//
// The function is idempotent: credentials that already exist in the
// DAOStore (by name) are skipped without error.
func MigrateFromBackend(ctx context.Context, backend storage.Backend, prefix string, daoStore *DAOStore) error {
	if backend == nil {
		return ErrNilBackend
	}
	if daoStore == nil {
		return fmt.Errorf("oath: nil DAO store for migration")
	}

	keys, err := backend.List(ctx, prefix)
	if err != nil {
		return fmt.Errorf("oath: failed to list legacy keys: %w", err)
	}

	for _, key := range keys {
		data, err := backend.Get(ctx, key)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				continue
			}
			return ErrMigrationFailed{Key: key, Cause: err}
		}

		var cred Credential
		if err := json.Unmarshal(data, &cred); err != nil {
			return ErrMigrationFailed{Key: key, Cause: err}
		}

		// Attempt to add; skip if duplicate (already migrated).
		if addErr := daoStore.Add(&cred); addErr != nil {
			if errors.Is(addErr, ErrCredentialExists) {
				// Already migrated, delete old key.
				_ = backend.Delete(ctx, key)
				continue
			}
			return ErrMigrationFailed{Key: key, Cause: addErr}
		}

		// Successfully migrated, delete old key.
		if delErr := backend.Delete(ctx, key); delErr != nil {
			// Non-fatal: the credential is already in the DAO store.
			// Log or ignore; the next migration run will skip it.
			continue
		}
	}

	return nil
}
