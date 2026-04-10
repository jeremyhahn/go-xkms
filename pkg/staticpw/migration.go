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

package staticpw

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// ErrMigrationFailed is returned when migration from the legacy backend fails.
type ErrMigrationFailed struct {
	Key   string
	Cause error
}

// Error implements the error interface.
func (e ErrMigrationFailed) Error() string {
	return fmt.Sprintf("staticpw: migration failed for key %q: %v", e.Key, e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrMigrationFailed) Unwrap() error {
	return e.Cause
}

// ErrNilMigrationBackend is returned when a nil storage.Backend is provided
// to MigrateFromBackend.
type ErrNilMigrationBackend struct{}

// Error implements the error interface.
func (e ErrNilMigrationBackend) Error() string {
	return "staticpw: nil backend for migration"
}

// ErrNilMigrationDAOStore is returned when a nil DAOStore is provided
// to MigrateFromBackend.
type ErrNilMigrationDAOStore struct{}

// Error implements the error interface.
func (e ErrNilMigrationDAOStore) Error() string {
	return "staticpw: nil DAO store for migration"
}

// MigrateEntry populates Title from Name if Title is empty.
// Returns true if the entry was modified.
func MigrateEntry(pw *StaticPassword) bool {
	modified := false
	if pw.Title == "" && pw.Name != "" {
		pw.Title = pw.Name
		modified = true
	}
	return modified
}

// MigrateStore iterates all entries and migrates each one.
// Returns the count of modified entries.
func MigrateStore(store Store) (int, error) {
	passwords, err := store.List()
	if err != nil {
		return 0, err
	}

	count := 0
	for _, pw := range passwords {
		if MigrateEntry(pw) {
			if err := store.Update(pw); err != nil {
				return count, err
			}
			count++
		}
	}
	return count, nil
}

// MigrateToScopedLayout moves legacy tenant password entries from
// "{tenantID}/staticpw/{id}.json" to "{tenantID}/staticpw/shared/{id}.json".
// Entries already under "shared/" or "users/" are skipped. Returns the count
// of migrated entries.
func MigrateToScopedLayout(backend storage.Backend, tenantID string) (int, error) {
	if !isValidTenantID(tenantID) {
		return 0, ErrInvalidTenantID
	}

	legacyPrefix := tenantID + "/" + defaultKeyPrefix
	sharedPrefix := legacyPrefix + "shared/"
	usersPrefix := legacyPrefix + "users/"

	keys, err := backend.List(context.Background(), legacyPrefix)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrPasswordNotFound, err)
	}

	count := 0
	for _, key := range keys {
		// Skip entries already in the scoped layout.
		if strings.HasPrefix(key, sharedPrefix) || strings.HasPrefix(key, usersPrefix) {
			continue
		}

		// Read the entry.
		data, getErr := backend.Get(context.Background(), key)
		if getErr != nil {
			continue
		}

		// Determine the new key: replace the legacy prefix with the shared prefix.
		suffix := strings.TrimPrefix(key, legacyPrefix)
		newKey := sharedPrefix + suffix

		// Unmarshal, mark as shared, re-marshal.
		var pw StaticPassword
		if unmarshalErr := json.Unmarshal(data, &pw); unmarshalErr != nil {
			continue
		}
		pw.Shared = true

		newData, marshalErr := json.Marshal(&pw)
		if marshalErr != nil {
			continue
		}

		// Write to new location.
		if putErr := backend.Put(context.Background(), newKey, newData); putErr != nil {
			return count, fmt.Errorf("%w: %v", ErrMarshalFailed, putErr)
		}

		// Delete old key.
		if delErr := backend.Delete(context.Background(), key); delErr != nil {
			return count, fmt.Errorf("%w: %v", ErrPasswordNotFound, delErr)
		}

		count++
	}

	return count, nil
}

// MigrateFromBackend migrates all static passwords from a legacy
// storage.Backend (flat key/value store) to a DAOStore. Each password
// stored under the given prefix is unmarshaled, converted to an entity,
// and saved via the DAO. Successfully migrated keys are deleted from the
// legacy backend. Folder markers (keys containing "__folders__/") are
// also migrated.
//
// The function is idempotent: passwords that already exist in the
// DAOStore (by name) are skipped without error.
func MigrateFromBackend(ctx context.Context, backend storage.Backend, prefix string, daoStore *DAOStore) error {
	if backend == nil {
		return ErrNilMigrationBackend{}
	}
	if daoStore == nil {
		return ErrNilMigrationDAOStore{}
	}

	keys, err := backend.List(ctx, prefix)
	if err != nil {
		return fmt.Errorf("staticpw: failed to list legacy keys: %w", err)
	}

	for _, key := range keys {
		// Handle folder markers.
		if strings.Contains(key, folderMarkerSuffix) {
			folder := extractFolderFromMarkerKey(key, prefix)
			if folder != "" {
				_ = daoStore.CreateFolder(folder)
			}
			_ = backend.Delete(ctx, key)
			continue
		}

		data, getErr := backend.Get(ctx, key)
		if getErr != nil {
			if errors.Is(getErr, storage.ErrNotFound) {
				continue
			}
			return ErrMigrationFailed{Key: key, Cause: getErr}
		}

		var pw StaticPassword
		if unmarshalErr := json.Unmarshal(data, &pw); unmarshalErr != nil {
			return ErrMigrationFailed{Key: key, Cause: unmarshalErr}
		}

		// Attempt to add; skip if duplicate (already migrated).
		if addErr := daoStore.Add(&pw); addErr != nil {
			if errors.Is(addErr, ErrPasswordExists) {
				_ = backend.Delete(ctx, key)
				continue
			}
			return ErrMigrationFailed{Key: key, Cause: addErr}
		}

		// Successfully migrated, delete old key.
		if delErr := backend.Delete(ctx, key); delErr != nil {
			continue
		}
	}

	return nil
}

// extractFolderFromMarkerKey extracts the folder path from a legacy
// folder marker key. The key format is "{prefix}__folders__/{folderPath}".
func extractFolderFromMarkerKey(key string, prefix string) string {
	markerPrefix := prefix + folderMarkerSuffix
	if strings.HasPrefix(key, markerPrefix) {
		return strings.TrimPrefix(key, markerPrefix)
	}
	idx := strings.Index(key, folderMarkerSuffix)
	if idx >= 0 {
		return key[idx+len(folderMarkerSuffix):]
	}
	return ""
}
