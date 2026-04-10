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

package oidc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// ErrMigration is returned when migration of an individual key fails.
type ErrMigration struct {
	Key   string
	Cause error
}

// Error implements the error interface.
func (e ErrMigration) Error() string {
	return fmt.Sprintf("oidc: migration failed for key %q: %v", e.Key, e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrMigration) Unwrap() error {
	return e.Cause
}

// MigrateFromBackend scans old prefix-keyed token entries from a
// storage.Backend and saves them into the DAOStore. After each entry
// is migrated successfully, the old key is deleted. Entries that fail
// to unmarshal are skipped and reported via ErrMigration (collected).
//
// The prefix should match the original BackendTokenStore prefix
// (e.g., "oidc/tokens/").
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

		var tokens TokenResponse
		if unmarshalErr := json.Unmarshal(data, &tokens); unmarshalErr != nil {
			migrationErrors = append(migrationErrors, ErrMigration{Key: key, Cause: unmarshalErr})
			continue
		}

		// Extract issuer from the key. The BackendTokenStore stores keys
		// as prefix + sanitized_issuer + ".json". We use the key itself
		// as issuer since the DAO will normalize it.
		issuer := extractIssuerFromKey(key, prefix)
		if issuer == "" {
			migrationErrors = append(migrationErrors, ErrMigration{Key: key, Cause: fmt.Errorf("cannot extract issuer from key")})
			continue
		}

		if saveErr := daoStore.Save(issuer, &tokens); saveErr != nil {
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

// extractIssuerFromKey extracts the issuer name from a storage key by
// stripping the prefix and ".json" suffix. The remaining string is the
// sanitized issuer name (with URL characters replaced by underscores).
func extractIssuerFromKey(key, prefix string) string {
	name := key
	if len(prefix) > 0 && len(key) > len(prefix) {
		name = key[len(prefix):]
	}
	// Strip .json suffix if present.
	if len(name) > 5 && name[len(name)-5:] == ".json" {
		name = name[:len(name)-5]
	}
	return name
}
