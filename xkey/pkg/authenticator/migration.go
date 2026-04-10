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

package authenticator

import "log/slog"

// MigrateCredentials migrates all credentials from the old BackendStorage
// (or any StatefulCredentialStorage) to a DAOCredentialStore. Each credential
// is loaded from the source and stored in the destination. Authenticator
// state is also migrated if present.
//
// Credentials that fail to migrate are logged and skipped rather than
// aborting the entire migration. The returned error slice contains one
// ErrMigration per failed credential.
func MigrateCredentials(
	source StatefulCredentialStorage,
	dest *DAOCredentialStore,
	logger *slog.Logger,
) []error {
	if logger == nil {
		logger = slog.Default()
	}

	var errs []error

	// Migrate authenticator state first.
	state, err := source.LoadState()
	if err == nil && state != nil {
		if saveErr := dest.SaveState(state); saveErr != nil {
			logger.Error("failed to migrate authenticator state",
				"error", saveErr)
			errs = append(errs, saveErr)
		} else {
			logger.Info("migrated authenticator state")
		}
	}

	// List all credentials from source.
	listable, ok := source.(ListableStorage)
	if !ok {
		logger.Warn("source storage does not implement ListableStorage, skipping credential migration")
		return errs
	}

	credIDs, err := listable.ListAll()
	if err != nil {
		logger.Error("failed to list credentials from source", "error", err)
		errs = append(errs, err)
		return errs
	}

	migrated := 0
	for _, credID := range credIDs {
		cred, loadErr := source.Load(credID)
		if loadErr != nil {
			migErr := ErrMigration{
				CredentialIDHex: string(credID),
				Cause:           loadErr,
			}
			logger.Error("failed to load credential during migration",
				"credential_id", credID,
				"error", loadErr)
			errs = append(errs, migErr)
			continue
		}

		if storeErr := dest.Store(cred); storeErr != nil {
			migErr := ErrMigration{
				CredentialIDHex: cred.RPID,
				Cause:           storeErr,
			}
			logger.Error("failed to store credential during migration",
				"credential_id", credID,
				"rp_id", cred.RPID,
				"error", storeErr)
			errs = append(errs, migErr)
			continue
		}

		migrated++
	}

	logger.Info("credential migration complete",
		"migrated", migrated,
		"errors", len(errs))

	return errs
}

// MigrateRPPolicies migrates all RP policies from the old RPPolicyStore
// to a DAORPPolicyStore.
func MigrateRPPolicies(
	source RPPolicyStore,
	dest *DAORPPolicyStore,
	logger *slog.Logger,
) []error {
	if logger == nil {
		logger = slog.Default()
	}

	var errs []error

	policies, err := source.ListPolicies()
	if err != nil {
		logger.Error("failed to list RP policies from source", "error", err)
		errs = append(errs, err)
		return errs
	}

	migrated := 0
	for _, policy := range policies {
		if setErr := dest.SetPolicy(policy); setErr != nil {
			logger.Error("failed to migrate RP policy",
				"rp_id", policy.RPID,
				"error", setErr)
			errs = append(errs, setErr)
			continue
		}
		migrated++
	}

	logger.Info("RP policy migration complete",
		"migrated", migrated,
		"errors", len(errs))

	return errs
}
