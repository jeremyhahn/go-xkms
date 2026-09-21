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
