// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0)
// for non-commercial use. Commercial licenses are available.
// See LICENSE and LICENSE-COMMERCIAL for details.

package services

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

// testBarrierPassword is the throwaway passphrase newUnsealedTestBarrierService
// seals its barrier under. It exists only for the lifetime of one test's temp
// directory and is never asserted on, so a fixed value is fine.
const testBarrierPassword = "test-barrier-password-not-a-secret"

// newUnsealedTestBarrierService returns a real BarrierService, initialized
// and unsealed under a throwaway software passphrase in a temp directory, for
// PhoneService tests that need a barrier available to seal the local Noise
// static private key on Pair and unseal it on Connect (#42). It is distinct
// from newTestBarrierService (barrier_service_test.go), which returns one
// that is constructed but not yet initialized.
func newUnsealedTestBarrierService(t *testing.T) *BarrierService {
	t.Helper()
	svc := NewBarrierService(t.TempDir(), slog.Default())
	require.NoError(t, svc.Initialize(testBarrierPassword, "passphrase"))
	return svc
}
