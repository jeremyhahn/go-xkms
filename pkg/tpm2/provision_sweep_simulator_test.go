// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/require"
)

// TestProvision_ClearBlockedByLockout_SchedulesForceClearThenFails proves
// Provision's DA-lockout recovery branch: when TPM2_Clear fails because the
// Lockout hierarchy auth is already set (a prior Provision run left it at
// soPIN, exactly as a reinstall that doesn't clear first would find it),
// Provision must recognize the TPM_RC_AUTH_FAIL failure, attempt the UEFI
// PPI ForceClear fallback, and -- since this test environment has no real
// TPM sysfs node for ForceClear to write to -- return the original Clear
// error rather than silently continuing to provision over a TPM it never
// actually cleared. hardResetViaSysRq is deliberately never reached here:
// it is gated behind ForceClear succeeding, which requires real TPM sysfs
// support this process must not touch.
func TestProvision_ClearBlockedByLockout_SchedulesForceClearThenFails(t *testing.T) {
	h := newUnprovisionedSimHarness(t, nil)
	soPIN := mustPassword([]byte("provision-lockout-test-pin-01"))
	require.NoError(t, h.TPM.Provision(soPIN))

	err := h.TPM.Provision(soPIN)
	require.Error(t, err, "a second Provision against a TPM whose Lockout auth is already set must fail, not silently reprovision")
	require.Contains(t, err.Error(), "TPM_RC_AUTH_FAIL",
		"the Lockout hierarchy is DA-protected, so the blocked Clear must be the real TPM_RC_AUTH_FAIL response, not TPM_RC_LOCKOUT")
}

// TestProvision_EveryCommandFailurePropagates sweeps Provision's full
// command sequence -- TPM2_Clear, the three hierarchy TPM2_HierarchyChangeAuth
// calls, ProvisionOwner's EK and SRK creation, CreatePlatformPolicy's PCR
// read/extend, and CreateIAK's own command sequence -- proving a failure at
// any step surfaces as an error instead of Provision reporting success over
// a TPM it only partially provisioned.
func TestProvision_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newUnprovisionedSimHarness(t, nil)
		soPIN := mustPassword([]byte("provision-sweep-pin-0123456"))

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			return h.TPM.Provision(soPIN)
		}
	},
		// The last command is CreateIAK's own deferred best-effort flush of
		// its primary's transient handle (see
		// TestCreateIAK_EveryCommandFailurePropagates); like every other
		// tpm.Flush call in this package it logs a failure instead of
		// returning it, and a defer always runs last.
		34)
}
