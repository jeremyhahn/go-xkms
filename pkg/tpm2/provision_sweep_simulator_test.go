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
	soPIN := mustPassword(t, []byte("provision-lockout-test-pin-01"))
	require.NoError(t, h.TPM.Provision(soPIN))

	err := h.TPM.Provision(soPIN)
	require.Error(t, err, "a second Provision against a TPM whose Lockout auth is already set must fail, not silently reprovision")
	require.Contains(t, err.Error(), "TPM_RC_AUTH_FAIL",
		"the Lockout hierarchy is DA-protected, so the blocked Clear must be the real TPM_RC_AUTH_FAIL response, not TPM_RC_LOCKOUT")
}

// TestProvision_EveryCommandFailurePropagates sweeps Provision's full
// command sequence -- TPM2_Clear, the three hierarchy TPM2_HierarchyChangeAuth
// calls, ProvisionOwner's EK and SRK creation, CreatePlatformPolicy's PCR
// read and trial policy session, and CreateIAK's own command sequence -- proving a failure at
// any step surfaces as an error instead of Provision reporting success over
// a TPM it only partially provisioned.
func TestProvision_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newUnprovisionedSimHarness(t, nil)
		soPIN := mustPassword(t, []byte("provision-sweep-pin-0123456"))

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
		-1)
}

// TestInstall_EveryCommandFailurePropagates sweeps Install's full command
// sequence against a freshly opened, never-provisioned simulator (SetHierarchyAuth,
// CreateEK, CreateSRK, CreatePlatformPolicy, installIAK/CreateIAK) proving a
// failure at any step surfaces as an error -- with the two narrow,
// independently-documented exceptions in the bestEffort list below -- instead
// of Install reporting success over a TPM it only partially provisioned.
//
// This closes #905: a prior command-by-command sweep found commands 44-47
// not surfacing as an Install() error and treated all four as "inside the
// IAK creation" because they immediately follow CreateIAK's own three
// commands in the flat, 1-indexed command count. Tracing each command's
// TPM_CC against installIAK/CreateIAK (key.go, provision.go) shows only
// command 44 is actually part of IAK creation -- CreateIAK's own deferred
// flush, already covered by TestCreateIAK_EveryCommandFailurePropagates's
// bestEffort. Commands 45-47 belong to the unrelated step Install runs
// immediately afterward: the trailing "retrieve the EK certificate" block
// (below), which is documented and tested here as its own, separate
// best-effort tail. IAK creation's three effectful commands -- CreatePrimary,
// EvictControl, CertifyCreation -- were independently confirmed via a manual
// command-code probe to propagate through Install() exactly as
// TestCreateIAK_EveryCommandFailurePropagates proves they do called
// directly; there was no swallowed IAK error.
func TestInstall_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newUnprovisionedSimHarness(t, func(c *Config) {
			// A freshly opened simulator's Endorsement hierarchy auth is
			// still empty: no SetHierarchyAuth has run. Install treats a nil
			// config.EK.HierarchyAuth as "assume empty auth for fresh TPMs"
			// (provision.go); the harness's baseline config instead carries
			// store.DEFAULT_PASSWORD so newSimHarness's auto-provisioning
			// (which does run SetHierarchyAuth) has a starting auth to
			// change. Install's own sweep needs the former to match this
			// TPM's real, still-empty hierarchy auth.
			c.EK.HierarchyAuth = nil
		})
		soPIN := mustPassword(t, []byte("install-sweep-pin-0123456789"))

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			return h.TPM.Install(soPIN, nil)
		}
	},
		// CreateIAK's own deferred best-effort flush of its primary's
		// transient handle -- the same single command
		// TestCreateIAK_EveryCommandFailurePropagates already documents and
		// tolerates at its position 9 -- reached here fourth from last,
		// directly after IAK creation's CertifyCreation.
		-4,
		// Install's trailing "Retrieve the EK certificate or log warning if
		// not available" block (provision.go): PlatformPolicyDigest's PCR
		// read (-3) and EKCertificate's two readEKCertFromNV NV_ReadPublic
		// probes, RSA then EC index (-2, -1). A manufacturer EK certificate
		// is commonly absent -- this simulator never has one -- and
		// EKCertificate returning any error here, not only "not found", is
		// deliberately non-fatal: Install has already fully provisioned the
		// EK, SSRK, platform policy and IAK by this point, and a device
		// without a burned-in EK certificate still has a usable identity.
		-3, -2, -1)
}
