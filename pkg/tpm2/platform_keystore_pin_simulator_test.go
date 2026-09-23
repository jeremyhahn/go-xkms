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

//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file covers PIN verification against a real Platform SRK: the dictionary
// attack accounting that throttles PIN guessing, and the auth probe on an SRK
// created WITHOUT the platform PCR policy.
//
// These properties were previously asserted against an external swtpm daemon on
// 127.0.0.1:2321 and skipped whenever nothing was listening -- which, in every
// unit-test run, was always. They now run in process against the go-tpm-tools
// simulator, so they execute unconditionally and never open a host TPM device.
// The remaining swtpm-only assertions (a correct PIN authorizes, a wrong PIN is
// reported as ErrAuthFailed, enrollment is idempotent and rejects an empty PIN)
// are asserted against the same simulator in
// platform_keystore_enroll_simulator_test.go and are not duplicated here.
//
// Each test owns one simulator via newSimHarness; the simulator is a
// process-global singleton, so only one may be live at a time.

// TestPlatformKeyStore_WrongPIN_IncrementsDACounter proves PIN guessing is
// throttled by the TPM itself.
//
// The Platform SRK is the object whose authorization value IS the user PIN, so
// it must be created with NoDA cleared. The standard SRK templates set NoDA
// (correct for a generic storage parent that is never the auth target), and an
// SRK inheriting that leaves PIN brute-forcing completely unthrottled: the
// lockout plumbing would be present, report a counter, and never move.
//
// Both directions are asserted, because a counter that increments on everything
// is as broken as one that never increments -- it would lock the operator out
// for using the correct PIN.
func TestPlatformKeyStore_WrongPIN_IncrementsDACounter(t *testing.T) {
	const userPIN = "operator-pin-4821"

	h := newEnrollHarness(t)
	pks := newPlatformKeyStore(t, h)
	require.NoError(t, pks.EnrollPlatformSRK("", userPIN))

	require.False(t, pks.SRKAttributes().TPMAttributes.Template.ObjectAttributes.NoDA,
		"the PIN SRK must have NoDA cleared so wrong PINs trip dictionary attack protection")

	require.NoError(t, pks.DictionaryAttackLockoutReset(nil))
	before, maxFail, _, _, err := pks.GetLockoutInfo()
	require.NoError(t, err)
	require.Greater(t, maxFail, 1,
		"precondition: the TPM must tolerate more than one failure, so a single "+
			"wrong PIN below cannot lock the test out")

	require.ErrorIs(t, pks.VerifyAuth("not-the-pin"), ErrAuthFailed)

	after, _, _, _, err := pks.GetLockoutInfo()
	require.NoError(t, err)
	assert.Greaterf(t, after, before,
		"a wrong PIN must increment the TPM dictionary attack counter (before=%d after=%d)",
		before, after)

	// A correct PIN must leave the counter alone.
	require.NoError(t, pks.DictionaryAttackLockoutReset(nil))
	baseline, _, _, _, err := pks.GetLockoutInfo()
	require.NoError(t, err)

	require.NoError(t, pks.VerifyAuth(userPIN))

	settled, _, _, _, err := pks.GetLockoutInfo()
	require.NoError(t, err)
	assert.Equal(t, baseline, settled,
		"a correct PIN must not increment the dictionary attack counter")
}

// TestPlatformKeyStore_VerifyAuth_WithoutPlatformPolicy proves PIN verification
// works on an SRK created without the platform PCR policy.
//
// The auth probe issues TPM2_Create under the SRK, and the session it needs
// differs between the two configurations: a policy-bound SRK is authorized with
// a PCR policy session, a plain one with a password session. Every other test in
// this package runs the policy-enabled branch (newSimConfig sets
// PlatformSRK.PlatformPolicy), so without this test the branch taken by
// deployments that disable the platform policy is never executed.
func TestPlatformKeyStore_VerifyAuth_WithoutPlatformPolicy(t *testing.T) {
	const userPIN = "operator-pin-4821"

	h := newSimHarness(t, func(c *Config) {
		c.SSRK.HierarchyAuth = types.SecretValue{}

		c.EK.HierarchyAuth = types.SecretValue{}

		c.PlatformSRK.PlatformPolicy = false
	})
	pks := newPlatformKeyStore(t, h)
	require.False(t, pks.PlatformPolicyEnabled(),
		"precondition: this test covers the platform-policy-disabled branch")

	require.NoError(t, pks.EnrollPlatformSRK("", userPIN))

	assert.NoError(t, pks.VerifyAuth(userPIN),
		"the enrolled PIN must authorize a policy-free platform SRK")
	assert.ErrorIs(t, pks.VerifyAuth("not-the-pin"), ErrAuthFailed,
		"a wrong PIN must be reported as an auth failure, not masked as a TPM fault")
}
