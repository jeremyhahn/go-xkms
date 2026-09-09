// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0)
// for non-commercial use. Commercial licenses are available.
// See LICENSE and LICENSE-COMMERCIAL for details.

package attestation_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// TestAllowUnattestablePairingResolvesTheTwoPlanes exercises the whole
// decision surface of the owner ruling of 2026-08-23 on #95: the user setting
// in devices.yaml, the enterprise/SO setting in the sealed PolicySection, and
// the lock that decides whether the second is consulted.
//
// The table is exhaustive over the three inputs rather than illustrative,
// because the interesting cases are the ones where the two planes DISAGREE.
//
// The enterprise plane is MONOTONE: it may only make the answer STRICTER. That
// is not a design preference, it is what a pairing surface can honestly
// enforce. Nothing on a pairing path verifies the policy HMAC -- verification
// needs the SO PIN, which a pairing does not have -- so treating the section as
// authoritative in BOTH directions let anyone who can edit xkey.yaml write
// lock_pairing_attestation_policy: true beside
// pairing_allow_unattestable_devices: true and pair an unattestable device over
// a devices.yaml that refuses. Locking the setting OPEN needs authenticated
// policy and is tracked as #118.
func TestAllowUnattestablePairingResolvesTheTwoPlanes(t *testing.T) {
	policy := func(allow, lock bool) *config.PolicySection {
		return &config.PolicySection{
			PairingAllowUnattestableDevices: allow,
			LockPairingAttestationPolicy:    lock,
		}
	}

	tests := []struct {
		name       string
		userAllows bool
		enterprise *config.PolicySection
		want       bool
		why        string
	}{
		{
			name: "nothing configured at all", userAllows: false, enterprise: nil, want: false,
			why: "the default the ruling names is fail closed, and it must come from " +
				"the zero value rather than from a defaults table",
		},
		{
			name: "user says yes, nothing enterprise", userAllows: true, enterprise: nil, want: true,
			why: "unlocked, the user's own setting is the answer",
		},
		{
			name: "user says yes, enterprise present but not locked", userAllows: true, enterprise: policy(false, false), want: true,
			why: "an enterprise value that has not been locked must not narrow the " +
				"user's setting; the lock is what makes the section authoritative",
		},
		{
			name: "user says no, enterprise present but not locked", userAllows: false, enterprise: policy(true, false), want: false,
			why: "and equally must not widen it",
		},
		{
			name: "user says yes, enterprise locks it closed", userAllows: true, enterprise: policy(false, true), want: false,
			why: "this is the case the lock exists for: a locked deployment cannot be " +
				"widened by editing devices.yaml",
		},
		{
			name: "user says no, enterprise locks it open", userAllows: false, enterprise: policy(true, true), want: false,
			why: "an UNVERIFIED policy section must never widen anything: nothing on " +
				"a pairing path checks the policy HMAC, so honouring this direction " +
				"would let anyone who can edit xkey.yaml pair an unattestable " +
				"device over a devices.yaml that refuses (#118)",
		},
		{
			name: "user says yes, enterprise locks it open", userAllows: true, enterprise: policy(true, true), want: true,
			why: "the user already allows it; the unverified section adds nothing " +
				"and takes nothing away",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want,
				attestation.AllowUnattestablePairing(tc.userAllows, tc.enterprise), tc.why)
		})
	}
}

// TestAllowUnattestablePairingDefaultsToRefuseOnAZeroPolicySection pins the
// half of the design that a defaults table would have got wrong.
//
// config.DefaultPolicy() is NOT what a loaded config carries when its file
// holds a partial `policy:` block: viper does not merge a struct default key by
// key, so a file setting only min_pin_length resolves every other policy key to
// its zero value (measured; filed as #114). Both fields here are therefore
// designed so that zero means "not locked, not allowed" -- the same answer as
// no policy at all.
func TestAllowUnattestablePairingDefaultsToRefuseOnAZeroPolicySection(t *testing.T) {
	require.False(t, attestation.AllowUnattestablePairing(false, &config.PolicySection{}),
		"a zero PolicySection must read as unlocked and disallowed, because that is "+
			"what a partially-specified policy file actually produces")
}
