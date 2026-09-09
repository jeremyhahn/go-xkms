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
// in devices.yaml, the enterprise/SO setting in the PolicySection, the lock
// that decides whether the second is consulted, and -- since #118 -- whether
// the section reached this function as a trusted policy at all.
//
// The table is exhaustive over the inputs rather than illustrative, because
// the interesting cases are the ones where the two planes DISAGREE.
//
// The enterprise plane is honoured in BOTH directions, permissive included,
// because it can only arrive here as a config.VerifiedPolicy: unsealed (the
// user's own file) or sealed-and-verified under the SO PIN. A sealed section
// that was not verified arrives as nil and is refused. That is what replaced
// the monotone mitigation of #110, which could never honour a deployment that
// legitimately locks the setting open.
func TestAllowUnattestablePairingResolvesTheTwoPlanes(t *testing.T) {
	policy := func(state config.PolicyState, allow, lock bool) *config.VerifiedPolicy {
		return &config.VerifiedPolicy{State: state, Policy: config.PolicySection{
			PairingAllowUnattestableDevices: allow,
			LockPairingAttestationPolicy:    lock,
		}}
	}
	unsealed := func(allow, lock bool) *config.VerifiedPolicy {
		return policy(config.PolicyUnsealed, allow, lock)
	}
	verified := func(allow, lock bool) *config.VerifiedPolicy {
		return policy(config.PolicySealedVerified, allow, lock)
	}

	tests := []struct {
		name       string
		userAllows bool
		policy     *config.VerifiedPolicy
		want       bool
		why        string
	}{
		{
			name: "sealed and not verified, user says yes", userAllows: true, policy: nil, want: false,
			why: "the enterprise plane exists but is unknown, so the answer is the " +
				"fail-closed default whatever devices.yaml says (#118)",
		},
		{
			name: "sealed and not verified, nothing else", userAllows: false, policy: nil, want: false,
			why: "the default the ruling names is fail closed",
		},
		{
			name: "user says no, unsealed and not locked", userAllows: false, policy: unsealed(true, false), want: false,
			why: "an unlocked value must not widen the user's setting",
		},
		{
			name: "user says yes, unsealed and not locked", userAllows: true, policy: unsealed(false, false), want: true,
			why: "unlocked, the user's own setting is the answer; an unlocked value " +
				"must not narrow it either",
		},
		{
			name: "user says yes, unsealed and locked closed", userAllows: true, policy: unsealed(false, true), want: false,
			why: "in personal mode the policy section is the user's own file and " +
				"its lock is honoured",
		},
		{
			name: "user says no, unsealed and locked open", userAllows: false, policy: unsealed(true, true), want: true,
			why: "same file, same authority, other direction: in personal mode there " +
				"is no adversary distinction between xkey.yaml and devices.yaml",
		},
		{
			name: "user says yes, verified and not locked", userAllows: true, policy: verified(false, false), want: true,
			why: "an SO value that has not been locked does not narrow the user's " +
				"setting; the lock is what makes the section authoritative",
		},
		{
			name: "user says no, verified and not locked", userAllows: false, policy: verified(true, false), want: false,
			why: "and equally does not widen it",
		},
		{
			name: "user says yes, verified and locked closed", userAllows: true, policy: verified(false, true), want: false,
			why: "this is the case the lock exists for: a locked deployment cannot be " +
				"widened by editing devices.yaml",
		},
		{
			name: "user says no, verified and locked open", userAllows: false, policy: verified(true, true), want: true,
			why: "the direction #118 unblocks: a policy that verified under the SO PIN " +
				"carries the SO's authority in both directions, so a fleet that " +
				"pairs development handsets can lock the setting open",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want,
				attestation.AllowUnattestablePairing(tc.userAllows, tc.policy), tc.why)
		})
	}
}

// TestAllowUnattestablePairingDefaultsToRefuseOnAZeroPolicySection pins the
// half of the design that a defaults table would have got wrong: both fields
// are designed so that zero means "not locked, not allowed", the same answer
// as no policy at all, and that must hold with or without #114's leaf-key
// merge.
func TestAllowUnattestablePairingDefaultsToRefuseOnAZeroPolicySection(t *testing.T) {
	require.False(t, attestation.AllowUnattestablePairing(false, &config.VerifiedPolicy{}),
		"a zero PolicySection must read as unlocked and disallowed")
}
