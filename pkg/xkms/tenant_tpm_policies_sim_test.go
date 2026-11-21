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

package xkms_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/localtpmtest"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// A revoked policy whose branches hold no pcr condition has no reference
// values to update from: an update without a branch re-approves it at the
// next epoch. A policy with a pcr condition still needs a signed named
// branch.
func TestTenantTPMPolicies_ReapprovesAPolicyWithoutAPCRCondition(t *testing.T) {
	host := localtpmtest.OpenSimulator(t, t.TempDir(), localtpmtest.MemoryStores)
	p, err := xkms.NewTenantTPMPolicies(host.Service(), "")
	require.NoError(t, err)
	ctx := t.Context()

	_, err = p.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{
		Name: "pin",
		Branches: []transport.TPMPolicyBranch{
			{Conditions: []transport.TPMPolicyCondition{{Type: transport.TPMPolicyConditionAuthValue}}},
			{Conditions: []transport.TPMPolicyCondition{{Type: transport.TPMPolicyConditionLocality, Localities: []uint{0}}}},
		},
	})
	require.NoError(t, err)
	revoked, err := p.TPMPolicyRevoke(ctx, &transport.TPMPolicyRequest{Name: "pin"})
	require.NoError(t, err)
	require.False(t, revoked.Approved)

	reapproved, err := p.TPMPolicyUpdate(ctx, &transport.TPMPolicyUpdateRequest{Name: "pin"})
	require.NoError(t, err)
	assert.True(t, reapproved.Approved)
	assert.Greater(t, reapproved.Epoch, revoked.Epoch)

	_, err = p.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{
		Name:     "boot",
		Branches: []transport.TPMPolicyBranch{transport.TPMPolicyPCRBranch("sha256", []uint{16})},
	})
	require.NoError(t, err)
	_, err = p.TPMPolicyRevoke(ctx, &transport.TPMPolicyRequest{Name: "boot"})
	require.NoError(t, err)
	_, err = p.TPMPolicyUpdate(ctx, &transport.TPMPolicyUpdateRequest{Name: "boot"})
	require.ErrorIs(t, err, xkms.ErrTPMPolicyBranchUpdate)
}
