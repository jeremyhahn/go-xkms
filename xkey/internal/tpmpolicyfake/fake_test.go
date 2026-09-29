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

package tpmpolicyfake

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

func TestFake_CreateCapturesLivePCRs(t *testing.T) {
	f := &Fake{}
	f.SetPCR(7, []byte{0xaa})
	p, err := f.TPMPolicyCreate(context.Background(), &transport.TPMPolicyCreateRequest{Name: "boot", Bank: "sha256", PCRs: []uint{7}})
	require.NoError(t, err)
	assert.Equal(t, "aa", p.PCRValues[7])
	assert.True(t, p.Approved)
}

func TestFake_CreateRefusesBadRequests(t *testing.T) {
	f := &Fake{}
	ctx := context.Background()
	_, err := f.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{Name: "", PCRs: []uint{7}})
	assert.ErrorIs(t, err, ErrNameRequired)
	_, err = f.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{Name: xkms.TPMPolicyPlatform, PCRs: []uint{7}})
	assert.ErrorIs(t, err, xkms.ErrTPMPolicyReserved)
	_, err = f.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{Name: "boot"})
	assert.ErrorIs(t, err, ErrNoPCRs)
	_, err = f.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{Name: "boot", PCRs: []uint{7}})
	require.NoError(t, err)
	_, err = f.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{Name: "boot", PCRs: []uint{7}})
	assert.ErrorIs(t, err, xkms.ErrTPMPolicyExists)
}

func TestFake_VerifyDetectsDriftAndUpdateRecaptures(t *testing.T) {
	f := &Fake{}
	ctx := context.Background()
	_, err := f.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{Name: "boot", PCRs: []uint{0, 7}})
	require.NoError(t, err)

	f.SetPCR(7, []byte{0x01})
	v, err := f.TPMPolicyVerify(ctx, &transport.TPMPolicyRequest{Name: "boot"})
	require.NoError(t, err)
	assert.False(t, v.Match)
	assert.Equal(t, []uint{7}, v.Mismatched)

	_, err = f.TPMPolicyUpdate(ctx, &transport.TPMPolicyRequest{Name: "boot"})
	require.NoError(t, err)
	v, err = f.TPMPolicyVerify(ctx, &transport.TPMPolicyRequest{Name: "boot"})
	require.NoError(t, err)
	assert.True(t, v.Match)
	assert.True(t, v.Approved)
}

func TestFake_RevokeWithdrawsApprovalAndUnknownPolicyFails(t *testing.T) {
	f := &Fake{}
	ctx := context.Background()
	_, err := f.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{Name: "boot", PCRs: []uint{7}})
	require.NoError(t, err)
	p, err := f.TPMPolicyRevoke(ctx, &transport.TPMPolicyRequest{Name: "boot"})
	require.NoError(t, err)
	assert.False(t, p.Approved)

	_, err = f.TPMPolicyRevoke(ctx, &transport.TPMPolicyRequest{Name: "missing"})
	assert.ErrorIs(t, err, xkms.ErrTPMPolicyNotFound)
}

func TestFake_DeleteRefusedWhileAssigned(t *testing.T) {
	f := &Fake{}
	ctx := context.Background()
	_, err := f.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{Name: "boot", PCRs: []uint{7}})
	require.NoError(t, err)
	f.Assign("", "key", "k1", "boot")

	err = f.TPMPolicyDelete(ctx, &transport.TPMPolicyDeleteRequest{Name: "boot"})
	var inUse *xkms.TPMPolicyInUseError
	require.ErrorAs(t, err, &inUse)
	assert.Equal(t, []string{"key/k1"}, inUse.Objects)

	objects, err := f.TPMPolicyObjects(ctx, &transport.TPMPolicyRequest{Name: "boot"})
	require.NoError(t, err)
	assert.Equal(t, []string{"key/k1"}, objects.Objects)
}

func TestFake_AutoUnsealIsExclusive(t *testing.T) {
	f := &Fake{}
	ctx := context.Background()
	for _, name := range []string{"a", "b"} {
		_, err := f.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{Name: name, PCRs: []uint{7}})
		require.NoError(t, err)
	}
	_, err := f.TPMPolicySetAutoUnseal(ctx, &transport.TPMPolicyAutoUnsealRequest{Name: "a", Enabled: true})
	require.NoError(t, err)
	_, err = f.TPMPolicySetAutoUnseal(ctx, &transport.TPMPolicyAutoUnsealRequest{Name: "b", Enabled: true})
	require.NoError(t, err)
	list, err := f.TPMPolicyList(ctx, &transport.TPMPolicyListRequest{})
	require.NoError(t, err)
	assert.False(t, list.Policies[0].AutoUnseal)
	assert.True(t, list.Policies[1].AutoUnseal)

	_, err = f.TPMPolicySetAutoUnseal(ctx, &transport.TPMPolicyAutoUnsealRequest{Name: "missing", Enabled: true})
	assert.ErrorIs(t, err, xkms.ErrTPMPolicyNotFound)
}

func TestFake_ObjectPolicy(t *testing.T) {
	f := &Fake{}
	ctx := context.Background()
	f.Assign("", "key", "k1", "")
	a, err := f.TPMObjectPolicy(ctx, &transport.TPMObjectPolicyRequest{KeyID: "tpm2:signing:ecdsa-p256:k1"})
	require.NoError(t, err)
	assert.Equal(t, xkms.TPMPolicyPlatform, a.Policy)

	_, err = f.TPMObjectPolicy(ctx, &transport.TPMObjectPolicyRequest{KeyID: "k2"})
	assert.ErrorIs(t, err, xkms.ErrTPMPolicyNotAssigned)
	_, err = f.TPMObjectPolicy(ctx, &transport.TPMObjectPolicyRequest{})
	assert.ErrorIs(t, err, ErrKeyIDRequired)
}

func TestFake_RotateAuthority(t *testing.T) {
	f := &Fake{}
	ctx := context.Background()
	_, err := f.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{Name: "boot", PCRs: []uint{7}})
	require.NoError(t, err)
	resp, err := f.TPMPolicyRotateAuthority(ctx, &transport.TPMAuthorityRotateRequest{})
	require.NoError(t, err)
	assert.Equal(t, uint64(2), resp.Generation)
	p, err := f.TPMPolicyGet(ctx, &transport.TPMPolicyRequest{Name: "boot"})
	require.NoError(t, err)
	assert.Equal(t, uint64(2), p.AuthorityGeneration)
}

func TestFake_TenantModes(t *testing.T) {
	f := &Fake{}
	ctx := context.Background()
	mode, err := f.GetTenantTPMMode(ctx, "acme")
	require.NoError(t, err)
	assert.Equal(t, string(xkms.TPMDefaultMode), mode.Mode)
	_, err = f.SetTenantTPMMode(ctx, &transport.SetTenantTPMModeRequest{TenantID: "acme", Mode: "none"})
	require.NoError(t, err)
	mode, err = f.GetTenantTPMMode(ctx, "acme")
	require.NoError(t, err)
	assert.Equal(t, "none", mode.Mode)
	_, err = f.SetTenantTPMMode(ctx, &transport.SetTenantTPMModeRequest{TenantID: "acme", Mode: "bogus"})
	assert.Error(t, err)
}

func TestFake_VTPMUnavailable(t *testing.T) {
	f := &Fake{}
	ctx := context.Background()
	status, err := f.TenantVTPMStatus(ctx, "acme")
	require.NoError(t, err)
	assert.False(t, status.Running)
	_, err = f.TenantVTPMStart(ctx, "acme")
	assert.ErrorIs(t, err, xkms.ErrTPMVTPMUnavailable)
	_, err = f.TenantVTPMStop(ctx, "acme")
	assert.ErrorIs(t, err, xkms.ErrTPMVTPMUnavailable)
}
