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
	p, err := f.TPMPolicyCreate(context.Background(), &transport.TPMPolicyCreateRequest{
		Name: "boot", Description: "firmware",
		Branches: []transport.TPMPolicyBranch{pcrBranch(7), {Conditions: []transport.TPMPolicyCondition{{Type: transport.TPMPolicyConditionAuthValue}}}},
	})
	require.NoError(t, err)
	assert.Equal(t, "aa", p.Branches[0].Conditions[0].PCRValues[7])
	assert.Nil(t, p.Branches[1].Conditions[0].PCRValues, "only a pcr condition captures values")
	assert.True(t, p.Approved)
	assert.True(t, p.Branches[0].Approved && p.Branches[1].Approved)
	assert.Equal(t, "firmware", p.Description)
}

// pcrBranch is the one pcr branch over pcrs of sha256.
func pcrBranch(pcrs ...uint) transport.TPMPolicyBranch {
	return transport.TPMPolicyPCRBranch("sha256", pcrs)
}

// create creates a one-branch policy named name over pcrs.
func create(t *testing.T, f *Fake, name string, pcrs ...uint) {
	t.Helper()
	_, err := f.TPMPolicyCreate(context.Background(), &transport.TPMPolicyCreateRequest{Name: name, Branches: []transport.TPMPolicyBranch{pcrBranch(pcrs...)}})
	require.NoError(t, err)
}

func TestFake_SetDescription(t *testing.T) {
	f := &Fake{}
	ctx := context.Background()
	create(t, f, "boot", 7)
	p, err := f.TPMPolicySetDescription(ctx, &transport.TPMPolicyDescriptionRequest{Name: "boot", Description: "firmware"})
	require.NoError(t, err)
	assert.Equal(t, "firmware", p.Description)
	got, err := f.TPMPolicyGet(ctx, &transport.TPMPolicyRequest{Name: "boot"})
	require.NoError(t, err)
	assert.Equal(t, "firmware", got.Description)

	_, err = f.TPMPolicySetDescription(ctx, &transport.TPMPolicyDescriptionRequest{Name: "missing"})
	assert.ErrorIs(t, err, xkms.ErrTPMPolicyNotFound)
	_, err = f.TPMPolicySetDescription(ctx, &transport.TPMPolicyDescriptionRequest{Name: xkms.TPMPolicyPlatform})
	assert.ErrorIs(t, err, xkms.ErrTPMPolicyReserved)
}

func TestFake_CreateRefusesBadRequests(t *testing.T) {
	f := &Fake{}
	ctx := context.Background()
	branches := []transport.TPMPolicyBranch{pcrBranch(7)}
	_, err := f.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{Name: "", Branches: branches})
	assert.ErrorIs(t, err, ErrNameRequired)
	_, err = f.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{Name: xkms.TPMPolicyPlatform, Branches: branches})
	assert.ErrorIs(t, err, xkms.ErrTPMPolicyReserved)
	_, err = f.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{Name: "boot"})
	assert.ErrorIs(t, err, ErrNoBranches)
	_, err = f.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{Name: "boot", Branches: []transport.TPMPolicyBranch{pcrBranch()}})
	assert.ErrorIs(t, err, ErrNoPCRs)
	_, err = f.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{Name: "boot", Branches: branches})
	require.NoError(t, err)
	_, err = f.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{Name: "boot", Branches: branches})
	assert.ErrorIs(t, err, xkms.ErrTPMPolicyExists)
}

func TestFake_VerifyDetectsDriftAndUpdateRecaptures(t *testing.T) {
	f := &Fake{}
	ctx := context.Background()
	create(t, f, "boot", 0, 7)

	f.SetPCR(7, []byte{0x01})
	v, err := f.TPMPolicyVerify(ctx, &transport.TPMPolicyRequest{Name: "boot"})
	require.NoError(t, err)
	assert.False(t, v.Match)
	assert.Equal(t, []transport.TPMPolicyBranchVerification{{Mismatched: []uint{7}, Approved: true}}, v.Branches)

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
	create(t, f, "boot", 7)
	p, err := f.TPMPolicyRevoke(ctx, &transport.TPMPolicyRequest{Name: "boot"})
	require.NoError(t, err)
	assert.False(t, p.Approved)

	_, err = f.TPMPolicyRevoke(ctx, &transport.TPMPolicyRequest{Name: "missing"})
	assert.ErrorIs(t, err, xkms.ErrTPMPolicyNotFound)
}

func TestFake_DeleteRefusedWhileAssigned(t *testing.T) {
	f := &Fake{}
	ctx := context.Background()
	create(t, f, "boot", 7)
	f.Assign("", "key", "k1", "boot")

	err := f.TPMPolicyDelete(ctx, &transport.TPMPolicyDeleteRequest{Name: "boot"})
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
		create(t, f, name, 7)
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
	create(t, f, "boot", 7)
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
