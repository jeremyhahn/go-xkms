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

package policy

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newSimFixture opens a fresh, provisioned simulator as the physical TPM and
// builds a Service over it. The simulator is a process-wide singleton: each
// test opens exactly one, and closes it when it ends.
func newSimFixture(t *testing.T) *fixture {
	t.Helper()
	keys := store.NewFileBackend(quietLogger, storage.NewMemory())
	cfg := pkgtpm2.DefaultConfig
	cfg.UseSimulator = true
	tpm := provisionedTPM(t, &pkgtpm2.Params{Config: &cfg, Backend: keys, Logger: quietLogger})
	return newFixture(t, tpm, keys, nil)
}

// sealObject seals secret in tenant's scope bound to policy.
func (f *fixture) sealObject(tenant, cn, policy string, secret []byte) *types.KeyAttributes {
	f.t.Helper()
	st := f.scopeTPM(tenant)
	defer f.closeScopeTPM(st)
	attrs := &types.KeyAttributes{
		CN:            cn,
		KeyType:       types.KeyTypeHMAC,
		Parent:        st.Parent,
		SealData:      types.NewSealData(secret),
		StoreType:     types.StoreTPM2,
		TenantID:      tenant,
		TPMPolicy:     policy,
		TPMAttributes: &types.TPMAttributes{Hierarchy: tpm2.TPMRHOwner},
	}
	_, err := st.TPM.SealKey(attrs, st.Keys, false)
	require.NoError(f.t, err)
	require.NoError(f.t, f.svc.Assign(f.ctx, tenant, ObjectSealed, cn, policy, nil))
	return attrs
}

// unseal unseals the sealed object in tenant's scope.
func (f *fixture) unseal(tenant string, sealed *types.KeyAttributes) ([]byte, error) {
	f.t.Helper()
	st := f.scopeTPM(tenant)
	defer f.closeScopeTPM(st)
	attrs := *sealed
	attrs.Parent = st.Parent
	attrs.SealData = nil
	return st.TPM.UnsealKey(&attrs, st.Keys)
}

// TestService_PolicySharedByKeys proves one named policy authorizes several
// keys of a tenant, and that the registry answers in both directions which
// keys use it and which policy each key uses.
func TestService_PolicySharedByKeys(t *testing.T) {
	f := newSimFixture(t)
	p := f.createPolicy("acme", "boot")
	require.Len(t, p.Approvals, 1)
	assert.NotNil(t, p.Approvals[0])
	assert.NotZero(t, p.Index)
	assert.NotEmpty(t, p.IndexName)
	assert.Len(t, p.Branches[0].Conditions[0].PCRValues[testPCR], sha256.Size)
	assert.Equal(t, pkgtpm2.PolicyRef("acme", "boot"), p.PolicyRef)

	a := f.createKey("acme", "signer-a", "boot", nil)
	b := f.createKey("acme", "signer-b", "boot", nil)
	require.NoError(t, f.sign("acme", a))
	require.NoError(t, f.sign("acme", b))

	objects, err := f.svc.ObjectsOf(f.ctx, "acme", "boot")
	require.NoError(t, err)
	assert.Equal(t, []string{"key/signer-a", "key/signer-b"}, objects)
	for _, cn := range []string{"signer-a", "signer-b"} {
		assignment, err := f.svc.PolicyOf(f.ctx, "acme", ObjectKey, cn)
		require.NoError(t, err)
		assert.Equal(t, "boot", assignment.Policy)
		assert.NotEmpty(t, assignment.AuthPolicy)
	}
}

// TestService_PCRChangeRefusesPolicyObjects proves the TPM refuses a
// no-password key and a sealed object bound to a policy once a selected PCR
// moves.
func TestService_PCRChangeRefusesPolicyObjects(t *testing.T) {
	f := newSimFixture(t)
	f.createPolicy("acme", "boot")
	key := f.createKey("acme", "signer", "boot", nil)
	secret := []byte("sealed under the boot policy")
	sealed := f.sealObject("acme", "sealed-secret", "boot", secret)

	got, err := f.unseal("acme", sealed)
	require.NoError(t, err)
	assert.Equal(t, secret, got)

	extendPCR(t, f.tpm.Transport())

	var mismatch *pkgtpm2.PolicyPCRMismatchError
	require.ErrorAs(t, f.sign("acme", key), &mismatch)
	assert.Equal(t, "boot", mismatch.Policy)
	_, err = f.unseal("acme", sealed)
	require.ErrorAs(t, err, &mismatch)
}

// TestService_UpdatePolicyReapprovesWithoutRekey proves an update restores
// both keys under the new PCR state from the very same blobs, and that a
// stored copy of a superseded approval is refused by the TPM.
func TestService_UpdatePolicyReapprovesWithoutRekey(t *testing.T) {
	f := newSimFixture(t)
	created := f.createPolicy("acme", "boot")
	a := f.createKey("acme", "signer-a", "boot", nil)
	b := f.createKey("acme", "signer-b", "boot", nil)
	privBefore, pubBefore := f.blobs("acme", a)
	original, err := f.svc.Approvals("acme", "boot")
	require.NoError(t, err)

	extendPCR(t, f.tpm.Transport())
	require.Error(t, f.sign("acme", a))

	updated, err := f.svc.UpdatePolicy(f.ctx, "acme", "boot")
	require.NoError(t, err)
	assert.Equal(t, created.Approvals[0].Epoch+1, updated.Approvals[0].Epoch)
	assert.NotEqual(t, created.Branches[0].Conditions[0].PCRValues[testPCR], updated.Branches[0].Conditions[0].PCRValues[testPCR], "the update re-captures the live PCR")
	require.NoError(t, f.sign("acme", a))
	require.NoError(t, f.sign("acme", b))
	privAfter, pubAfter := f.blobs("acme", a)
	assert.Equal(t, privBefore, privAfter, "no re-key")
	assert.Equal(t, pubBefore, pubAfter, "no re-key")

	f.tpm.SetPolicyBindingResolver(replayResolver{Service: f.svc, approvals: original})
	require.Error(t, f.sign("acme", a), "the pre-update approval no longer authorizes the key")

	// A second update without a PCR change isolates the counter: the
	// replayed approval describes the live PCRs and is refused only because
	// its epoch has been superseded.
	f.tpm.SetPolicyBindingResolver(f.svc)
	current, err := f.svc.Approvals("acme", "boot")
	require.NoError(t, err)
	_, err = f.svc.UpdatePolicy(f.ctx, "acme", "boot")
	require.NoError(t, err)
	f.tpm.SetPolicyBindingResolver(replayResolver{Service: f.svc, approvals: current})
	var revoked *pkgtpm2.PolicyApprovalRevokedError
	require.ErrorAs(t, f.sign("acme", a), &revoked)
	assert.Equal(t, current[0].Epoch, revoked.Epoch)
	f.tpm.SetPolicyBindingResolver(f.svc)
	require.NoError(t, f.sign("acme", a))
}

// TestService_DeletePolicyRefusedWhileAssigned proves a policy with assigned
// objects cannot be deleted, the refusal lists them, and once they are gone
// the policy and its NV index are removed.
func TestService_DeletePolicyRefusedWhileAssigned(t *testing.T) {
	f := newSimFixture(t)
	p := f.createPolicy("acme", "boot")
	f.createKey("acme", "signer-a", "boot", nil)
	f.createKey("acme", "signer-b", "boot", nil)

	err := f.svc.DeletePolicy(f.ctx, "acme", "boot", nil)
	var inUse *PolicyInUseError
	require.ErrorAs(t, err, &inUse)
	assert.Equal(t, []string{"key/signer-a", "key/signer-b"}, inUse.Objects)

	require.NoError(t, f.svc.Unassign(f.ctx, "acme", ObjectKey, "signer-a"))
	require.NoError(t, f.svc.Unassign(f.ctx, "acme", ObjectKey, "signer-b"))
	require.NoError(t, f.svc.DeletePolicy(f.ctx, "acme", "boot", nil))

	_, err = f.svc.Policy(f.ctx, "acme", "boot")
	require.ErrorIs(t, err, ErrPolicyNotFound)
	_, err = f.tpm.NVIndexName(tpm2.TPMHandle(p.Index))
	require.Error(t, err, "the policy's NV index is undefined")
}

// TestService_RevokeAndRestore proves a revoke withdraws the approved branch
// of the policy's keys -- while a key's password branch, and every other
// policy, keep working -- and that an update restores it.
func TestService_RevokeAndRestore(t *testing.T) {
	f := newSimFixture(t)
	f.createPolicy("acme", "boot")
	f.createPolicy("acme", "other")
	noPassword := f.createKey("acme", "no-password", "boot", nil)
	withPassword := f.createKey("acme", "with-password", "boot", []byte("key-pin"))
	otherKey := f.createKey("acme", "other-key", "other", nil)

	revoked, err := f.svc.RevokePolicy(f.ctx, "acme", "boot")
	require.NoError(t, err)
	assert.Equal(t, []*Approval{nil}, revoked.Approvals)

	require.ErrorIs(t, f.sign("acme", noPassword), ErrPolicyRevoked)
	require.ErrorIs(t, f.sign("acme", withoutPassword(withPassword)), ErrPolicyRevoked)
	require.NoError(t, f.sign("acme", withPassword), "the password branch needs no approval")
	require.NoError(t, f.sign("acme", otherKey), "the other policy was re-signed at the new epoch")

	again, err := f.svc.RevokePolicy(f.ctx, "acme", "boot")
	require.NoError(t, err)
	assert.Equal(t, []*Approval{nil}, again.Approvals, "revoking a revoked policy changes nothing")

	v, err := f.svc.VerifyPolicy(f.ctx, "acme", "boot")
	require.NoError(t, err)
	assert.True(t, v.Match)
	assert.False(t, v.Approved)

	_, err = f.svc.UpdatePolicy(f.ctx, "acme", "boot")
	require.NoError(t, err)
	require.NoError(t, f.sign("acme", noPassword))
	require.NoError(t, f.sign("acme", otherKey))
}

// TestService_RotateAuthority proves a rotation moves every key to a new
// authority without re-keying, deletes the old authority, and leaves its
// approvals unable to authorize anything.
func TestService_RotateAuthority(t *testing.T) {
	f := newSimFixture(t)
	f.createPolicy("acme", "boot")
	key := f.createKey("acme", "signer", "boot", nil)
	privBefore, pubBefore := f.blobs("acme", key)
	old, err := f.svc.Approvals("acme", "boot")
	require.NoError(t, err)
	before, err := f.registry.Scope(f.ctx, "acme")
	require.NoError(t, err)

	scope, err := f.svc.RotateAuthority(f.ctx, "acme")
	require.NoError(t, err)
	assert.Equal(t, uint64(2), scope.Authority.Generation)
	assert.Nil(t, scope.Rotating)
	assert.NotEqual(t, before.Authority.Name, scope.Authority.Name)

	require.NoError(t, f.sign("acme", key))
	privAfter, pubAfter := f.blobs("acme", key)
	assert.Equal(t, privBefore, privAfter, "no re-key")
	assert.Equal(t, pubBefore, pubAfter, "no re-key")

	st := f.scopeTPM("acme")
	f.closeScopeTPM(st)
	_, err = st.Keys.Get(&types.KeyAttributes{CN: before.Authority.CN}, store.FSEXT_PUBLIC_BLOB)
	require.ErrorIs(t, err, storage.ErrNotFound, "the old authority is deleted")

	f.tpm.SetPolicyBindingResolver(replayResolver{Service: f.svc, approvals: old})
	err = f.sign("acme", key)
	require.ErrorIs(t, err, tpm2.TPMRCValue, "TPM2_PolicyAuthorizeNV refuses the old authority")
	var mismatch *pkgtpm2.PolicyPCRMismatchError
	assert.False(t, errors.As(err, &mismatch), "the PCRs did not move")
}

// TestService_SharedModeIsolation proves two shared-mode tenants using the
// same policy and key names each see only their own, cannot load each
// other's keys, and keep their blobs under their own prefixes.
func TestService_SharedModeIsolation(t *testing.T) {
	f := newSimFixture(t)
	tenants := []string{"acme", "globex"}
	policies := map[string]*Policy{}
	keys := map[string]*types.KeyAttributes{}
	for _, tenant := range tenants {
		policies[tenant] = f.createPolicy(tenant, "boot")
		keys[tenant] = f.createKey(tenant, "signer", "boot", nil)
		require.NoError(t, f.sign(tenant, keys[tenant]))
	}
	assert.NotEqual(t, policies["acme"].Index, policies["globex"].Index)
	assert.NotEqual(t, policies["acme"].PolicyRef, policies["globex"].PolicyRef)

	for _, tenant := range tenants {
		objects, err := f.svc.ObjectsOf(f.ctx, tenant, "boot")
		require.NoError(t, err)
		assert.Equal(t, []string{"key/signer"}, objects)
		listed, err := f.svc.ListPolicies(f.ctx, tenant)
		require.NoError(t, err)
		require.Len(t, listed, 1)
		assert.Equal(t, policies[tenant].Index, listed[0].Index)
	}

	acme := f.scopeTPM("acme")
	acmeParentName := acme.Parent.TPMAttributes.Name
	f.closeScopeTPM(acme)
	globex := f.scopeTPM("globex")
	defer f.closeScopeTPM(globex)
	assert.NotEqual(t, acmeParentName, globex.Parent.TPMAttributes.Name)
	stolen := *keys["acme"]
	stolen.Parent = globex.Parent
	_, err := globex.TPM.Sign(nil, make([]byte, sha256.Size), &store.SignerOpts{KeyAttributes: &stolen, Backend: acme.Keys})
	require.ErrorIs(t, err, tpm2.TPMRCIntegrity, "acme's key cannot be loaded under globex's storage key")

	_, acmePub := f.blobs("acme", keys["acme"])
	_, globexPub := f.blobs("globex", keys["globex"])
	assert.NotEqual(t, acmePub, globexPub)
	for _, tenant := range tenants {
		stored, err := f.keyStorage.List(f.ctx, tenant+"/tpm/keys/")
		require.NoError(t, err)
		assert.Contains(t, stored, tenant+"/tpm/keys/signer"+store.FSEXT_PUBLIC_BLOB)
	}
	root, err := f.keyStorage.List(f.ctx, "signer")
	require.NoError(t, err)
	assert.Empty(t, root, "no blob is stored by CN alone")
}

// TestService_SetMode proves the mode rules: the system scope's mode is
// fixed, a scope holding policies or objects cannot change mode, an empty one
// can, and mode none refuses every TPM operation.
func TestService_SetMode(t *testing.T) {
	f := newSimFixture(t)

	mode, err := f.svc.Mode(f.ctx, "initech")
	require.NoError(t, err)
	assert.Equal(t, DefaultMode, mode)
	require.ErrorIs(t, f.svc.SetMode(f.ctx, "", ModeNone, nil), ErrSystemScopeMode)
	require.ErrorIs(t, f.svc.SetMode(f.ctx, "system", ModeVTPM, nil), ErrSystemScopeMode)
	var invalid *InvalidModeError
	require.ErrorAs(t, f.svc.SetMode(f.ctx, "initech", Mode("bogus"), nil), &invalid)

	f.createPolicy("acme", "boot")
	var inUse *ScopeInUseError
	require.ErrorAs(t, f.svc.SetMode(f.ctx, "acme", ModeNone, nil), &inUse)
	assert.Equal(t, []string{"boot"}, inUse.Policies)
	require.NoError(t, f.svc.Assign(f.ctx, "hooli", ObjectKey, "platform-key", "", nil))
	require.ErrorAs(t, f.svc.SetMode(f.ctx, "hooli", ModeNone, nil), &inUse)
	assert.Equal(t, []string{"key/platform-key"}, inUse.Objects)

	created, err := f.svc.EnsureScope(f.ctx, "initech", nil)
	require.NoError(t, err)
	require.NoError(t, f.svc.SetMode(f.ctx, "initech", ModeShared, nil), "setting the current mode is a no-op")
	require.NoError(t, f.svc.SetMode(f.ctx, "initech", ModeNone, nil))
	mode, err = f.svc.Mode(f.ctx, "initech")
	require.NoError(t, err)
	assert.Equal(t, ModeNone, mode)
	_, err = f.tpm.NVIndexName(tpm2.TPMHandle(created.Counter))
	require.Error(t, err, "leaving shared mode undefines the counter")

	_, err = f.svc.CreatePolicy(f.ctx, "initech", CreatePolicyRequest{Name: "boot", Branches: []Branch{PCRBranch("sha256", testPCR)}})
	require.ErrorIs(t, err, ErrTPMModeNone)
	_, err = f.svc.ScopeTPM(f.ctx, "initech")
	require.ErrorIs(t, err, ErrTPMModeNone)
	require.ErrorIs(t, f.svc.Assign(f.ctx, "initech", ObjectKey, "k", "", nil), ErrTPMModeNone)
	_, err = f.svc.ListPolicies(f.ctx, "initech")
	require.ErrorIs(t, err, ErrTPMModeNone)
	_, err = f.svc.UpdatePolicy(f.ctx, "initech", "boot")
	require.ErrorIs(t, err, ErrTPMModeNone)

	require.NoError(t, f.svc.SetMode(f.ctx, "initech", ModeShared, nil))
	f.createPolicy("initech", "boot")
	key := f.createKey("initech", "signer", "boot", nil)
	require.NoError(t, f.sign("initech", key))

	require.ErrorIs(t, f.svc.SetMode(f.ctx, "umbrella", ModeVTPM, nil), ErrVTPMUnavailable)
	_, err = f.registry.Scope(f.ctx, "umbrella")
	require.ErrorIs(t, err, ErrScopeNotFound, "a failed creation leaves no scope behind")
}

// TestService_ReconcileResignsBehindCounter proves a crash after the counter
// moved but before the approvals were stored fails closed, and that the next
// process re-signs at the counter's value.
func TestService_ReconcileResignsBehindCounter(t *testing.T) {
	f := newSimFixture(t)
	f.createPolicy("acme", "boot")
	key := f.createKey("acme", "signer", "boot", nil)
	scopeBefore, err := f.registry.Scope(f.ctx, "acme")
	require.NoError(t, err)
	policyBefore, err := f.registry.Policy(f.ctx, "acme", "boot")
	require.NoError(t, err)

	_, err = f.svc.UpdatePolicy(f.ctx, "acme", "boot")
	require.NoError(t, err)
	// Roll the registry back to its state before the update: the counter
	// has moved, the stored approvals have not.
	require.NoError(t, f.registry.PutScope(f.ctx, scopeBefore))
	require.NoError(t, f.registry.UpdatePolicy(f.ctx, "acme", policyBefore))
	var revoked *pkgtpm2.PolicyApprovalRevokedError
	require.ErrorAs(t, f.sign("acme", key), &revoked, "stale approvals fail closed")

	f.restart()
	require.NoError(t, f.sign("acme", key))
	scope, err := f.registry.Scope(f.ctx, "acme")
	require.NoError(t, err)
	assert.Equal(t, scopeBefore.Epoch+1, scope.Epoch)
}

// TestService_ReconcileFinishesRotation proves a rotation interrupted after
// the new authority was recorded is completed when the scope is next opened.
func TestService_ReconcileFinishesRotation(t *testing.T) {
	f := newSimFixture(t)
	p := f.createPolicy("acme", "boot")
	key := f.createKey("acme", "signer", "boot", nil)

	st, unlock, err := f.svc.lockScope("acme")
	require.NoError(t, err)
	scope, err := f.svc.loadActive(f.ctx, st, nil)
	require.NoError(t, err)
	next, err := f.svc.createAuthority(st, 2)
	require.NoError(t, err)
	scope.Rotating = next
	require.NoError(t, f.registry.PutScope(f.ctx, scope))
	unlock()

	f.restart()
	require.NoError(t, f.sign("acme", key))
	scope, err = f.registry.Scope(f.ctx, "acme")
	require.NoError(t, err)
	assert.Nil(t, scope.Rotating)
	assert.Equal(t, uint64(2), scope.Authority.Generation)
	_, indexDigest, err := f.tpm.ReadPolicyIndex(tpm2.TPMHandle(p.Index))
	require.NoError(t, err)
	want, err := pkgtpm2.AuthorizeDigest(tpm2.TPMAlgSHA256, tpm2.TPM2BName{Buffer: next.Name}, p.PolicyRef)
	require.NoError(t, err)
	assert.Equal(t, want, indexDigest, "the index names the new authority")
}

// TestService_VerifyPolicy proves verification reports the PCRs that moved
// and whether the policy holds a current approval.
func TestService_VerifyPolicy(t *testing.T) {
	f := newSimFixture(t)
	p, err := f.svc.CreatePolicy(f.ctx, "acme", CreatePolicyRequest{Name: "boot", Branches: []Branch{PCRBranch("sha256", testPCR, 0)}})
	require.NoError(t, err)
	assert.Equal(t, []uint{0, testPCR}, p.Branches[0].Conditions[0].PCRs, "the selection is stored in ascending order")

	v, err := f.svc.VerifyPolicy(f.ctx, "acme", "boot")
	require.NoError(t, err)
	assert.Equal(t, &Verification{
		Policy:   "boot",
		Branches: []BranchVerification{{Match: true, Approved: true}},
		Match:    true,
		Approved: true,
	}, v)

	extendPCR(t, f.tpm.Transport())
	v, err = f.svc.VerifyPolicy(f.ctx, "acme", "boot")
	require.NoError(t, err)
	assert.False(t, v.Match)
	assert.Equal(t, []uint{testPCR}, v.Branches[0].Mismatched)
	assert.True(t, v.Approved)
}

// TestService_NonSHA256Bank proves a policy over the SHA-1 bank authorizes
// its key: the PolicyPCR operand is the session hash (SHA-256) over the
// bank's values, not the bank's own hash.
func TestService_NonSHA256Bank(t *testing.T) {
	f := newSimFixture(t)
	p, err := f.svc.CreatePolicy(f.ctx, "acme", CreatePolicyRequest{Name: "legacy", Branches: []Branch{PCRBranch("SHA1", testPCR)}})
	require.NoError(t, err)
	assert.Equal(t, "sha1", p.Branches[0].Conditions[0].Bank)
	assert.Len(t, p.Branches[0].Conditions[0].PCRValues[testPCR], 20)

	key := f.createKey("acme", "signer", "legacy", nil)
	require.NoError(t, f.sign("acme", key))
}

// TestService_AutoUnseal proves at most one policy of a scope carries the
// auto-unseal mark.
func TestService_AutoUnseal(t *testing.T) {
	f := newSimFixture(t)
	_, err := f.svc.AutoUnsealPolicy(f.ctx, "acme")
	require.ErrorIs(t, err, ErrPolicyNotFound)

	for _, name := range []string{"first", "second"} {
		_, err := f.svc.CreatePolicy(f.ctx, "acme", CreatePolicyRequest{Name: name, Branches: []Branch{PCRBranch("sha256", testPCR)}, AutoUnseal: true})
		require.NoError(t, err)
	}
	p, err := f.svc.AutoUnsealPolicy(f.ctx, "acme")
	require.NoError(t, err)
	assert.Equal(t, "second", p.Name)
	first, err := f.svc.Policy(f.ctx, "acme", "first")
	require.NoError(t, err)
	assert.False(t, first.AutoUnseal, "creating another auto-unseal policy moves the mark")

	require.NoError(t, f.svc.SetAutoUnseal(f.ctx, "acme", "first", true))
	p, err = f.svc.AutoUnsealPolicy(f.ctx, "acme")
	require.NoError(t, err)
	assert.Equal(t, "first", p.Name)

	require.NoError(t, f.svc.SetAutoUnseal(f.ctx, "acme", "first", false))
	_, err = f.svc.AutoUnsealPolicy(f.ctx, "acme")
	require.ErrorIs(t, err, ErrPolicyNotFound)
}

// TestService_SystemScope proves the system scope lives on the physical TPM
// under the Platform SRK, and its keys resolve in the "system" scope.
func TestService_SystemScope(t *testing.T) {
	f := newSimFixture(t)
	scope, err := f.svc.EnsureScope(f.ctx, "", nil)
	require.NoError(t, err)
	assert.Equal(t, "system", scope.Tenant)
	assert.Equal(t, ModeShared, scope.Mode)
	assert.Empty(t, scope.StorageKey)

	st := f.scopeTPM("")
	f.closeScopeTPM(st)
	assert.Same(t, f.tpm, st.TPM)
	assert.Equal(t, f.cfg.PlatformSRK, st.Parent)

	f.createPolicy("", "boot")
	key := f.createKey("", "system-signer", "boot", nil)
	require.NoError(t, f.sign("", key))
	objects, err := f.svc.ObjectsOf(f.ctx, "system", "boot")
	require.NoError(t, err)
	assert.Equal(t, []string{"key/system-signer"}, objects)
}

// TestService_PolicyErrors proves every policy operation refuses the
// reserved name, invalid names and tenants, and unknown policies.
func TestService_PolicyErrors(t *testing.T) {
	f := newSimFixture(t)
	f.createPolicy("acme", "boot")

	_, err := f.svc.CreatePolicy(f.ctx, "acme", CreatePolicyRequest{Name: "boot", Branches: []Branch{PCRBranch("sha256", testPCR)}})
	require.ErrorIs(t, err, ErrPolicyExists)
	var badTenant *InvalidTenantError
	_, err = f.svc.CreatePolicy(f.ctx, "a/b", CreatePolicyRequest{Name: "boot", Branches: []Branch{PCRBranch("sha256", testPCR)}})
	require.ErrorAs(t, err, &badTenant)
	_, err = f.svc.CreatePolicy(f.ctx, "acme", CreatePolicyRequest{Name: "x", Branches: []Branch{PCRBranch("sm3", testPCR)}})
	var badBank *InvalidPCRBankError
	require.ErrorAs(t, err, &badBank)

	for _, tc := range []struct {
		name string
		want error
	}{
		{name: PlatformPolicy, want: ErrReservedPolicy},
		{name: "missing", want: ErrPolicyNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.svc.Policy(f.ctx, "acme", tc.name)
			require.ErrorIs(t, err, tc.want)
			_, err = f.svc.UpdatePolicy(f.ctx, "acme", tc.name)
			require.ErrorIs(t, err, tc.want)
			_, err = f.svc.RevokePolicy(f.ctx, "acme", tc.name)
			require.ErrorIs(t, err, tc.want)
			_, err = f.svc.VerifyPolicy(f.ctx, "acme", tc.name)
			require.ErrorIs(t, err, tc.want)
			require.ErrorIs(t, f.svc.DeletePolicy(f.ctx, "acme", tc.name, nil), tc.want)
			require.ErrorIs(t, f.svc.SetAutoUnseal(f.ctx, "acme", tc.name, true), tc.want)
			_, err = f.svc.PolicyIndex("acme", tc.name)
			require.ErrorIs(t, err, tc.want)
			_, err = f.svc.Approvals("acme", tc.name)
			require.ErrorIs(t, err, tc.want)
		})
	}
	var badName *InvalidNameError
	_, err = f.svc.UpdatePolicy(f.ctx, "acme", "a/b")
	require.ErrorAs(t, err, &badName)
	_, err = f.svc.CreatePolicy(f.ctx, "acme", CreatePolicyRequest{Name: PlatformPolicy, Branches: []Branch{PCRBranch("sha256", testPCR)}})
	require.ErrorIs(t, err, ErrReservedPolicy)

	require.ErrorIs(t, f.svc.Assign(f.ctx, "acme", ObjectKey, "k", "missing", nil), ErrPolicyNotFound)
	require.ErrorAs(t, f.svc.Assign(f.ctx, "acme", ObjectKind("widget"), "k", "", nil), &badName)
	_, err = f.svc.PolicyOf(f.ctx, "acme", ObjectKey, "unassigned")
	require.ErrorIs(t, err, ErrNotAssigned)
	require.NoError(t, f.svc.Unassign(f.ctx, "acme", ObjectKey, "unassigned"), "unassigning nothing is not an error")
	platform, err := f.svc.ObjectsOf(f.ctx, "acme", "")
	require.NoError(t, err)
	assert.Empty(t, platform)

	_, err = f.svc.Approvals("nobody", "boot")
	require.ErrorIs(t, err, ErrScopeNotFound)
	_, err = f.svc.RotateAuthority(f.ctx, "a/b")
	require.ErrorAs(t, err, &badTenant)

	require.ErrorIs(t, f.svc.StartVTPM(f.ctx, "acme"), ErrVTPMUnavailable)
	require.ErrorIs(t, f.svc.StopVTPM(f.ctx, "acme"), ErrVTPMUnavailable)
	assert.False(t, f.svc.VTPMStatus("acme").Running)
	_, err = f.svc.StateKey("acme")
	var secretsErr *SecretsError
	require.ErrorAs(t, err, &secretsErr, "a tenant never in vtpm mode has no state key")
}

// TestService_OpenFailures proves a scope that cannot be opened is refused
// with the reason, rather than used along a guessed path: sealed secrets
// that do not unseal, a counter behind the recorded epoch, and a missing
// storage key.
func TestService_OpenFailures(t *testing.T) {
	f := newSimFixture(t)
	for _, tenant := range []string{"acme", "globex", "initech"} {
		_, err := f.svc.EnsureScope(f.ctx, tenant, nil)
		require.NoError(t, err)
	}

	acme, err := f.registry.Scope(f.ctx, "acme")
	require.NoError(t, err)
	acme.SealedSecrets = []byte("{not sealed data")
	require.NoError(t, f.registry.PutScope(f.ctx, acme))

	globex, err := f.registry.Scope(f.ctx, "globex")
	require.NoError(t, err)
	globex.Epoch += 10
	require.NoError(t, f.registry.PutScope(f.ctx, globex))

	keys, err := f.svc.tenantKeys("initech")
	require.NoError(t, err)
	require.NoError(t, keys.Delete(&types.KeyAttributes{CN: storageKeyCN}))

	f.restart()
	var secretsErr *SecretsError
	_, err = f.svc.ScopeTPM(f.ctx, "acme")
	require.ErrorAs(t, err, &secretsErr)
	var rollback *CounterRollbackError
	_, err = f.svc.ScopeTPM(f.ctx, "globex")
	require.ErrorAs(t, err, &rollback)
	assert.Equal(t, globex.Epoch, rollback.Epoch)
	var tpmErr *TPMError
	_, err = f.svc.ScopeTPM(f.ctx, "initech")
	require.ErrorAs(t, err, &tpmErr)
	assert.Equal(t, "load storage key", tpmErr.Op)
}

// withPIN returns a copy of key that presents pin as its password.
func withPIN(t *testing.T, key *types.KeyAttributes, pin string) *types.KeyAttributes {
	t.Helper()
	c := *key
	c.Password = mustPassword(t, []byte(pin))
	return &c
}

// TestService_CompositeAND proves a policy whose one branch requires both the
// PCR state and the object's password signs only when both hold: the
// password alone (after the PCR moved) and the PCR alone (no password) are
// refused, so the object got no outer password branch. A key without a
// password cannot be bound to it at all.
func TestService_CompositeAND(t *testing.T) {
	f := newSimFixture(t)
	f.createComposite("acme", "pcr-and-pin", Branch{Conditions: []Condition{
		{Type: ConditionPCR, Bank: "sha256", PCRs: []uint{testPCR}},
		{Type: ConditionAuthValue},
	}})
	key := f.createKey("acme", "and-key", "pcr-and-pin", []byte("and-pin"))

	require.NoError(t, f.sign("acme", key), "password and PCR")
	var missing *pkgtpm2.PolicyAuthValueMissingError
	require.ErrorAs(t, f.sign("acme", withoutPassword(key)), &missing, "the PCR alone")
	require.Error(t, f.sign("acme", withPIN(t, key, "wrong-pin")), "a wrong password")

	extendPCR(t, f.tpm.Transport())
	var mismatch *pkgtpm2.PolicyPCRMismatchError
	require.ErrorAs(t, f.sign("acme", key), &mismatch, "the password alone")

	st := f.scopeTPM("acme")
	defer f.closeScopeTPM(st)
	_, err := st.TPM.CreateECDSA(&types.KeyAttributes{
		CN:                 "and-key-no-pin",
		Hash:               key.Hash,
		KeyAlgorithm:       key.KeyAlgorithm,
		KeyType:            key.KeyType,
		Parent:             st.Parent,
		SignatureAlgorithm: key.SignatureAlgorithm,
		StoreType:          key.StoreType,
		TenantID:           "acme",
		TPMPolicy:          "pcr-and-pin",
		ECCAttributes:      key.ECCAttributes,
		TPMAttributes:      &types.TPMAttributes{Hierarchy: tpm2.TPMRHOwner},
	}, st.Keys, false)
	require.ErrorIs(t, err, pkgtpm2.ErrPolicyAuthValueRequired)
}

// TestService_CompositeOR proves a policy of a pcr branch OR a password
// branch: the key signs without its password while the PCR holds, with it
// once the PCR has moved, and never with a wrong one.
func TestService_CompositeOR(t *testing.T) {
	f := newSimFixture(t)
	p := f.createComposite("acme", "pcr-or-pin", pcrBranch(), authValueBranch())
	require.Len(t, p.Approvals, 2)
	key := f.createKey("acme", "or-key", "pcr-or-pin", []byte("or-pin"))

	require.NoError(t, f.sign("acme", withoutPassword(key)), "the pcr branch")

	extendPCR(t, f.tpm.Transport())
	var refused *pkgtpm2.PolicyBranchesRefusedError
	require.ErrorAs(t, f.sign("acme", withoutPassword(key)), &refused)
	assert.Len(t, refused.Branches, 2)
	require.NoError(t, f.sign("acme", key), "the password branch")
	require.ErrorIs(t, f.sign("acme", withPIN(t, key, "wrong-pin")), tpm2.TPMRCAuthFail)
}

// TestService_LocalityBranches proves a locality condition allowing the
// command locality signs, and one allowing only locality 3 is refused with
// the locality error.
func TestService_LocalityBranches(t *testing.T) {
	f := newSimFixture(t)
	f.createComposite("acme", "locality-0", Branch{Conditions: []Condition{{Type: ConditionLocality, Localities: []uint{0}}}})
	f.createComposite("acme", "locality-3", Branch{Conditions: []Condition{{Type: ConditionLocality, Localities: []uint{3}}}})

	require.NoError(t, f.sign("acme", f.createKey("acme", "key-0", "locality-0", nil)))
	var mismatch *pkgtpm2.PolicyLocalityMismatchError
	require.ErrorAs(t, f.sign("acme", f.createKey("acme", "key-3", "locality-3", nil)), &mismatch)
	assert.Equal(t, "locality-3", mismatch.Policy)
}

// TestService_CompositeLifecycle proves an update re-captures every pcr
// condition and re-approves every branch without re-keying, a revoke
// withdraws every branch, a rotation re-signs every branch, and a replayed
// set of superseded branch approvals is refused by the TPM.
func TestService_CompositeLifecycle(t *testing.T) {
	f := newSimFixture(t)
	created := f.createComposite("acme", "boot", pcrBranch(), Branch{Conditions: []Condition{
		{Type: ConditionPCR, Bank: "sha256", PCRs: []uint{0, testPCR}},
		{Type: ConditionAuthValue},
	}})
	key := f.createKey("acme", "signer", "boot", []byte("signer-pin"))
	privBefore, pubBefore := f.blobs("acme", key)
	original, err := f.svc.Approvals("acme", "boot")
	require.NoError(t, err)
	require.Len(t, original, 2)

	extendPCR(t, f.tpm.Transport())
	require.Error(t, f.sign("acme", withoutPassword(key)))
	require.Error(t, f.sign("acme", key))

	updated, err := f.svc.UpdatePolicy(f.ctx, "acme", "boot")
	require.NoError(t, err)
	require.Len(t, updated.Approvals, 2)
	for i := range updated.Branches {
		assert.Equal(t, created.Approvals[i].Epoch+1, updated.Approvals[i].Epoch)
		assert.NotEqual(t, created.Branches[i].Conditions[0].PCRValues[testPCR],
			updated.Branches[i].Conditions[0].PCRValues[testPCR], "branch %d re-captured", i)
	}
	assert.Equal(t, created.Branches[1].Conditions[0].PCRs, updated.Branches[1].Conditions[0].PCRs, "the structure never changes")
	require.NoError(t, f.sign("acme", withoutPassword(key)))
	require.NoError(t, f.sign("acme", key))
	privAfter, pubAfter := f.blobs("acme", key)
	assert.Equal(t, privBefore, privAfter, "no re-key")
	assert.Equal(t, pubBefore, pubAfter, "no re-key")

	f.tpm.SetPolicyBindingResolver(replayResolver{Service: f.svc, approvals: original})
	var refused *pkgtpm2.PolicyBranchesRefusedError
	require.ErrorAs(t, f.sign("acme", key), &refused, "the pre-update approvals no longer authorize the key")
	f.tpm.SetPolicyBindingResolver(f.svc)

	revoked, err := f.svc.RevokePolicy(f.ctx, "acme", "boot")
	require.NoError(t, err)
	assert.Equal(t, []*Approval{nil, nil}, revoked.Approvals)
	require.ErrorIs(t, f.sign("acme", key), ErrPolicyRevoked, "no outer password branch survives a revoke")
	v, err := f.svc.VerifyPolicy(f.ctx, "acme", "boot")
	require.NoError(t, err)
	assert.False(t, v.Approved)
	assert.False(t, v.Branches[0].Approved)

	_, err = f.svc.UpdatePolicy(f.ctx, "acme", "boot")
	require.NoError(t, err)
	scope, err := f.svc.RotateAuthority(f.ctx, "acme")
	require.NoError(t, err)
	rotated, err := f.svc.Policy(f.ctx, "acme", "boot")
	require.NoError(t, err)
	for _, a := range rotated.Approvals {
		assert.Equal(t, scope.Authority.Generation, a.AuthorityGeneration)
	}
	require.NoError(t, f.sign("acme", withoutPassword(key)))
	require.NoError(t, f.sign("acme", key))
}

// TestService_VerifyPolicyPerBranch proves verification reports each
// branch's own mismatched PCRs.
func TestService_VerifyPolicyPerBranch(t *testing.T) {
	f := newSimFixture(t)
	f.createComposite("acme", "boot", pcrBranch(), Branch{Conditions: []Condition{
		{Type: ConditionPCR, Bank: "sha256", PCRs: []uint{0}},
		{Type: ConditionLocality, Localities: []uint{0}},
	}}, authValueBranch())

	extendPCR(t, f.tpm.Transport())
	v, err := f.svc.VerifyPolicy(f.ctx, "acme", "boot")
	require.NoError(t, err)
	assert.Equal(t, []BranchVerification{
		{Match: false, Mismatched: []uint{testPCR}, Approved: true},
		{Match: true, Approved: true},
		{Match: true, Approved: true},
	}, v.Branches)
	assert.False(t, v.Match)
	assert.True(t, v.Approved)
}

// TestService_Description proves a description is set at creation, replaced
// by SetDescription, stored, and left alone by an update.
func TestService_Description(t *testing.T) {
	f := newSimFixture(t)
	p, err := f.svc.CreatePolicy(f.ctx, "acme", CreatePolicyRequest{
		Name: "boot", Description: "firmware state", Branches: []Branch{pcrBranch()},
	})
	require.NoError(t, err)
	assert.Equal(t, "firmware state", p.Description)

	updated, err := f.svc.SetDescription(f.ctx, "acme", "boot", "firmware and boot loader")
	require.NoError(t, err)
	assert.Equal(t, "firmware and boot loader", updated.Description)
	assert.Equal(t, p.Approvals[0].Epoch, updated.Approvals[0].Epoch, "a description change signs nothing")

	_, err = f.svc.UpdatePolicy(f.ctx, "acme", "boot")
	require.NoError(t, err)
	stored, err := f.svc.Policy(f.ctx, "acme", "boot")
	require.NoError(t, err)
	assert.Equal(t, "firmware and boot loader", stored.Description)

	_, err = f.svc.SetDescription(f.ctx, "acme", "missing", "x")
	require.ErrorIs(t, err, ErrPolicyNotFound)
}
