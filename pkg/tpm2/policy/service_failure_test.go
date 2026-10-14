//go:build tpm_simulator

package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/dao"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/vtpm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newFailingVTPMFixture returns a simulator-backed fixture whose vTPM
// manager runs a fake swtpm that exits at once.
func newFailingVTPMFixture(t *testing.T) *fixture {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "fake-swtpm")
	require.NoError(t, os.WriteFile(binary, []byte("#!/bin/sh\nexit 3\n"), 0o700))

	keys := memoryBlobs(t)
	cfg := pkgtpm2.DefaultConfig
	cfg.UseSimulator = true
	tpm := provisionedTPM(t, &pkgtpm2.Params{Config: &cfg, Backend: keys, Logger: quietLogger})
	return newFixture(t, tpm, keys, &vtpm.Config{Binary: binary, StateDir: t.TempDir(), RunDir: shortDir(t), Logger: quietLogger})
}

// newServiceOverFailingStore returns a service with f's TPM and keys over a
// registry whose entity keys fail once the returned store is armed.
func newServiceOverFailingStore(t *testing.T, f *fixture, entity string) (*Service, *entityFailingStore) {
	t.Helper()
	store := &entityFailingStore{AtomicKVStore: qrdbsdk.NewMemoryKVStore(), entity: entity, ops: map[string]bool{}}
	registry, err := NewRegistry(dao.NewStoreFactory(store))
	require.NoError(t, err)
	cfg := f.cfg
	cfg.Registry = registry
	svc, err := NewService(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, svc.Close()) })
	return svc, store
}

// TestService_VTPMThatCannotStartLeavesTheTenantOutOfVTPMMode proves a node
// whose swtpm will not start reports a *VTPMError and records no vtpm scope,
// so the tenant is not left pointing at a vTPM that does not exist.
func TestService_VTPMThatCannotStartLeavesTheTenantOutOfVTPMMode(t *testing.T) {
	f := newFailingVTPMFixture(t)

	err := f.svc.SetMode(f.ctx, "acme", ModeVTPM, nil)
	var vtpmErr *VTPMError
	require.ErrorAs(t, err, &vtpmErr)
	assert.Equal(t, "acme", vtpmErr.Tenant)
	assert.Equal(t, "start", vtpmErr.Op)
	assert.ErrorIs(t, err, vtpm.ErrNotRunning)
	assert.False(t, f.svc.VTPMStatus("acme").Running)

	mode, err := f.svc.Mode(f.ctx, "acme")
	require.NoError(t, err)
	assert.NotEqual(t, ModeVTPM, mode)
	assert.ErrorIs(t, f.svc.StartVTPM(f.ctx, "acme"), ErrNotVTPMMode)
}

// TestService_ReportsAScopeReadFailureInsteadOfAssumingTheDefaultMode proves
// a scope the registry cannot read is a *StoreError, never mistaken for an
// absent scope and its default mode.
func TestService_ReportsAScopeReadFailureInsteadOfAssumingTheDefaultMode(t *testing.T) {
	svc, store := newServiceOverFailingStore(t, newFailingVTPMFixture(t), scopeEntityType)
	store.arm("get")

	ctx := context.Background()
	ops := map[string]func() error{
		"mode":          func() error { _, err := svc.Mode(ctx, "acme"); return err },
		"set mode":      func() error { return svc.SetMode(ctx, "acme", ModeVTPM, nil) },
		"start vtpm":    func() error { return svc.StartVTPM(ctx, "acme") },
		"stop vtpm":     func() error { return svc.StopVTPM(ctx, "acme") },
		"list policies": func() error { _, err := svc.ListPolicies(ctx, "acme"); return err },
		"policy":        func() error { _, err := svc.Policy(ctx, "acme", "boot"); return err },
		"assign":        func() error { return svc.Assign(ctx, "acme", ObjectKey, "signer", "boot", nil) },
		"unassign":      func() error { return svc.Unassign(ctx, "acme", ObjectKey, "signer") },
		"policy of":     func() error { _, err := svc.PolicyOf(ctx, "acme", ObjectKey, "signer"); return err },
		"objects of":    func() error { _, err := svc.ObjectsOf(ctx, "acme", "boot"); return err },
	}
	for name, run := range ops {
		t.Run(name, func(t *testing.T) {
			requireStoreOp(t, run(), "get")
		})
	}
}

// TestService_ReportsPolicyChangesItCannotStore proves a policy change the
// registry refuses is reported and leaves the stored policy as it was; in
// particular a revocation that is not stored does not move the counter.
func TestService_ReportsPolicyChangesItCannotStore(t *testing.T) {
	svc, store := newServiceOverFailingStore(t, newSimFixture(t), policyEntityType)
	ctx := context.Background()
	request := CreatePolicyRequest{Name: "boot", Branches: []Branch{PCRBranch("sha256", testPCR)}}
	created, err := svc.CreatePolicy(ctx, "acme", request)
	require.NoError(t, err)
	require.True(t, created.approved())
	store.arm("put")

	_, err = svc.RevokePolicy(ctx, "acme", "boot")
	requireStoreOp(t, err, "put")
	_, err = svc.SetDescription(ctx, "acme", "boot", "boot chain")
	requireStoreOp(t, err, "put")
	requireStoreOp(t, svc.SetAutoUnseal(ctx, "acme", "boot", true), "put")

	stored, err := svc.Policy(ctx, "acme", "boot")
	require.NoError(t, err)
	assert.True(t, stored.approved(), "an unstored revocation leaves the policy approved")
	assert.Equal(t, created.Description, stored.Description)
	assert.False(t, stored.AutoUnseal)
}
