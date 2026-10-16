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

package policy

import (
	"bytes"
	"context"
	"errors"

	"github.com/google/go-tpm/tpm2"
	xscope "github.com/jeremyhahn/go-xkms/pkg/scope"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/vtpm"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// stateKeyCNPrefix names the sealed object, in the system scope, that holds
// a tenant's vTPM state key.
const stateKeyCNPrefix = "vtpm-state-"

// openVTPM starts st's vTPM, connects to it, provisions it on its first
// start, and sets st.tpm. The caller holds st.mu.
func (s *Service) openVTPM(ctx context.Context, st *scopeState) (err error) {
	if s.vtpm == nil {
		return ErrVTPMUnavailable
	}
	if err := s.vtpm.Start(ctx, st.name); err != nil {
		return &VTPMError{Tenant: st.name, Op: "start", Err: err}
	}
	socket, err := s.vtpm.Transport(st.name)
	if err != nil {
		return &VTPMError{Tenant: st.name, Op: "connect", Err: err}
	}
	conn := socket
	defer func() {
		if err != nil {
			err = errors.Join(err, conn.Close())
		}
	}()
	keys, err := s.tenantKeys(st.name)
	if err != nil {
		return err
	}

	// The vTPM has the physical TPM's profile: the same EK, SRK and
	// platform-PCR configuration, reached over the vTPM's own connection.
	cfg := *s.tpm.Config()
	cfg.UseSimulator = false
	opened, err := pkgtpm2.NewTPM2(&pkgtpm2.Params{Config: &cfg, Backend: keys, Logger: s.logger, Transport: conn})
	fresh := errors.Is(err, pkgtpm2.ErrNotInitialized)
	if err != nil && !fresh {
		return &VTPMError{Tenant: st.name, Op: "open", Err: err}
	}
	t, ok := opened.(*pkgtpm2.TPM2)
	if !ok {
		return ErrUnexpectedTPM
	}
	if fresh {
		if err := pkgtpm2.ProvisionFresh(t, t.Config()); err != nil {
			return &VTPMError{Tenant: st.name, Op: "provision", Err: err}
		}
	}
	parent, err := t.PlatformSRKAttributes()
	if err != nil {
		return &VTPMError{Tenant: st.name, Op: "read Platform SRK", Err: err}
	}
	t.SetPolicyBindingResolver(s)
	st.conn = conn
	st.tpm = &ScopeTPM{Scope: st.name, TPM: t, Parent: parent, Keys: keys}
	return nil
}

// StartVTPM starts tenant's vTPM and opens its scope. Starting a running
// vTPM is a no-op.
func (s *Service) StartVTPM(ctx context.Context, tenant string) error {
	st, unlock, err := s.lockScope(tenant)
	if err != nil {
		return err
	}
	defer unlock()
	scope, err := s.requireVTPM(ctx, st)
	if err != nil {
		return err
	}
	if st.tpm != nil {
		return nil
	}
	if err := s.open(ctx, st, scope); err != nil {
		return err
	}
	return s.reconcile(ctx, st, scope)
}

// StopVTPM closes tenant's vTPM connection and stops the vTPM, which saves
// its state. A ScopeTPM obtained before cannot be used afterwards; the next
// use of the scope starts the vTPM again.
func (s *Service) StopVTPM(ctx context.Context, tenant string) error {
	st, unlock, err := s.lockScope(tenant)
	if err != nil {
		return err
	}
	defer unlock()
	if _, err := s.requireVTPM(ctx, st); err != nil {
		return err
	}
	if err := s.release(st); err != nil {
		return err
	}
	if err := s.vtpm.Stop(st.name); err != nil {
		return &VTPMError{Tenant: st.name, Op: "stop", Err: err}
	}
	return nil
}

// VTPMStatus reports tenant's vTPM. Without a vTPM supervisor, or for a
// tenant with no running vTPM, Running is false.
func (s *Service) VTPMStatus(tenant string) vtpm.Status {
	name := xscope.TenantName(tenant)
	if s.vtpm == nil {
		return vtpm.Status{Tenant: name}
	}
	return s.vtpm.Status(name)
}

// requireVTPM returns st's scope, or ErrNotVTPMMode when it is not a vtpm
// scope. The caller holds st.mu.
func (s *Service) requireVTPM(ctx context.Context, st *scopeState) (*Scope, error) {
	if s.vtpm == nil {
		return nil, ErrVTPMUnavailable
	}
	scope, err := s.registry.Scope(ctx, st.name)
	if errors.Is(err, ErrScopeNotFound) {
		return nil, ErrNotVTPMMode
	}
	if err != nil {
		return nil, err
	}
	if scope.Mode != ModeVTPM {
		return nil, ErrNotVTPMMode
	}
	return scope, nil
}

// StateKey implements vtpm.StateKeyProvider: tenant's vTPM state key,
// unsealed from the system scope by the physical TPM under the vtpm-state
// policy.
func (s *Service) StateKey(tenant string) ([]byte, error) {
	if key, ok := s.stateKeys.Load(tenant); ok {
		return bytes.Clone(key.([]byte)), nil
	}
	// The system scope is opened (and reconciled) first, so an approval
	// left behind by a crash is renewed before the unseal needs it.
	if _, err := s.EnsureScope(context.Background(), "", nil); err != nil {
		return nil, err
	}
	key, err := s.tpm.UnsealKey(s.stateKeyAttrs(tenant, nil), s.keys)
	if err != nil {
		return nil, &SecretsError{Scope: tenant, Op: "unseal vTPM state key", Err: err}
	}
	s.stateKeys.Store(tenant, key)
	return bytes.Clone(key), nil
}

// stateKeyAttrs returns the attributes of the system-scope sealed object
// holding tenant's vTPM state key, bound to the vtpm-state policy.
func (s *Service) stateKeyAttrs(tenant string, key []byte) *types.KeyAttributes {
	attrs := &types.KeyAttributes{
		CN:            stateKeyCNPrefix + tenant,
		KeyType:       types.KeyTypeHMAC,
		Parent:        s.platformSRK,
		StoreType:     types.StoreTPM2,
		TPMPolicy:     VTPMStatePolicy,
		TPMAttributes: &types.TPMAttributes{Hierarchy: tpm2.TPMRHOwner},
	}
	if key != nil {
		attrs.SealData = types.NewSealData(key)
	}
	return attrs
}

// ensureStateKey makes sure tenant has a vTPM state key: a random key sealed
// in the system scope under the vtpm-state policy, which is created (over
// the platform PCR) the first time any tenant needs it. A key left by an
// earlier vtpm scope of the tenant is kept, because the vTPM's saved state
// is encrypted with it. ownerAuth authorizes the physical TPM's owner
// hierarchy. The caller holds the tenant's lock, never the system scope's.
func (s *Service) ensureStateKey(ctx context.Context, tenant string, ownerAuth []byte) error {
	st, unlock, err := s.lockScope("")
	if err != nil {
		return err
	}
	defer unlock()
	scope, err := s.loadActive(ctx, st, ownerAuth)
	if err != nil {
		return err
	}
	if err := s.ensureStatePolicy(ctx, st, scope, ownerAuth); err != nil {
		return err
	}

	attrs := s.stateKeyAttrs(tenant, nil)
	_, err = s.keys.Get(attrs, store.FSEXT_PUBLIC_BLOB)
	switch {
	case err == nil:
		return nil
	case !errors.Is(err, store.ErrBlobNotFound):
		return &SecretsError{Scope: tenant, Op: "read vTPM state key", Err: err}
	}

	key, err := randomSecret()
	if err != nil {
		return &SecretsError{Scope: tenant, Op: "generate vTPM state key", Err: err}
	}
	created, err := s.tpm.SealKey(s.stateKeyAttrs(tenant, key), s.keys, false)
	if err != nil {
		return &SecretsError{Scope: tenant, Op: "seal vTPM state key", Err: err}
	}
	public, err := created.OutPublic.Contents()
	if err != nil {
		return &SecretsError{Scope: tenant, Op: "seal vTPM state key", Err: err}
	}
	if err := s.registry.Assign(ctx, st.name, &Assignment{
		ObjectID:   ObjectID(ObjectSealed, attrs.CN),
		Kind:       ObjectSealed,
		Policy:     VTPMStatePolicy,
		AuthPolicy: public.AuthPolicy.Buffer,
		CreatedAt:  s.clock(),
	}); err != nil {
		return err
	}
	s.stateKeys.Store(tenant, key)
	return nil
}

// ensureStatePolicy creates the system scope's vtpm-state policy over the
// physical TPM's platform PCR set when it does not exist. The caller holds the
// system scope's lock.
func (s *Service) ensureStatePolicy(ctx context.Context, st *scopeState, scope *Scope, ownerAuth []byte) error {
	_, err := s.registry.Policy(ctx, st.name, VTPMStatePolicy)
	if !errors.Is(err, ErrPolicyNotFound) {
		return err
	}
	cfg := s.tpm.Config()
	bank := cfg.PlatformPCRBank
	if bank == "" {
		bank = pkgtpm2.PCRBankSHA256
	}
	branches, err := validateBranches([]Branch{PCRBranch(bank, cfg.PlatformPCRs...)})
	if err != nil {
		return err
	}
	_, err = s.createPolicy(ctx, st, scope, CreatePolicyRequest{
		Name:        VTPMStatePolicy,
		Description: "Seals each vTPM's state key to the physical TPM's platform PCR.",
		Branches:    branches,
		OwnerAuth:   ownerAuth,
	})
	return err
}
