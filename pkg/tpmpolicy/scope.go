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

package tpmpolicy

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

const (
	// storageKeyCN names a shared-mode tenant's storage key in the tenant's
	// own key store.
	storageKeyCN = "tpm-storage-key"

	// authorityCNPrefix names a scope's policy authority, followed by its
	// generation.
	authorityCNPrefix = "tpm-policy-authority-"

	// tenantKeysSuffix is appended to a tenant's name to form the prefix of
	// its key store within Config.KeyStorage.
	tenantKeysSuffix = "/tpm/keys/"
)

// ScopeTPM is where a scope's TPM objects live: the TPM, the storage parent
// to create and load them under, and the key store holding their blobs. The
// caller closes it when done, which flushes a shared tenant's storage key.
//
//   - system scope: the physical TPM, the Platform SRK, the physical key
//     store;
//   - shared tenant: the physical TPM, the tenant's own storage key (a child
//     of the Platform SRK authorized by a secret only the tenant's scope
//     holds), and a key store under "<tenant>/tpm/keys/";
//   - vtpm tenant: the tenant's vTPM, its Platform SRK, and a key store under
//     "<tenant>/tpm/keys/".
type ScopeTPM struct {
	// Scope is the scope name: the tenant ID, or "system".
	Scope string

	// TPM is the TPM holding the scope's objects.
	TPM *pkgtpm2.TPM2

	// Parent is the storage parent of the scope's objects, loaded.
	Parent *types.KeyAttributes

	// Keys stores the blobs of the scope's objects.
	Keys store.KeyBackend

	// release flushes the loaded storage key a shared tenant's ScopeTPM
	// owns; nil when Parent is persistent.
	release func() error
}

// Close releases the ScopeTPM's loaded parent. A TPM holds only a few
// transient objects at once (three on the reference simulator, and three per
// connection through the Linux kernel's resource manager), so a tenant's
// storage key is loaded only while it is used. Close is safe to call more
// than once.
func (t *ScopeTPM) Close() error {
	if t.release == nil {
		return nil
	}
	release := t.release
	t.release = nil
	return release()
}

// scopeState is the in-process state of one scope: the lock serializing its
// multi-step TPM operations, and its open TPM and unsealed secrets.
type scopeState struct {
	name string
	mu   sync.Mutex

	// tpm and secrets are set once the scope is opened in this process. A
	// shared tenant's tpm.Parent is its storage key, loaded only while an
	// operation holds mu and nil otherwise.
	tpm     *ScopeTPM
	secrets *scopeSecrets

	// conn is the vTPM connection of a vtpm-mode scope.
	conn transport.TPMCloser
}

// isSystem reports whether the state is the system scope's.
func (st *scopeState) isSystem() bool { return st.name == systemScopeName }

// tenantID returns the KeyAttributes.TenantID of the scope's objects: empty
// for the system scope.
func (st *scopeState) tenantID() string {
	if st.isSystem() {
		return ""
	}
	return st.name
}

// hasStorageKey reports whether the scope's parent is a tenant storage key
// that must be loaded for use, rather than a persistent SRK.
func (st *scopeState) hasStorageKey() bool {
	return st.tpm != nil && st.conn == nil && !st.isSystem()
}

// ownerAuth returns the owner-hierarchy auth for the scope's TPM: the
// caller's physical-TPM owner auth, or none for a vTPM, whose owner
// hierarchy xkms provisioned without one.
func (st *scopeState) ownerAuth(physical []byte) []byte {
	if st.conn != nil {
		return nil
	}
	return physical
}

// scopeName validates tenant and returns its scope name.
func scopeName(tenant string) (string, error) {
	name := ScopeName(tenant)
	if err := storage.ValidateTenantID(name); err != nil {
		return "", &InvalidTenantError{Tenant: tenant, Err: err}
	}
	return name, nil
}

// lockScope returns tenant's scope state, locked, and its unlock function,
// which also flushes the storage key the operation loaded.
func (s *Service) lockScope(tenant string) (*scopeState, func(), error) {
	name, err := scopeName(tenant)
	if err != nil {
		return nil, nil, err
	}
	s.statesMu.Lock()
	st, ok := s.states[name]
	if !ok {
		st = &scopeState{name: name}
		s.states[name] = st
	}
	s.statesMu.Unlock()
	st.mu.Lock()
	unlock := func() {
		if err := s.unloadParent(st); err != nil {
			s.logger.Error("tpmpolicy: failed to flush a tenant storage key",
				slog.String("scope", st.name), slog.Any("error", err))
		}
		st.mu.Unlock()
	}
	return st, unlock, nil
}

// loadParent loads a shared tenant's storage key into st.tpm.Parent for the
// operation holding st.mu. Other scopes' parents are persistent.
func (s *Service) loadParent(st *scopeState) error {
	if !st.hasStorageKey() || st.tpm.Parent != nil {
		return nil
	}
	parent, err := s.loadStorageKey(st, st.tpm.Keys)
	if err != nil {
		return err
	}
	st.tpm.Parent = parent
	return nil
}

// unloadParent flushes the storage key loadParent loaded.
func (s *Service) unloadParent(st *scopeState) error {
	if !st.hasStorageKey() || st.tpm.Parent == nil {
		return nil
	}
	parent := st.tpm.Parent
	st.tpm.Parent = nil
	return s.flush(st.name, parent)
}

// flush flushes a loaded storage key from the physical TPM.
func (s *Service) flush(scope string, key *types.KeyAttributes) error {
	_, err := tpm2.FlushContext{FlushHandle: key.TPMAttributes.Handle}.Execute(s.tpm.Transport())
	if err != nil {
		return &TPMError{Scope: scope, Op: "flush storage key", Err: err}
	}
	return nil
}

// defaultMode is the mode a scope is created with on first use: the system
// scope is always on the physical TPM.
func defaultMode(name string) Mode {
	if name == systemScopeName {
		return ModeShared
	}
	return DefaultMode
}

// EnsureScope returns tenant's scope, creating it with DefaultMode on first
// use ("" or "system" is the system scope, always on the physical TPM).
// ownerAuth authorizes defining the scope's counter under the physical TPM's
// owner hierarchy; it is only used when the scope is created. A scope loaded
// for the first time in this process is reconciled: an interrupted authority
// rotation is finished, and approvals behind the counter are re-signed.
func (s *Service) EnsureScope(ctx context.Context, tenant string, ownerAuth []byte) (*Scope, error) {
	st, unlock, err := s.lockScope(tenant)
	if err != nil {
		return nil, err
	}
	defer unlock()
	return s.load(ctx, st, ownerAuth)
}

// ScopeTPM returns where tenant's TPM objects live, creating the scope on
// first use. A scope whose counter needs a non-empty owner auth to define
// must be created first with EnsureScope or SetMode.
func (s *Service) ScopeTPM(ctx context.Context, tenant string) (*ScopeTPM, error) {
	st, unlock, err := s.lockScope(tenant)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if _, err := s.loadActive(ctx, st, nil); err != nil {
		return nil, err
	}
	scopeTPM := *st.tpm
	if st.hasStorageKey() {
		// The loaded storage key passes to the caller, whose Close flushes it.
		parent := st.tpm.Parent
		st.tpm.Parent = nil
		scopeTPM.release = func() error { return s.flush(st.name, parent) }
	}
	return &scopeTPM, nil
}

// Mode returns tenant's TPM mode: DefaultMode for a tenant with no scope yet.
func (s *Service) Mode(ctx context.Context, tenant string) (Mode, error) {
	name, err := scopeName(tenant)
	if err != nil {
		return "", err
	}
	scope, err := s.registry.Scope(ctx, name)
	if errors.Is(err, ErrScopeNotFound) {
		return defaultMode(name), nil
	}
	if err != nil {
		return "", err
	}
	return scope.Mode, nil
}

// requireTPM returns ErrTPMModeNone when tenant's mode is none.
func (s *Service) requireTPM(ctx context.Context, tenant string) (string, error) {
	name, err := scopeName(tenant)
	if err != nil {
		return "", err
	}
	mode, err := s.Mode(ctx, name)
	if err != nil {
		return "", err
	}
	if mode == ModeNone {
		return "", ErrTPMModeNone
	}
	return name, nil
}

// SetMode changes tenant's TPM mode. Only the system administrator may call
// it; enforcing that is the caller's job. The system scope's mode cannot
// change, and a scope that holds objects or policies is refused with
// *ScopeInUseError, because TPM objects cannot move between TPMs. The old
// scope's TPM resources are removed and the new scope is created; ownerAuth
// authorizes the physical TPM's owner hierarchy for both.
//
// Leaving vtpm mode stops the tenant's vTPM but keeps its state and state
// key, so returning to vtpm mode resumes the same vTPM.
func (s *Service) SetMode(ctx context.Context, tenant string, mode Mode, ownerAuth []byte) error {
	if _, ok := modes[mode]; !ok {
		return &InvalidModeError{Mode: string(mode)}
	}
	st, unlock, err := s.lockScope(tenant)
	if err != nil {
		return err
	}
	defer unlock()
	if st.isSystem() {
		return ErrSystemScopeMode
	}

	scope, err := s.registry.Scope(ctx, st.name)
	found := err == nil
	if err != nil && !errors.Is(err, ErrScopeNotFound) {
		return err
	}
	current := defaultMode(st.name)
	if found {
		current = scope.Mode
	}
	switch {
	case found && current == mode:
		return nil
	case current != mode:
		// Objects may be recorded before the scope itself exists, so the
		// check does not depend on finding a scope record.
		if err := s.registry.refuseIfPopulated(ctx, st.name); err != nil {
			return err
		}
	}
	if found {
		if err := s.teardown(ctx, st, scope, ownerAuth); err != nil {
			return err
		}
		if err := s.registry.DeleteScope(ctx, st.name); err != nil {
			return err
		}
	}
	_, err = s.create(ctx, st, mode, ownerAuth)
	return err
}

// load returns st's scope, creating it with its default mode when it has
// none, and opens and reconciles it on first use in this process. The caller
// holds st.mu.
func (s *Service) load(ctx context.Context, st *scopeState, ownerAuth []byte) (*Scope, error) {
	scope, err := s.registry.Scope(ctx, st.name)
	if errors.Is(err, ErrScopeNotFound) {
		return s.create(ctx, st, defaultMode(st.name), ownerAuth)
	}
	if err != nil {
		return nil, err
	}
	if scope.Mode == ModeNone {
		return scope, nil
	}
	if st.tpm != nil {
		return scope, s.loadParent(st)
	}
	if err := s.open(ctx, st, scope); err != nil {
		return nil, err
	}
	if err := s.reconcile(ctx, st, scope); err != nil {
		return nil, err
	}
	return scope, nil
}

// loadActive is load for operations that need the scope's TPM: it refuses a
// scope whose mode is none.
func (s *Service) loadActive(ctx context.Context, st *scopeState, ownerAuth []byte) (*Scope, error) {
	scope, err := s.load(ctx, st, ownerAuth)
	if err != nil {
		return nil, err
	}
	if scope.Mode == ModeNone {
		return nil, ErrTPMModeNone
	}
	return scope, nil
}

// open unseals an existing scope's secrets and opens its TPM. The caller
// holds st.mu.
func (s *Service) open(ctx context.Context, st *scopeState, scope *Scope) error {
	secrets, err := s.unsealSecrets(ctx, st.name, scope.SealedSecrets)
	if err != nil {
		return err
	}
	st.secrets = secrets
	if err := s.openTPM(ctx, st, scope.Mode); err != nil {
		st.secrets = nil
		return err
	}
	return nil
}

// openTPM sets st.tpm for a scope of mode whose secrets are set. A shared
// tenant's storage key must already exist.
func (s *Service) openTPM(ctx context.Context, st *scopeState, mode Mode) error {
	switch {
	case st.isSystem():
		st.tpm = &ScopeTPM{Scope: st.name, TPM: s.tpm, Parent: s.platformSRK, Keys: s.keys}
		return nil
	case mode == ModeVTPM:
		return s.openVTPM(ctx, st)
	}
	keys, err := s.tenantKeys(st.name)
	if err != nil {
		return err
	}
	st.tpm = &ScopeTPM{Scope: st.name, TPM: s.tpm, Keys: keys}
	if err := s.loadParent(st); err != nil {
		st.tpm = nil
		return err
	}
	return nil
}

// create creates st's scope in mode: its secrets, storage key (shared
// tenants), counter and first policy authority, then the scope record. A
// failure removes whatever TPM resources were already created, so the scope
// can be created again. The caller holds st.mu.
func (s *Service) create(ctx context.Context, st *scopeState, mode Mode, ownerAuth []byte) (_ *Scope, err error) {
	now := s.clock()
	scope := &Scope{Tenant: st.name, Mode: mode, CreatedAt: now, UpdatedAt: now}
	if mode == ModeNone {
		return scope, s.registry.PutScope(ctx, scope)
	}

	var undo []func() error
	defer func() {
		if err == nil {
			return
		}
		for i := len(undo) - 1; i >= 0; i-- {
			err = errors.Join(err, undo[i]())
		}
		err = errors.Join(err, s.release(st))
	}()

	if mode == ModeVTPM {
		if s.vtpm == nil {
			return nil, ErrVTPMUnavailable
		}
		if err := s.ensureStateKey(ctx, st.name, ownerAuth); err != nil {
			return nil, err
		}
	}

	shared := mode == ModeShared && !st.isSystem()
	secrets, err := newScopeSecrets(st.name, shared)
	if err != nil {
		return nil, err
	}
	if scope.SealedSecrets, err = s.sealSecrets(ctx, st.name, secrets); err != nil {
		return nil, err
	}
	undo = append(undo, func() error { return s.deleteSealedSecrets(st.name) })
	st.secrets = secrets

	if shared {
		keys, err := s.tenantKeys(st.name)
		if err != nil {
			return nil, err
		}
		if err := s.createStorageKey(st, keys); err != nil {
			return nil, err
		}
		undo = append(undo, func() error { return keys.Delete(s.storageKeyAttrs(st, nil)) })
		scope.StorageKey = storageKeyCN
	}
	if err := s.openTPM(ctx, st, mode); err != nil {
		return nil, err
	}

	counter, err := s.defineIndex(st, func(t *pkgtpm2.TPM2, index tpm2.TPMHandle) error {
		_, err := t.DefineCounterIndex(index, secrets.NVWriteAuth, st.ownerAuth(ownerAuth))
		return err
	})
	if err != nil {
		return nil, err
	}
	undo = append(undo, func() error { return s.undefineIndex(st, counter, ownerAuth) })
	scope.Counter = uint32(counter)
	if scope.Epoch, err = st.tpm.TPM.ReadCounter(counter); err != nil {
		return nil, &TPMError{Scope: st.name, Op: "read counter", Err: err}
	}

	authority, err := s.createAuthority(st, 1)
	if err != nil {
		return nil, err
	}
	undo = append(undo, func() error { return s.deleteAuthority(st, authority) })
	scope.Authority = *authority

	if err := s.registry.PutScope(ctx, scope); err != nil {
		return nil, err
	}
	s.logger.Info("tpmpolicy: created TPM scope",
		slog.String("scope", st.name),
		slog.String("mode", string(mode)),
		slog.String("counter", fmt.Sprintf("0x%08x", counter)))
	return scope, nil
}

// teardown removes an existing scope's TPM resources before its mode
// changes: its counter, authorities, storage key and sealed secrets. A vTPM
// is stopped. The caller holds st.mu and has checked the scope is empty.
func (s *Service) teardown(ctx context.Context, st *scopeState, scope *Scope, ownerAuth []byte) error {
	if scope.Mode == ModeNone {
		return nil
	}
	if st.tpm == nil {
		if err := s.open(ctx, st, scope); err != nil {
			return err
		}
	}
	if err := s.undefineIndex(st, tpm2.TPMHandle(scope.Counter), ownerAuth); err != nil {
		return err
	}
	authorities := []*Authority{&scope.Authority}
	if scope.Rotating != nil {
		authorities = append(authorities, scope.Rotating)
	}
	for _, authority := range authorities {
		if err := s.deleteAuthority(st, authority); err != nil {
			return err
		}
	}
	keys := st.tpm.Keys
	vtpmMode := st.conn != nil
	if err := s.release(st); err != nil {
		return err
	}
	if scope.StorageKey != "" {
		if err := keys.Delete(s.storageKeyAttrs(st, nil)); err != nil {
			return &TPMError{Scope: st.name, Op: "delete storage key", Err: err}
		}
	}
	if vtpmMode {
		if err := s.vtpm.Stop(st.name); err != nil {
			return &VTPMError{Tenant: st.name, Op: "stop", Err: err}
		}
	}
	return s.deleteSealedSecrets(st.name)
}

// release forgets st's open TPM and secrets: it flushes a shared tenant's
// loaded storage key, or closes a vTPM connection. The caller holds st.mu.
func (s *Service) release(st *scopeState) error {
	err := s.unloadParent(st)
	if st.conn != nil {
		if closeErr := errors.Join(st.tpm.TPM.Close(), st.conn.Close()); closeErr != nil {
			err = errors.Join(err, &VTPMError{Tenant: st.name, Op: "disconnect", Err: closeErr})
		}
	}
	st.tpm, st.secrets, st.conn = nil, nil, nil
	return err
}

// reconcile finishes what a crash interrupted when a scope is opened: an
// authority rotation in progress, and approvals signed at an epoch the
// counter has moved past. Re-signing at the counter's value is safe: the
// stored PCR values are the ones already approved. The caller holds st.mu.
func (s *Service) reconcile(ctx context.Context, st *scopeState, scope *Scope) error {
	if scope.Rotating != nil {
		if err := s.finishRotation(ctx, st, scope); err != nil {
			return err
		}
	}
	counter, err := st.tpm.TPM.ReadCounter(tpm2.TPMHandle(scope.Counter))
	if err != nil {
		return &TPMError{Scope: st.name, Op: "read counter", Err: err}
	}
	switch {
	case counter < scope.Epoch:
		return &CounterRollbackError{Scope: st.name, Counter: counter, Epoch: scope.Epoch}
	case counter > scope.Epoch:
		s.logger.Warn("tpmpolicy: re-signing approvals behind the revocation counter",
			slog.String("scope", st.name),
			slog.Uint64("epoch", scope.Epoch),
			slog.Uint64("counter", counter))
		_, err := s.resignAll(ctx, st, scope, counter, nil)
		return err
	}
	return nil
}

// tenantKeys returns the key store of a tenant's objects: Config.KeyStorage
// under "<tenant>/tpm/keys/".
func (s *Service) tenantKeys(tenant string) (store.KeyBackend, error) {
	prefixed, err := storage.NewPrefixBackend(s.keyStorage, tenant+tenantKeysSuffix)
	if err != nil {
		return nil, &StoreError{Op: "prefix", Key: tenant + tenantKeysSuffix, Err: err}
	}
	return store.NewFileBackend(s.logger, prefixed), nil
}

// storageKeyAttrs returns the attributes of a shared tenant's storage key,
// authorized by its secret when secrets are known.
func (s *Service) storageKeyAttrs(st *scopeState, auth types.Password) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:            storageKeyCN,
		KeyAlgorithm:  s.platformSRK.KeyAlgorithm,
		KeyType:       types.KeyTypeStorage,
		Parent:        s.platformSRK,
		Password:      auth,
		StoreType:     types.StoreTPM2,
		TenantID:      st.tenantID(),
		TPMAttributes: &types.TPMAttributes{Hierarchy: tpm2.TPMRHOwner},
	}
}

// createStorageKey creates a shared tenant's storage key under the Platform
// SRK in the tenant's key store.
func (s *Service) createStorageKey(st *scopeState, keys store.KeyBackend) error {
	auth, err := password(st.name, st.secrets.StorageKeyAuth)
	if err != nil {
		return err
	}
	if err := s.tpm.CreateStorageKey(s.storageKeyAttrs(st, auth), keys); err != nil {
		return &TPMError{Scope: st.name, Op: "create storage key", Err: err}
	}
	return nil
}

// loadStorageKey loads a shared tenant's storage key and returns its
// attributes with the loaded handle and Name, ready to parent the tenant's
// objects. The key stays loaded until the scope is released.
func (s *Service) loadStorageKey(st *scopeState, keys store.KeyBackend) (*types.KeyAttributes, error) {
	auth, err := password(st.name, st.secrets.StorageKeyAuth)
	if err != nil {
		return nil, err
	}
	attrs := s.storageKeyAttrs(st, auth)
	loaded, err := s.tpm.LoadKeyPair(attrs, nil, keys)
	if err != nil {
		return nil, &TPMError{Scope: st.name, Op: "load storage key", Err: err}
	}
	attrs.TPMAttributes.Handle = loaded.ObjectHandle
	attrs.TPMAttributes.Name = loaded.Name
	return attrs, nil
}

// authorityCN returns the CN of a scope's policy authority of generation.
func authorityCN(generation uint64) string {
	return fmt.Sprintf("%s%d", authorityCNPrefix, generation)
}

// authorityAttrs returns the attributes of the policy authority named cn:
// an ECDSA P-256 signing key under the scope's parent, bound to the platform
// policy and authorized by the scope's authority secret.
func (s *Service) authorityAttrs(st *scopeState, cn string) (*types.KeyAttributes, error) {
	auth, err := password(st.name, st.secrets.AuthorityAuth)
	if err != nil {
		return nil, err
	}
	return &types.KeyAttributes{
		CN:                 cn,
		Hash:               crypto.SHA256,
		KeyAlgorithm:       x509.ECDSA,
		KeyType:            types.KeyTypeSigning,
		Parent:             st.tpm.Parent,
		Password:           auth,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		StoreType:          types.StoreTPM2,
		TenantID:           st.tenantID(),
		TPMPolicy:          types.TPMPolicyPlatform,
		ECCAttributes:      &types.ECCAttributes{Curve: elliptic.P256()},
		TPMAttributes:      &types.TPMAttributes{Hierarchy: tpm2.TPMRHOwner},
	}, nil
}

// createAuthority creates the scope's policy authority of generation in the
// scope's key store and returns its identity. A blob left by an interrupted
// earlier attempt at the same generation is overwritten: no index or
// approval can name it yet.
func (s *Service) createAuthority(st *scopeState, generation uint64) (*Authority, error) {
	attrs, err := s.authorityAttrs(st, authorityCN(generation))
	if err != nil {
		return nil, err
	}
	if _, err := st.tpm.TPM.CreateECDSA(attrs, st.tpm.Keys, true); err != nil {
		return nil, &TPMError{Scope: st.name, Op: "create policy authority", Err: err}
	}
	name, public, err := st.tpm.TPM.AuthorityName(attrs, st.tpm.Keys)
	if err != nil {
		return nil, &TPMError{Scope: st.name, Op: "read policy authority", Err: err}
	}
	return &Authority{
		CN:         attrs.CN,
		Name:       name.Buffer,
		Public:     public.Bytes(),
		Generation: generation,
	}, nil
}

// deleteAuthority deletes a policy authority's blobs from the scope's key
// store.
func (s *Service) deleteAuthority(st *scopeState, authority *Authority) error {
	attrs, err := s.authorityAttrs(st, authority.CN)
	if err != nil {
		return err
	}
	if err := st.tpm.TPM.DeleteKeyPair(attrs, st.tpm.Keys); err != nil {
		return &TPMError{Scope: st.name, Op: "delete policy authority", Err: err}
	}
	return nil
}

// defineIndex allocates a free owner-range NV index on the scope's TPM and
// defines it with define. Allocation is serialized, so two scopes on one TPM
// never pick the same index.
func (s *Service) defineIndex(st *scopeState, define func(*pkgtpm2.TPM2, tpm2.TPMHandle) error) (tpm2.TPMHandle, error) {
	s.nvMu.Lock()
	defer s.nvMu.Unlock()
	index, err := st.tpm.TPM.FindFreeNVIndex(pkgtpm2.NVOwnerIndexFirst, pkgtpm2.NVOwnerIndexLast)
	if err != nil {
		return 0, &TPMError{Scope: st.name, Op: "allocate NV index", Err: err}
	}
	if err := define(st.tpm.TPM, index); err != nil {
		return 0, &TPMError{Scope: st.name, Op: fmt.Sprintf("define NV index 0x%08x", index), Err: err}
	}
	return index, nil
}

// undefineIndex deletes an NV index of the scope's TPM.
func (s *Service) undefineIndex(st *scopeState, index tpm2.TPMHandle, ownerAuth []byte) error {
	if err := st.tpm.TPM.UndefineNVIndex(index, st.ownerAuth(ownerAuth)); err != nil {
		return &TPMError{Scope: st.name, Op: fmt.Sprintf("undefine NV index 0x%08x", index), Err: err}
	}
	return nil
}
