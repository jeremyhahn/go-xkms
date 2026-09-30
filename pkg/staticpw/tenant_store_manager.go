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

package staticpw

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/scope"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// ErrNoSystemBarrier is returned when the system tenant's password store is
// addressed and the barrier registry holds no system barrier.
var ErrNoSystemBarrier = errors.New("staticpw: the barrier registry has no system barrier")

// TenantStoreStatus is the password store status one user sees: whether the
// user's personal session is locked, whether the tenant barrier is sealed,
// and how many entries the user can currently read.
type TenantStoreStatus struct {
	IsLocked      bool `json:"is_locked"`
	BarrierSealed bool `json:"barrier_sealed"`
	PasswordCount int  `json:"password_count"`
}

// VaultStatus describes one user's personal vault: whether a factor is
// enrolled, whether the personal session is open, and the enrolled factors.
type VaultStatus struct {
	Initialized bool              `json:"initialized"`
	Unlocked    bool              `json:"unlocked"`
	Factors     []VaultFactorInfo `json:"factors"`
}

// EnrollResult is the outcome of enrolling a factor or recovering a vault.
type EnrollResult struct {
	// Factor is the factor enrolled.
	Factor VaultFactorInfo

	// RecoveryCode is set only when a new recovery code was issued (the
	// first enrollment, and every recovery). It is shown to the user exactly
	// once and never stored in the clear.
	RecoveryCode string
}

// sealProbe reports whether a barrier is sealed. *seal.TenantBarrier and the
// system *seal.Barrier both satisfy it.
type sealProbe interface {
	IsSealed() bool
}

// userSession is an open personal session: the user's DEK, unwrapped, and
// the personal store that seals entries with it.
type userSession struct {
	dek   []byte
	store *BackendStore
}

// end zeroes the DEK. The store is dropped with the session.
func (s *userSession) end() { clear(s.dek) }

// tenantPasswordState holds one tenant's shared store and its users' open
// personal sessions.
type tenantPasswordState struct {
	shared   *BackendStore   // the tenant-shared entries
	sessions sync.Map        // subject -> *userSession
	keyLocks sync.Map        // subject -> *sync.Mutex: serializes a user's vault changes
	backend  storage.Backend // the tenant barrier, as a storage backend
	barrier  sealProbe
	tenantID string
}

// sealed reports whether the tenant barrier is sealed. Sealing ends every
// personal session: a barrier unsealed again later does not resume them.
func (st *tenantPasswordState) sealed() bool {
	if !st.barrier.IsSealed() {
		return false
	}
	st.endSessions()
	return true
}

// endSessions ends every personal session, zeroing its DEK.
func (st *tenantPasswordState) endSessions() {
	st.sessions.Range(func(key, value any) bool {
		value.(*userSession).end()
		st.sessions.Delete(key)
		return true
	})
}

// session returns subject's open session, or nil.
func (st *tenantPasswordState) session(subject string) *userSession {
	if val, ok := st.sessions.Load(subject); ok {
		return val.(*userSession)
	}
	return nil
}

// keyLock returns the mutex serializing subject's vault changes: two
// concurrent first enrollments must not mint two DEKs.
func (st *tenantPasswordState) keyLock(subject string) *sync.Mutex {
	val, _ := st.keyLocks.LoadOrStore(subject, &sync.Mutex{})
	return val.(*sync.Mutex)
}

// TenantPasswordStoreManager routes password operations to per-tenant stores
// under the xkms scope model (pkg/scope):
//
//   - Shared entries ("{tenant}/staticpw/shared/") are readable and writable
//     by every authenticated user of the tenant whenever the tenant barrier
//     is unsealed. They have no session of their own.
//   - A user's personal entries ("{tenant}/staticpw/users/{subject}/") are
//     sealed with the user's own DEK and are readable only while the user's
//     personal session is open. The DEK is stored only wrapped under the
//     user's factors (vault.go), so the tenant barrier alone reads none of
//     them. Each user locks and unlocks independently.
//
// Each tenant's data is encrypted by its TenantBarrier from the
// BarrierRegistry. The system tenant is an ordinary tenant whose data is
// encrypted by the system barrier. The systemStore serves only requests that
// carry no identity (internal callers, authentication disabled).
type TenantPasswordStoreManager struct {
	registry    *seal.BarrierRegistry
	systemStore Store
	tenants     sync.Map // tenant scope name -> *tenantPasswordState
}

// NewTenantPasswordStoreManager creates a manager over registry. systemStore
// serves requests with no identity.
func NewTenantPasswordStoreManager(registry *seal.BarrierRegistry, systemStore Store) (*TenantPasswordStoreManager, error) {
	if registry == nil {
		return nil, ErrNilBarrierRegistry
	}
	if systemStore == nil {
		return nil, ErrNilStore
	}
	return &TenantPasswordStoreManager{
		registry:    registry,
		systemStore: systemStore,
	}, nil
}

// SystemStore returns the store that serves requests with no identity.
func (m *TenantPasswordStoreManager) SystemStore() Store {
	return m.systemStore
}

// tenantState returns tenantID's state, creating it on first use. The empty
// tenant and the system tenant are both the system tenant.
func (m *TenantPasswordStoreManager) tenantState(tenantID string) (*tenantPasswordState, error) {
	name := scope.TenantName(tenantID)
	if val, ok := m.tenants.Load(name); ok {
		return val.(*tenantPasswordState), nil
	}

	backend, probe, err := m.barrierFor(name)
	if err != nil {
		return nil, err
	}
	shared, err := NewSharedTenantStore(backend, name)
	if err != nil {
		return nil, err
	}
	state := &tenantPasswordState{
		shared:   shared,
		backend:  backend,
		barrier:  probe,
		tenantID: name,
	}

	actual, loaded := m.tenants.LoadOrStore(name, state)
	if loaded {
		if cerr := shared.Close(); cerr != nil {
			slog.Debug("staticpw: failed to close a duplicate shared tenant store", "tenant_id", name, "error", cerr)
		}
		return actual.(*tenantPasswordState), nil
	}
	return state, nil
}

// barrierFor returns the barrier holding tenant name's entries, as a storage
// backend and as a seal probe.
func (m *TenantPasswordStoreManager) barrierFor(name string) (storage.Backend, sealProbe, error) {
	if name == scope.SystemTenant {
		system := m.registry.SystemBarrier()
		if system == nil {
			return nil, nil, ErrNoSystemBarrier
		}
		return seal.NewBarrierBackend(system), system, nil
	}
	tb, err := m.registry.Tenant(name)
	if err != nil {
		return nil, nil, err
	}
	return seal.NewBarrierBackend(tb.Barrier()), tb, nil
}

// userState returns the state of tenantID for a vault operation of userID:
// the tenant must exist and be unsealed, and userID must be valid.
func (m *TenantPasswordStoreManager) userState(tenantID, userID string) (*tenantPasswordState, error) {
	if !isValidUserID(userID) {
		return nil, ErrInvalidUserID
	}
	state, err := m.tenantState(tenantID)
	if err != nil {
		return nil, err
	}
	if state.sealed() {
		return nil, seal.ErrTenantSealed
	}
	return state, nil
}

// ResolveScopedStore returns the store userID sees in tenantID: the tenant's
// shared entries, plus the user's personal entries while the user's personal
// session is open. With the session locked, personal operations report
// ErrStoreLocked and shared entries stay usable.
//
// An empty tenantID is a request without an identity and gets the
// systemStore. An empty userID gets the shared entries only. Returns
// seal.ErrTenantSealed while the tenant barrier is sealed.
func (m *TenantPasswordStoreManager) ResolveScopedStore(tenantID, userID string) (Store, error) {
	if tenantID == "" {
		return m.systemStore, nil
	}
	state, err := m.tenantState(tenantID)
	if err != nil {
		return nil, err
	}
	if state.sealed() {
		return nil, seal.ErrTenantSealed
	}
	if userID == "" {
		return state.shared, nil
	}
	if !isValidUserID(userID) {
		return nil, ErrInvalidUserID
	}
	if session := state.session(userID); session != nil {
		return NewScopedStore(state.shared, session.store, userID)
	}
	return NewLockedScopedStore(state.shared, userID)
}

// VaultStatus returns userID's vault status in tenantID.
func (m *TenantPasswordStoreManager) VaultStatus(ctx context.Context, tenantID, userID string) (*VaultStatus, error) {
	state, err := m.userState(tenantID, userID)
	if err != nil {
		return nil, err
	}
	factors, err := m.factors(ctx, state, userID)
	if err != nil {
		return nil, err
	}
	status := &VaultStatus{
		Initialized: len(factors) > 0,
		Unlocked:    state.session(userID) != nil,
		Factors:     make([]VaultFactorInfo, 0, len(factors)),
	}
	for _, f := range factors {
		status.Factors = append(status.Factors, f.VaultFactorInfo)
	}
	return status, nil
}

// factors returns userID's stored factors.
func (m *TenantPasswordStoreManager) factors(ctx context.Context, state *tenantPasswordState, userID string) ([]*vaultFactor, error) {
	keyring, err := newVaultKeyring(state.backend, state.tenantID, userID)
	if err != nil {
		return nil, err
	}
	return keyring.factors(ctx)
}

// UnlockUser opens userID's personal session in tenantID with cred, a
// passphrase or passkey the user enrolled: the credential unwraps the user's
// DEK, which is held until LockUser or a seal. The recovery code does not
// unlock; it recovers (RecoverVault).
//
// Returns ErrVaultNotInitialized when the user has no factor,
// ErrVaultCredentialRejected when cred unwraps none, ErrStoreNotLocked when
// the session is already open, and seal.ErrTenantSealed while sealed.
func (m *TenantPasswordStoreManager) UnlockUser(ctx context.Context, tenantID, userID string, cred VaultCredential) error {
	if cred.Type == FactorRecovery {
		return ErrVaultRecoveryFactor
	}
	if err := cred.validate(false); err != nil {
		return err
	}
	state, err := m.userState(tenantID, userID)
	if err != nil {
		return err
	}
	mu := state.keyLock(userID)
	mu.Lock()
	defer mu.Unlock()

	if state.session(userID) != nil {
		return ErrStoreNotLocked
	}
	keyring, factors, err := m.keyring(ctx, state, userID)
	if err != nil {
		return err
	}
	if len(factors) == 0 {
		return ErrVaultNotInitialized
	}
	dek, err := unwrapWith(keyring, factors, cred)
	if err != nil {
		return err
	}
	return m.openSession(state, userID, dek)
}

// keyring returns userID's keyring and its factors.
func (m *TenantPasswordStoreManager) keyring(ctx context.Context, state *tenantPasswordState, userID string) (*vaultKeyring, []*vaultFactor, error) {
	keyring, err := newVaultKeyring(state.backend, state.tenantID, userID)
	if err != nil {
		return nil, nil, err
	}
	factors, err := keyring.factors(ctx)
	if err != nil {
		return nil, nil, err
	}
	return keyring, factors, nil
}

// unwrapWith returns the DEK the first factor matching cred unwraps.
func unwrapWith(keyring *vaultKeyring, factors []*vaultFactor, cred VaultCredential) ([]byte, error) {
	for _, f := range factors {
		if f.Type != cred.Type {
			continue
		}
		if cred.Type == FactorPasskey && !bytes.Equal(f.CredentialID, cred.CredentialID) {
			continue
		}
		dek, err := keyring.unwrap(f, cred.Secret)
		if errors.Is(err, ErrVaultCredentialRejected) {
			continue
		}
		return dek, err
	}
	return nil, ErrVaultCredentialRejected
}

// openSession records userID's open session over dek, which it takes
// ownership of.
func (m *TenantPasswordStoreManager) openSession(state *tenantPasswordState, userID string, dek []byte) error {
	store, err := NewPersonalTenantStore(newDEKBackend(state.backend, dek), state.tenantID, userID)
	if err != nil {
		clear(dek)
		return err
	}
	session := &userSession{dek: dek, store: store}
	if previous, loaded := state.sessions.Swap(userID, session); loaded {
		previous.(*userSession).end()
	}
	return nil
}

// EnrollFactor enrolls cred, a passphrase or passkey, as a factor of userID
// in tenantID.
//
// The first enrollment initializes the vault: it mints the user's DEK, wraps
// it under cred and under a new one-time recovery code, opens the personal
// session and returns the recovery code (shown once). A later enrollment
// needs the user's session open: it wraps the same DEK under cred, and the
// DEK itself never changes.
func (m *TenantPasswordStoreManager) EnrollFactor(ctx context.Context, tenantID, userID string, cred VaultCredential) (*EnrollResult, error) {
	if err := cred.validate(true); err != nil {
		return nil, err
	}
	state, err := m.userState(tenantID, userID)
	if err != nil {
		return nil, err
	}
	mu := state.keyLock(userID)
	mu.Lock()
	defer mu.Unlock()

	keyring, factors, err := m.keyring(ctx, state, userID)
	if err != nil {
		return nil, err
	}
	if len(factors) == 0 {
		return m.initVault(ctx, state, keyring, userID, cred)
	}

	session := state.session(userID)
	if session == nil {
		return nil, ErrStoreLocked
	}
	if err := checkPasskeyUnique(factors, cred); err != nil {
		return nil, err
	}
	f, err := keyring.wrap(cred, session.dek)
	if err != nil {
		return nil, err
	}
	if err := keyring.put(ctx, f); err != nil {
		return nil, err
	}
	return &EnrollResult{Factor: f.VaultFactorInfo}, nil
}

// initVault mints userID's DEK and wraps it under cred and a new recovery
// code, then opens the session.
func (m *TenantPasswordStoreManager) initVault(ctx context.Context, state *tenantPasswordState, keyring *vaultKeyring, userID string, cred VaultCredential) (*EnrollResult, error) {
	dek, err := randomBytes(dekLength)
	if err != nil {
		return nil, err
	}
	f, err := keyring.wrap(cred, dek)
	if err != nil {
		clear(dek)
		return nil, err
	}
	code, recovery, err := wrapRecovery(keyring, dek)
	if err != nil {
		clear(dek)
		return nil, err
	}
	// The recovery factor is written first: a vault with a factor but no
	// recovery code must never exist.
	for _, factor := range []*vaultFactor{recovery, f} {
		if err := keyring.put(ctx, factor); err != nil {
			clear(dek)
			return nil, err
		}
	}
	if err := m.openSession(state, userID, dek); err != nil {
		return nil, err
	}
	return &EnrollResult{Factor: f.VaultFactorInfo, RecoveryCode: code}, nil
}

// wrapRecovery issues a recovery code and the factor wrapping dek under it.
func wrapRecovery(keyring *vaultKeyring, dek []byte) (string, *vaultFactor, error) {
	code, secret, err := newRecoveryCode()
	if err != nil {
		return "", nil, err
	}
	defer clear(secret)
	f, err := keyring.wrap(VaultCredential{Type: FactorRecovery, Secret: secret, Label: "recovery code"}, dek)
	if err != nil {
		return "", nil, err
	}
	return code, f, nil
}

// checkPasskeyUnique refuses enrolling a passkey credential already
// enrolled.
func checkPasskeyUnique(factors []*vaultFactor, cred VaultCredential) error {
	if cred.Type != FactorPasskey {
		return nil
	}
	for _, f := range factors {
		if f.Type == FactorPasskey && bytes.Equal(f.CredentialID, cred.CredentialID) {
			return ErrVaultPasskeyExists
		}
	}
	return nil
}

// RotateFactor replaces factor id of userID with cred, a new secret of the
// same type: the DEK is re-wrapped under cred and the old wrap removed. The
// user's session must be open.
func (m *TenantPasswordStoreManager) RotateFactor(ctx context.Context, tenantID, userID, id string, cred VaultCredential) (*EnrollResult, error) {
	if err := cred.validate(true); err != nil {
		return nil, err
	}
	state, err := m.userState(tenantID, userID)
	if err != nil {
		return nil, err
	}
	mu := state.keyLock(userID)
	mu.Lock()
	defer mu.Unlock()

	keyring, factors, session, err := m.openVault(ctx, state, userID)
	if err != nil {
		return nil, err
	}
	old, err := managedFactor(factors, id)
	if err != nil {
		return nil, err
	}
	if old.Type != cred.Type {
		return nil, ErrVaultInvalidCredential
	}
	if cred.Type == FactorPasskey && !bytes.Equal(old.CredentialID, cred.CredentialID) {
		if err := checkPasskeyUnique(factors, cred); err != nil {
			return nil, err
		}
	}
	f, err := keyring.wrap(cred, session.dek)
	if err != nil {
		return nil, err
	}
	// Write the new wrap before removing the old one: an interruption
	// leaves one factor too many, never one too few.
	if err := keyring.put(ctx, f); err != nil {
		return nil, err
	}
	if err := keyring.remove(ctx, old.ID); err != nil {
		return nil, err
	}
	return &EnrollResult{Factor: f.VaultFactorInfo}, nil
}

// RemoveFactor removes factor id of userID. The user's session must be open,
// the recovery factor cannot be removed, and the last passphrase or passkey
// cannot be removed.
func (m *TenantPasswordStoreManager) RemoveFactor(ctx context.Context, tenantID, userID, id string) error {
	state, err := m.userState(tenantID, userID)
	if err != nil {
		return err
	}
	mu := state.keyLock(userID)
	mu.Lock()
	defer mu.Unlock()

	keyring, factors, _, err := m.openVault(ctx, state, userID)
	if err != nil {
		return err
	}
	if _, err := managedFactor(factors, id); err != nil {
		return err
	}
	remaining := 0
	for _, f := range factors {
		if f.Type != FactorRecovery && f.ID != id {
			remaining++
		}
	}
	if remaining == 0 {
		return ErrVaultLastFactor
	}
	return keyring.remove(ctx, id)
}

// openVault returns the keyring, factors and open session of userID, or
// ErrVaultNotInitialized / ErrStoreLocked. The caller holds the user's key
// lock.
func (m *TenantPasswordStoreManager) openVault(ctx context.Context, state *tenantPasswordState, userID string) (*vaultKeyring, []*vaultFactor, *userSession, error) {
	keyring, factors, err := m.keyring(ctx, state, userID)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(factors) == 0 {
		return nil, nil, nil, ErrVaultNotInitialized
	}
	session := state.session(userID)
	if session == nil {
		return nil, nil, nil, ErrStoreLocked
	}
	return keyring, factors, session, nil
}

// managedFactor returns factor id, refusing the recovery factor.
func managedFactor(factors []*vaultFactor, id string) (*vaultFactor, error) {
	for _, f := range factors {
		if f.ID != id {
			continue
		}
		if f.Type == FactorRecovery {
			return nil, ErrVaultRecoveryFactor
		}
		return f, nil
	}
	return nil, ErrVaultFactorNotFound
}

// RecoverVault uses userID's recovery code to enroll cred, a new passphrase
// or passkey, when the user has lost the factors they had. The code is
// one-time: it is replaced by a new one, returned in the result and shown
// once. The personal session is opened.
func (m *TenantPasswordStoreManager) RecoverVault(ctx context.Context, tenantID, userID string, recoveryCode []byte, cred VaultCredential) (*EnrollResult, error) {
	if err := cred.validate(true); err != nil {
		return nil, err
	}
	if len(recoveryCode) == 0 {
		return nil, ErrVaultInvalidCredential
	}
	state, err := m.userState(tenantID, userID)
	if err != nil {
		return nil, err
	}
	mu := state.keyLock(userID)
	mu.Lock()
	defer mu.Unlock()

	keyring, factors, err := m.keyring(ctx, state, userID)
	if err != nil {
		return nil, err
	}
	if len(factors) == 0 {
		return nil, ErrVaultNotInitialized
	}
	secret := normalizeRecoveryCode(recoveryCode)
	defer clear(secret)
	var used *vaultFactor
	var dek []byte
	for _, f := range factors {
		if f.Type != FactorRecovery {
			continue
		}
		if unwrapped, uerr := keyring.unwrap(f, secret); uerr == nil {
			used, dek = f, unwrapped
			break
		}
	}
	if used == nil {
		return nil, ErrVaultCredentialRejected
	}
	if err := checkPasskeyUnique(factors, cred); err != nil {
		clear(dek)
		return nil, err
	}

	f, err := keyring.wrap(cred, dek)
	if err != nil {
		clear(dek)
		return nil, err
	}
	code, recovery, err := wrapRecovery(keyring, dek)
	if err != nil {
		clear(dek)
		return nil, err
	}
	// New factor and new recovery code first, then retire the used code.
	for _, factor := range []*vaultFactor{f, recovery} {
		if err := keyring.put(ctx, factor); err != nil {
			clear(dek)
			return nil, err
		}
	}
	if err := keyring.remove(ctx, used.ID); err != nil {
		clear(dek)
		return nil, err
	}
	if err := m.openSession(state, userID, dek); err != nil {
		return nil, err
	}
	return &EnrollResult{Factor: f.VaultFactorInfo, RecoveryCode: code}, nil
}

// LockUser closes userID's personal session in tenantID and zeroes the DEK.
// Other users' sessions are untouched. Returns ErrStoreAlreadyLocked when the
// session is not open.
func (m *TenantPasswordStoreManager) LockUser(tenantID, userID string) error {
	if !isValidUserID(userID) {
		return ErrInvalidUserID
	}
	state, err := m.tenantState(tenantID)
	if err != nil {
		return err
	}
	val, open := state.sessions.LoadAndDelete(userID)
	if !open {
		return ErrStoreAlreadyLocked
	}
	val.(*userSession).end()
	return nil
}

// IsUserLocked reports whether userID's personal session in tenantID is
// locked. Sessions start locked.
func (m *TenantPasswordStoreManager) IsUserLocked(tenantID, userID string) (bool, error) {
	state, err := m.tenantState(tenantID)
	if err != nil {
		return false, err
	}
	if state.sealed() {
		return true, nil
	}
	return state.session(userID) == nil, nil
}

// UserStoreStatus returns the status userID sees in tenantID. PasswordCount
// counts the entries the user can read now: the shared entries, and the
// personal ones while the session is open.
func (m *TenantPasswordStoreManager) UserStoreStatus(tenantID, userID string) (*TenantStoreStatus, error) {
	if userID != "" && !isValidUserID(userID) {
		return nil, ErrInvalidUserID
	}
	state, err := m.tenantState(tenantID)
	if err != nil {
		return nil, err
	}
	if state.sealed() {
		return &TenantStoreStatus{IsLocked: true, BarrierSealed: true}, nil
	}
	status := &TenantStoreStatus{IsLocked: state.session(userID) == nil}

	store, err := m.ResolveScopedStore(state.tenantID, userID)
	if err != nil {
		return nil, err
	}
	entries, err := store.List()
	if err != nil {
		return nil, err
	}
	status.PasswordCount = len(entries)
	return status, nil
}

// Close closes all cached tenant stores and ends every session.
func (m *TenantPasswordStoreManager) Close() error {
	var lastErr error
	m.tenants.Range(func(key, value any) bool {
		state := value.(*tenantPasswordState)
		state.endSessions()
		if err := state.shared.Close(); err != nil {
			lastErr = err
		}
		m.tenants.Delete(key)
		return true
	})
	return lastErr
}
