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
	"sync"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/kdf"
	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

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

	// PasskeyRelyingParty is the relying party ID a new passkey must be
	// created for; "" when the deployment offers no passkeys.
	PasskeyRelyingParty string `json:"passkey_rp_id,omitempty"`
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

// userSession is an open personal session: the user's DEK, unwrapped, and
// the naming key derived from it.
type userSession struct {
	mu    sync.RWMutex
	ended bool
	dek   []byte
	names entryNames
}

// end zeroes the DEK and the naming key derived from it. A store still
// holding the session reads and writes nothing after it.
func (s *userSession) end() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ended = true
	clear(s.dek)
	clear(s.names.key)
}

// withDEK calls fn with the session's DEK, which fn must not retain, and
// reports ErrStoreLocked once the session has ended.
func (s *userSession) withDEK(fn func(dek []byte) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.ended {
		return ErrStoreLocked
	}
	return fn(s.dek)
}

// wrap builds a factor of cred's type on keyring wrapping the session's DEK.
func (s *userSession) wrap(ctx context.Context, keyring *vaultKeyring, cred VaultCredential) (*vaultFactor, error) {
	var f *vaultFactor
	err := s.withDEK(func(dek []byte) error {
		var err error
		f, err = keyring.wrap(ctx, cred, dek)
		return err
	})
	return f, err
}

// tenantPasswordState holds one tenant's open personal sessions.
type tenantPasswordState struct {
	sessions sync.Map // subject -> *userSession
	keyLocks sync.Map // subject -> *sync.Mutex: serializes a user's vault changes
	tenantID string
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

// tenantView is a tenant's state with the DAO factory over the store the
// tenant resolved to for the operation at hand.
type tenantView struct {
	*tenantPasswordState
	daos *qrdbsdk.DAOFactory
}

// TenantPasswordStoreManager routes password operations to per-tenant stores
// under the xkms scope model (pkg/scope):
//
//   - Shared entries ("{tenant}/staticpw/shared/") are readable and writable
//     by every authenticated user of the tenant whenever the tenant is
//     unsealed. They have no session of their own.
//   - A user's personal entries ("{tenant}/staticpw/users/{subject}/") are
//     sealed with the user's own DEK and are readable only while the user's
//     personal session is open. The DEK is stored only wrapped under the
//     user's factors (vault.go), so the tenant's store alone reads none of
//     them. Each user locks and unlocks independently.
//
// Each tenant's records live in the store the go-qrdb tenant store resolver
// routes the tenant to: a barrier-isolated tenant's own TenantBarrier, or the
// system store confined to the tenant's keyspace. The system tenant is an
// ordinary tenant. The systemStore serves only requests that carry no
// identity (internal callers, authentication disabled).
type TenantPasswordStoreManager struct {
	stores              qrdbsdk.TenantStoreResolver
	systemStore         Store
	tenants             sync.Map // tenant scope name -> *tenantPasswordState
	passphraseKDFParams func() *kdf.KDFParams

	// passkeyRP is the WebAuthn relying party ID passkey factors are
	// created for; empty disables passkey enrollment.
	passkeyRP string
}

// Option configures a TenantPasswordStoreManager.
type Option func(*TenantPasswordStoreManager)

// WithPassphraseKDFParams overrides the Argon2id cost new passphrase vault
// factors are wrapped with (defaultPassphraseKDFParams, the repository
// default, otherwise). Production callers never need it: it exists so every
// package that builds a TenantPasswordStoreManager in tests can enroll and
// unlock passphrase factors, many times over, at a cost cheap enough not to
// dominate a suite's runtime and memory when many such tests run in
// parallel, while still exercising the production wrap/unwrap code path.
func WithPassphraseKDFParams(params func() *kdf.KDFParams) Option {
	return func(m *TenantPasswordStoreManager) {
		m.passphraseKDFParams = params
	}
}

// WithPasskeyRelyingParty sets the WebAuthn relying party ID -- the domain
// the web console is served from (webauthn.rp_id) -- that the vault's
// passkey factors are created for. Every client creates and evaluates a
// vault passkey for this ID, which is what lets a passkey enrolled in a
// browser unlock from xkey and xkmsctl, and the reverse. Without it passkey
// enrollment answers ErrVaultPasskeyUnavailable.
func WithPasskeyRelyingParty(rpID string) Option {
	return func(m *TenantPasswordStoreManager) { m.passkeyRP = rpID }
}

// NewTenantPasswordStoreManager creates a manager over the tenant stores
// stores resolves. systemStore serves requests with no identity.
func NewTenantPasswordStoreManager(stores qrdbsdk.TenantStoreResolver, systemStore Store, opts ...Option) (*TenantPasswordStoreManager, error) {
	if stores == nil {
		return nil, ErrNilTenantStores
	}
	if systemStore == nil {
		return nil, ErrNilStore
	}
	m := &TenantPasswordStoreManager{
		stores:              stores,
		systemStore:         systemStore,
		passphraseKDFParams: defaultPassphraseKDFParams,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m, nil
}

// PasskeyRelyingParty returns the relying party ID vault passkeys are
// created for, or "" when passkeys are unavailable.
func (m *TenantPasswordStoreManager) PasskeyRelyingParty() string {
	return m.passkeyRP
}

// validateEnrollment checks a credential presented to enroll, rotate to or
// recover with: its shape, and for a passkey that it was created for the
// server's relying party.
func (m *TenantPasswordStoreManager) validateEnrollment(ctx context.Context, cred VaultCredential) error {
	if err := cred.validate(ctx, true); err != nil {
		return err
	}
	if cred.Type != FactorPasskey {
		return nil
	}
	if m.passkeyRP == "" {
		return ErrVaultPasskeyUnavailable
	}
	if cred.RelyingParty != m.passkeyRP {
		return ErrVaultRelyingPartyMismatch
	}
	return nil
}

// SystemStore returns the store that serves requests with no identity.
func (m *TenantPasswordStoreManager) SystemStore() Store {
	return m.systemStore
}

// tenantState returns tenantID's state, creating it on first use. The empty
// tenant and the system tenant are both the system tenant.
func (m *TenantPasswordStoreManager) tenantState(tenantID string) (*tenantPasswordState, error) {
	name := scope.TenantName(tenantID)
	if !isValidTenantID(name) {
		return nil, ErrInvalidTenantID
	}
	val, _ := m.tenants.LoadOrStore(name, &tenantPasswordState{tenantID: name})
	return val.(*tenantPasswordState), nil
}

// resolve returns tenantID's state over the store the tenant resolves to.
// A sealed tenant ends every personal session -- a tenant unsealed again
// later does not resume them -- and is seal.ErrTenantSealed.
func (m *TenantPasswordStoreManager) resolve(ctx context.Context, tenantID string) (*tenantView, error) {
	state, err := m.tenantState(tenantID)
	if err != nil {
		return nil, err
	}
	kv, err := m.stores.Resolve(ctx, state.tenantID)
	if errors.Is(err, qrdbsdk.ErrTenantStoreSealed) {
		state.endSessions()
		return nil, seal.ErrTenantSealed
	}
	if err != nil {
		return nil, &StoreError{Op: "resolve", Key: state.tenantID, Err: err}
	}
	return &tenantView{tenantPasswordState: state, daos: dao.NewStoreFactory(kv)}, nil
}

// userState returns the state of tenantID for a vault operation of userID:
// the tenant must be unsealed, and userID must be valid.
func (m *TenantPasswordStoreManager) userState(ctx context.Context, tenantID, userID string) (*tenantView, error) {
	if !isValidUserID(userID) {
		return nil, ErrInvalidUserID
	}
	return m.resolve(ctx, tenantID)
}

// ResolveScopedStore returns the store userID sees in tenantID: the tenant's
// shared entries, plus the user's personal entries while the user's personal
// session is open. With the session locked, personal operations report
// ErrStoreLocked and shared entries stay usable.
//
// An empty tenantID is a request without an identity and gets the
// systemStore. An empty userID gets the shared entries only. Returns
// seal.ErrTenantSealed while the tenant is sealed.
func (m *TenantPasswordStoreManager) ResolveScopedStore(ctx context.Context, tenantID, userID string) (Store, error) {
	if tenantID == "" {
		return m.systemStore, nil
	}
	state, err := m.resolve(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	shared, err := NewSharedTenantStore(state.daos, state.tenantID)
	if err != nil {
		return nil, err
	}
	if userID == "" {
		return shared, nil
	}
	if !isValidUserID(userID) {
		return nil, ErrInvalidUserID
	}
	session := state.session(userID)
	if session == nil {
		return NewLockedScopedStore(shared, userID)
	}
	personal, err := newSealedPersonalStore(state.daos, state.tenantID, userID, session)
	if err != nil {
		return nil, err
	}
	return NewScopedStore(shared, personal, userID)
}

// VaultStatus returns userID's vault status in tenantID.
func (m *TenantPasswordStoreManager) VaultStatus(ctx context.Context, tenantID, userID string) (*VaultStatus, error) {
	state, err := m.userState(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	factors, err := m.factors(ctx, state, userID)
	if err != nil {
		return nil, err
	}
	status := &VaultStatus{
		Initialized:         len(factors) > 0,
		Unlocked:            state.session(userID) != nil,
		Factors:             make([]VaultFactorInfo, 0, len(factors)),
		PasskeyRelyingParty: m.passkeyRP,
	}
	for _, f := range factors {
		status.Factors = append(status.Factors, f.VaultFactorInfo)
	}
	return status, nil
}

// factors returns userID's stored factors.
func (m *TenantPasswordStoreManager) factors(ctx context.Context, state *tenantView, userID string) ([]*vaultFactor, error) {
	keyring, err := newVaultKeyring(state.daos, state.tenantID, userID, m.passphraseKDFParams)
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
	if err := cred.validate(ctx, false); err != nil {
		return err
	}
	state, err := m.userState(ctx, tenantID, userID)
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
	dek, err := unwrapWith(ctx, keyring, factors, cred)
	if err != nil {
		return err
	}
	return m.openSession(state, userID, dek)
}

// keyring returns userID's keyring and its factors.
func (m *TenantPasswordStoreManager) keyring(ctx context.Context, state *tenantView, userID string) (*vaultKeyring, []*vaultFactor, error) {
	keyring, err := newVaultKeyring(state.daos, state.tenantID, userID, m.passphraseKDFParams)
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
func unwrapWith(ctx context.Context, keyring *vaultKeyring, factors []*vaultFactor, cred VaultCredential) ([]byte, error) {
	for _, f := range factors {
		if f.Type != cred.Type {
			continue
		}
		if cred.Type == FactorPasskey && !bytes.Equal(f.CredentialID, cred.CredentialID) {
			continue
		}
		if cred.Type.IsKeyFactor() && f.KeyFingerprint != cred.KeyFingerprint {
			continue
		}
		dek, err := keyring.unwrap(ctx, f, cred.Secret)
		if errors.Is(err, ErrVaultCredentialRejected) {
			continue
		}
		return dek, err
	}
	return nil, ErrVaultCredentialRejected
}

// openSession records userID's open session over dek, which it takes
// ownership of.
func (m *TenantPasswordStoreManager) openSession(state *tenantView, userID string, dek []byte) error {
	// Entry IDs and marker paths are keyed by the DEK, so the tenant's
	// store alone reveals no names or folders (see entryNames).
	names, err := newPersonalNames(dek)
	if err != nil {
		clear(dek)
		return err
	}
	session := &userSession{dek: dek, names: names}
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
	if err := m.validateEnrollment(ctx, cred); err != nil {
		return nil, err
	}
	state, err := m.userState(ctx, tenantID, userID)
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
	if err := checkUnique(factors, cred, nil); err != nil {
		return nil, err
	}
	f, err := session.wrap(ctx, keyring, cred)
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
func (m *TenantPasswordStoreManager) initVault(ctx context.Context, state *tenantView, keyring *vaultKeyring, userID string, cred VaultCredential) (*EnrollResult, error) {
	dek, err := randomBytes(dekLength)
	if err != nil {
		return nil, err
	}
	f, err := keyring.wrap(ctx, cred, dek)
	if err != nil {
		clear(dek)
		return nil, err
	}
	code, recovery, err := wrapRecovery(ctx, keyring, dek)
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
func wrapRecovery(ctx context.Context, keyring *vaultKeyring, dek []byte) (string, *vaultFactor, error) {
	code, secret, err := newRecoveryCode(ctx)
	if err != nil {
		return "", nil, err
	}
	defer secret.Destroy()
	f, err := keyring.wrap(ctx, VaultCredential{Type: FactorRecovery, Secret: secret, Label: "recovery code"}, dek)
	if err != nil {
		return "", nil, err
	}
	return code, f, nil
}

// checkUnique refuses enrolling a passkey credential or a key already
// enrolled. replacing, when rotating, is the factor being replaced: the same
// passkey or key may re-enroll over itself.
func checkUnique(factors []*vaultFactor, cred VaultCredential, replacing *vaultFactor) error {
	var fingerprint string
	if cred.Type.IsKeyFactor() {
		var err error
		if fingerprint, err = cred.keyFingerprint(); err != nil {
			return err
		}
	}
	for _, f := range factors {
		if f == replacing {
			continue
		}
		if cred.Type == FactorPasskey && f.Type == FactorPasskey && bytes.Equal(f.CredentialID, cred.CredentialID) {
			return ErrVaultPasskeyExists
		}
		if fingerprint != "" && f.KeyFingerprint == fingerprint {
			return ErrVaultKeyExists
		}
	}
	return nil
}

// RotateFactor replaces factor id of userID with cred, a new secret of the
// same type: the DEK is re-wrapped under cred and the old wrap removed. The
// user's session must be open.
func (m *TenantPasswordStoreManager) RotateFactor(ctx context.Context, tenantID, userID, id string, cred VaultCredential) (*EnrollResult, error) {
	if err := m.validateEnrollment(ctx, cred); err != nil {
		return nil, err
	}
	state, err := m.userState(ctx, tenantID, userID)
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
	if err := checkUnique(factors, cred, old); err != nil {
		return nil, err
	}
	f, err := session.wrap(ctx, keyring, cred)
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
	state, err := m.userState(ctx, tenantID, userID)
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
func (m *TenantPasswordStoreManager) openVault(ctx context.Context, state *tenantView, userID string) (*vaultKeyring, []*vaultFactor, *userSession, error) {
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
	if err := m.validateEnrollment(ctx, cred); err != nil {
		return nil, err
	}
	if len(recoveryCode) == 0 {
		return nil, ErrVaultInvalidCredential
	}
	state, err := m.userState(ctx, tenantID, userID)
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
	normalized := normalizeRecoveryCode(recoveryCode)
	secret, err := secure.NewSecret(ctx, normalized)
	if err != nil {
		return nil, ErrVaultCredentialRejected
	}
	defer secret.Destroy()
	var used *vaultFactor
	var dek []byte
	for _, f := range factors {
		if f.Type != FactorRecovery {
			continue
		}
		if unwrapped, uerr := keyring.unwrap(ctx, f, secret); uerr == nil {
			used, dek = f, unwrapped
			break
		}
	}
	if used == nil {
		return nil, ErrVaultCredentialRejected
	}
	if err := checkUnique(factors, cred, nil); err != nil {
		clear(dek)
		return nil, err
	}

	f, err := keyring.wrap(ctx, cred, dek)
	if err != nil {
		clear(dek)
		return nil, err
	}
	code, recovery, err := wrapRecovery(ctx, keyring, dek)
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
// locked. Sessions start locked, and a sealed tenant locks every session.
func (m *TenantPasswordStoreManager) IsUserLocked(ctx context.Context, tenantID, userID string) (bool, error) {
	state, err := m.resolve(ctx, tenantID)
	if errors.Is(err, seal.ErrTenantSealed) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return state.session(userID) == nil, nil
}

// UserStoreStatus returns the status userID sees in tenantID. PasswordCount
// counts the entries the user can read now: the shared entries, and the
// personal ones while the session is open.
func (m *TenantPasswordStoreManager) UserStoreStatus(ctx context.Context, tenantID, userID string) (*TenantStoreStatus, error) {
	if userID != "" && !isValidUserID(userID) {
		return nil, ErrInvalidUserID
	}
	state, err := m.tenantState(tenantID)
	if err != nil {
		return nil, err
	}
	store, err := m.ResolveScopedStore(ctx, state.tenantID, userID)
	if errors.Is(err, seal.ErrTenantSealed) {
		return &TenantStoreStatus{IsLocked: true, BarrierSealed: true}, nil
	}
	if err != nil {
		return nil, err
	}
	status := &TenantStoreStatus{IsLocked: state.session(userID) == nil}
	entries, err := store.List()
	if err != nil {
		return nil, err
	}
	status.PasswordCount = len(entries)
	return status, nil
}

// Close ends every personal session. The tenant stores belong to the
// resolver, so nothing else is released.
func (m *TenantPasswordStoreManager) Close() error {
	m.tenants.Range(func(key, value any) bool {
		value.(*tenantPasswordState).endSessions()
		m.tenants.Delete(key)
		return true
	})
	return nil
}
