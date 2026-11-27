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

package webauthn

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// barrierCredStore holds every armed GetByUserID until `parties` callers
// have read the account's credentials, so concurrent invite finishes all see
// the same (empty) credential list before any of them saves.
type barrierCredStore struct {
	CredentialStore

	parties int32
	armed   atomic.Bool
	arrived atomic.Int32
	once    sync.Once
	release chan struct{}
}

func (s *barrierCredStore) GetByUserID(ctx context.Context, userID []byte) ([]*Credential, error) {
	creds, err := s.CredentialStore.GetByUserID(ctx, userID)
	if s.armed.Load() {
		if s.arrived.Add(1) >= s.parties {
			s.once.Do(func() { close(s.release) })
		}
		select {
		case <-s.release:
		case <-time.After(5 * time.Second):
		}
	}
	return creds, err
}

// TestFinishInviteRegistration_ConcurrentFinishesEnrolOneCredential: two
// begins for one pending invited account give two sessions; their finishes
// race past the zero-credential check together. Exactly one credential is
// stored, the loser gets ErrRegistrationRefused and stores nothing, and the
// account stays pending for the one redemption that follows.
func TestFinishInviteRegistration_ConcurrentFinishesEnrolOneCredential(t *testing.T) {
	ctx := context.Background()
	f := newEnrollFixture(t, false)
	barrier := &barrierCredStore{CredentialStore: f.creds, parties: 2, release: make(chan struct{})}
	svc, err := NewService(ServiceParams{
		Config:          validTestConfig(),
		UserStore:       f.users,
		SessionStore:    NewMemorySessionStore(),
		CredentialStore: barrier,
	})
	require.NoError(t, err)

	u := f.mustCreatePending(t, "race@example.com")
	type attempt struct {
		sessionID string
		parsed    *protocol.ParsedCredentialCreationData
	}
	attempts := make([]attempt, 2)
	for i := range attempts {
		options, sessionID, err := svc.BeginInviteRegistration(ctx, u.WebAuthnID())
		require.NoError(t, err)
		parsed, err := parseAttestationResponse(f.inviteAttestation(t, options, newEC2Credential(t)))
		require.NoError(t, err)
		attempts[i] = attempt{sessionID: sessionID, parsed: parsed}
	}

	barrier.armed.Store(true)
	errs := make([]error, len(attempts))
	var wg sync.WaitGroup
	for i, a := range attempts {
		wg.Add(1)
		go func(i int, a attempt) {
			defer wg.Done()
			_, errs[i] = svc.FinishInviteRegistration(ctx, a.sessionID, u.WebAuthnID(), a.parsed)
		}(i, a)
	}
	wg.Wait()

	var won, refused int
	for _, err := range errs {
		switch {
		case err == nil:
			won++
		case errors.Is(err, ErrRegistrationRefused):
			refused++
		default:
			t.Fatalf("unexpected finish error: %v", err)
		}
	}
	assert.Equal(t, 1, won, "exactly one finish enrols the invite credential")
	assert.Equal(t, 1, refused, "the losing finish is refused")

	creds, err := f.creds.GetByUserID(ctx, u.WebAuthnID())
	require.NoError(t, err)
	assert.Len(t, creds, 1, "the loser stores no credential")

	got, err := f.users.GetByID(ctx, u.WebAuthnID())
	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.LifecyclePending, got.Lifecycle(), "enrolment leaves the account pending for its single redemption")
}

// TestFinishInviteRegistration_FailedSaveReleasesFirstCredentialClaim: a
// finish whose credential save fails releases its first-credential claim, so
// a later finish for the same invitation still enrols.
func TestFinishInviteRegistration_FailedSaveReleasesFirstCredentialClaim(t *testing.T) {
	ctx := context.Background()
	f := newEnrollFixture(t, false)
	faulty := &faultyCredStore{inner: f.creds, saveErr: errors.New("disk full")}
	svc, err := NewService(ServiceParams{
		Config:          validTestConfig(),
		UserStore:       f.users,
		SessionStore:    NewMemorySessionStore(),
		CredentialStore: faulty,
	})
	require.NoError(t, err)

	u := f.mustCreatePending(t, "retry@example.com")
	finish := func() error {
		options, sessionID, err := svc.BeginInviteRegistration(ctx, u.WebAuthnID())
		require.NoError(t, err)
		parsed, err := parseAttestationResponse(f.inviteAttestation(t, options, newEC2Credential(t)))
		require.NoError(t, err)
		_, err = svc.FinishInviteRegistration(ctx, sessionID, u.WebAuthnID(), parsed)
		return err
	}
	require.Error(t, finish())
	faulty.saveErr = nil
	require.NoError(t, finish())

	creds, err := f.creds.GetByUserID(ctx, u.WebAuthnID())
	require.NoError(t, err)
	assert.Len(t, creds, 1)
}

// factorRecorder is the side-effect ledger of recordingDecorator: the
// credential IDs a decorator has turned into authentication factors.
type factorRecorder struct {
	mu      sync.Mutex
	factors map[string]bool
}

func (r *factorRecorder) ids() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.factors))
	for id := range r.factors {
		out = append(out, id)
	}
	return out
}

// recordingDecorator models a composer's credential-store decorator: a
// successful Save adds an authentication factor, a successful Delete
// removes it.
type recordingDecorator struct {
	CredentialStore
	rec *factorRecorder
}

func (d *recordingDecorator) Save(ctx context.Context, cred *Credential) error {
	if err := d.CredentialStore.Save(ctx, cred); err != nil {
		return err
	}
	d.rec.mu.Lock()
	d.rec.factors[string(cred.ID)] = true
	d.rec.mu.Unlock()
	return nil
}

func (d *recordingDecorator) Delete(ctx context.Context, credID []byte) error {
	if err := d.CredentialStore.Delete(ctx, credID); err != nil {
		return err
	}
	d.rec.mu.Lock()
	delete(d.rec.factors, string(credID))
	d.rec.mu.Unlock()
	return nil
}

// claimHookStore runs onClaim once, right after the first won
// ClaimFirstCredential, and lets wrap replace the claim it returns.
type claimHookStore struct {
	CredentialStore
	once    sync.Once
	onClaim func()
	wrap    func(FirstCredentialClaim) FirstCredentialClaim
}

func (s *claimHookStore) ClaimFirstCredential(ctx context.Context, userID []byte) (FirstCredentialClaim, error) {
	claim, err := s.CredentialStore.ClaimFirstCredential(ctx, userID)
	if err != nil {
		return claim, err
	}
	s.once.Do(func() {
		if s.wrap != nil {
			claim = s.wrap(claim)
		}
		if s.onClaim != nil {
			s.onClaim()
		}
	})
	return claim, nil
}

// crashingClaim simulates a ceremony that dies after its fenced save and
// before Commit.
type crashingClaim struct {
	FirstCredentialClaim
}

func (c *crashingClaim) Commit(context.Context, *Credential) error {
	panic("ceremony crashed before commit")
}

// fencedInviteRig is a slow and a recovering invite ceremony for one pending
// account, each on its own replica of the credential store (one shared
// factory), both behind a recording decorator with one shared ledger.
type fencedInviteRig struct {
	f      *enrollFixture
	hook   *claimHookStore
	slow   *Service
	winner *Service
	rec    *factorRecorder
	user   User
}

func newFencedInviteRig(t *testing.T) *fencedInviteRig {
	t.Helper()
	factory := newTestDAOFactory()
	users, creds, accounts := newTestAdapterWith(t, factory)
	f := newEnrollFixture(t, false)
	f.users, f.creds, f.accounts = users, creds, accounts
	recoverer := newTestCredentialStore(t, factory)
	recoverer.now = pastClaimLease()

	rec := &factorRecorder{factors: map[string]bool{}}
	hook := &claimHookStore{CredentialStore: creds}
	newSvc := func(store CredentialStore) *Service {
		svc, err := NewService(ServiceParams{
			Config:          validTestConfig(),
			UserStore:       users,
			SessionStore:    NewMemorySessionStore(),
			CredentialStore: &recordingDecorator{CredentialStore: store, rec: rec},
		})
		require.NoError(t, err)
		return svc
	}
	return &fencedInviteRig{
		f: f, hook: hook, rec: rec,
		slow:   newSvc(hook),
		winner: newSvc(recoverer),
		user:   f.mustCreatePending(t, "fenced@example.com"),
	}
}

// begin opens an invite ceremony on svc and returns its finish.
func (r *fencedInviteRig) begin(t *testing.T, svc *Service) func() error {
	t.Helper()
	ctx := context.Background()
	options, sessionID, err := svc.BeginInviteRegistration(ctx, r.user.WebAuthnID())
	require.NoError(t, err)
	parsed, err := parseAttestationResponse(r.f.inviteAttestation(t, options, newEC2Credential(t)))
	require.NoError(t, err)
	return func() error {
		_, err := svc.FinishInviteRegistration(ctx, sessionID, r.user.WebAuthnID(), parsed)
		return err
	}
}

// assertOnlyStoredFactors: the decorator's factors are exactly the account's
// readable credentials.
func (r *fencedInviteRig) assertOnlyStoredFactors(t *testing.T) {
	t.Helper()
	stored, err := r.f.creds.GetByUserID(context.Background(), r.user.WebAuthnID())
	require.NoError(t, err)
	require.Len(t, stored, 1, "the account keeps only the winner's credential")
	assert.ElementsMatch(t, []string{string(stored[0].ID)}, r.rec.ids(),
		"a fenced-out ceremony leaves no decorator factor behind")
}

// TestFinishInviteRegistration_LostCommitLeavesNoDecoratorFactor: the slow
// ceremony's claim is recovered and committed by another ceremony before
// the slow one saves. The slow finish is refused and the decorator holds a
// factor only for the winner's credential.
func TestFinishInviteRegistration_LostCommitLeavesNoDecoratorFactor(t *testing.T) {
	r := newFencedInviteRig(t)
	slowFinish := r.begin(t, r.slow)
	winnerFinish := r.begin(t, r.winner)
	r.hook.onClaim = func() { require.NoError(t, winnerFinish()) }

	require.ErrorIs(t, slowFinish(), ErrRegistrationRefused)
	r.assertOnlyStoredFactors(t)
}

// TestFinishInviteRegistration_StaleClaimerCrashLeavesNoDecoratorFactor: the
// slow ceremony's claim is recovered and committed by another ceremony, then
// the stale slow one saves under it and dies before Commit. The decorator
// holds no factor for the crashed credential.
func TestFinishInviteRegistration_StaleClaimerCrashLeavesNoDecoratorFactor(t *testing.T) {
	r := newFencedInviteRig(t)
	slowFinish := r.begin(t, r.slow)
	winnerFinish := r.begin(t, r.winner)
	r.hook.wrap = func(c FirstCredentialClaim) FirstCredentialClaim { return &crashingClaim{FirstCredentialClaim: c} }
	r.hook.onClaim = func() { require.NoError(t, winnerFinish()) }

	assert.Panics(t, func() { _ = slowFinish() }, "the stale ceremony crashes before commit")
	r.assertOnlyStoredFactors(t)
}

// crashAfterCommitClaim simulates a ceremony that dies after its claim
// commits and before the decorated Save of its first credential runs.
type crashAfterCommitClaim struct {
	FirstCredentialClaim
}

func (c *crashAfterCommitClaim) Commit(ctx context.Context, cred *Credential) error {
	if err := c.FirstCredentialClaim.Commit(ctx, cred); err != nil {
		return err
	}
	panic("ceremony crashed after commit")
}

// countingDecorator counts the Saves that reach the recording decorator's
// effect (a factor added).
type countingDecorator struct {
	*recordingDecorator
	effects *atomic.Int32
}

func (d *countingDecorator) Save(ctx context.Context, cred *Credential) error {
	if err := d.recordingDecorator.Save(ctx, cred); err != nil {
		return err
	}
	d.effects.Add(1)
	return nil
}

// repairRig is one invite ceremony for a pending account behind a counting
// recording decorator over a hooked store, and a second replica of the
// credential store (one shared factory) whose clock is past the claim lease.
type repairRig struct {
	f       *enrollFixture
	hook    *claimHookStore
	svc     *Service
	other   *daoCredentialStore
	rec     *factorRecorder
	effects *atomic.Int32
	user    User
}

func newRepairRig(t *testing.T) *repairRig {
	t.Helper()
	factory := newTestDAOFactory()
	users, creds, accounts := newTestAdapterWith(t, factory)
	f := newEnrollFixture(t, false)
	f.users, f.creds, f.accounts = users, creds, accounts
	other := newTestCredentialStore(t, factory)
	other.now = pastClaimLease()

	rec := &factorRecorder{factors: map[string]bool{}}
	effects := &atomic.Int32{}
	hook := &claimHookStore{CredentialStore: creds}
	svc, err := NewService(ServiceParams{
		Config:       validTestConfig(),
		UserStore:    users,
		SessionStore: NewMemorySessionStore(),
		CredentialStore: &countingDecorator{
			recordingDecorator: &recordingDecorator{CredentialStore: hook, rec: rec},
			effects:            effects,
		},
	})
	require.NoError(t, err)
	return &repairRig{
		f: f, hook: hook, svc: svc, other: other, rec: rec, effects: effects,
		user: f.mustCreatePending(t, "repair@example.com"),
	}
}

// begin opens an invite ceremony and returns its finish and a resume that
// proves possession of the enrolled credential.
func (r *repairRig) begin(t *testing.T) (finish func() error, resume func(t *testing.T)) {
	t.Helper()
	ctx := context.Background()
	options, sessionID, err := r.svc.BeginInviteRegistration(ctx, r.user.WebAuthnID())
	require.NoError(t, err)
	credential := newEC2Credential(t)
	parsed, err := parseAttestationResponse(r.f.inviteAttestation(t, options, credential))
	require.NoError(t, err)
	finish = func() error {
		_, err := r.svc.FinishInviteRegistration(ctx, sessionID, r.user.WebAuthnID(), parsed)
		return err
	}
	resume = func(t *testing.T) {
		t.Helper()
		issuedAt := time.Now().Add(-time.Minute)
		opts, resumeID, err := r.svc.BeginInviteResume(ctx, r.user.WebAuthnID(), issuedAt)
		require.NoError(t, err)
		_, err = r.svc.FinishInviteResume(ctx, resumeID, r.user.WebAuthnID(), issuedAt, r.f.assert(t, opts, credential, nil))
		require.NoError(t, err)
	}
	return finish, resume
}

// storedID returns the ID of the account's one readable credential.
func (r *repairRig) storedID(t *testing.T) string {
	t.Helper()
	stored, err := r.f.creds.GetByUserID(context.Background(), r.user.WebAuthnID())
	require.NoError(t, err)
	require.Len(t, stored, 1, "the account keeps its first credential")
	return string(stored[0].ID)
}

// TestInviteResume_RepairsDecoratorFactorAfterCrashAfterCommit: the ceremony
// dies after its claim commits and before the decorated Save. The credential
// is the account's but has no factor; the invite resume adds it.
func TestInviteResume_RepairsDecoratorFactorAfterCrashAfterCommit(t *testing.T) {
	r := newRepairRig(t)
	finish, resume := r.begin(t)
	r.hook.wrap = func(c FirstCredentialClaim) FirstCredentialClaim {
		return &crashAfterCommitClaim{FirstCredentialClaim: c}
	}

	assert.Panics(t, func() { _ = finish() }, "the ceremony crashes after commit")
	id := r.storedID(t)
	require.Empty(t, r.rec.ids(), "the crash left the credential undecorated")

	resume(t)
	assert.ElementsMatch(t, []string{id}, r.rec.ids(), "the resume repairs the missing factor")
}

// TestInviteResume_RepairsDecoratorFactorAfterRollForward: the ceremony saves
// under its claim and dies before Commit; a later claimer rolls the claim
// forward. The credential is the account's but has no factor; the invite
// resume adds it.
func TestInviteResume_RepairsDecoratorFactorAfterRollForward(t *testing.T) {
	r := newRepairRig(t)
	finish, resume := r.begin(t)
	r.hook.wrap = func(c FirstCredentialClaim) FirstCredentialClaim { return &crashingClaim{FirstCredentialClaim: c} }

	assert.Panics(t, func() { _ = finish() }, "the ceremony crashes before commit")
	_, err := r.other.ClaimFirstCredential(context.Background(), r.user.WebAuthnID())
	require.ErrorIs(t, err, ErrFirstCredentialClaimed, "the later claimer rolls the crashed claim forward")
	id := r.storedID(t)
	require.Empty(t, r.rec.ids(), "the roll-forward left the credential undecorated")

	resume(t)
	assert.ElementsMatch(t, []string{id}, r.rec.ids(), "the resume repairs the missing factor")
}

// TestInviteResume_SettledFirstCredentialIsNotDecoratedAgain: after a finish
// that completed its decorated Save, a resume adds no second factor.
func TestInviteResume_SettledFirstCredentialIsNotDecoratedAgain(t *testing.T) {
	r := newRepairRig(t)
	finish, resume := r.begin(t)

	require.NoError(t, finish())
	id := r.storedID(t)
	require.Equal(t, int32(1), r.effects.Load(), "the finish decorates its credential once")
	require.ElementsMatch(t, []string{id}, r.rec.ids())

	resume(t)
	assert.Equal(t, int32(1), r.effects.Load(), "a settled credential is not decorated again")
	assert.ElementsMatch(t, []string{id}, r.rec.ids())
}
