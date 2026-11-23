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

// saveRecordingCredStore is a write-through decorator, as an embedder
// writes one: it embeds CredentialStore and overrides Save only.
type saveRecordingCredStore struct {
	CredentialStore
	saved [][]byte
}

func (r *saveRecordingCredStore) Save(ctx context.Context, cred *Credential) error {
	if err := r.CredentialStore.Save(ctx, cred); err != nil {
		return err
	}
	r.saved = append(r.saved, append([]byte(nil), cred.ID...))
	return nil
}

// TestFinishInviteRegistration_DecoratedSaveSeesTheFencedWrite pins the Codex
// round-2 P1 on service.go: the invitation ceremony's fenced first-credential
// write goes through the configured store's Save, so a decorator that
// overrides Save sees it, and the credential is still bound to the claim
// (readable once the ceremony commits it).
func TestFinishInviteRegistration_DecoratedSaveSeesTheFencedWrite(t *testing.T) {
	ctx := context.Background()
	f := newEnrollFixture(t, false)
	recorder := &saveRecordingCredStore{CredentialStore: f.creds}
	svc, err := NewService(ServiceParams{
		Config:          validTestConfig(),
		UserStore:       f.users,
		SessionStore:    NewMemorySessionStore(),
		CredentialStore: recorder,
	})
	require.NoError(t, err)

	u := f.mustCreatePending(t, "decorated@example.com")
	options, sessionID, err := svc.BeginInviteRegistration(ctx, u.WebAuthnID())
	require.NoError(t, err)
	parsed, err := parseAttestationResponse(f.inviteAttestation(t, options, newEC2Credential(t)))
	require.NoError(t, err)
	_, err = svc.FinishInviteRegistration(ctx, sessionID, u.WebAuthnID(), parsed)
	require.NoError(t, err)

	creds, err := f.creds.GetByUserID(ctx, u.WebAuthnID())
	require.NoError(t, err)
	require.Len(t, creds, 1)
	require.Len(t, recorder.saved, 1, "the decorator's Save saw the invitation ceremony's credential")
	assert.Equal(t, creds[0].ID, recorder.saved[0])

	// The write stayed fenced: a second claim for the account is refused.
	_, err = f.creds.ClaimFirstCredential(ctx, u.WebAuthnID())
	require.ErrorIs(t, err, ErrFirstCredentialClaimed)
}
