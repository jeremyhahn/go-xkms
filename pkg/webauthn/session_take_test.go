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

package webauthn

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// MemorySessionStore.Take
// ---------------------------------------------------------------------------

func TestMemorySessionStore_TakeConsumesTheSession(t *testing.T) {
	ctx := context.Background()
	store := NewMemorySessionStore()
	sessionID, err := store.Save(ctx, &webauthn.SessionData{UserID: []byte("user-1")})
	require.NoError(t, err)

	taken, err := store.Take(ctx, sessionID)
	require.NoError(t, err)
	require.NotNil(t, taken)
	assert.Equal(t, []byte("user-1"), taken.UserID)

	_, err = store.Get(ctx, sessionID)
	assert.ErrorIs(t, err, ErrSessionNotFound,
		"a taken session must be gone: take is get-and-delete, not get")
}

func TestMemorySessionStore_TakeMissingSession(t *testing.T) {
	_, err := NewMemorySessionStore().Take(context.Background(), "no-such-session")

	assert.ErrorIs(t, err, ErrSessionNotFound)
}

func TestMemorySessionStore_TakeExpiredSessionConsumesAndFails(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	clock := now
	var mu sync.Mutex
	store := NewMemorySessionStoreWithTTL(time.Minute, WithClock(func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return clock
	}))

	sessionID, err := store.Save(ctx, &webauthn.SessionData{UserID: []byte("user-1")})
	require.NoError(t, err)

	mu.Lock()
	clock = now.Add(2 * time.Minute)
	mu.Unlock()

	_, err = store.Take(ctx, sessionID)
	assert.ErrorIs(t, err, ErrSessionExpired)
	assert.Equal(t, 0, store.Count(),
		"an expired session must still be consumed so it cannot be retried")
}

func TestMemorySessionStore_TakeElectsOneWinnerUnderConcurrency(t *testing.T) {
	ctx := context.Background()
	store := NewMemorySessionStore()
	sessionID, err := store.Save(ctx, &webauthn.SessionData{UserID: []byte("user-1")})
	require.NoError(t, err)

	const workers = 32
	var (
		start sync.WaitGroup
		done  sync.WaitGroup
		mu    sync.Mutex
		wins  int
	)
	start.Add(1)
	for i := 0; i < workers; i++ {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			if _, takeErr := store.Take(ctx, sessionID); takeErr == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	start.Done()
	done.Wait()

	assert.Equal(t, 1, wins, "exactly one concurrent take may claim a session")
}

// ---------------------------------------------------------------------------
// Ceremony fixture
// ---------------------------------------------------------------------------

// ceremonyFixture holds a service wired to in-memory stores plus the virtual
// authenticator that drives real attestation and assertion responses.
type ceremonyFixture struct {
	svc           *Service
	rp            virtualwebauthn.RelyingParty
	authenticator virtualwebauthn.Authenticator
	credential    virtualwebauthn.Credential
}

func newCeremonyFixture(t *testing.T, params ...func(*ServiceParams)) *ceremonyFixture {
	t.Helper()

	cfg := &Config{
		RPID:                    "example.com",
		RPDisplayName:           "Example Corp",
		RPOrigins:               []string{"https://example.com"},
		AllowPublicRegistration: openRegistration(),
	}

	users, creds := newTestStores(t)
	sp := ServiceParams{
		Config:          cfg,
		UserStore:       users,
		SessionStore:    NewMemorySessionStore(),
		CredentialStore: creds,
	}
	for _, p := range params {
		p(&sp)
	}

	svc, err := NewService(sp)
	require.NoError(t, err)

	return &ceremonyFixture{
		svc: svc,
		rp: virtualwebauthn.RelyingParty{
			Name:   cfg.RPDisplayName,
			ID:     cfg.RPID,
			Origin: cfg.RPOrigins[0],
		},
		authenticator: virtualwebauthn.NewAuthenticator(),
		credential:    newEC2Credential(t),
	}
}

// beginRegistration starts a registration and returns the session ID together
// with the raw attestation response the browser would post back.
func (f *ceremonyFixture) beginRegistration(t *testing.T, email string) (sessionID, attestation string) {
	t.Helper()

	options, sessionID, err := f.svc.BeginRegistration(context.Background(), email, "Race User")
	require.NoError(t, err)

	optionsJSON, err := json.Marshal(options.Response)
	require.NoError(t, err)

	parsedOptions, err := virtualwebauthn.ParseAttestationOptions(string(optionsJSON))
	require.NoError(t, err)

	return sessionID, virtualwebauthn.CreateAttestationResponse(f.rp, f.authenticator, f.credential, *parsedOptions)
}

// beginLogin starts a login and returns the session ID together with the raw
// assertion response the browser would post back.
func (f *ceremonyFixture) beginLogin(t *testing.T, userID []byte) (sessionID, assertion string) {
	t.Helper()

	options, sessionID, err := f.svc.BeginLogin(context.Background(), userID)
	require.NoError(t, err)

	optionsJSON, err := json.Marshal(options.Response)
	require.NoError(t, err)

	parsedOptions, err := virtualwebauthn.ParseAssertionOptions(string(optionsJSON))
	require.NoError(t, err)

	return sessionID, virtualwebauthn.CreateAssertionResponse(f.rp, f.authenticator, f.credential, *parsedOptions)
}

// ---------------------------------------------------------------------------
// Concurrent finish: one session, one success.
// ---------------------------------------------------------------------------

func TestFinishRegistration_ConcurrentFinishesYieldExactlyOneSuccess(t *testing.T) {
	ctx := context.Background()
	f := newCeremonyFixture(t)
	sessionID, attestation := f.beginRegistration(t, "race-register@example.com")

	const workers = 12
	var (
		start sync.WaitGroup
		done  sync.WaitGroup
		mu    sync.Mutex
		wins  int
		errs  []error
	)
	start.Add(1)
	for i := 0; i < workers; i++ {
		done.Add(1)
		go func() {
			defer done.Done()

			// Each goroutine parses its own copy: replaying one ceremony
			// response concurrently is exactly the attack, and sharing the
			// parsed struct would test the parser instead of the session.
			response, parseErr := parseAttestationResponse(attestation)
			if parseErr != nil {
				mu.Lock()
				errs = append(errs, parseErr)
				mu.Unlock()
				return
			}

			start.Wait()
			_, _, finishErr := f.svc.FinishRegistration(ctx, sessionID, response)
			mu.Lock()
			defer mu.Unlock()
			if finishErr != nil {
				errs = append(errs, finishErr)
				return
			}
			wins++
		}()
	}
	start.Done()
	done.Wait()

	assert.Equal(t, 1, wins,
		"a registration session is single-use: concurrent finishes must not all enroll a credential")
	require.Len(t, errs, workers-1)
	for _, err := range errs {
		assert.True(t, errors.Is(err, ErrVerificationFailed),
			"a finish that could not claim the session must fail as an authentication failure, got: %v", err)
	}
}

func TestFinishLogin_ConcurrentFinishesYieldExactlyOneSuccess(t *testing.T) {
	ctx := context.Background()
	f := newCeremonyFixture(t)

	regSessionID, attestation := f.beginRegistration(t, "race-login@example.com")
	regResponse, err := parseAttestationResponse(attestation)
	require.NoError(t, err)
	_, user, err := f.svc.FinishRegistration(ctx, regSessionID, regResponse)
	require.NoError(t, err)
	f.authenticator.AddCredential(f.credential)

	sessionID, assertion := f.beginLogin(t, user.WebAuthnID())

	const workers = 12
	var (
		start sync.WaitGroup
		done  sync.WaitGroup
		mu    sync.Mutex
		wins  int
		errs  []error
	)
	start.Add(1)
	for i := 0; i < workers; i++ {
		done.Add(1)
		go func() {
			defer done.Done()

			response, parseErr := parseAssertionResponse(assertion)
			if parseErr != nil {
				mu.Lock()
				errs = append(errs, parseErr)
				mu.Unlock()
				return
			}

			start.Wait()
			_, _, finishErr := f.svc.FinishLogin(ctx, sessionID, user.WebAuthnID(), response)
			mu.Lock()
			defer mu.Unlock()
			if finishErr != nil {
				errs = append(errs, finishErr)
				return
			}
			wins++
		}()
	}
	start.Done()
	done.Wait()

	assert.Equal(t, 1, wins,
		"an authentication session is single-use: a replayed assertion must not authenticate twice")
	require.Len(t, errs, workers-1)
	for _, err := range errs {
		assert.True(t, errors.Is(err, ErrVerificationFailed),
			"a finish that could not claim the session must fail as an authentication failure, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// A store that cannot claim the session must not authenticate.
// ---------------------------------------------------------------------------

// takeFailingSessionStore claims nothing: Take always fails while the rest of
// the store works. It stands for a session backend that cannot guarantee
// single use.
type takeFailingSessionStore struct {
	SessionStore
	err error
}

func (s *takeFailingSessionStore) Take(context.Context, string) (*webauthn.SessionData, error) {
	return nil, s.err
}

func (s *takeFailingSessionStore) TakeRegistration(context.Context, string) (*webauthn.SessionData, *PendingRegistration, error) {
	return nil, nil, s.err
}

func TestFinishLogin_TakeFailureDoesNotAuthenticate(t *testing.T) {
	ctx := context.Background()
	f := newCeremonyFixture(t)

	regSessionID, attestation := f.beginRegistration(t, "take-fail-login@example.com")
	regResponse, err := parseAttestationResponse(attestation)
	require.NoError(t, err)
	_, user, err := f.svc.FinishRegistration(ctx, regSessionID, regResponse)
	require.NoError(t, err)
	f.authenticator.AddCredential(f.credential)

	sessionID, assertion := f.beginLogin(t, user.WebAuthnID())
	response, err := parseAssertionResponse(assertion)
	require.NoError(t, err)

	// Swap in a store that cannot claim sessions, keeping the same session data.
	f.svc.sessions = &takeFailingSessionStore{
		SessionStore: f.svc.sessions,
		err:          errors.New("kv unavailable"),
	}

	token, authenticated, err := f.svc.FinishLogin(ctx, sessionID, user.WebAuthnID(), response)

	require.Error(t, err, "an unclaimable session must never authenticate")
	assert.Empty(t, token)
	assert.Nil(t, authenticated)
	assert.True(t, errors.Is(err, ErrVerificationFailed))
}

func TestFinishRegistration_TakeFailureDoesNotEnroll(t *testing.T) {
	ctx := context.Background()
	f := newCeremonyFixture(t)
	sessionID, attestation := f.beginRegistration(t, "take-fail-register@example.com")
	response, err := parseAttestationResponse(attestation)
	require.NoError(t, err)

	f.svc.sessions = &takeFailingSessionStore{
		SessionStore: f.svc.sessions,
		err:          errors.New("kv unavailable"),
	}

	token, user, err := f.svc.FinishRegistration(ctx, sessionID, response)

	require.Error(t, err, "an unclaimable session must never enroll a credential")
	assert.Empty(t, token)
	assert.Nil(t, user)
	assert.True(t, errors.Is(err, ErrVerificationFailed))
}
