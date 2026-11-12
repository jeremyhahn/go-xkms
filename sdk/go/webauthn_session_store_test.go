package xkms

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// sdkSessionStore is a custom WebAuthn session store a composer writes
// against the SDK alone: every type in its method set comes from this
// package.
type sdkSessionStore struct {
	mu       sync.Mutex
	next     int
	sessions map[string]sdkSessionEntry
}

type sdkSessionEntry struct {
	data    *WebAuthnSessionData
	pending *WebAuthnPendingRegistration
}

var _ WebAuthnSessionStore = (*sdkSessionStore)(nil)

func (s *sdkSessionStore) Save(ctx context.Context, data *WebAuthnSessionData) (string, error) {
	return s.SaveRegistration(ctx, data, nil)
}

func (s *sdkSessionStore) SaveRegistration(_ context.Context, data *WebAuthnSessionData, pending *WebAuthnPendingRegistration) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	id := string(rune('a' + s.next))
	s.sessions[id] = sdkSessionEntry{data: data, pending: pending}
	return id, nil
}

func (s *sdkSessionStore) Get(_ context.Context, sessionID string) (*WebAuthnSessionData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, err := s.liveEntry(sessionID)
	if err != nil {
		return nil, err
	}
	return entry.data, nil
}

func (s *sdkSessionStore) Take(ctx context.Context, sessionID string) (*WebAuthnSessionData, error) {
	data, _, err := s.TakeRegistration(ctx, sessionID)
	return data, err
}

func (s *sdkSessionStore) TakeRegistration(_ context.Context, sessionID string) (*WebAuthnSessionData, *WebAuthnPendingRegistration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, err := s.liveEntry(sessionID)
	if err != nil {
		return nil, nil, err
	}
	delete(s.sessions, sessionID)
	return entry.data, entry.pending, nil
}

// liveEntry answers with the SDK's session sentinels: not found for a missing
// or taken session, expired (and dropped) for one past its deadline. The
// caller holds s.mu.
func (s *sdkSessionStore) liveEntry(sessionID string) (sdkSessionEntry, error) {
	entry, ok := s.sessions[sessionID]
	if !ok {
		return sdkSessionEntry{}, ErrWebAuthnSessionNotFound
	}
	if !entry.data.Expires.IsZero() && time.Now().After(entry.data.Expires) {
		delete(s.sessions, sessionID)
		return sdkSessionEntry{}, ErrWebAuthnSessionExpired
	}
	return entry, nil
}

func (s *sdkSessionStore) Delete(_ context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
	return nil
}

// A composer that imports only the SDK can implement a custom session store
// and hand it to the WebAuthn service, pending registration included.
func TestWebAuthnSessionStore_ImplementableFromTheSDK(t *testing.T) {
	store := &sdkSessionStore{sessions: map[string]sdkSessionEntry{}}
	params := WebAuthnServiceParams{SessionStore: store}
	if params.SessionStore == nil {
		t.Fatal("the custom store must be accepted as the session store")
	}

	ctx := context.Background()
	data := &WebAuthnSessionData{Challenge: "challenge"}
	pending := &WebAuthnPendingRegistration{Email: "sdk@example.com", DisplayName: "SDK"}
	id, err := params.SessionStore.SaveRegistration(ctx, data, pending)
	if err != nil {
		t.Fatalf("SaveRegistration: %v", err)
	}
	gotData, gotPending, err := params.SessionStore.TakeRegistration(ctx, id)
	if err != nil {
		t.Fatalf("TakeRegistration: %v", err)
	}
	if gotData != data || gotPending == nil || *gotPending != *pending {
		t.Fatalf("TakeRegistration returned %v, %v; want the saved session and %v", gotData, gotPending, pending)
	}
	if _, _, err := params.SessionStore.TakeRegistration(ctx, id); !errors.Is(err, ErrWebAuthnSessionNotFound) {
		t.Fatalf("a taken session must be gone, got %v", err)
	}

	expiredID, err := params.SessionStore.Save(ctx, &WebAuthnSessionData{Challenge: "late", Expires: time.Now().Add(-time.Minute)})
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := params.SessionStore.Take(ctx, expiredID); !errors.Is(err, ErrWebAuthnSessionExpired) {
		t.Fatalf("an expired session must answer ErrWebAuthnSessionExpired, got %v", err)
	}
}

// The SDK's session sentinels are the ones the WebAuthn service maps to
// 400 invalid_session and session_expired, so an SDK-only store keeps them.
func TestWebAuthnSessionSentinels_AreTheCanonicalErrors(t *testing.T) {
	if !errors.Is(ErrWebAuthnSessionNotFound, webauthn.ErrSessionNotFound) {
		t.Fatal("ErrWebAuthnSessionNotFound must be webauthn.ErrSessionNotFound")
	}
	if !errors.Is(ErrWebAuthnSessionExpired, webauthn.ErrSessionExpired) {
		t.Fatal("ErrWebAuthnSessionExpired must be webauthn.ErrSessionExpired")
	}
}
