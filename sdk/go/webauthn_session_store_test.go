package xkms

import (
	"context"
	"errors"
	"sync"
	"testing"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// sdkSessionStore is a custom WebAuthn session store a composer writes
// against the SDK alone: every type in its method set comes from this
// package or from go-webauthn.
type sdkSessionStore struct {
	mu       sync.Mutex
	next     int
	sessions map[string]sdkSessionEntry
}

type sdkSessionEntry struct {
	data    *gowebauthn.SessionData
	pending *WebAuthnPendingRegistration
}

var _ WebAuthnSessionStore = (*sdkSessionStore)(nil)

var errSDKSessionNotFound = errors.New("session not found")

func (s *sdkSessionStore) Save(ctx context.Context, data *gowebauthn.SessionData) (string, error) {
	return s.SaveRegistration(ctx, data, nil)
}

func (s *sdkSessionStore) SaveRegistration(_ context.Context, data *gowebauthn.SessionData, pending *WebAuthnPendingRegistration) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	id := string(rune('a' + s.next))
	s.sessions[id] = sdkSessionEntry{data: data, pending: pending}
	return id, nil
}

func (s *sdkSessionStore) Get(_ context.Context, sessionID string) (*gowebauthn.SessionData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.sessions[sessionID]
	if !ok {
		return nil, errSDKSessionNotFound
	}
	return entry.data, nil
}

func (s *sdkSessionStore) Take(ctx context.Context, sessionID string) (*gowebauthn.SessionData, error) {
	data, _, err := s.TakeRegistration(ctx, sessionID)
	return data, err
}

func (s *sdkSessionStore) TakeRegistration(_ context.Context, sessionID string) (*gowebauthn.SessionData, *WebAuthnPendingRegistration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.sessions[sessionID]
	if !ok {
		return nil, nil, errSDKSessionNotFound
	}
	delete(s.sessions, sessionID)
	return entry.data, entry.pending, nil
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
	data := &gowebauthn.SessionData{Challenge: "challenge"}
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
	if _, _, err := params.SessionStore.TakeRegistration(ctx, id); !errors.Is(err, errSDKSessionNotFound) {
		t.Fatalf("a taken session must be gone, got %v", err)
	}
}
