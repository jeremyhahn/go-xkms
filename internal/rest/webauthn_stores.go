// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package rest

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/webauthn"
)

// WebAuthnStores provides the WebAuthn storage implementations for the REST server.
// It wraps the in-memory stores from the webauthn package with optional
// persistence hooks for production use.
type WebAuthnStores struct {
	users       webauthn.UserStore
	sessions    webauthn.SessionStore
	credentials webauthn.CredentialStore
}

// WebAuthnStoresConfig configures the WebAuthn stores.
type WebAuthnStoresConfig struct {
	// SessionTTL is the duration after which sessions expire.
	// Default: 5 minutes
	SessionTTL time.Duration
}

// NewWebAuthnStores creates new WebAuthn stores for the REST server.
// These stores use in-memory storage suitable for development and testing.
// For production, consider implementing persistent stores backed by a database.
func NewWebAuthnStores(cfg *WebAuthnStoresConfig) *WebAuthnStores {
	if cfg == nil {
		cfg = &WebAuthnStoresConfig{}
	}

	// Set defaults
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 5 * time.Minute
	}

	return &WebAuthnStores{
		users:       webauthn.NewMemoryUserStore(),
		sessions:    webauthn.NewMemorySessionStoreWithTTL(cfg.SessionTTL),
		credentials: webauthn.NewMemoryCredentialStore(),
	}
}

// UserStore returns the user store.
func (s *WebAuthnStores) UserStore() webauthn.UserStore {
	return s.users
}

// SessionStore returns the session store.
func (s *WebAuthnStores) SessionStore() webauthn.SessionStore {
	return s.sessions
}

// CredentialStore returns the credential store.
func (s *WebAuthnStores) CredentialStore() webauthn.CredentialStore {
	return s.credentials
}

// CleanupSessions removes expired sessions and returns the count of removed sessions.
func (s *WebAuthnStores) CleanupSessions() int {
	if memStore, ok := s.sessions.(*webauthn.MemorySessionStore); ok {
		return memStore.Cleanup()
	}
	return 0
}

// StartCleanupRoutine starts a background goroutine that periodically cleans up
// expired sessions. Call the returned cancel function to stop the routine.
func (s *WebAuthnStores) StartCleanupRoutine(ctx context.Context, interval time.Duration) context.CancelFunc {
	ctx, cancel := context.WithCancel(ctx)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.CleanupSessions()
			}
		}
	}()

	return cancel
}

// Clear clears all stores (useful for testing).
func (s *WebAuthnStores) Clear() {
	if memStore, ok := s.users.(*webauthn.MemoryUserStore); ok {
		memStore.Clear()
	}
	if memStore, ok := s.sessions.(*webauthn.MemorySessionStore); ok {
		memStore.Clear()
	}
	if memStore, ok := s.credentials.(*webauthn.MemoryCredentialStore); ok {
		memStore.Clear()
	}
}
