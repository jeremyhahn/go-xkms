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

package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"
)

// mockUserChecker implements UserChecker for testing
type mockUserChecker struct {
	hasUsers  bool
	err       error
	callCount int
	mu        sync.Mutex
}

func (m *mockUserChecker) HasAnyUsers(ctx context.Context) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount++
	return m.hasUsers, m.err
}

func (m *mockUserChecker) setHasUsers(hasUsers bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hasUsers = hasUsers
}

func (m *mockUserChecker) getCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

// mockAuthenticator implements Authenticator for testing
type mockAuthenticator struct {
	name     string
	identity *Identity
	err      error
}

func (m *mockAuthenticator) AuthenticateHTTP(r *http.Request) (*Identity, error) {
	return m.identity, m.err
}

func (m *mockAuthenticator) AuthenticateGRPC(ctx context.Context, md metadata.MD) (*Identity, error) {
	return m.identity, m.err
}

func (m *mockAuthenticator) Name() string {
	return m.name
}

func TestNewAdaptiveAuthenticator(t *testing.T) {
	tests := []struct {
		name    string
		config  *AdaptiveConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
			errMsg:  "config is required",
		},
		{
			name: "nil user checker",
			config: &AdaptiveConfig{
				UserChecker:           nil,
				RequiredAuthenticator: &mockAuthenticator{name: "test"},
			},
			wantErr: true,
			errMsg:  "user checker is required",
		},
		{
			name: "nil required authenticator",
			config: &AdaptiveConfig{
				UserChecker:           &mockUserChecker{},
				RequiredAuthenticator: nil,
			},
			wantErr: true,
			errMsg:  "required authenticator is required",
		},
		{
			name: "valid config with defaults",
			config: &AdaptiveConfig{
				UserChecker:           &mockUserChecker{},
				RequiredAuthenticator: &mockAuthenticator{name: "test"},
			},
			wantErr: false,
		},
		{
			name: "valid config with custom cache expiry",
			config: &AdaptiveConfig{
				UserChecker:           &mockUserChecker{},
				RequiredAuthenticator: &mockAuthenticator{name: "test"},
				CacheExpiry:           1 * time.Minute,
			},
			wantErr: false,
		},
		{
			name: "valid config with logger",
			config: &AdaptiveConfig{
				UserChecker:           &mockUserChecker{},
				RequiredAuthenticator: &mockAuthenticator{name: "test"},
				Logger:                slog.Default(),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := NewAdaptiveAuthenticator(tt.config)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if err.Error() != tt.errMsg {
					t.Errorf("error = %v, want %v", err.Error(), tt.errMsg)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if auth == nil {
				t.Error("expected non-nil authenticator")
			}
		})
	}
}

func TestAdaptiveAuthenticator_AuthenticateHTTP_NoUsers(t *testing.T) {
	userChecker := &mockUserChecker{hasUsers: false}
	requiredAuth := &mockAuthenticator{
		name:     "required",
		identity: &Identity{Subject: "required-user"},
	}

	auth, err := NewAdaptiveAuthenticator(&AdaptiveConfig{
		UserChecker:           userChecker,
		RequiredAuthenticator: requiredAuth,
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	identity, err := auth.AuthenticateHTTP(req)
	if err != nil {
		t.Fatalf("AuthenticateHTTP() error = %v", err)
	}
	if identity == nil {
		t.Fatal("expected identity, got nil")
	}
	// Should use noop authenticator when no users exist
	if identity.Subject != "anonymous" {
		t.Errorf("Subject = %v, want anonymous", identity.Subject)
	}
}

func TestAdaptiveAuthenticator_AuthenticateHTTP_WithUsers(t *testing.T) {
	userChecker := &mockUserChecker{hasUsers: true}
	requiredIdentity := &Identity{
		Subject:    "authenticated-user",
		Claims:     map[string]interface{}{"role": "admin"},
		Attributes: map[string]string{},
	}
	requiredAuth := &mockAuthenticator{
		name:     "required",
		identity: requiredIdentity,
	}

	auth, err := NewAdaptiveAuthenticator(&AdaptiveConfig{
		UserChecker:           userChecker,
		RequiredAuthenticator: requiredAuth,
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	identity, err := auth.AuthenticateHTTP(req)
	if err != nil {
		t.Fatalf("AuthenticateHTTP() error = %v", err)
	}
	if identity == nil {
		t.Fatal("expected identity, got nil")
	}
	// Should use required authenticator when users exist
	if identity.Subject != "authenticated-user" {
		t.Errorf("Subject = %v, want authenticated-user", identity.Subject)
	}
}

func TestAdaptiveAuthenticator_AuthenticateHTTP_AuthError(t *testing.T) {
	userChecker := &mockUserChecker{hasUsers: true}
	expectedErr := errors.New("auth failed")
	requiredAuth := &mockAuthenticator{
		name: "required",
		err:  expectedErr,
	}

	auth, err := NewAdaptiveAuthenticator(&AdaptiveConfig{
		UserChecker:           userChecker,
		RequiredAuthenticator: requiredAuth,
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err = auth.AuthenticateHTTP(req)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != expectedErr.Error() {
		t.Errorf("error = %v, want %v", err, expectedErr)
	}
}

func TestAdaptiveAuthenticator_AuthenticateGRPC_NoUsers(t *testing.T) {
	userChecker := &mockUserChecker{hasUsers: false}
	requiredAuth := &mockAuthenticator{
		name:     "required",
		identity: &Identity{Subject: "required-user"},
	}

	auth, err := NewAdaptiveAuthenticator(&AdaptiveConfig{
		UserChecker:           userChecker,
		RequiredAuthenticator: requiredAuth,
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	ctx := context.Background()
	md := metadata.MD{}
	identity, err := auth.AuthenticateGRPC(ctx, md)
	if err != nil {
		t.Fatalf("AuthenticateGRPC() error = %v", err)
	}
	if identity == nil {
		t.Fatal("expected identity, got nil")
	}
	// Should use noop authenticator when no users exist
	if identity.Subject != "anonymous" {
		t.Errorf("Subject = %v, want anonymous", identity.Subject)
	}
}

func TestAdaptiveAuthenticator_AuthenticateGRPC_WithUsers(t *testing.T) {
	userChecker := &mockUserChecker{hasUsers: true}
	requiredIdentity := &Identity{
		Subject:    "authenticated-user",
		Claims:     map[string]interface{}{"role": "admin"},
		Attributes: map[string]string{},
	}
	requiredAuth := &mockAuthenticator{
		name:     "required",
		identity: requiredIdentity,
	}

	auth, err := NewAdaptiveAuthenticator(&AdaptiveConfig{
		UserChecker:           userChecker,
		RequiredAuthenticator: requiredAuth,
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	ctx := context.Background()
	md := metadata.MD{}
	identity, err := auth.AuthenticateGRPC(ctx, md)
	if err != nil {
		t.Fatalf("AuthenticateGRPC() error = %v", err)
	}
	if identity == nil {
		t.Fatal("expected identity, got nil")
	}
	// Should use required authenticator when users exist
	if identity.Subject != "authenticated-user" {
		t.Errorf("Subject = %v, want authenticated-user", identity.Subject)
	}
}

func TestAdaptiveAuthenticator_AuthenticateGRPC_AuthError(t *testing.T) {
	userChecker := &mockUserChecker{hasUsers: true}
	expectedErr := errors.New("grpc auth failed")
	requiredAuth := &mockAuthenticator{
		name: "required",
		err:  expectedErr,
	}

	auth, err := NewAdaptiveAuthenticator(&AdaptiveConfig{
		UserChecker:           userChecker,
		RequiredAuthenticator: requiredAuth,
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	ctx := context.Background()
	md := metadata.MD{}
	_, err = auth.AuthenticateGRPC(ctx, md)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != expectedErr.Error() {
		t.Errorf("error = %v, want %v", err, expectedErr)
	}
}

func TestAdaptiveAuthenticator_Name(t *testing.T) {
	tests := []struct {
		name     string
		hasUsers bool
		authName string
		want     string
	}{
		{
			name:     "no users",
			hasUsers: false,
			authName: "jwt",
			want:     "adaptive:noop",
		},
		{
			name:     "with users",
			hasUsers: true,
			authName: "jwt",
			want:     "adaptive:jwt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userChecker := &mockUserChecker{hasUsers: tt.hasUsers}
			requiredAuth := &mockAuthenticator{name: tt.authName}

			auth, err := NewAdaptiveAuthenticator(&AdaptiveConfig{
				UserChecker:           userChecker,
				RequiredAuthenticator: requiredAuth,
			})
			if err != nil {
				t.Fatalf("failed to create authenticator: %v", err)
			}

			got := auth.Name()
			if got != tt.want {
				t.Errorf("Name() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAdaptiveAuthenticator_RequiresAuth(t *testing.T) {
	tests := []struct {
		name     string
		hasUsers bool
		want     bool
	}{
		{
			name:     "no users - no auth required",
			hasUsers: false,
			want:     false,
		},
		{
			name:     "with users - auth required",
			hasUsers: true,
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userChecker := &mockUserChecker{hasUsers: tt.hasUsers}
			requiredAuth := &mockAuthenticator{name: "jwt"}

			auth, err := NewAdaptiveAuthenticator(&AdaptiveConfig{
				UserChecker:           userChecker,
				RequiredAuthenticator: requiredAuth,
			})
			if err != nil {
				t.Fatalf("failed to create authenticator: %v", err)
			}

			got := auth.RequiresAuth()
			if got != tt.want {
				t.Errorf("RequiresAuth() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAdaptiveAuthenticator_CurrentAuthenticator(t *testing.T) {
	tests := []struct {
		name     string
		hasUsers bool
		wantName string
	}{
		{
			name:     "no users - returns noop",
			hasUsers: false,
			wantName: "noop",
		},
		{
			name:     "with users - returns required",
			hasUsers: true,
			wantName: "required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userChecker := &mockUserChecker{hasUsers: tt.hasUsers}
			requiredAuth := &mockAuthenticator{name: "required"}

			auth, err := NewAdaptiveAuthenticator(&AdaptiveConfig{
				UserChecker:           userChecker,
				RequiredAuthenticator: requiredAuth,
			})
			if err != nil {
				t.Fatalf("failed to create authenticator: %v", err)
			}

			got := auth.CurrentAuthenticator()
			if got == nil {
				t.Fatal("expected non-nil authenticator")
			}
			if got.Name() != tt.wantName {
				t.Errorf("CurrentAuthenticator().Name() = %v, want %v", got.Name(), tt.wantName)
			}
		})
	}
}

func TestAdaptiveAuthenticator_ForceRefresh(t *testing.T) {
	userChecker := &mockUserChecker{hasUsers: false}
	requiredAuth := &mockAuthenticator{name: "jwt"}

	auth, err := NewAdaptiveAuthenticator(&AdaptiveConfig{
		UserChecker:           userChecker,
		RequiredAuthenticator: requiredAuth,
		CacheExpiry:           1 * time.Hour, // Long cache to ensure caching works
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// Initial check should not require auth
	if auth.RequiresAuth() {
		t.Error("expected RequiresAuth() to return false initially")
	}

	initialCallCount := userChecker.getCallCount()

	// Change the user state
	userChecker.setHasUsers(true)

	// Without force refresh, should use cached value
	if auth.RequiresAuth() {
		t.Error("expected RequiresAuth() to still return false (cached)")
	}

	// Call count shouldn't increase (using cache)
	if userChecker.getCallCount() != initialCallCount {
		t.Error("expected no additional user checks (should use cache)")
	}

	// Force refresh
	auth.ForceRefresh(context.Background())

	// Now should require auth
	if !auth.RequiresAuth() {
		t.Error("expected RequiresAuth() to return true after ForceRefresh")
	}
}

func TestAdaptiveAuthenticator_CacheExpiry(t *testing.T) {
	userChecker := &mockUserChecker{hasUsers: false}
	requiredAuth := &mockAuthenticator{name: "jwt"}

	// Very short cache expiry for testing
	auth, err := NewAdaptiveAuthenticator(&AdaptiveConfig{
		UserChecker:           userChecker,
		RequiredAuthenticator: requiredAuth,
		CacheExpiry:           10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// Initial check
	if auth.RequiresAuth() {
		t.Error("expected RequiresAuth() to return false initially")
	}

	// Change user state
	userChecker.setHasUsers(true)

	// Wait for cache to expire
	time.Sleep(20 * time.Millisecond)

	// Should now see the new value
	if !auth.RequiresAuth() {
		t.Error("expected RequiresAuth() to return true after cache expiry")
	}
}

func TestAdaptiveAuthenticator_UserCheckerError(t *testing.T) {
	userChecker := &mockUserChecker{hasUsers: false}
	requiredAuth := &mockAuthenticator{name: "jwt"}

	auth, err := NewAdaptiveAuthenticator(&AdaptiveConfig{
		UserChecker:           userChecker,
		RequiredAuthenticator: requiredAuth,
		CacheExpiry:           10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// Initial check to populate cache
	if auth.RequiresAuth() {
		t.Error("expected RequiresAuth() to return false initially")
	}

	// Set error on user checker
	userChecker.mu.Lock()
	userChecker.err = errors.New("database error")
	userChecker.hasUsers = true
	userChecker.mu.Unlock()

	// Wait for cache to expire
	time.Sleep(20 * time.Millisecond)

	// On error, should use cached value (false)
	if auth.RequiresAuth() {
		t.Error("expected RequiresAuth() to return cached false on error")
	}
}

func TestAdaptiveAuthenticator_ConcurrentAccess(t *testing.T) {
	userChecker := &mockUserChecker{hasUsers: false}
	requiredAuth := &mockAuthenticator{
		name:     "jwt",
		identity: &Identity{Subject: "user"},
	}

	auth, err := NewAdaptiveAuthenticator(&AdaptiveConfig{
		UserChecker:           userChecker,
		RequiredAuthenticator: requiredAuth,
		CacheExpiry:           1 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// Run concurrent requests
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = auth.RequiresAuth()
			_ = auth.Name()
			_ = auth.CurrentAuthenticator()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			_, _ = auth.AuthenticateHTTP(req)
			_, _ = auth.AuthenticateGRPC(context.Background(), metadata.MD{})
		}()
	}
	wg.Wait()
}

func TestAuthError_Error(t *testing.T) {
	err := newAuthError("test error")
	if err.Error() != "test error" {
		t.Errorf("Error() = %v, want test error", err.Error())
	}
}

func TestAdaptiveAuthenticator_ModeSwitch(t *testing.T) {
	userChecker := &mockUserChecker{hasUsers: false}
	requiredAuth := &mockAuthenticator{
		name:     "jwt",
		identity: &Identity{Subject: "user"},
	}

	auth, err := NewAdaptiveAuthenticator(&AdaptiveConfig{
		UserChecker:           userChecker,
		RequiredAuthenticator: requiredAuth,
		CacheExpiry:           10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// Start with no users (bootstrap mode)
	if auth.RequiresAuth() {
		t.Error("expected no auth required initially")
	}
	if auth.Name() != "adaptive:noop" {
		t.Errorf("Name() = %v, want adaptive:noop", auth.Name())
	}

	// Add users
	userChecker.setHasUsers(true)
	time.Sleep(20 * time.Millisecond) // Wait for cache expiry

	// Should now require auth
	if !auth.RequiresAuth() {
		t.Error("expected auth required after users added")
	}
	if auth.Name() != "adaptive:jwt" {
		t.Errorf("Name() = %v, want adaptive:jwt", auth.Name())
	}

	// Remove all users
	userChecker.setHasUsers(false)
	time.Sleep(20 * time.Millisecond) // Wait for cache expiry

	// Should go back to bootstrap mode
	if auth.RequiresAuth() {
		t.Error("expected no auth required after users removed")
	}
	if auth.Name() != "adaptive:noop" {
		t.Errorf("Name() = %v, want adaptive:noop", auth.Name())
	}
}
