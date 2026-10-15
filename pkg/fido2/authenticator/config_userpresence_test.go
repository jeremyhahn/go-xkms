package authenticator

import (
	"errors"
	"testing"
)

// TestConfigValidate_NilUserPresenceHandlerRefused pins the #317 contract at
// the validation seam: a config with no handler is invalid, with the typed
// error, before any authenticator is constructed.
func TestConfigValidate_NilUserPresenceHandlerRefused(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.Storage = NewMemoryStorage()
	cfg.UserPresenceHandler = nil

	err := cfg.Validate()
	if !errors.Is(err, ErrUserPresenceHandlerRequired) {
		t.Fatalf("Validate() with nil UserPresenceHandler = %v, want ErrUserPresenceHandlerRequired", err)
	}
}

// TestConfigValidate_ExplicitHandlerAccepted is the positive half: stating
// the policy -- even auto-grant -- satisfies validation.
func TestConfigValidate_ExplicitHandlerAccepted(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.Storage = NewMemoryStorage()
	cfg.UserPresenceHandler = NewAutoGrantHandler()

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() with an explicit handler = %v, want nil", err)
	}
}

// TestNewAuthenticator_NilUserPresenceHandlerRefused pins that the
// constructor surfaces the validation error rather than installing a default.
func TestNewAuthenticator_NilUserPresenceHandlerRefused(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.Storage = NewMemoryStorage()
	cfg.UserPresenceHandler = nil

	auth, err := NewAuthenticator(cfg)
	if !errors.Is(err, ErrUserPresenceHandlerRequired) {
		t.Fatalf("NewAuthenticator() = (%v, %v), want ErrUserPresenceHandlerRequired", auth, err)
	}
	if auth != nil {
		t.Fatalf("NewAuthenticator() returned a non-nil authenticator alongside the error")
	}
}
