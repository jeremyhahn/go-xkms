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

package config

import (
	"errors"
	"testing"
)

// TestCreateAuthenticator_Disabled verifies a configuration that names no
// authenticator is refused: xkms has no unauthenticated mode.
func TestCreateAuthenticator_Disabled(t *testing.T) {
	for name, cfg := range map[string]*AuthConfig{
		"auth disabled":   {Enabled: false, Type: "mtls"},
		"empty auth type": {Enabled: true, Type: ""},
	} {
		t.Run(name, func(t *testing.T) {
			authenticator, err := cfg.CreateAuthenticator()
			if !errors.Is(err, ErrAuthenticationDisabled) {
				t.Fatalf("CreateAuthenticator() error = %v, want ErrAuthenticationDisabled", err)
			}
			if authenticator != nil {
				t.Errorf("CreateAuthenticator() = %v, want nil", authenticator)
			}
		})
	}
}

// TestCreateAuthenticator_NoOpTypesAreUnknown verifies the removed "noop" and
// "none" auth types are refused as unknown rather than admitting every caller.
func TestCreateAuthenticator_NoOpTypesAreUnknown(t *testing.T) {
	for _, authType := range []string{"noop", "none"} {
		t.Run(authType, func(t *testing.T) {
			cfg := &AuthConfig{Enabled: true, Type: authType}
			authenticator, err := cfg.CreateAuthenticator()
			if err == nil {
				t.Fatalf("CreateAuthenticator() with type %q succeeded, want an error", authType)
			}
			if authenticator != nil {
				t.Errorf("CreateAuthenticator() = %v, want nil", authenticator)
			}
		})
	}
}

func TestCreateAuthenticator_TypeMTLS(t *testing.T) {
	cfg := &AuthConfig{
		Enabled: true,
		Type:    "mtls",
		MTLS:    true,
	}

	authenticator, err := cfg.CreateAuthenticator()

	if err != nil {
		t.Fatalf("CreateAuthenticator() error = %v, want nil", err)
	}

	if authenticator == nil {
		t.Fatal("CreateAuthenticator() returned nil")
	}

	if authenticator.Name() != "mtls" {
		t.Errorf("authenticator.Name() = %v, want mtls", authenticator.Name())
	}
}

func TestCreateAuthenticator_TypeMTLS_NotEnabled(t *testing.T) {
	cfg := &AuthConfig{
		Enabled: true,
		Type:    "mtls",
		MTLS:    false,
	}

	authenticator, err := cfg.CreateAuthenticator()

	if err == nil {
		t.Fatal("CreateAuthenticator() should return error for mtls not enabled")
	}

	if authenticator != nil {
		t.Errorf("CreateAuthenticator() returned %v, want nil", authenticator)
	}
}

func TestCreateAuthenticator_TypeJWT(t *testing.T) {
	cfg := &AuthConfig{
		Enabled: true,
		Type:    "jwt",
	}

	authenticator, err := cfg.CreateAuthenticator()

	if err == nil {
		t.Fatal("CreateAuthenticator() should return error for jwt (requires server config)")
	}

	if authenticator != nil {
		t.Errorf("CreateAuthenticator() returned %v, want nil", authenticator)
	}
}

func TestCreateAuthenticator_TypeAdaptive(t *testing.T) {
	cfg := &AuthConfig{
		Enabled: true,
		Type:    "adaptive",
	}

	authenticator, err := cfg.CreateAuthenticator()

	if err == nil {
		t.Fatal("CreateAuthenticator() should return error for adaptive (requires server config)")
	}

	if authenticator != nil {
		t.Errorf("CreateAuthenticator() returned %v, want nil", authenticator)
	}
}

func TestCreateAuthenticator_UnknownType(t *testing.T) {
	cfg := &AuthConfig{
		Enabled: true,
		Type:    "unknown-type",
	}

	authenticator, err := cfg.CreateAuthenticator()

	if err == nil {
		t.Fatal("CreateAuthenticator() should return error for unknown type")
	}

	if authenticator != nil {
		t.Errorf("CreateAuthenticator() returned %v, want nil", authenticator)
	}
}

func TestCreateMTLSAuthenticator(t *testing.T) {
	cfg := &AuthConfig{
		Enabled: true,
		Type:    "mtls",
		MTLS:    true,
	}

	authenticator, err := cfg.createMTLSAuthenticator()

	if err != nil {
		t.Fatalf("createMTLSAuthenticator() error = %v, want nil", err)
	}

	if authenticator == nil {
		t.Fatal("createMTLSAuthenticator() returned nil")
	}

	if authenticator.Name() != "mtls" {
		t.Errorf("Name() = %v, want mtls", authenticator.Name())
	}
}

func TestCreateMTLSAuthenticator_NotEnabled(t *testing.T) {
	cfg := &AuthConfig{
		Enabled: true,
		Type:    "mtls",
		MTLS:    false,
	}

	authenticator, err := cfg.createMTLSAuthenticator()

	if err == nil {
		t.Fatal("createMTLSAuthenticator() should return error when mTLS not enabled")
	}

	if authenticator != nil {
		t.Errorf("createMTLSAuthenticator() returned %v, want nil", authenticator)
	}
}
