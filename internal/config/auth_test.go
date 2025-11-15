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

package config

import (
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/adapters/auth"
)

func TestCreateAuthenticator_Disabled(t *testing.T) {
	cfg := &AuthConfig{
		Enabled: false,
	}

	authenticator, err := cfg.CreateAuthenticator()

	if err != nil {
		t.Fatalf("CreateAuthenticator() error = %v, want nil", err)
	}

	if authenticator == nil {
		t.Fatal("CreateAuthenticator() returned nil")
	}

	if authenticator.Name() != "noop" {
		t.Errorf("authenticator.Name() = %v, want noop", authenticator.Name())
	}
}

func TestCreateAuthenticator_TypeNoop(t *testing.T) {
	cfg := &AuthConfig{
		Enabled: true,
		Type:    "noop",
	}

	authenticator, err := cfg.CreateAuthenticator()

	if err != nil {
		t.Fatalf("CreateAuthenticator() error = %v, want nil", err)
	}

	if authenticator == nil {
		t.Fatal("CreateAuthenticator() returned nil")
	}

	if authenticator.Name() != "noop" {
		t.Errorf("authenticator.Name() = %v, want noop", authenticator.Name())
	}
}

func TestCreateAuthenticator_TypeNone(t *testing.T) {
	cfg := &AuthConfig{
		Enabled: true,
		Type:    "none",
	}

	authenticator, err := cfg.CreateAuthenticator()

	if err != nil {
		t.Fatalf("CreateAuthenticator() error = %v, want nil", err)
	}

	if authenticator == nil {
		t.Fatal("CreateAuthenticator() returned nil")
	}

	if authenticator.Name() != "noop" {
		t.Errorf("authenticator.Name() = %v, want noop", authenticator.Name())
	}
}

func TestCreateAuthenticator_TypeEmpty(t *testing.T) {
	cfg := &AuthConfig{
		Enabled: true,
		Type:    "",
	}

	authenticator, err := cfg.CreateAuthenticator()

	if err != nil {
		t.Fatalf("CreateAuthenticator() error = %v, want nil", err)
	}

	if authenticator == nil {
		t.Fatal("CreateAuthenticator() returned nil")
	}

	if authenticator.Name() != "noop" {
		t.Errorf("authenticator.Name() = %v, want noop", authenticator.Name())
	}
}

func TestCreateAuthenticator_TypeAPIKey(t *testing.T) {
	cfg := &AuthConfig{
		Enabled: true,
		Type:    "apikey",
		APIKeys: map[string]APIKeyConfig{
			"test-key": {
				Subject: "test-user",
				Roles:   []string{"admin"},
			},
		},
	}

	authenticator, err := cfg.CreateAuthenticator()

	if err != nil {
		t.Fatalf("CreateAuthenticator() error = %v, want nil", err)
	}

	if authenticator == nil {
		t.Fatal("CreateAuthenticator() returned nil")
	}

	if authenticator.Name() != "apikey" {
		t.Errorf("authenticator.Name() = %v, want apikey", authenticator.Name())
	}
}

func TestCreateAuthenticator_TypeAPIKey_NoKeys(t *testing.T) {
	cfg := &AuthConfig{
		Enabled: true,
		Type:    "apikey",
		APIKeys: map[string]APIKeyConfig{},
	}

	authenticator, err := cfg.CreateAuthenticator()

	if err == nil {
		t.Fatal("CreateAuthenticator() should return error for apikey with no keys")
	}

	if authenticator != nil {
		t.Errorf("CreateAuthenticator() returned %v, want nil", authenticator)
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
		t.Fatal("CreateAuthenticator() should return error for jwt (not implemented)")
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

func TestCreateAPIKeyAuthenticator_BasicConfig(t *testing.T) {
	cfg := &AuthConfig{
		Enabled: true,
		Type:    "apikey",
		APIKeys: map[string]APIKeyConfig{
			"key1": {
				Subject: "user1",
			},
			"key2": {
				Subject: "user2",
			},
		},
	}

	authenticator, err := cfg.createAPIKeyAuthenticator()

	if err != nil {
		t.Fatalf("createAPIKeyAuthenticator() error = %v, want nil", err)
	}

	if authenticator == nil {
		t.Fatal("createAPIKeyAuthenticator() returned nil")
	}

	// Verify the authenticator works
	apiKeyAuth, ok := authenticator.(*auth.APIKeyAuthenticator)
	if !ok {
		t.Fatal("authenticator is not *auth.APIKeyAuthenticator")
	}

	if apiKeyAuth.Name() != "apikey" {
		t.Errorf("Name() = %v, want apikey", apiKeyAuth.Name())
	}
}

func TestCreateAPIKeyAuthenticator_WithRoles(t *testing.T) {
	cfg := &AuthConfig{
		Enabled: true,
		Type:    "apikey",
		APIKeys: map[string]APIKeyConfig{
			"admin-key": {
				Subject: "admin",
				Roles:   []string{"admin", "user"},
			},
		},
	}

	authenticator, err := cfg.createAPIKeyAuthenticator()

	if err != nil {
		t.Fatalf("createAPIKeyAuthenticator() error = %v, want nil", err)
	}

	if authenticator == nil {
		t.Fatal("createAPIKeyAuthenticator() returned nil")
	}

	// Verify the authenticator is an APIKeyAuthenticator
	apiKeyAuth, ok := authenticator.(*auth.APIKeyAuthenticator)
	if !ok {
		t.Fatal("authenticator is not *auth.APIKeyAuthenticator")
	}

	if apiKeyAuth.Name() != "apikey" {
		t.Errorf("Name() = %v, want apikey", apiKeyAuth.Name())
	}
}

func TestCreateAPIKeyAuthenticator_WithPermissions(t *testing.T) {
	cfg := &AuthConfig{
		Enabled: true,
		Type:    "apikey",
		APIKeys: map[string]APIKeyConfig{
			"dev-key": {
				Subject:     "developer",
				Permissions: []string{"read", "write"},
			},
		},
	}

	authenticator, err := cfg.createAPIKeyAuthenticator()

	if err != nil {
		t.Fatalf("createAPIKeyAuthenticator() error = %v, want nil", err)
	}

	if authenticator == nil {
		t.Fatal("createAPIKeyAuthenticator() returned nil")
	}

	// Verify the authenticator is an APIKeyAuthenticator
	apiKeyAuth, ok := authenticator.(*auth.APIKeyAuthenticator)
	if !ok {
		t.Fatal("authenticator is not *auth.APIKeyAuthenticator")
	}

	if apiKeyAuth.Name() != "apikey" {
		t.Errorf("Name() = %v, want apikey", apiKeyAuth.Name())
	}
}

func TestCreateAPIKeyAuthenticator_WithClaims(t *testing.T) {
	cfg := &AuthConfig{
		Enabled: true,
		Type:    "apikey",
		APIKeys: map[string]APIKeyConfig{
			"custom-key": {
				Subject: "custom-user",
				Claims: map[string]interface{}{
					"team":   "engineering",
					"region": "us-west",
				},
			},
		},
	}

	authenticator, err := cfg.createAPIKeyAuthenticator()

	if err != nil {
		t.Fatalf("createAPIKeyAuthenticator() error = %v, want nil", err)
	}

	if authenticator == nil {
		t.Fatal("createAPIKeyAuthenticator() returned nil")
	}

	// Verify the authenticator is an APIKeyAuthenticator
	apiKeyAuth, ok := authenticator.(*auth.APIKeyAuthenticator)
	if !ok {
		t.Fatal("authenticator is not *auth.APIKeyAuthenticator")
	}

	if apiKeyAuth.Name() != "apikey" {
		t.Errorf("Name() = %v, want apikey", apiKeyAuth.Name())
	}
}

func TestCreateAPIKeyAuthenticator_WithRolesPermissionsAndClaims(t *testing.T) {
	cfg := &AuthConfig{
		Enabled: true,
		Type:    "apikey",
		APIKeys: map[string]APIKeyConfig{
			"full-key": {
				Subject:     "full-user",
				Roles:       []string{"admin"},
				Permissions: []string{"read", "write", "delete"},
				Claims: map[string]interface{}{
					"department": "security",
					"level":      5,
				},
			},
		},
	}

	authenticator, err := cfg.createAPIKeyAuthenticator()

	if err != nil {
		t.Fatalf("createAPIKeyAuthenticator() error = %v, want nil", err)
	}

	if authenticator == nil {
		t.Fatal("createAPIKeyAuthenticator() returned nil")
	}

	// Verify the authenticator is an APIKeyAuthenticator
	apiKeyAuth, ok := authenticator.(*auth.APIKeyAuthenticator)
	if !ok {
		t.Fatal("authenticator is not *auth.APIKeyAuthenticator")
	}

	if apiKeyAuth.Name() != "apikey" {
		t.Errorf("Name() = %v, want apikey", apiKeyAuth.Name())
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
