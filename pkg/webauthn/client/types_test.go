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

package client

import (
	"errors"
	"testing"
	"time"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr error
	}{
		{
			name: "valid config",
			config: Config{
				ServerURL:            "https://example.com",
				AuthenticatorAdapter: NewSoftwareAdapter(),
			},
			wantErr: nil,
		},
		{
			name: "empty server URL",
			config: Config{
				ServerURL:            "",
				AuthenticatorAdapter: NewSoftwareAdapter(),
			},
			wantErr: ErrServerURLRequired,
		},
		{
			name: "nil authenticator adapter",
			config: Config{
				ServerURL:            "https://example.com",
				AuthenticatorAdapter: nil,
			},
			wantErr: ErrNilAuthenticatorAdapter,
		},
		{
			name:    "both missing",
			config:  Config{},
			wantErr: ErrServerURLRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("Validate() returned unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Errorf("Validate() returned nil, want %v", tt.wantErr)
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Validate() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfig_SetDefaults(t *testing.T) {
	t.Run("sets default timeout", func(t *testing.T) {
		cfg := &Config{}
		cfg.SetDefaults()
		if cfg.Timeout != 30*time.Second {
			t.Errorf("Timeout = %v, want %v", cfg.Timeout, 30*time.Second)
		}
	})

	t.Run("preserves custom timeout", func(t *testing.T) {
		cfg := &Config{Timeout: 10 * time.Second}
		cfg.SetDefaults()
		if cfg.Timeout != 10*time.Second {
			t.Errorf("Timeout = %v, want %v", cfg.Timeout, 10*time.Second)
		}
	})
}

func TestRegistrationRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		req     RegistrationRequest
		wantErr error
	}{
		{
			name:    "valid request",
			req:     RegistrationRequest{Username: "user@example.com"},
			wantErr: nil,
		},
		{
			name:    "empty username",
			req:     RegistrationRequest{Username: ""},
			wantErr: ErrUsernameRequired,
		},
		{
			name: "with display name and auth token",
			req: RegistrationRequest{
				Username:    "user@example.com",
				DisplayName: "Test User",
				AuthToken:   "jwt-token",
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("Validate() returned unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Errorf("Validate() returned nil, want %v", tt.wantErr)
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Validate() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestAuthenticationRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		req     AuthenticationRequest
		wantErr error
	}{
		{
			name:    "valid request",
			req:     AuthenticationRequest{Username: "user@example.com"},
			wantErr: nil,
		},
		{
			name:    "empty username",
			req:     AuthenticationRequest{Username: ""},
			wantErr: ErrUsernameRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("Validate() returned unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Errorf("Validate() returned nil, want %v", tt.wantErr)
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Validate() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestRegistrationResult_Fields(t *testing.T) {
	r := &RegistrationResult{
		UserID:       "abc123",
		CredentialID: "cred456",
		JWT:          "token789",
	}
	if r.UserID != "abc123" {
		t.Errorf("UserID = %q, want %q", r.UserID, "abc123")
	}
	if r.CredentialID != "cred456" {
		t.Errorf("CredentialID = %q, want %q", r.CredentialID, "cred456")
	}
	if r.JWT != "token789" {
		t.Errorf("JWT = %q, want %q", r.JWT, "token789")
	}
}

func TestAuthenticationResult_Fields(t *testing.T) {
	r := &AuthenticationResult{
		UserID: "abc123",
		JWT:    "token789",
	}
	if r.UserID != "abc123" {
		t.Errorf("UserID = %q, want %q", r.UserID, "abc123")
	}
	if r.JWT != "token789" {
		t.Errorf("JWT = %q, want %q", r.JWT, "token789")
	}
}
