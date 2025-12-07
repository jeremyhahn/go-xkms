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

package webauthn

import (
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid minimal config",
			config: &Config{
				RPID:          "example.com",
				RPDisplayName: "Example",
				RPOrigins:     []string{"https://example.com"},
			},
			wantErr: false,
		},
		{
			name: "missing RPID",
			config: &Config{
				RPDisplayName: "Example",
				RPOrigins:     []string{"https://example.com"},
			},
			wantErr: true,
			errMsg:  "RPID is required",
		},
		{
			name: "missing RPDisplayName",
			config: &Config{
				RPID:      "example.com",
				RPOrigins: []string{"https://example.com"},
			},
			wantErr: true,
			errMsg:  "RPDisplayName is required",
		},
		{
			name: "missing RPOrigins",
			config: &Config{
				RPID:          "example.com",
				RPDisplayName: "Example",
			},
			wantErr: true,
			errMsg:  "at least one RPOrigin is required",
		},
		{
			name: "empty RPOrigins",
			config: &Config{
				RPID:          "example.com",
				RPDisplayName: "Example",
				RPOrigins:     []string{},
			},
			wantErr: true,
			errMsg:  "at least one RPOrigin is required",
		},
		{
			name: "invalid user verification",
			config: &Config{
				RPID:             "example.com",
				RPDisplayName:    "Example",
				RPOrigins:        []string{"https://example.com"},
				UserVerification: "invalid",
			},
			wantErr: true,
			errMsg:  "invalid user verification",
		},
		{
			name: "invalid attestation preference",
			config: &Config{
				RPID:                  "example.com",
				RPDisplayName:         "Example",
				RPOrigins:             []string{"https://example.com"},
				AttestationPreference: "invalid",
			},
			wantErr: true,
			errMsg:  "invalid attestation preference",
		},
		{
			name: "invalid resident key requirement",
			config: &Config{
				RPID:                   "example.com",
				RPDisplayName:          "Example",
				RPOrigins:              []string{"https://example.com"},
				ResidentKeyRequirement: "invalid",
			},
			wantErr: true,
			errMsg:  "invalid resident key requirement",
		},
		{
			name: "invalid authenticator attachment",
			config: &Config{
				RPID:                    "example.com",
				RPDisplayName:           "Example",
				RPOrigins:               []string{"https://example.com"},
				AuthenticatorAttachment: "invalid",
			},
			wantErr: true,
			errMsg:  "invalid authenticator attachment",
		},
		{
			name: "all valid values",
			config: &Config{
				RPID:                    "example.com",
				RPDisplayName:           "Example",
				RPOrigins:               []string{"https://example.com", "https://www.example.com"},
				UserVerification:        "required",
				AttestationPreference:   "direct",
				ResidentKeyRequirement:  "required",
				AuthenticatorAttachment: "platform",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestConfig_SetDefaults(t *testing.T) {
	config := &Config{
		RPID:          "example.com",
		RPDisplayName: "Example",
		RPOrigins:     []string{"https://example.com"},
	}

	config.SetDefaults()

	assert.Equal(t, 60*time.Second, config.Timeout)
	assert.Equal(t, "preferred", config.UserVerification)
	assert.Equal(t, "none", config.AttestationPreference)
	assert.Equal(t, "preferred", config.ResidentKeyRequirement)
}

func TestConfig_SetDefaults_PreservesExisting(t *testing.T) {
	config := &Config{
		RPID:                   "example.com",
		RPDisplayName:          "Example",
		RPOrigins:              []string{"https://example.com"},
		Timeout:                30 * time.Second,
		UserVerification:       "required",
		AttestationPreference:  "direct",
		ResidentKeyRequirement: "required",
	}

	config.SetDefaults()

	assert.Equal(t, 30*time.Second, config.Timeout)
	assert.Equal(t, "required", config.UserVerification)
	assert.Equal(t, "direct", config.AttestationPreference)
	assert.Equal(t, "required", config.ResidentKeyRequirement)
}

func TestConfig_ToWebAuthnConfig(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		check  func(t *testing.T, cfg *Config)
	}{
		{
			name: "basic config",
			config: &Config{
				RPID:          "example.com",
				RPDisplayName: "Example",
				RPOrigins:     []string{"https://example.com"},
				Debug:         true,
			},
			check: func(t *testing.T, cfg *Config) {
				wc := cfg.ToWebAuthnConfig()
				assert.Equal(t, "example.com", wc.RPID)
				assert.Equal(t, "Example", wc.RPDisplayName)
				assert.Equal(t, []string{"https://example.com"}, wc.RPOrigins)
				assert.True(t, wc.Debug)
			},
		},
		{
			name: "with timeout",
			config: &Config{
				RPID:          "example.com",
				RPDisplayName: "Example",
				RPOrigins:     []string{"https://example.com"},
				Timeout:       90 * time.Second,
			},
			check: func(t *testing.T, cfg *Config) {
				wc := cfg.ToWebAuthnConfig()
				assert.Equal(t, 90*time.Second, wc.Timeouts.Login.Timeout)
				assert.Equal(t, 90*time.Second, wc.Timeouts.Registration.Timeout)
				assert.True(t, wc.Timeouts.Login.Enforce)
				assert.True(t, wc.Timeouts.Registration.Enforce)
			},
		},
		{
			name: "attestation preference none",
			config: &Config{
				RPID:                  "example.com",
				RPDisplayName:         "Example",
				RPOrigins:             []string{"https://example.com"},
				AttestationPreference: "none",
			},
			check: func(t *testing.T, cfg *Config) {
				wc := cfg.ToWebAuthnConfig()
				assert.Equal(t, protocol.PreferNoAttestation, wc.AttestationPreference)
			},
		},
		{
			name: "attestation preference indirect",
			config: &Config{
				RPID:                  "example.com",
				RPDisplayName:         "Example",
				RPOrigins:             []string{"https://example.com"},
				AttestationPreference: "indirect",
			},
			check: func(t *testing.T, cfg *Config) {
				wc := cfg.ToWebAuthnConfig()
				assert.Equal(t, protocol.PreferIndirectAttestation, wc.AttestationPreference)
			},
		},
		{
			name: "attestation preference direct",
			config: &Config{
				RPID:                  "example.com",
				RPDisplayName:         "Example",
				RPOrigins:             []string{"https://example.com"},
				AttestationPreference: "direct",
			},
			check: func(t *testing.T, cfg *Config) {
				wc := cfg.ToWebAuthnConfig()
				assert.Equal(t, protocol.PreferDirectAttestation, wc.AttestationPreference)
			},
		},
		{
			name: "attestation preference enterprise",
			config: &Config{
				RPID:                  "example.com",
				RPDisplayName:         "Example",
				RPOrigins:             []string{"https://example.com"},
				AttestationPreference: "enterprise",
			},
			check: func(t *testing.T, cfg *Config) {
				wc := cfg.ToWebAuthnConfig()
				assert.Equal(t, protocol.PreferEnterpriseAttestation, wc.AttestationPreference)
			},
		},
		{
			name: "user verification required",
			config: &Config{
				RPID:             "example.com",
				RPDisplayName:    "Example",
				RPOrigins:        []string{"https://example.com"},
				UserVerification: "required",
			},
			check: func(t *testing.T, cfg *Config) {
				wc := cfg.ToWebAuthnConfig()
				assert.Equal(t, protocol.VerificationRequired, wc.AuthenticatorSelection.UserVerification)
			},
		},
		{
			name: "user verification preferred",
			config: &Config{
				RPID:             "example.com",
				RPDisplayName:    "Example",
				RPOrigins:        []string{"https://example.com"},
				UserVerification: "preferred",
			},
			check: func(t *testing.T, cfg *Config) {
				wc := cfg.ToWebAuthnConfig()
				assert.Equal(t, protocol.VerificationPreferred, wc.AuthenticatorSelection.UserVerification)
			},
		},
		{
			name: "user verification discouraged",
			config: &Config{
				RPID:             "example.com",
				RPDisplayName:    "Example",
				RPOrigins:        []string{"https://example.com"},
				UserVerification: "discouraged",
			},
			check: func(t *testing.T, cfg *Config) {
				wc := cfg.ToWebAuthnConfig()
				assert.Equal(t, protocol.VerificationDiscouraged, wc.AuthenticatorSelection.UserVerification)
			},
		},
		{
			name: "resident key required",
			config: &Config{
				RPID:                   "example.com",
				RPDisplayName:          "Example",
				RPOrigins:              []string{"https://example.com"},
				ResidentKeyRequirement: "required",
			},
			check: func(t *testing.T, cfg *Config) {
				wc := cfg.ToWebAuthnConfig()
				assert.Equal(t, protocol.ResidentKeyRequirementRequired, wc.AuthenticatorSelection.ResidentKey)
			},
		},
		{
			name: "resident key preferred",
			config: &Config{
				RPID:                   "example.com",
				RPDisplayName:          "Example",
				RPOrigins:              []string{"https://example.com"},
				ResidentKeyRequirement: "preferred",
			},
			check: func(t *testing.T, cfg *Config) {
				wc := cfg.ToWebAuthnConfig()
				assert.Equal(t, protocol.ResidentKeyRequirementPreferred, wc.AuthenticatorSelection.ResidentKey)
			},
		},
		{
			name: "resident key discouraged",
			config: &Config{
				RPID:                   "example.com",
				RPDisplayName:          "Example",
				RPOrigins:              []string{"https://example.com"},
				ResidentKeyRequirement: "discouraged",
			},
			check: func(t *testing.T, cfg *Config) {
				wc := cfg.ToWebAuthnConfig()
				assert.Equal(t, protocol.ResidentKeyRequirementDiscouraged, wc.AuthenticatorSelection.ResidentKey)
			},
		},
		{
			name: "authenticator attachment platform",
			config: &Config{
				RPID:                    "example.com",
				RPDisplayName:           "Example",
				RPOrigins:               []string{"https://example.com"},
				AuthenticatorAttachment: "platform",
			},
			check: func(t *testing.T, cfg *Config) {
				wc := cfg.ToWebAuthnConfig()
				assert.Equal(t, protocol.Platform, wc.AuthenticatorSelection.AuthenticatorAttachment)
			},
		},
		{
			name: "authenticator attachment cross-platform",
			config: &Config{
				RPID:                    "example.com",
				RPDisplayName:           "Example",
				RPOrigins:               []string{"https://example.com"},
				AuthenticatorAttachment: "cross-platform",
			},
			check: func(t *testing.T, cfg *Config) {
				wc := cfg.ToWebAuthnConfig()
				assert.Equal(t, protocol.CrossPlatform, wc.AuthenticatorSelection.AuthenticatorAttachment)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.check(t, tt.config)
		})
	}
}
