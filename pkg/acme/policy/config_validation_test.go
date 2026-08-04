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

package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidatePolicyConfig_ValidDefault(t *testing.T) {
	cfg := DefaultPolicyConfig()
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestValidatePolicyConfig_ValidEmpty(t *testing.T) {
	// A completely empty/zero-value config is valid (no policy enforcement).
	cfg := &PolicyConfig{}
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestValidatePolicyConfig_ValidIdentifiersOnly(t *testing.T) {
	cfg := &PolicyConfig{
		EnabledIdentifierTypes: map[string]bool{
			IdentifierTypeDNS: true,
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestValidatePolicyConfig_ValidChallengesOnly(t *testing.T) {
	cfg := &PolicyConfig{
		EnabledChallengeTypes: map[string]bool{
			ChallengeTypeHTTP01: true,
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestValidatePolicyConfig_BlocklistWithNoTypes(t *testing.T) {
	// A config with blocklist entries but no enabled identifier or challenge
	// types is invalid because the blocklist cannot be evaluated without
	// at least one operational type.
	cfg := &PolicyConfig{
		Blocklist: BlocklistConfig{
			HighRiskBlockedNames: []string{"evil.com"},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one enabled identifier type or challenge type")
}

func TestValidatePolicyConfig_AllDisabledWithBlocklist(t *testing.T) {
	// Maps exist but all values are false -- still no enabled entries.
	cfg := &PolicyConfig{
		Blocklist: BlocklistConfig{
			ExactBlockedNames: []string{"blocked.example.com"},
		},
		EnabledIdentifierTypes: map[string]bool{
			IdentifierTypeDNS: false,
			IdentifierTypeIP:  false,
		},
		EnabledChallengeTypes: map[string]bool{
			ChallengeTypeHTTP01: false,
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one enabled identifier type or challenge type")
}

func TestValidatePolicyConfig_BlocklistWithIdentifier(t *testing.T) {
	// Blocklist + at least one enabled identifier type is valid.
	cfg := &PolicyConfig{
		Blocklist: BlocklistConfig{
			HighRiskBlockedNames: []string{"evil.com"},
		},
		EnabledIdentifierTypes: map[string]bool{
			IdentifierTypeDNS: true,
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestValidatePolicyConfig_BlocklistWithChallenge(t *testing.T) {
	// Blocklist + at least one enabled challenge type is valid.
	cfg := &PolicyConfig{
		Blocklist: BlocklistConfig{
			AdminBlockedPrefixes: []string{"10.0.0.0/8"},
		},
		EnabledChallengeTypes: map[string]bool{
			ChallengeTypeDNS01: true,
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
}
