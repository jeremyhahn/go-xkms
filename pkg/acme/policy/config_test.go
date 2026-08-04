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
)

func TestDefaultBlocklistConfig(t *testing.T) {
	config := DefaultBlocklistConfig()

	// Verify non-nil
	if config == nil {
		t.Fatal("DefaultBlocklistConfig() returned nil")
	}

	// Verify high-risk blocked names include expected entries
	expectedHighRisk := []string{
		"example.com",
		"example.net",
		"example.org",
		"localhost",
		"local",
		"onion",
	}

	for _, expected := range expectedHighRisk {
		found := false
		for _, name := range config.HighRiskBlockedNames {
			if name == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("HighRiskBlockedNames should contain %q", expected)
		}
	}

	// Verify IP prefixes include expected entries
	expectedPrefixes := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	for _, expected := range expectedPrefixes {
		found := false
		for _, prefix := range config.AdminBlockedPrefixes {
			if prefix == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("AdminBlockedPrefixes should contain %q", expected)
		}
	}
}

func TestDefaultPolicyConfig(t *testing.T) {
	config := DefaultPolicyConfig()

	// Verify non-nil
	if config == nil {
		t.Fatal("DefaultPolicyConfig() returned nil")
	}

	// Verify enabled identifier types
	expectedIdTypes := []string{
		IdentifierTypeDNS,
		IdentifierTypeIP,
		IdentifierTypePermanentIdentifier,
	}

	for _, idType := range expectedIdTypes {
		if !config.EnabledIdentifierTypes[idType] {
			t.Errorf("EnabledIdentifierTypes[%q] should be true", idType)
		}
	}

	// Verify enabled challenge types
	expectedChallenges := []string{
		ChallengeTypeHTTP01,
		ChallengeTypeDNS01,
		ChallengeTypeTLSALPN01,
		ChallengeTypeDeviceAttest01,
		ChallengeTypeEnroll01,
		ChallengeTypeEndorse01,
	}

	for _, challType := range expectedChallenges {
		if !config.EnabledChallengeTypes[challType] {
			t.Errorf("EnabledChallengeTypes[%q] should be true", challType)
		}
	}

	// Verify default settings
	if !config.RequirePublicSuffix {
		t.Error("RequirePublicSuffix should be true by default")
	}
	if !config.AllowWildcards {
		t.Error("AllowWildcards should be true by default")
	}
}

func TestBlocklistConfig_Merge(t *testing.T) {
	base := &BlocklistConfig{
		HighRiskBlockedNames: []string{"base1.com", "base2.com"},
		ExactBlockedNames:    []string{"exact1.base.com"},
		AdminBlockedNames:    []string{"admin1.com"},
		AdminBlockedPrefixes: []string{"10.0.0.0/8"},
	}

	other := &BlocklistConfig{
		HighRiskBlockedNames: []string{"other1.com"},
		ExactBlockedNames:    []string{"exact1.other.com"},
		AdminBlockedNames:    []string{"admin2.com"},
		AdminBlockedPrefixes: []string{"192.168.0.0/16"},
	}

	base.Merge(other)

	// Verify merged high risk names
	if len(base.HighRiskBlockedNames) != 3 {
		t.Errorf("HighRiskBlockedNames length = %d, want 3", len(base.HighRiskBlockedNames))
	}

	// Verify merged exact names
	if len(base.ExactBlockedNames) != 2 {
		t.Errorf("ExactBlockedNames length = %d, want 2", len(base.ExactBlockedNames))
	}

	// Verify merged admin names
	if len(base.AdminBlockedNames) != 2 {
		t.Errorf("AdminBlockedNames length = %d, want 2", len(base.AdminBlockedNames))
	}

	// Verify merged prefixes
	if len(base.AdminBlockedPrefixes) != 2 {
		t.Errorf("AdminBlockedPrefixes length = %d, want 2", len(base.AdminBlockedPrefixes))
	}
}

func TestBlocklistConfig_Merge_Nil(t *testing.T) {
	base := &BlocklistConfig{
		HighRiskBlockedNames: []string{"base.com"},
	}

	// Should not panic
	base.Merge(nil)

	// Should remain unchanged
	if len(base.HighRiskBlockedNames) != 1 {
		t.Errorf("HighRiskBlockedNames length = %d, want 1 after nil merge", len(base.HighRiskBlockedNames))
	}
}

func TestBlocklistConfig_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		config   *BlocklistConfig
		expected bool
	}{
		{
			name:     "completely empty",
			config:   &BlocklistConfig{},
			expected: true,
		},
		{
			name: "with high risk names",
			config: &BlocklistConfig{
				HighRiskBlockedNames: []string{"example.com"},
			},
			expected: false,
		},
		{
			name: "with exact names",
			config: &BlocklistConfig{
				ExactBlockedNames: []string{"exact.example.com"},
			},
			expected: false,
		},
		{
			name: "with admin names",
			config: &BlocklistConfig{
				AdminBlockedNames: []string{"admin.example.com"},
			},
			expected: false,
		},
		{
			name: "with IP prefixes",
			config: &BlocklistConfig{
				AdminBlockedPrefixes: []string{"10.0.0.0/8"},
			},
			expected: false,
		},
		{
			name: "with empty slices",
			config: &BlocklistConfig{
				HighRiskBlockedNames: []string{},
				ExactBlockedNames:    []string{},
				AdminBlockedNames:    []string{},
				AdminBlockedPrefixes: []string{},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.IsEmpty()
			if got != tt.expected {
				t.Errorf("IsEmpty() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestBlocklistConfig_Clone(t *testing.T) {
	original := &BlocklistConfig{
		HighRiskBlockedNames: []string{"high1.com", "high2.com"},
		ExactBlockedNames:    []string{"exact.example.com"},
		AdminBlockedNames:    []string{"admin.example.com"},
		AdminBlockedPrefixes: []string{"10.0.0.0/8", "192.168.0.0/16"},
	}

	clone := original.Clone()

	// Verify clone is not nil
	if clone == nil {
		t.Fatal("Clone() returned nil")
	}

	// Verify contents match
	if len(clone.HighRiskBlockedNames) != len(original.HighRiskBlockedNames) {
		t.Errorf("HighRiskBlockedNames length = %d, want %d",
			len(clone.HighRiskBlockedNames), len(original.HighRiskBlockedNames))
	}

	// Verify independence - modify clone
	clone.HighRiskBlockedNames = append(clone.HighRiskBlockedNames, "new.com")
	if len(original.HighRiskBlockedNames) != 2 {
		t.Error("Modifying clone affected original")
	}
}

func TestBlocklistConfig_Clone_Nil(t *testing.T) {
	var config *BlocklistConfig
	clone := config.Clone()
	if clone != nil {
		t.Error("Clone() of nil should return nil")
	}
}

func TestPolicyConfig_Clone(t *testing.T) {
	original := &PolicyConfig{
		Blocklist: BlocklistConfig{
			HighRiskBlockedNames: []string{"example.com"},
		},
		EnabledIdentifierTypes: map[string]bool{
			IdentifierTypeDNS: true,
			IdentifierTypeIP:  false,
		},
		EnabledChallengeTypes: map[string]bool{
			ChallengeTypeHTTP01: true,
			ChallengeTypeDNS01:  true,
		},
		RequirePublicSuffix: true,
		AllowWildcards:      true,
	}

	clone := original.Clone()

	// Verify clone is not nil
	if clone == nil {
		t.Fatal("Clone() returned nil")
	}

	// Verify contents match
	if !clone.RequirePublicSuffix {
		t.Error("RequirePublicSuffix should be true")
	}
	if !clone.AllowWildcards {
		t.Error("AllowWildcards should be true")
	}

	// Verify identifier types
	if !clone.EnabledIdentifierTypes[IdentifierTypeDNS] {
		t.Error("DNS identifier type should be enabled")
	}
	if clone.EnabledIdentifierTypes[IdentifierTypeIP] {
		t.Error("IP identifier type should be disabled")
	}

	// Verify independence - modify clone
	clone.EnabledIdentifierTypes[IdentifierTypeDNS] = false
	if !original.EnabledIdentifierTypes[IdentifierTypeDNS] {
		t.Error("Modifying clone affected original")
	}
}

func TestPolicyConfig_Clone_Nil(t *testing.T) {
	var config *PolicyConfig
	clone := config.Clone()
	if clone != nil {
		t.Error("Clone() of nil should return nil")
	}
}

func TestPolicyConfig_Clone_NilMaps(t *testing.T) {
	original := &PolicyConfig{
		RequirePublicSuffix: true,
		// Maps are nil
	}

	clone := original.Clone()

	if clone == nil {
		t.Fatal("Clone() returned nil")
	}

	// Maps should be nil in clone too
	if clone.EnabledIdentifierTypes != nil {
		t.Error("EnabledIdentifierTypes should be nil")
	}
	if clone.EnabledChallengeTypes != nil {
		t.Error("EnabledChallengeTypes should be nil")
	}
}
