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

package profiles

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
)

// =============================================================================
// NewTCGEKProfile Tests
// =============================================================================

func TestNewTCGEKProfile(t *testing.T) {
	t.Run("name_matches_constant", func(t *testing.T) {
		profile := NewTCGEKProfile()
		if profile.Name() != TCGEKProfileName {
			t.Errorf("expected name %q, got %q", TCGEKProfileName, profile.Name())
		}
	})

	t.Run("description_is_set", func(t *testing.T) {
		profile := NewTCGEKProfile()
		if profile.Description() == "" {
			t.Error("expected non-empty description")
		}
	})

	t.Run("key_usage_is_key_encipherment", func(t *testing.T) {
		profile := NewTCGEKProfile()
		if profile.KeyUsage() != x509.KeyUsageKeyEncipherment {
			t.Errorf("expected KeyUsageKeyEncipherment (%d), got %d",
				x509.KeyUsageKeyEncipherment, profile.KeyUsage())
		}
	})

	t.Run("ext_key_usage_contains_client_and_server_auth", func(t *testing.T) {
		profile := NewTCGEKProfile()
		eku := profile.ExtKeyUsage()
		if len(eku) != 2 {
			t.Fatalf("expected 2 ext key usages, got %d", len(eku))
		}
		if eku[0] != x509.ExtKeyUsageClientAuth {
			t.Errorf("expected ExtKeyUsageClientAuth at index 0, got %d", eku[0])
		}
		if eku[1] != x509.ExtKeyUsageServerAuth {
			t.Errorf("expected ExtKeyUsageServerAuth at index 1, got %d", eku[1])
		}
	})

	t.Run("validity_is_indefinite", func(t *testing.T) {
		profile := NewTCGEKProfile()
		if profile.DefaultValidity() != tcgIndefiniteValidityDays {
			t.Errorf("expected validity %d, got %d",
				tcgIndefiniteValidityDays, profile.DefaultValidity())
		}
	})

	t.Run("is_not_ca", func(t *testing.T) {
		profile := NewTCGEKProfile()
		if profile.IsCA() {
			t.Error("EK profile should not be a CA")
		}
	})
}

// =============================================================================
// NewTCGAKProfile Tests
// =============================================================================

func TestNewTCGAKProfile(t *testing.T) {
	t.Run("name_matches_constant", func(t *testing.T) {
		profile := NewTCGAKProfile()
		if profile.Name() != TCGAKProfileName {
			t.Errorf("expected name %q, got %q", TCGAKProfileName, profile.Name())
		}
	})

	t.Run("description_is_set", func(t *testing.T) {
		profile := NewTCGAKProfile()
		if profile.Description() == "" {
			t.Error("expected non-empty description")
		}
	})

	t.Run("key_usage_is_digital_signature", func(t *testing.T) {
		profile := NewTCGAKProfile()
		if profile.KeyUsage() != x509.KeyUsageDigitalSignature {
			t.Errorf("expected KeyUsageDigitalSignature (%d), got %d",
				x509.KeyUsageDigitalSignature, profile.KeyUsage())
		}
	})

	t.Run("ext_key_usage_contains_client_and_server_auth", func(t *testing.T) {
		profile := NewTCGAKProfile()
		eku := profile.ExtKeyUsage()
		if len(eku) != 2 {
			t.Fatalf("expected 2 ext key usages, got %d", len(eku))
		}
		if eku[0] != x509.ExtKeyUsageClientAuth {
			t.Errorf("expected ExtKeyUsageClientAuth at index 0, got %d", eku[0])
		}
		if eku[1] != x509.ExtKeyUsageServerAuth {
			t.Errorf("expected ExtKeyUsageServerAuth at index 1, got %d", eku[1])
		}
	})

	t.Run("validity_is_indefinite", func(t *testing.T) {
		profile := NewTCGAKProfile()
		if profile.DefaultValidity() != tcgIndefiniteValidityDays {
			t.Errorf("expected validity %d, got %d",
				tcgIndefiniteValidityDays, profile.DefaultValidity())
		}
	})

	t.Run("is_not_ca", func(t *testing.T) {
		profile := NewTCGAKProfile()
		if profile.IsCA() {
			t.Error("AK profile should not be a CA")
		}
	})
}

// =============================================================================
// NewTCGIDevIDProfile Tests
// =============================================================================

func TestNewTCGIDevIDProfile(t *testing.T) {
	t.Run("name_matches_constant", func(t *testing.T) {
		profile := NewTCGIDevIDProfile()
		if profile.Name() != TCGIDevIDProfileName {
			t.Errorf("expected name %q, got %q", TCGIDevIDProfileName, profile.Name())
		}
	})

	t.Run("description_is_set", func(t *testing.T) {
		profile := NewTCGIDevIDProfile()
		if profile.Description() == "" {
			t.Error("expected non-empty description")
		}
	})

	t.Run("key_usage_is_digital_signature_and_key_encipherment", func(t *testing.T) {
		profile := NewTCGIDevIDProfile()
		expected := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		if profile.KeyUsage() != expected {
			t.Errorf("expected KeyUsage %d (DigitalSignature|KeyEncipherment), got %d",
				expected, profile.KeyUsage())
		}
	})

	t.Run("key_usage_includes_digital_signature", func(t *testing.T) {
		profile := NewTCGIDevIDProfile()
		if profile.KeyUsage()&x509.KeyUsageDigitalSignature == 0 {
			t.Error("expected KeyUsageDigitalSignature to be set")
		}
	})

	t.Run("key_usage_includes_key_encipherment", func(t *testing.T) {
		profile := NewTCGIDevIDProfile()
		if profile.KeyUsage()&x509.KeyUsageKeyEncipherment == 0 {
			t.Error("expected KeyUsageKeyEncipherment to be set")
		}
	})

	t.Run("ext_key_usage_contains_client_and_server_auth", func(t *testing.T) {
		profile := NewTCGIDevIDProfile()
		eku := profile.ExtKeyUsage()
		if len(eku) != 2 {
			t.Fatalf("expected 2 ext key usages, got %d", len(eku))
		}
		if eku[0] != x509.ExtKeyUsageClientAuth {
			t.Errorf("expected ExtKeyUsageClientAuth at index 0, got %d", eku[0])
		}
		if eku[1] != x509.ExtKeyUsageServerAuth {
			t.Errorf("expected ExtKeyUsageServerAuth at index 1, got %d", eku[1])
		}
	})

	t.Run("validity_is_indefinite", func(t *testing.T) {
		profile := NewTCGIDevIDProfile()
		if profile.DefaultValidity() != tcgIndefiniteValidityDays {
			t.Errorf("expected validity %d, got %d",
				tcgIndefiniteValidityDays, profile.DefaultValidity())
		}
	})

	t.Run("is_not_ca", func(t *testing.T) {
		profile := NewTCGIDevIDProfile()
		if profile.IsCA() {
			t.Error("IDevID profile should not be a CA")
		}
	})
}

// =============================================================================
// Apply Tests
// =============================================================================

func TestTCGEKProfile_Apply(t *testing.T) {
	t.Run("sets_correct_fields_on_template", func(t *testing.T) {
		profile := NewTCGEKProfile()
		template := &x509.Certificate{}

		err := profile.Apply(template)
		if err != nil {
			t.Fatalf("Apply returned unexpected error: %v", err)
		}

		if template.KeyUsage != x509.KeyUsageKeyEncipherment {
			t.Errorf("expected KeyUsageKeyEncipherment, got %d", template.KeyUsage)
		}

		if len(template.ExtKeyUsage) != 2 {
			t.Fatalf("expected 2 ext key usages, got %d", len(template.ExtKeyUsage))
		}
		if template.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
			t.Errorf("expected ExtKeyUsageClientAuth at index 0, got %d", template.ExtKeyUsage[0])
		}
		if template.ExtKeyUsage[1] != x509.ExtKeyUsageServerAuth {
			t.Errorf("expected ExtKeyUsageServerAuth at index 1, got %d", template.ExtKeyUsage[1])
		}

		if template.IsCA {
			t.Error("template should not be marked as CA")
		}
		if template.BasicConstraintsValid {
			t.Error("template should not have BasicConstraintsValid set")
		}
	})

	t.Run("returns_error_for_nil_template", func(t *testing.T) {
		profile := NewTCGEKProfile()

		err := profile.Apply(nil)
		if err == nil {
			t.Fatal("expected error for nil template")
		}
		if !errors.Is(err, ErrInvalidProfile) {
			t.Errorf("expected ErrInvalidProfile, got %v", err)
		}
	})

	t.Run("does_not_overwrite_existing_extra_extensions", func(t *testing.T) {
		profile := NewTCGEKProfile()
		template := &x509.Certificate{
			ExtraExtensions: make([]pkix.Extension, 1),
		}

		err := profile.Apply(template)
		if err != nil {
			t.Fatalf("Apply returned unexpected error: %v", err)
		}

		// EK profile has no custom extensions, so existing should be preserved
		if len(template.ExtraExtensions) != 1 {
			t.Errorf("expected 1 extra extension preserved, got %d", len(template.ExtraExtensions))
		}
	})
}

func TestTCGAKProfile_Apply(t *testing.T) {
	t.Run("sets_correct_fields_on_template", func(t *testing.T) {
		profile := NewTCGAKProfile()
		template := &x509.Certificate{}

		err := profile.Apply(template)
		if err != nil {
			t.Fatalf("Apply returned unexpected error: %v", err)
		}

		if template.KeyUsage != x509.KeyUsageDigitalSignature {
			t.Errorf("expected KeyUsageDigitalSignature, got %d", template.KeyUsage)
		}

		if len(template.ExtKeyUsage) != 2 {
			t.Fatalf("expected 2 ext key usages, got %d", len(template.ExtKeyUsage))
		}
		if template.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
			t.Errorf("expected ExtKeyUsageClientAuth at index 0, got %d", template.ExtKeyUsage[0])
		}
		if template.ExtKeyUsage[1] != x509.ExtKeyUsageServerAuth {
			t.Errorf("expected ExtKeyUsageServerAuth at index 1, got %d", template.ExtKeyUsage[1])
		}

		if template.IsCA {
			t.Error("template should not be marked as CA")
		}
		if template.BasicConstraintsValid {
			t.Error("template should not have BasicConstraintsValid set")
		}
	})

	t.Run("returns_error_for_nil_template", func(t *testing.T) {
		profile := NewTCGAKProfile()

		err := profile.Apply(nil)
		if err == nil {
			t.Fatal("expected error for nil template")
		}
		if !errors.Is(err, ErrInvalidProfile) {
			t.Errorf("expected ErrInvalidProfile, got %v", err)
		}
	})
}

func TestTCGIDevIDProfile_Apply(t *testing.T) {
	t.Run("sets_correct_fields_on_template", func(t *testing.T) {
		profile := NewTCGIDevIDProfile()
		template := &x509.Certificate{}

		err := profile.Apply(template)
		if err != nil {
			t.Fatalf("Apply returned unexpected error: %v", err)
		}

		expectedUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		if template.KeyUsage != expectedUsage {
			t.Errorf("expected KeyUsage %d (DigitalSignature|KeyEncipherment), got %d",
				expectedUsage, template.KeyUsage)
		}

		if len(template.ExtKeyUsage) != 2 {
			t.Fatalf("expected 2 ext key usages, got %d", len(template.ExtKeyUsage))
		}
		if template.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
			t.Errorf("expected ExtKeyUsageClientAuth at index 0, got %d", template.ExtKeyUsage[0])
		}
		if template.ExtKeyUsage[1] != x509.ExtKeyUsageServerAuth {
			t.Errorf("expected ExtKeyUsageServerAuth at index 1, got %d", template.ExtKeyUsage[1])
		}

		if template.IsCA {
			t.Error("template should not be marked as CA")
		}
		if template.BasicConstraintsValid {
			t.Error("template should not have BasicConstraintsValid set")
		}
	})

	t.Run("returns_error_for_nil_template", func(t *testing.T) {
		profile := NewTCGIDevIDProfile()

		err := profile.Apply(nil)
		if err == nil {
			t.Fatal("expected error for nil template")
		}
		if !errors.Is(err, ErrInvalidProfile) {
			t.Errorf("expected ErrInvalidProfile, got %v", err)
		}
	})

	t.Run("preserves_existing_template_fields", func(t *testing.T) {
		profile := NewTCGIDevIDProfile()
		template := &x509.Certificate{
			DNSNames:    []string{"device.example.com"},
			IPAddresses: nil,
		}

		err := profile.Apply(template)
		if err != nil {
			t.Fatalf("Apply returned unexpected error: %v", err)
		}

		// Apply should only set KeyUsage, ExtKeyUsage, and CA fields.
		// It should not touch other fields like DNSNames.
		if len(template.DNSNames) != 1 || template.DNSNames[0] != "device.example.com" {
			t.Errorf("Apply should not modify DNSNames, got %v", template.DNSNames)
		}
	})
}

// =============================================================================
// RegisterTCGProfiles Tests
// =============================================================================

func TestRegisterTCGProfiles(t *testing.T) {
	t.Run("registers_all_three_profiles", func(t *testing.T) {
		registry := NewRegistry()

		err := RegisterTCGProfiles(registry)
		if err != nil {
			t.Fatalf("RegisterTCGProfiles returned unexpected error: %v", err)
		}

		if registry.Count() != 3 {
			t.Errorf("expected 3 profiles, got %d", registry.Count())
		}
	})

	t.Run("ek_profile_is_registered_and_retrievable", func(t *testing.T) {
		registry := NewRegistry()
		err := RegisterTCGProfiles(registry)
		if err != nil {
			t.Fatalf("RegisterTCGProfiles returned unexpected error: %v", err)
		}

		if !registry.Has(TCGEKProfileName) {
			t.Errorf("registry should have profile %q", TCGEKProfileName)
		}

		profile, err := registry.Get(TCGEKProfileName)
		if err != nil {
			t.Fatalf("Get(%q) returned unexpected error: %v", TCGEKProfileName, err)
		}
		if profile.Name() != TCGEKProfileName {
			t.Errorf("expected profile name %q, got %q", TCGEKProfileName, profile.Name())
		}
	})

	t.Run("ak_profile_is_registered_and_retrievable", func(t *testing.T) {
		registry := NewRegistry()
		err := RegisterTCGProfiles(registry)
		if err != nil {
			t.Fatalf("RegisterTCGProfiles returned unexpected error: %v", err)
		}

		if !registry.Has(TCGAKProfileName) {
			t.Errorf("registry should have profile %q", TCGAKProfileName)
		}

		profile, err := registry.Get(TCGAKProfileName)
		if err != nil {
			t.Fatalf("Get(%q) returned unexpected error: %v", TCGAKProfileName, err)
		}
		if profile.Name() != TCGAKProfileName {
			t.Errorf("expected profile name %q, got %q", TCGAKProfileName, profile.Name())
		}
	})

	t.Run("idevid_profile_is_registered_and_retrievable", func(t *testing.T) {
		registry := NewRegistry()
		err := RegisterTCGProfiles(registry)
		if err != nil {
			t.Fatalf("RegisterTCGProfiles returned unexpected error: %v", err)
		}

		if !registry.Has(TCGIDevIDProfileName) {
			t.Errorf("registry should have profile %q", TCGIDevIDProfileName)
		}

		profile, err := registry.Get(TCGIDevIDProfileName)
		if err != nil {
			t.Fatalf("Get(%q) returned unexpected error: %v", TCGIDevIDProfileName, err)
		}
		if profile.Name() != TCGIDevIDProfileName {
			t.Errorf("expected profile name %q, got %q", TCGIDevIDProfileName, profile.Name())
		}
	})

	t.Run("duplicate_registration_returns_error", func(t *testing.T) {
		registry := NewRegistry()

		err := RegisterTCGProfiles(registry)
		if err != nil {
			t.Fatalf("first RegisterTCGProfiles returned unexpected error: %v", err)
		}

		err = RegisterTCGProfiles(registry)
		if err == nil {
			t.Fatal("expected error on duplicate registration")
		}
		if !errors.Is(err, ErrProfileExists) {
			t.Errorf("expected ErrProfileExists, got %v", err)
		}
	})

	t.Run("duplicate_registration_preserves_original_count", func(t *testing.T) {
		registry := NewRegistry()

		err := RegisterTCGProfiles(registry)
		if err != nil {
			t.Fatalf("first RegisterTCGProfiles returned unexpected error: %v", err)
		}

		// Second registration should fail but not corrupt the registry
		_ = RegisterTCGProfiles(registry)

		if registry.Count() != 3 {
			t.Errorf("expected 3 profiles after failed duplicate registration, got %d",
				registry.Count())
		}
	})

	t.Run("registered_profiles_have_correct_key_usage", func(t *testing.T) {
		registry := NewRegistry()
		err := RegisterTCGProfiles(registry)
		if err != nil {
			t.Fatalf("RegisterTCGProfiles returned unexpected error: %v", err)
		}

		tests := []struct {
			name     string
			expected x509.KeyUsage
		}{
			{TCGEKProfileName, x509.KeyUsageKeyEncipherment},
			{TCGAKProfileName, x509.KeyUsageDigitalSignature},
			{TCGIDevIDProfileName, x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				profile, err := registry.Get(tc.name)
				if err != nil {
					t.Fatalf("Get(%q) returned unexpected error: %v", tc.name, err)
				}
				if profile.KeyUsage() != tc.expected {
					t.Errorf("expected key usage %d, got %d", tc.expected, profile.KeyUsage())
				}
			})
		}
	})
}

// =============================================================================
// AllTCGProfiles Tests
// =============================================================================

func TestAllTCGProfiles(t *testing.T) {
	t.Run("returns_exactly_three_profiles", func(t *testing.T) {
		all := AllTCGProfiles()
		if len(all) != 3 {
			t.Fatalf("expected 3 profiles, got %d", len(all))
		}
	})

	t.Run("contains_correct_profile_names", func(t *testing.T) {
		all := AllTCGProfiles()

		expectedNames := map[string]bool{
			TCGEKProfileName:     false,
			TCGAKProfileName:     false,
			TCGIDevIDProfileName: false,
		}

		for _, p := range all {
			if _, ok := expectedNames[p.Name()]; !ok {
				t.Errorf("unexpected profile name %q", p.Name())
			}
			expectedNames[p.Name()] = true
		}

		for name, found := range expectedNames {
			if !found {
				t.Errorf("expected profile %q not found in AllTCGProfiles", name)
			}
		}
	})

	t.Run("profiles_are_in_expected_order", func(t *testing.T) {
		all := AllTCGProfiles()
		if all[0].Name() != TCGEKProfileName {
			t.Errorf("expected first profile to be %q, got %q", TCGEKProfileName, all[0].Name())
		}
		if all[1].Name() != TCGAKProfileName {
			t.Errorf("expected second profile to be %q, got %q", TCGAKProfileName, all[1].Name())
		}
		if all[2].Name() != TCGIDevIDProfileName {
			t.Errorf("expected third profile to be %q, got %q", TCGIDevIDProfileName, all[2].Name())
		}
	})

	t.Run("none_are_ca_profiles", func(t *testing.T) {
		all := AllTCGProfiles()
		for _, p := range all {
			if p.IsCA() {
				t.Errorf("profile %q should not be a CA", p.Name())
			}
		}
	})

	t.Run("all_have_indefinite_validity", func(t *testing.T) {
		all := AllTCGProfiles()
		for _, p := range all {
			if p.DefaultValidity() != tcgIndefiniteValidityDays {
				t.Errorf("profile %q: expected validity %d, got %d",
					p.Name(), tcgIndefiniteValidityDays, p.DefaultValidity())
			}
		}
	})

	t.Run("all_have_descriptions", func(t *testing.T) {
		all := AllTCGProfiles()
		for _, p := range all {
			if p.Description() == "" {
				t.Errorf("profile %q has empty description", p.Name())
			}
		}
	})

	t.Run("returns_independent_slices", func(t *testing.T) {
		first := AllTCGProfiles()
		second := AllTCGProfiles()

		// Mutating the first slice should not affect the second
		first[0] = nil
		if second[0] == nil {
			t.Error("AllTCGProfiles should return independent slices")
		}
	})
}

// =============================================================================
// TCG Profile Constants Tests
// =============================================================================

func TestTCGProfileConstants(t *testing.T) {
	t.Run("ek_profile_name_value", func(t *testing.T) {
		if TCGEKProfileName != "tcg-ek" {
			t.Errorf("expected TCGEKProfileName to be %q, got %q", "tcg-ek", TCGEKProfileName)
		}
	})

	t.Run("ak_profile_name_value", func(t *testing.T) {
		if TCGAKProfileName != "tcg-ak" {
			t.Errorf("expected TCGAKProfileName to be %q, got %q", "tcg-ak", TCGAKProfileName)
		}
	})

	t.Run("idevid_profile_name_value", func(t *testing.T) {
		if TCGIDevIDProfileName != "tcg-idevid" {
			t.Errorf("expected TCGIDevIDProfileName to be %q, got %q", "tcg-idevid", TCGIDevIDProfileName)
		}
	})

	t.Run("indefinite_validity_is_100_years", func(t *testing.T) {
		if tcgIndefiniteValidityDays != 36500 {
			t.Errorf("expected tcgIndefiniteValidityDays to be 36500, got %d",
				tcgIndefiniteValidityDays)
		}
	})
}

// =============================================================================
// TCG Profile Differentiation Tests
// =============================================================================

func TestTCGProfiles_KeyUsageDifferences(t *testing.T) {
	t.Run("ek_has_only_key_encipherment", func(t *testing.T) {
		profile := NewTCGEKProfile()
		if profile.KeyUsage()&x509.KeyUsageDigitalSignature != 0 {
			t.Error("EK profile should not have DigitalSignature")
		}
		if profile.KeyUsage()&x509.KeyUsageKeyEncipherment == 0 {
			t.Error("EK profile should have KeyEncipherment")
		}
	})

	t.Run("ak_has_only_digital_signature", func(t *testing.T) {
		profile := NewTCGAKProfile()
		if profile.KeyUsage()&x509.KeyUsageDigitalSignature == 0 {
			t.Error("AK profile should have DigitalSignature")
		}
		if profile.KeyUsage()&x509.KeyUsageKeyEncipherment != 0 {
			t.Error("AK profile should not have KeyEncipherment")
		}
	})

	t.Run("idevid_has_both_digital_signature_and_key_encipherment", func(t *testing.T) {
		profile := NewTCGIDevIDProfile()
		if profile.KeyUsage()&x509.KeyUsageDigitalSignature == 0 {
			t.Error("IDevID profile should have DigitalSignature")
		}
		if profile.KeyUsage()&x509.KeyUsageKeyEncipherment == 0 {
			t.Error("IDevID profile should have KeyEncipherment")
		}
	})
}

// =============================================================================
// TCG Profile Apply Table-Driven Tests
// =============================================================================

func TestTCGProfiles_Apply_TableDriven(t *testing.T) {
	tests := []struct {
		name             string
		profile          *BaseProfile
		expectedKeyUsage x509.KeyUsage
		expectedEKULen   int
	}{
		{
			name:             "ek_profile_apply",
			profile:          NewTCGEKProfile(),
			expectedKeyUsage: x509.KeyUsageKeyEncipherment,
			expectedEKULen:   2,
		},
		{
			name:             "ak_profile_apply",
			profile:          NewTCGAKProfile(),
			expectedKeyUsage: x509.KeyUsageDigitalSignature,
			expectedEKULen:   2,
		},
		{
			name:             "idevid_profile_apply",
			profile:          NewTCGIDevIDProfile(),
			expectedKeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			expectedEKULen:   2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			template := &x509.Certificate{}
			err := tc.profile.Apply(template)
			if err != nil {
				t.Fatalf("Apply returned unexpected error: %v", err)
			}

			if template.KeyUsage != tc.expectedKeyUsage {
				t.Errorf("expected key usage %d, got %d",
					tc.expectedKeyUsage, template.KeyUsage)
			}

			if len(template.ExtKeyUsage) != tc.expectedEKULen {
				t.Errorf("expected %d ext key usages, got %d",
					tc.expectedEKULen, len(template.ExtKeyUsage))
			}

			if template.IsCA {
				t.Error("template should not be CA after Apply")
			}

			if template.BasicConstraintsValid {
				t.Error("template should not have BasicConstraintsValid after Apply")
			}
		})
	}
}

func TestTCGProfiles_Apply_NilTemplate_TableDriven(t *testing.T) {
	tcgProfiles := []struct {
		name    string
		profile *BaseProfile
	}{
		{"ek", NewTCGEKProfile()},
		{"ak", NewTCGAKProfile()},
		{"idevid", NewTCGIDevIDProfile()},
	}

	for _, tc := range tcgProfiles {
		t.Run(tc.name+"_nil_template", func(t *testing.T) {
			err := tc.profile.Apply(nil)
			if err == nil {
				t.Fatal("expected error for nil template")
			}
			if !errors.Is(err, ErrInvalidProfile) {
				t.Errorf("expected ErrInvalidProfile, got %v", err)
			}
		})
	}
}
