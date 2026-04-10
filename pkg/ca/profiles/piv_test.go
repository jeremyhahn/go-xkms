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
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

// =============================================================================
// PIV Authentication Profile Tests
// =============================================================================

func TestNewPIVAuthenticationProfile(t *testing.T) {
	t.Run("creates_valid_profile", func(t *testing.T) {
		p := NewPIVAuthenticationProfile()

		if p == nil {
			t.Fatal("NewPIVAuthenticationProfile returned nil")
		}

		if p.Name() != ProfileNamePIVAuthentication {
			t.Errorf("Name() = %q, want %q", p.Name(), ProfileNamePIVAuthentication)
		}

		if p.Slot() != SlotAuthentication {
			t.Errorf("Slot() = %q, want %q", p.Slot(), SlotAuthentication)
		}

		if p.Description() == "" {
			t.Error("Description() should not be empty")
		}

		if p.DefaultValidity() != DefaultPIVValidityDays {
			t.Errorf("DefaultValidity() = %d, want %d", p.DefaultValidity(), DefaultPIVValidityDays)
		}
	})

	t.Run("has_correct_key_usage", func(t *testing.T) {
		p := NewPIVAuthenticationProfile()

		if p.KeyUsage() != x509.KeyUsageDigitalSignature {
			t.Errorf("KeyUsage() = %d, want %d", p.KeyUsage(), x509.KeyUsageDigitalSignature)
		}
	})

	t.Run("has_correct_ext_key_usage", func(t *testing.T) {
		p := NewPIVAuthenticationProfile()

		eku := p.ExtKeyUsage()
		if len(eku) != 1 || eku[0] != x509.ExtKeyUsageClientAuth {
			t.Errorf("ExtKeyUsage() = %v, want [ClientAuth]", eku)
		}
	})
}

func TestPIVAuthenticationProfile_Apply(t *testing.T) {
	t.Run("applies_profile_settings", func(t *testing.T) {
		p := NewPIVAuthenticationProfile()
		template := &x509.Certificate{}

		err := p.Apply(template, nil)
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}

		if template.KeyUsage != x509.KeyUsageDigitalSignature {
			t.Errorf("KeyUsage = %d, want %d", template.KeyUsage, x509.KeyUsageDigitalSignature)
		}

		if len(template.ExtKeyUsage) != 1 || template.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
			t.Errorf("ExtKeyUsage = %v, want [ClientAuth]", template.ExtKeyUsage)
		}

		// Should have OIDSmartCardLogon in UnknownExtKeyUsage
		if len(template.UnknownExtKeyUsage) != 1 {
			t.Errorf("UnknownExtKeyUsage length = %d, want 1", len(template.UnknownExtKeyUsage))
		} else if !template.UnknownExtKeyUsage[0].Equal(OIDSmartCardLogon) {
			t.Error("UnknownExtKeyUsage should contain OIDSmartCardLogon")
		}

		if template.IsCA {
			t.Error("IsCA should be false")
		}

		if !template.BasicConstraintsValid {
			t.Error("BasicConstraintsValid should be true")
		}
	})

	t.Run("nil_template_returns_error", func(t *testing.T) {
		p := NewPIVAuthenticationProfile()
		err := p.Apply(nil, nil)
		if err != ca.ErrInvalidProfile {
			t.Errorf("Apply(nil) = %v, want ErrInvalidProfile", err)
		}
	})
}

// =============================================================================
// PIV Signature Profile Tests
// =============================================================================

func TestNewPIVSignatureProfile(t *testing.T) {
	t.Run("creates_valid_profile", func(t *testing.T) {
		p := NewPIVSignatureProfile()

		if p == nil {
			t.Fatal("NewPIVSignatureProfile returned nil")
		}

		if p.Name() != ProfileNamePIVSignature {
			t.Errorf("Name() = %q, want %q", p.Name(), ProfileNamePIVSignature)
		}

		if p.Slot() != SlotSignature {
			t.Errorf("Slot() = %q, want %q", p.Slot(), SlotSignature)
		}
	})

	t.Run("has_correct_key_usage", func(t *testing.T) {
		p := NewPIVSignatureProfile()

		expectedKU := x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
		if p.KeyUsage() != expectedKU {
			t.Errorf("KeyUsage() = %d, want %d", p.KeyUsage(), expectedKU)
		}
	})

	t.Run("has_correct_ext_key_usage", func(t *testing.T) {
		p := NewPIVSignatureProfile()

		eku := p.ExtKeyUsage()
		if len(eku) != 1 || eku[0] != x509.ExtKeyUsageEmailProtection {
			t.Errorf("ExtKeyUsage() = %v, want [EmailProtection]", eku)
		}
	})
}

func TestPIVSignatureProfile_Apply(t *testing.T) {
	t.Run("applies_profile_settings", func(t *testing.T) {
		p := NewPIVSignatureProfile()
		template := &x509.Certificate{}

		err := p.Apply(template, nil)
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}

		expectedKU := x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
		if template.KeyUsage != expectedKU {
			t.Errorf("KeyUsage = %d, want %d", template.KeyUsage, expectedKU)
		}

		// Should have OIDDocumentSigning in UnknownExtKeyUsage
		if len(template.UnknownExtKeyUsage) != 1 {
			t.Errorf("UnknownExtKeyUsage length = %d, want 1", len(template.UnknownExtKeyUsage))
		} else if !template.UnknownExtKeyUsage[0].Equal(OIDDocumentSigning) {
			t.Error("UnknownExtKeyUsage should contain OIDDocumentSigning")
		}

		if template.IsCA {
			t.Error("IsCA should be false")
		}
	})

	t.Run("nil_template_returns_error", func(t *testing.T) {
		p := NewPIVSignatureProfile()
		err := p.Apply(nil, nil)
		if err != ca.ErrInvalidProfile {
			t.Errorf("Apply(nil) = %v, want ErrInvalidProfile", err)
		}
	})
}

// =============================================================================
// PIV Key Management Profile Tests
// =============================================================================

func TestNewPIVKeyManagementProfile(t *testing.T) {
	t.Run("creates_valid_profile", func(t *testing.T) {
		p := NewPIVKeyManagementProfile()

		if p == nil {
			t.Fatal("NewPIVKeyManagementProfile returned nil")
		}

		if p.Name() != ProfileNamePIVKeyManagement {
			t.Errorf("Name() = %q, want %q", p.Name(), ProfileNamePIVKeyManagement)
		}

		if p.Slot() != SlotKeyManagement {
			t.Errorf("Slot() = %q, want %q", p.Slot(), SlotKeyManagement)
		}
	})

	t.Run("has_correct_key_usage", func(t *testing.T) {
		p := NewPIVKeyManagementProfile()

		expectedKU := x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageDataEncipherment
		if p.KeyUsage() != expectedKU {
			t.Errorf("KeyUsage() = %d, want %d", p.KeyUsage(), expectedKU)
		}
	})

	t.Run("has_correct_ext_key_usage", func(t *testing.T) {
		p := NewPIVKeyManagementProfile()

		eku := p.ExtKeyUsage()
		if len(eku) != 1 || eku[0] != x509.ExtKeyUsageEmailProtection {
			t.Errorf("ExtKeyUsage() = %v, want [EmailProtection]", eku)
		}
	})
}

func TestPIVKeyManagementProfile_Apply(t *testing.T) {
	t.Run("applies_profile_settings", func(t *testing.T) {
		p := NewPIVKeyManagementProfile()
		template := &x509.Certificate{}

		err := p.Apply(template, nil)
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}

		expectedKU := x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageDataEncipherment
		if template.KeyUsage != expectedKU {
			t.Errorf("KeyUsage = %d, want %d", template.KeyUsage, expectedKU)
		}

		// No custom OIDs for key management
		if len(template.UnknownExtKeyUsage) != 0 {
			t.Errorf("UnknownExtKeyUsage length = %d, want 0", len(template.UnknownExtKeyUsage))
		}

		if template.IsCA {
			t.Error("IsCA should be false")
		}
	})

	t.Run("nil_template_returns_error", func(t *testing.T) {
		p := NewPIVKeyManagementProfile()
		err := p.Apply(nil, nil)
		if err != ca.ErrInvalidProfile {
			t.Errorf("Apply(nil) = %v, want ErrInvalidProfile", err)
		}
	})
}

// =============================================================================
// PIV Card Authentication Profile Tests
// =============================================================================

func TestNewPIVCardAuthProfile(t *testing.T) {
	t.Run("creates_valid_profile", func(t *testing.T) {
		p := NewPIVCardAuthProfile()

		if p == nil {
			t.Fatal("NewPIVCardAuthProfile returned nil")
		}

		if p.Name() != ProfileNamePIVCardAuth {
			t.Errorf("Name() = %q, want %q", p.Name(), ProfileNamePIVCardAuth)
		}

		if p.Slot() != SlotCardAuth {
			t.Errorf("Slot() = %q, want %q", p.Slot(), SlotCardAuth)
		}

		// Card Auth has longer validity to match card expiry
		if p.DefaultValidity() != DefaultPIVCardAuthValidityDays {
			t.Errorf("DefaultValidity() = %d, want %d", p.DefaultValidity(), DefaultPIVCardAuthValidityDays)
		}
	})

	t.Run("has_correct_key_usage", func(t *testing.T) {
		p := NewPIVCardAuthProfile()

		if p.KeyUsage() != x509.KeyUsageDigitalSignature {
			t.Errorf("KeyUsage() = %d, want %d", p.KeyUsage(), x509.KeyUsageDigitalSignature)
		}
	})

	t.Run("has_correct_ext_key_usage", func(t *testing.T) {
		p := NewPIVCardAuthProfile()

		eku := p.ExtKeyUsage()
		if len(eku) != 1 || eku[0] != x509.ExtKeyUsageClientAuth {
			t.Errorf("ExtKeyUsage() = %v, want [ClientAuth]", eku)
		}
	})
}

func TestPIVCardAuthProfile_Apply(t *testing.T) {
	t.Run("applies_profile_settings", func(t *testing.T) {
		p := NewPIVCardAuthProfile()
		template := &x509.Certificate{}

		err := p.Apply(template, nil)
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}

		// Should have OIDSmartCardLogon and OIDPIVCardAuthentication
		if len(template.UnknownExtKeyUsage) != 2 {
			t.Errorf("UnknownExtKeyUsage length = %d, want 2", len(template.UnknownExtKeyUsage))
		}

		hasSmartCardLogon := false
		hasCardAuth := false
		for _, oid := range template.UnknownExtKeyUsage {
			if oid.Equal(OIDSmartCardLogon) {
				hasSmartCardLogon = true
			}
			if oid.Equal(OIDPIVCardAuthentication) {
				hasCardAuth = true
			}
		}
		if !hasSmartCardLogon {
			t.Error("UnknownExtKeyUsage should contain OIDSmartCardLogon")
		}
		if !hasCardAuth {
			t.Error("UnknownExtKeyUsage should contain OIDPIVCardAuthentication")
		}

		if template.IsCA {
			t.Error("IsCA should be false")
		}
	})

	t.Run("nil_template_returns_error", func(t *testing.T) {
		p := NewPIVCardAuthProfile()
		err := p.Apply(nil, nil)
		if err != ca.ErrInvalidProfile {
			t.Errorf("Apply(nil) = %v, want ErrInvalidProfile", err)
		}
	})
}

// =============================================================================
// PIVProfileForSlot Tests
// =============================================================================

func TestPIVProfileForSlot(t *testing.T) {
	tests := []struct {
		name         string
		slot         string
		expectErr    bool
		expectedName string
	}{
		{
			name:         "authentication_slot",
			slot:         SlotAuthentication,
			expectErr:    false,
			expectedName: ProfileNamePIVAuthentication,
		},
		{
			name:         "signature_slot",
			slot:         SlotSignature,
			expectErr:    false,
			expectedName: ProfileNamePIVSignature,
		},
		{
			name:         "key_management_slot",
			slot:         SlotKeyManagement,
			expectErr:    false,
			expectedName: ProfileNamePIVKeyManagement,
		},
		{
			name:         "card_auth_slot",
			slot:         SlotCardAuth,
			expectErr:    false,
			expectedName: ProfileNamePIVCardAuth,
		},
		{
			name:      "invalid_slot",
			slot:      "invalid",
			expectErr: true,
		},
		{
			name:      "empty_slot",
			slot:      "",
			expectErr: true,
		},
		{
			name:      "uppercase_slot",
			slot:      "9A", // Should fail as slots are lowercase
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			profile, err := PIVProfileForSlot(tc.slot)

			if tc.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				if err != ca.ErrInvalidProfile {
					t.Errorf("expected ErrInvalidProfile, got %v", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if profile.Name() != tc.expectedName {
				t.Errorf("Name() = %q, want %q", profile.Name(), tc.expectedName)
			}
		})
	}
}

// =============================================================================
// RegisterPIVProfiles Tests
// =============================================================================

func TestRegisterPIVProfiles(t *testing.T) {
	t.Run("registers_all_profiles", func(t *testing.T) {
		registry := ca.NewDefaultProfileRegistry()

		err := RegisterPIVProfiles(registry)
		if err != nil {
			t.Fatalf("RegisterPIVProfiles failed: %v", err)
		}

		// Verify all profiles are registered
		expectedProfiles := []string{
			ProfileNamePIVAuthentication,
			ProfileNamePIVSignature,
			ProfileNamePIVKeyManagement,
			ProfileNamePIVCardAuth,
		}

		for _, name := range expectedProfiles {
			p, err := registry.Get(name)
			if err != nil {
				t.Errorf("profile %q not found: %v", name, err)
				continue
			}
			if p == nil {
				t.Errorf("profile %q is nil", name)
			}
		}
	})

	t.Run("allows_duplicate_registration", func(t *testing.T) {
		// The ca.ProfileRegistry interface replaces existing profiles
		// rather than returning an error on duplicates
		registry := ca.NewDefaultProfileRegistry()

		// First registration should succeed
		err := RegisterPIVProfiles(registry)
		if err != nil {
			t.Fatalf("first RegisterPIVProfiles failed: %v", err)
		}

		// Second registration should also succeed (replaces existing)
		err = RegisterPIVProfiles(registry)
		if err != nil {
			t.Errorf("second RegisterPIVProfiles failed unexpectedly: %v", err)
		}

		// Verify profiles still exist
		for _, slot := range PIVSlots() {
			profile, err := PIVProfileForSlot(slot)
			if err != nil {
				t.Errorf("slot %q profile should exist: %v", slot, err)
				continue
			}
			_, err = registry.Get(profile.Name())
			if err != nil {
				t.Errorf("profile %q should exist after re-registration: %v", profile.Name(), err)
			}
		}
	})
}

// =============================================================================
// AllPIVProfiles Tests
// =============================================================================

func TestAllPIVProfiles(t *testing.T) {
	t.Run("returns_all_profiles", func(t *testing.T) {
		profiles := AllPIVProfiles()

		if len(profiles) != 4 {
			t.Errorf("AllPIVProfiles() length = %d, want 4", len(profiles))
		}

		// Verify each profile type is present
		names := make(map[string]bool)
		for _, p := range profiles {
			names[p.Name()] = true
		}

		expectedNames := []string{
			ProfileNamePIVAuthentication,
			ProfileNamePIVSignature,
			ProfileNamePIVKeyManagement,
			ProfileNamePIVCardAuth,
		}

		for _, name := range expectedNames {
			if !names[name] {
				t.Errorf("profile %q not found in AllPIVProfiles()", name)
			}
		}
	})
}

// =============================================================================
// PIVSlots Tests
// =============================================================================

func TestPIVSlots(t *testing.T) {
	t.Run("returns_all_slots", func(t *testing.T) {
		slots := PIVSlots()

		if len(slots) != 4 {
			t.Errorf("PIVSlots() length = %d, want 4", len(slots))
		}

		expected := map[string]bool{
			SlotAuthentication: false,
			SlotSignature:      false,
			SlotKeyManagement:  false,
			SlotCardAuth:       false,
		}

		for _, slot := range slots {
			if _, ok := expected[slot]; !ok {
				t.Errorf("unexpected slot: %q", slot)
			}
			expected[slot] = true
		}

		for slot, found := range expected {
			if !found {
				t.Errorf("slot %q not found in PIVSlots()", slot)
			}
		}
	})
}

// =============================================================================
// IsPIVSlot Tests
// =============================================================================

func TestIsPIVSlot(t *testing.T) {
	tests := []struct {
		slot   string
		expect bool
	}{
		{slot: SlotAuthentication, expect: true},
		{slot: SlotSignature, expect: true},
		{slot: SlotKeyManagement, expect: true},
		{slot: SlotCardAuth, expect: true},
		{slot: "9a", expect: true},
		{slot: "9c", expect: true},
		{slot: "9d", expect: true},
		{slot: "9e", expect: true},
		{slot: "9A", expect: false}, // Case-sensitive
		{slot: "invalid", expect: false},
		{slot: "", expect: false},
		{slot: "9f", expect: false},
	}

	for _, tc := range tests {
		t.Run(tc.slot, func(t *testing.T) {
			if got := IsPIVSlot(tc.slot); got != tc.expect {
				t.Errorf("IsPIVSlot(%q) = %v, want %v", tc.slot, got, tc.expect)
			}
		})
	}
}

// =============================================================================
// PIVSlotName Tests
// =============================================================================

func TestPIVSlotName(t *testing.T) {
	tests := []struct {
		slot   string
		expect string
	}{
		{slot: SlotAuthentication, expect: "PIV Authentication"},
		{slot: SlotSignature, expect: "Digital Signature"},
		{slot: SlotKeyManagement, expect: "Key Management"},
		{slot: SlotCardAuth, expect: "Card Authentication"},
		{slot: "invalid", expect: ""},
		{slot: "", expect: ""},
	}

	for _, tc := range tests {
		t.Run(tc.slot, func(t *testing.T) {
			if got := PIVSlotName(tc.slot); got != tc.expect {
				t.Errorf("PIVSlotName(%q) = %q, want %q", tc.slot, got, tc.expect)
			}
		})
	}
}

// =============================================================================
// PIV Extension Helper Tests
// =============================================================================

func TestNewPIVAuthenticationExtension(t *testing.T) {
	t.Run("creates_valid_extension", func(t *testing.T) {
		ext, err := NewPIVAuthenticationExtension()
		if err != nil {
			t.Fatalf("NewPIVAuthenticationExtension failed: %v", err)
		}

		if ext == nil {
			t.Fatal("extension is nil")
		}

		if !ext.Id.Equal(OIDFPKICommonPolicy) {
			t.Errorf("extension OID = %v, want %v", ext.Id, OIDFPKICommonPolicy)
		}

		if ext.Critical {
			t.Error("extension should not be critical")
		}

		if len(ext.Value) == 0 {
			t.Error("extension value should not be empty")
		}
	})
}

// =============================================================================
// PIVProfile Interface Compliance Tests
// =============================================================================

func TestPIVProfiles_ImplementPIVProfile(t *testing.T) {
	// Verify all PIV profiles implement the PIVProfile interface
	var _ PIVProfile = (*PIVAuthenticationProfile)(nil)
	var _ PIVProfile = (*PIVSignatureProfile)(nil)
	var _ PIVProfile = (*PIVKeyManagementProfile)(nil)
	var _ PIVProfile = (*PIVCardAuthProfile)(nil)
}

// =============================================================================
// Slot Constants Tests
// =============================================================================

func TestSlotConstants(t *testing.T) {
	// Verify slot constant values match NIST SP 800-73-4
	tests := []struct {
		constant string
		value    string
	}{
		{constant: "SlotAuthentication", value: "9a"},
		{constant: "SlotSignature", value: "9c"},
		{constant: "SlotKeyManagement", value: "9d"},
		{constant: "SlotCardAuth", value: "9e"},
	}

	actuals := map[string]string{
		"SlotAuthentication": SlotAuthentication,
		"SlotSignature":      SlotSignature,
		"SlotKeyManagement":  SlotKeyManagement,
		"SlotCardAuth":       SlotCardAuth,
	}

	for _, tc := range tests {
		t.Run(tc.constant, func(t *testing.T) {
			if actuals[tc.constant] != tc.value {
				t.Errorf("%s = %q, want %q", tc.constant, actuals[tc.constant], tc.value)
			}
		})
	}
}

// =============================================================================
// Validity Period Tests
// =============================================================================

func TestPIVValidityPeriods(t *testing.T) {
	t.Run("default_piv_validity_is_3_years", func(t *testing.T) {
		if DefaultPIVValidityDays != 1095 {
			t.Errorf("DefaultPIVValidityDays = %d, want 1095 (3 years)", DefaultPIVValidityDays)
		}
	})

	t.Run("card_auth_validity_is_5_years", func(t *testing.T) {
		if DefaultPIVCardAuthValidityDays != 1825 {
			t.Errorf("DefaultPIVCardAuthValidityDays = %d, want 1825 (5 years)", DefaultPIVCardAuthValidityDays)
		}
	})
}

// =============================================================================
// OID Constants Tests
// =============================================================================

func TestOIDConstants(t *testing.T) {
	// Verify OID constants are not empty
	tests := []struct {
		name string
		oid  []int
	}{
		{name: "OIDSmartCardLogon", oid: OIDSmartCardLogon},
		{name: "OIDDocumentSigning", oid: OIDDocumentSigning},
		{name: "OIDPIVInterim", oid: OIDPIVInterim},
		{name: "OIDPIVContentSigning", oid: OIDPIVContentSigning},
		{name: "OIDPIVCardAuthentication", oid: OIDPIVCardAuthentication},
		{name: "OIDPIVCHUID", oid: OIDPIVCHUID},
		{name: "OIDFPKICommonPolicy", oid: OIDFPKICommonPolicy},
		{name: "OIDFPKICommonHardware", oid: OIDFPKICommonHardware},
		{name: "OIDFPKICommonHighAssurance", oid: OIDFPKICommonHighAssurance},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.oid) == 0 {
				t.Errorf("%s is empty", tc.name)
			}
		})
	}
}
