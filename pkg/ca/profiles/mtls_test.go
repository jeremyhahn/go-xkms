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
// mTLS Client Profile Tests
// =============================================================================

func TestNewMTLSClientProfile(t *testing.T) {
	t.Run("creates_valid_profile", func(t *testing.T) {
		p := NewMTLSClientProfile()

		if p == nil {
			t.Fatal("NewMTLSClientProfile returned nil")
		}

		if p.Name() != ProfileNameMTLSClient {
			t.Errorf("Name() = %q, want %q", p.Name(), ProfileNameMTLSClient)
		}

		if p.Description() == "" {
			t.Error("Description() should not be empty")
		}

		if p.DefaultValidity() != DefaultMTLSValidityDays {
			t.Errorf("DefaultValidity() = %d, want %d", p.DefaultValidity(), DefaultMTLSValidityDays)
		}
	})

	t.Run("has_correct_key_usage", func(t *testing.T) {
		p := NewMTLSClientProfile()

		expectedKU := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		if p.KeyUsage() != expectedKU {
			t.Errorf("KeyUsage() = %d, want %d", p.KeyUsage(), expectedKU)
		}
	})

	t.Run("has_correct_ext_key_usage", func(t *testing.T) {
		p := NewMTLSClientProfile()

		eku := p.ExtKeyUsage()
		if len(eku) != 1 || eku[0] != x509.ExtKeyUsageClientAuth {
			t.Errorf("ExtKeyUsage() = %v, want [ClientAuth]", eku)
		}
	})

	t.Run("ext_key_usage_returns_copy", func(t *testing.T) {
		p := NewMTLSClientProfile()

		eku1 := p.ExtKeyUsage()
		eku2 := p.ExtKeyUsage()

		eku1[0] = x509.ExtKeyUsageServerAuth
		if eku2[0] != x509.ExtKeyUsageClientAuth {
			t.Error("ExtKeyUsage() should return a copy")
		}
	})
}

func TestMTLSClientProfile_Apply(t *testing.T) {
	t.Run("applies_profile_settings", func(t *testing.T) {
		p := NewMTLSClientProfile()
		template := &x509.Certificate{}

		err := p.Apply(template, nil)
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}

		expectedKU := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		if template.KeyUsage != expectedKU {
			t.Errorf("KeyUsage = %d, want %d", template.KeyUsage, expectedKU)
		}

		if len(template.ExtKeyUsage) != 1 || template.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
			t.Errorf("ExtKeyUsage = %v, want [ClientAuth]", template.ExtKeyUsage)
		}

		if template.IsCA {
			t.Error("IsCA should be false")
		}

		if !template.BasicConstraintsValid {
			t.Error("BasicConstraintsValid should be true")
		}
	})

	t.Run("nil_template_returns_error", func(t *testing.T) {
		p := NewMTLSClientProfile()
		err := p.Apply(nil, nil)
		if err != ca.ErrInvalidProfile {
			t.Errorf("Apply(nil) = %v, want ErrInvalidProfile", err)
		}
	})
}

// =============================================================================
// mTLS Server Profile Tests
// =============================================================================

func TestNewMTLSServerProfile(t *testing.T) {
	t.Run("creates_valid_profile", func(t *testing.T) {
		p := NewMTLSServerProfile()

		if p == nil {
			t.Fatal("NewMTLSServerProfile returned nil")
		}

		if p.Name() != ProfileNameMTLSServer {
			t.Errorf("Name() = %q, want %q", p.Name(), ProfileNameMTLSServer)
		}

		if p.Description() == "" {
			t.Error("Description() should not be empty")
		}

		if p.DefaultValidity() != DefaultMTLSValidityDays {
			t.Errorf("DefaultValidity() = %d, want %d", p.DefaultValidity(), DefaultMTLSValidityDays)
		}
	})

	t.Run("has_correct_key_usage", func(t *testing.T) {
		p := NewMTLSServerProfile()

		expectedKU := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		if p.KeyUsage() != expectedKU {
			t.Errorf("KeyUsage() = %d, want %d", p.KeyUsage(), expectedKU)
		}
	})

	t.Run("has_correct_ext_key_usage", func(t *testing.T) {
		p := NewMTLSServerProfile()

		eku := p.ExtKeyUsage()
		if len(eku) != 1 || eku[0] != x509.ExtKeyUsageServerAuth {
			t.Errorf("ExtKeyUsage() = %v, want [ServerAuth]", eku)
		}
	})
}

func TestMTLSServerProfile_Apply(t *testing.T) {
	t.Run("applies_profile_settings", func(t *testing.T) {
		p := NewMTLSServerProfile()
		template := &x509.Certificate{}

		err := p.Apply(template, nil)
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}

		expectedKU := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		if template.KeyUsage != expectedKU {
			t.Errorf("KeyUsage = %d, want %d", template.KeyUsage, expectedKU)
		}

		if len(template.ExtKeyUsage) != 1 || template.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
			t.Errorf("ExtKeyUsage = %v, want [ServerAuth]", template.ExtKeyUsage)
		}

		if template.IsCA {
			t.Error("IsCA should be false")
		}

		if !template.BasicConstraintsValid {
			t.Error("BasicConstraintsValid should be true")
		}
	})

	t.Run("nil_template_returns_error", func(t *testing.T) {
		p := NewMTLSServerProfile()
		err := p.Apply(nil, nil)
		if err != ca.ErrInvalidProfile {
			t.Errorf("Apply(nil) = %v, want ErrInvalidProfile", err)
		}
	})
}

// =============================================================================
// mTLS Dual Profile Tests
// =============================================================================

func TestNewMTLSDualProfile(t *testing.T) {
	t.Run("creates_valid_profile", func(t *testing.T) {
		p := NewMTLSDualProfile()

		if p == nil {
			t.Fatal("NewMTLSDualProfile returned nil")
		}

		if p.Name() != ProfileNameMTLSDual {
			t.Errorf("Name() = %q, want %q", p.Name(), ProfileNameMTLSDual)
		}

		if p.Description() == "" {
			t.Error("Description() should not be empty")
		}

		if p.DefaultValidity() != DefaultMTLSValidityDays {
			t.Errorf("DefaultValidity() = %d, want %d", p.DefaultValidity(), DefaultMTLSValidityDays)
		}
	})

	t.Run("has_correct_key_usage", func(t *testing.T) {
		p := NewMTLSDualProfile()

		expectedKU := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		if p.KeyUsage() != expectedKU {
			t.Errorf("KeyUsage() = %d, want %d", p.KeyUsage(), expectedKU)
		}
	})

	t.Run("has_both_client_and_server_ext_key_usage", func(t *testing.T) {
		p := NewMTLSDualProfile()

		eku := p.ExtKeyUsage()
		if len(eku) != 2 {
			t.Fatalf("ExtKeyUsage() length = %d, want 2", len(eku))
		}

		hasClient := false
		hasServer := false
		for _, e := range eku {
			if e == x509.ExtKeyUsageClientAuth {
				hasClient = true
			}
			if e == x509.ExtKeyUsageServerAuth {
				hasServer = true
			}
		}

		if !hasClient {
			t.Error("ExtKeyUsage should contain ClientAuth")
		}
		if !hasServer {
			t.Error("ExtKeyUsage should contain ServerAuth")
		}
	})
}

func TestMTLSDualProfile_Apply(t *testing.T) {
	t.Run("applies_profile_settings", func(t *testing.T) {
		p := NewMTLSDualProfile()
		template := &x509.Certificate{}

		err := p.Apply(template, nil)
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}

		expectedKU := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		if template.KeyUsage != expectedKU {
			t.Errorf("KeyUsage = %d, want %d", template.KeyUsage, expectedKU)
		}

		if len(template.ExtKeyUsage) != 2 {
			t.Errorf("ExtKeyUsage length = %d, want 2", len(template.ExtKeyUsage))
		}

		if template.IsCA {
			t.Error("IsCA should be false")
		}

		if !template.BasicConstraintsValid {
			t.Error("BasicConstraintsValid should be true")
		}
	})

	t.Run("nil_template_returns_error", func(t *testing.T) {
		p := NewMTLSDualProfile()
		err := p.Apply(nil, nil)
		if err != ca.ErrInvalidProfile {
			t.Errorf("Apply(nil) = %v, want ErrInvalidProfile", err)
		}
	})
}

// =============================================================================
// RegisterMTLSProfiles Tests
// =============================================================================

func TestRegisterMTLSProfiles(t *testing.T) {
	t.Run("registers_all_profiles", func(t *testing.T) {
		registry := ca.NewDefaultProfileRegistry()

		err := RegisterMTLSProfiles(registry)
		if err != nil {
			t.Fatalf("RegisterMTLSProfiles failed: %v", err)
		}

		// Verify all profiles are registered
		expectedProfiles := []string{
			ProfileNameMTLSClient,
			ProfileNameMTLSServer,
			ProfileNameMTLSDual,
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
		err := RegisterMTLSProfiles(registry)
		if err != nil {
			t.Fatalf("first RegisterMTLSProfiles failed: %v", err)
		}

		// Second registration should also succeed (replaces existing)
		err = RegisterMTLSProfiles(registry)
		if err != nil {
			t.Errorf("second RegisterMTLSProfiles failed unexpectedly: %v", err)
		}

		// Verify profiles still exist
		for _, name := range MTLSProfileNames() {
			_, err := registry.Get(name)
			if err != nil {
				t.Errorf("profile %q should exist after re-registration: %v", name, err)
			}
		}
	})
}

// =============================================================================
// AllMTLSProfiles Tests
// =============================================================================

func TestAllMTLSProfiles(t *testing.T) {
	t.Run("returns_all_profiles", func(t *testing.T) {
		profiles := AllMTLSProfiles()

		if len(profiles) != 3 {
			t.Errorf("AllMTLSProfiles() length = %d, want 3", len(profiles))
		}

		// Verify each profile type is present
		names := make(map[string]bool)
		for _, p := range profiles {
			names[p.Name()] = true
		}

		expectedNames := []string{
			ProfileNameMTLSClient,
			ProfileNameMTLSServer,
			ProfileNameMTLSDual,
		}

		for _, name := range expectedNames {
			if !names[name] {
				t.Errorf("profile %q not found in AllMTLSProfiles()", name)
			}
		}
	})
}

// =============================================================================
// MTLSProfileByName Tests
// =============================================================================

func TestMTLSProfileByName(t *testing.T) {
	tests := []struct {
		name         string
		profileName  string
		expectErr    bool
		expectedName string
	}{
		{
			name:         "client_profile",
			profileName:  ProfileNameMTLSClient,
			expectErr:    false,
			expectedName: ProfileNameMTLSClient,
		},
		{
			name:         "server_profile",
			profileName:  ProfileNameMTLSServer,
			expectErr:    false,
			expectedName: ProfileNameMTLSServer,
		},
		{
			name:         "dual_profile",
			profileName:  ProfileNameMTLSDual,
			expectErr:    false,
			expectedName: ProfileNameMTLSDual,
		},
		{
			name:        "invalid_name",
			profileName: "invalid",
			expectErr:   true,
		},
		{
			name:        "empty_name",
			profileName: "",
			expectErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			profile, err := MTLSProfileByName(tc.profileName)

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
// MTLSProfileNames Tests
// =============================================================================

func TestMTLSProfileNames(t *testing.T) {
	t.Run("returns_all_names", func(t *testing.T) {
		names := MTLSProfileNames()

		if len(names) != 3 {
			t.Errorf("MTLSProfileNames() length = %d, want 3", len(names))
		}

		expected := map[string]bool{
			ProfileNameMTLSClient: false,
			ProfileNameMTLSServer: false,
			ProfileNameMTLSDual:   false,
		}

		for _, name := range names {
			if _, ok := expected[name]; !ok {
				t.Errorf("unexpected name: %q", name)
			}
			expected[name] = true
		}

		for name, found := range expected {
			if !found {
				t.Errorf("name %q not found in MTLSProfileNames()", name)
			}
		}
	})
}

// =============================================================================
// IsMTLSProfile Tests
// =============================================================================

func TestIsMTLSProfile(t *testing.T) {
	tests := []struct {
		name   string
		expect bool
	}{
		{name: ProfileNameMTLSClient, expect: true},
		{name: ProfileNameMTLSServer, expect: true},
		{name: ProfileNameMTLSDual, expect: true},
		{name: "mtls-client", expect: true},
		{name: "mtls-server", expect: true},
		{name: "mtls-dual", expect: true},
		{name: "invalid", expect: false},
		{name: "", expect: false},
		{name: "MTLS-CLIENT", expect: false}, // Case-sensitive
		{name: "server", expect: false},
		{name: "client", expect: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsMTLSProfile(tc.name); got != tc.expect {
				t.Errorf("IsMTLSProfile(%q) = %v, want %v", tc.name, got, tc.expect)
			}
		})
	}
}

// =============================================================================
// MTLSProfile Interface Compliance Tests
// =============================================================================

func TestMTLSProfiles_ImplementMTLSProfile(t *testing.T) {
	// Verify all mTLS profiles implement the MTLSProfile interface
	var _ MTLSProfile = (*MTLSClientProfile)(nil)
	var _ MTLSProfile = (*MTLSServerProfile)(nil)
	var _ MTLSProfile = (*MTLSDualProfile)(nil)
}

// =============================================================================
// Profile Name Constants Tests
// =============================================================================

func TestMTLSProfileNameConstants(t *testing.T) {
	tests := []struct {
		constant string
		value    string
	}{
		{constant: "ProfileNameMTLSClient", value: "mtls-client"},
		{constant: "ProfileNameMTLSServer", value: "mtls-server"},
		{constant: "ProfileNameMTLSDual", value: "mtls-dual"},
	}

	actuals := map[string]string{
		"ProfileNameMTLSClient": ProfileNameMTLSClient,
		"ProfileNameMTLSServer": ProfileNameMTLSServer,
		"ProfileNameMTLSDual":   ProfileNameMTLSDual,
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

func TestMTLSValidityPeriod(t *testing.T) {
	t.Run("default_validity_is_1_year", func(t *testing.T) {
		if DefaultMTLSValidityDays != 365 {
			t.Errorf("DefaultMTLSValidityDays = %d, want 365 (1 year)", DefaultMTLSValidityDays)
		}
	})

	t.Run("all_profiles_use_default_validity", func(t *testing.T) {
		profiles := AllMTLSProfiles()
		for _, p := range profiles {
			if p.DefaultValidity() != DefaultMTLSValidityDays {
				t.Errorf("%s DefaultValidity() = %d, want %d", p.Name(), p.DefaultValidity(), DefaultMTLSValidityDays)
			}
		}
	})
}

// =============================================================================
// OID Constants Tests
// =============================================================================

func TestMTLSOIDConstants(t *testing.T) {
	t.Run("server_auth_oid", func(t *testing.T) {
		expected := []int{1, 3, 6, 1, 5, 5, 7, 3, 1}
		if len(OIDServerAuth) != len(expected) {
			t.Errorf("OIDServerAuth length = %d, want %d", len(OIDServerAuth), len(expected))
		}
		for i, v := range expected {
			if OIDServerAuth[i] != v {
				t.Errorf("OIDServerAuth[%d] = %d, want %d", i, OIDServerAuth[i], v)
			}
		}
	})

	t.Run("client_auth_oid", func(t *testing.T) {
		expected := []int{1, 3, 6, 1, 5, 5, 7, 3, 2}
		if len(OIDClientAuth) != len(expected) {
			t.Errorf("OIDClientAuth length = %d, want %d", len(OIDClientAuth), len(expected))
		}
		for i, v := range expected {
			if OIDClientAuth[i] != v {
				t.Errorf("OIDClientAuth[%d] = %d, want %d", i, OIDClientAuth[i], v)
			}
		}
	})
}

// =============================================================================
// Apply Method Idempotency Tests
// =============================================================================

func TestMTLSProfile_Apply_Idempotent(t *testing.T) {
	tests := []struct {
		name    string
		profile MTLSProfile
	}{
		{name: "client", profile: NewMTLSClientProfile()},
		{name: "server", profile: NewMTLSServerProfile()},
		{name: "dual", profile: NewMTLSDualProfile()},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			template := &x509.Certificate{}

			// Apply twice
			if err := tc.profile.Apply(template, nil); err != nil {
				t.Fatalf("first Apply failed: %v", err)
			}

			firstKU := template.KeyUsage
			firstEKU := len(template.ExtKeyUsage)

			if err := tc.profile.Apply(template, nil); err != nil {
				t.Fatalf("second Apply failed: %v", err)
			}

			// Values should remain the same
			if template.KeyUsage != firstKU {
				t.Error("KeyUsage changed after second Apply")
			}
			if len(template.ExtKeyUsage) != firstEKU {
				t.Error("ExtKeyUsage changed after second Apply")
			}
		})
	}
}
