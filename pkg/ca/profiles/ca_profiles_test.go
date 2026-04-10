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
)

// =============================================================================
// Root CA Profile Tests
// =============================================================================

func TestNewRootCAProfile(t *testing.T) {
	t.Run("creates_valid_profile", func(t *testing.T) {
		p := NewRootCAProfile()

		if p == nil {
			t.Fatal("NewRootCAProfile returned nil")
		}

		if p.Name() != RootCAProfileName {
			t.Errorf("Name() = %q, want %q", p.Name(), RootCAProfileName)
		}

		if p.Description() == "" {
			t.Error("Description() should not be empty")
		}

		if p.DefaultValidity() != DefaultRootValidity {
			t.Errorf("DefaultValidity() = %d, want %d", p.DefaultValidity(), DefaultRootValidity)
		}

		if !p.IsCA() {
			t.Error("IsCA() should be true for root CA profile")
		}
	})

	t.Run("has_correct_key_usage", func(t *testing.T) {
		p := NewRootCAProfile()

		expectedKU := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		if p.KeyUsage() != expectedKU {
			t.Errorf("KeyUsage() = %d, want %d", p.KeyUsage(), expectedKU)
		}
	})

	t.Run("has_unlimited_path_length", func(t *testing.T) {
		p := NewRootCAProfile()

		if p.PathLenConstraint() != UnlimitedPathLen {
			t.Errorf("PathLenConstraint() = %d, want %d (unlimited)", p.PathLenConstraint(), UnlimitedPathLen)
		}
	})

	t.Run("has_no_extended_key_usage", func(t *testing.T) {
		p := NewRootCAProfile()

		// Root CAs should not have EKU per best practices
		eku := p.ExtKeyUsage()
		if len(eku) != 0 {
			t.Errorf("ExtKeyUsage() length = %d, want 0 (per best practices)", len(eku))
		}
	})
}

func TestRootCAProfile_Apply(t *testing.T) {
	t.Run("applies_ca_settings", func(t *testing.T) {
		p := NewRootCAProfile()
		template := &x509.Certificate{}

		err := p.Apply(template)
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}

		if !template.IsCA {
			t.Error("IsCA should be true")
		}

		if !template.BasicConstraintsValid {
			t.Error("BasicConstraintsValid should be true")
		}
	})

	t.Run("applies_correct_key_usage", func(t *testing.T) {
		p := NewRootCAProfile()
		template := &x509.Certificate{}

		err := p.Apply(template)
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}

		expectedKU := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		if template.KeyUsage != expectedKU {
			t.Errorf("KeyUsage = %d, want %d", template.KeyUsage, expectedKU)
		}
	})

	t.Run("does_not_set_path_length_constraint", func(t *testing.T) {
		p := NewRootCAProfile()
		template := &x509.Certificate{}

		err := p.Apply(template)
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}

		// Root CA with unlimited path length should not set MaxPathLen
		if template.MaxPathLen != 0 {
			t.Errorf("MaxPathLen = %d, want 0 (unset)", template.MaxPathLen)
		}

		if template.MaxPathLenZero {
			t.Error("MaxPathLenZero should be false for root CA")
		}
	})

	t.Run("nil_template_returns_error", func(t *testing.T) {
		p := NewRootCAProfile()
		err := p.Apply(nil)
		if err != ErrInvalidProfile {
			t.Errorf("Apply(nil) = %v, want ErrInvalidProfile", err)
		}
	})
}

// =============================================================================
// Intermediate CA Profile Tests
// =============================================================================

func TestNewIntermediateCAProfile(t *testing.T) {
	tests := []struct {
		name            string
		pathLen         int
		expectedPathLen int
		description     string
	}{
		{
			name:            "path_len_zero",
			pathLen:         0,
			expectedPathLen: 0,
			description:     "pathLen=0 means no subordinate CAs allowed",
		},
		{
			name:            "path_len_one",
			pathLen:         1,
			expectedPathLen: 1,
			description:     "pathLen=1 allows one level of subordinate CAs",
		},
		{
			name:            "path_len_two",
			pathLen:         2,
			expectedPathLen: 2,
			description:     "pathLen=2 allows two levels of subordinate CAs",
		},
		{
			name:            "path_len_negative",
			pathLen:         -1,
			expectedPathLen: -1,
			description:     "pathLen=-1 means no constraint",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := NewIntermediateCAProfile(tc.pathLen)

			if p == nil {
				t.Fatal("NewIntermediateCAProfile returned nil")
			}

			if p.Name() != IntermediateCAProfileName {
				t.Errorf("Name() = %q, want %q", p.Name(), IntermediateCAProfileName)
			}

			if !p.IsCA() {
				t.Error("IsCA() should be true")
			}

			if p.PathLenConstraint() != tc.expectedPathLen {
				t.Errorf("PathLenConstraint() = %d, want %d (%s)",
					p.PathLenConstraint(), tc.expectedPathLen, tc.description)
			}

			if p.MaxPathLen() != tc.expectedPathLen {
				t.Errorf("MaxPathLen() = %d, want %d", p.MaxPathLen(), tc.expectedPathLen)
			}
		})
	}
}

func TestNewIntermediateCAProfile_DefaultSettings(t *testing.T) {
	p := NewIntermediateCAProfile(0)

	t.Run("has_correct_validity", func(t *testing.T) {
		if p.DefaultValidity() != DefaultIntermediateValidity {
			t.Errorf("DefaultValidity() = %d, want %d", p.DefaultValidity(), DefaultIntermediateValidity)
		}
	})

	t.Run("has_correct_key_usage", func(t *testing.T) {
		expectedKU := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		if p.KeyUsage() != expectedKU {
			t.Errorf("KeyUsage() = %d, want %d", p.KeyUsage(), expectedKU)
		}
	})

	t.Run("has_description", func(t *testing.T) {
		if p.Description() == "" {
			t.Error("Description() should not be empty")
		}
	})
}

func TestNewSubordinateCAProfile(t *testing.T) {
	t.Run("is_alias_for_intermediate", func(t *testing.T) {
		p := NewSubordinateCAProfile(0)

		if p == nil {
			t.Fatal("NewSubordinateCAProfile returned nil")
		}

		if p.Name() != IntermediateCAProfileName {
			t.Errorf("Name() = %q, want %q", p.Name(), IntermediateCAProfileName)
		}
	})
}

func TestIntermediateCAProfile_Apply(t *testing.T) {
	t.Run("applies_ca_settings", func(t *testing.T) {
		p := NewIntermediateCAProfile(0)
		template := &x509.Certificate{}

		err := p.Apply(template)
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}

		if !template.IsCA {
			t.Error("IsCA should be true")
		}

		if !template.BasicConstraintsValid {
			t.Error("BasicConstraintsValid should be true")
		}
	})

	t.Run("applies_path_len_zero", func(t *testing.T) {
		p := NewIntermediateCAProfile(0)
		template := &x509.Certificate{}

		err := p.Apply(template)
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}

		if template.MaxPathLen != 0 {
			t.Errorf("MaxPathLen = %d, want 0", template.MaxPathLen)
		}

		if !template.MaxPathLenZero {
			t.Error("MaxPathLenZero should be true when pathLen=0")
		}
	})

	t.Run("applies_path_len_positive", func(t *testing.T) {
		p := NewIntermediateCAProfile(2)
		template := &x509.Certificate{}

		err := p.Apply(template)
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}

		if template.MaxPathLen != 2 {
			t.Errorf("MaxPathLen = %d, want 2", template.MaxPathLen)
		}

		if template.MaxPathLenZero {
			t.Error("MaxPathLenZero should be false when pathLen>0")
		}
	})

	t.Run("applies_correct_key_usage", func(t *testing.T) {
		p := NewIntermediateCAProfile(0)
		template := &x509.Certificate{}

		err := p.Apply(template)
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}

		expectedKU := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		if template.KeyUsage != expectedKU {
			t.Errorf("KeyUsage = %d, want %d", template.KeyUsage, expectedKU)
		}
	})

	t.Run("nil_template_returns_error", func(t *testing.T) {
		p := NewIntermediateCAProfile(0)
		err := p.Apply(nil)
		if err != ErrInvalidProfile {
			t.Errorf("Apply(nil) = %v, want ErrInvalidProfile", err)
		}
	})
}

// =============================================================================
// RegisterCAProfiles Tests
// =============================================================================

func TestRegisterCAProfiles(t *testing.T) {
	t.Run("registers_all_profiles", func(t *testing.T) {
		registry := NewRegistry()

		err := RegisterCAProfiles(registry)
		if err != nil {
			t.Fatalf("RegisterCAProfiles failed: %v", err)
		}

		// Verify root-ca is registered
		if !registry.Has(RootCAProfileName) {
			t.Errorf("profile %q not found", RootCAProfileName)
		}

		// Verify intermediate-ca is registered
		if !registry.Has(IntermediateCAProfileName) {
			t.Errorf("profile %q not found", IntermediateCAProfileName)
		}
	})

	t.Run("registered_profiles_are_valid", func(t *testing.T) {
		registry := NewRegistry()
		_ = RegisterCAProfiles(registry)

		rootProfile, err := registry.Get(RootCAProfileName)
		if err != nil {
			t.Fatalf("failed to get root profile: %v", err)
		}
		if !rootProfile.IsCA() {
			t.Error("root profile IsCA should be true")
		}

		intermediateProfile, err := registry.Get(IntermediateCAProfileName)
		if err != nil {
			t.Fatalf("failed to get intermediate profile: %v", err)
		}
		if !intermediateProfile.IsCA() {
			t.Error("intermediate profile IsCA should be true")
		}
	})

	t.Run("returns_error_on_duplicate", func(t *testing.T) {
		registry := NewRegistry()

		// First registration should succeed
		err := RegisterCAProfiles(registry)
		if err != nil {
			t.Fatalf("first RegisterCAProfiles failed: %v", err)
		}

		// Second registration should fail due to duplicates
		err = RegisterCAProfiles(registry)
		if err == nil {
			t.Error("expected error on duplicate registration, got nil")
		}
		if err != ErrProfileExists {
			t.Errorf("expected ErrProfileExists, got %v", err)
		}
	})
}

// =============================================================================
// AllCAProfiles Tests
// =============================================================================

func TestAllCAProfiles(t *testing.T) {
	t.Run("returns_all_profiles", func(t *testing.T) {
		profiles := AllCAProfiles()

		if len(profiles) != 2 {
			t.Errorf("AllCAProfiles() length = %d, want 2", len(profiles))
		}
	})

	t.Run("contains_root_profile", func(t *testing.T) {
		profiles := AllCAProfiles()

		found := false
		for _, p := range profiles {
			if p.Name() == RootCAProfileName {
				found = true
				break
			}
		}

		if !found {
			t.Error("root CA profile not found in AllCAProfiles()")
		}
	})

	t.Run("contains_intermediate_profile", func(t *testing.T) {
		profiles := AllCAProfiles()

		found := false
		for _, p := range profiles {
			if p.Name() == IntermediateCAProfileName {
				found = true
				break
			}
		}

		if !found {
			t.Error("intermediate CA profile not found in AllCAProfiles()")
		}
	})

	t.Run("all_profiles_are_ca", func(t *testing.T) {
		profiles := AllCAProfiles()

		for _, p := range profiles {
			if !p.IsCA() {
				t.Errorf("profile %q IsCA() should be true", p.Name())
			}
		}
	})
}

// =============================================================================
// AddCAExtensions Tests
// =============================================================================

func TestAddCAExtensions(t *testing.T) {
	t.Run("adds_crl_distribution_points", func(t *testing.T) {
		template := &x509.Certificate{}
		config := &CAExtensionsConfig{
			CRLDistributionPoints: []string{
				"http://crl.example.com/ca.crl",
				"http://crl2.example.com/ca.crl",
			},
		}

		err := AddCAExtensions(template, false, config)
		if err != nil {
			t.Fatalf("AddCAExtensions failed: %v", err)
		}

		if len(template.CRLDistributionPoints) != 2 {
			t.Errorf("CRLDistributionPoints length = %d, want 2", len(template.CRLDistributionPoints))
		}
	})

	t.Run("adds_ocsp_servers", func(t *testing.T) {
		template := &x509.Certificate{}
		config := &CAExtensionsConfig{
			OCSPServers: []string{
				"http://ocsp.example.com",
			},
		}

		err := AddCAExtensions(template, false, config)
		if err != nil {
			t.Fatalf("AddCAExtensions failed: %v", err)
		}

		if len(template.OCSPServer) != 1 {
			t.Errorf("OCSPServer length = %d, want 1", len(template.OCSPServer))
		}

		if template.OCSPServer[0] != "http://ocsp.example.com" {
			t.Errorf("OCSPServer[0] = %q, want %q", template.OCSPServer[0], "http://ocsp.example.com")
		}
	})

	t.Run("adds_ca_issuers", func(t *testing.T) {
		template := &x509.Certificate{}
		config := &CAExtensionsConfig{
			CAIssuers: []string{
				"http://ca.example.com/ca.crt",
			},
		}

		err := AddCAExtensions(template, false, config)
		if err != nil {
			t.Fatalf("AddCAExtensions failed: %v", err)
		}

		if len(template.IssuingCertificateURL) != 1 {
			t.Errorf("IssuingCertificateURL length = %d, want 1", len(template.IssuingCertificateURL))
		}
	})

	t.Run("handles_nil_config", func(t *testing.T) {
		template := &x509.Certificate{}

		err := AddCAExtensions(template, false, nil)
		if err != nil {
			t.Errorf("AddCAExtensions with nil config should not fail: %v", err)
		}
	})

	t.Run("nil_template_returns_error", func(t *testing.T) {
		config := &CAExtensionsConfig{}

		err := AddCAExtensions(nil, false, config)
		if err != ErrInvalidProfile {
			t.Errorf("AddCAExtensions(nil) = %v, want ErrInvalidProfile", err)
		}
	})

	t.Run("adds_all_extensions_combined", func(t *testing.T) {
		template := &x509.Certificate{}
		config := &CAExtensionsConfig{
			CRLDistributionPoints: []string{"http://crl.example.com/ca.crl"},
			OCSPServers:           []string{"http://ocsp.example.com"},
			CAIssuers:             []string{"http://ca.example.com/ca.crt"},
		}

		err := AddCAExtensions(template, false, config)
		if err != nil {
			t.Fatalf("AddCAExtensions failed: %v", err)
		}

		if len(template.CRLDistributionPoints) != 1 {
			t.Error("CRLDistributionPoints not set")
		}
		if len(template.OCSPServer) != 1 {
			t.Error("OCSPServer not set")
		}
		if len(template.IssuingCertificateURL) != 1 {
			t.Error("IssuingCertificateURL not set")
		}
	})
}

// =============================================================================
// Constants Tests
// =============================================================================

func TestCAProfileConstants(t *testing.T) {
	t.Run("profile_name_constants", func(t *testing.T) {
		if RootCAProfileName != "root-ca" {
			t.Errorf("RootCAProfileName = %q, want %q", RootCAProfileName, "root-ca")
		}
		if IntermediateCAProfileName != "intermediate-ca" {
			t.Errorf("IntermediateCAProfileName = %q, want %q", IntermediateCAProfileName, "intermediate-ca")
		}
	})

	t.Run("validity_constants", func(t *testing.T) {
		if DefaultRootValidity != 3650 {
			t.Errorf("DefaultRootValidity = %d, want 3650 (10 years)", DefaultRootValidity)
		}
		if DefaultIntermediateValidity != 1825 {
			t.Errorf("DefaultIntermediateValidity = %d, want 1825 (5 years)", DefaultIntermediateValidity)
		}
	})

	t.Run("path_len_constant", func(t *testing.T) {
		if UnlimitedPathLen != -1 {
			t.Errorf("UnlimitedPathLen = %d, want -1", UnlimitedPathLen)
		}
	})
}

// =============================================================================
// ProfileProvider Interface Compliance Tests
// =============================================================================

func TestCAProfiles_ImplementProfileProvider(t *testing.T) {
	var _ ProfileProvider = (*RootCAProfile)(nil)
	var _ ProfileProvider = (*IntermediateCAProfile)(nil)
}

// =============================================================================
// Apply Idempotency Tests
// =============================================================================

func TestCAProfile_Apply_Idempotent(t *testing.T) {
	tests := []struct {
		name    string
		profile ProfileProvider
	}{
		{name: "root", profile: NewRootCAProfile()},
		{name: "intermediate", profile: NewIntermediateCAProfile(0)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			template := &x509.Certificate{}

			// Get the right Apply method
			switch p := tc.profile.(type) {
			case *RootCAProfile:
				if err := p.Apply(template); err != nil {
					t.Fatalf("first Apply failed: %v", err)
				}
				if err := p.Apply(template); err != nil {
					t.Fatalf("second Apply failed: %v", err)
				}
			case *IntermediateCAProfile:
				if err := p.Apply(template); err != nil {
					t.Fatalf("first Apply failed: %v", err)
				}
				if err := p.Apply(template); err != nil {
					t.Fatalf("second Apply failed: %v", err)
				}
			}

			// Values should remain consistent
			if !template.IsCA {
				t.Error("IsCA should still be true after multiple Apply calls")
			}
		})
	}
}

// =============================================================================
// RFC 5280 Compliance Tests
// =============================================================================

func TestCAProfiles_RFC5280_Compliance(t *testing.T) {
	t.Run("root_ca_has_basic_constraints", func(t *testing.T) {
		p := NewRootCAProfile()
		template := &x509.Certificate{}
		_ = p.Apply(template)

		if !template.BasicConstraintsValid {
			t.Error("RFC 5280: Basic Constraints must be present for CA certificates")
		}
		if !template.IsCA {
			t.Error("RFC 5280: cA field must be TRUE for CA certificates")
		}
	})

	t.Run("intermediate_ca_has_basic_constraints", func(t *testing.T) {
		p := NewIntermediateCAProfile(0)
		template := &x509.Certificate{}
		_ = p.Apply(template)

		if !template.BasicConstraintsValid {
			t.Error("RFC 5280: Basic Constraints must be present for CA certificates")
		}
		if !template.IsCA {
			t.Error("RFC 5280: cA field must be TRUE for CA certificates")
		}
	})

	t.Run("ca_has_key_usage_for_signing", func(t *testing.T) {
		profiles := []ProfileProvider{
			NewRootCAProfile(),
			NewIntermediateCAProfile(0),
		}

		for _, p := range profiles {
			template := &x509.Certificate{}
			switch prof := p.(type) {
			case *RootCAProfile:
				_ = prof.Apply(template)
			case *IntermediateCAProfile:
				_ = prof.Apply(template)
			}

			if template.KeyUsage&x509.KeyUsageCertSign == 0 {
				t.Errorf("%s: CA should have CertSign key usage", p.Name())
			}
		}
	})
}

// =============================================================================
// Edge Case Tests
// =============================================================================

func TestIntermediateCAProfile_LargePathLen(t *testing.T) {
	t.Run("large_path_len", func(t *testing.T) {
		p := NewIntermediateCAProfile(100)
		template := &x509.Certificate{}

		err := p.Apply(template)
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}

		if template.MaxPathLen != 100 {
			t.Errorf("MaxPathLen = %d, want 100", template.MaxPathLen)
		}
	})
}

// =============================================================================
// CAExtensionsConfig Tests
// =============================================================================

func TestCAExtensionsConfig_Empty(t *testing.T) {
	t.Run("empty_config_does_nothing", func(t *testing.T) {
		template := &x509.Certificate{}
		config := &CAExtensionsConfig{}

		err := AddCAExtensions(template, false, config)
		if err != nil {
			t.Fatalf("AddCAExtensions failed: %v", err)
		}

		if len(template.CRLDistributionPoints) != 0 {
			t.Error("CRLDistributionPoints should be empty")
		}
		if len(template.OCSPServer) != 0 {
			t.Error("OCSPServer should be empty")
		}
		if len(template.IssuingCertificateURL) != 0 {
			t.Error("IssuingCertificateURL should be empty")
		}
	})
}

// =============================================================================
// Stub Profile Option Tests
// =============================================================================

func TestWithCRLDistributionPoints(t *testing.T) {
	t.Run("can_be_called_without_error", func(t *testing.T) {
		// This is currently a stub option - just verify it can be called
		p := NewBaseProfile("test",
			WithCRLDistributionPoints("http://crl.example.com/ca.crl"),
		)
		if p == nil {
			t.Fatal("profile should not be nil")
		}
	})

	t.Run("accepts_multiple_urls", func(t *testing.T) {
		p := NewBaseProfile("test",
			WithCRLDistributionPoints(
				"http://crl1.example.com/ca.crl",
				"http://crl2.example.com/ca.crl",
			),
		)
		if p == nil {
			t.Fatal("profile should not be nil")
		}
	})
}

func TestWithOCSPServers(t *testing.T) {
	t.Run("can_be_called_without_error", func(t *testing.T) {
		// This is currently a stub option - just verify it can be called
		p := NewBaseProfile("test",
			WithOCSPServers("http://ocsp.example.com"),
		)
		if p == nil {
			t.Fatal("profile should not be nil")
		}
	})

	t.Run("accepts_multiple_urls", func(t *testing.T) {
		p := NewBaseProfile("test",
			WithOCSPServers(
				"http://ocsp1.example.com",
				"http://ocsp2.example.com",
			),
		)
		if p == nil {
			t.Fatal("profile should not be nil")
		}
	})
}

func TestWithCAIssuers(t *testing.T) {
	t.Run("can_be_called_without_error", func(t *testing.T) {
		// This is currently a stub option - just verify it can be called
		p := NewBaseProfile("test",
			WithCAIssuers("http://ca.example.com/ca.crt"),
		)
		if p == nil {
			t.Fatal("profile should not be nil")
		}
	})

	t.Run("accepts_multiple_urls", func(t *testing.T) {
		p := NewBaseProfile("test",
			WithCAIssuers(
				"http://ca1.example.com/ca.crt",
				"http://ca2.example.com/ca.crt",
			),
		)
		if p == nil {
			t.Fatal("profile should not be nil")
		}
	})
}
