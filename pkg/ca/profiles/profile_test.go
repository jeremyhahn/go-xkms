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
	"encoding/asn1"
	"sync"
	"testing"
)

// =============================================================================
// Registry Tests
// =============================================================================

func TestNewRegistry(t *testing.T) {
	t.Run("creates_empty_registry", func(t *testing.T) {
		r := NewRegistry()
		if r == nil {
			t.Fatal("NewRegistry returned nil")
		}
		if r.Count() != 0 {
			t.Errorf("expected empty registry, got count %d", r.Count())
		}
	})

	t.Run("list_returns_empty_slice", func(t *testing.T) {
		r := NewRegistry()
		names := r.List()
		if names == nil {
			t.Error("List should return empty slice, not nil")
		}
		if len(names) != 0 {
			t.Errorf("expected empty list, got %d items", len(names))
		}
	})
}

func TestRegistry_Register(t *testing.T) {
	tests := []struct {
		name        string
		profile     ProfileProvider
		expectErr   error
		description string
	}{
		{
			name:        "valid_profile",
			profile:     NewBaseProfile("test-profile", WithDescription("Test profile")),
			expectErr:   nil,
			description: "registering a valid profile should succeed",
		},
		{
			name:        "nil_profile",
			profile:     nil,
			expectErr:   ErrInvalidProfile,
			description: "registering nil profile should return ErrInvalidProfile",
		},
		{
			name:        "empty_name_profile",
			profile:     NewBaseProfile(""),
			expectErr:   ErrInvalidProfile,
			description: "registering profile with empty name should return ErrInvalidProfile",
		},
		{
			name:        "whitespace_name_profile",
			profile:     NewBaseProfile("   "),
			expectErr:   ErrInvalidProfile,
			description: "registering profile with whitespace name should return ErrInvalidProfile",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRegistry()
			err := r.Register(tc.profile)
			if err != tc.expectErr {
				t.Errorf("%s: got error %v, want %v", tc.description, err, tc.expectErr)
			}
		})
	}
}

func TestRegistry_Register_DuplicateReturnsError(t *testing.T) {
	r := NewRegistry()
	profile := NewBaseProfile("duplicate-test")

	// First registration should succeed
	if err := r.Register(profile); err != nil {
		t.Fatalf("first registration failed: %v", err)
	}

	// Second registration should fail
	err := r.Register(profile)
	if err != ErrProfileExists {
		t.Errorf("expected ErrProfileExists, got %v", err)
	}
}

func TestRegistry_Register_CaseInsensitive(t *testing.T) {
	r := NewRegistry()

	// Register with uppercase
	profile := NewBaseProfile("TEST-PROFILE")
	if err := r.Register(profile); err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	// Try to register with lowercase - should fail as duplicate
	profile2 := NewBaseProfile("test-profile")
	err := r.Register(profile2)
	if err != ErrProfileExists {
		t.Errorf("expected ErrProfileExists for case-insensitive duplicate, got %v", err)
	}
}

func TestRegistry_Get(t *testing.T) {
	r := NewRegistry()
	profile := NewBaseProfile("get-test", WithDescription("Get test profile"))
	_ = r.Register(profile)

	tests := []struct {
		name      string
		lookup    string
		expectErr error
	}{
		{
			name:      "exact_match",
			lookup:    "get-test",
			expectErr: nil,
		},
		{
			name:      "case_insensitive_uppercase",
			lookup:    "GET-TEST",
			expectErr: nil,
		},
		{
			name:      "case_insensitive_mixed",
			lookup:    "Get-Test",
			expectErr: nil,
		},
		{
			name:      "not_found",
			lookup:    "nonexistent",
			expectErr: ErrProfileNotFound,
		},
		{
			name:      "empty_name",
			lookup:    "",
			expectErr: ErrProfileNotFound,
		},
		{
			name:      "whitespace_name",
			lookup:    "   ",
			expectErr: ErrProfileNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := r.Get(tc.lookup)
			if err != tc.expectErr {
				t.Errorf("got error %v, want %v", err, tc.expectErr)
			}
			if tc.expectErr == nil && p == nil {
				t.Error("expected profile, got nil")
			}
			if tc.expectErr == nil && p.Description() != "Get test profile" {
				t.Errorf("got wrong profile: %s", p.Description())
			}
		})
	}
}

func TestRegistry_List(t *testing.T) {
	t.Run("returns_sorted_names", func(t *testing.T) {
		r := NewRegistry()
		_ = r.Register(NewBaseProfile("zebra"))
		_ = r.Register(NewBaseProfile("alpha"))
		_ = r.Register(NewBaseProfile("middle"))

		names := r.List()
		if len(names) != 3 {
			t.Fatalf("expected 3 names, got %d", len(names))
		}

		expected := []string{"alpha", "middle", "zebra"}
		for i, name := range names {
			if name != expected[i] {
				t.Errorf("position %d: got %s, want %s", i, name, expected[i])
			}
		}
	})

	t.Run("returns_normalized_names", func(t *testing.T) {
		r := NewRegistry()
		_ = r.Register(NewBaseProfile("UPPERCASE"))
		_ = r.Register(NewBaseProfile("MixedCase"))

		names := r.List()
		for _, name := range names {
			if name != "uppercase" && name != "mixedcase" {
				t.Errorf("name not normalized: %s", name)
			}
		}
	})
}

func TestRegistry_Unregister(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(*Registry)
		unregister string
		expectErr  error
	}{
		{
			name: "removes_existing_profile",
			setup: func(r *Registry) {
				_ = r.Register(NewBaseProfile("to-remove"))
			},
			unregister: "to-remove",
			expectErr:  nil,
		},
		{
			name: "case_insensitive_removal",
			setup: func(r *Registry) {
				_ = r.Register(NewBaseProfile("lowercase"))
			},
			unregister: "LOWERCASE",
			expectErr:  nil,
		},
		{
			name:       "not_found",
			setup:      func(r *Registry) {},
			unregister: "nonexistent",
			expectErr:  ErrProfileNotFound,
		},
		{
			name:       "empty_name",
			setup:      func(r *Registry) {},
			unregister: "",
			expectErr:  ErrProfileNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRegistry()
			tc.setup(r)

			err := r.Unregister(tc.unregister)
			if err != tc.expectErr {
				t.Errorf("got error %v, want %v", err, tc.expectErr)
			}

			// Verify profile is actually removed on success
			if tc.expectErr == nil {
				if r.Has(tc.unregister) {
					t.Error("profile still exists after unregister")
				}
			}
		})
	}
}

func TestRegistry_Has(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(NewBaseProfile("exists"))

	tests := []struct {
		name   string
		lookup string
		expect bool
	}{
		{name: "exists", lookup: "exists", expect: true},
		{name: "case_insensitive", lookup: "EXISTS", expect: true},
		{name: "not_exists", lookup: "nonexistent", expect: false},
		{name: "empty", lookup: "", expect: false},
		{name: "whitespace", lookup: "   ", expect: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := r.Has(tc.lookup); got != tc.expect {
				t.Errorf("Has(%q) = %v, want %v", tc.lookup, got, tc.expect)
			}
		})
	}
}

func TestRegistry_Count(t *testing.T) {
	r := NewRegistry()

	if got := r.Count(); got != 0 {
		t.Errorf("empty registry: got %d, want 0", got)
	}

	_ = r.Register(NewBaseProfile("one"))
	if got := r.Count(); got != 1 {
		t.Errorf("after one register: got %d, want 1", got)
	}

	_ = r.Register(NewBaseProfile("two"))
	if got := r.Count(); got != 2 {
		t.Errorf("after two registers: got %d, want 2", got)
	}

	_ = r.Unregister("one")
	if got := r.Count(); got != 1 {
		t.Errorf("after unregister: got %d, want 1", got)
	}
}

func TestRegistry_ConcurrentAccess(t *testing.T) {
	r := NewRegistry()
	var wg sync.WaitGroup
	iterations := 100

	// Concurrent writes
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			name := "profile-" + string(rune('a'+idx%26))
			_ = r.Register(NewBaseProfile(name))
		}(i)
	}

	// Concurrent reads
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = r.List()
			_ = r.Count()
			_ = r.Has("profile-a")
		}()
	}

	wg.Wait()

	// Verify registry is still consistent
	if r.Count() < 1 || r.Count() > 26 {
		t.Errorf("unexpected count after concurrent access: %d", r.Count())
	}
}

// =============================================================================
// BaseProfile Tests
// =============================================================================

func TestNewBaseProfile(t *testing.T) {
	t.Run("creates_valid_profile_with_defaults", func(t *testing.T) {
		p := NewBaseProfile("test")

		if p.Name() != "test" {
			t.Errorf("Name() = %q, want %q", p.Name(), "test")
		}
		if p.Description() != "" {
			t.Errorf("Description() should be empty by default, got %q", p.Description())
		}
		if p.DefaultValidity() != 365 {
			t.Errorf("DefaultValidity() = %d, want 365", p.DefaultValidity())
		}
		if p.PathLenConstraint() != -1 {
			t.Errorf("PathLenConstraint() = %d, want -1", p.PathLenConstraint())
		}
		if p.IsCA() {
			t.Error("IsCA() should be false by default")
		}
		if p.KeyUsage() != 0 {
			t.Errorf("KeyUsage() = %d, want 0", p.KeyUsage())
		}
		if p.ExtKeyUsage() != nil {
			t.Error("ExtKeyUsage() should be nil by default")
		}
		if p.Extensions() != nil {
			t.Error("Extensions() should be nil by default")
		}
	})
}

func TestWithDescription(t *testing.T) {
	p := NewBaseProfile("test", WithDescription("Test description"))
	if p.Description() != "Test description" {
		t.Errorf("Description() = %q, want %q", p.Description(), "Test description")
	}
}

func TestWithKeyUsage(t *testing.T) {
	tests := []struct {
		name     string
		keyUsage x509.KeyUsage
	}{
		{
			name:     "single_usage",
			keyUsage: x509.KeyUsageDigitalSignature,
		},
		{
			name:     "combined_usage",
			keyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		},
		{
			name:     "ca_usage",
			keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := NewBaseProfile("test", WithKeyUsage(tc.keyUsage))
			if p.KeyUsage() != tc.keyUsage {
				t.Errorf("KeyUsage() = %d, want %d", p.KeyUsage(), tc.keyUsage)
			}
		})
	}
}

func TestWithExtKeyUsage(t *testing.T) {
	t.Run("single_eku", func(t *testing.T) {
		p := NewBaseProfile("test", WithExtKeyUsage(x509.ExtKeyUsageServerAuth))
		eku := p.ExtKeyUsage()
		if len(eku) != 1 || eku[0] != x509.ExtKeyUsageServerAuth {
			t.Errorf("ExtKeyUsage() = %v, want [ServerAuth]", eku)
		}
	})

	t.Run("multiple_ekus", func(t *testing.T) {
		p := NewBaseProfile("test", WithExtKeyUsage(
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		))
		eku := p.ExtKeyUsage()
		if len(eku) != 2 {
			t.Errorf("ExtKeyUsage() length = %d, want 2", len(eku))
		}
	})

	t.Run("empty_ekus", func(t *testing.T) {
		p := NewBaseProfile("test", WithExtKeyUsage())
		if p.ExtKeyUsage() != nil {
			t.Error("ExtKeyUsage() should be nil for empty input")
		}
	})

	t.Run("returns_copy", func(t *testing.T) {
		p := NewBaseProfile("test", WithExtKeyUsage(x509.ExtKeyUsageServerAuth))
		eku1 := p.ExtKeyUsage()
		eku2 := p.ExtKeyUsage()
		eku1[0] = x509.ExtKeyUsageCodeSigning
		if eku2[0] != x509.ExtKeyUsageServerAuth {
			t.Error("ExtKeyUsage() should return a copy")
		}
	})
}

func TestWithValidity(t *testing.T) {
	tests := []struct {
		name   string
		days   int
		expect int
	}{
		{name: "positive_days", days: 90, expect: 90},
		{name: "large_days", days: 3650, expect: 3650},
		{name: "zero_days_uses_default", days: 0, expect: 365},
		{name: "negative_days_uses_default", days: -1, expect: 365},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := NewBaseProfile("test", WithValidity(tc.days))
			if p.DefaultValidity() != tc.expect {
				t.Errorf("DefaultValidity() = %d, want %d", p.DefaultValidity(), tc.expect)
			}
		})
	}
}

func TestWithCA(t *testing.T) {
	tests := []struct {
		name       string
		pathLen    int
		expectCA   bool
		expectPath int
	}{
		{name: "unlimited", pathLen: -1, expectCA: true, expectPath: -1},
		{name: "zero", pathLen: 0, expectCA: true, expectPath: 0},
		{name: "positive", pathLen: 2, expectCA: true, expectPath: 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := NewBaseProfile("test", WithCA(tc.pathLen))
			if p.IsCA() != tc.expectCA {
				t.Errorf("IsCA() = %v, want %v", p.IsCA(), tc.expectCA)
			}
			if p.PathLenConstraint() != tc.expectPath {
				t.Errorf("PathLenConstraint() = %d, want %d", p.PathLenConstraint(), tc.expectPath)
			}
			// WithCA should also set CertSign and CRLSign key usage
			expectedKU := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
			if p.KeyUsage()&expectedKU != expectedKU {
				t.Error("WithCA should set CertSign and CRLSign key usage")
			}
		})
	}
}

func TestWithExtensions(t *testing.T) {
	t.Run("adds_single_extension", func(t *testing.T) {
		ext := pkix.Extension{
			Id:       asn1.ObjectIdentifier{1, 2, 3, 4},
			Critical: false,
			Value:    []byte("test"),
		}
		p := NewBaseProfile("test", WithExtensions(ext))
		exts := p.Extensions()
		if len(exts) != 1 {
			t.Fatalf("Extensions() length = %d, want 1", len(exts))
		}
		if !exts[0].Id.Equal(ext.Id) {
			t.Error("extension ID mismatch")
		}
	})

	t.Run("adds_multiple_extensions", func(t *testing.T) {
		ext1 := pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 3, 4}}
		ext2 := pkix.Extension{Id: asn1.ObjectIdentifier{5, 6, 7, 8}}
		p := NewBaseProfile("test", WithExtensions(ext1, ext2))
		exts := p.Extensions()
		if len(exts) != 2 {
			t.Errorf("Extensions() length = %d, want 2", len(exts))
		}
	})

	t.Run("empty_extensions", func(t *testing.T) {
		p := NewBaseProfile("test", WithExtensions())
		if p.Extensions() != nil {
			t.Error("Extensions() should be nil for empty input")
		}
	})

	t.Run("returns_copy", func(t *testing.T) {
		ext := pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 2, 3, 4},
			Value: []byte("original"),
		}
		p := NewBaseProfile("test", WithExtensions(ext))
		exts := p.Extensions()
		exts[0].Value = []byte("modified")
		exts2 := p.Extensions()
		if string(exts2[0].Value) != "original" {
			t.Error("Extensions() should return a copy")
		}
	})
}

// =============================================================================
// BaseProfile.Apply Tests
// =============================================================================

func TestBaseProfile_Apply(t *testing.T) {
	t.Run("applies_key_usage", func(t *testing.T) {
		p := NewBaseProfile("test",
			WithKeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment),
		)
		template := &x509.Certificate{}
		if err := p.Apply(template); err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		expectedKU := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		if template.KeyUsage != expectedKU {
			t.Errorf("KeyUsage = %d, want %d", template.KeyUsage, expectedKU)
		}
	})

	t.Run("applies_ext_key_usage", func(t *testing.T) {
		p := NewBaseProfile("test",
			WithExtKeyUsage(x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth),
		)
		template := &x509.Certificate{}
		if err := p.Apply(template); err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if len(template.ExtKeyUsage) != 2 {
			t.Errorf("ExtKeyUsage length = %d, want 2", len(template.ExtKeyUsage))
		}
	})

	t.Run("applies_ca_settings", func(t *testing.T) {
		p := NewBaseProfile("test", WithCA(0))
		template := &x509.Certificate{}
		if err := p.Apply(template); err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if !template.IsCA {
			t.Error("IsCA should be true")
		}
		if !template.BasicConstraintsValid {
			t.Error("BasicConstraintsValid should be true")
		}
		if template.MaxPathLen != 0 {
			t.Errorf("MaxPathLen = %d, want 0", template.MaxPathLen)
		}
		if !template.MaxPathLenZero {
			t.Error("MaxPathLenZero should be true")
		}
	})

	t.Run("applies_ca_settings_with_positive_pathlen", func(t *testing.T) {
		p := NewBaseProfile("test", WithCA(2))
		template := &x509.Certificate{}
		if err := p.Apply(template); err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if template.MaxPathLen != 2 {
			t.Errorf("MaxPathLen = %d, want 2", template.MaxPathLen)
		}
		if template.MaxPathLenZero {
			t.Error("MaxPathLenZero should be false for pathLen > 0")
		}
	})

	t.Run("applies_extensions", func(t *testing.T) {
		ext := pkix.Extension{
			Id:       asn1.ObjectIdentifier{1, 2, 3, 4},
			Critical: true,
			Value:    []byte("test"),
		}
		p := NewBaseProfile("test", WithExtensions(ext))
		template := &x509.Certificate{}
		if err := p.Apply(template); err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if len(template.ExtraExtensions) != 1 {
			t.Errorf("ExtraExtensions length = %d, want 1", len(template.ExtraExtensions))
		}
	})

	t.Run("nil_template_returns_error", func(t *testing.T) {
		p := NewBaseProfile("test")
		err := p.Apply(nil)
		if err != ErrInvalidProfile {
			t.Errorf("Apply(nil) = %v, want ErrInvalidProfile", err)
		}
	})

	t.Run("non_ca_does_not_set_isca", func(t *testing.T) {
		p := NewBaseProfile("test", WithKeyUsage(x509.KeyUsageDigitalSignature))
		template := &x509.Certificate{}
		if err := p.Apply(template); err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if template.IsCA {
			t.Error("IsCA should be false for non-CA profile")
		}
		if template.BasicConstraintsValid {
			t.Error("BasicConstraintsValid should be false for non-CA profile")
		}
	})
}

// =============================================================================
// DefaultRegistry Tests
// =============================================================================

func TestDefaultRegistry(t *testing.T) {
	t.Run("returns_registry_with_standard_profiles", func(t *testing.T) {
		r := DefaultRegistry()
		if r == nil {
			t.Fatal("DefaultRegistry returned nil")
		}

		// Check standard profiles exist
		standardProfiles := []string{
			"server",
			"client",
			"code-signing",
			"email",
			"ocsp-responder",
			"timestamping",
			"ca",
		}

		for _, name := range standardProfiles {
			if !r.Has(name) {
				t.Errorf("standard profile %q not found", name)
			}
		}
	})

	t.Run("server_profile_has_correct_settings", func(t *testing.T) {
		r := DefaultRegistry()
		p, err := r.Get("server")
		if err != nil {
			t.Fatalf("failed to get server profile: %v", err)
		}

		expectedKU := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		if p.KeyUsage() != expectedKU {
			t.Errorf("server KeyUsage = %d, want %d", p.KeyUsage(), expectedKU)
		}

		eku := p.ExtKeyUsage()
		if len(eku) != 1 || eku[0] != x509.ExtKeyUsageServerAuth {
			t.Errorf("server ExtKeyUsage = %v, want [ServerAuth]", eku)
		}
	})

	t.Run("client_profile_has_correct_settings", func(t *testing.T) {
		r := DefaultRegistry()
		p, err := r.Get("client")
		if err != nil {
			t.Fatalf("failed to get client profile: %v", err)
		}

		eku := p.ExtKeyUsage()
		if len(eku) != 1 || eku[0] != x509.ExtKeyUsageClientAuth {
			t.Errorf("client ExtKeyUsage = %v, want [ClientAuth]", eku)
		}
	})

	t.Run("ca_profile_has_correct_settings", func(t *testing.T) {
		r := DefaultRegistry()
		p, err := r.Get("ca")
		if err != nil {
			t.Fatalf("failed to get ca profile: %v", err)
		}

		if !p.IsCA() {
			t.Error("ca profile IsCA should be true")
		}

		expectedKU := x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		if p.KeyUsage() != expectedKU {
			t.Errorf("ca KeyUsage = %d, want %d", p.KeyUsage(), expectedKU)
		}

		if p.DefaultValidity() != 1825 {
			t.Errorf("ca DefaultValidity = %d, want 1825", p.DefaultValidity())
		}
	})

	t.Run("ocsp_responder_has_shorter_validity", func(t *testing.T) {
		r := DefaultRegistry()
		p, err := r.Get("ocsp-responder")
		if err != nil {
			t.Fatalf("failed to get ocsp-responder profile: %v", err)
		}

		if p.DefaultValidity() != 90 {
			t.Errorf("ocsp-responder DefaultValidity = %d, want 90", p.DefaultValidity())
		}
	})

	t.Run("returns_singleton", func(t *testing.T) {
		r1 := DefaultRegistry()
		r2 := DefaultRegistry()
		if r1 != r2 {
			t.Error("DefaultRegistry should return the same instance")
		}
	})
}

// =============================================================================
// ProfileProvider Interface Compliance Tests
// =============================================================================

func TestBaseProfile_ImplementsProfileProvider(t *testing.T) {
	var _ ProfileProvider = (*BaseProfile)(nil)
}

// =============================================================================
// Multiple Options Combination Tests
// =============================================================================

func TestNewBaseProfile_MultipleOptions(t *testing.T) {
	ext := pkix.Extension{
		Id:    asn1.ObjectIdentifier{1, 2, 3},
		Value: []byte("test"),
	}

	p := NewBaseProfile("multi-option",
		WithDescription("Multi-option test"),
		WithKeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment),
		WithExtKeyUsage(x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth),
		WithValidity(90),
		WithExtensions(ext),
	)

	if p.Name() != "multi-option" {
		t.Errorf("Name() = %q, want %q", p.Name(), "multi-option")
	}
	if p.Description() != "Multi-option test" {
		t.Errorf("Description() = %q, want %q", p.Description(), "Multi-option test")
	}
	if p.DefaultValidity() != 90 {
		t.Errorf("DefaultValidity() = %d, want 90", p.DefaultValidity())
	}

	expectedKU := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	if p.KeyUsage() != expectedKU {
		t.Errorf("KeyUsage() = %d, want %d", p.KeyUsage(), expectedKU)
	}

	if len(p.ExtKeyUsage()) != 2 {
		t.Errorf("ExtKeyUsage() length = %d, want 2", len(p.ExtKeyUsage()))
	}

	if len(p.Extensions()) != 1 {
		t.Errorf("Extensions() length = %d, want 1", len(p.Extensions()))
	}
}
