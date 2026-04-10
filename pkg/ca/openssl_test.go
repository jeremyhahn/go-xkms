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

package ca

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenSSLConfigToSubject(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *OpenSSLConfig
		expected Subject
	}{
		{
			name: "full config",
			cfg: &OpenSSLConfig{
				Country:            "US",
				Province:           "California",
				Locality:           "San Francisco",
				Organization:       "Acme Corp",
				OrganizationalUnit: "Engineering",
				CommonName:         "acme.example.com",
			},
			expected: Subject{
				Country:            "US",
				Province:           "California",
				Locality:           "San Francisco",
				Organization:       "Acme Corp",
				OrganizationalUnit: "Engineering",
				CommonName:         "acme.example.com",
			},
		},
		{
			name: "partial config",
			cfg: &OpenSSLConfig{
				Country:      "DE",
				Organization: "Test GmbH",
			},
			expected: Subject{
				Country:      "DE",
				Organization: "Test GmbH",
			},
		},
		{
			name:     "empty config",
			cfg:      &OpenSSLConfig{},
			expected: Subject{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.cfg.ToSubject()
			if result != tt.expected {
				t.Errorf("ToSubject() = %+v, want %+v", result, tt.expected)
			}
		})
	}
}

func TestLoadOpenSSLConfig(t *testing.T) {
	t.Run("with valid config", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "openssl.cnf")
		content := `[ req_distinguished_name ]
countryName_default = US
0.organizationName_default = Test Org
`
		if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		// Save and restore environment
		oldEnv := os.Getenv("OPENSSL_CONF")
		defer func() { _ = os.Setenv("OPENSSL_CONF", oldEnv) }()
		_ = os.Setenv("OPENSSL_CONF", configPath)

		cfg, err := LoadOpenSSLConfig()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if cfg == nil {
			t.Fatal("Expected config, got nil")
		}
		if cfg.Country != "US" {
			t.Errorf("Country = %q, want %q", cfg.Country, "US")
		}
		if cfg.Organization != "Test Org" {
			t.Errorf("Organization = %q, want %q", cfg.Organization, "Test Org")
		}
	})

	t.Run("no config available", func(t *testing.T) {
		// Point to nonexistent file and clear env
		oldEnv := os.Getenv("OPENSSL_CONF")
		defer func() { _ = os.Setenv("OPENSSL_CONF", oldEnv) }()
		_ = os.Setenv("OPENSSL_CONF", "/definitely/nonexistent/path/openssl.cnf")

		// We can't easily force go-qrdb's internal paths to nonexistent,
		// but OPENSSL_CONF pointing to a nonexistent file should fall through
		// to standard paths. On most CI/dev systems a standard path exists,
		// so we just verify no error and no panic.
		_, err := LoadOpenSSLConfig()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
	})
}

func TestLoadOpenSSLConfigInternal(t *testing.T) {
	t.Run("with valid config returns subject", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "openssl.cnf")
		content := `[ req_distinguished_name ]
countryName_default = US
0.organizationName_default = Test Org
`
		if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		// Save and restore environment
		oldEnv := os.Getenv("OPENSSL_CONF")
		defer func() { _ = os.Setenv("OPENSSL_CONF", oldEnv) }()
		_ = os.Setenv("OPENSSL_CONF", configPath)

		subject := loadOpenSSLConfig()
		if subject == nil {
			t.Fatal("Expected subject, got nil")
		}
		if subject.Country != "US" {
			t.Errorf("Country = %q, want %q", subject.Country, "US")
		}
		if subject.Organization != "Test Org" {
			t.Errorf("Organization = %q, want %q", subject.Organization, "Test Org")
		}
	})

	t.Run("empty config returns nil", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "openssl.cnf")
		content := `[ req_distinguished_name ]
# no defaults set
`
		if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		// Save and restore environment
		oldEnv := os.Getenv("OPENSSL_CONF")
		defer func() { _ = os.Setenv("OPENSSL_CONF", oldEnv) }()
		_ = os.Setenv("OPENSSL_CONF", configPath)

		subject := loadOpenSSLConfig()
		if subject != nil {
			t.Errorf("Expected nil subject for empty config, got %+v", subject)
		}
	})
}

func TestMergeSubject(t *testing.T) {
	tests := []struct {
		name     string
		dst      *Subject
		src      *Subject
		expected *Subject
	}{
		{
			name:     "nil dst",
			dst:      nil,
			src:      &Subject{CommonName: "test"},
			expected: nil,
		},
		{
			name:     "nil src",
			dst:      &Subject{CommonName: "existing"},
			src:      nil,
			expected: &Subject{CommonName: "existing"},
		},
		{
			name: "merge empty dst",
			dst:  &Subject{},
			src: &Subject{
				CommonName:   "test.com",
				Country:      "US",
				Organization: "Test Org",
			},
			expected: &Subject{
				CommonName:   "test.com",
				Country:      "US",
				Organization: "Test Org",
			},
		},
		{
			name: "preserve existing values",
			dst: &Subject{
				CommonName: "existing.com",
				Country:    "GB",
			},
			src: &Subject{
				CommonName:   "src.com",
				Country:      "US",
				Organization: "Src Org",
				Province:     "California",
			},
			expected: &Subject{
				CommonName:   "existing.com", // preserved
				Country:      "GB",           // preserved
				Organization: "Src Org",      // merged
				Province:     "California",   // merged
			},
		},
		{
			name: "all fields",
			dst:  &Subject{},
			src: &Subject{
				CommonName:         "cn",
				Organization:       "org",
				OrganizationalUnit: "ou",
				Country:            "country",
				Province:           "province",
				Locality:           "locality",
				Address:            "address",
				PostalCode:         "postal",
			},
			expected: &Subject{
				CommonName:         "cn",
				Organization:       "org",
				OrganizationalUnit: "ou",
				Country:            "country",
				Province:           "province",
				Locality:           "locality",
				Address:            "address",
				PostalCode:         "postal",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mergeSubject(tt.dst, tt.src)

			if tt.expected == nil {
				// For nil dst case, just verify no panic
				return
			}

			if tt.dst == nil {
				if tt.expected != nil {
					t.Errorf("Expected non-nil result")
				}
				return
			}

			if tt.dst.CommonName != tt.expected.CommonName {
				t.Errorf("CommonName = %q, want %q", tt.dst.CommonName, tt.expected.CommonName)
			}
			if tt.dst.Country != tt.expected.Country {
				t.Errorf("Country = %q, want %q", tt.dst.Country, tt.expected.Country)
			}
			if tt.dst.Province != tt.expected.Province {
				t.Errorf("Province = %q, want %q", tt.dst.Province, tt.expected.Province)
			}
			if tt.dst.Locality != tt.expected.Locality {
				t.Errorf("Locality = %q, want %q", tt.dst.Locality, tt.expected.Locality)
			}
			if tt.dst.Organization != tt.expected.Organization {
				t.Errorf("Organization = %q, want %q", tt.dst.Organization, tt.expected.Organization)
			}
			if tt.dst.OrganizationalUnit != tt.expected.OrganizationalUnit {
				t.Errorf("OrganizationalUnit = %q, want %q", tt.dst.OrganizationalUnit, tt.expected.OrganizationalUnit)
			}
			if tt.dst.Address != tt.expected.Address {
				t.Errorf("Address = %q, want %q", tt.dst.Address, tt.expected.Address)
			}
			if tt.dst.PostalCode != tt.expected.PostalCode {
				t.Errorf("PostalCode = %q, want %q", tt.dst.PostalCode, tt.expected.PostalCode)
			}
		})
	}
}

func TestApplyOpenSSLDefaults(t *testing.T) {
	tests := []struct {
		name       string
		subject    *Subject
		opensslCfg *OpenSSLConfig
		expected   *Subject
	}{
		{
			name:       "nil openssl config",
			subject:    &Subject{CommonName: "test"},
			opensslCfg: nil,
			expected:   &Subject{CommonName: "test"},
		},
		{
			name:       "nil subject is safe",
			subject:    nil,
			opensslCfg: &OpenSSLConfig{Country: "US"},
			expected:   nil,
		},
		{
			name: "preserves existing values",
			subject: &Subject{
				CommonName:   "existing.com",
				Country:      "GB",
				Organization: "Existing Org",
			},
			opensslCfg: &OpenSSLConfig{
				Country:      "US",
				Province:     "California",
				Organization: "OpenSSL Org",
				Locality:     "San Francisco",
			},
			expected: &Subject{
				CommonName:   "existing.com",
				Country:      "GB",            // preserved
				Province:     "California",    // applied (was empty)
				Organization: "Existing Org",  // preserved
				Locality:     "San Francisco", // applied (was empty)
			},
		},
		{
			name: "fills empty subject fields",
			subject: &Subject{
				CommonName: "test.com",
			},
			opensslCfg: &OpenSSLConfig{
				Country:            "AU",
				Province:           "NSW",
				Locality:           "Sydney",
				Organization:       "Test Corp",
				OrganizationalUnit: "IT",
			},
			expected: &Subject{
				CommonName:         "test.com",
				Country:            "AU",
				Province:           "NSW",
				Locality:           "Sydney",
				Organization:       "Test Corp",
				OrganizationalUnit: "IT",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			applyOpenSSLDefaults(tt.subject, tt.opensslCfg)

			if tt.expected == nil {
				// nil expected case: nothing should have changed
				return
			}

			if tt.subject == nil {
				t.Fatal("Expected Subject, got nil")
			}

			if tt.subject.CommonName != tt.expected.CommonName {
				t.Errorf("CommonName = %q, want %q", tt.subject.CommonName, tt.expected.CommonName)
			}
			if tt.subject.Country != tt.expected.Country {
				t.Errorf("Country = %q, want %q", tt.subject.Country, tt.expected.Country)
			}
			if tt.subject.Province != tt.expected.Province {
				t.Errorf("Province = %q, want %q", tt.subject.Province, tt.expected.Province)
			}
			if tt.subject.Locality != tt.expected.Locality {
				t.Errorf("Locality = %q, want %q", tt.subject.Locality, tt.expected.Locality)
			}
			if tt.subject.Organization != tt.expected.Organization {
				t.Errorf("Organization = %q, want %q", tt.subject.Organization, tt.expected.Organization)
			}
			if tt.subject.OrganizationalUnit != tt.expected.OrganizationalUnit {
				t.Errorf("OrganizationalUnit = %q, want %q", tt.subject.OrganizationalUnit, tt.expected.OrganizationalUnit)
			}
		})
	}
}

func TestTryLoadOpenSSLDefaults(t *testing.T) {
	t.Run("with valid config", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "openssl.cnf")
		content := `[ req_distinguished_name ]
countryName_default = US
0.organizationName_default = Test Org
`
		if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		// Save and restore environment
		oldEnv := os.Getenv("OPENSSL_CONF")
		defer func() { _ = os.Setenv("OPENSSL_CONF", oldEnv) }()
		_ = os.Setenv("OPENSSL_CONF", configPath)

		subject := &Subject{CommonName: "Test CA"}
		TryLoadOpenSSLDefaults(subject)

		if subject.Country != "US" {
			t.Errorf("Country = %q, want %q", subject.Country, "US")
		}
		if subject.Organization != "Test Org" {
			t.Errorf("Organization = %q, want %q", subject.Organization, "Test Org")
		}
	})

	t.Run("nil subject is safe", func(t *testing.T) {
		// Should not panic with nil subject
		TryLoadOpenSSLDefaults(nil)
	})
}
