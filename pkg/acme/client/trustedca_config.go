// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package client

import (
	"net/url"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

// Supported key algorithms for certificate authority operations.
var validKeyAlgorithms = map[string]struct{}{
	"RSA-2048":   {},
	"RSA-3072":   {},
	"RSA-4096":   {},
	"ECDSA-P256": {},
	"ECDSA-P384": {},
	"ECDSA-P521": {},
	"Ed25519":    {},
}

// Supported signature algorithms for certificate signing.
var validSignatureAlgorithms = map[string]struct{}{
	"SHA256-RSA":   {},
	"SHA384-RSA":   {},
	"SHA512-RSA":   {},
	"SHA256-ECDSA": {},
	"SHA384-ECDSA": {},
	"SHA512-ECDSA": {},
	"Ed25519":      {},
}

// Config holds the configuration for a TrustedCA instance.
type TrustedCAConfig struct {
	// ACME server configuration
	ACME TCAACMEConfig `yaml:"acme" json:"acme"`

	// CA configuration
	CA CAConfig `yaml:"ca" json:"ca"`

	// Admin API configuration
	Admin AdminConfig `yaml:"admin" json:"admin"`

	// Multi-tenancy configuration
	MultiTenant MultiTenantConfig `yaml:"multi_tenant" json:"multi_tenant"`
}

// ACMEConfig holds ACME server configuration.
type TCAACMEConfig struct {
	// HTTPSAddr is the address to listen on for ACME requests (HTTPS, TLS 1.3).
	HTTPSAddr string `yaml:"https_addr" json:"https_addr"`

	// ExternalURL is the external URL of the ACME server.
	ExternalURL string `yaml:"external_url" json:"external_url"`

	// TermsOfService is the URL to the terms of service.
	TermsOfService string `yaml:"terms_of_service" json:"terms_of_service"`

	// Website is the URL to the CA website.
	Website string `yaml:"website" json:"website"`

	// CAIdentifiers are the CA identifiers for the directory.
	CAIdentifiers []string `yaml:"ca_identifiers" json:"ca_identifiers"`

	// SupportedChallenges lists the supported challenge types.
	SupportedChallenges []string `yaml:"supported_challenges" json:"supported_challenges"`

	// TLS holds TLS configuration (TLS 1.3 enforced by default).
	TLS TCATLSConfig `yaml:"tls" json:"tls"`
}

// TLSConfig holds TLS configuration for HTTPS.
type TCATLSConfig struct {
	// MinVersion is the minimum TLS version (default: "1.3").
	MinVersion string `yaml:"min_version" json:"min_version"`

	// MaxVersion is the maximum TLS version (default: "1.3").
	MaxVersion string `yaml:"max_version" json:"max_version"`
}

// CAConfig holds Certificate Authority configuration.
type CAConfig struct {
	// DefaultKeyAlgorithm is the default key algorithm.
	DefaultKeyAlgorithm string `yaml:"default_key_algorithm" json:"default_key_algorithm"`

	// DefaultSignatureAlgorithm is the default signature algorithm.
	DefaultSignatureAlgorithm string `yaml:"default_signature_algorithm" json:"default_signature_algorithm"`

	// CertificateValidityDays is the default certificate validity in days.
	CertificateValidityDays int `yaml:"certificate_validity_days" json:"certificate_validity_days"`
}

// AdminConfig holds admin API configuration.
type AdminConfig struct {
	// Enabled indicates whether the admin API is enabled.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// HTTPSAddr is the address to listen on for admin requests (HTTPS, TLS 1.3).
	HTTPSAddr string `yaml:"https_addr" json:"https_addr"`

	// RequireAuth indicates whether authentication is required.
	RequireAuth bool `yaml:"require_auth" json:"require_auth"`

	// TLS holds TLS configuration (TLS 1.3 enforced by default).
	TLS TCATLSConfig `yaml:"tls" json:"tls"`
}

// MultiTenantConfig holds multi-tenancy configuration.
type MultiTenantConfig struct {
	// Enabled indicates whether multi-tenancy is enabled.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// DefaultTenantID is the default tenant ID for single-tenant mode.
	DefaultTenantID string `yaml:"default_tenant_id" json:"default_tenant_id"`

	// TenantIsolation configures tenant isolation settings.
	TenantIsolation TenantIsolationConfig `yaml:"tenant_isolation" json:"tenant_isolation"`
}

// TenantIsolationConfig holds tenant isolation settings.
type TenantIsolationConfig struct {
	// EnforceIsolation enables strict tenant isolation.
	EnforceIsolation bool `yaml:"enforce_isolation" json:"enforce_isolation"`

	// AllowCrossTenantSuperAdmin allows super-admins to access other tenants.
	AllowCrossTenantSuperAdmin bool `yaml:"allow_cross_tenant_super_admin" json:"allow_cross_tenant_super_admin"`
}

// DefaultConfig returns a default configuration with TLS 1.3 enforced.
// All keys are managed by go-xkms - no filesystem key paths required.
func DefaultTrustedCAConfig() *TrustedCAConfig {
	return &TrustedCAConfig{
		ACME: TCAACMEConfig{
			HTTPSAddr:           ":8443",
			TermsOfService:      "https://example.com/tos",
			SupportedChallenges: []string{"http-01", "dns-01", "device-attest-01", "enroll-01", "endorse-01"},
			TLS: TCATLSConfig{
				MinVersion: "1.3",
				MaxVersion: "1.3",
			},
		},
		CA: CAConfig{
			DefaultKeyAlgorithm:       "ECDSA-P256",
			DefaultSignatureAlgorithm: "SHA256-ECDSA",
			CertificateValidityDays:   365,
		},
		Admin: AdminConfig{
			Enabled:     false,
			HTTPSAddr:   ":9443",
			RequireAuth: true,
			TLS: TCATLSConfig{
				MinVersion: "1.3",
				MaxVersion: "1.3",
			},
		},
		MultiTenant: MultiTenantConfig{
			Enabled:         false,
			DefaultTenantID: "default",
			TenantIsolation: TenantIsolationConfig{
				EnforceIsolation:           true,
				AllowCrossTenantSuperAdmin: true,
			},
		},
	}
}

// Validate validates the entire TrustedCA configuration by delegating
// to each sub-config's Validate method.
func (c *TrustedCAConfig) Validate() error {
	if err := c.ACME.Validate(); err != nil {
		return err
	}
	if err := c.CA.Validate(); err != nil {
		return err
	}
	if err := c.Admin.Validate(); err != nil {
		return err
	}
	if err := c.MultiTenant.Validate(); err != nil {
		return err
	}
	return nil
}

// Validate validates the ACME server configuration.
// HTTPSAddr and ExternalURL are required. ExternalURL must be a valid HTTPS URL.
func (a *TCAACMEConfig) Validate() error {
	if a.HTTPSAddr == "" {
		return errors.MalformedError("acme.https_addr is required")
	}
	if a.ExternalURL == "" {
		return errors.MalformedError("acme.external_url is required")
	}
	parsed, err := url.Parse(a.ExternalURL)
	if err != nil {
		return errors.MalformedError("acme.external_url is not a valid URL: %s", a.ExternalURL)
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return errors.MalformedError("acme.external_url must use https scheme, got %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return errors.MalformedError("acme.external_url must include a host")
	}
	if err := a.TLS.Validate(); err != nil {
		return err
	}
	return nil
}

// Validate validates the TLS configuration.
// Only TLS 1.3 is accepted: both MinVersion and MaxVersion must be "1.3".
func (t *TCATLSConfig) Validate() error {
	if t.MinVersion != "" && t.MinVersion != "1.3" {
		return errors.MalformedError("tls.min_version must be \"1.3\", got %q", t.MinVersion)
	}
	if t.MaxVersion != "" && t.MaxVersion != "1.3" {
		return errors.MalformedError("tls.max_version must be \"1.3\", got %q", t.MaxVersion)
	}
	return nil
}

// Validate validates the Certificate Authority configuration.
// Requires a valid key algorithm, valid signature algorithm, and a certificate
// validity period between 1 and 10950 days (approximately 30 years).
func (ca *CAConfig) Validate() error {
	if ca.DefaultKeyAlgorithm == "" {
		return errors.MalformedError("ca.default_key_algorithm is required")
	}
	if _, ok := validKeyAlgorithms[ca.DefaultKeyAlgorithm]; !ok {
		return errors.MalformedError("ca.default_key_algorithm %q is not a supported key algorithm", ca.DefaultKeyAlgorithm)
	}
	if ca.DefaultSignatureAlgorithm == "" {
		return errors.MalformedError("ca.default_signature_algorithm is required")
	}
	if _, ok := validSignatureAlgorithms[ca.DefaultSignatureAlgorithm]; !ok {
		return errors.MalformedError("ca.default_signature_algorithm %q is not a supported signature algorithm", ca.DefaultSignatureAlgorithm)
	}
	if ca.CertificateValidityDays < 1 || ca.CertificateValidityDays > 10950 {
		return errors.MalformedError("ca.certificate_validity_days must be between 1 and 10950, got %d", ca.CertificateValidityDays)
	}
	return nil
}

// Validate validates the admin API configuration.
// When Enabled is true, HTTPSAddr is required.
func (a *AdminConfig) Validate() error {
	if !a.Enabled {
		return nil
	}
	if a.HTTPSAddr == "" {
		return errors.MalformedError("admin.https_addr is required when admin API is enabled")
	}
	if err := a.TLS.Validate(); err != nil {
		return err
	}
	return nil
}

// Validate validates the multi-tenancy configuration.
// When Enabled is true, DefaultTenantID is required.
func (m *MultiTenantConfig) Validate() error {
	if !m.Enabled {
		return nil
	}
	if m.DefaultTenantID == "" {
		return errors.MalformedError("multi_tenant.default_tenant_id is required when multi-tenancy is enabled")
	}
	return nil
}
