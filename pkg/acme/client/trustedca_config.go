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

package client

import (
	"net/url"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
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
	// DataDir is the base directory this TrustedCA instance persists to.
	// Audit.LogPath, when not set explicitly, resolves to
	// DataDir/DefaultAuditLogFileName (see Validate) -- the same
	// DataDir-relative pattern xkmsd's embedded ACME server uses for its
	// own audit trail (pkg/config.ACMEAuditConfig.ResolveLogPath) -- so a
	// standalone TrustedCA never falls back to a cwd-relative default
	// (go-xkms#929). Required whenever Audit.Enabled is true and
	// Audit.LogPath is not set.
	DataDir string `yaml:"data_dir" json:"data_dir"`

	// ACME server configuration
	ACME TCAACMEConfig `yaml:"acme" json:"acme"`

	// CA configuration
	CA CAConfig `yaml:"ca" json:"ca"`

	// Admin API configuration
	Admin AdminConfig `yaml:"admin" json:"admin"`

	// Multi-tenancy is not a config field: it is a construction-time wiring
	// decision, matching how every other structural component of TrustedCA
	// (CA, storage factory, QRDB service, auth client) is wired -- through an
	// Option, not through this config struct. WithMultiTenant() is the only
	// switch; WithQRDB() supplies the multi-tenant store it requires. This
	// also matches xkmsd's embedded ACME server: cmd/xkmsd/admin.go always
	// calls admin.NewTenantAwareAdminService directly and has no
	// pkg/config.ACMEConfig multi-tenant key -- the switch there is which
	// constructor gets called, not a boolean in config. A former
	// MultiTenantConfig section here (Enabled, DefaultTenantID,
	// TenantIsolation) was validated and defaulted but never read by
	// anything; it was deleted rather than wired, since nothing in the
	// codebase gave DefaultTenantID or TenantIsolation runtime meaning
	// (go-xkms#946).

	// Audit configures the audit trail recording every issuance, revocation,
	// account, and enrollment decision. DefaultTrustedCAConfig enables it; the
	// admin API's GET /admin/audit reads back exactly this trail. LogPath is
	// left empty by DefaultTrustedCAConfig and resolved against DataDir by
	// Validate.
	Audit audit.Config `yaml:"audit" json:"audit"`
}

// DefaultAuditLogFileName is the audit trail file name created inside
// DataDir by a TrustedCA that did not have Audit.LogPath configured
// explicitly.
const DefaultAuditLogFileName = "trusted-ca-audit.log"

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

	// CAIdentifiers are the issuer domain names this CA is known by in CAA
	// (RFC 8659) issue/issuewild records — advertised in the directory meta
	// object per RFC 8555 Section 9.7.6, and the identities order finalize
	// checks a domain's CAA RRset against before issuing. Required: see
	// TCAACMEConfig.Validate.
	CAIdentifiers []string `yaml:"ca_identifiers" json:"ca_identifiers"`

	// CAADNSServer optionally pins the recursive resolver (host:port, e.g.
	// "8.8.8.8:53") used for CAA lookups at order finalize. Empty uses the
	// same default resolver the dns-01 challenge tooling uses
	// (pkg/acme/challenges/dns-01/providers.DefaultNameservers).
	CAADNSServer string `yaml:"caa_dns_server" json:"caa_dns_server"`

	// SupportedChallenges lists the supported challenge types.
	SupportedChallenges []string `yaml:"supported_challenges" json:"supported_challenges"`

	// TLS holds TLS configuration (TLS 1.3 enforced by default).
	TLS TCATLSConfig `yaml:"tls" json:"tls"`

	// AllowLoopbackIdentifier permits an authorization's permanent-identifier
	// to be the loopback address 127.0.0.1 for enrollment challenges
	// (enroll-01/endorse-01/device-attest-01), substituting the request's
	// client IP as the validation target. This supports local development
	// and testing; it is a development switch and is off by default. See
	// handlers.Params.AllowLoopbackIdentifier (#140).
	AllowLoopbackIdentifier bool `yaml:"allow_loopback_identifier" json:"allow_loopback_identifier"`
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
		// The audit trail is a compliance control, so it is on by default and
		// has to be switched off deliberately. LogPath is left empty here:
		// Validate resolves it against DataDir (or rejects the config if
		// DataDir is also unset), so the caller sees a typed error instead
		// of a cwd-relative log file (go-xkms#929).
		Audit: audit.Config{
			Enabled:              true,
			MaxSizeMB:            100,
			MaxAgeDays:           365,
			MaxBackups:           10,
			Format:               "json",
			BufferSize:           100,
			FlushIntervalSeconds: 5,
		},
	}
}

// Validate validates the entire TrustedCA configuration by delegating
// to each sub-config's Validate method. A nil receiver is rejected rather
// than dereferenced: WithConfig(nil) is a caller error New must fail
// closed on, not a panic (go-xkms#938).
func (c *TrustedCAConfig) Validate() error {
	if c == nil {
		return errors.MalformedError("config is required")
	}
	if err := c.ACME.Validate(); err != nil {
		return err
	}
	if err := c.CA.Validate(); err != nil {
		return err
	}
	if err := c.resolveAuditLogPath(); err != nil {
		return err
	}
	if err := c.Audit.Validate(); err != nil {
		return err
	}
	if err := c.Admin.Validate(); err != nil {
		return err
	}
	return nil
}

// resolveAuditLogPath derives Audit.LogPath from DataDir when the operator
// enabled the audit trail but did not set Audit.LogPath explicitly,
// mirroring pkg/config.ACMEAuditConfig.ResolveLogPath -- the same
// DataDir-relative pattern xkmsd's embedded ACME server uses for its own
// audit trail. A disabled trail needs no path at all. DataDir is required
// to derive the default: there is no cwd-relative fallback (go-xkms#929).
func (c *TrustedCAConfig) resolveAuditLogPath() error {
	if !c.Audit.Enabled || c.Audit.LogPath != "" {
		return nil
	}
	if c.DataDir == "" {
		return errors.MalformedError(
			"data_dir is required to resolve audit.logPath when audit.enabled is true and audit.logPath is not set")
	}
	c.Audit.LogPath = filepath.Join(c.DataDir, DefaultAuditLogFileName)
	return nil
}

// Validate validates the ACME server configuration.
// HTTPSAddr is required.
//
// ExternalURL is optional: TrustedCA.Serve derives an origin from the
// listen address (AdvertisedURL) when neither the WithExternalURL option nor
// this field is set, so a bind-address-only deployment is a config Validate
// must accept (go-xkms#140). When ExternalURL is set, it must be a valid
// HTTPS URL with a host: Validate cannot see whether WithExternalURL will
// supply a value at construction time, so it only enforces the format of
// what the operator actually wrote here.
//
// CAIdentifiers is required: RFC 8555 Section 8.1 requires this CA to check
// CAA (RFC 8659) records before issuing, and without at least one identity
// the CA has nothing to compare a domain's issue/issuewild record against.
func (a *TCAACMEConfig) Validate() error {
	if a.HTTPSAddr == "" {
		return errors.MalformedError("acme.https_addr is required")
	}
	if a.ExternalURL != "" {
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
	}
	if len(a.CAIdentifiers) == 0 {
		return errors.MalformedError("acme.ca_identifiers is required")
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
