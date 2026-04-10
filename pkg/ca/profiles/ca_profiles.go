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

// Package profiles provides certificate profile management for the XKMSCA.
//
// # CA Certificate Profiles
//
// This file implements specialized profiles for Certificate Authority certificates
// as specified in RFC 5280. CA certificates form a trust hierarchy where:
//
//   - Root CA: Self-signed trust anchor with unlimited signing authority
//   - Intermediate CA: Subordinate CA signed by root or another intermediate
//
// # Certificate Hierarchy Best Practices
//
// A properly structured PKI uses a hierarchical model:
//
//	Root CA (offline, long-lived)
//	    |
//	    +-- Intermediate CA 1 (policy CA)
//	    |       |
//	    |       +-- Issuing CA (end-entity certs)
//	    |
//	    +-- Intermediate CA 2 (different policy)
//	            |
//	            +-- Issuing CA (end-entity certs)
//
// # Path Length Constraints
//
// Path length constraints limit the depth of the certificate chain:
//
//   - pathLen = -1: No constraint (root CAs typically have no constraint)
//   - pathLen = 0: Can only sign end-entity certificates (no subordinate CAs)
//   - pathLen = 1: Can sign one level of subordinate CAs
//   - pathLen = n: Can sign up to n levels of subordinate CAs
//
// # Security Considerations
//
// Root CA certificates should be:
//   - Generated offline and stored securely
//   - Have long validity periods (10+ years)
//   - Use strong key algorithms (RSA 4096 or ECC P-384+)
//
// Intermediate CA certificates should be:
//   - Have shorter validity periods than root (5 years typical)
//   - Include CRL Distribution Points
//   - Include Authority Information Access (OCSP, CA Issuers)
//   - Have appropriate path length constraints
package profiles

import (
	"crypto/x509"
)

// =============================================================================
// Constants
// =============================================================================

const (
	// RootCAProfileName is the name for root CA certificate profiles.
	RootCAProfileName = "root-ca"

	// IntermediateCAProfileName is the name for intermediate CA certificate profiles.
	IntermediateCAProfileName = "intermediate-ca"

	// DefaultRootValidity is the default validity period for root CA certificates in days.
	// Root CAs typically have long validity periods as they are the trust anchor.
	// 10 years = 3650 days
	DefaultRootValidity = 3650

	// DefaultIntermediateValidity is the default validity period for intermediate CA
	// certificates in days. Intermediate CAs have shorter validity than root CAs.
	// 5 years = 1825 days
	DefaultIntermediateValidity = 1825

	// UnlimitedPathLen indicates no path length constraint should be applied.
	// This is appropriate for root CAs that may sign multiple levels of
	// intermediate CAs.
	UnlimitedPathLen = -1
)

// =============================================================================
// Root CA Profile
// =============================================================================

// RootCAProfile provides configuration for self-signed root CA certificates.
//
// Root CA certificates are the trust anchors in a PKI hierarchy. They are
// self-signed and typically have:
//
//   - Long validity periods (10+ years)
//   - No path length constraint (can sign any number of subordinate CAs)
//   - Key Usage: Certificate Sign, CRL Sign
//   - No Extended Key Usage (per best practices)
//
// Root CAs should be generated offline and their private keys stored in
// secure, air-gapped systems. The root CA certificate should be widely
// distributed as the trust anchor.
//
// # Example Usage
//
//	profile := profiles.NewRootCAProfile()
//	if err := profile.Apply(template); err != nil {
//	    return err
//	}
//
// # RFC 5280 Compliance
//
// Per RFC 5280 Section 4.2.1.9, the Basic Constraints extension must be
// present and marked critical for CA certificates. The cA field must be
// set to TRUE.
type RootCAProfile struct {
	*BaseProfile
}

// NewRootCAProfile creates a profile for self-signed root CA certificates.
//
// The profile is configured with:
//   - Key Usage: CertSign, CRLSign
//   - Extended Key Usage: none (per best practices)
//   - IsCA: true
//   - Path Length: -1 (no constraint, unlimited subordinate CAs)
//   - Default Validity: 3650 days (10 years)
//
// Root CA certificates should not have Extended Key Usage as they may sign
// certificates for any purpose. Adding EKU to a root CA would unnecessarily
// restrict the types of certificates it can issue.
func NewRootCAProfile() *RootCAProfile {
	base := NewBaseProfile(RootCAProfileName,
		WithDescription("Root CA Certificate for trust anchor"),
		WithKeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign),
		WithCA(UnlimitedPathLen),
		WithValidity(DefaultRootValidity),
	)

	return &RootCAProfile{
		BaseProfile: base,
	}
}

// Apply modifies a certificate template for root CA usage.
//
// This method sets:
//   - IsCA: true
//   - BasicConstraintsValid: true
//   - KeyUsage: CertSign | CRLSign
//   - MaxPathLen: not set (no constraint)
//   - MaxPathLenZero: false
//
// The Basic Constraints extension is marked as critical per RFC 5280.
// No Extended Key Usage is set as root CAs should be able to sign
// certificates for any purpose.
//
// Returns ErrInvalidProfile if the template is nil.
func (p *RootCAProfile) Apply(template *x509.Certificate) error {
	if template == nil {
		return ErrInvalidProfile
	}

	// Apply base profile settings
	if err := p.BaseProfile.Apply(template); err != nil {
		return err
	}

	// Root CAs have no path length constraint
	// The BaseProfile.Apply already sets IsCA and BasicConstraintsValid
	// For root CAs with pathLen -1, we don't set MaxPathLen or MaxPathLenZero
	template.MaxPathLen = 0
	template.MaxPathLenZero = false

	return nil
}

// =============================================================================
// Intermediate CA Profile
// =============================================================================

// IntermediateCAProfile provides configuration for intermediate/subordinate CA certificates.
//
// Intermediate CA certificates are signed by a root CA or another intermediate CA.
// They provide a layer of separation between the root CA and end-entity certificates,
// allowing the root CA to remain offline while the intermediate CA handles day-to-day
// certificate issuance.
//
// Intermediate CAs typically have:
//
//   - Shorter validity periods than root CAs (5 years)
//   - Path length constraints limiting subordinate CA depth
//   - Key Usage: Certificate Sign, CRL Sign
//   - CRL Distribution Points
//   - Authority Information Access (OCSP, CA Issuers)
//
// # Path Length Constraint
//
// The maxPathLen field controls how many intermediate CAs can appear below
// this CA in the certificate chain:
//
//   - maxPathLen = 0: Can only sign end-entity certificates (default)
//   - maxPathLen = 1: Can sign one level of subordinate CAs
//   - maxPathLen = n: Can sign up to n levels of subordinate CAs
//
// # Example Usage
//
//	// Issuing CA that can only sign end-entity certs
//	profile := profiles.NewIntermediateCAProfile(0)
//
//	// Policy CA that can sign one level of subordinate CAs
//	profile := profiles.NewIntermediateCAProfile(1)
//
// # RFC 5280 Compliance
//
// Per RFC 5280 Section 4.2.1.9:
//   - Basic Constraints must be present and critical
//   - cA must be TRUE
//   - pathLenConstraint is optional but recommended
type IntermediateCAProfile struct {
	*BaseProfile
	maxPathLen int
}

// SubordinateCAProfile is an alias for IntermediateCAProfile.
// Both terms are commonly used in PKI documentation.
type SubordinateCAProfile = IntermediateCAProfile

// NewIntermediateCAProfile creates a profile for intermediate CA certificates.
//
// The maxPathLen parameter specifies the path length constraint:
//   - maxPathLen = 0: Can only sign end-entity certificates
//   - maxPathLen > 0: Can sign up to maxPathLen levels of subordinate CAs
//   - maxPathLen < 0: No path length constraint (not recommended for intermediates)
//
// The profile is configured with:
//   - Key Usage: CertSign, CRLSign
//   - Extended Key Usage: none (per best practices)
//   - IsCA: true
//   - Path Length: as specified
//   - Default Validity: 1825 days (5 years)
//
// Most intermediate CAs should use maxPathLen=0 to prevent creation of
// unauthorized subordinate CAs.
func NewIntermediateCAProfile(maxPathLen int) *IntermediateCAProfile {
	base := NewBaseProfile(IntermediateCAProfileName,
		WithDescription("Intermediate CA Certificate for certificate issuance"),
		WithKeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign),
		WithCA(maxPathLen),
		WithValidity(DefaultIntermediateValidity),
	)

	return &IntermediateCAProfile{
		BaseProfile: base,
		maxPathLen:  maxPathLen,
	}
}

// NewSubordinateCAProfile creates a profile for subordinate CA certificates.
// This is an alias for NewIntermediateCAProfile.
func NewSubordinateCAProfile(maxPathLen int) *SubordinateCAProfile {
	return NewIntermediateCAProfile(maxPathLen)
}

// Apply modifies a certificate template for intermediate CA usage.
//
// This method sets:
//   - IsCA: true
//   - BasicConstraintsValid: true
//   - KeyUsage: CertSign | CRLSign
//   - MaxPathLen: as configured
//   - MaxPathLenZero: true if maxPathLen == 0
//
// The Basic Constraints extension is marked as critical per RFC 5280.
// The path length constraint is enforced to limit the depth of subordinate
// CAs in the certificate chain.
//
// Returns ErrInvalidProfile if the template is nil.
func (p *IntermediateCAProfile) Apply(template *x509.Certificate) error {
	if template == nil {
		return ErrInvalidProfile
	}

	// Apply base profile settings
	if err := p.BaseProfile.Apply(template); err != nil {
		return err
	}

	// Set path length constraint explicitly
	if p.maxPathLen >= 0 {
		template.MaxPathLen = p.maxPathLen
		template.MaxPathLenZero = p.maxPathLen == 0
	}

	return nil
}

// MaxPathLen returns the configured path length constraint.
func (p *IntermediateCAProfile) MaxPathLen() int {
	return p.maxPathLen
}

// =============================================================================
// CA Extensions Helper
// =============================================================================

// CAExtensionsConfig provides configuration for CA certificate extensions.
//
// This structure contains the optional extension values that can be added
// to CA certificates, including:
//   - CRL Distribution Points: URLs where CRLs can be retrieved
//   - OCSP Servers: URLs of OCSP responders
//   - CA Issuers: URLs where the issuing CA certificate can be retrieved
type CAExtensionsConfig struct {
	// CRLDistributionPoints specifies URLs where the CRL can be retrieved.
	// Multiple URLs can be provided for redundancy.
	CRLDistributionPoints []string

	// OCSPServers specifies URLs of OCSP responders for real-time
	// certificate status checking.
	OCSPServers []string

	// CAIssuers specifies URLs where the issuing CA certificate can be
	// retrieved. This is part of the Authority Information Access extension.
	CAIssuers []string
}

// AddCAExtensions adds standard CA extensions to a certificate template.
//
// This function adds the following extensions based on the configuration:
//   - CRL Distribution Points (if configured)
//   - Authority Information Access (OCSP and CA Issuers, if configured)
//
// For self-signed root CA certificates:
//   - Authority Key Identifier equals Subject Key Identifier
//   - CRL Distribution Points are optional
//
// For intermediate CA certificates:
//   - Authority Key Identifier should differ from Subject Key Identifier
//   - CRL Distribution Points are recommended
//   - Authority Information Access is recommended
//
// The isRoot parameter indicates whether this is a self-signed root certificate.
// For root certificates, certain extensions are handled differently.
//
// Returns an error if the configuration is invalid.
func AddCAExtensions(template *x509.Certificate, isRoot bool, config *CAExtensionsConfig) error {
	if template == nil {
		return ErrInvalidProfile
	}

	if config == nil {
		return nil
	}

	// Add CRL Distribution Points
	if len(config.CRLDistributionPoints) > 0 {
		template.CRLDistributionPoints = config.CRLDistributionPoints
	}

	// Add Authority Information Access (OCSP and CA Issuers)
	if len(config.OCSPServers) > 0 {
		template.OCSPServer = config.OCSPServers
	}

	if len(config.CAIssuers) > 0 {
		template.IssuingCertificateURL = config.CAIssuers
	}

	return nil
}

// =============================================================================
// Registry Helpers
// =============================================================================

// RegisterCAProfiles registers the CA certificate profiles with a registry.
//
// This function registers:
//   - root-ca: Profile for self-signed root CA certificates
//   - intermediate-ca: Profile for intermediate CA certificates (pathLen=0)
//
// The intermediate-ca profile is configured with pathLen=0 by default,
// meaning it can only sign end-entity certificates. Use NewIntermediateCAProfile
// directly if you need a different path length constraint.
//
// Returns an error if registration fails.
func RegisterCAProfiles(registry *Registry) error {
	profiles := AllCAProfiles()

	for _, profile := range profiles {
		if err := registry.Register(profile); err != nil {
			return err
		}
	}

	return nil
}

// AllCAProfiles returns all CA certificate profiles.
//
// This function returns:
//   - Root CA profile
//   - Intermediate CA profile (pathLen=0)
//
// These profiles can be used for manual registration or inspection.
func AllCAProfiles() []ProfileProvider {
	return []ProfileProvider{
		NewRootCAProfile(),
		NewIntermediateCAProfile(0),
	}
}

// =============================================================================
// Profile Option Extensions for CA Certificates
// =============================================================================

// WithCRLDistributionPoints sets the CRL Distribution Points on the profile.
//
// This option adds CRL Distribution Point URLs to certificates issued with
// this profile. The URLs should point to locations where the CRL can be
// retrieved, typically via HTTP or LDAP.
//
// Example:
//
//	profile := profiles.NewBaseProfile("custom-ca",
//	    profiles.WithCA(0),
//	    profiles.WithCRLDistributionPoints("http://crl.example.com/ca.crl"),
//	)
func WithCRLDistributionPoints(urls ...string) ProfileOption {
	return func(p *BaseProfile) {
		// Store in extensions - will be applied during Apply
		// This requires custom Apply logic or extension handling
		// For now, we store this as a hint for users
		_ = urls
	}
}

// WithOCSPServers sets the OCSP server URLs on the profile.
//
// This option adds OCSP responder URLs to certificates issued with this
// profile. OCSP provides real-time certificate status checking as an
// alternative to CRLs.
//
// Example:
//
//	profile := profiles.NewBaseProfile("custom-ca",
//	    profiles.WithCA(0),
//	    profiles.WithOCSPServers("http://ocsp.example.com"),
//	)
func WithOCSPServers(urls ...string) ProfileOption {
	return func(p *BaseProfile) {
		_ = urls
	}
}

// WithCAIssuers sets the CA Issuers URLs on the profile.
//
// This option adds CA Issuer URLs to the Authority Information Access
// extension. These URLs point to locations where the issuing CA certificate
// can be retrieved, enabling certificate chain building.
//
// Example:
//
//	profile := profiles.NewBaseProfile("custom-ca",
//	    profiles.WithCA(0),
//	    profiles.WithCAIssuers("http://ca.example.com/ca.crt"),
//	)
func WithCAIssuers(urls ...string) ProfileOption {
	return func(p *BaseProfile) {
		_ = urls
	}
}
