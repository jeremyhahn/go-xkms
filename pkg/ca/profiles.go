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

// Package ca provides certificate profile management.
//
// Profiles encapsulate standard certificate configurations for different use cases.
// Each profile specifies key usage, extended key usage, validity periods, and other
// certificate attributes appropriate for its intended purpose.
package ca

import (
	"crypto/x509"
	"sort"
	"strings"
	"sync"
)

// =============================================================================
// Default Profile Registry
// =============================================================================

// defaultProfileRegistry implements ProfileRegistry with built-in certificate profiles.
type defaultProfileRegistry struct {
	profiles map[string]ProfileProvider
	mu       sync.RWMutex
}

// NewDefaultProfileRegistry creates a ProfileRegistry with standard built-in profiles.
//
// Built-in profiles include:
//   - server: TLS server authentication
//   - client: TLS client authentication
//   - code-signing: Code signing operations
//   - email: S/MIME email protection
//   - ocsp-responder: OCSP response signing
//   - timestamping: Timestamp authority
//   - ca: Certificate Authority (subordinate CA)
//
// Thread-safe: Yes
func NewDefaultProfileRegistry() ProfileRegistry {
	registry := &defaultProfileRegistry{
		profiles: make(map[string]ProfileProvider),
	}

	// Register built-in profiles
	registry.registerBuiltinProfiles()

	return registry
}

// registerBuiltinProfiles registers all built-in certificate profiles.
func (r *defaultProfileRegistry) registerBuiltinProfiles() {
	profiles := []ProfileProvider{
		NewServerProfile(),
		NewClientProfile(),
		NewCodeSigningProfile(),
		NewEmailProfile(),
		NewOCSPResponderProfile(),
		NewTimestampingProfile(),
		NewCAProfile(),
	}

	for _, profile := range profiles {
		r.profiles[strings.ToLower(profile.Name())] = profile
	}
}

// Register registers a profile with the given name.
//
// If a profile with the same name already exists, it is replaced.
// Profile names are case-insensitive and normalized to lowercase.
//
// Returns ErrInvalidProfile if the profile is nil or invalid.
//
// Thread-safe: Yes
func (r *defaultProfileRegistry) Register(name string, profile ProfileProvider) error {
	if profile == nil {
		return ErrInvalidProfile
	}

	normalizedName := strings.ToLower(strings.TrimSpace(name))
	if normalizedName == "" {
		return ErrInvalidProfile
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.profiles[normalizedName] = profile
	return nil
}

// Get returns a profile by name.
//
// Profile names are case-insensitive.
//
// Returns ErrProfileNotFound if no profile with the given name exists.
//
// Thread-safe: Yes
func (r *defaultProfileRegistry) Get(name string) (ProfileProvider, error) {
	normalizedName := strings.ToLower(strings.TrimSpace(name))

	r.mu.RLock()
	defer r.mu.RUnlock()

	profile, exists := r.profiles[normalizedName]
	if !exists {
		return nil, ErrProfileNotFound
	}

	return profile, nil
}

// List returns all registered profile names.
//
// The returned slice is sorted alphabetically and contains the
// normalized (lowercase) profile names.
//
// Thread-safe: Yes
func (r *defaultProfileRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.profiles))
	for name := range r.profiles {
		names = append(names, name)
	}

	sort.Strings(names)
	return names
}

// =============================================================================
// Base Profile Implementation
// =============================================================================

// baseProfile provides a base implementation for certificate profiles.
type baseProfile struct {
	name            string
	keyUsage        x509.KeyUsage
	extKeyUsage     []x509.ExtKeyUsage
	defaultValidity int
}

// Name returns the profile name.
func (p *baseProfile) Name() string {
	return p.name
}

// KeyUsage returns the key usage for this profile.
func (p *baseProfile) KeyUsage() x509.KeyUsage {
	return p.keyUsage
}

// ExtKeyUsage returns the extended key usage for this profile.
func (p *baseProfile) ExtKeyUsage() []x509.ExtKeyUsage {
	return p.extKeyUsage
}

// DefaultValidity returns the default validity period in days.
func (p *baseProfile) DefaultValidity() int {
	return p.defaultValidity
}

// Apply applies the profile to a certificate template.
//
// This method modifies the certificate template in place, setting
// key usage, extended key usage, and other profile-specific attributes.
func (p *baseProfile) Apply(template *x509.Certificate, request *CertificateRequest) error {
	if template == nil {
		return ErrInvalidProfile
	}

	template.KeyUsage = p.keyUsage
	template.ExtKeyUsage = p.extKeyUsage

	return nil
}

// =============================================================================
// Built-in Certificate Profiles
// =============================================================================

// serverProfile provides configuration for TLS server certificates.
type serverProfile struct {
	baseProfile
}

// NewServerProfile creates a profile for TLS server authentication certificates.
//
// Key usage:
//   - DigitalSignature
//   - KeyEncipherment
//
// Extended key usage:
//   - ServerAuth
//
// Default validity: 365 days
func NewServerProfile() ProfileProvider {
	return &serverProfile{
		baseProfile: baseProfile{
			name:            "server",
			keyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			extKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			defaultValidity: 365,
		},
	}
}

// clientProfile provides configuration for TLS client certificates.
type clientProfile struct {
	baseProfile
}

// NewClientProfile creates a profile for TLS client authentication certificates.
//
// Key usage:
//   - DigitalSignature
//   - KeyEncipherment
//
// Extended key usage:
//   - ClientAuth
//
// Default validity: 365 days
func NewClientProfile() ProfileProvider {
	return &clientProfile{
		baseProfile: baseProfile{
			name:            "client",
			keyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			extKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			defaultValidity: 365,
		},
	}
}

// codeSigningProfile provides configuration for code signing certificates.
type codeSigningProfile struct {
	baseProfile
}

// NewCodeSigningProfile creates a profile for code signing certificates.
//
// Key usage:
//   - DigitalSignature
//
// Extended key usage:
//   - CodeSigning
//
// Default validity: 365 days
func NewCodeSigningProfile() ProfileProvider {
	return &codeSigningProfile{
		baseProfile: baseProfile{
			name:            "code-signing",
			keyUsage:        x509.KeyUsageDigitalSignature,
			extKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			defaultValidity: 365,
		},
	}
}

// emailProfile provides configuration for S/MIME email certificates.
type emailProfile struct {
	baseProfile
}

// NewEmailProfile creates a profile for S/MIME email protection certificates.
//
// Key usage:
//   - DigitalSignature
//   - ContentCommitment (nonRepudiation)
//   - KeyEncipherment
//
// Extended key usage:
//   - EmailProtection
//
// Default validity: 365 days
func NewEmailProfile() ProfileProvider {
	return &emailProfile{
		baseProfile: baseProfile{
			name:            "email",
			keyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment,
			extKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
			defaultValidity: 365,
		},
	}
}

// ocspResponderProfile provides configuration for OCSP responder certificates.
type ocspResponderProfile struct {
	baseProfile
}

// NewOCSPResponderProfile creates a profile for OCSP response signing certificates.
//
// Key usage:
//   - DigitalSignature
//
// Extended key usage:
//   - OCSPSigning
//
// Default validity: 90 days (OCSP responder certs are typically short-lived)
func NewOCSPResponderProfile() ProfileProvider {
	return &ocspResponderProfile{
		baseProfile: baseProfile{
			name:            "ocsp-responder",
			keyUsage:        x509.KeyUsageDigitalSignature,
			extKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
			defaultValidity: 90,
		},
	}
}

// timestampingProfile provides configuration for timestamping certificates.
type timestampingProfile struct {
	baseProfile
}

// NewTimestampingProfile creates a profile for timestamp authority certificates.
//
// Key usage:
//   - DigitalSignature
//   - ContentCommitment (nonRepudiation)
//
// Extended key usage:
//   - TimeStamping
//
// Default validity: 365 days
func NewTimestampingProfile() ProfileProvider {
	return &timestampingProfile{
		baseProfile: baseProfile{
			name:            "timestamping",
			keyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
			extKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
			defaultValidity: 365,
		},
	}
}

// caProfile provides configuration for subordinate CA certificates.
type caProfile struct {
	baseProfile
}

// NewCAProfile creates a profile for subordinate CA certificates.
//
// Key usage:
//   - CertSign
//   - CRLSign
//   - DigitalSignature
//
// Extended key usage: (none - CA certificates don't need EKU)
//
// Default validity: 1825 days (5 years)
func NewCAProfile() ProfileProvider {
	return &caProfile{
		baseProfile: baseProfile{
			name:            "ca",
			keyUsage:        x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
			extKeyUsage:     nil,
			defaultValidity: 1825, // 5 years
		},
	}
}

// Apply applies the CA profile to a certificate template.
// This overrides the base implementation to set IsCA and BasicConstraintsValid.
func (p *caProfile) Apply(template *x509.Certificate, request *CertificateRequest) error {
	if template == nil {
		return ErrInvalidProfile
	}

	template.KeyUsage = p.keyUsage
	template.ExtKeyUsage = p.extKeyUsage
	template.IsCA = true
	template.BasicConstraintsValid = true

	// Set path length from request if specified
	if request != nil {
		template.MaxPathLen = request.MaxPathLen
		template.MaxPathLenZero = request.MaxPathLenZero
	}

	return nil
}

// =============================================================================
// Custom Profile Builder
// =============================================================================

// ProfileBuilder provides a fluent interface for creating custom profiles.
type ProfileBuilder struct {
	name            string
	keyUsage        x509.KeyUsage
	extKeyUsage     []x509.ExtKeyUsage
	defaultValidity int
	isCA            bool
}

// NewProfileBuilder creates a new ProfileBuilder for creating custom profiles.
func NewProfileBuilder(name string) *ProfileBuilder {
	return &ProfileBuilder{
		name:            name,
		defaultValidity: 365, // Default to 1 year
	}
}

// WithKeyUsage sets the key usage flags.
func (b *ProfileBuilder) WithKeyUsage(usage x509.KeyUsage) *ProfileBuilder {
	b.keyUsage = usage
	return b
}

// WithExtKeyUsage sets the extended key usage values.
func (b *ProfileBuilder) WithExtKeyUsage(usage ...x509.ExtKeyUsage) *ProfileBuilder {
	b.extKeyUsage = usage
	return b
}

// WithDefaultValidity sets the default validity period in days.
func (b *ProfileBuilder) WithDefaultValidity(days int) *ProfileBuilder {
	b.defaultValidity = days
	return b
}

// AsCA marks this profile as a CA profile.
func (b *ProfileBuilder) AsCA() *ProfileBuilder {
	b.isCA = true
	b.keyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	return b
}

// Build creates the ProfileProvider from the builder configuration.
func (b *ProfileBuilder) Build() ProfileProvider {
	if b.isCA {
		return &customCAProfile{
			baseProfile: baseProfile{
				name:            b.name,
				keyUsage:        b.keyUsage,
				extKeyUsage:     b.extKeyUsage,
				defaultValidity: b.defaultValidity,
			},
		}
	}

	return &baseProfile{
		name:            b.name,
		keyUsage:        b.keyUsage,
		extKeyUsage:     b.extKeyUsage,
		defaultValidity: b.defaultValidity,
	}
}

// customCAProfile is a custom CA profile created via the builder.
type customCAProfile struct {
	baseProfile
}

// Apply applies the custom CA profile to a certificate template.
func (p *customCAProfile) Apply(template *x509.Certificate, request *CertificateRequest) error {
	if template == nil {
		return ErrInvalidProfile
	}

	template.KeyUsage = p.keyUsage
	template.ExtKeyUsage = p.extKeyUsage
	template.IsCA = true
	template.BasicConstraintsValid = true

	if request != nil {
		template.MaxPathLen = request.MaxPathLen
		template.MaxPathLenZero = request.MaxPathLenZero
	}

	return nil
}
