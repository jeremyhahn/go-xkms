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
// Certificate profiles encapsulate standard configurations for different certificate
// types, defining key usage, extended key usage, validity periods, and other X.509
// attributes. The profile system allows both built-in profiles for common use cases
// and custom profiles for application-specific requirements.
//
// # Built-in Profiles
//
// The package includes standard profiles for common certificate types:
//
//   - server: TLS server authentication certificates
//   - client: TLS client authentication certificates
//   - code-signing: Code signing certificates
//   - email: S/MIME email protection certificates
//   - ocsp-responder: OCSP response signing certificates
//   - timestamping: Timestamp authority certificates
//   - ca: Subordinate CA certificates
//
// # Custom Profiles
//
// Custom profiles can be created using the BaseProfile type with functional options:
//
//	profile := profiles.NewBaseProfile("my-custom-profile",
//	    profiles.WithDescription("Custom profile for internal services"),
//	    profiles.WithKeyUsage(x509.KeyUsageDigitalSignature),
//	    profiles.WithExtKeyUsage(x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth),
//	    profiles.WithValidity(90),
//	)
//
//	registry := profiles.NewRegistry()
//	if err := registry.Register(profile); err != nil {
//	    log.Fatal(err)
//	}
//
// # Thread Safety
//
// The Registry is safe for concurrent use by multiple goroutines. Profile
// implementations must also be thread-safe as they may be accessed concurrently
// during certificate issuance.
//
// # Example: Creating a Custom Registry
//
//	func createCustomRegistry() *profiles.Registry {
//	    registry := profiles.NewRegistry()
//
//	    // Register built-in profiles
//	    registry.Register(profiles.NewBaseProfile("server",
//	        profiles.WithDescription("TLS server authentication"),
//	        profiles.WithKeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment),
//	        profiles.WithExtKeyUsage(x509.ExtKeyUsageServerAuth),
//	        profiles.WithValidity(365),
//	    ))
//
//	    // Register custom profile
//	    registry.Register(profiles.NewBaseProfile("api-gateway",
//	        profiles.WithDescription("API gateway mutual TLS"),
//	        profiles.WithKeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment),
//	        profiles.WithExtKeyUsage(x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth),
//	        profiles.WithValidity(180),
//	    ))
//
//	    return registry
//	}
package profiles

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// =============================================================================
// Errors
// =============================================================================

// Error variables for profile operations.
var (
	// ErrProfileNotFound indicates the requested profile does not exist in the registry.
	ErrProfileNotFound = errors.New("profiles: profile not found")

	// ErrProfileExists indicates a profile with the same name is already registered.
	ErrProfileExists = errors.New("profiles: profile already registered")

	// ErrInvalidProfile indicates the profile is nil or has invalid configuration.
	ErrInvalidProfile = errors.New("profiles: invalid profile")
)

// =============================================================================
// ProfileProvider Interface
// =============================================================================

// ProfileProvider defines a certificate profile that can be applied to certificate templates.
//
// A profile encapsulates the standard configuration for a specific certificate type,
// including key usage flags, extended key usage purposes, validity periods, and
// optional custom extensions. Profiles provide a consistent and reusable way to
// configure certificates for specific use cases.
//
// Implementations must be thread-safe as profiles may be accessed concurrently
// during certificate issuance operations.
//
// # Implementation Guidelines
//
// Custom profile implementations should:
//   - Return consistent values for all getter methods
//   - Validate template parameters in Apply before modification
//   - Use atomic operations or immutable state for thread safety
//   - Document any special requirements or constraints
type ProfileProvider interface {
	// Name returns the unique identifier for this profile.
	//
	// Profile names should be lowercase with hyphens for multi-word names
	// (e.g., "code-signing", "ocsp-responder"). Names are case-insensitive
	// when used with the Registry.
	//
	// Thread-safe: Yes
	Name() string

	// Apply modifies a certificate template according to the profile's rules.
	//
	// This method sets the KeyUsage, ExtKeyUsage, and any custom extensions
	// on the provided template. For CA profiles, it also sets IsCA and
	// BasicConstraintsValid to true.
	//
	// The template parameter must not be nil. Implementations should validate
	// the template and return ErrInvalidProfile if it cannot be configured.
	//
	// Thread-safe: Yes
	Apply(template *x509.Certificate) error

	// KeyUsage returns the key usage flags for this profile.
	//
	// Key usage flags are defined in x509.KeyUsage and indicate the
	// cryptographic operations the certificate key is authorized for.
	//
	// Thread-safe: Yes
	KeyUsage() x509.KeyUsage

	// ExtKeyUsage returns the extended key usage for this profile.
	//
	// Extended key usage values specify the purposes for which the
	// certificate may be used (e.g., server auth, client auth, code signing).
	//
	// Thread-safe: Yes
	ExtKeyUsage() []x509.ExtKeyUsage

	// DefaultValidity returns the default validity period in days.
	//
	// This value is used when a certificate request does not specify
	// an explicit validity period. Different profile types have different
	// recommended validity periods based on security best practices.
	//
	// Thread-safe: Yes
	DefaultValidity() int

	// Description returns a human-readable description of the profile.
	//
	// The description explains the intended use case for the profile
	// and any special considerations for its use.
	//
	// Thread-safe: Yes
	Description() string

	// IsCA returns true if this profile is for CA certificates.
	//
	// CA profiles set the IsCA flag and BasicConstraintsValid on the
	// certificate template. Non-CA profiles leave these flags unset.
	//
	// Thread-safe: Yes
	IsCA() bool

	// PathLenConstraint returns the path length constraint for CA certificates.
	//
	// The path length constraint limits the number of intermediate CAs
	// that can appear below this CA in the certificate chain.
	//
	// Returns -1 if no path length constraint should be set (unlimited).
	// Returns 0 to prevent any subordinate CAs.
	// Returns n to allow up to n subordinate CAs.
	//
	// This value is only meaningful when IsCA() returns true.
	//
	// Thread-safe: Yes
	PathLenConstraint() int
}

// =============================================================================
// Registry
// =============================================================================

// Registry manages a collection of named certificate profiles.
//
// The registry provides thread-safe registration, lookup, and enumeration
// of profiles. It supports dynamic registration and unregistration of
// profiles at runtime.
//
// Profile names are case-insensitive and normalized to lowercase during
// registration and lookup.
//
// # Example Usage
//
//	registry := profiles.NewRegistry()
//
//	// Register a custom profile
//	profile := profiles.NewBaseProfile("internal-service",
//	    profiles.WithDescription("Internal microservice certificate"),
//	    profiles.WithKeyUsage(x509.KeyUsageDigitalSignature),
//	    profiles.WithExtKeyUsage(x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth),
//	    profiles.WithValidity(90),
//	)
//	if err := registry.Register(profile); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Look up a profile
//	p, err := registry.Get("internal-service")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// List all profiles
//	names := registry.List()
//	for _, name := range names {
//	    fmt.Println(name)
//	}
type Registry struct {
	profiles atomic.Pointer[map[string]ProfileProvider]
	mu       sync.Mutex
}

// NewRegistry creates a new empty profile registry.
//
// The returned registry has no profiles registered. Use Register to add
// profiles, or use DefaultRegistry to get a registry with standard
// profiles pre-registered.
func NewRegistry() *Registry {
	r := &Registry{}
	profiles := make(map[string]ProfileProvider)
	r.profiles.Store(&profiles)
	return r
}

// Register registers a profile with the registry.
//
// The profile is registered using its Name() as the key. Profile names
// are normalized to lowercase for case-insensitive lookup.
//
// If a profile with the same name already exists, ErrProfileExists is
// returned. Use Unregister first if you need to replace an existing profile.
//
// Returns ErrInvalidProfile if the profile is nil or has an empty name.
//
// Thread-safe: Yes
func (r *Registry) Register(profile ProfileProvider) error {
	if profile == nil {
		return ErrInvalidProfile
	}

	name := strings.ToLower(strings.TrimSpace(profile.Name()))
	if name == "" {
		return ErrInvalidProfile
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	currentProfiles := *r.profiles.Load()
	if _, exists := currentProfiles[name]; exists {
		return ErrProfileExists
	}

	// Create a new map with the added profile (copy-on-write)
	newProfiles := make(map[string]ProfileProvider, len(currentProfiles)+1)
	for k, v := range currentProfiles {
		newProfiles[k] = v
	}
	newProfiles[name] = profile
	r.profiles.Store(&newProfiles)

	return nil
}

// Get returns a profile by name.
//
// Profile names are case-insensitive. The name is normalized to lowercase
// before lookup.
//
// Returns ErrProfileNotFound if no profile with the given name exists.
//
// Thread-safe: Yes
func (r *Registry) Get(name string) (ProfileProvider, error) {
	normalizedName := strings.ToLower(strings.TrimSpace(name))
	if normalizedName == "" {
		return nil, ErrProfileNotFound
	}

	profiles := *r.profiles.Load()
	profile, exists := profiles[normalizedName]
	if !exists {
		return nil, ErrProfileNotFound
	}

	return profile, nil
}

// List returns all registered profile names in sorted order.
//
// The returned slice contains the normalized (lowercase) profile names,
// sorted alphabetically. The slice is a copy and may be safely modified.
//
// Thread-safe: Yes
func (r *Registry) List() []string {
	profiles := *r.profiles.Load()

	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}

	sort.Strings(names)
	return names
}

// Unregister removes a profile from the registry.
//
// Profile names are case-insensitive. The name is normalized to lowercase
// before removal.
//
// Returns ErrProfileNotFound if no profile with the given name exists.
//
// Thread-safe: Yes
func (r *Registry) Unregister(name string) error {
	normalizedName := strings.ToLower(strings.TrimSpace(name))
	if normalizedName == "" {
		return ErrProfileNotFound
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	currentProfiles := *r.profiles.Load()
	if _, exists := currentProfiles[normalizedName]; !exists {
		return ErrProfileNotFound
	}

	// Create a new map without the removed profile (copy-on-write)
	newProfiles := make(map[string]ProfileProvider, len(currentProfiles)-1)
	for k, v := range currentProfiles {
		if k != normalizedName {
			newProfiles[k] = v
		}
	}
	r.profiles.Store(&newProfiles)

	return nil
}

// Has returns true if a profile with the given name is registered.
//
// Profile names are case-insensitive. The name is normalized to lowercase
// before lookup.
//
// Thread-safe: Yes
func (r *Registry) Has(name string) bool {
	normalizedName := strings.ToLower(strings.TrimSpace(name))
	if normalizedName == "" {
		return false
	}

	profiles := *r.profiles.Load()
	_, exists := profiles[normalizedName]
	return exists
}

// Count returns the number of registered profiles.
//
// Thread-safe: Yes
func (r *Registry) Count() int {
	profiles := *r.profiles.Load()
	return len(profiles)
}

// =============================================================================
// BaseProfile
// =============================================================================

// BaseProfile provides a common implementation for simple certificate profiles.
//
// BaseProfile can be used directly for most certificate profile needs or
// embedded in custom profile types that require additional behavior.
//
// # Creating a Profile
//
// Use NewBaseProfile with functional options to create a profile:
//
//	profile := profiles.NewBaseProfile("api-server",
//	    profiles.WithDescription("API server TLS certificate"),
//	    profiles.WithKeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment),
//	    profiles.WithExtKeyUsage(x509.ExtKeyUsageServerAuth),
//	    profiles.WithValidity(365),
//	)
//
// # CA Profiles
//
// Use WithCA to create a CA certificate profile:
//
//	caProfile := profiles.NewBaseProfile("intermediate-ca",
//	    profiles.WithDescription("Intermediate Certificate Authority"),
//	    profiles.WithCA(0),  // pathLen=0 means no further subordinate CAs
//	    profiles.WithValidity(1825),  // 5 years
//	)
//
// # Custom Extensions
//
// Use WithExtensions to add custom X.509 extensions:
//
//	ext := pkix.Extension{
//	    Id:       asn1.ObjectIdentifier{1, 2, 3, 4},
//	    Critical: false,
//	    Value:    []byte("custom data"),
//	}
//	profile := profiles.NewBaseProfile("custom",
//	    profiles.WithExtensions(ext),
//	)
type BaseProfile struct {
	name              string
	description       string
	keyUsage          x509.KeyUsage
	extKeyUsage       []x509.ExtKeyUsage
	defaultValidity   int
	isCA              bool
	pathLenConstraint int
	extensions        []pkix.Extension
}

// NewBaseProfile creates a new BaseProfile with the given name and options.
//
// The name is used to identify the profile in the registry. Options can be
// used to configure key usage, extended key usage, validity period, and
// other profile attributes.
//
// Default values if no options are provided:
//   - description: empty string
//   - keyUsage: 0 (no key usage)
//   - extKeyUsage: nil (no extended key usage)
//   - defaultValidity: 365 days
//   - isCA: false
//   - pathLenConstraint: -1 (no constraint)
//   - extensions: nil
func NewBaseProfile(name string, opts ...ProfileOption) *BaseProfile {
	p := &BaseProfile{
		name:              name,
		defaultValidity:   365,
		pathLenConstraint: -1,
	}

	for _, opt := range opts {
		opt(p)
	}

	return p
}

// Name returns the profile name.
func (p *BaseProfile) Name() string {
	return p.name
}

// Description returns the profile description.
func (p *BaseProfile) Description() string {
	return p.description
}

// KeyUsage returns the key usage flags for this profile.
func (p *BaseProfile) KeyUsage() x509.KeyUsage {
	return p.keyUsage
}

// ExtKeyUsage returns the extended key usage for this profile.
//
// The returned slice is a copy to prevent modification.
func (p *BaseProfile) ExtKeyUsage() []x509.ExtKeyUsage {
	if p.extKeyUsage == nil {
		return nil
	}
	result := make([]x509.ExtKeyUsage, len(p.extKeyUsage))
	copy(result, p.extKeyUsage)
	return result
}

// DefaultValidity returns the default validity period in days.
func (p *BaseProfile) DefaultValidity() int {
	return p.defaultValidity
}

// IsCA returns true if this is a CA certificate profile.
func (p *BaseProfile) IsCA() bool {
	return p.isCA
}

// PathLenConstraint returns the path length constraint.
//
// Returns -1 if no constraint is set.
func (p *BaseProfile) PathLenConstraint() int {
	return p.pathLenConstraint
}

// Extensions returns the custom extensions for this profile.
//
// The returned slice is a copy to prevent modification.
func (p *BaseProfile) Extensions() []pkix.Extension {
	if p.extensions == nil {
		return nil
	}
	result := make([]pkix.Extension, len(p.extensions))
	copy(result, p.extensions)
	return result
}

// Apply modifies a certificate template according to the profile's configuration.
//
// This method sets the following template fields:
//   - KeyUsage: Set to the profile's key usage flags
//   - ExtKeyUsage: Set to the profile's extended key usage
//   - ExtraExtensions: Appended with the profile's custom extensions
//   - IsCA: Set to true if this is a CA profile
//   - BasicConstraintsValid: Set to true if this is a CA profile
//   - MaxPathLen: Set to the path length constraint for CA profiles
//   - MaxPathLenZero: Set to true if pathLen is 0 for CA profiles
//
// Returns ErrInvalidProfile if the template is nil.
func (p *BaseProfile) Apply(template *x509.Certificate) error {
	if template == nil {
		return ErrInvalidProfile
	}

	template.KeyUsage = p.keyUsage
	template.ExtKeyUsage = p.extKeyUsage

	if len(p.extensions) > 0 {
		template.ExtraExtensions = append(template.ExtraExtensions, p.extensions...)
	}

	if p.isCA {
		template.IsCA = true
		template.BasicConstraintsValid = true

		if p.pathLenConstraint >= 0 {
			template.MaxPathLen = p.pathLenConstraint
			template.MaxPathLenZero = p.pathLenConstraint == 0
		}
	}

	return nil
}

// =============================================================================
// Profile Options
// =============================================================================

// ProfileOption is a functional option for configuring a BaseProfile.
type ProfileOption func(*BaseProfile)

// WithDescription sets the profile description.
//
// The description should explain the intended use case for the profile.
func WithDescription(desc string) ProfileOption {
	return func(p *BaseProfile) {
		p.description = desc
	}
}

// WithKeyUsage sets the key usage flags.
//
// Key usage flags can be combined using bitwise OR:
//
//	profiles.WithKeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment)
func WithKeyUsage(ku x509.KeyUsage) ProfileOption {
	return func(p *BaseProfile) {
		p.keyUsage = ku
	}
}

// WithExtKeyUsage sets the extended key usage values.
//
// Multiple values can be provided:
//
//	profiles.WithExtKeyUsage(x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
func WithExtKeyUsage(eku ...x509.ExtKeyUsage) ProfileOption {
	return func(p *BaseProfile) {
		if len(eku) > 0 {
			p.extKeyUsage = make([]x509.ExtKeyUsage, len(eku))
			copy(p.extKeyUsage, eku)
		}
	}
}

// WithValidity sets the default validity period in days.
//
// The validity period must be positive. A value of 0 or negative
// will result in the default validity of 365 days being used.
func WithValidity(days int) ProfileOption {
	return func(p *BaseProfile) {
		if days > 0 {
			p.defaultValidity = days
		}
	}
}

// WithCA configures the profile for CA certificates.
//
// The pathLen parameter specifies the path length constraint:
//   - pathLen < 0: No path length constraint (unlimited subordinate CAs)
//   - pathLen = 0: No subordinate CAs allowed
//   - pathLen > 0: Up to pathLen subordinate CAs allowed
//
// This option also automatically adds CertSign and CRLSign to the key usage.
func WithCA(pathLen int) ProfileOption {
	return func(p *BaseProfile) {
		p.isCA = true
		p.pathLenConstraint = pathLen
		p.keyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
}

// WithExtensions adds custom X.509 extensions to the profile.
//
// Extensions are appended to the certificate template's ExtraExtensions
// during Apply. Multiple calls to WithExtensions will accumulate extensions.
func WithExtensions(ext ...pkix.Extension) ProfileOption {
	return func(p *BaseProfile) {
		if len(ext) > 0 {
			p.extensions = append(p.extensions, ext...)
		}
	}
}

// =============================================================================
// Default Registry
// =============================================================================

// defaultRegistryOnce ensures the default registry is created only once.
var (
	defaultRegistryOnce sync.Once
	defaultRegistry     *Registry
)

// DefaultRegistry returns a registry with all standard profiles pre-registered.
//
// The default registry includes the following built-in profiles:
//
//   - server: TLS server authentication (365 days)
//   - client: TLS client authentication (365 days)
//   - code-signing: Code signing operations (365 days)
//   - email: S/MIME email protection (365 days)
//   - ocsp-responder: OCSP response signing (90 days)
//   - timestamping: Timestamp authority (365 days)
//   - ca: Subordinate CA certificates (1825 days / 5 years)
//
// The returned registry is a shared singleton. Modifications to the registry
// will affect all callers. Use NewRegistry() if you need an isolated registry.
//
// Thread-safe: Yes
func DefaultRegistry() *Registry {
	defaultRegistryOnce.Do(func() {
		defaultRegistry = NewRegistry()
		registerStandardProfiles(defaultRegistry)
	})
	return defaultRegistry
}

// registerStandardProfiles registers all built-in certificate profiles.
func registerStandardProfiles(r *Registry) {
	profiles := []ProfileProvider{
		// TLS Server Authentication
		NewBaseProfile("server",
			WithDescription("TLS server authentication certificate"),
			WithKeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment),
			WithExtKeyUsage(x509.ExtKeyUsageServerAuth),
			WithValidity(365),
		),

		// TLS Client Authentication
		NewBaseProfile("client",
			WithDescription("TLS client authentication certificate"),
			WithKeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment),
			WithExtKeyUsage(x509.ExtKeyUsageClientAuth),
			WithValidity(365),
		),

		// Code Signing
		NewBaseProfile("code-signing",
			WithDescription("Code signing certificate for software distribution"),
			WithKeyUsage(x509.KeyUsageDigitalSignature),
			WithExtKeyUsage(x509.ExtKeyUsageCodeSigning),
			WithValidity(365),
		),

		// S/MIME Email Protection
		NewBaseProfile("email",
			WithDescription("S/MIME email protection certificate"),
			WithKeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment|x509.KeyUsageKeyEncipherment),
			WithExtKeyUsage(x509.ExtKeyUsageEmailProtection),
			WithValidity(365),
		),

		// OCSP Responder
		NewBaseProfile("ocsp-responder",
			WithDescription("OCSP response signing certificate"),
			WithKeyUsage(x509.KeyUsageDigitalSignature),
			WithExtKeyUsage(x509.ExtKeyUsageOCSPSigning),
			WithValidity(90),
		),

		// Timestamping
		NewBaseProfile("timestamping",
			WithDescription("Timestamp authority certificate"),
			WithKeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment),
			WithExtKeyUsage(x509.ExtKeyUsageTimeStamping),
			WithValidity(365),
		),

		// Subordinate CA
		NewBaseProfile("ca",
			WithDescription("Subordinate Certificate Authority"),
			WithKeyUsage(x509.KeyUsageDigitalSignature),
			WithCA(0),
			WithValidity(1825),
		),
	}

	for _, profile := range profiles {
		// Ignore errors during registration of standard profiles
		// as they should never fail with valid profile definitions
		_ = r.Register(profile)
	}
}
