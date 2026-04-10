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

// Package profiles provides certificate profile implementations for the XKMSCA.
//
// # Mutual TLS (mTLS) Certificate Profiles
//
// This file implements mutual TLS certificate profiles for bidirectional
// authentication scenarios. mTLS extends standard TLS by requiring both the
// client and server to present valid certificates, providing stronger security
// guarantees than server-only TLS authentication.
//
// # mTLS Overview
//
// In mutual TLS, both parties verify each other's identity:
//   - The server presents a certificate proving its identity to the client
//   - The client presents a certificate proving its identity to the server
//   - Both certificates must be signed by trusted Certificate Authorities
//
// This bidirectional authentication is critical for zero-trust architectures,
// service mesh deployments, and high-security API communications.
//
// # Profile Types
//
// MTLSClientProfile:
// Used for TLS client authentication where a client needs to prove its identity
// to a server. Common use cases include:
//   - Service-to-service authentication in microservices
//   - API client authentication
//   - Database client connections
//   - VPN client certificates
//
// MTLSServerProfile:
// Used for TLS server authentication in mTLS scenarios. While similar to
// standard TLS server certificates, these are explicitly designed for
// environments where client authentication is also required. Common use cases:
//   - Internal API servers
//   - Service mesh ingress
//   - Secure admin interfaces
//
// MTLSDualProfile:
// Used for certificates that need both client and server authentication
// capabilities. This is common in peer-to-peer scenarios or service mesh
// sidecars where a single identity acts as both client and server:
//   - Service mesh sidecar proxies (Envoy, Linkerd)
//   - Peer-to-peer communication
//   - Bidirectional gRPC services
//   - Database cluster nodes
//
// # Usage
//
//	// Issue an mTLS client certificate
//	profile := profiles.NewMTLSClientProfile()
//	registry.Register(profile.Name(), profile)
//	cert, err := ca.IssueCertificateWithProfile(request, "mtls-client")
//
//	// Issue an mTLS server certificate
//	profile := profiles.NewMTLSServerProfile()
//	registry.Register(profile.Name(), profile)
//	cert, err := ca.IssueCertificateWithProfile(request, "mtls-server")
//
//	// Issue a dual-purpose mTLS certificate
//	profile := profiles.NewMTLSDualProfile()
//	registry.Register(profile.Name(), profile)
//	cert, err := ca.IssueCertificateWithProfile(request, "mtls-dual")
//
// # Security Considerations
//
// Certificate Validity:
// mTLS certificates default to 365-day validity periods. For highly sensitive
// environments, consider shorter validity periods (90 days or less) to limit
// the exposure window if a private key is compromised.
//
// Key Storage:
// Private keys for mTLS certificates should be protected appropriately:
//   - Use hardware security modules (HSMs) for high-value services
//   - Use TPM-bound keys for hardware-rooted identity
//   - Implement proper key rotation procedures
//   - Never share private keys between services
//
// Certificate Revocation:
// Ensure proper CRL distribution points or OCSP responders are configured
// so that compromised certificates can be quickly invalidated across the
// infrastructure.
//
// Subject Identity:
// Use meaningful subject names that identify the service or entity:
//   - CN=service-name.namespace.svc.cluster.local (Kubernetes)
//   - CN=api-gateway.prod.example.com (DNS-based)
//   - Include SPIFFE IDs in SAN for service mesh compatibility
//
// # References
//
//   - RFC 5246: The Transport Layer Security (TLS) Protocol Version 1.2
//   - RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
//   - NIST SP 800-52 Rev. 2: Guidelines for TLS Implementations
package profiles

import (
	"crypto/x509"
	"encoding/asn1"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

// =============================================================================
// mTLS OID Constants
// =============================================================================

// Standard OIDs for TLS extended key usage.
var (
	// OIDServerAuth is the OID for TLS Server Authentication.
	// This EKU indicates the certificate can be used to authenticate a TLS server.
	// OID: 1.3.6.1.5.5.7.3.1
	OIDServerAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}

	// OIDClientAuth is the OID for TLS Client Authentication.
	// This EKU indicates the certificate can be used to authenticate a TLS client.
	// OID: 1.3.6.1.5.5.7.3.2
	OIDClientAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
)

// =============================================================================
// mTLS Profile Constants
// =============================================================================

// Default validity periods for mTLS certificates in days.
const (
	// DefaultMTLSValidityDays is the standard validity period for mTLS certificates (1 year).
	// For high-security environments, consider using shorter validity periods.
	DefaultMTLSValidityDays = 365
)

// mTLS profile names for registry lookups.
const (
	ProfileNameMTLSClient = "mtls-client"
	ProfileNameMTLSServer = "mtls-server"
	ProfileNameMTLSDual   = "mtls-dual"
)

// =============================================================================
// Base mTLS Profile
// =============================================================================

// baseMTLSProfile provides common mTLS profile functionality.
type baseMTLSProfile struct {
	name            string
	description     string
	keyUsage        x509.KeyUsage
	extKeyUsage     []x509.ExtKeyUsage
	defaultValidity int
}

// Name returns the profile name.
func (p *baseMTLSProfile) Name() string {
	return p.name
}

// KeyUsage returns the key usage for this profile.
func (p *baseMTLSProfile) KeyUsage() x509.KeyUsage {
	return p.keyUsage
}

// ExtKeyUsage returns the extended key usage for this profile.
func (p *baseMTLSProfile) ExtKeyUsage() []x509.ExtKeyUsage {
	result := make([]x509.ExtKeyUsage, len(p.extKeyUsage))
	copy(result, p.extKeyUsage)
	return result
}

// DefaultValidity returns the default validity period in days.
func (p *baseMTLSProfile) DefaultValidity() int {
	return p.defaultValidity
}

// Description returns a human-readable description of the profile.
func (p *baseMTLSProfile) Description() string {
	return p.description
}

// Apply applies the base mTLS profile to a certificate template.
func (p *baseMTLSProfile) Apply(template *x509.Certificate, request *ca.CertificateRequest) error {
	if template == nil {
		return ca.ErrInvalidProfile
	}

	template.KeyUsage = p.keyUsage
	template.ExtKeyUsage = p.extKeyUsage

	// mTLS certificates are end-entity certificates, not CA certificates
	template.IsCA = false
	template.BasicConstraintsValid = true

	return nil
}

// =============================================================================
// mTLS Client Profile
// =============================================================================

// MTLSClientProfile implements the mTLS client certificate profile.
//
// This profile is used for certificates that authenticate clients to servers
// in mutual TLS scenarios. The certificate proves the client's identity to
// the server during the TLS handshake.
//
// Key characteristics:
//   - Key Usage: Digital Signature, Key Encipherment
//   - Extended Key Usage: Client Authentication
//   - Default Validity: 1 year (365 days)
//   - Not a CA certificate
//
// Use cases:
//   - Service-to-service authentication
//   - API client authentication
//   - Database client connections
//   - VPN/proxy client certificates
type MTLSClientProfile struct {
	*baseMTLSProfile
}

// NewMTLSClientProfile creates a new mTLS client authentication profile.
//
// The profile configures certificates for TLS client authentication with:
//   - Digital Signature: Required for TLS authentication
//   - Key Encipherment: Supports RSA key exchange in TLS 1.2
//   - Client Auth EKU: Indicates the certificate is for client authentication
//
// Example:
//
//	profile := NewMTLSClientProfile()
//	registry.Register(profile.Name(), profile)
//
//	request := &ca.CertificateRequest{
//	    CommonName: "api-client.example.com",
//	}
//	cert, err := ca.IssueCertificateWithProfile(request, "mtls-client")
func NewMTLSClientProfile() *MTLSClientProfile {
	return &MTLSClientProfile{
		baseMTLSProfile: &baseMTLSProfile{
			name:        ProfileNameMTLSClient,
			description: "mTLS Client Certificate for mutual TLS authentication",
			keyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			extKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
			},
			defaultValidity: DefaultMTLSValidityDays,
		},
	}
}

// Apply applies the mTLS client profile to a certificate template.
//
// This method sets up the certificate template for client authentication:
//   - Sets key usage to Digital Signature and Key Encipherment
//   - Sets extended key usage to Client Authentication
//   - Ensures the certificate is not marked as a CA
//   - Sets BasicConstraintsValid to true
//
// The request parameter can be used for context-sensitive configuration
// in future enhancements but is currently used only for validation.
func (p *MTLSClientProfile) Apply(template *x509.Certificate, request *ca.CertificateRequest) error {
	return p.baseMTLSProfile.Apply(template, request)
}

// =============================================================================
// mTLS Server Profile
// =============================================================================

// MTLSServerProfile implements the mTLS server certificate profile.
//
// This profile is used for certificates that authenticate servers to clients
// in mutual TLS scenarios. While similar to standard TLS server certificates,
// these are explicitly designed for environments where client authentication
// is also required.
//
// Key characteristics:
//   - Key Usage: Digital Signature, Key Encipherment
//   - Extended Key Usage: Server Authentication
//   - Default Validity: 1 year (365 days)
//   - Not a CA certificate
//
// Use cases:
//   - Internal API servers requiring mTLS
//   - Service mesh ingress points
//   - Secure admin interfaces
//   - Internal microservices
type MTLSServerProfile struct {
	*baseMTLSProfile
}

// NewMTLSServerProfile creates a new mTLS server authentication profile.
//
// The profile configures certificates for TLS server authentication with:
//   - Digital Signature: Required for TLS authentication
//   - Key Encipherment: Supports RSA key exchange in TLS 1.2
//   - Server Auth EKU: Indicates the certificate is for server authentication
//
// Example:
//
//	profile := NewMTLSServerProfile()
//	registry.Register(profile.Name(), profile)
//
//	request := &ca.CertificateRequest{
//	    CommonName: "api-server.example.com",
//	    DNSNames:   []string{"api-server.example.com", "api.internal"},
//	}
//	cert, err := ca.IssueCertificateWithProfile(request, "mtls-server")
func NewMTLSServerProfile() *MTLSServerProfile {
	return &MTLSServerProfile{
		baseMTLSProfile: &baseMTLSProfile{
			name:        ProfileNameMTLSServer,
			description: "mTLS Server Certificate for mutual TLS authentication",
			keyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			extKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
			},
			defaultValidity: DefaultMTLSValidityDays,
		},
	}
}

// Apply applies the mTLS server profile to a certificate template.
//
// This method sets up the certificate template for server authentication:
//   - Sets key usage to Digital Signature and Key Encipherment
//   - Sets extended key usage to Server Authentication
//   - Ensures the certificate is not marked as a CA
//   - Sets BasicConstraintsValid to true
//
// The request parameter can be used for context-sensitive configuration
// in future enhancements but is currently used only for validation.
func (p *MTLSServerProfile) Apply(template *x509.Certificate, request *ca.CertificateRequest) error {
	return p.baseMTLSProfile.Apply(template, request)
}

// =============================================================================
// mTLS Dual Profile
// =============================================================================

// MTLSDualProfile implements the mTLS dual-purpose certificate profile.
//
// This profile is used for certificates that need both client and server
// authentication capabilities. This is common in peer-to-peer scenarios
// or service mesh deployments where a single identity acts as both
// a client (making requests) and a server (receiving requests).
//
// Key characteristics:
//   - Key Usage: Digital Signature, Key Encipherment
//   - Extended Key Usage: Client Authentication, Server Authentication
//   - Default Validity: 1 year (365 days)
//   - Not a CA certificate
//
// Use cases:
//   - Service mesh sidecar proxies (Envoy, Linkerd, Istio)
//   - Peer-to-peer service communication
//   - Bidirectional gRPC services
//   - Database cluster node authentication
//   - Distributed system nodes
type MTLSDualProfile struct {
	*baseMTLSProfile
}

// NewMTLSDualProfile creates a new mTLS dual-purpose authentication profile.
//
// The profile configures certificates for both client and server authentication:
//   - Digital Signature: Required for TLS authentication
//   - Key Encipherment: Supports RSA key exchange in TLS 1.2
//   - Client Auth EKU: Indicates the certificate can authenticate as a client
//   - Server Auth EKU: Indicates the certificate can authenticate as a server
//
// Example:
//
//	profile := NewMTLSDualProfile()
//	registry.Register(profile.Name(), profile)
//
//	request := &ca.CertificateRequest{
//	    CommonName: "service-node-1.mesh.local",
//	    DNSNames:   []string{"service-node-1.mesh.local"},
//	}
//	cert, err := ca.IssueCertificateWithProfile(request, "mtls-dual")
func NewMTLSDualProfile() *MTLSDualProfile {
	return &MTLSDualProfile{
		baseMTLSProfile: &baseMTLSProfile{
			name:        ProfileNameMTLSDual,
			description: "mTLS Dual Certificate for both client and server authentication",
			keyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			extKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageServerAuth,
			},
			defaultValidity: DefaultMTLSValidityDays,
		},
	}
}

// Apply applies the mTLS dual profile to a certificate template.
//
// This method sets up the certificate template for dual authentication:
//   - Sets key usage to Digital Signature and Key Encipherment
//   - Sets extended key usage to both Client and Server Authentication
//   - Ensures the certificate is not marked as a CA
//   - Sets BasicConstraintsValid to true
//
// The request parameter can be used for context-sensitive configuration
// in future enhancements but is currently used only for validation.
func (p *MTLSDualProfile) Apply(template *x509.Certificate, request *ca.CertificateRequest) error {
	return p.baseMTLSProfile.Apply(template, request)
}

// =============================================================================
// mTLS Profile Interface
// =============================================================================

// MTLSProfile extends ProfileProvider with mTLS-specific methods.
type MTLSProfile interface {
	ca.ProfileProvider

	// Description returns a human-readable description of the profile.
	Description() string
}

// =============================================================================
// mTLS Profile Helper Functions
// =============================================================================

// mtlsProfileConstructors maps mTLS profile names to their constructors.
var mtlsProfileConstructors = map[string]func() MTLSProfile{
	ProfileNameMTLSClient: func() MTLSProfile { return NewMTLSClientProfile() },
	ProfileNameMTLSServer: func() MTLSProfile { return NewMTLSServerProfile() },
	ProfileNameMTLSDual:   func() MTLSProfile { return NewMTLSDualProfile() },
}

// MTLSProfileByName returns the mTLS profile for the given name.
//
// Valid profile names are:
//   - "mtls-client" - Client authentication profile
//   - "mtls-server" - Server authentication profile
//   - "mtls-dual"   - Dual-purpose authentication profile
//
// Returns ErrInvalidProfile if the name is not a valid mTLS profile name.
//
// Example:
//
//	profile, err := MTLSProfileByName("mtls-dual")
//	if err != nil {
//	    log.Fatal(err)
//	}
func MTLSProfileByName(name string) (MTLSProfile, error) {
	constructor, exists := mtlsProfileConstructors[name]
	if !exists {
		return nil, ca.ErrInvalidProfile
	}
	return constructor(), nil
}

// RegisterMTLSProfiles registers all mTLS profiles with the given registry.
//
// This registers the following profiles:
//   - mtls-client: Client authentication profile
//   - mtls-server: Server authentication profile
//   - mtls-dual:   Dual-purpose authentication profile
//
// Returns an error if any profile fails to register.
//
// Example:
//
//	registry := ca.NewDefaultProfileRegistry()
//	if err := RegisterMTLSProfiles(registry); err != nil {
//	    log.Fatal(err)
//	}
func RegisterMTLSProfiles(registry ca.ProfileRegistry) error {
	profiles := []ca.ProfileProvider{
		NewMTLSClientProfile(),
		NewMTLSServerProfile(),
		NewMTLSDualProfile(),
	}

	for _, profile := range profiles {
		if err := registry.Register(profile.Name(), profile); err != nil {
			return err
		}
	}

	return nil
}

// AllMTLSProfiles returns all mTLS profiles.
//
// This is useful for iterating over all mTLS profiles or for batch operations
// such as registering all profiles with a custom registry.
//
// Example:
//
//	for _, profile := range AllMTLSProfiles() {
//	    fmt.Printf("Profile: %s - %s\n", profile.Name(), profile.Description())
//	}
func AllMTLSProfiles() []MTLSProfile {
	return []MTLSProfile{
		NewMTLSClientProfile(),
		NewMTLSServerProfile(),
		NewMTLSDualProfile(),
	}
}

// MTLSProfileNames returns all valid mTLS profile names.
//
// This is useful for validation or generating documentation about
// available mTLS profile types.
func MTLSProfileNames() []string {
	return []string{
		ProfileNameMTLSClient,
		ProfileNameMTLSServer,
		ProfileNameMTLSDual,
	}
}

// IsMTLSProfile returns true if the given string is a valid mTLS profile name.
//
// Example:
//
//	if IsMTLSProfile("mtls-dual") {
//	    // Handle mTLS profile
//	}
func IsMTLSProfile(name string) bool {
	_, exists := mtlsProfileConstructors[name]
	return exists
}
