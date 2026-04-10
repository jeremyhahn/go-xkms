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

package auth

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// UserStore is a narrow interface used by MTLSAuthenticator for cert-to-user lookup.
// This avoids a circular dependency on the pkg/user package.
type UserStore interface {
	// GetByCertFingerprint retrieves user info by the SHA-256 fingerprint of a client certificate.
	GetByCertFingerprint(ctx context.Context, fingerprint string) (MTLSUser, error)
}

// MTLSUser represents user information returned from a cert fingerprint lookup.
type MTLSUser struct {
	// Username is the user's unique login identifier.
	Username string
	// DisplayName is a human-readable name.
	DisplayName string
	// Role is the user's authorization role.
	Role string
	// TenantID is the tenant scope for this user.
	TenantID string
	// Enabled indicates whether the user account is active.
	Enabled bool
}

// MTLSAuthenticator authenticates requests using mutual TLS (client certificates)
type MTLSAuthenticator struct {
	// extractClaims is a function that extracts claims from a client certificate
	extractClaims func(*x509.Certificate) map[string]interface{}

	// extractSubject is a function that extracts the subject from a client certificate
	extractSubject func(*x509.Certificate) string

	// userStore is an optional store for mapping certificate fingerprints to users
	userStore UserStore
}

// MTLSConfig configures the mTLS authenticator
type MTLSConfig struct {
	// ExtractClaims extracts claims from the client certificate
	// If nil, uses default extraction (CN, OU, O)
	ExtractClaims func(*x509.Certificate) map[string]interface{}

	// ExtractSubject extracts the subject identifier from the client certificate
	// If nil, uses the certificate's Subject Common Name
	ExtractSubject func(*x509.Certificate) string

	// UserStore is an optional store that maps certificate fingerprints to users.
	// When provided, the authenticator will look up the user by the SHA-256 fingerprint
	// of the client certificate's DER-encoded Raw bytes. If found and enabled, the
	// identity subject is set to the username and the role claim is added.
	// If found but disabled, ErrUserDisabled is returned.
	// If not found, the authenticator falls back to extracting identity from certificate fields.
	UserStore UserStore
}

// Compile-time interface check
var _ Authenticator = (*MTLSAuthenticator)(nil)

// NewMTLSAuthenticator creates a new mTLS authenticator
func NewMTLSAuthenticator(config *MTLSConfig) *MTLSAuthenticator {
	if config == nil {
		config = &MTLSConfig{}
	}

	if config.ExtractClaims == nil {
		config.ExtractClaims = defaultExtractClaims
	}

	if config.ExtractSubject == nil {
		config.ExtractSubject = defaultExtractSubject
	}

	return &MTLSAuthenticator{
		extractClaims:  config.ExtractClaims,
		extractSubject: config.ExtractSubject,
		userStore:      config.UserStore,
	}
}

// AuthenticateHTTP authenticates an HTTP request using the client certificate
func (a *MTLSAuthenticator) AuthenticateHTTP(r *http.Request) (*Identity, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, ErrNoPeerCertificate
	}

	cert := r.TLS.PeerCertificates[0]

	identity, err := a.buildIdentity(r.Context(), cert)
	if err != nil {
		return nil, err
	}

	identity.Attributes["remote_addr"] = r.RemoteAddr

	return identity, nil
}

// AuthenticateGRPC authenticates a gRPC request using the client certificate from peer info
func (a *MTLSAuthenticator) AuthenticateGRPC(ctx context.Context, md metadata.MD) (*Identity, error) {
	// Get peer information from context
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, ErrNoPeerInfo
	}

	// Extract TLS info
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, ErrNoTLSInfo
	}

	if len(tlsInfo.State.PeerCertificates) == 0 {
		return nil, ErrNoPeerCertificate
	}

	cert := tlsInfo.State.PeerCertificates[0]

	identity, err := a.buildIdentity(ctx, cert)
	if err != nil {
		return nil, err
	}

	identity.Attributes["peer_addr"] = p.Addr.String()

	return identity, nil
}

// Name returns the authenticator name
func (a *MTLSAuthenticator) Name() string {
	return "mtls"
}

// ComputeCertFingerprint computes the SHA-256 hex fingerprint of a certificate's
// DER-encoded Raw bytes. This is the canonical fingerprint used for cert binding lookups.
func ComputeCertFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

// buildIdentity constructs an identity from a client certificate. When a UserStore is
// configured, it first attempts to look up the user by certificate fingerprint. If the
// user is found and enabled, the identity is enriched with user information and role.
// If the user is found but disabled, ErrUserDisabled is returned. If the user is not
// found (or no UserStore is configured), the identity is extracted from the certificate fields.
func (a *MTLSAuthenticator) buildIdentity(ctx context.Context, cert *x509.Certificate) (*Identity, error) {
	if a.userStore != nil {
		fingerprint := ComputeCertFingerprint(cert)
		user, err := a.userStore.GetByCertFingerprint(ctx, fingerprint)
		if err == nil {
			// User found -- check if enabled
			if !user.Enabled {
				return nil, ErrUserDisabled
			}

			identity := &Identity{
				Subject:    user.Username,
				TenantID:   user.TenantID,
				Claims:     a.extractClaims(cert),
				Attributes: make(map[string]string),
			}

			// Enrich claims with user role
			if user.Role != "" {
				identity.Claims["roles"] = []string{user.Role}
			}
			identity.Claims["display_name"] = user.DisplayName
			identity.Attributes["auth_method"] = "mtls"
			identity.Attributes["cert_serial"] = cert.SerialNumber.String()
			identity.Attributes["cert_issuer"] = cert.Issuer.String()
			identity.Attributes["cert_fingerprint"] = fingerprint

			return identity, nil
		}
		// User not found -- fall through to certificate-based extraction
	}

	identity := &Identity{
		Subject:    a.extractSubject(cert),
		Claims:     a.extractClaims(cert),
		Attributes: make(map[string]string),
	}

	// Extract tenant from first OU if present
	if len(cert.Subject.OrganizationalUnit) > 0 {
		identity.TenantID = cert.Subject.OrganizationalUnit[0]
	}

	identity.Attributes["auth_method"] = "mtls"
	identity.Attributes["cert_serial"] = cert.SerialNumber.String()
	identity.Attributes["cert_issuer"] = cert.Issuer.String()

	return identity, nil
}

// defaultExtractSubject extracts the subject from the certificate's Common Name
func defaultExtractSubject(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}

	// Fallback to first DNS name
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}

	// Fallback to serial number
	return cert.SerialNumber.String()
}

// defaultExtractClaims extracts standard claims from the certificate
func defaultExtractClaims(cert *x509.Certificate) map[string]interface{} {
	claims := make(map[string]interface{})

	claims["common_name"] = cert.Subject.CommonName
	claims["organization"] = cert.Subject.Organization
	claims["organizational_unit"] = cert.Subject.OrganizationalUnit
	claims["country"] = cert.Subject.Country
	claims["province"] = cert.Subject.Province
	claims["locality"] = cert.Subject.Locality
	claims["dns_names"] = cert.DNSNames
	claims["email_addresses"] = cert.EmailAddresses

	// Add extended key usage as permissions
	if len(cert.ExtKeyUsage) > 0 {
		perms := make([]string, 0, len(cert.ExtKeyUsage))
		for _, usage := range cert.ExtKeyUsage {
			perms = append(perms, keyUsageString(usage))
		}
		claims["permissions"] = perms
	}

	return claims
}

// keyUsageString converts x509.ExtKeyUsage to a string
func keyUsageString(usage x509.ExtKeyUsage) string {
	switch usage {
	case x509.ExtKeyUsageAny:
		return "any"
	case x509.ExtKeyUsageServerAuth:
		return "server_auth"
	case x509.ExtKeyUsageClientAuth:
		return "client_auth"
	case x509.ExtKeyUsageCodeSigning:
		return "code_signing"
	case x509.ExtKeyUsageEmailProtection:
		return "email_protection"
	case x509.ExtKeyUsageTimeStamping:
		return "time_stamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "ocsp_signing"
	default:
		return fmt.Sprintf("unknown_%d", usage)
	}
}
