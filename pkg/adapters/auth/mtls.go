// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package auth

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// MTLSAuthenticator authenticates requests using mutual TLS (client certificates)
type MTLSAuthenticator struct {
	// extractClaims is a function that extracts claims from a client certificate
	extractClaims func(*x509.Certificate) map[string]interface{}

	// extractSubject is a function that extracts the subject from a client certificate
	extractSubject func(*x509.Certificate) string
}

// MTLSConfig configures the mTLS authenticator
type MTLSConfig struct {
	// ExtractClaims extracts claims from the client certificate
	// If nil, uses default extraction (CN, OU, O)
	ExtractClaims func(*x509.Certificate) map[string]interface{}

	// ExtractSubject extracts the subject identifier from the client certificate
	// If nil, uses the certificate's Subject Common Name
	ExtractSubject func(*x509.Certificate) string
}

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
	}
}

// AuthenticateHTTP authenticates an HTTP request using the client certificate
func (a *MTLSAuthenticator) AuthenticateHTTP(r *http.Request) (*Identity, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no client certificate provided")
	}

	cert := r.TLS.PeerCertificates[0]

	identity := &Identity{
		Subject:    a.extractSubject(cert),
		Claims:     a.extractClaims(cert),
		Attributes: make(map[string]string),
	}

	identity.Attributes["auth_method"] = "mtls"
	identity.Attributes["cert_serial"] = cert.SerialNumber.String()
	identity.Attributes["cert_issuer"] = cert.Issuer.String()
	identity.Attributes["remote_addr"] = r.RemoteAddr

	return identity, nil
}

// AuthenticateGRPC authenticates a gRPC request using the client certificate from peer info
func (a *MTLSAuthenticator) AuthenticateGRPC(ctx context.Context, md metadata.MD) (*Identity, error) {
	// Get peer information from context
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("no peer information in context")
	}

	// Extract TLS info
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, fmt.Errorf("no TLS information in peer")
	}

	if len(tlsInfo.State.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no client certificate provided")
	}

	cert := tlsInfo.State.PeerCertificates[0]

	identity := &Identity{
		Subject:    a.extractSubject(cert),
		Claims:     a.extractClaims(cert),
		Attributes: make(map[string]string),
	}

	identity.Attributes["auth_method"] = "mtls"
	identity.Attributes["cert_serial"] = cert.SerialNumber.String()
	identity.Attributes["cert_issuer"] = cert.Issuer.String()
	identity.Attributes["peer_addr"] = p.Addr.String()

	return identity, nil
}

// Name returns the authenticator name
func (a *MTLSAuthenticator) Name() string {
	return "mtls"
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
