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
	"crypto/x509"
	"fmt"
	"net/http"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// UserStore is a narrow interface used by MTLSAuthenticator for cert-to-user lookup.
// It keeps the authenticator decoupled from the concrete identity backend; the
// production implementation (QRDBUserStore) resolves users from the embedded
// qrdb node by their certificate SPKI thumbprint.
type UserStore interface {
	// GetByCertFingerprint retrieves user info by the canonical SPKI thumbprint of a client certificate.
	GetByCertFingerprint(ctx context.Context, fingerprint string) (MTLSUser, error)
}

// MTLSUser represents user information returned from a cert fingerprint lookup.
type MTLSUser struct {
	// Username is the user's unique login identifier.
	Username string
	// Email is the canonical tenant-unique login key (go-qrdb #190). It is
	// empty for principals that have no email login key, such as bootstrap
	// and service accounts; an empty value means "absent", never a
	// placeholder.
	Email string
	// DisplayName is a human-readable name.
	DisplayName string
	// Roles are the identifiers of every role assigned to the user, exactly as
	// the identity store records them. For the qrdb store these are qrdb role
	// IDs — the only form go-qrdb's authorizer resolves (it looks roles up by
	// ID, never by name) — so they are carried verbatim and never projected to
	// names, and none is dropped: the authorizer grants the union of all of
	// them.
	Roles []string
	// TenantID is the tenant scope for this user.
	TenantID string
	// Enabled indicates whether the user account is active.
	Enabled bool
	// AuthMethods is the account's permitted-authentication-method policy
	// (qrdb User.AuthMethods), as qrdb stores it. Empty states no
	// restriction; otherwise the mTLS authenticator refuses the account unless
	// the list names qrdbsdk.MethodMTLS.
	AuthMethods []string
}

// CertMetadata captures string-shaped attributes that the mTLS authenticator
// derives from a client certificate. These flow into Identity.Metadata so
// downstream code can correlate identity with audit/log entries without
// re-parsing the certificate.
type CertMetadata struct {
	// CommonName is the certificate's Subject Common Name.
	CommonName string
	// Organization is the comma-joined list of Subject.Organization values.
	Organization string
	// OrganizationalUnit is the comma-joined list of Subject.OrganizationalUnit values.
	OrganizationalUnit string
	// Country is the comma-joined list of Subject.Country values.
	Country string
	// Province is the comma-joined list of Subject.Province values.
	Province string
	// Locality is the comma-joined list of Subject.Locality values.
	Locality string
	// DNSNames is the comma-joined list of SAN DNS names.
	DNSNames string
	// EmailAddresses is the comma-joined list of SAN email addresses.
	EmailAddresses string
	// ExtKeyUsage is the comma-joined list of extended key usages.
	ExtKeyUsage string
}

// MTLSAuthenticator authenticates requests using mutual TLS (client certificates).
type MTLSAuthenticator struct {
	// extractMetadata derives string metadata for Identity.Metadata.
	extractMetadata func(*x509.Certificate) CertMetadata

	// extractSubject is a function that extracts the subject from a client certificate
	extractSubject func(*x509.Certificate) string

	// userStore is an optional store for mapping certificate fingerprints to users
	userStore UserStore
}

// MTLSConfig configures the mTLS authenticator.
type MTLSConfig struct {
	// ExtractMetadata derives certificate-derived metadata for the
	// authenticated identity. If nil, defaultExtractCertMetadata is used.
	ExtractMetadata func(*x509.Certificate) CertMetadata

	// ExtractSubject extracts the subject identifier from the client certificate
	// If nil, uses the certificate's Subject Common Name
	ExtractSubject func(*x509.Certificate) string

	// UserStore is an optional store that maps certificate identities to users.
	// When provided, the authenticator looks up the user by the canonical SPKI
	// thumbprint (qrdbsdk.ComputeSPKIThumbprint) of the client certificate. If found and enabled, the
	// identity subject is set to the username and the role claim is added.
	// If found but disabled, ErrUserDisabled is returned.
	// If found but the account's permitted-method policy excludes mTLS,
	// *AuthMethodNotPermittedError is returned.
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

	if config.ExtractMetadata == nil {
		config.ExtractMetadata = defaultExtractCertMetadata
	}

	if config.ExtractSubject == nil {
		config.ExtractSubject = defaultExtractSubject
	}

	return &MTLSAuthenticator{
		extractMetadata: config.ExtractMetadata,
		extractSubject:  config.ExtractSubject,
		userStore:       config.UserStore,
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

	identity.Metadata["remote_addr"] = r.RemoteAddr

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

	identity.Metadata["peer_addr"] = p.Addr.String()

	return identity, nil
}

// Name returns qrdbsdk.MethodMTLS, the method name qrdb's permitted-method
// policy is written against.
func (a *MTLSAuthenticator) Name() string {
	return qrdbsdk.MethodMTLS
}

// buildIdentity constructs an identity from a client certificate. When a UserStore is
// configured, it first attempts to look up the user by canonical SPKI thumbprint. If the
// user is found and enabled, the identity is enriched with user information and role.
// If the user is found but disabled, ErrUserDisabled is returned; if the user's
// permitted-method policy excludes mTLS, *AuthMethodNotPermittedError is returned.
// If the user is not found (or no UserStore is configured), the identity is
// extracted from the certificate fields.
func (a *MTLSAuthenticator) buildIdentity(ctx context.Context, cert *x509.Certificate) (*Identity, error) {
	if a.userStore != nil {
		// Canonical mTLS identity: qrdb's SPKI thumbprint (SHA-256 over
		// SubjectPublicKeyInfo, base64url). This is the single algorithm shared by
		// qrdb, xkms, and quicbaas so cert bindings resolve consistently across the
		// stack. Consumed via the qrdb SDK — never reimplemented locally.
		fingerprint := qrdbsdk.ComputeSPKIThumbprint(cert)
		user, err := a.userStore.GetByCertFingerprint(ctx, fingerprint)
		if err == nil {
			// User found -- check if enabled
			if !user.Enabled {
				return nil, ErrUserDisabled
			}
			// A certificate is a valid credential for an account in good
			// standing, but the account may still withdraw mTLS as a way in
			// (a FIDO2-only user, say). qrdb enforces this in its own
			// middleware; the xkms planes must too, or withdrawal fails open.
			if err := checkAuthMethod(user, a.Name()); err != nil {
				return nil, err
			}

			identity := &Identity{
				Subject:  user.Username,
				TenantID: user.TenantID,
				Metadata: a.certMetadataMap(cert),
			}

			if len(user.Roles) > 0 {
				identity.Roles = append([]string(nil), user.Roles...)
			}
			identity.Metadata["display_name"] = user.DisplayName
			if user.Email != "" {
				identity.Metadata["email"] = user.Email
			}
			identity.Metadata["auth_method"] = qrdbsdk.MethodMTLS
			identity.Metadata["cert_serial"] = cert.SerialNumber.String()
			identity.Metadata["cert_issuer"] = cert.Issuer.String()
			identity.Metadata["cert_fingerprint"] = fingerprint

			return identity, nil
		}
		// User not found -- fall through to certificate-based extraction
	}

	identity := &Identity{
		Subject:  a.extractSubject(cert),
		Metadata: a.certMetadataMap(cert),
	}

	// Extract tenant from first OU if present
	if len(cert.Subject.OrganizationalUnit) > 0 {
		identity.TenantID = cert.Subject.OrganizationalUnit[0]
	}

	identity.Metadata["auth_method"] = qrdbsdk.MethodMTLS
	identity.Metadata["cert_serial"] = cert.SerialNumber.String()
	identity.Metadata["cert_issuer"] = cert.Issuer.String()

	return identity, nil
}

// certMetadataMap converts the configured certificate metadata extractor's
// output into a flat map suitable for Identity.Metadata. Empty fields are
// omitted to keep the map compact.
func (a *MTLSAuthenticator) certMetadataMap(cert *x509.Certificate) map[string]string {
	cm := a.extractMetadata(cert)
	out := make(map[string]string, 9)
	if cm.CommonName != "" {
		out["common_name"] = cm.CommonName
	}
	if cm.Organization != "" {
		out["organization"] = cm.Organization
	}
	if cm.OrganizationalUnit != "" {
		out["organizational_unit"] = cm.OrganizationalUnit
	}
	if cm.Country != "" {
		out["country"] = cm.Country
	}
	if cm.Province != "" {
		out["province"] = cm.Province
	}
	if cm.Locality != "" {
		out["locality"] = cm.Locality
	}
	if cm.DNSNames != "" {
		out["dns_names"] = cm.DNSNames
	}
	if cm.EmailAddresses != "" {
		out["email_addresses"] = cm.EmailAddresses
	}
	if cm.ExtKeyUsage != "" {
		out["ext_key_usage"] = cm.ExtKeyUsage
	}
	return out
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

// defaultExtractCertMetadata extracts the standard string-shaped certificate
// attributes used as identity metadata.
func defaultExtractCertMetadata(cert *x509.Certificate) CertMetadata {
	return CertMetadata{
		CommonName:         cert.Subject.CommonName,
		Organization:       joinNonEmpty(cert.Subject.Organization),
		OrganizationalUnit: joinNonEmpty(cert.Subject.OrganizationalUnit),
		Country:            joinNonEmpty(cert.Subject.Country),
		Province:           joinNonEmpty(cert.Subject.Province),
		Locality:           joinNonEmpty(cert.Subject.Locality),
		DNSNames:           joinNonEmpty(cert.DNSNames),
		EmailAddresses:     joinNonEmpty(cert.EmailAddresses),
		ExtKeyUsage:        joinExtKeyUsage(cert.ExtKeyUsage),
	}
}

// joinNonEmpty joins a string slice with commas, returning "" for an empty slice.
func joinNonEmpty(values []string) string {
	if len(values) == 0 {
		return ""
	}
	out := values[0]
	for _, v := range values[1:] {
		if v == "" {
			continue
		}
		out += "," + v
	}
	return out
}

// joinExtKeyUsage formats extended key usages as a comma-separated string.
func joinExtKeyUsage(usages []x509.ExtKeyUsage) string {
	if len(usages) == 0 {
		return ""
	}
	out := keyUsageString(usages[0])
	for _, u := range usages[1:] {
		out += "," + keyUsageString(u)
	}
	return out
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
