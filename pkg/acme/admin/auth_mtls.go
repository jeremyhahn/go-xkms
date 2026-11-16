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

package admin

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"

	"google.golang.org/grpc/metadata"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// ErrAuthenticatorNotConfigured is returned when an MTLSAuthHandler was
// built without an authenticator. The request is refused, never admitted.
var ErrAuthenticatorNotConfigured = errors.New("admin: mTLS authenticator not configured")

// CertificateTenantMismatchError reports that the user a client certificate
// resolved to belongs to a tenant other than the one the certificate names.
// The caller is refused rather than admitted with that user's roles. It
// unwraps to auth.ErrUnauthenticated.
type CertificateTenantMismatchError struct {
	// CertificateTenantID is the normalized tenant the certificate names.
	CertificateTenantID string
	// UserTenantID is the tenant of the user the certificate resolved to.
	UserTenantID string
}

// Error describes the mismatch.
func (e *CertificateTenantMismatchError) Error() string {
	return "admin: certificate names tenant " + e.CertificateTenantID + " but its user belongs to tenant " + e.UserTenantID
}

// Unwrap returns auth.ErrUnauthenticated: no identity was established.
func (e *CertificateTenantMismatchError) Unwrap() error {
	return auth.ErrUnauthenticated
}

// MTLSAuthHandler is the production AuthHandler for the ACME admin surface.
// It authenticates each request from its mTLS client certificate using
// xkms's canonical auth.MTLSAuthenticator — the same authenticator
// construction the REST transport uses (pkg/api/rest/host.go) — so a
// certificate means the same identity here as it does on every other
// transport. It then publishes both the AuthenticatedUser record (tenant
// scoping, audit attribution) and the canonical auth.Identity the
// PermissionGate authorizes against.
//
// The admin routes are identity-gated module routes: qrdb's authentication
// chain has already refused an anonymous caller, but this handler resolves
// the caller itself rather than trusting the module boundary. It applies
// qrdb's own certificate-to-tenant rule (qrdbsdk.TenantFromClientCert) under
// the deployment's trust domain, binds that tenant, and only then looks the
// certificate's thumbprint up — within that tenant alone, so a tenant user
// resolves in its own tenant and a certificate is never searched for in
// another one.
type MTLSAuthHandler struct {
	authenticator *auth.MTLSAuthenticator
	trustDomain   string
}

// NewMTLSAuthHandler wraps an *auth.MTLSAuthenticator as an AuthHandler for
// the admin surface. trustDomain is the cluster SPIFFE trust domain the
// deployment's CA issues under; no tenant may be it.
func NewMTLSAuthHandler(authenticator *auth.MTLSAuthenticator, trustDomain string) *MTLSAuthHandler {
	return &MTLSAuthHandler{authenticator: authenticator, trustDomain: trustDomain}
}

// Authenticate implements AuthHandler: it resolves the caller's identity from
// the request's TLS client certificate and denies the request (401) when none
// can be resolved. Authorization is a separate concern, decided per route by
// the PermissionGate.
func (h *MTLSAuthHandler) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, err := h.authenticate(r)
		if err != nil {
			writeProblem(w, http.StatusUnauthorized, problemUnauthorized, "Authentication required")
			return
		}
		user := &AuthenticatedUser{
			UserID:   identity.Subject,
			Username: identity.Subject,
			TenantID: identity.TenantID,
			Roles:    identity.Roles,
		}
		next.ServeHTTP(w, r.WithContext(withUser(r.Context(), user)))
	})
}

// authenticate resolves the request's identity. It returns
// auth.ErrNoPeerCertificate without a client certificate and otherwise
// whatever authenticateCertificate refuses with.
func (h *MTLSAuthHandler) authenticate(r *http.Request) (*auth.Identity, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, auth.ErrNoPeerCertificate
	}
	return h.authenticateCertificate(r.Context(), r.TLS.PeerCertificates[0], func(ctx context.Context) (*auth.Identity, error) {
		return h.authenticator.AuthenticateHTTP(r.WithContext(ctx))
	})
}

// AuthenticateGRPC resolves the identity of a gRPC caller that presented cert,
// the leaf certificate of ctx's TLS peer, by the same rule Authenticate
// applies to a REST caller.
func (h *MTLSAuthHandler) AuthenticateGRPC(ctx context.Context, cert *x509.Certificate, md metadata.MD) (*auth.Identity, error) {
	return h.authenticateCertificate(ctx, cert, func(ctx context.Context) (*auth.Identity, error) {
		return h.authenticator.AuthenticateGRPC(ctx, md)
	})
}

// authenticateCertificate is the admin surface's one certificate-to-identity
// rule. The tenant is the one qrdbsdk.TenantFromClientCert names under the
// deployment's trust domain -- the trust domain of its
// spiffe://<tenant>/<kind>/<name> SAN, which its first Subject OU must also
// name -- normalized as qrdb's middleware does. lookup then resolves
// the go-qrdb user the certificate binds to within that tenant alone, and the
// caller's roles are that user's roles: nothing in the certificate, its OU
// least of all, is ever read as a role.
//
// It returns ErrAuthenticatorNotConfigured without an authenticator, the
// *qrdbsdk.ClientCertificateTenantError of a certificate that names no usable
// tenant, whatever lookup refuses with (for example auth.ErrCertNotBound for a
// certificate bound to no user in its tenant), and a
// *CertificateTenantMismatchError when the resolved user belongs to another
// tenant.
func (h *MTLSAuthHandler) authenticateCertificate(ctx context.Context, cert *x509.Certificate, lookup func(context.Context) (*auth.Identity, error)) (*auth.Identity, error) {
	if h == nil || h.authenticator == nil {
		return nil, ErrAuthenticatorNotConfigured
	}
	tenantID, err := qrdbsdk.TenantFromClientCert(cert, h.trustDomain)
	if err != nil {
		return nil, err
	}
	tenantID = qrdbsdk.NormalizeTenantID(tenantID)
	identity, err := lookup(qrdbsdk.ContextWithTenant(ctx, tenantID))
	if err != nil {
		return nil, err
	}
	if qrdbsdk.NormalizeTenantID(identity.TenantID) != tenantID {
		return nil, &CertificateTenantMismatchError{CertificateTenantID: tenantID, UserTenantID: identity.TenantID}
	}
	identity.TenantID = tenantID
	return identity, nil
}

// Compile-time interface check.
var _ AuthHandler = (*MTLSAuthHandler)(nil)
