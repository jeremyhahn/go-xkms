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
	"errors"
	"net/http"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// ErrAuthenticatorNotConfigured is returned when an MTLSAuthHandler was
// built without an authenticator. The request is refused, never admitted.
var ErrAuthenticatorNotConfigured = errors.New("admin: mTLS authenticator not configured")

// MTLSAuthHandler is the production AuthHandler for the ACME admin surface.
// It authenticates each request from its mTLS client certificate using
// xkms's canonical auth.MTLSAuthenticator — the same authenticator
// construction the REST transport uses (pkg/api/rest/host.go) — so a
// certificate means the same identity here as it does on every other
// transport. It then publishes both the AuthenticatedUser record (tenant
// scoping, audit attribution) and the canonical auth.Identity the
// PermissionGate authorizes against.
//
// The admin routes are public module routes: qrdb's authentication
// middleware binds no tenant before this handler runs. The handler applies
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
// the admin surface. trustDomain is the SPIFFE trust domain the deployment's
// CA issues under; a SPIFFE SAN from any other trust domain is refused.
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
// ErrAuthenticatorNotConfigured without an authenticator,
// auth.ErrNoPeerCertificate without a client certificate, the
// *qrdbsdk.ClientCertificateTenantError of a certificate that names no usable
// tenant, and otherwise whatever the authenticator refuses with (for example
// auth.ErrCertNotBound for a certificate bound to no user in its tenant).
func (h *MTLSAuthHandler) authenticate(r *http.Request) (*auth.Identity, error) {
	if h.authenticator == nil {
		return nil, ErrAuthenticatorNotConfigured
	}
	ctx, err := h.bindCertificateTenant(r)
	if err != nil {
		return nil, err
	}
	return h.authenticator.AuthenticateHTTP(r.WithContext(ctx))
}

// bindCertificateTenant returns the request context bound to the tenant the
// client certificate names, normalized exactly as qrdb's middleware does (a
// certificate naming no tenant is the system tenant's).
func (h *MTLSAuthHandler) bindCertificateTenant(r *http.Request) (context.Context, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, auth.ErrNoPeerCertificate
	}
	tenantID, _, err := qrdbsdk.TenantFromClientCert(r.TLS.PeerCertificates[0], h.trustDomain)
	if err != nil {
		return nil, err
	}
	return qrdbsdk.ContextWithTenant(r.Context(), qrdbsdk.NormalizeTenantID(tenantID)), nil
}

// Compile-time interface check.
var _ AuthHandler = (*MTLSAuthHandler)(nil)
