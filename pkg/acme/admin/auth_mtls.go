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
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// MTLSAuthHandler is the production AuthHandler for the ACME admin surface.
// It authenticates each request from its mTLS client certificate using
// xkms's canonical auth.MTLSAuthenticator — the same authenticator
// construction the REST transport uses (pkg/api/rest/host.go) — so a
// certificate means the same identity here as it does on every other
// transport. It then publishes both the AuthenticatedUser record (tenant
// scoping, audit attribution) and the canonical auth.Identity the
// PermissionGate authorizes against.
type MTLSAuthHandler struct {
	authenticator *auth.MTLSAuthenticator
}

// NewMTLSAuthHandler wraps an *auth.MTLSAuthenticator as an AuthHandler for
// the admin surface.
func NewMTLSAuthHandler(authenticator *auth.MTLSAuthenticator) *MTLSAuthHandler {
	return &MTLSAuthHandler{authenticator: authenticator}
}

// Authenticate implements AuthHandler: it resolves the caller's identity from
// the request's TLS client certificate and denies the request (401) when none
// can be resolved. Authorization is a separate concern, decided per route by
// the PermissionGate.
func (h *MTLSAuthHandler) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.authenticator == nil {
			writeProblem(w, http.StatusUnauthorized, problemUnauthorized, "Authentication required")
			return
		}
		identity, err := h.authenticator.AuthenticateHTTP(r)
		if err != nil || identity == nil {
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

// Compile-time interface check.
var _ AuthHandler = (*MTLSAuthHandler)(nil)
