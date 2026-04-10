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

package rest

import (
	"errors"
	"net/http"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/authz"
)

var (
	// ErrAuthorizationFailed is returned when the authorizer encounters
	// an internal error while evaluating the request.
	ErrAuthorizationFailed = errors.New("authorization error")

	// ErrAccessDenied is returned when the authorizer denies access to the
	// requested resource.
	ErrAccessDenied = errors.New("access denied")
)

// AuthzMiddleware provides authorization checking for HTTP handlers.
// It delegates authorization decisions to an authz.Authorizer implementation
// and records audit events through an audit.Logger.
type AuthzMiddleware struct {
	authorizer  authz.Authorizer
	auditLogger audit.Logger
}

// NewAuthzMiddleware creates a new authorization middleware with the given
// authorizer and audit logger.
func NewAuthzMiddleware(authorizer authz.Authorizer, auditLogger audit.Logger) *AuthzMiddleware {
	return &AuthzMiddleware{
		authorizer:  authorizer,
		auditLogger: auditLogger,
	}
}

// Wrap returns an HTTP handler that checks authorization before calling the
// next handler. resource and action map to the RBAC permission model:
//   - resource: "keys", "certs", "users", "backends", "piv", "seal"
//   - action: "read", "write", "delete", "use", "manage"
func (m *AuthzMiddleware) Wrap(resource, action string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract identity from context (set by authentication middleware)
		identity := auth.GetIdentity(r.Context())

		subject := ""
		role := ""
		if identity != nil {
			subject = identity.Subject
			role = extractRole(identity)
		}

		// Build authorization request
		authzReq := &authz.AuthorizationRequest{
			Subject:  subject,
			Role:     role,
			Resource: resource,
			Action:   action,
			Context:  make(map[string]string),
		}

		// Perform authorization check
		decision, err := m.authorizer.Authorize(r.Context(), authzReq)

		// Determine outcome for audit logging
		outcome := audit.OutcomeAllow
		if err != nil || (decision != nil && !decision.Allowed) {
			outcome = audit.OutcomeDeny
		}

		// Build and log audit event (best effort - errors are intentionally
		// discarded to avoid disrupting the request pipeline)
		auditEvent := &audit.Event{
			Timestamp:  time.Now(),
			Subject:    subject,
			Action:     action,
			Resource:   resource,
			ResourceID: r.URL.Path,
			Outcome:    outcome,
			Details: map[string]string{
				"method":      r.Method,
				"remote_addr": r.RemoteAddr,
			},
		}
		if role != "" {
			auditEvent.Details["role"] = role
		}
		_ = m.auditLogger.Log(r.Context(), auditEvent)

		// Handle authorization errors
		if err != nil {
			writeErrorWithMessage(w, ErrAuthorizationFailed, ErrAuthorizationFailed.Error(), http.StatusInternalServerError)
			return
		}

		// Handle denied decisions
		if decision != nil && !decision.Allowed {
			reason := ErrAccessDenied.Error()
			if decision.Reason != "" {
				reason = decision.Reason
			}
			writeErrorWithMessage(w, ErrAccessDenied, reason, http.StatusForbidden)
			return
		}

		// Authorized - call the next handler
		next(w, r)
	}
}

// extractRole extracts the first role from an identity's claims.
// It handles roles stored as []string, []interface{}, or string.
func extractRole(identity *auth.Identity) string {
	if identity == nil || identity.Claims == nil {
		return ""
	}

	roles, ok := identity.Claims["roles"]
	if !ok {
		return ""
	}

	switch r := roles.(type) {
	case []string:
		if len(r) > 0 {
			return r[0]
		}
	case []interface{}:
		if len(r) > 0 {
			if s, ok := r[0].(string); ok {
				return s
			}
		}
	case string:
		return r
	}

	return ""
}
