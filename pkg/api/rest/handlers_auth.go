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
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/auth/token"
)

// PIVLoginOptions configures the TLS-client-certificate login exchange.
type PIVLoginOptions struct {
	// Enabled turns POST /api/v1/auth/login/piv on.
	Enabled bool

	// TrustedIssuers optionally restricts accepted certificate issuer
	// distinguished names (exact match). Empty accepts any issuer the TLS
	// layer verified.
	TrustedIssuers []string
}

// authTokenResponse is the JSON body returned by the login and refresh
// endpoints.
type authTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// authRefreshRequest is the JSON body accepted by refresh and logout.
type authRefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// authMeResponse describes the authenticated session for the web UI: who the
// caller is, what the UI may show them, and which server capabilities exist.
type authMeResponse struct {
	Subject     string   `json:"subject"`
	TenantID    string   `json:"tenant_id,omitempty"`
	Username    string   `json:"username,omitempty"`
	DisplayName string   `json:"display_name,omitempty"`
	AuthMethod  string   `json:"auth_method,omitempty"`
	Roles       []string `json:"roles,omitempty"`

	// Permissions maps "resource:action" to whether the caller holds it.
	// All-true when RBAC is disabled (the server enforces nothing more).
	Permissions map[string]bool `json:"permissions"`

	// Capabilities flags which optional server subsystems are wired, so the
	// UI can hide whole sections that cannot work on this deployment.
	Capabilities map[string]bool `json:"capabilities"`
}

// authValidateResponse is the lightweight session probe response.
type authValidateResponse struct {
	Subject  string `json:"subject"`
	TenantID string `json:"tenant_id,omitempty"`
}

// uiPermissionMatrix lists the resource:action pairs the web UI gates its
// navigation and controls on. It mirrors the RBAC decorators in setupRouter;
// the server-side decorators remain the enforcement authority.
var uiPermissionMatrix = [][2]string{
	{auth.ResourceKeys, auth.ActionList},
	{auth.ResourceKeys, auth.ActionCreate},
	{auth.ResourceKeys, auth.ActionSign},
	{auth.ResourceKeys, auth.ActionEncrypt},
	{auth.ResourceKeys, auth.ActionDelete},
	{auth.ResourceKeys, auth.ActionImport},
	{auth.ResourceKeys, auth.ActionExport},
	{auth.ResourceCerts, auth.ActionList},
	{auth.ResourceCerts, auth.ActionGenerate},
	{auth.ResourceCerts, auth.ActionRevoke},
	{auth.ResourceBackends, auth.ActionList},
	{auth.ResourceUsers, auth.ActionList},
	{auth.ResourceUsers, auth.ActionCreate},
	{auth.ResourceTenants, auth.ActionList},
	{auth.ResourceSeal, auth.ActionStatus},
	{auth.ResourceSeal, auth.ActionUnseal},
	{auth.ResourceSeal, auth.ActionRekey},
	{auth.ResourcePIN, auth.ActionRead},
	{auth.ResourcePIV, auth.ActionRead},
	{auth.ResourceSSH, auth.ActionUse},
	{auth.ResourcePasswords, auth.ActionRead},
	{auth.ResourceCA, auth.ActionRead},
	{auth.ResourceCeremony, auth.ActionStatus},
}

// handlePIVLogin exchanges a TLS-verified client certificate (PIV smart card
// or mTLS identity) for a bearer token pair. The certificate must resolve to
// an enabled user through the canonical SPKI-thumbprint binding; certificates
// without a user binding are rejected — the TLS layer verifying a chain is
// not an identity.
func (s *Server) handlePIVLogin(w http.ResponseWriter, r *http.Request) {
	if s.tokenIssuer == nil || s.pivLogin == nil || !s.pivLogin.Enabled {
		writeErrorWithMessage(w, ErrUnauthorized, "certificate login is not enabled", http.StatusUnauthorized)
		return
	}

	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		s.auditAuthEvent(r.Context(), "", "auth.login.piv", audit.OutcomeDeny, "no client certificate")
		writeErrorWithMessage(w, ErrUnauthorized, "client certificate required", http.StatusUnauthorized)
		return
	}
	cert := r.TLS.PeerCertificates[0]

	if len(s.pivLogin.TrustedIssuers) > 0 {
		issuerDN := cert.Issuer.String()
		trusted := false
		for _, dn := range s.pivLogin.TrustedIssuers {
			if dn == issuerDN {
				trusted = true
				break
			}
		}
		if !trusted {
			s.auditAuthEvent(r.Context(), cert.Subject.CommonName, "auth.login.piv", audit.OutcomeDeny, "untrusted issuer")
			writeErrorWithMessage(w, ErrUnauthorized, "authentication failed", http.StatusUnauthorized)
			return
		}
	}

	if s.authUsers == nil {
		s.auditAuthEvent(r.Context(), cert.Subject.CommonName, "auth.login.piv", audit.OutcomeDeny, "no user store")
		writeErrorWithMessage(w, ErrUnauthorized, "authentication failed", http.StatusUnauthorized)
		return
	}

	// Canonical cert binding: qrdb's SPKI SHA-256 thumbprint — the single
	// algorithm shared across the stack.
	thumbprint := qrdbsdk.ComputeSPKIThumbprint(cert)
	user, err := s.authUsers.GetByCertFingerprint(r.Context(), thumbprint)
	if err != nil {
		s.auditAuthEvent(r.Context(), cert.Subject.CommonName, "auth.login.piv", audit.OutcomeDeny, "no user binding")
		writeErrorWithMessage(w, ErrUnauthorized, "authentication failed", http.StatusUnauthorized)
		return
	}
	if !user.Enabled {
		s.auditAuthEvent(r.Context(), user.Username, "auth.login.piv", audit.OutcomeDeny, "user disabled")
		writeErrorWithMessage(w, ErrUnauthorized, "authentication failed", http.StatusUnauthorized)
		return
	}

	identity := &auth.Identity{
		Subject:  user.Username,
		TenantID: user.TenantID,
		Metadata: map[string]string{
			"username":     user.Username,
			"display_name": user.DisplayName,
			"auth_method":  "piv",
		},
	}
	if user.Role != "" {
		identity.Roles = []string{user.Role}
	}

	pair, err := s.tokenIssuer.Mint(r.Context(), identity)
	if err != nil {
		s.auditAuthEvent(r.Context(), user.Username, "auth.login.piv", audit.OutcomeDeny, "token mint failed")
		writeErrorWithMessage(w, ErrInternalError, "authentication failed", http.StatusInternalServerError)
		return
	}

	s.auditAuthEvent(r.Context(), user.Username, "auth.login.piv", audit.OutcomeAllow, "")
	writeJSON(w, authTokenResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		TokenType:    pair.TokenType,
		ExpiresIn:    pair.ExpiresIn,
	}, http.StatusOK)
}

// handleAuthRefresh exchanges a valid refresh token for a rotated pair.
func (s *Server) handleAuthRefresh(w http.ResponseWriter, r *http.Request) {
	if s.tokenIssuer == nil {
		writeErrorWithMessage(w, ErrUnauthorized, "session tokens are not enabled", http.StatusUnauthorized)
		return
	}

	var req authRefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		writeErrorWithMessage(w, ErrInvalidRequest, "refresh_token is required", http.StatusBadRequest)
		return
	}

	pair, err := s.tokenIssuer.Refresh(r.Context(), req.RefreshToken)
	if err != nil {
		var reuse *token.RefreshReuseError
		if errors.As(err, &reuse) {
			// Token theft signature: someone replayed a rotated token.
			s.auditAuthEvent(r.Context(), "", "auth.refresh.reuse", audit.OutcomeDeny, "refresh token reuse; family revoked")
		}
		writeErrorWithMessage(w, ErrUnauthorized, "invalid refresh token", http.StatusUnauthorized)
		return
	}

	writeJSON(w, authTokenResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		TokenType:    pair.TokenType,
		ExpiresIn:    pair.ExpiresIn,
	}, http.StatusOK)
}

// handleAuthMe returns the authenticated identity, its effective UI
// permissions, and the server's capability flags.
func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	identity := auth.GetIdentity(r.Context())
	if identity == nil {
		writeErrorWithMessage(w, ErrUnauthorized, "no authenticated identity", http.StatusUnauthorized)
		return
	}

	permissions := make(map[string]bool, len(uiPermissionMatrix))
	for _, pair := range uiPermissionMatrix {
		key := pair[0] + ":" + pair[1]
		if s.rbacMiddleware == nil || s.rbacAuthorizer == nil {
			// RBAC disabled: the server enforces nothing beyond
			// authentication, so the UI should not hide anything either.
			permissions[key] = true
			continue
		}
		permissions[key] = s.rbacAuthorizer.Authorize(r.Context(), identity, pair[0], pair[1]) == nil
	}

	resp := authMeResponse{
		Subject:      identity.Subject,
		TenantID:     identity.TenantID,
		Username:     identity.Metadata["username"],
		DisplayName:  identity.Metadata["display_name"],
		AuthMethod:   identity.Metadata["auth_method"],
		Roles:        identity.Roles,
		Permissions:  permissions,
		Capabilities: s.capabilityFlags(),
	}
	writeJSON(w, resp, http.StatusOK)
}

// handleAuthValidate is the lightweight boot-time session probe.
func (s *Server) handleAuthValidate(w http.ResponseWriter, r *http.Request) {
	identity := auth.GetIdentity(r.Context())
	if identity == nil {
		writeErrorWithMessage(w, ErrUnauthorized, "no authenticated identity", http.StatusUnauthorized)
		return
	}
	writeJSON(w, authValidateResponse{
		Subject:  identity.Subject,
		TenantID: identity.TenantID,
	}, http.StatusOK)
}

// handleAuthLogout revokes the presented refresh token's whole family.
// Idempotent: revoking an unknown or already-revoked token succeeds.
func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if s.tokenIssuer == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var req authRefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err == nil && req.RefreshToken != "" {
		if err := s.tokenIssuer.Revoke(r.Context(), req.RefreshToken); err != nil {
			writeErrorWithMessage(w, ErrInternalError, "logout failed", http.StatusInternalServerError)
			return
		}
	}

	if identity := auth.GetIdentity(r.Context()); identity != nil {
		s.auditAuthEvent(r.Context(), identity.Subject, "auth.logout", audit.OutcomeAllow, "")
	}
	w.WriteHeader(http.StatusNoContent)
}

// capabilityFlags reports which optional subsystems this deployment wired.
// Served only to authenticated callers (inside /auth/me) so an anonymous
// scanner cannot fingerprint the deployment shape.
func (s *Server) capabilityFlags() map[string]bool {
	return map[string]bool{
		"webauthn":   s.webauthnHandler != nil,
		"piv_login":  s.pivLogin != nil && s.pivLogin.Enabled,
		"rbac":       s.rbacMiddleware != nil,
		"ca":         s.caHandlers != nil,
		"custodians": s.custodianHandlers != nil,
		"shares":     s.shareHandlers != nil,
		"tenants":    s.tenantHandlers != nil,
		"passwords":  s.passwordHandlers != nil,
		"platform":   s.platformHandlers != nil,
		"policies":   s.policyHandlers != nil,
		"ceremony":   s.initHandlers != nil,
		"ssh":        s.sshHandlers != nil,
		"frost":      frostEnabled,
		"factors":    s.authFactorHandlers != nil,
		"audit":      s.auditHandlers != nil,
	}
}

// auditAuthEvent records an authentication-plane audit event; a nil audit
// logger drops it.
func (s *Server) auditAuthEvent(ctx context.Context, subject, action, outcome, detail string) {
	if s.auditor == nil {
		return
	}
	event := &audit.Event{
		Timestamp: time.Now().UTC(),
		Subject:   subject,
		Action:    action,
		Resource:  "auth",
		Outcome:   outcome,
	}
	if detail != "" {
		event.Details = map[string]string{"reason": detail}
	}
	if err := s.auditor.Log(ctx, event); err != nil {
		s.logger.Warn("audit log write failed", "action", action, "error", err)
	}
}
