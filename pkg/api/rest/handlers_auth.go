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
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/auth/token"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// PIVLoginOptions configures the TLS-client-certificate login exchange.
type PIVLoginOptions struct {
	// Enabled turns POST /api/v1/auth/login/piv on.
	Enabled bool

	// TrustedIssuers optionally restricts accepted certificate issuer
	// distinguished names (exact match). Empty accepts any issuer the TLS
	// layer verified.
	TrustedIssuers []string

	// AttestationRoots anchors the proof that the login key lives on a
	// smartcard: the PIV attestation CA of the vendor (for a YubiKey, the
	// Yubico PIV Attestation root). A login is treated as hardware-backed
	// only when some certificate the client presents chains to this pool
	// AND carries the same SubjectPublicKeyInfo as the login certificate.
	// Certificates the client presents are chain material, never anchors.
	//
	// Nil means no anchor is configured, and then the exchange refuses
	// every login unless AllowUnattested is set: a DN is not evidence, and
	// a login that cannot prove hardware must not be recorded as hardware.
	AttestationRoots *x509.CertPool

	// AttestationIntermediates optionally carries vendor intermediates the
	// device does not present itself.
	AttestationIntermediates *x509.CertPool

	// AllowUnattested accepts a login whose key no presented certificate
	// attests, minting a token whose attest_level says so. The zero value
	// is strict; set it only for deployments that knowingly accept software
	// keys on this route.
	AllowUnattested bool

	// RecordedLevel optionally looks up the attestation level xkms itself
	// recorded when the login key was enrolled — e.g. from a PIV slot's
	// KeyAttributes.AttestLevel (pkg/xkms's PIVKeyGenerator implementations)
	// or an admin PIV factor's enrollment metadata — keyed by the login
	// certificate. found is false when no such record exists for this
	// certificate, which is not a claim about the key; it means this
	// exchange has nothing to prefer and falls back to the certificate
	// chain alone.
	//
	// Nil means no enrollment lookup is wired, and every login is decided
	// from the certificate chain exactly as before RecordedLevel existed.
	RecordedLevel func(cert *x509.Certificate) (level types.AttestLevel, found bool)
}

// Attestation levels recorded on the token minted by the PIV login exchange,
// in the attest_level claim, so an unattested login is representable rather
// than indistinguishable from a proven one.
//
// These are the REST-local names for the one shared attestation-level
// vocabulary, types.AttestLevel (types.AttestLevelHardware /
// types.AttestLevelUnattested): the wire value is pinned to the shared
// constant's spelling rather than re-declared, so a claim minted here and a
// level recorded by pkg/xkms's PIVKeyGenerator implementations always agree.
// A third value, "software" (types.AttestLevelSoftware), can also reach the
// claim — see attestationLevel — when RecordedLevel reports it; it has no
// package constant here because the certificate-chain path, the only path
// that predates RecordedLevel, can never produce it: a chain proves hardware
// or proves nothing, never that a key is definitely software.
const (
	// PIVAttestLevelHardware means either a presented certificate chained to
	// a configured attestation anchor and attests the login key, or a
	// recorded enrollment level of types.AttestLevelHardware took precedence.
	PIVAttestLevelHardware = string(types.AttestLevelHardware)
	// PIVAttestLevelUnattested means nothing proved the key is on a
	// smartcard and the deployment accepted the login anyway.
	PIVAttestLevelUnattested = string(types.AttestLevelUnattested)
)

// attestLevelMetadataKey is the identity metadata key the token issuer maps
// to the attest_level claim.
const attestLevelMetadataKey = "attest_level"

// attestationLevel decides what is known about the login key, peers[0], and
// returns the level to record, or an empty level with the operator-facing
// reason the login is refused.
//
// Precedence: when RecordedLevel is set and reports a level for the login
// certificate, that level is used as-is and the certificate chain below is
// not consulted at all for this decision — chainAttestationLevel only runs
// when RecordedLevel is nil, or reports not-found for this certificate. This
// is a strict either/or, not a merge of the two signals: a recorded
// types.AttestLevelHardware is never downgraded by a chain that fails to
// prove it, because the chain is never examined once a recorded level is
// found; a recorded types.AttestLevelUnattested or types.AttestLevelSoftware
// is never upgraded by a chain that happens to prove residency, for the same
// reason — the chain-derived path is the fallback for a key with no recorded
// enrollment, not a second opinion on one that has one.
//
// A recorded level still passes through the same admission policy the
// chain-derived path applies: types.AttestLevelHardware is always accepted,
// but anything weaker is accepted only when AllowUnattested is set, exactly
// as an unattested chain-derived login is today. RecordedLevel decides WHAT
// the key is, not whether a non-hardware key may log in — that remains
// AllowUnattested's job.
func (o *PIVLoginOptions) attestationLevel(peers []*x509.Certificate) (level, reason string) {
	if o.RecordedLevel != nil {
		if recorded, found := o.RecordedLevel(peers[0]); found {
			if recorded == types.AttestLevelHardware {
				return PIVAttestLevelHardware, ""
			}
			if o.AllowUnattested {
				return recorded.String(), ""
			}
			return "", "the recorded enrollment level is not hardware-backed and unattested logins are not allowed"
		}
	}
	return o.chainAttestationLevel(peers)
}

// chainAttestationLevel decides what the presented certificate chain alone
// proves about the login key, peers[0]. It is attestationLevel's fallback
// for a key with no recorded enrollment level.
func (o *PIVLoginOptions) chainAttestationLevel(peers []*x509.Certificate) (level, reason string) {
	if o.AttestationRoots == nil {
		if o.AllowUnattested {
			return PIVAttestLevelUnattested, ""
		}
		return "", "no attestation anchor is configured and unattested logins are not allowed"
	}

	login := peers[0]
	anchoredForAnotherKey := false
	for i, candidate := range peers {
		// Every other presented certificate is path-building material for
		// this candidate; the anchors come only from the configuration.
		chain := make([]*x509.Certificate, 0, len(peers))
		chain = append(chain, candidate)
		for j, other := range peers {
			if j != i {
				chain = append(chain, other)
			}
		}
		if _, err := pivcert.VerifyAttestation(chain, &pivcert.AttestationVerifyOptions{
			TrustedRoots:  o.AttestationRoots,
			Intermediates: o.AttestationIntermediates,
		}); err != nil {
			continue
		}
		if bytes.Equal(candidate.RawSubjectPublicKeyInfo, login.RawSubjectPublicKeyInfo) {
			return PIVAttestLevelHardware, ""
		}
		anchoredForAnotherKey = true
	}

	if o.AllowUnattested {
		return PIVAttestLevelUnattested, ""
	}
	if anchoredForAnotherKey {
		return "", "the presented attestation chains to a trusted anchor but attests a different key than the login certificate"
	}
	return "", "no presented certificate chains to a configured attestation anchor"
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
	Subject  string `json:"subject"`
	TenantID string `json:"tenant_id,omitempty"`
	Username string `json:"username,omitempty"`

	// Email is the canonical tenant-unique login key (go-qrdb #190) — the
	// identifier a client can re-authenticate with. Absent for principals
	// that have none (certificate-only identities, service accounts, the
	// loopback token); never fabricated from the username.
	Email       string   `json:"email,omitempty"`
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
	{auth.ResourceKeys, auth.ActionVerify},
	{auth.ResourceKeys, auth.ActionEncrypt},
	{auth.ResourceKeys, auth.ActionDecrypt},
	{auth.ResourceKeys, auth.ActionWrap},
	{auth.ResourceKeys, auth.ActionDerive},
	{auth.ResourceKeys, auth.ActionRotate},
	{auth.ResourceKeys, auth.ActionDelete},
	{auth.ResourceKeys, auth.ActionImport},
	{auth.ResourceKeys, auth.ActionExport},
	{auth.ResourceCerts, auth.ActionList},
	{auth.ResourceCerts, auth.ActionGenerate},
	{auth.ResourceCerts, auth.ActionRevoke},
	{auth.ResourceBackends, auth.ActionList},
	{auth.ResourceUsers, auth.ActionList},
	{auth.ResourceUsers, auth.ActionRead},
	{auth.ResourceUsers, auth.ActionCreate},
	{auth.ResourceUsers, auth.ActionUpdate},
	{auth.ResourceUsers, auth.ActionDelete},
	{auth.ResourceTenants, auth.ActionList},
	{auth.ResourceSeal, auth.ActionStatus},
	{auth.ResourceSeal, auth.ActionSeal},
	{auth.ResourceSeal, auth.ActionUnseal},
	{auth.ResourceSeal, auth.ActionRekey},
	{auth.ResourcePIN, auth.ActionRead},
	{auth.ResourcePIV, auth.ActionRead},
	{auth.ResourceSSH, auth.ActionUse},
	{auth.ResourcePasswords, auth.ActionRead},
	{auth.ResourceCA, auth.ActionRead},
	{auth.ResourceCeremony, auth.ActionStatus},
	{auth.ResourceAudit, auth.ActionRead},
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
		if s.auditAuthDenyOrFail(w, r, "", "auth.login.piv", "no client certificate") {
			return
		}
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
			if s.auditAuthDenyOrFail(w, r, cert.Subject.CommonName, "auth.login.piv", "untrusted issuer") {
				return
			}
			writeErrorWithMessage(w, ErrUnauthorized, "authentication failed", http.StatusUnauthorized)
			return
		}
	}

	// Prove hardware before touching the user store: a certificate that
	// cannot show its key is on a smartcard is refused with the reason on
	// the audit record, where the operator reads it, and a generic answer
	// on the wire.
	attestLevel, refusal := s.pivLogin.attestationLevel(r.TLS.PeerCertificates)
	if refusal != "" {
		if s.auditAuthDenyOrFail(w, r, cert.Subject.CommonName, "auth.login.piv", "attestation: "+refusal) {
			return
		}
		writeErrorWithMessage(w, ErrUnauthorized, "client certificate is not hardware-attested", http.StatusUnauthorized)
		return
	}

	if s.authUsers == nil {
		if s.auditAuthDenyOrFail(w, r, cert.Subject.CommonName, "auth.login.piv", "no user store") {
			return
		}
		writeErrorWithMessage(w, ErrUnauthorized, "authentication failed", http.StatusUnauthorized)
		return
	}

	// Canonical cert binding: qrdb's SPKI SHA-256 thumbprint — the single
	// algorithm shared across the stack.
	thumbprint := qrdbsdk.ComputeSPKIThumbprint(cert)
	user, err := s.authUsers.GetByCertFingerprint(r.Context(), thumbprint)
	if err != nil {
		if s.auditAuthDenyOrFail(w, r, cert.Subject.CommonName, "auth.login.piv", "no user binding") {
			return
		}
		writeErrorWithMessage(w, ErrUnauthorized, "authentication failed", http.StatusUnauthorized)
		return
	}
	if !user.Enabled {
		if s.auditAuthDenyOrFail(w, r, user.Username, "auth.login.piv", "user disabled") {
			return
		}
		writeErrorWithMessage(w, ErrUnauthorized, "authentication failed", http.StatusUnauthorized)
		return
	}

	identity := &auth.Identity{
		Subject:  user.Username,
		TenantID: user.TenantID,
		Metadata: map[string]string{
			"username":             user.Username,
			"display_name":         user.DisplayName,
			"auth_method":          "piv",
			attestLevelMetadataKey: attestLevel,
		},
	}
	if user.Email != "" {
		identity.Metadata["email"] = user.Email
	}
	if user.Role != "" {
		identity.Roles = []string{user.Role}
	}

	pair, err := s.tokenIssuer.Mint(r.Context(), identity)
	if err != nil {
		if s.auditAuthDenyOrFail(w, r, user.Username, "auth.login.piv", "token mint failed") {
			return
		}
		writeErrorWithMessage(w, ErrInternalError, "authentication failed", http.StatusInternalServerError)
		return
	}

	// The token has been minted but not yet handed to the caller: the audit
	// write is part of the login decision (owner ruling, go-xkms#688), so a
	// failed write here must refuse the login rather than hand back an
	// unaudited session grant.
	if auditErr := s.auditAuthEvent(r.Context(), user.Username, "auth.login.piv", audit.OutcomeAllow, "attest_level="+attestLevel); auditErr != nil {
		writeErrorWithMessage(w, ErrInternalError, "authentication failed", http.StatusInternalServerError)
		return
	}
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
			if s.auditAuthDenyOrFail(w, r, "", "auth.refresh.reuse", "refresh token reuse; family revoked") {
				return
			}
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
		Email:        identity.Metadata["email"],
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
		if auditErr := s.auditAuthEvent(r.Context(), identity.Subject, "auth.logout", audit.OutcomeAllow, ""); auditErr != nil {
			writeErrorWithMessage(w, ErrInternalError, "logout failed", http.StatusInternalServerError)
			return
		}
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

// auditAuthEvent records an authentication-plane audit event and applies the
// go-xkms audit write-failure policy (docs/audit-log/engineering.md,
// pkg/audit.ClassifyAction): every "auth.*" action classifies
// SeveritySecurity (the default for an action not explicitly reviewed as
// informational), so a failed write returns *audit.ErrAuditWriteFailed and
// the caller must fail the login/logout request rather than let an
// authentication decision — grant or refusal — stand unaudited. A nil audit
// logger drops the event and returns nil: audit logging is opt-in wiring,
// not itself a failure.
func (s *Server) auditAuthEvent(ctx context.Context, subject, action, outcome, detail string) error {
	if s.auditor == nil {
		return nil
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
	return audit.HandleWriteFailure(s.logger, action, s.auditor.Log(ctx, event))
}

// auditAuthDenyOrFail records a deny outcome for action and reports whether
// the caller should stop: it writes the 500 response and returns true when
// the audit write itself failed (an unaudited refusal is still a
// security-relevant decision that must not proceed silently), or returns
// false so the caller writes its own, more specific deny response.
func (s *Server) auditAuthDenyOrFail(w http.ResponseWriter, r *http.Request, subject, action, detail string) bool {
	if auditErr := s.auditAuthEvent(r.Context(), subject, action, audit.OutcomeDeny, detail); auditErr != nil {
		writeErrorWithMessage(w, ErrInternalError, "authentication failed", http.StatusInternalServerError)
		return true
	}
	return false
}
