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
	// Yubico PIV Attestation root). Setting it makes the exchange strict:
	// every login must present, after the login certificate, a separate PIV
	// slot attestation certificate that chains to this pool, carries the
	// login certificate's SubjectPublicKeyInfo, and satisfies the PIV
	// attestation profile (see verifyAttestationEvidence). Certificates the
	// client presents are chain material, never anchors, and the login
	// certificate is never its own evidence.
	//
	// Nil means no anchor is configured, and then the exchange refuses
	// every login unless AllowUnattested is set: a DN is not evidence, and
	// a login that cannot prove hardware must not be recorded as hardware.
	AttestationRoots *x509.CertPool

	// AttestationIntermediates optionally carries vendor intermediates the
	// device does not present itself.
	AttestationIntermediates *x509.CertPool

	// AttestationPolicy optionally adds the deployment's own requirements on
	// what a verified attestation says — a required touch policy, a PIN
	// policy, a firmware floor — after the built-in profile has passed. A
	// non-nil error refuses the login with PIVRefusalAttestationPolicy. It
	// is consulted only when AttestationRoots is set, and never for a
	// certificate that does not attest the login key.
	AttestationPolicy func(att *pivcert.Attestation) error

	// AllowUnattested accepts a login whose key nothing attests, minting a
	// token whose attest_level says so. It applies only when no
	// AttestationRoots is configured: a deployment that configures
	// attestation trust requires the evidence, so NewServer refuses the two
	// together (ErrPIVLoginUnattestedWithAnchors). The zero value is strict.
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
	// A recorded level is never evidence: with AttestationRoots set the
	// login must still present its attestation, and a recorded level only
	// refuses one the record says is not hardware-backed.
	//
	// Nil means no enrollment lookup is wired, and every login is decided
	// from the certificate chain exactly as before RecordedLevel existed.
	RecordedLevel func(cert *x509.Certificate) (level types.AttestLevel, found bool)

	// TrustDomain is the SPIFFE trust domain the server pins; production
	// hosts must set it. The exchange reads the login certificate's tenant
	// with qrdb's TenantFromClientCert under this pin and looks the user up
	// within that tenant only. The tenant is a SPIFFE trust domain named by
	// both the certificate's first OU and its spiffe://<tenant>/<kind>/<name>
	// SAN, and no tenant may be this pin. Empty skips the pin, which qrdb
	// reserves for tests.
	TrustDomain string
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

// PIVAttestationRefusal is the stable, machine-readable reason the PIV login
// exchange refuses a certificate on attestation grounds. It is written to the
// auth.login.piv audit record ("attestation: <reason>"), where the operator
// reads it; the client is only told the certificate is not hardware-attested.
type PIVAttestationRefusal string

// PIV login attestation refusal reasons.
const (
	// PIVRefusalNoAnchor: no AttestationRoots is configured and unattested
	// logins are not allowed.
	PIVRefusalNoAnchor PIVAttestationRefusal = "no_attestation_anchor"

	// PIVRefusalRecordedNotHardware: RecordedLevel holds an enrollment record
	// for the login key that is not hardware-backed.
	PIVRefusalRecordedNotHardware PIVAttestationRefusal = "recorded_level_not_hardware"

	// PIVRefusalNoEvidence: the client presented no certificate besides the
	// login certificate, so there is no attestation to verify.
	PIVRefusalNoEvidence PIVAttestationRefusal = "no_attestation_evidence"

	// PIVRefusalUntrustedChain: no presented certificate chains to a
	// configured attestation root.
	PIVRefusalUntrustedChain PIVAttestationRefusal = "attestation_chain_untrusted"

	// PIVRefusalKeyMismatch: an attestation chains to a configured root but
	// attests a different key than the login certificate's.
	PIVRefusalKeyMismatch PIVAttestationRefusal = "attested_key_mismatch"

	// PIVRefusalProfile: the certificate attesting the login key is not a
	// PIV slot attestation certificate (see checkAttestationProfile).
	PIVRefusalProfile PIVAttestationRefusal = "attestation_profile_mismatch"

	// PIVRefusalAttestationPolicy: PIVLoginOptions.AttestationPolicy
	// refused the verified attestation.
	PIVRefusalAttestationPolicy PIVAttestationRefusal = "attestation_policy_refused"
)

// ErrPIVAttestationRefused is the error the PIV login exchange refuses a
// certificate with on attestation grounds. Reason is stable; Cause, when
// set, is the underlying verification failure, for server-side logs only.
type ErrPIVAttestationRefused struct {
	Reason PIVAttestationRefusal
	Cause  error
}

// Error implements error.
func (e *ErrPIVAttestationRefused) Error() string {
	if e.Cause != nil {
		return "rest: piv login attestation refused: " + string(e.Reason) + ": " + e.Cause.Error()
	}
	return "rest: piv login attestation refused: " + string(e.Reason)
}

// Unwrap returns the underlying verification failure.
func (e *ErrPIVAttestationRefused) Unwrap() error { return e.Cause }

// refusePIVAttestation builds the refusal for reason, wrapping cause.
func refusePIVAttestation(reason PIVAttestationRefusal, cause error) *ErrPIVAttestationRefused {
	return &ErrPIVAttestationRefused{Reason: reason, Cause: cause}
}

// attestationLevel decides what is known about the login key, peers[0], and
// returns the level to record, or the refusal.
//
// With AttestationRoots configured the exchange is strict and the presented
// attestation alone decides: verifyAttestationEvidence must prove the key,
// whatever RecordedLevel says. A recorded level can only refuse there — a
// record saying the key is not hardware-backed is never overruled by a chain.
//
// Without AttestationRoots, when RecordedLevel is set and reports a level for
// the login certificate, that level is used as-is: types.AttestLevelHardware
// is accepted, and anything weaker only when AllowUnattested is set.
// RecordedLevel decides WHAT the key is, not whether a non-hardware key may
// log in — that remains AllowUnattested's job. With no record, the login is
// accepted as unattested only when AllowUnattested is set.
func (o *PIVLoginOptions) attestationLevel(peers []*x509.Certificate) (string, *ErrPIVAttestationRefused) {
	recorded, found := types.AttestLevel(""), false
	if o.RecordedLevel != nil {
		recorded, found = o.RecordedLevel(peers[0])
	}

	if o.AttestationRoots != nil {
		if found && recorded != types.AttestLevelHardware {
			return "", refusePIVAttestation(PIVRefusalRecordedNotHardware, nil)
		}
		if refusal := o.verifyAttestationEvidence(peers); refusal != nil {
			return "", refusal
		}
		return PIVAttestLevelHardware, nil
	}

	if found {
		if recorded == types.AttestLevelHardware {
			return PIVAttestLevelHardware, nil
		}
		if o.AllowUnattested {
			return recorded.String(), nil
		}
		return "", refusePIVAttestation(PIVRefusalRecordedNotHardware, nil)
	}
	if o.AllowUnattested {
		return PIVAttestLevelUnattested, nil
	}
	return "", refusePIVAttestation(PIVRefusalNoAnchor, nil)
}

// verifyAttestationEvidence proves the login key, peers[0], is a PIV slot key
// from the evidence the client presented after it. It is the strict contract
// of a PIV slot attestation (Yubico PIV attestation; NIST SP 800-73 slot
// model): a separate attestation certificate for the slot,
//
//  1. chains to a configured AttestationRoots anchor, with the other
//     presented certificates (the device attestation certificate, slot f9)
//     and AttestationIntermediates as path material only;
//  2. carries exactly the login certificate's SubjectPublicKeyInfo, so the
//     key the TLS handshake proved possession of is the key attested;
//  3. satisfies the PIV slot attestation profile (checkAttestationProfile),
//     then AttestationPolicy when one is set.
//
// The login certificate is never its own evidence, even when it chains to an
// attestation root itself. When no candidate passes, the refusal is the one
// from the candidate that got furthest, so a borrowed attestation for another
// key reads as a key mismatch rather than as an untrusted chain.
func (o *PIVLoginOptions) verifyAttestationEvidence(peers []*x509.Certificate) *ErrPIVAttestationRefused {
	login := peers[0]
	var refusal *ErrPIVAttestationRefused
	stage := 0
	refuse := func(reached int, reason PIVAttestationRefusal, cause error) {
		if reached > stage {
			stage = reached
			refusal = refusePIVAttestation(reason, cause)
		}
	}

	for i, candidate := range peers[1:] {
		if candidate == nil || bytes.Equal(candidate.Raw, login.Raw) {
			continue
		}
		chain := make([]*x509.Certificate, 0, len(peers)-1)
		chain = append(chain, candidate)
		for j, other := range peers[1:] {
			if j != i {
				chain = append(chain, other)
			}
		}
		att, err := pivcert.VerifyAttestation(chain, &pivcert.AttestationVerifyOptions{
			TrustedRoots:  o.AttestationRoots,
			Intermediates: o.AttestationIntermediates,
		})
		if err != nil {
			refuse(1, PIVRefusalUntrustedChain, err)
			continue
		}
		if !bytes.Equal(candidate.RawSubjectPublicKeyInfo, login.RawSubjectPublicKeyInfo) {
			refuse(2, PIVRefusalKeyMismatch, nil)
			continue
		}
		if err := checkAttestationProfile(att); err != nil {
			refuse(3, PIVRefusalProfile, err)
			continue
		}
		if o.AttestationPolicy != nil {
			if err := o.AttestationPolicy(att); err != nil {
				refuse(4, PIVRefusalAttestationPolicy, err)
				continue
			}
		}
		return nil
	}

	if refusal == nil {
		return refusePIVAttestation(PIVRefusalNoEvidence, nil)
	}
	return refusal
}

// checkAttestationProfile checks that a verified certificate is a PIV slot
// attestation certificate and not merely some certificate for the same key:
// it must carry the Yubico PIV attestation claims (pkg/pivcert, the
// 1.3.6.1.4.1.41482.3 arc) that every slot attestation carries — firmware
// version, device serial, and the slot's PIN and touch policy — with every
// present extension decodable and both policies values this build knows.
// The form factor is not required: firmware that predates it omits it.
func checkAttestationProfile(att *pivcert.Attestation) error {
	switch {
	case len(att.Unparseable) > 0:
		return ErrPIVAttestationUnparseable
	case att.FirmwareVersion == nil, att.SerialNumber == nil, att.PINPolicy == nil, att.TouchPolicy == nil:
		return ErrPIVAttestationClaimMissing
	case !att.PINPolicy.Known(), !att.TouchPolicy.Known():
		return ErrPIVAttestationPolicyUnknown
	}
	return nil
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

	// Permissions maps every "resource:action" the caller holds, as qrdb's
	// RBAC lists it, to true; a permission not held is absent. With RBAC
	// disabled it carries every registered permission (the server enforces
	// nothing more).
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
	if refusal != nil {
		s.logger.Info("piv login refused on attestation", "subject", cert.Subject.CommonName, "error", refusal)
		if s.auditAuthDenyOrFail(w, r, cert.Subject.CommonName, "auth.login.piv", "attestation: "+string(refusal.Reason)) {
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

	// This is a public route, so no middleware has bound a tenant: the
	// certificate names it, and the thumbprint is looked up within that
	// tenant only, as go-qrdb's pkg/auth/mtls.go TenantFromClientCert
	// requires of a composing host. These are the four steps of
	// pkg/acme/admin/auth_mtls.go authenticateCertificate (go-xkms#1240).
	// A certificate whose OU and SPIFFE SAN do not name the same tenant is
	// refused; a tenant in a header or the body is never read.
	tenantID, err := qrdbsdk.TenantFromClientCert(cert, s.pivLogin.TrustDomain)
	if err != nil {
		s.logger.Info("piv login refused on certificate tenant", "subject", cert.Subject.CommonName, "error", err)
		if s.auditAuthDenyOrFail(w, r, cert.Subject.CommonName, "auth.login.piv", "certificate tenant refused") {
			return
		}
		writeErrorWithMessage(w, ErrUnauthorized, "authentication failed", http.StatusUnauthorized)
		return
	}
	tenantID = qrdbsdk.NormalizeTenantID(tenantID)
	user, err := s.authUsers.GetByCertFingerprint(qrdbsdk.ContextWithTenant(r.Context(), tenantID), thumbprint)
	if err != nil {
		if s.auditAuthDenyOrFail(w, r, cert.Subject.CommonName, "auth.login.piv", "no user binding") {
			return
		}
		writeErrorWithMessage(w, ErrUnauthorized, "authentication failed", http.StatusUnauthorized)
		return
	}
	if qrdbsdk.NormalizeTenantID(user.TenantID) != tenantID {
		if s.auditAuthDenyOrFail(w, r, user.Username, "auth.login.piv", "certificate tenant mismatch") {
			return
		}
		writeErrorWithMessage(w, ErrUnauthorized, "authentication failed", http.StatusUnauthorized)
		return
	}
	user.TenantID = tenantID
	if !user.Enabled {
		if s.auditAuthDenyOrFail(w, r, user.Username, "auth.login.piv", "user disabled") {
			return
		}
		writeErrorWithMessage(w, ErrUnauthorized, "authentication failed", http.StatusUnauthorized)
		return
	}

	// The session token this mints is accepted on qrdb's chain with an
	// unobservable login method, so the account's permitted-method policy
	// is enforced here, by the issuer, for the method that authenticated:
	// the PIV smart card. qrdb keeps MethodPIV distinct from MethodMTLS, so
	// a policy can permit one without the other.
	if err := qrdbsdk.CheckAuthMethod(&qrdbsdk.User{Username: user.Username, TenantID: user.TenantID, AuthMethods: user.AuthMethods}, qrdbsdk.MethodPIV); err != nil {
		if s.auditAuthDenyOrFail(w, r, user.Username, "auth.login.piv", "method not permitted") {
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
			"auth_method":          qrdbsdk.MethodPIV,
			attestLevelMetadataKey: attestLevel,
			// Declares Subject's encoding explicitly for the refresh-time
			// re-check (go-xkms#1297 review): QRDBUserResolver must never
			// guess it from the subject's shape. This exchange serves both
			// PIV and mTLS certificate logins; both mint a username subject.
			auth.SubjectKindMetadataKey: auth.SubjectKindUsername,
		},
	}
	if user.Email != "" {
		identity.Metadata["email"] = user.Email
	}
	if len(user.Roles) > 0 {
		identity.Roles = append([]string(nil), user.Roles...)
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

// identityAuthMethod names the method that authenticated identity. Every xkms
// authenticator stamps it into Metadata; the qrdb node's own mTLS
// authenticator, which decides any request presenting a verified client
// certificate (ChainAfterMTLS), stamps nothing, so an unstamped identity on a
// request that carries a client certificate was authenticated by mTLS.
func identityAuthMethod(r *http.Request, identity *auth.Identity) string {
	if method := identity.Metadata["auth_method"]; method != "" {
		return method
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return qrdbsdk.MethodMTLS
	}
	return ""
}

// handleAuthMe returns the authenticated identity, its effective UI
// permissions, and the server's capability flags.
func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	identity := auth.GetIdentity(r.Context())
	if identity == nil {
		writeErrorWithMessage(w, ErrUnauthorized, "no authenticated identity", http.StatusUnauthorized)
		return
	}

	authorizer := s.rbacAuthorizer
	if s.rbacMiddleware == nil {
		// RBAC disabled: the server enforces nothing beyond authentication,
		// so a disabled authorizer reports every permission and the UI hides
		// nothing either.
		authorizer = nil
	}
	held, err := authorizer.ListPermissions(r.Context(), identity)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	permissions := make(map[string]bool, len(held))
	for _, name := range held {
		permissions[name] = true
	}

	// An identity the qrdb node bound to a user account carries the account's
	// username in Username (BindUser) and its immutable id in Subject; an
	// identity minted from an xkms token carries the username in Metadata.
	username := identity.Username
	if username == "" {
		username = identity.Metadata["username"]
	}

	resp := authMeResponse{
		Subject:      identity.Subject,
		TenantID:     identity.TenantID,
		Username:     username,
		Email:        identity.Metadata["email"],
		DisplayName:  identity.Metadata["display_name"],
		AuthMethod:   identityAuthMethod(r, identity),
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
		"webauthn":         s.webauthnHandler != nil,
		"piv_login":        s.pivLogin != nil && s.pivLogin.Enabled,
		"rbac":             s.rbacMiddleware != nil,
		"ca":               s.caHandlers != nil,
		"tenants":          s.tenantHandlers != nil,
		"passwords":        s.passwordHandlers != nil,
		"platform":         s.platformHandlers != nil,
		"tpm_policies":     s.xkmsService != nil && s.xkmsService.TPMPolicyService() != nil,
		"oidc_credentials": s.xkmsService != nil && s.xkmsService.OIDCCredentialService() != nil,
		"ssh":              s.sshHandlers != nil,
		"frost":            frostEnabled,
		"cluster":          s.xkmsService != nil && s.xkmsService.Clustered(),
	}
}

// auditAuthEvent records an authentication-plane audit event. A failed write
// returns *qrdbsdk.AuditGateError and the caller must fail the login/logout
// request rather than let an authentication decision — grant or refusal —
// stand unaudited (docs/audit-log/engineering.md). A nil audit logger drops
// the event and returns nil: audit logging is opt-in wiring, not itself a
// failure.
func (s *Server) auditAuthEvent(ctx context.Context, subject, action, outcome, detail string) error {
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
	return audit.Emit(ctx, s.auditor, event)
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
