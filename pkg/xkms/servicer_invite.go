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

package xkms

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	xkmswebauthn "github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// This file implements the administrator-issued enrollment invitation flow
// (go-xkms#1294 part B): how a provisioned account with zero passkeys
// enrolls its first credential.
//
// An admin creates a user through CreateUser (servicer_user.go), which
// creates it LifecyclePending and mints a single-use invitation through
// s.inviteStore. The invitee redeems the token through exactly one of the
// two entry points below — FIDO2 (BeginInviteRegistration /
// FinishInviteRegistration) or PIV (ActivateInvitePIV) — which binds their
// first credential, activates the account, and redeems the invitation, in
// that order: the credential is bound to a still-PENDING account, so a
// failure before activation leaves the invitation intact and the token
// retryable, and activation is confirmed (by re-reading the account on an
// ambiguous write) before the single-use token is spent — a redeemed
// invitation never outlives an unbound credential, and an active account is
// never left with a still-live token (mirrors go-quicbaas's
// PIVActivator.Activate / ActivateFIDO2Finish ordering).
//
// Every unauthenticated lookup collapses "not found", "expired" and
// "already redeemed" into ErrInviteUnusable (classifyInviteError): telling a
// stranger a token exists but is spent confirms a real user was invited,
// which is the enumeration an opaque token exists to prevent.

// InviteStore is the tenant-routed invitation lifecycle surface CreateUser
// and every invite-redemption entry point consume. It is not a
// re-declaration of qrdb's invitation logic, only the seam pkg/compose wires
// its one production implementation through (see SetInviteStore's doc
// comment on XKMSService and pkg/compose/invite.go's
// tenantPrefixedInviteStore, built unconditionally over the StorageFactory
// seam every other xkmsd subsystem uses, so invitations work in the default
// configuration with no fallback branch).
type InviteStore interface {
	// Create issues an invitation for userID in tenantID and returns the
	// plaintext token, which is returned exactly once and is not
	// recoverable afterwards.
	Create(ctx context.Context, userID, tenantID string, ttl time.Duration) (token string, entity *qrdbsdk.InviteEntity, err error)

	// Lookup resolves a token within tenantID without consuming it.
	Lookup(ctx context.Context, tenantID, token string) (*qrdbsdk.InviteEntity, error)

	// Redeem consumes a token within tenantID exactly once.
	Redeem(ctx context.Context, tenantID, token string) (*qrdbsdk.InviteEntity, error)
}

// InviteConfig controls the operator-configured invitation link base URL and
// TTL bounds. The zero value is usable: an empty PublicBaseURL yields a link
// carrying no origin (only the path), and empty TTL bounds fall back to
// qrdbsdk.DefaultInviteTTL and a 7-day cap.
type InviteConfig struct {
	// PublicBaseURL is the externally reachable origin (and any UI path
	// prefix) invitation links are built from, e.g. "https://kms.example.com/ui".
	// It is never derived from a request's Host header.
	PublicBaseURL string

	// DefaultTTL is how long an invitation stays redeemable when the caller
	// does not request a specific one. Zero defaults to qrdbsdk.DefaultInviteTTL.
	DefaultTTL time.Duration

	// MaxTTL caps a requested TTL; a request above it is clamped, not
	// refused. Zero defaults to 7 days.
	MaxTTL time.Duration
}

// defaultMaxInviteTTL is the fallback cap applied when InviteConfig.MaxTTL is
// zero: long enough that a legitimately delayed invitee is not locked out,
// short enough that a forgotten invitation stops being a live credential.
const defaultMaxInviteTTL = 7 * 24 * time.Hour

// effectiveInviteTTL resolves requested against the configured default and
// cap. A non-positive request takes the configured default; anything above
// the configured (or fallback) cap is clamped down to it.
func (s *XKMSService) effectiveInviteTTL(requested time.Duration) time.Duration {
	def := s.inviteConfig.DefaultTTL
	if def <= 0 {
		def = qrdbsdk.DefaultInviteTTL
	}
	max := s.inviteConfig.MaxTTL
	if max <= 0 {
		max = defaultMaxInviteTTL
	}
	ttl := requested
	if ttl <= 0 {
		ttl = def
	}
	if ttl > max {
		ttl = max
	}
	return ttl
}

// buildInviteURL renders the invitation link an operator's mail or chat
// message carries, from the configured public base URL — never from a
// request's Host header, so the WebAuthn ceremony's RP ID (which must match
// the origin the browser loads the ceremony from) stays the value the
// operator configured, and an admin's own client address never leaks into a
// link mailed to someone else. An empty PublicBaseURL yields a path-only
// value, which is only useful for a caller inspecting the token directly.
func (s *XKMSService) buildInviteURL(tenantID, token string) string {
	base := strings.TrimRight(s.inviteConfig.PublicBaseURL, "/")
	return base + "/#/invite/" + url.PathEscape(tenantID) + "/" + url.PathEscape(token)
}

// classifyInviteError collapses qrdb's invite sentinels into the one opaque
// answer every unauthenticated caller gets (ErrInviteUnusable); anything
// else is a genuine operational failure and keeps its own detail.
func classifyInviteError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, qrdbsdk.ErrInviteNotFound),
		errors.Is(err, qrdbsdk.ErrInviteExpired),
		errors.Is(err, qrdbsdk.ErrInviteAlreadyRedeemed),
		errors.Is(err, qrdbsdk.ErrInviteEmptyToken):
		return ErrInviteUnusable
	default:
		return &ErrUserOperation{Operation: "lookup invite", Err: err}
	}
}

// inviteUserID decodes an invitation's stored subject (qrdb's uint64 user id,
// carried as a string — see invite.Entity.UserID) back into the numeric id.
// A malformed value is reported the same opaque way as any other unusable
// invitation: it cannot be a live token this service issued.
func inviteUserID(entity *qrdbsdk.InviteEntity) (uint64, error) {
	id, err := strconv.ParseUint(entity.UserID, 10, 64)
	if err != nil {
		return 0, ErrInviteUnusable
	}
	return id, nil
}

// createInvite mints a single-use invitation for u in tenantID and returns
// the plaintext token, the link built from it, and its expiry. Called by
// CreateUser (servicer_user.go) immediately after the account is created
// pending; the caller rolls the account back if this fails, so a user never
// exists in a state nothing can activate.
func (s *XKMSService) createInvite(ctx context.Context, tenantID string, userID uint64, requestedTTL time.Duration) (*transport.InviteInfo, error) {
	if s.inviteStore == nil {
		return nil, ErrNotConfigured
	}
	ttl := s.effectiveInviteTTL(requestedTTL)
	token, entity, err := s.inviteStore.Create(ctx, strconv.FormatUint(userID, 10), tenantID, ttl)
	if err != nil {
		return nil, &ErrUserOperation{Operation: "create invite", Err: err}
	}
	return &transport.InviteInfo{
		Token:     token,
		URL:       s.buildInviteURL(tenantID, token),
		ExpiresAt: entity.ExpiresAt,
	}, nil
}

// GetInvite resolves a still-usable invitation's metadata without consuming
// it, for an unauthenticated activation page to render. Every failure —
// absent, expired, redeemed, or a token naming a user record that is no
// longer readable — answers with the one opaque ErrInviteUnusable.
// Implements transport.InviteServicer.
func (s *XKMSService) GetInvite(ctx context.Context, req *transport.GetInviteRequest) (*transport.GetInviteResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if s.inviteStore == nil || s.users == nil {
		return nil, ErrNotConfigured
	}
	entity, err := s.inviteStore.Lookup(ctx, req.TenantID, req.Token)
	if err != nil {
		return nil, classifyInviteError(err)
	}
	userID, err := inviteUserID(entity)
	if err != nil {
		return nil, err
	}
	u, err := s.users.GetUser(ctx, userID)
	if err != nil {
		return nil, ErrInviteUnusable
	}
	return &transport.GetInviteResponse{
		Email:       u.Email,
		DisplayName: u.Name,
		ExpiresAt:   entity.ExpiresAt,
		Methods:     []string{"webauthn", "piv"},
	}, nil
}

// BeginInviteRegistration opens the invite-authorized WebAuthn registration
// ceremony: the invitation authorizes enrolling the FIRST credential of the
// PENDING account it names, which is the one case an unauthenticated caller
// may ever start a registration ceremony for (go-xkms#1294 part B; compare
// pkg/webauthn.Service.BeginRegistration, which refuses every other case).
// Implements transport.InviteServicer.
func (s *XKMSService) BeginInviteRegistration(ctx context.Context, req *transport.BeginInviteRegistrationRequest) (*transport.BeginInviteRegistrationResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if s.inviteStore == nil || s.webauthnService == nil || s.users == nil {
		return nil, ErrNotConfigured
	}
	entity, err := s.inviteStore.Lookup(ctx, req.TenantID, req.Token)
	if err != nil {
		return nil, classifyInviteError(err)
	}
	userID, err := inviteUserID(entity)
	if err != nil {
		return nil, err
	}
	u, err := s.users.GetUser(ctx, userID)
	if err != nil {
		return nil, ErrInviteUnusable
	}

	options, sessionID, err := s.webauthnService.BeginInviteRegistration(ctx, u.Email)
	if err != nil {
		if errors.Is(err, xkmswebauthn.ErrRegistrationRefused) {
			return nil, ErrInviteUnusable
		}
		return nil, &ErrWebAuthnCeremony{Operation: "begin invite registration", Err: err}
	}
	optsJSON, err := json.Marshal(options)
	if err != nil {
		return nil, &ErrWebAuthnCeremony{Operation: "marshal options", Err: err}
	}
	return &transport.BeginInviteRegistrationResponse{SessionID: sessionID, OptionsJSON: string(optsJSON)}, nil
}

// FinishInviteRegistration completes the invite-authorized WebAuthn
// registration ceremony: it binds the credential to the still-pending
// account, activates the account, and redeems the invitation, in that safe
// order (see the file doc comment). Implements transport.InviteServicer.
func (s *XKMSService) FinishInviteRegistration(ctx context.Context, req *transport.FinishInviteRegistrationRequest) (*transport.FinishInviteRegistrationResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if s.inviteStore == nil || s.webauthnService == nil || s.users == nil {
		return nil, ErrNotConfigured
	}
	// Looked up (not redeemed) BEFORE the ceremony is validated: the
	// expensive, failure-prone work must not burn a single-use token when it
	// fails, and a caller whose attestation is rejected can retry with a
	// working authenticator instead of needing to be re-invited.
	if _, err := s.inviteStore.Lookup(ctx, req.TenantID, req.Token); err != nil {
		return nil, classifyInviteError(err)
	}

	parsed, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(req.AttestationJSON))
	if err != nil {
		return nil, &ErrWebAuthnCeremony{Operation: "parse attestation", Err: err}
	}

	user, err := s.webauthnService.FinishInviteRegistration(ctx, req.SessionID, parsed)
	if err != nil {
		if errors.Is(err, xkmswebauthn.ErrRegistrationRefused) {
			return nil, ErrInviteUnusable
		}
		return nil, &ErrWebAuthnCeremony{Operation: "finish invite registration", Err: err}
	}

	userID, err := xkmswebauthn.UserIDFromHandle(user.WebAuthnID())
	if err != nil {
		return nil, &ErrUserOperation{Operation: "decode invite user handle", Err: err}
	}

	if err := s.activateInviteUser(ctx, userID); err != nil {
		return nil, err
	}
	if _, err := s.inviteStore.Redeem(ctx, req.TenantID, req.Token); err != nil {
		return nil, &ErrUserOperation{Operation: "redeem invite", Err: err}
	}
	return &transport.FinishInviteRegistrationResponse{UserID: userID}, nil
}

// ActivateInvitePIV completes PIV invite activation: it verifies the
// presented certificate's chain against the CA's trust roots, binds its SPKI
// thumbprint to the still-pending account, activates the account, and
// redeems the invitation — the same safe order FinishInviteRegistration
// uses, and for the same reason. Implements transport.InviteServicer.
func (s *XKMSService) ActivateInvitePIV(ctx context.Context, req *transport.ActivateInvitePIVRequest) (*transport.ActivateInvitePIVResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if s.inviteStore == nil || s.users == nil {
		return nil, ErrNotConfigured
	}
	if _, err := s.getCA(); err != nil {
		return nil, ErrNotConfigured
	}

	// Looked up BEFORE the certificate is parsed or verified, for the same
	// reason FinishInviteRegistration looks up first: an unauthenticated
	// caller posting an arbitrary certificate must not be able to burn, or
	// probe the state of, a token that was never theirs.
	entity, err := s.inviteStore.Lookup(ctx, req.TenantID, req.Token)
	if err != nil {
		return nil, classifyInviteError(err)
	}
	userID, err := inviteUserID(entity)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(req.CertPEM))
	if block == nil {
		return nil, &ErrPIVCertDecode{Reason: "no PEM block found"}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, &ErrPIVCertDecode{Reason: err.Error()}
	}

	roots, err := s.caRootPool()
	if err != nil {
		return nil, err
	}
	if err := pivcert.VerifyChain(cert, roots, nil); err != nil {
		return nil, &ErrPIVCertRejected{Err: err}
	}

	u, err := s.users.GetUser(ctx, userID)
	if err != nil {
		return nil, ErrInviteUnusable
	}
	if u.Lifecycle != string(qrdbsdk.LifecyclePending) {
		return nil, ErrInviteUnusable
	}

	thumbprint := qrdbsdk.ComputeSPKIThumbprint(cert)
	if _, err := s.users.AddCertBinding(ctx, userID, thumbprint, cert.NotAfter.Unix()); err != nil {
		return nil, &ErrUserOperation{Operation: "bind piv certificate", Err: err}
	}

	if err := s.activateInviteUser(ctx, userID); err != nil {
		return nil, err
	}
	if _, err := s.inviteStore.Redeem(ctx, req.TenantID, req.Token); err != nil {
		return nil, &ErrUserOperation{Operation: "redeem invite", Err: err}
	}
	return &transport.ActivateInvitePIVResponse{UserID: userID}, nil
}

// activateInviteUser transitions userID from pending to active.
//
// A failed write does not prove the state did not land: a commit whose
// response was lost reports failure on an account that IS now active.
// Refusing unconditionally on that outcome would leave a redeemable invite
// on an already-active account. So this reconciles before deciding: it
// re-reads the user and lets the persisted state settle it. Active means the
// write happened and the invite must still be redeemed by the caller; any
// other outcome (including a failed re-read) keeps the fail-closed refusal,
// which leaves the invitation intact and the account recoverable — mirrors
// go-quicbaas's ActivateFIDO2Finish / PIVActivator.Activate.
func (s *XKMSService) activateInviteUser(ctx context.Context, userID uint64) error {
	active := string(qrdbsdk.LifecycleActive)
	if _, err := s.users.UpdateUser(ctx, &qrdbtransport.UpdateUserRequest{ID: userID, Lifecycle: active}); err != nil {
		if u, gErr := s.users.GetUser(ctx, userID); gErr == nil && u != nil && u.Lifecycle == active {
			return nil
		}
		return &ErrUserOperation{Operation: "activate invited user", Err: err}
	}
	return nil
}

// caRootPool builds the trust-root pool PIV invite activation verifies
// against, from the CA's own published bundle — the same cross-signed root
// pool the ACME server and DANE publishing pipeline use (pkg/ca). There is
// no separate PIV-activation trust-anchor configuration surface: xkms owns
// exactly one CA trust pool.
func (s *XKMSService) caRootPool() (*x509.CertPool, error) {
	ca, err := s.getCA()
	if err != nil {
		return nil, ErrNotConfigured
	}
	bundle, err := ca.CABundle()
	if err != nil {
		return nil, &ErrUserOperation{Operation: "load CA bundle", Err: err}
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bundle) {
		return nil, &ErrUserOperation{Operation: "load CA bundle", Err: errCABundleEmpty}
	}
	return pool, nil
}

// errCABundleEmpty reports a CA bundle that parsed no certificates.
var errCABundleEmpty = errors.New("ca bundle contains no parsable certificates")
