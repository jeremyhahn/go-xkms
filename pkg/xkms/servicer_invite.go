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

	qrdbuser "github.com/jeremyhahn/go-qrdb/pkg/user"
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

// requireSystemTenantInvite refuses, before any lookup, an invitation of any
// tenant but the system tenant, the WebAuthn relying party's tenant, with the
// opaque answer every unusable invite gets. Redemption reads and activates
// the invited account without an authenticated caller, so it serves only the
// tenant it can bind safely; tenant-scoped redemption is go-xkms #2202.
func requireSystemTenantInvite(tenantID string) error {
	if qrdbsdk.NormalizeTenantID(tenantID) != qrdbsdk.SystemTenantID {
		return ErrInviteUnusable
	}
	return nil
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
	if err := requireSystemTenantInvite(req.TenantID); err != nil {
		return nil, err
	}
	if s.inviteStore == nil || !s.inviteUsersConfigured() {
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
	u, err := s.getInviteUser(ctx, req.TenantID, userID)
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
	if err := requireSystemTenantInvite(req.TenantID); err != nil {
		return nil, err
	}
	if s.inviteStore == nil || s.webauthnService == nil || !s.inviteUsersConfigured() {
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
	if _, err := s.getInviteUser(ctx, req.TenantID, userID); err != nil {
		return nil, ErrInviteUnusable
	}

	// The ceremony binds the account the invitation names, by its user
	// handle, never an email lookup: the email can name another account.
	invitedHandle := xkmswebauthn.HandleFromUserID(userID)

	// An account whose credential was stored under this invitation but
	// whose activation then failed resumes with a possession proof: the
	// options are a WebAuthn get for exactly that credential, answered
	// through FinishInviteRegistration.
	var options any
	ceremony := transport.InviteCeremonyGet
	assertion, sessionID, err := s.webauthnService.BeginInviteResume(ctx, invitedHandle, entity.CreatedAt)
	switch {
	case err == nil:
		options = assertion
	case errors.Is(err, xkmswebauthn.ErrInviteNotResumable):
		creation, regSessionID, regErr := s.webauthnService.BeginInviteRegistration(ctx, invitedHandle)
		if regErr != nil {
			if errors.Is(regErr, xkmswebauthn.ErrRegistrationRefused) {
				return nil, ErrInviteUnusable
			}
			return nil, &ErrWebAuthnCeremony{Operation: "begin invite registration", Err: regErr}
		}
		options, sessionID, ceremony = creation, regSessionID, transport.InviteCeremonyCreate
	default:
		return nil, &ErrWebAuthnCeremony{Operation: "begin invite resume", Err: err}
	}
	optsJSON, err := json.Marshal(options)
	if err != nil {
		return nil, &ErrWebAuthnCeremony{Operation: "marshal options", Err: err}
	}
	return &transport.BeginInviteRegistrationResponse{SessionID: sessionID, OptionsJSON: string(optsJSON), Ceremony: ceremony}, nil
}

// FinishInviteRegistration completes the invite-authorized WebAuthn
// registration ceremony: it binds the credential to the still-pending
// account, activates the account, and redeems the invitation, in that safe
// order (see the file doc comment). Implements transport.InviteServicer.
func (s *XKMSService) FinishInviteRegistration(ctx context.Context, req *transport.FinishInviteRegistrationRequest) (*transport.FinishInviteRegistrationResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if err := requireSystemTenantInvite(req.TenantID); err != nil {
		return nil, err
	}
	if s.inviteStore == nil || s.webauthnService == nil || !s.inviteUsersConfigured() {
		return nil, ErrNotConfigured
	}
	// Looked up (not redeemed) BEFORE the ceremony is validated: the
	// expensive, failure-prone work must not burn a single-use token when it
	// fails, and a caller whose attestation is rejected can retry with a
	// working authenticator instead of needing to be re-invited.
	entity, err := s.inviteStore.Lookup(ctx, req.TenantID, req.Token)
	if err != nil {
		return nil, classifyInviteError(err)
	}
	invitedID, err := inviteUserID(entity)
	if err != nil {
		return nil, err
	}

	// The answer is either the attestation of a new enrolment or, after a
	// finish whose credential was stored but whose activation then failed,
	// the assertion answering BeginInviteResume's get ceremony. Re-sending
	// the attestation proves nothing (its credential ID and public key are
	// public), so only a valid assertion by the enrolled credential over
	// the resume session's challenge resumes. Both are bound to this
	// invitation's account; neither touches another invitation.
	invitedHandle := xkmswebauthn.HandleFromUserID(invitedID)
	var user xkmswebauthn.User
	if parsed, perr := protocol.ParseCredentialCreationResponseBody(strings.NewReader(req.AttestationJSON)); perr == nil {
		user, err = s.webauthnService.FinishInviteRegistration(ctx, req.SessionID, invitedHandle, parsed)
	} else if asserted, aerr := protocol.ParseCredentialRequestResponseBody(strings.NewReader(req.AttestationJSON)); aerr == nil {
		user, err = s.webauthnService.FinishInviteResume(ctx, req.SessionID, invitedHandle, entity.CreatedAt, asserted)
	} else {
		// No assertion: the session is still claimed, so a refused
		// answer leaves no challenge to sign later.
		_, _ = s.webauthnService.FinishInviteResume(ctx, req.SessionID, invitedHandle, entity.CreatedAt, nil)
		return nil, &ErrWebAuthnCeremony{Operation: "parse attestation", Err: perr}
	}
	if err != nil {
		if errors.Is(err, xkmswebauthn.ErrRegistrationRefused) || errors.Is(err, xkmswebauthn.ErrInviteNotResumable) {
			return nil, ErrInviteUnusable
		}
		return nil, &ErrWebAuthnCeremony{Operation: "finish invite registration", Err: err}
	}

	userID, err := xkmswebauthn.UserIDFromHandle(user.WebAuthnID())
	if err != nil {
		return nil, &ErrUserOperation{Operation: "decode invite user handle", Err: err}
	}
	// Defence in depth: the enrolled account is the invited one.
	if userID != invitedID {
		return nil, ErrInviteUnusable
	}

	if err := s.activateInviteUser(ctx, req.TenantID, userID); err != nil {
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
	if err := requireSystemTenantInvite(req.TenantID); err != nil {
		return nil, err
	}
	// PIV redemption needs the node's conditional activation, which only
	// the embedded node's user service (InviteUserService) carries.
	if s.inviteStore == nil || s.inviteUsers == nil {
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

	// The account must be the invitation's, in the invitation's tenant.
	if _, err := s.getInviteUser(ctx, req.TenantID, userID); err != nil {
		return nil, ErrInviteUnusable
	}

	// One conditional commit binds the certificate and activates the
	// account, and only while it is pending with no binding: of concurrent
	// redemptions exactly one binds its certificate (Codex round-4 P1,
	// ruling 952); every other one is the opaque unusable answer.
	thumbprint := qrdbsdk.ComputeSPKIThumbprint(cert)
	if _, err := s.inviteUsers.ActivateWithCertBinding(qrdbsdk.ContextWithTenant(ctx, req.TenantID), userID, thumbprint, cert.NotAfter.Unix()); err != nil {
		var notPending *qrdbuser.AccountNotPendingError
		if errors.As(err, &notPending) {
			return nil, ErrInviteUnusable
		}
		return nil, &ErrUserOperation{Operation: "activate invited user with piv certificate", Err: err}
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
func (s *XKMSService) activateInviteUser(ctx context.Context, tenantID string, userID uint64) error {
	if err := s.setInviteUserActive(ctx, tenantID, userID); err != nil {
		if u, gErr := s.getInviteUser(ctx, tenantID, userID); gErr == nil && u.Lifecycle == string(qrdbsdk.LifecycleActive) {
			return nil
		}
		if errors.Is(err, ErrInviteUnusable) {
			return ErrInviteUnusable
		}
		return &ErrUserOperation{Operation: "activate invited user", Err: err}
	}
	return nil
}

// InviteUserService is the embedded node's user service (Node.UserService)
// as invitation redemption uses it. Redemption runs for an unauthenticated
// caller, whom the node's client refuses; the node's own service reads and
// writes in the tenant the context names without authorizing a caller, so
// the invitation token, validated first, is the only authority redemption
// acts on.
//
// ActivateWithCertBinding is qrdb's conditional first-credential
// activation (qrdbuser.CertActivator): it binds the certificate to a
// pending account holding no binding and activates it in one commit, and
// refuses any other account with *qrdbuser.AccountNotPendingError. PIV
// redemption needs it so concurrent redemptions bind one certificate.
type InviteUserService interface {
	GetUser(ctx context.Context, id uint64) (*qrdbsdk.User, error)
	UpdateUser(ctx context.Context, req *qrdbsdk.UpdateUserRequest) (*qrdbsdk.User, error)
	ActivateWithCertBinding(ctx context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbsdk.User, error)
}

// inviteAccount is what redemption reads of the account an invitation names.
type inviteAccount struct {
	Email     string
	Name      string
	Lifecycle string
}

// inviteUsersConfigured reports whether redemption has a user service to
// read and activate the invited account through.
func (s *XKMSService) inviteUsersConfigured() bool {
	return s.inviteUsers != nil || s.users != nil
}

// getInviteUser reads the account an invitation of tenantID names: through
// the node's user service in that tenant when one is wired, refusing a
// record of another tenant, else through the user client.
func (s *XKMSService) getInviteUser(ctx context.Context, tenantID string, userID uint64) (*inviteAccount, error) {
	if s.inviteUsers == nil {
		u, err := s.users.GetUser(ctx, userID)
		if err != nil {
			return nil, err
		}
		return &inviteAccount{Email: u.Email, Name: u.Name, Lifecycle: u.Lifecycle}, nil
	}
	u, err := s.inviteUsers.GetUser(qrdbsdk.ContextWithTenant(ctx, tenantID), userID)
	if err != nil {
		return nil, err
	}
	if u == nil || qrdbsdk.NormalizeTenantID(u.TenantID) != qrdbsdk.NormalizeTenantID(tenantID) {
		return nil, ErrInviteUnusable
	}
	return &inviteAccount{Email: u.Email, Name: u.Name, Lifecycle: string(u.Lifecycle)}, nil
}

// setInviteUserActive writes the invited account of tenantID active.
func (s *XKMSService) setInviteUserActive(ctx context.Context, tenantID string, userID uint64) error {
	if s.inviteUsers == nil {
		_, err := s.users.UpdateUser(ctx, &qrdbtransport.UpdateUserRequest{ID: userID, Lifecycle: string(qrdbsdk.LifecycleActive)})
		return err
	}
	// The ceremony checked the lifecycle before this call; an administrator
	// may have disabled the account since. The guard judges the committed
	// record the conditional commit swaps against, so only a still-pending
	// account is activated: a disable is never undone.
	_, err := s.inviteUsers.UpdateUser(qrdbsdk.ContextWithTenant(ctx, tenantID), &qrdbsdk.UpdateUserRequest{
		ID:        userID,
		Lifecycle: qrdbsdk.LifecycleActive,
		Guard: func(prior, _ *qrdbsdk.User) error {
			if prior.Lifecycle != qrdbsdk.LifecyclePending {
				return ErrInviteUnusable
			}
			return nil
		},
	})
	return err
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
