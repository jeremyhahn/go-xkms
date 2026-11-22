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

	qrdbtenant "github.com/jeremyhahn/go-qrdb/pkg/tenant"
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
// FinishInviteRegistration) or PIV (ActivateInvitePIV).
//
// FIDO2 binds the first credential, activates the account, and redeems the
// invitation, in that order. The ceremony session must belong to the user
// the invitation names: the webauthn finish refuses any other account's
// session before it persists a credential. The single-use session (taken
// atomically) serialises concurrent finishes of one ceremony, and a failure
// before activation leaves the invitation intact and the token retryable;
// activation is confirmed (by re-reading the account on an ambiguous
// write) before the token is spent.
//
// PIV runs validate, claim, bind, activate: the certificate chain and the
// pending account are checked first (a failure leaves the invitation
// retryable), then the invitation is claimed with the store's single-winner
// Redeem, so of concurrent requests only one binds a certificate. A bind or
// activation failure after the claim fails closed: the account stays
// pending and needs a new invitation.
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
	token, entity, err := s.inviteStore.Create(inviteStoreContext(ctx), strconv.FormatUint(userID, 10), tenantID, ttl)
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
	if s.inviteStore == nil || s.inviteUserClient() == nil {
		return nil, ErrNotConfigured
	}
	entity, err := s.inviteStore.Lookup(inviteStoreContext(ctx), req.TenantID, req.Token)
	if err != nil {
		return nil, classifyInviteError(err)
	}
	ctx = bindInviteTenant(ctx, req.TenantID)
	userID, err := inviteUserID(entity)
	if err != nil {
		return nil, err
	}
	u, err := s.inviteUserClient().GetUser(ctx, userID)
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
	if s.inviteStore == nil || s.webAuthn() == nil || s.inviteUserClient() == nil {
		return nil, ErrNotConfigured
	}
	entity, err := s.inviteStore.Lookup(inviteStoreContext(ctx), req.TenantID, req.Token)
	if err != nil {
		return nil, classifyInviteError(err)
	}
	// After the lookup: an unknown invite answers the same for any tenant,
	// so the refusal does not reveal the served tenant (ruling 1041 (2)).
	if err := s.ensureInviteTenantServed(req.TenantID); err != nil {
		return nil, err
	}
	ctx = bindInviteTenant(ctx, req.TenantID)
	userID, err := inviteUserID(entity)
	if err != nil {
		return nil, err
	}
	if _, err := s.inviteUserClient().GetUser(ctx, userID); err != nil {
		return nil, ErrInviteUnusable
	}

	// The invite's own account, by id, in the invite's validated tenant
	// (bound on ctx): never re-resolve its email in the WebAuthn store's
	// configured scope.
	options, sessionID, err := s.webAuthn().BeginInviteRegistrationForUser(ctx, xkmswebauthn.HandleFromUserID(userID))
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
	if s.inviteStore == nil || s.webAuthn() == nil || s.inviteUserClient() == nil {
		return nil, ErrNotConfigured
	}
	// Looked up (not redeemed) BEFORE the ceremony is validated: the
	// expensive, failure-prone work must not burn a single-use token when it
	// fails, and a caller whose attestation is rejected can retry with a
	// working authenticator instead of needing to be re-invited.
	entity, err := s.inviteStore.Lookup(inviteStoreContext(ctx), req.TenantID, req.Token)
	if err != nil {
		return nil, classifyInviteError(err)
	}
	// The ceremony must be the one begun for THIS invitation's user: the
	// webauthn finish refuses a session of any other account before it
	// persists a credential, so one live token cannot complete (and
	// activate) a ceremony begun with another.
	inviteeID, err := inviteUserID(entity)
	if err != nil {
		return nil, err
	}
	// After the lookup, as in BeginInviteRegistration (ruling 1041 (2)).
	if err := s.ensureInviteTenantServed(req.TenantID); err != nil {
		return nil, err
	}
	ctx = bindInviteTenant(ctx, req.TenantID)

	parsed, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(req.AttestationJSON))
	if err != nil {
		return nil, &ErrWebAuthnCeremony{Operation: "parse attestation", Err: err}
	}

	user, err := s.webAuthn().FinishInviteRegistration(ctx, req.SessionID, xkmswebauthn.HandleFromUserID(inviteeID), parsed)
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
	if _, err := s.inviteStore.Redeem(inviteStoreContext(ctx), req.TenantID, req.Token); err != nil {
		return nil, &ErrUserOperation{Operation: "redeem invite", Err: err}
	}
	return &transport.FinishInviteRegistrationResponse{UserID: userID}, nil
}

// ActivateInvitePIV completes PIV invite activation in the safe order
// validate, claim, bind, activate: it verifies the presented certificate's
// chain against the CA's trust roots and checks the account is still
// pending, then claims the invitation (the store's single-winner Redeem),
// then binds the certificate's SPKI thumbprint to the account and
// activates it. A request that fails validation never claims, so the
// invitation stays retryable; of concurrent requests only the one that
// wins the claim binds. If the bind or the activation fails after the
// claim, the request fails closed: the account stays pending and needs a
// new invitation. Implements transport.InviteServicer.
func (s *XKMSService) ActivateInvitePIV(ctx context.Context, req *transport.ActivateInvitePIVRequest) (*transport.ActivateInvitePIVResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if s.inviteStore == nil || s.inviteUserClient() == nil {
		return nil, ErrNotConfigured
	}
	if _, err := s.getCA(); err != nil {
		return nil, ErrNotConfigured
	}

	// Looked up BEFORE the certificate is parsed or verified, for the same
	// reason FinishInviteRegistration looks up first: an unauthenticated
	// caller posting an arbitrary certificate must not be able to burn, or
	// probe the state of, a token that was never theirs.
	entity, err := s.inviteStore.Lookup(inviteStoreContext(ctx), req.TenantID, req.Token)
	if err != nil {
		return nil, classifyInviteError(err)
	}
	ctx = bindInviteTenant(ctx, req.TenantID)
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

	// The certificate must name the invited account's tenant under the
	// rule and trust-domain pin PIV login applies (handlePIVLogin reads
	// qrdbsdk.TenantFromClientCert under the same pin): a certificate the
	// CA trusts but that names another tenant would be bound where login
	// never looks it up. Checked before anything is claimed or bound.
	certTenant, err := qrdbsdk.TenantFromClientCert(cert, s.SPIFFETrustDomain())
	if err != nil {
		return nil, &ErrPIVCertRejected{Err: err}
	}

	u, err := s.inviteUserClient().GetUser(ctx, userID)
	if err != nil {
		return nil, ErrInviteUnusable
	}
	if u.Lifecycle != string(qrdbsdk.LifecyclePending) {
		return nil, ErrInviteUnusable
	}
	if certTenant != req.TenantID || (u.TenantID != "" && u.TenantID != req.TenantID) {
		return nil, &ErrPIVCertRejected{Err: errPIVCertTenantMismatch}
	}

	// Claim the invitation BEFORE anything is bound. Concurrent requests can
	// all pass the lookup and the pending check above; the store's Redeem
	// resolves them to exactly one winner (ErrAlreadyRedeemed for the
	// rest), so only the winner binds its certificate.
	if _, err := s.inviteStore.Redeem(inviteStoreContext(ctx), req.TenantID, req.Token); err != nil {
		return nil, ErrInviteUnusable
	}

	thumbprint := qrdbsdk.ComputeSPKIThumbprint(cert)
	if _, err := s.inviteUserClient().AddCertBinding(ctx, userID, thumbprint, cert.NotAfter.Unix()); err != nil {
		return nil, &ErrUserOperation{Operation: "bind piv certificate", Err: err}
	}

	if err := s.activateInviteUser(ctx, userID); err != nil {
		return nil, err
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
	if _, err := s.inviteUserClient().UpdateUser(ctx, &qrdbtransport.UpdateUserRequest{ID: userID, Lifecycle: active}); err != nil {
		if u, gErr := s.inviteUserClient().GetUser(ctx, userID); gErr == nil && u != nil && u.Lifecycle == active {
			return nil
		}
		return &ErrUserOperation{Operation: "activate invited user", Err: err}
	}
	return nil
}

// InviteUserClient is the part of qrdbtransport.UserClient the invite
// routes call: they read the invited user, bind a PIV certificate to it and
// activate it.
type InviteUserClient interface {
	GetUser(ctx context.Context, id uint64) (*qrdbtransport.User, error)
	UpdateUser(ctx context.Context, req *qrdbtransport.UpdateUserRequest) (*qrdbtransport.User, error)
	AddCertBinding(ctx context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbtransport.User, error)
}

// SetInviteUserClient wires the user client the invite routes use. The
// invite routes are public, so their request context carries no qrdb
// credentials: on an embedded node that enforces authentication, the user
// client SetUserClients wires (the datastore client's) is refused there
// with qrdb/auth: unauthenticated, which GetInvite reported as an unusable
// link (ruling 973 (2)). xkmsd and a host with an embedded node pass the
// node's user service (auth.NodeUserClient). The user an invite call acts
// on is the one the invite record names, never one the caller chooses.
func (s *XKMSService) SetInviteUserClient(users InviteUserClient) {
	if users == nil {
		s.inviteUsers.Store(nil)
		return
	}
	s.inviteUsers.Store(&inviteUserClientRef{client: users})
}

// inviteUserClientRef boxes an InviteUserClient so the interface value can
// be stored in an atomic.Pointer: the client is set once at composition
// while the invite routes may already be serving.
type inviteUserClientRef struct{ client InviteUserClient }

// inviteUserClient is SetInviteUserClient's client, or SetUserClients'
// when none is set; nil when neither is.
func (s *XKMSService) inviteUserClient() InviteUserClient {
	if ref := s.inviteUsers.Load(); ref != nil {
		return ref.client
	}
	if s.users == nil {
		return nil
	}
	return s.users
}

// bindInviteTenant binds the tenant an invite record was found in on ctx,
// once inviteStore.Lookup has validated it there. The invite routes are
// anonymous, so the embedded node's user service would otherwise route the
// invited user's by-ID reads and writes to the system tenant. An empty
// tenant leaves ctx unchanged.
func bindInviteTenant(ctx context.Context, tenantID string) context.Context {
	if tenantID == "" {
		return ctx
	}
	return qrdbtenant.WithTenantID(ctx, tenantID)
}

// inviteStoreContext is the context every invite store call runs on. The
// invitations live in system storage, written and read as the node's
// service principal, whatever tenant the invited account is in: the
// invite's tenant binding (bindInviteTenant), which the user operations of
// the same request need, must not reach it, or an RBAC-enforcing node
// refuses the call ("identity not in target tenant").
func inviteStoreContext(ctx context.Context) context.Context {
	return qrdbtenant.WithTenantID(ctx, qrdbsdk.SystemTenantID)
}

// ensureInviteTenantServed refuses invitation enrolment for an account
// outside the tenant the relying party serves (ruling 1029 B): the passkey
// login ceremony resolves accounts in that one tenant, so a passkey enrolled
// elsewhere could never sign in. An empty tenant on either side is the
// system tenant.
func (s *XKMSService) ensureInviteTenantServed(inviteTenant string) error {
	// A user store that names no tenant fails closed: it is never read as
	// the system tenant (ruling 1041 (1)).
	served, err := s.webAuthn().UserStoreTenant()
	if err != nil {
		return errors.Join(ErrInviteTenantNotServed, err)
	}
	if inviteTenant == "" {
		inviteTenant = qrdbsdk.SystemTenantID
	}
	if inviteTenant != served {
		return ErrInviteTenantNotServed
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

// errPIVCertTenantMismatch refuses a PIV invitation activation whose
// certificate names a tenant other than the invited account's.
var errPIVCertTenantMismatch = errors.New("certificate tenant is not the invited account's tenant")
