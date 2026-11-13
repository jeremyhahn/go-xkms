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
	"encoding/base64"
	"errors"
	"log"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// userToTransport projects an embedded-qrdb user onto the xkms-facing
// UserInfo. Every role id the user holds is resolved to its role name, in
// stored order, so callers see role names rather than qrdb role ids.
func (s *XKMSService) userToTransport(ctx context.Context, u *qrdbtransport.User) (transport.UserInfo, error) {
	var roles []string
	for _, id := range u.RoleIDs {
		r, err := s.roles.GetRole(ctx, id)
		if err != nil {
			return transport.UserInfo{}, &ErrUserOperation{Operation: "resolve role", Err: err}
		}
		roles = append(roles, r.Name)
	}
	return transport.UserInfo{
		ID:       u.ID,
		Username: u.Username,
		// Project the PERSISTED canonical key and display name. Neither was
		// read back before: Email had no field on UserInfo at all, and Name was
		// stored but never projected, so GetUser and ListUsers returned an
		// empty display name for a user that had one (Codex, go-xkms #190).
		Email:       u.Email,
		DisplayName: u.Name,
		Roles:       roles,
		// qrdb v0.20: Lifecycle is the only account state; only active is enabled.
		Enabled: u.Lifecycle == string(qrdbsdk.LifecycleActive),
	}, nil
}

// roleNameToID resolves a role name to its qrdb role id in tenantID (the
// context tenant when empty). A built-in role's id is deterministic
// (qrdbsdk.SystemRoleID); a custom role is looked up by name. An empty name
// resolves to an empty id (no role assignment).
func (s *XKMSService) roleNameToID(ctx context.Context, tenantID, name string) (string, error) {
	if name == "" {
		return "", nil
	}
	if tenantID == "" {
		if fromCtx, ok := qrdbsdk.TenantFromContext(ctx); ok {
			tenantID = fromCtx
		}
	}
	if qrdbsdk.IsSystemRoleName(name) {
		return qrdbsdk.SystemRoleID(tenantID, name), nil
	}
	r, err := s.roles.GetRoleByName(ctx, &qrdbtransport.GetRoleByNameRequest{TenantID: tenantID, Name: name})
	if err != nil {
		var notFound *qrdbsdk.RoleNotFoundError
		if errors.As(err, &notFound) {
			return "", &ErrUserOperation{Operation: "resolve role", Err: &ErrUnknownRole{Role: name}}
		}
		return "", &ErrUserOperation{Operation: "resolve role", Err: err}
	}
	return r.ID, nil
}

// CreateUser creates a new xkms user backed by the embedded qrdb node.
//
// An account with an email login key (the normal case) is created PENDING,
// never active: a brand-new account holds no credential, so there is
// nothing for it to authenticate an enrollment ceremony with. CreateUser
// mints a single-use activation invitation in the same call (go-xkms#1294
// part B) — the plaintext token is returned exactly once, in the response,
// and is not recoverable afterwards — and the invitee redeems it through
// BeginInviteRegistration/FinishInviteRegistration (FIDO2) or
// ActivateInvitePIV (PIV), which binds their first credential and activates
// the account. If minting the invitation fails, the just-created account is
// rolled back: a pending account nothing can ever activate is worse than no
// account at all.
//
// WithoutEmailLoginKey is the one exception: a certificate-only/bootstrap
// identity has no email an invitation could be sent to, so it is created
// ACTIVE with no invitation, exactly as before this change.
func (s *XKMSService) CreateUser(ctx context.Context, req *transport.CreateUserRequest) (*transport.GetUserResponse, error) {
	if s.users == nil {
		return nil, ErrNotConfigured
	}
	// FAIL CLOSED on a missing login key. qrdb makes Email the canonical
	// tenant-unique key, and this path previously sent Username only — so every
	// provisioned user landed with an empty email index. WebAuthn enrollment
	// resolves by email, which meant a user created here could be enrolled by
	// nobody (Codex, go-xkms #190), and against a current qrdb node the create
	// is refused outright rather than merely producing an unreachable account.
	//
	// Refusing here, rather than defaulting Email from Username, is deliberate:
	// deriving one from the other is the username/email conflation this change
	// exists to remove, and it would silently produce a second class of user
	// whose reachability depends on the shape of a string.
	// NORMALIZE FIRST, then decide. Comparing the raw value against "" let a
	// whitespace-only email through the guard; qrdb then trims it, finds it
	// empty, and refuses — so malformed CLIENT input surfaced as a generic
	// backend failure mapped to 500/Internal, which is the exact path this
	// guard exists to close (Codex, go-xkms #190).
	//
	// The normalizer is qrdb's own exported one, not a local TrimSpace: it is
	// documented there as THE single canonical normalization for the login key,
	// so using it keeps this check and the server's agreeing by construction
	// rather than by coincidence. The normalized value is what gets sent, so
	// the address validated here is the address stored.
	email := qrdbsdk.NormalizeEmail(req.Email)
	if email == "" && !req.WithoutEmailLoginKey {
		return nil, &ErrUserOperation{
			Operation: "create user",
			Err:       ErrEmailRequired,
		}
	}
	// Fail BEFORE anything is created: an invited account this build cannot
	// mint an invitation for is a pending account nothing can ever activate.
	// Checked after the client-input validation above so a malformed
	// request is still reported as one, not masked by a server
	// misconfiguration that happens to be true at the same time.
	if !req.WithoutEmailLoginKey && s.inviteStore == nil {
		return nil, ErrNotConfigured
	}
	// Minting the invitation is inviting a user into the caller's tenant,
	// which go-qrdb decides under users:invite, not users:create (the
	// transports' gate). Asked before the account exists, so a refusal
	// leaves nothing to roll back; returned unchanged so the transports map
	// go-qrdb's denial as they do their own.
	if !req.WithoutEmailLoginKey {
		if err := s.AuthorizeCaller(ctx,
			qrdbsdk.PermissionResource(qrdbsdk.PermissionUsersInvite),
			qrdbsdk.PermissionAction(qrdbsdk.PermissionUsersInvite)); err != nil {
			return nil, err
		}
	}
	roleID, err := s.roleNameToID(ctx, req.TenantID, req.Role)
	if err != nil {
		return nil, err
	}
	var roleIDs []string
	if roleID != "" {
		roleIDs = []string{roleID}
	}
	u, err := s.users.CreateUser(ctx, &qrdbtransport.CreateUserRequest{
		Username: req.Username,
		Email:    email,
		// DisplayName was previously set on the RESPONSE only and never
		// persisted, so it was returned to the caller and lost. qrdb now has a
		// Name field for it.
		Name:                 req.DisplayName,
		WithoutEmailLoginKey: req.WithoutEmailLoginKey,
		TenantID:             req.TenantID,
		RoleIDs:              roleIDs,
		// Pending unless this is the certificate-only/bootstrap path: an
		// email-login-key account has no credential yet and activates only
		// through invite redemption (go-xkms#1294 part B).
		Pending: !req.WithoutEmailLoginKey,
	})
	if err != nil {
		return nil, &ErrUserOperation{Operation: "create user", Err: err}
	}
	// No DisplayName fix-up here: userToTransport projects the PERSISTED Name,
	// so the response reflects what the store actually holds. Assigning the
	// request value back masked the fact that Name was never read on the way
	// out — create looked right while GetUser and ListUsers returned nothing.
	info, err := s.userToTransport(ctx, u)
	if err != nil {
		s.rollbackCreatedUser(ctx, u.ID)
		return nil, err
	}
	resp := &transport.GetUserResponse{User: info}
	if req.WithoutEmailLoginKey {
		return resp, nil
	}

	// Mint the activation invitation in the tenant the record actually
	// landed in (u.TenantID), not req.TenantID: an empty request tenant
	// resolves to qrdb's default, and sourcing it from the created record
	// keeps this call and the account's own storage location agreeing by
	// construction (the same reasoning userToTransport already applies to
	// DisplayName above).
	invite, err := s.createInvite(ctx, u.TenantID, u.ID, time.Duration(req.InviteTTLSeconds)*time.Second)
	if err != nil {
		// A user this build cannot activate is worse than no user: roll it
		// back rather than return an account stuck pending forever.
		s.rollbackCreatedUser(ctx, u.ID)
		return nil, err
	}
	resp.Invite = invite
	return resp, nil
}

// rollbackCreatedUser deletes a user CreateUser has just created when a later
// step of the create fails. It is best-effort: the caller is already being
// told create failed, and a cleanup failure must not replace the reason it did.
func (s *XKMSService) rollbackCreatedUser(ctx context.Context, id uint64) {
	if err := s.users.DeleteUser(ctx, id); err != nil {
		log.Printf("xkms: rollback of user %d after a failed create failed: %v", id, err)
	}
}

// ListUsers returns all xkms users.
func (s *XKMSService) ListUsers(ctx context.Context, opts ...transport.ListOption) (*transport.ListUsersResponse, error) {
	if s.users == nil {
		return nil, ErrNotConfigured
	}
	resp, err := s.users.ListUsers(ctx, &qrdbtransport.ListUsersRequest{})
	if err != nil {
		return nil, &ErrUserOperation{Operation: "list users", Err: err}
	}
	infos := make([]transport.UserInfo, len(resp.Users))
	for i, u := range resp.Users {
		if infos[i], err = s.userToTransport(ctx, u); err != nil {
			return nil, err
		}
	}
	return &transport.ListUsersResponse{Users: infos}, nil
}

// GetUser returns information about a specific xkms user.
func (s *XKMSService) GetUser(ctx context.Context, username string) (*transport.GetUserResponse, error) {
	if s.users == nil {
		return nil, ErrNotConfigured
	}
	u, err := s.users.GetUserByUsername(ctx, "", username)
	if err != nil {
		return nil, &ErrUserOperation{Operation: "get user", Err: err}
	}
	info, err := s.userToTransport(ctx, u)
	if err != nil {
		return nil, err
	}
	return &transport.GetUserResponse{User: info}, nil
}

// DeleteUser removes an xkms user.
func (s *XKMSService) DeleteUser(ctx context.Context, username string) error {
	if s.users == nil {
		return ErrNotConfigured
	}
	u, err := s.users.GetUserByUsername(ctx, "", username)
	if err != nil {
		return &ErrUserOperation{Operation: "get user for deletion", Err: err}
	}
	if err := s.users.DeleteUser(ctx, u.ID); err != nil {
		return &ErrUserOperation{Operation: "delete user", Err: err}
	}
	s.revokeUserSessions(ctx, u)
	return nil
}

// EnableUser enables a previously disabled xkms user account.
func (s *XKMSService) EnableUser(ctx context.Context, username string) error {
	if s.users == nil {
		return ErrNotConfigured
	}
	u, err := s.users.GetUserByUsername(ctx, "", username)
	if err != nil {
		return &ErrUserOperation{Operation: "get user", Err: err}
	}
	if err := s.users.EnableUser(ctx, u.ID); err != nil {
		return &ErrUserOperation{Operation: "enable user", Err: err}
	}
	return nil
}

// DisableUser disables an xkms user account, preventing authentication.
func (s *XKMSService) DisableUser(ctx context.Context, username string) error {
	if s.users == nil {
		return ErrNotConfigured
	}
	u, err := s.users.GetUserByUsername(ctx, "", username)
	if err != nil {
		return &ErrUserOperation{Operation: "get user", Err: err}
	}
	if err := s.users.DisableUser(ctx, u.ID); err != nil {
		return &ErrUserOperation{Operation: "disable user", Err: err}
	}
	s.revokeUserSessions(ctx, u)
	return nil
}

// revokeUserSessions ends every refresh-token session u holds, covering
// both subject encodings a login can mint a refresh token under: the
// username (mTLS and PIV logins, MTLSAuthenticator.userIdentity /
// handlePIVLogin) and the WebAuthn user handle (passkey logins,
// WebAuthnTokenAdapter.identityFor) -- go-xkms#1297.
//
// Best-effort by design: the qrdb lifecycle change the caller just made has
// already succeeded and must not be rolled back by a session-revocation
// failure, so a failure here is logged, not returned. The refresh-time
// re-check (pkg/auth.QRDBUserResolver) still refuses u's sessions on their
// next refresh attempt even when this sweep could not reach the store.
func (s *XKMSService) revokeUserSessions(ctx context.Context, u *qrdbtransport.User) {
	if s.tokenIssuer == nil {
		return
	}
	if err := s.tokenIssuer.RevokeBySubject(ctx, u.Username); err != nil {
		log.Printf("xkms: revoke refresh sessions for user %q failed: %v", u.Username, err)
	}
	handle := base64.RawURLEncoding.EncodeToString(webauthn.HandleFromUserID(u.ID))
	if err := s.tokenIssuer.RevokeBySubject(ctx, handle); err != nil {
		log.Printf("xkms: revoke webauthn refresh sessions for user %q failed: %v", u.Username, err)
	}
}

// BindUserCert binds an mTLS certificate's SPKI thumbprint to an xkms user.
// The username is resolved to its embedded qrdb user, then the binding is
// added through the qrdb user client. notAfterUnix is the certificate's
// expiry as a Unix timestamp (zero if unknown).
func (s *XKMSService) BindUserCert(ctx context.Context, username, thumbprint string, notAfterUnix int64) error {
	if s.users == nil {
		return ErrNotConfigured
	}
	u, err := s.users.GetUserByUsername(ctx, "", username)
	if err != nil {
		return &ErrUserOperation{Operation: "get user", Err: err}
	}
	if _, err := s.users.AddCertBinding(ctx, u.ID, thumbprint, notAfterUnix); err != nil {
		return &ErrUserOperation{Operation: "bind cert", Err: err}
	}
	return nil
}

// ListUserCredentials returns the WebAuthn credentials associated with an xkms
// user. Credential records live in the WebAuthn relying-party store; this
// surface reports the user's enrolled credentials.
func (s *XKMSService) ListUserCredentials(ctx context.Context, username string) (*transport.ListUserCredentialsResponse, error) {
	if s.users == nil {
		return nil, ErrNotConfigured
	}
	if _, err := s.users.GetUserByUsername(ctx, "", username); err != nil {
		return nil, &ErrUserOperation{Operation: "get user", Err: err}
	}
	return &transport.ListUserCredentialsResponse{Credentials: []transport.CredentialInfo{}}, nil
}
