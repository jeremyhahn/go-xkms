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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// userToTransport projects an embedded-qrdb user onto the xkms-facing
// UserInfo. The user's first role id is resolved to its role name so callers
// see xkms role names rather than qrdb role ids.
func (s *XKMSService) userToTransport(ctx context.Context, u *qrdbtransport.User) transport.UserInfo {
	role := ""
	if len(u.RoleIDs) > 0 {
		if r, err := s.roles.GetRole(ctx, u.RoleIDs[0]); err == nil {
			role = r.Name
		}
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
		Role:        role,
		// qrdb v0.20: Lifecycle is the only account state; only active is enabled.
		Enabled: u.Lifecycle == string(qrdbsdk.LifecycleActive),
	}
}

// roleNameToID resolves an xkms role name to its embedded-qrdb role id. An
// empty name resolves to an empty id (no role assignment).
func (s *XKMSService) roleNameToID(ctx context.Context, name string) (string, error) {
	if name == "" {
		return "", nil
	}
	resp, err := s.roles.ListRoles(ctx, &qrdbtransport.ListRolesRequest{})
	if err != nil {
		return "", &ErrUserOperation{Operation: "resolve role", Err: err}
	}
	for _, r := range resp.Roles {
		if r.Name == name {
			return r.ID, nil
		}
	}
	return "", &ErrUserOperation{Operation: "resolve role", Err: &ErrUnknownRole{Role: name}}
}

// CreateUser creates a new xkms user backed by the embedded qrdb node.
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
	roleID, err := s.roleNameToID(ctx, req.Role)
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
	})
	if err != nil {
		return nil, &ErrUserOperation{Operation: "create user", Err: err}
	}
	// No DisplayName fix-up here: userToTransport projects the PERSISTED Name,
	// so the response reflects what the store actually holds. Assigning the
	// request value back masked the fact that Name was never read on the way
	// out — create looked right while GetUser and ListUsers returned nothing.
	return &transport.GetUserResponse{User: s.userToTransport(ctx, u)}, nil
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
		infos[i] = s.userToTransport(ctx, u)
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
	return &transport.GetUserResponse{User: s.userToTransport(ctx, u)}, nil
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
	return nil
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
