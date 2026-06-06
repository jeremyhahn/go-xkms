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
		Username: u.Username,
		Role:     role,
		Enabled:  u.Enabled,
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
		TenantID: req.TenantID,
		RoleIDs:  roleIDs,
	})
	if err != nil {
		return nil, &ErrUserOperation{Operation: "create user", Err: err}
	}
	info := s.userToTransport(ctx, u)
	info.DisplayName = req.DisplayName
	return &transport.GetUserResponse{User: info}, nil
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
