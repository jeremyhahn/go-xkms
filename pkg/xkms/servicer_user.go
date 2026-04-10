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

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/user"
)

// UserServicer defines operations for managing users and their credentials.
type UserServicer interface {
	ListUsers(ctx context.Context) (*transport.ListUsersResponse, error)
	GetUser(ctx context.Context, username string) (*transport.GetUserResponse, error)
	DeleteUser(ctx context.Context, username string) error
	EnableUser(ctx context.Context, username string) error
	DisableUser(ctx context.Context, username string) error
	ListUserCredentials(ctx context.Context, username string) (*transport.ListUserCredentialsResponse, error)
}

// userToTransport converts a user.User to a transport.UserInfo.
func userToTransport(u *user.User) transport.UserInfo {
	return transport.UserInfo{
		Username:    u.Username,
		DisplayName: u.DisplayName,
		Role:        string(u.Role),
		Enabled:     u.Enabled,
		CreatedAt:   u.CreatedAt,
		LastLogin:   u.LastLoginAt,
	}
}

// credentialToTransport converts a user.Credential to a transport.CredentialInfo.
func credentialToTransport(c *user.Credential) transport.CredentialInfo {
	return transport.CredentialInfo{
		ID:          base64.URLEncoding.EncodeToString(c.ID),
		DisplayName: c.Name,
		CreatedAt:   c.CreatedAt,
		LastUsed:    c.LastUsedAt,
	}
}

// ListUsers returns a list of all registered users.
func (s *XKMSService) ListUsers(ctx context.Context, opts ...transport.ListOption) (*transport.ListUsersResponse, error) {
	if s.userStore == nil {
		return nil, ErrNotConfigured
	}
	users, err := s.userStore.List(ctx)
	if err != nil {
		return nil, &ErrUserOperation{Operation: "list users", Err: err}
	}
	infos := make([]transport.UserInfo, len(users))
	for i, u := range users {
		infos[i] = userToTransport(u)
	}
	return &transport.ListUsersResponse{Users: infos}, nil
}

// GetUser returns information about a specific user.
func (s *XKMSService) GetUser(ctx context.Context, username string) (*transport.GetUserResponse, error) {
	if s.userStore == nil {
		return nil, ErrNotConfigured
	}
	u, err := s.userStore.GetByUsername(ctx, username)
	if err != nil {
		return nil, &ErrUserOperation{Operation: "get user", Err: err}
	}
	return &transport.GetUserResponse{User: userToTransport(u)}, nil
}

// DeleteUser removes a user and their associated credentials.
func (s *XKMSService) DeleteUser(ctx context.Context, username string) error {
	if s.userStore == nil {
		return ErrNotConfigured
	}
	u, err := s.userStore.GetByUsername(ctx, username)
	if err != nil {
		return &ErrUserOperation{Operation: "get user for deletion", Err: err}
	}
	return s.userStore.Delete(ctx, u.ID)
}

// EnableUser enables a previously disabled user account.
func (s *XKMSService) EnableUser(ctx context.Context, username string) error {
	if s.userStore == nil {
		return ErrNotConfigured
	}
	u, err := s.userStore.GetByUsername(ctx, username)
	if err != nil {
		return &ErrUserOperation{Operation: "get user", Err: err}
	}
	u.Enabled = true
	return s.userStore.Update(ctx, u)
}

// DisableUser disables a user account, preventing authentication.
func (s *XKMSService) DisableUser(ctx context.Context, username string) error {
	if s.userStore == nil {
		return ErrNotConfigured
	}
	u, err := s.userStore.GetByUsername(ctx, username)
	if err != nil {
		return &ErrUserOperation{Operation: "get user", Err: err}
	}
	u.Enabled = false
	return s.userStore.Update(ctx, u)
}

// ListUserCredentials returns the credentials associated with a user.
func (s *XKMSService) ListUserCredentials(ctx context.Context, username string) (*transport.ListUserCredentialsResponse, error) {
	if s.userStore == nil {
		return nil, ErrNotConfigured
	}
	u, err := s.userStore.GetByUsername(ctx, username)
	if err != nil {
		return nil, &ErrUserOperation{Operation: "get user", Err: err}
	}
	creds := make([]transport.CredentialInfo, len(u.Credentials))
	for i := range u.Credentials {
		creds[i] = credentialToTransport(&u.Credentials[i])
	}
	return &transport.ListUserCredentialsResponse{Credentials: creds}, nil
}
