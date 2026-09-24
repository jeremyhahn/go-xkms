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

package mcp

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// User management handlers. xkms presents its own user model; the backing
// store is the embedded qrdb node, reached through the injected
// XKMSService, exactly as pkg/api/rest/user_handlers.go reaches it. These
// mirror that transport's request/response shapes and status-after-mutate
// behavior so the CLI and webui see the same contract regardless of which
// transport they dial.

// --- Request types ---

// UserUsernameParams is the parameter shape shared by every user.* method
// that addresses a single user by name alone.
type UserUsernameParams struct {
	Username string `json:"username"`
}

// UserBindCertParams represents parameters for user.bindCert.
type UserBindCertParams struct {
	Username     string `json:"username"`
	Thumbprint   string `json:"thumbprint"`
	NotAfterUnix int64  `json:"not_after_unix"`
}

// --- Response types ---

// UserDeleteResult represents the result of deleting a user.
type UserDeleteResult struct {
	Username string `json:"username"`
	Status   string `json:"status"`
}

// UserBindCertResult represents the result of binding a certificate to a user.
type UserBindCertResult struct {
	Username string `json:"username"`
	Status   string `json:"status"`
}

// UserCredentialItem mirrors the wire shape the SDK client expects for a
// user credential, matching pkg/api/rest's userCredentialItem.
type UserCredentialItem struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// UserListCredentialsResult represents the result of listing a user's
// enrolled credentials.
type UserListCredentialsResult struct {
	Credentials []UserCredentialItem `json:"credentials"`
}

// --- Typed errors for user MCP handlers ---

// ErrUsernameRequired is returned when a user.* method requires a username
// but none was provided.
var ErrUsernameRequired = errors.New("username is required")

// unmarshalUserParams decodes req.Params into dst, wrapping a decode failure
// so it reads back to the caller as Invalid params (-32602) rather than an
// opaque internal error: toolErrorCode (pkg/api/transport/mcp) classifies
// any message containing "invalid" as ErrCodeInvalidParams.
func unmarshalUserParams(req *JSONRPCRequest, dst interface{}) error {
	if err := json.Unmarshal(req.Params, dst); err != nil {
		return &errs.Wrapped{Msg: "invalid params", Err: err}
	}
	return nil
}

// handleCreateUser handles the user.create method.
func (s *Server) handleCreateUser(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.CreateUserRequest
	if err := unmarshalUserParams(req, &params); err != nil {
		return nil, err
	}

	resp, err := s.xkmsService.CreateUser(ctx, &params)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// handleListUsers handles the user.list method. It takes no parameters,
// matching the REST transport's GET /api/v1/users/, which applies no
// pagination either.
func (s *Server) handleListUsers(ctx context.Context, _ *JSONRPCRequest) (interface{}, error) {
	resp, err := s.xkmsService.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// handleGetUser handles the user.get method.
func (s *Server) handleGetUser(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params UserUsernameParams
	if err := unmarshalUserParams(req, &params); err != nil {
		return nil, err
	}
	if params.Username == "" {
		return nil, ErrUsernameRequired
	}

	resp, err := s.xkmsService.GetUser(ctx, params.Username)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// handleDeleteUser handles the user.delete method.
func (s *Server) handleDeleteUser(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params UserUsernameParams
	if err := unmarshalUserParams(req, &params); err != nil {
		return nil, err
	}
	if params.Username == "" {
		return nil, ErrUsernameRequired
	}

	if err := s.xkmsService.DeleteUser(ctx, params.Username); err != nil {
		return nil, err
	}
	return UserDeleteResult{Username: params.Username, Status: "deleted"}, nil
}

// handleEnableUser handles the user.enable method. It mirrors the REST
// transport's PUT /api/v1/users/{username}: apply the mutation, then read
// the user back so the caller sees the effective state rather than a bare
// acknowledgement.
func (s *Server) handleEnableUser(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params UserUsernameParams
	if err := unmarshalUserParams(req, &params); err != nil {
		return nil, err
	}
	if params.Username == "" {
		return nil, ErrUsernameRequired
	}

	if err := s.xkmsService.EnableUser(ctx, params.Username); err != nil {
		return nil, err
	}
	resp, err := s.xkmsService.GetUser(ctx, params.Username)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// handleDisableUser handles the user.disable method. See handleEnableUser
// for why it reads the user back after mutating.
func (s *Server) handleDisableUser(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params UserUsernameParams
	if err := unmarshalUserParams(req, &params); err != nil {
		return nil, err
	}
	if params.Username == "" {
		return nil, ErrUsernameRequired
	}

	if err := s.xkmsService.DisableUser(ctx, params.Username); err != nil {
		return nil, err
	}
	resp, err := s.xkmsService.GetUser(ctx, params.Username)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// handleBindUserCert handles the user.bindCert method.
func (s *Server) handleBindUserCert(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params UserBindCertParams
	if err := unmarshalUserParams(req, &params); err != nil {
		return nil, err
	}
	if params.Username == "" {
		return nil, ErrUsernameRequired
	}

	if err := s.xkmsService.BindUserCert(ctx, params.Username, params.Thumbprint, params.NotAfterUnix); err != nil {
		return nil, err
	}
	return UserBindCertResult{Username: params.Username, Status: "bound"}, nil
}

// handleListUserCredentials handles the user.listCredentials method.
func (s *Server) handleListUserCredentials(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params UserUsernameParams
	if err := unmarshalUserParams(req, &params); err != nil {
		return nil, err
	}
	if params.Username == "" {
		return nil, ErrUsernameRequired
	}

	resp, err := s.xkmsService.ListUserCredentials(ctx, params.Username)
	if err != nil {
		return nil, err
	}

	items := make([]UserCredentialItem, 0, len(resp.Credentials))
	for _, c := range resp.Credentials {
		items = append(items, UserCredentialItem{ID: c.ID, Name: c.DisplayName})
	}
	return UserListCredentialsResult{Credentials: items}, nil
}
