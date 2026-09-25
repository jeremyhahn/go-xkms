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
	"errors"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
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

// mapUserError converts an error returned by a user.* handler -- either its
// own params validation or a failure from the xkms user service layer
// (pkg/xkms/servicer_user.go, backed by the embedded qrdb node's user
// servicer) -- into a *KeyOpError carrying the JSON-RPC code InvokeMethod
// should report. It plays the same role mapKeyOpError and mapSSHError play
// for their own sub-systems (errors_keyops.go, errors_ssh.go).
//
// Before this function existed, every user.* handler returned the bare
// service error: unmarshalUserParams's decode failure was a plain
// *errs.Wrapped (not a *KeyOpError, so pkg/apimodule's mcpToolHandler could
// not classify it), and ErrUsernameRequired and every downstream service
// error were returned completely unwrapped. Both reached the caller as
// wire.CodeInternal regardless of cause (go-xkms#774, #814).
//
// A *qrdbsdk.UserNotFoundError is go-qrdb's own not-found type
// (pkg/user.UserNotFoundError, aliased through transport.UserNotFoundError
// and re-exported here as qrdbsdk.UserNotFoundError): go-qrdb's own gRPC,
// QUIC, and MCP-wire transports all classify it as NotFound
// (pkg/api/grpc/service_auth.go's mapUserNotFound, pkg/api/quic/errors.go,
// pkg/api/mcp/wire's ErrorPayload doc comment), so this adopts that
// classification rather than inventing a second one for the same condition
// ("lower layers win"). sdkssh.JSONRPCCodeNotFound is the JSON-RPC code this
// package already uses for the identical wire.CodeNotFound outcome
// (errors_ssh.go's mapSSHError), so xkms.* key/backend and user lookups
// funnel through the same reserved-range code rather than each minting its
// own.
//
// ErrUsernameRequired and xkms.ErrEmailRequired are the caller's own
// mistake, so they join decodeParams's family under Invalid params, matching
// pkg/api/grpc/service_user.go's createUserErrorCode and every username
// guard in that file (codes.InvalidArgument). Anything else falls to
// Internal, unchanged from the behavior before this function existed.
func mapUserError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, ErrUsernameRequired) || errors.Is(err, xkms.ErrEmailRequired) {
		return &KeyOpError{Code: ErrCodeInvalidParams, Err: err}
	}

	var notFound *qrdbsdk.UserNotFoundError
	if errors.As(err, &notFound) {
		return &KeyOpError{Code: sdkssh.JSONRPCCodeNotFound, Err: err}
	}

	return &KeyOpError{Code: ErrCodeInternalError, Err: err}
}

// handleCreateUser handles the user.create method.
func (s *Server) handleCreateUser(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.CreateUserRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	resp, err := s.xkmsService.CreateUser(ctx, &params)
	if err != nil {
		return nil, mapUserError(err)
	}
	return resp, nil
}

// handleListUsers handles the user.list method. It takes no parameters,
// matching the REST transport's GET /api/v1/users/, which applies no
// pagination either.
func (s *Server) handleListUsers(ctx context.Context, _ *JSONRPCRequest) (interface{}, error) {
	resp, err := s.xkmsService.ListUsers(ctx)
	if err != nil {
		return nil, mapUserError(err)
	}
	return resp, nil
}

// handleGetUser handles the user.get method.
func (s *Server) handleGetUser(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params UserUsernameParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if params.Username == "" {
		return nil, mapUserError(ErrUsernameRequired)
	}

	resp, err := s.xkmsService.GetUser(ctx, params.Username)
	if err != nil {
		return nil, mapUserError(err)
	}
	return resp, nil
}

// handleDeleteUser handles the user.delete method.
func (s *Server) handleDeleteUser(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params UserUsernameParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if params.Username == "" {
		return nil, mapUserError(ErrUsernameRequired)
	}

	if err := s.xkmsService.DeleteUser(ctx, params.Username); err != nil {
		return nil, mapUserError(err)
	}
	return UserDeleteResult{Username: params.Username, Status: "deleted"}, nil
}

// handleEnableUser handles the user.enable method. It mirrors the REST
// transport's PUT /api/v1/users/{username}: apply the mutation, then read
// the user back so the caller sees the effective state rather than a bare
// acknowledgement.
func (s *Server) handleEnableUser(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params UserUsernameParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if params.Username == "" {
		return nil, mapUserError(ErrUsernameRequired)
	}

	if err := s.xkmsService.EnableUser(ctx, params.Username); err != nil {
		return nil, mapUserError(err)
	}
	resp, err := s.xkmsService.GetUser(ctx, params.Username)
	if err != nil {
		return nil, mapUserError(err)
	}
	return resp, nil
}

// handleDisableUser handles the user.disable method. See handleEnableUser
// for why it reads the user back after mutating.
func (s *Server) handleDisableUser(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params UserUsernameParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if params.Username == "" {
		return nil, mapUserError(ErrUsernameRequired)
	}

	if err := s.xkmsService.DisableUser(ctx, params.Username); err != nil {
		return nil, mapUserError(err)
	}
	resp, err := s.xkmsService.GetUser(ctx, params.Username)
	if err != nil {
		return nil, mapUserError(err)
	}
	return resp, nil
}

// handleBindUserCert handles the user.bindCert method.
func (s *Server) handleBindUserCert(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params UserBindCertParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if params.Username == "" {
		return nil, mapUserError(ErrUsernameRequired)
	}

	if err := s.xkmsService.BindUserCert(ctx, params.Username, params.Thumbprint, params.NotAfterUnix); err != nil {
		return nil, mapUserError(err)
	}
	return UserBindCertResult{Username: params.Username, Status: "bound"}, nil
}

// handleListUserCredentials handles the user.listCredentials method.
func (s *Server) handleListUserCredentials(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params UserUsernameParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if params.Username == "" {
		return nil, mapUserError(ErrUsernameRequired)
	}

	resp, err := s.xkmsService.ListUserCredentials(ctx, params.Username)
	if err != nil {
		return nil, mapUserError(err)
	}

	items := make([]UserCredentialItem, 0, len(resp.Credentials))
	for _, c := range resp.Credentials {
		items = append(items, UserCredentialItem{ID: c.ID, Name: c.DisplayName})
	}
	return UserListCredentialsResult{Credentials: items}, nil
}
