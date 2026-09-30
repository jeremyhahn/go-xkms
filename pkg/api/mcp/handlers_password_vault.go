// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package mcp

import (
	"context"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// The personal-vault methods, password.vault.*. Every one acts on the
// caller's own vault -- the tenant and subject of the authenticated identity,
// which the servicer resolves -- so none takes a user. Params and results are
// the transport types; their byte fields (credential_id, prf_salt, secret)
// are base64 in JSON.

// ErrVaultFactorIDRequired is returned when a vault operation names no
// factor.
var ErrVaultFactorIDRequired = errors.New("factor_id is required")

// PasswordVaultRemoveFactorResult is the result of removing a vault factor.
type PasswordVaultRemoveFactorResult struct {
	Message string `json:"message"`
}

// handlePasswordVaultStatus handles the password.vault.status method.
func (s *Server) handlePasswordVaultStatus(ctx context.Context, _ *JSONRPCRequest) (interface{}, error) {
	svc, err := s.passwordService()
	if err != nil {
		return nil, err
	}
	status, err := svc.PasswordVaultStatus(ctx)
	if err != nil {
		return nil, mapPasswordVaultError(err)
	}
	return status, nil
}

// handlePasswordVaultEnroll handles the password.vault.enroll method. Its
// params are a transport.PasswordVaultCredential. The first enrollment
// initializes the vault, opens the session and returns the one-time recovery
// code.
func (s *Server) handlePasswordVaultEnroll(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.PasswordVaultEnrollRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	defer clear(params.Secret)

	svc, err := s.passwordService()
	if err != nil {
		return nil, err
	}
	resp, err := svc.PasswordVaultEnroll(ctx, &params)
	if err != nil {
		return nil, mapPasswordVaultError(err)
	}
	return resp, nil
}

// handlePasswordVaultRotate handles the password.vault.rotate method: a
// factor_id plus the new credential of the same factor type.
func (s *Server) handlePasswordVaultRotate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.PasswordVaultRotateRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	defer clear(params.Secret)
	if params.FactorID == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: ErrVaultFactorIDRequired}
	}

	svc, err := s.passwordService()
	if err != nil {
		return nil, err
	}
	resp, err := svc.PasswordVaultRotate(ctx, &params)
	if err != nil {
		return nil, mapPasswordVaultError(err)
	}
	return resp, nil
}

// handlePasswordVaultRemoveFactor handles the password.vault.removeFactor
// method. The recovery code and the last passphrase or passkey cannot be
// removed.
func (s *Server) handlePasswordVaultRemoveFactor(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.PasswordVaultRemoveFactorRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if params.FactorID == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: ErrVaultFactorIDRequired}
	}

	svc, err := s.passwordService()
	if err != nil {
		return nil, err
	}
	if err := svc.PasswordVaultRemoveFactor(ctx, &params); err != nil {
		return nil, mapPasswordVaultError(err)
	}
	return PasswordVaultRemoveFactorResult{Message: "Vault factor removed"}, nil
}

// handlePasswordVaultRecover handles the password.vault.recover method: the
// recovery code plus the new factor's credential. It returns the replacement
// recovery code; the used one stops working.
func (s *Server) handlePasswordVaultRecover(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.PasswordVaultRecoverRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	defer clear(params.Secret)

	svc, err := s.passwordService()
	if err != nil {
		return nil, err
	}
	resp, err := svc.PasswordVaultRecover(ctx, &params)
	if err != nil {
		return nil, mapPasswordVaultError(err)
	}
	return resp, nil
}

// mapPasswordVaultError converts an error returned by a personal-vault
// operation into a *KeyOpError, mirroring pkg/api/grpc's mapPasswordError
// in this transport's vocabulary: a malformed credential or an empty vault
// is Invalid params, a credential that unwraps no factor is Unauthorized
// (without saying why), an unknown factor is Not found, a duplicate passkey
// is Duplicate, and removing the last factor is a precondition failure on
// the internal floor, as a locked store is. A request without an identity
// has no vault: a capability boundary, reported as Method not found.
func mapPasswordVaultError(err error) error {
	switch {
	case errors.Is(err, staticpw.ErrVaultInvalidCredential),
		errors.Is(err, staticpw.ErrVaultRecoveryFactor),
		errors.Is(err, staticpw.ErrVaultNotInitialized):
		return &KeyOpError{Code: ErrCodeInvalidParams, Err: err}
	case errors.Is(err, staticpw.ErrVaultCredentialRejected):
		return &KeyOpError{Code: ErrCodeUnauthorized, Err: staticpw.ErrVaultCredentialRejected}
	case errors.Is(err, staticpw.ErrVaultFactorNotFound):
		return &KeyOpError{Code: sdkssh.JSONRPCCodeNotFound, Err: staticpw.ErrVaultFactorNotFound}
	case errors.Is(err, staticpw.ErrVaultPasskeyExists):
		return &KeyOpError{Code: sdkssh.JSONRPCCodeDuplicate, Err: staticpw.ErrVaultPasskeyExists}
	case errors.Is(err, staticpw.ErrVaultLastFactor):
		return classified(ErrCodeInternalError, staticpw.ErrVaultLastFactor)
	case errors.Is(err, xkms.ErrOperationNotSupported):
		return &KeyOpError{Code: ErrCodeMethodNotFound, Err: err}
	default:
		return mapPasswordStoreError(err)
	}
}
