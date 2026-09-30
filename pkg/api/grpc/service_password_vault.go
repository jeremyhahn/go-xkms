// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package grpc

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-xkms/pkg/api/grpc/pbconv"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// The personal-vault RPCs. Every one acts on the caller's own vault -- the
// tenant and subject of the authenticated identity -- which the service
// layer resolves; none takes a user on the wire. Like PasswordStoreUnlock
// they do not reject a nil identity up front, because the Unix socket serves
// this same service without an authentication interceptor; the service
// layer answers such a caller with ErrOperationNotSupported instead.

// vaultResource is the audit resource ID of the vault RPCs.
const vaultResource = "vault"

// PasswordVaultStatus describes the caller's personal vault and its enrolled
// factors.
func (s *Service) PasswordVaultStatus(ctx context.Context, _ *pb.PasswordVaultStatusRequest) (*pb.PasswordVaultStatusResponse, error) {
	if err := s.authorize(ctx, auth.ResourcePasswords, auth.ActionRead, vaultResource); err != nil {
		return nil, err
	}
	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, err := svc.PasswordVaultStatus(ctx)
	if err != nil {
		return nil, mapPasswordError(err)
	}
	return pbconv.VaultStatusToPB(resp), nil
}

// PasswordVaultEnroll enrolls a passphrase or passkey on the caller's vault.
// The first enrollment initializes the vault and returns the one-time
// recovery code.
func (s *Service) PasswordVaultEnroll(ctx context.Context, req *pb.PasswordVaultEnrollRequest) (*pb.PasswordVaultEnrollResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if err := s.authorize(ctx, auth.ResourcePasswords, auth.ActionUnlock, vaultResource); err != nil {
		return nil, err
	}
	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, err := svc.PasswordVaultEnroll(ctx, &transport.PasswordVaultEnrollRequest{
		PasswordVaultCredential: pbconv.VaultCredentialFromPB(req.GetCredential()),
	})
	if err != nil {
		return nil, mapPasswordError(err)
	}
	return pbconv.VaultEnrollResponseToPB(resp), nil
}

// PasswordVaultRotate re-wraps the caller's DEK under a new secret for one of
// the caller's factors.
func (s *Service) PasswordVaultRotate(ctx context.Context, req *pb.PasswordVaultRotateRequest) (*pb.PasswordVaultEnrollResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if req.GetFactorId() == "" {
		return nil, status.Error(codes.InvalidArgument, "factor_id is required")
	}
	if err := s.authorize(ctx, auth.ResourcePasswords, auth.ActionUnlock, vaultResource); err != nil {
		return nil, err
	}
	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, err := svc.PasswordVaultRotate(ctx, &transport.PasswordVaultRotateRequest{
		FactorID:                req.GetFactorId(),
		PasswordVaultCredential: pbconv.VaultCredentialFromPB(req.GetCredential()),
	})
	if err != nil {
		return nil, mapPasswordError(err)
	}
	return pbconv.VaultEnrollResponseToPB(resp), nil
}

// PasswordVaultRemoveFactor removes one of the caller's factors.
func (s *Service) PasswordVaultRemoveFactor(ctx context.Context, req *pb.PasswordVaultRemoveFactorRequest) (*pb.PasswordVaultRemoveFactorResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if req.GetFactorId() == "" {
		return nil, status.Error(codes.InvalidArgument, "factor_id is required")
	}
	if err := s.authorize(ctx, auth.ResourcePasswords, auth.ActionUnlock, vaultResource); err != nil {
		return nil, err
	}
	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	if err := svc.PasswordVaultRemoveFactor(ctx, &transport.PasswordVaultRemoveFactorRequest{FactorID: req.GetFactorId()}); err != nil {
		return nil, mapPasswordError(err)
	}
	return &pb.PasswordVaultRemoveFactorResponse{}, nil
}

// PasswordVaultRecover uses the caller's one-time recovery code to enroll a
// new factor and returns the replacement code.
func (s *Service) PasswordVaultRecover(ctx context.Context, req *pb.PasswordVaultRecoverRequest) (*pb.PasswordVaultEnrollResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if err := s.authorize(ctx, auth.ResourcePasswords, auth.ActionUnlock, vaultResource); err != nil {
		return nil, err
	}
	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, err := svc.PasswordVaultRecover(ctx, &transport.PasswordVaultRecoverRequest{
		RecoveryCode:            req.GetRecoveryCode(),
		PasswordVaultCredential: pbconv.VaultCredentialFromPB(req.GetCredential()),
	})
	if err != nil {
		return nil, mapPasswordError(err)
	}
	return pbconv.VaultEnrollResponseToPB(resp), nil
}
