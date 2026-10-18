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

package grpc

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/jeremyhahn/go-xkms/pkg/api/apierrors"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// Typed errors for barrier and PIN gRPC operations.
var (
	// ErrBarrierNotConfigured is returned when no XKMSService is composed to
	// serve the barrier RPCs.
	ErrBarrierNotConfigured = errors.New("grpc: barrier not configured")

	// ErrPINManagerNotConfigured is returned when no XKMSService is composed
	// to serve the PIN RPCs.
	ErrPINManagerNotConfigured = errors.New("grpc: PIN manager not configured")
)

// The system-barrier and PIN RPCs delegate to the XKMSService: the barrier
// and the PIN backend are platform-global, and the service's
// system-tenant check is what refuses a tenant-scoped caller (go-xkms#1227).
// The RBAC gate cannot: a tenant-local Admin's self-scoped seal:* and pin:*
// grants resolve against its own tenant. No RPC here reaches the barrier or
// the PIN backend any other way.

// mapPINError converts a PIN domain error to the appropriate gRPC status
// error, classifying it through apierrors.PINSentinelClasses -- the table
// go-xkms#773 made this package share with pkg/api/mcp's mirror of this
// function, following the go-xkms#912 precedent set for PIV and barrier. If
// the error is a known PIN error, it maps to the corresponding gRPC code.
// Otherwise, it returns an Internal error.
func mapPINError(err error, operation string) error {
	if err == nil {
		return nil
	}
	if class, ok := apierrors.ClassOf(apierrors.PINSentinelClasses, err); ok {
		return status.Errorf(grpcCodeForClass(class), "%s: %v", operation, err)
	}
	return status.Errorf(codes.Internal, "%s: %v", operation, err)
}

// ==================== Barrier Operations ====================

// ==================== PIN Operations ====================

// pinService returns the composed XKMSService, or the Unavailable status a
// PIN RPC answers when none is composed.
func (s *Service) pinService() (*xkms.XKMSService, error) {
	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, ErrPINManagerNotConfigured.Error())
	}
	return s.xkmsService, nil
}

// SetSOPIN sets the Security Officer PIN.
func (s *Service) SetSOPIN(ctx context.Context, req *pb.SetSOPINRequest) (*emptypb.Empty, error) {
	if err := s.authorize(ctx, auth.ResourcePIN, auth.ActionWrite, "so-pin"); err != nil {
		return nil, err
	}
	svc, err := s.pinService()
	if err != nil {
		return nil, err
	}
	if err := svc.SetSOPIN(ctx, &transport.SetSOPINRequest{CurrentSOPIN: req.GetCurrentSoPin(), NewSOPIN: req.GetNewSoPin()}); err != nil {
		return nil, mapPINError(err, "set SO PIN")
	}
	return &emptypb.Empty{}, nil
}

// SetUserPIN sets the user PIN. Requires SO PIN authorization.
func (s *Service) SetUserPIN(ctx context.Context, req *pb.SetUserPINRequest) (*emptypb.Empty, error) {
	if err := s.authorize(ctx, auth.ResourcePIN, auth.ActionWrite, "user-pin"); err != nil {
		return nil, err
	}
	svc, err := s.pinService()
	if err != nil {
		return nil, err
	}
	if err := svc.SetUserPIN(ctx, &transport.SetUserPINRequest{SOPIN: req.GetSoPin(), NewUserPIN: req.GetNewUserPin()}); err != nil {
		return nil, mapPINError(err, "set user PIN")
	}
	return &emptypb.Empty{}, nil
}

// ChangeSOPIN changes the Security Officer PIN.
func (s *Service) ChangeSOPIN(ctx context.Context, req *pb.ChangeSOPINRequest) (*emptypb.Empty, error) {
	if err := s.authorize(ctx, auth.ResourcePIN, auth.ActionWrite, "so-pin"); err != nil {
		return nil, err
	}
	svc, err := s.pinService()
	if err != nil {
		return nil, err
	}
	if err := svc.ChangeSOPIN(ctx, &transport.ChangeSOPINRequest{CurrentSOPIN: req.GetCurrentSoPin(), NewSOPIN: req.GetNewSoPin()}); err != nil {
		return nil, mapPINError(err, "change SO PIN")
	}
	return &emptypb.Empty{}, nil
}

// ChangeUserPIN changes the user PIN.
func (s *Service) ChangeUserPIN(ctx context.Context, req *pb.ChangeUserPINRequest) (*emptypb.Empty, error) {
	if err := s.authorize(ctx, auth.ResourcePIN, auth.ActionWrite, "user-pin"); err != nil {
		return nil, err
	}
	svc, err := s.pinService()
	if err != nil {
		return nil, err
	}
	if err := svc.ChangeUserPIN(ctx, &transport.ChangeUserPINRequest{CurrentUserPIN: req.GetCurrentUserPin(), NewUserPIN: req.GetNewUserPin()}); err != nil {
		return nil, mapPINError(err, "change user PIN")
	}
	return &emptypb.Empty{}, nil
}

// VerifySOPIN verifies the provided Security Officer PIN.
func (s *Service) VerifySOPIN(ctx context.Context, req *pb.VerifySOPINRequest) (*emptypb.Empty, error) {
	if err := s.authorize(ctx, auth.ResourcePIN, auth.ActionRead, "so-pin"); err != nil {
		return nil, err
	}
	svc, err := s.pinService()
	if err != nil {
		return nil, err
	}
	if err := svc.VerifySOPIN(ctx, &transport.VerifySOPINRequest{SOPIN: req.GetSoPin()}); err != nil {
		return nil, mapPINError(err, "verify SO PIN")
	}
	return &emptypb.Empty{}, nil
}

// VerifyUserPIN verifies the provided user PIN.
func (s *Service) VerifyUserPIN(ctx context.Context, req *pb.VerifyUserPINRequest) (*emptypb.Empty, error) {
	if err := s.authorize(ctx, auth.ResourcePIN, auth.ActionRead, "user-pin"); err != nil {
		return nil, err
	}
	svc, err := s.pinService()
	if err != nil {
		return nil, err
	}
	if err := svc.VerifyUserPIN(ctx, &transport.VerifyUserPINRequest{UserPIN: req.GetUserPin()}); err != nil {
		return nil, mapPINError(err, "verify user PIN")
	}
	return &emptypb.Empty{}, nil
}

// GetLockoutStatus returns the current PIN lockout status. A backend that does
// not track lockout reports a zero-valued status: no lockout is active.
func (s *Service) GetLockoutStatus(ctx context.Context, _ *emptypb.Empty) (*pb.LockoutStatusResponse, error) {
	if err := s.authorize(ctx, auth.ResourcePIN, auth.ActionRead, "lockout-status"); err != nil {
		return nil, err
	}
	svc, err := s.pinService()
	if err != nil {
		return nil, err
	}
	ls, err := svc.GetLockoutStatus(ctx)
	if err != nil {
		return nil, mapPINError(err, "get lockout status")
	}
	return &pb.LockoutStatusResponse{
		FailedAttempts:  int32(ls.FailedAttempts), // #nosec G115 - Failed attempts fits in int32
		MaxAttempts:     int32(ls.MaxAttempts),    // #nosec G115 - Max attempts fits in int32
		IsLocked:        ls.IsLocked,
		LockoutUntil:    ls.LockoutUntil,
		RecoverySeconds: int32(ls.RecoverySeconds), // #nosec G115 - Recovery seconds fits in int32
	}, nil
}

// ResetLockout resets the PIN lockout counter using SO PIN authorization.
func (s *Service) ResetLockout(ctx context.Context, req *pb.ResetLockoutRequest) (*emptypb.Empty, error) {
	if err := s.authorize(ctx, auth.ResourcePIN, auth.ActionWrite, "lockout-reset"); err != nil {
		return nil, err
	}
	svc, err := s.pinService()
	if err != nil {
		return nil, err
	}
	if err := svc.ResetLockout(ctx, &transport.ResetLockoutRequest{SOPIN: req.GetSoPin()}); err != nil {
		return nil, mapPINError(err, "reset lockout")
	}
	return &emptypb.Empty{}, nil
}
