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
	"time"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Typed errors for barrier and PIN gRPC operations.
var (
	// ErrBarrierNotConfigured is returned when the barrier has not been
	// configured via SetBarrier.
	ErrBarrierNotConfigured = errors.New("grpc: barrier not configured")

	// ErrPINManagerNotConfigured is returned when the PIN manager has not
	// been configured via SetPINManager.
	ErrPINManagerNotConfigured = errors.New("grpc: PIN manager not configured")
)

// barrierErrorToGRPC maps barrier domain errors to gRPC status codes.
var barrierErrorToGRPC = map[error]codes.Code{
	// Core barrier errors.
	seal.ErrSealed:                codes.FailedPrecondition,
	seal.ErrAlreadyUnsealed:       codes.AlreadyExists,
	seal.ErrAlreadyInitialized:    codes.AlreadyExists,
	seal.ErrNotInitialized:        codes.FailedPrecondition,
	seal.ErrInvalidCredentials:    codes.Unauthenticated,
	seal.ErrNoAvailableStrategy:   codes.Unavailable,
	seal.ErrStrategyNotFound:      codes.NotFound,
	seal.ErrStrategyMismatch:      codes.FailedPrecondition,
	seal.ErrCorruptRootKey:        codes.DataLoss,
	seal.ErrEncryptorNotAvailable: codes.FailedPrecondition,

	// Shamir secret sharing errors.
	seal.ErrShamirNotConfigured:      codes.FailedPrecondition,
	seal.ErrShamirThresholdInvalid:   codes.InvalidArgument,
	seal.ErrShamirQuorumIncomplete:   codes.FailedPrecondition,
	seal.ErrShamirQuorumExpired:      codes.DeadlineExceeded,
	seal.ErrShamirDuplicateShare:     codes.AlreadyExists,
	seal.ErrShamirCombineFailed:      codes.Internal,
	seal.ErrShamirShareNotFound:      codes.NotFound,
	seal.ErrShamirNoSharesFound:      codes.NotFound,
	seal.ErrShamirVerificationFailed: codes.DataLoss,
	seal.ErrShamirStorageFailed:      codes.Internal,

	// Recovery and root token errors.
	seal.ErrRecoveryKeysNotFound:        codes.NotFound,
	seal.ErrRootTokenVerificationFailed: codes.Unauthenticated,
}

// pinErrorToGRPC maps PIN domain errors to gRPC status codes.
var pinErrorToGRPC = map[error]codes.Code{
	pin.ErrPINNotSet:         codes.FailedPrecondition,
	pin.ErrPINLocked:         codes.ResourceExhausted,
	pin.ErrPINInvalid:        codes.Unauthenticated,
	pin.ErrSOPINRequired:     codes.Unauthenticated,
	pin.ErrPINTooShort:       codes.InvalidArgument,
	pin.ErrPINAlreadySet:     codes.AlreadyExists,
	pin.ErrInvalidCurrentPIN: codes.Unauthenticated,
	pin.ErrStateCorrupted:    codes.DataLoss,
	pin.ErrStrategyNotSet:    codes.FailedPrecondition,
}

// Package-level barrier and PIN manager references, set via their
// respective setter functions.
var (
	barrier    *seal.Barrier
	pinManager pin.PINManager //nolint:staticcheck // TODO: migrate to PINBackend
)

// SetBarrier configures the barrier for the gRPC service.
// This must be called before any barrier RPCs can be used.
func SetBarrier(b *seal.Barrier) {
	barrier = b
}

// GetBarrier returns the configured barrier, or nil if not set.
func GetBarrier() *seal.Barrier {
	return barrier
}

// SetPINManager configures the PIN manager for the gRPC service.
// This must be called before any PIN RPCs can be used.
func SetPINManager(pm pin.PINManager) { //nolint:staticcheck // TODO: migrate to PINBackend
	pinManager = pm
}

// GetPINManager returns the configured PIN manager, or nil if not set.
func GetPINManager() pin.PINManager { //nolint:staticcheck // TODO: migrate to PINBackend
	return pinManager
}

// mapBarrierError converts a barrier domain error to the appropriate gRPC
// status error. If the error is a known barrier error, it maps to the
// corresponding gRPC code. Otherwise, it returns an Internal error.
func mapBarrierError(err error, operation string) error {
	if err == nil {
		return nil
	}
	for barrierErr, code := range barrierErrorToGRPC {
		if errors.Is(err, barrierErr) {
			return status.Errorf(code, "%s: %v", operation, err)
		}
	}
	return status.Errorf(codes.Internal, "%s: %v", operation, err)
}

// mapPINError converts a PIN domain error to the appropriate gRPC status
// error. If the error is a known PIN error, it maps to the corresponding
// gRPC code. Otherwise, it returns an Internal error.
func mapPINError(err error, operation string) error {
	if err == nil {
		return nil
	}
	for pinErr, code := range pinErrorToGRPC {
		if errors.Is(err, pinErr) {
			return status.Errorf(code, "%s: %v", operation, err)
		}
	}
	return status.Errorf(codes.Internal, "%s: %v", operation, err)
}

// ==================== Barrier Operations ====================

// BarrierInitialize generates a root key, seals it with the best available
// strategy, and transitions the barrier to unsealed state.
func (s *Service) BarrierInitialize(ctx context.Context, req *pb.BarrierInitializeRequest) (*emptypb.Empty, error) {
	if barrier == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBarrierNotConfigured.Error())
	}

	if err := s.authorize(ctx, "barrier", "write", "initialize"); err != nil {
		return nil, err
	}

	creds := seal.Credentials{Secret: req.GetSecret()}
	if err := barrier.Initialize(ctx, creds); err != nil {
		return nil, mapBarrierError(err, "barrier initialize")
	}

	return &emptypb.Empty{}, nil
}

// BarrierUnseal loads and unseals the root key, deriving the data encryption
// key to enable storage operations.
func (s *Service) BarrierUnseal(ctx context.Context, req *pb.BarrierUnsealRequest) (*emptypb.Empty, error) {
	if barrier == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBarrierNotConfigured.Error())
	}

	if err := s.authorize(ctx, "barrier", "write", "unseal"); err != nil {
		return nil, err
	}

	creds := seal.Credentials{Secret: req.GetSecret()}
	if err := barrier.Unseal(ctx, creds); err != nil {
		return nil, mapBarrierError(err, "barrier unseal")
	}

	return &emptypb.Empty{}, nil
}

// BarrierSeal transitions the barrier to sealed state and zeros the DEK.
func (s *Service) BarrierSeal(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	if barrier == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBarrierNotConfigured.Error())
	}

	if err := s.authorize(ctx, "barrier", "write", "seal"); err != nil {
		return nil, err
	}

	if err := barrier.Seal(); err != nil {
		return nil, mapBarrierError(err, "barrier seal")
	}

	return &emptypb.Empty{}, nil
}

// BarrierStatus returns the current state of the barrier including whether
// it is sealed, which strategy is active, and hardware backing status.
func (s *Service) BarrierStatus(ctx context.Context, _ *emptypb.Empty) (*pb.BarrierStatusResponse, error) {
	if barrier == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBarrierNotConfigured.Error())
	}

	if err := s.authorize(ctx, "barrier", "read", "status"); err != nil {
		return nil, err
	}

	bs := barrier.Status()

	var initializedAt string
	if !bs.InitializedAt.IsZero() {
		initializedAt = bs.InitializedAt.Format(time.RFC3339)
	}

	return &pb.BarrierStatusResponse{
		Sealed:         bs.Sealed,
		Strategy:       string(bs.Strategy),
		HardwareBacked: bs.HardwareBacked,
		InitializedAt:  initializedAt,
	}, nil
}

// ==================== PIN Operations ====================

// SetSOPIN sets the Security Officer PIN.
func (s *Service) SetSOPIN(ctx context.Context, req *pb.SetSOPINRequest) (*emptypb.Empty, error) {
	if pinManager == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrPINManagerNotConfigured.Error())
	}

	if err := s.authorize(ctx, "pin", "write", "so-pin"); err != nil {
		return nil, err
	}

	if err := pinManager.SetSOPIN(req.GetCurrentSoPin(), req.GetNewSoPin()); err != nil {
		return nil, mapPINError(err, "set SO PIN")
	}

	return &emptypb.Empty{}, nil
}

// SetUserPIN sets the user PIN. Requires SO PIN authorization.
func (s *Service) SetUserPIN(ctx context.Context, req *pb.SetUserPINRequest) (*emptypb.Empty, error) {
	if pinManager == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrPINManagerNotConfigured.Error())
	}

	if err := s.authorize(ctx, "pin", "write", "user-pin"); err != nil {
		return nil, err
	}

	if err := pinManager.SetUserPIN(req.GetSoPin(), req.GetNewUserPin()); err != nil {
		return nil, mapPINError(err, "set user PIN")
	}

	return &emptypb.Empty{}, nil
}

// ChangeSOPIN changes the Security Officer PIN.
func (s *Service) ChangeSOPIN(ctx context.Context, req *pb.ChangeSOPINRequest) (*emptypb.Empty, error) {
	if pinManager == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrPINManagerNotConfigured.Error())
	}

	if err := s.authorize(ctx, "pin", "write", "so-pin"); err != nil {
		return nil, err
	}

	if err := pinManager.ChangeSOPIN(req.GetCurrentSoPin(), req.GetNewSoPin()); err != nil {
		return nil, mapPINError(err, "change SO PIN")
	}

	return &emptypb.Empty{}, nil
}

// ChangeUserPIN changes the user PIN.
func (s *Service) ChangeUserPIN(ctx context.Context, req *pb.ChangeUserPINRequest) (*emptypb.Empty, error) {
	if pinManager == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrPINManagerNotConfigured.Error())
	}

	if err := s.authorize(ctx, "pin", "write", "user-pin"); err != nil {
		return nil, err
	}

	if err := pinManager.ChangeUserPIN(req.GetCurrentUserPin(), req.GetNewUserPin()); err != nil {
		return nil, mapPINError(err, "change user PIN")
	}

	return &emptypb.Empty{}, nil
}

// VerifySOPIN verifies the provided Security Officer PIN.
func (s *Service) VerifySOPIN(ctx context.Context, req *pb.VerifySOPINRequest) (*emptypb.Empty, error) {
	if pinManager == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrPINManagerNotConfigured.Error())
	}

	if err := s.authorize(ctx, "pin", "read", "so-pin"); err != nil {
		return nil, err
	}

	if err := pinManager.VerifySOPIN(req.GetSoPin()); err != nil {
		return nil, mapPINError(err, "verify SO PIN")
	}

	return &emptypb.Empty{}, nil
}

// VerifyUserPIN verifies the provided user PIN.
func (s *Service) VerifyUserPIN(ctx context.Context, req *pb.VerifyUserPINRequest) (*emptypb.Empty, error) {
	if pinManager == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrPINManagerNotConfigured.Error())
	}

	if err := s.authorize(ctx, "pin", "read", "user-pin"); err != nil {
		return nil, err
	}

	if err := pinManager.VerifyUserPIN(req.GetUserPin()); err != nil {
		return nil, mapPINError(err, "verify user PIN")
	}

	return &emptypb.Empty{}, nil
}

// GetLockoutStatus returns the current PIN lockout status. When the backend
// does not track lockout (returns nil), a zero-valued response is returned
// indicating no lockout is active.
func (s *Service) GetLockoutStatus(ctx context.Context, _ *emptypb.Empty) (*pb.LockoutStatusResponse, error) {
	if pinManager == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrPINManagerNotConfigured.Error())
	}

	if err := s.authorize(ctx, "pin", "read", "lockout-status"); err != nil {
		return nil, err
	}

	ls := pinManager.GetLockoutStatus()
	if ls == nil {
		// Backend does not track lockout (e.g., SoftwareBackend). Return
		// a zero-valued response indicating no lockout is active.
		return &pb.LockoutStatusResponse{}, nil
	}

	var lockoutUntil string
	if !ls.LockoutUntil.IsZero() {
		lockoutUntil = ls.LockoutUntil.Format(time.RFC3339)
	}

	return &pb.LockoutStatusResponse{
		FailedAttempts:  int32(ls.FailedAttempts), // #nosec G115 - Failed attempts fits in int32
		MaxAttempts:     int32(ls.MaxAttempts),    // #nosec G115 - Max attempts fits in int32
		IsLocked:        ls.IsLocked,
		LockoutUntil:    lockoutUntil,
		RecoverySeconds: int32(ls.RecoverySeconds), // #nosec G115 - Recovery seconds fits in int32
	}, nil
}

// ResetLockout resets the PIN lockout counter using SO PIN authorization.
func (s *Service) ResetLockout(ctx context.Context, req *pb.ResetLockoutRequest) (*emptypb.Empty, error) {
	if pinManager == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrPINManagerNotConfigured.Error())
	}

	if err := s.authorize(ctx, "pin", "write", "lockout-reset"); err != nil {
		return nil, err
	}

	if err := pinManager.ResetLockout(req.GetSoPin()); err != nil {
		return nil, mapPINError(err, "reset lockout")
	}

	return &emptypb.Empty{}, nil
}
