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
	"time"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ==================== Shamir Barrier Operations ====================

// BarrierInitializeShamir generates a root key and splits it into Shamir
// shares. The barrier transitions to unsealed state after initialization.
func (s *Service) BarrierInitializeShamir(ctx context.Context, req *pb.BarrierInitializeShamirRequest) (*pb.BarrierShamirInitResponse, error) {
	if barrier == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBarrierNotConfigured.Error())
	}

	if err := s.authorize(ctx, "seal", "initialize_shamir", "initialize-shamir"); err != nil {
		return nil, err
	}

	creds := seal.Credentials{Secret: req.GetSecret()}
	result, err := barrier.InitializeShamir(ctx, creds)
	if err != nil {
		return nil, mapBarrierError(err, "barrier initialize shamir")
	}

	// Share material is never returned: shares are sealed to enrolled
	// Security Officers via the CeremonyDistributor (qrdb share-free
	// contract). Only the threshold/total metadata is reported.
	return &pb.BarrierShamirInitResponse{
		Threshold:   int32(result.Threshold),   // #nosec G115 - Threshold fits in int32
		TotalShares: int32(result.TotalShares), // #nosec G115 - TotalShares fits in int32
		ShareCount:  int32(result.ShareCount),  // #nosec G115 - ShareCount fits in int32
	}, nil
}

// BarrierUnsealShare submits a single share for stateful quorum-based
// unsealing. When enough shares have been submitted (reaching the threshold),
// the barrier automatically unseals. Returns progress information.
func (s *Service) BarrierUnsealShare(ctx context.Context, req *pb.BarrierUnsealShareRequest) (*pb.BarrierQuorumProgressResponse, error) {
	if barrier == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBarrierNotConfigured.Error())
	}

	if err := s.authorize(ctx, "barrier", "unseal-share", "unseal-share"); err != nil {
		return nil, err
	}

	progress, err := barrier.UnsealWithShare(ctx, req.GetShare())
	if err != nil {
		// Return progress alongside the error when available.
		if progress != nil {
			return &pb.BarrierQuorumProgressResponse{
				Required:  int32(progress.Required),  // #nosec G115 - Required fits in int32
				Submitted: int32(progress.Submitted), // #nosec G115 - Submitted fits in int32
				Complete:  progress.Complete,
			}, mapBarrierError(err, "barrier unseal share")
		}
		return nil, mapBarrierError(err, "barrier unseal share")
	}

	return &pb.BarrierQuorumProgressResponse{
		Required:  int32(progress.Required),  // #nosec G115 - Required fits in int32
		Submitted: int32(progress.Submitted), // #nosec G115 - Submitted fits in int32
		Complete:  progress.Complete,
	}, nil
}

// BarrierUnsealShares performs stateless batch unsealing with all shares
// provided in a single call. All required shares must be present.
func (s *Service) BarrierUnsealShares(ctx context.Context, req *pb.BarrierUnsealSharesRequest) (*emptypb.Empty, error) {
	if barrier == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBarrierNotConfigured.Error())
	}

	if err := s.authorize(ctx, "seal", "unseal", "unseal-shares"); err != nil {
		return nil, err
	}

	if err := barrier.UnsealWithShares(ctx, req.GetShares()); err != nil {
		return nil, mapBarrierError(err, "barrier unseal shares")
	}

	return &emptypb.Empty{}, nil
}

// BarrierRekey generates a new set of Shamir shares for the existing root key.
// The barrier must be unsealed and StrategyShamir must be registered. Old
// shares are deleted and replaced with new shares using the given parameters.
func (s *Service) BarrierRekey(ctx context.Context, req *pb.BarrierRekeyRequest) (*pb.BarrierShamirInitResponse, error) {
	if barrier == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBarrierNotConfigured.Error())
	}

	if err := s.authorize(ctx, "seal", "rekey", "rekey"); err != nil {
		return nil, err
	}

	result, err := barrier.Rekey(ctx, int(req.GetThreshold()), int(req.GetTotal()))
	if err != nil {
		return nil, mapBarrierError(err, "barrier rekey")
	}

	// New shares are sealed to enrolled Security Officers and never
	// returned; only the threshold/total metadata is reported.
	return &pb.BarrierShamirInitResponse{
		Threshold:   int32(result.Threshold),   // #nosec G115 - Threshold fits in int32
		TotalShares: int32(result.TotalShares), // #nosec G115 - TotalShares fits in int32
		ShareCount:  int32(result.ShareCount),  // #nosec G115 - ShareCount fits in int32
	}, nil
}

// ==================== Recovery Key Operations ====================

// BarrierGenerateRecoveryKeys generates an independent set of Shamir shares
// that can reconstruct the current DEK. The barrier must be unsealed.
// Recovery shares are sealed to enrolled recovery officers and never
// returned (qrdb share-free contract).
func (s *Service) BarrierGenerateRecoveryKeys(ctx context.Context, req *pb.BarrierGenerateRecoveryKeysRequest) (*pb.BarrierRecoveryKeysResponse, error) {
	if barrier == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBarrierNotConfigured.Error())
	}

	if err := s.authorize(ctx, "seal", "generate_recovery", "generate-recovery-keys"); err != nil {
		return nil, err
	}

	result, err := barrier.GenerateRecoveryKeys(ctx, int(req.GetThreshold()), int(req.GetTotal()))
	if err != nil {
		return nil, mapBarrierError(err, "barrier generate recovery keys")
	}

	// Recovery shares are sealed to enrolled recovery officers and never
	// returned; only the threshold/total metadata is reported.
	return &pb.BarrierRecoveryKeysResponse{
		Threshold:   int32(result.Threshold),   // #nosec G115 - Threshold fits in int32
		TotalShares: int32(result.TotalShares), // #nosec G115 - TotalShares fits in int32
		ShareCount:  int32(result.ShareCount),  // #nosec G115 - ShareCount fits in int32
	}, nil
}

// BarrierRecoverWithKeys reconstructs the DEK from recovery key shares
// and unseals the barrier. The barrier must be sealed.
func (s *Service) BarrierRecoverWithKeys(ctx context.Context, req *pb.BarrierRecoverWithKeysRequest) (*emptypb.Empty, error) {
	if barrier == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBarrierNotConfigured.Error())
	}

	if err := s.authorize(ctx, "seal", "recover_with_keys", "recover-with-keys"); err != nil {
		return nil, err
	}

	if err := barrier.RecoverWithKeys(ctx, req.GetKeys()); err != nil {
		return nil, mapBarrierError(err, "barrier recover with keys")
	}

	return &emptypb.Empty{}, nil
}

// BarrierDeleteRecoveryKeys removes recovery key metadata from storage.
// The actual shares are not stored -- only the metadata is deleted.
func (s *Service) BarrierDeleteRecoveryKeys(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	if barrier == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBarrierNotConfigured.Error())
	}

	if err := s.authorize(ctx, "seal", "generate_recovery", "delete-recovery-keys"); err != nil {
		return nil, err
	}

	if err := barrier.DeleteRecoveryKeys(ctx); err != nil {
		return nil, mapBarrierError(err, "barrier delete recovery keys")
	}

	return &emptypb.Empty{}, nil
}

// ==================== Root Token Operations ====================

// BarrierGenerateRootToken generates a one-time root token by proving
// knowledge of the master key through Shamir share reconstruction.
func (s *Service) BarrierGenerateRootToken(ctx context.Context, req *pb.BarrierGenerateRootTokenRequest) (*pb.BarrierRootTokenResponse, error) {
	if barrier == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBarrierNotConfigured.Error())
	}

	if err := s.authorize(ctx, "seal", "rotate_root_key", "generate-root-token"); err != nil {
		return nil, err
	}

	token, err := barrier.GenerateRootToken(ctx, req.GetShares())
	if err != nil {
		return nil, mapBarrierError(err, "barrier generate root token")
	}

	return &pb.BarrierRootTokenResponse{
		Token:     token.Token,
		CreatedAt: token.CreatedAt.Format(time.RFC3339),
	}, nil
}
