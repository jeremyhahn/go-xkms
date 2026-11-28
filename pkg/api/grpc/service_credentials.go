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

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// GetCredentialStrategy reports the configured credential strategy and the
// resolved PKCS#11 backend PIN strategy (#2262). It mirrors REST's
// CredentialHandlers.HandleGetStrategy, under the same credentials:strategy
// permission.
func (s *Service) GetCredentialStrategy(ctx context.Context, _ *pb.GetCredentialStrategyRequest) (*pb.CredentialStrategyResponse, error) {
	if err := s.authorize(ctx, auth.ResourceCredentials, auth.ActionStrategy, ""); err != nil {
		return nil, err
	}
	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	strategy, err := s.xkmsService.GetCredentialStrategy(ctx)
	if err != nil {
		if errors.Is(err, xkms.ErrNotConfigured) {
			return nil, status.Error(codes.Unavailable, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &pb.CredentialStrategyResponse{
		Strategy:           strategy.Strategy,
		AutoUnseal:         strategy.AutoUnseal,
		BackendPinStrategy: strategy.BackendPINStrategy,
	}, nil
}
