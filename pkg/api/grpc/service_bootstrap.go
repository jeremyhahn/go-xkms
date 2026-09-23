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
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// BootstrapListenerKeys is the gRPC (and, over the same generated client,
// Unix) server side of the trust-bootstrap listener's public key report
// (go-xkms#632). It gates on the bootstrap resource, distinct from seal:*:
// the listener's identity is not barrier state, and an administrator who can
// read it must not thereby gain any barrier permission.
func (s *Service) BootstrapListenerKeys(ctx context.Context, _ *emptypb.Empty) (*pb.BootstrapListenerKeysResponse, error) {
	if err := s.authorize(ctx, auth.ResourceBootstrap, auth.ActionRead, ""); err != nil {
		return nil, err
	}
	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, err := s.xkmsService.BootstrapListenerKeys(ctx)
	if err != nil {
		return nil, mapBootstrapError(err)
	}
	return &pb.BootstrapListenerKeysResponse{
		NoisePublicKey: resp.NoisePublicKey,
		P256PublicKey:  resp.P256PublicKey,
	}, nil
}

// mapBootstrapError translates a trust-bootstrap listener error into the
// gRPC status code a caller can act on.
func mapBootstrapError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, xkms.ErrBootstrapListenerNotEnabled):
		return status.Error(codes.Unavailable, "bootstrap listener not enabled")
	default:
		return status.Error(codes.Internal, err.Error())
	}
}
