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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// otaImageKeyID validates a board id and backend and returns the board's key
// ID, on which the key permissions are checked.
func (s *Service) otaImageKeyID(ctx context.Context, boardID, backend string) (string, error) {
	keyID, err := xkms.OTAImageKeyID(boardID)
	if err != nil {
		return "", mapKeyOpError(ctx, s.xkmsService, err)
	}
	if backend == "" {
		return "", status.Error(codes.InvalidArgument, "backend is required")
	}
	return keyID, nil
}

// requireXKMSService refuses a call while the key service is not initialized.
func (s *Service) requireXKMSService() error {
	if s.xkmsService == nil {
		return status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}
	return nil
}

// CreateOTAImageKey creates the ES256 OTA image-signing key of one
// trusted-firmware board.
func (s *Service) CreateOTAImageKey(ctx context.Context, req *pb.OTAImageKeyRequest) (*pb.GenerateKeyResponse, error) {
	keyID, err := s.otaImageKeyID(ctx, req.BoardId, req.Backend)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionCreate, keyID); err != nil {
		return nil, err
	}
	if err := s.requireXKMSService(); err != nil {
		return nil, err
	}

	resp, err := s.xkmsService.CreateOTAImageKey(ctx, &transport.OTAImageKeyRequest{
		Backend:   req.Backend,
		BoardID:   req.BoardId,
		Algorithm: req.Algorithm,
		TenantID:  callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.GenerateKeyResponse{
		KeyId:        resp.KeyID,
		Backend:      req.Backend,
		KeyType:      resp.KeyType,
		PublicKeyPem: resp.PublicKeyPEM,
		CreatedAt:    timestamppb.Now(),
	}, nil
}

// RotateOTAImageKey creates the next version of a board's OTA image-signing
// key and makes it current; earlier versions keep verifying.
func (s *Service) RotateOTAImageKey(ctx context.Context, req *pb.OTAImageKeyRequest) (*pb.RotateKeyResponse, error) {
	keyID, err := s.otaImageKeyID(ctx, req.BoardId, req.Backend)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionRotate, keyID); err != nil {
		return nil, err
	}
	if err := s.requireXKMSService(); err != nil {
		return nil, err
	}

	resp, err := s.xkmsService.RotateOTAImageKey(ctx, &transport.OTAImageKeyRequest{
		Backend:   req.Backend,
		BoardID:   req.BoardId,
		Algorithm: req.Algorithm,
		TenantID:  callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.RotateKeyResponse{
		KeyId:                      resp.KeyID,
		Backend:                    req.Backend,
		KeyType:                    resp.KeyType,
		PublicKeyPem:               resp.PublicKeyPEM,
		RotatedAt:                  timestamppb.Now(),
		KeyVersion:                 resp.KeyVersion,
		CertificateReissueRequired: resp.CertificateReissueRequired,
	}, nil
}

// SignOTAImage signs an OTA image with the current version of its board's
// key, which the response's key_version names.
func (s *Service) SignOTAImage(ctx context.Context, req *pb.SignOTAImageRequest) (*pb.SignResponse, error) {
	keyID, err := s.otaImageKeyID(ctx, req.BoardId, req.Backend)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionSign, keyID); err != nil {
		return nil, err
	}
	if err := s.requireXKMSService(); err != nil {
		return nil, err
	}

	resp, err := s.xkmsService.SignOTAImage(ctx, &transport.OTAImageSignRequest{
		Backend:      req.Backend,
		BoardID:      req.BoardId,
		Data:         req.Data,
		DataIsDigest: req.DataIsDigest,
		TenantID:     callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.SignResponse{Signature: resp.Signature, KeyVersion: resp.KeyVersion}, nil
}

// ExportOTAImageKey returns the public half of the current version of a
// board's key. It reads a public key, so the get permission applies.
func (s *Service) ExportOTAImageKey(ctx context.Context, req *pb.OTAImageKeyRequest) (*pb.ExportOTAImageKeyResponse, error) {
	keyID, err := s.otaImageKeyID(ctx, req.BoardId, req.Backend)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionGet, keyID); err != nil {
		return nil, err
	}
	if err := s.requireXKMSService(); err != nil {
		return nil, err
	}

	resp, err := s.xkmsService.ExportOTAImageKey(ctx, &transport.OTAImageKeyRequest{
		Backend:   req.Backend,
		BoardID:   req.BoardId,
		Algorithm: req.Algorithm,
		TenantID:  callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.ExportOTAImageKeyResponse{
		BoardId:    resp.BoardID,
		KeyId:      resp.KeyID,
		KeyVersion: resp.KeyVersion,
		Algorithm:  resp.Algorithm,
		PublicKey:  resp.PublicKey,
		CoseKey:    resp.COSEKey,
	}, nil
}
