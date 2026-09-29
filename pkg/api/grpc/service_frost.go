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

//go:build frost

package grpc

import (
	"context"
	"fmt"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/frost"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// The FROST RPCs are thin adapters over the XKMSService FROST methods, which
// resolve every key inside the caller's tenant (go-xkms#1231). Each RPC
// authorizes first, then delegates, and maps the service error through
// mapKeyOpError, so another tenant's key is the same codes.NotFound a missing
// key is.

// frostDefaultPageSize is the page size FrostListKeys applies when the request
// names none.
const frostDefaultPageSize = 100

// frostService returns the injected xkms service, or the Unavailable status
// every service-layer RPC reports without one.
func (s *Service) frostService() (*xkms.XKMSService, error) {
	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}
	return s.xkmsService, nil
}

// frostKeyInfoToProto renders a service key description for the wire.
func frostKeyInfoToProto(info *xkms.FrostKeyInfo) *pb.FrostKeyInfo {
	return &pb.FrostKeyInfo{
		KeyId:          info.KeyID,
		Algorithm:      info.Algorithm,
		Threshold:      int32(info.Threshold),
		Total:          int32(info.Total),
		ParticipantId:  info.ParticipantID,
		GroupPublicKey: info.GroupPublicKey,
		Participants:   info.Participants,
		CreatedAt:      timestamppb.New(info.CreatedAt),
	}
}

// frostCommitmentsFromProto converts the wire commitments of a signing
// request.
func frostCommitmentsFromProto(in []*pb.FrostCommitment) []*frost.Commitment {
	commitments := make([]*frost.Commitment, len(in))
	for i, c := range in {
		commitments[i] = &frost.Commitment{
			ParticipantID: c.ParticipantId,
			Commitments: &frost.SigningCommitments{
				ParticipantID:     c.ParticipantId,
				HidingCommitment:  c.HidingCommitment,
				BindingCommitment: c.BindingCommitment,
			},
		}
	}
	return commitments
}

// FrostGenerateKey generates a FROST key: in participant mode the key is
// stored for the caller's tenant, in dealer mode every participant's package
// is returned.
func (s *Service) FrostGenerateKey(ctx context.Context, req *pb.FrostGenerateKeyRequest) (*pb.FrostGenerateKeyResponse, error) {
	if req.Threshold < 2 {
		return nil, status.Error(codes.InvalidArgument, "threshold must be at least 2")
	}
	if req.Total < req.Threshold {
		return nil, status.Error(codes.InvalidArgument, "total must be >= threshold")
	}

	// FROST key generation creates threshold key material, so it is gated by
	// the same permission as any other key creation (see GenerateKey in
	// service.go), and identically in the MCP frost.generateKey permission
	// entry.
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionCreate, req.KeyId); err != nil {
		return nil, err
	}
	svc, err := s.frostService()
	if err != nil {
		return nil, err
	}

	gen, err := svc.FrostGenerateKey(ctx, &xkms.FrostGenerateKeyRequest{
		KeyID:         req.KeyId,
		Algorithm:     req.Algorithm,
		Threshold:     int(req.Threshold),
		Total:         int(req.Total),
		Participants:  req.Participants,
		ParticipantID: req.ParticipantId,
		DealerMode:    req.DealerMode,
	})
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	packages := make([]*pb.FrostKeyPackage, 0, len(gen.Packages))
	for _, pkg := range gen.Packages {
		packages = append(packages, &pb.FrostKeyPackage{
			KeyId:              gen.KeyID,
			Algorithm:          gen.Algorithm,
			Threshold:          req.Threshold,
			Total:              req.Total,
			ParticipantId:      pkg.ParticipantID,
			ParticipantName:    pkg.ParticipantName,
			SecretShare:        pkg.SecretShare,
			GroupPublicKey:     pkg.GroupPublicKey,
			VerificationShares: pkg.VerificationShares,
		})
	}

	return &pb.FrostGenerateKeyResponse{
		KeyId:          gen.KeyID,
		Algorithm:      gen.Algorithm,
		Threshold:      req.Threshold,
		Total:          req.Total,
		GroupPublicKey: gen.GroupPublicKey,
		ParticipantId:  gen.ParticipantID,
		Packages:       packages,
		CreatedAt:      timestamppb.New(gen.CreatedAt),
	}, nil
}

// FrostImportKey imports a FROST key package into the caller's tenant.
func (s *Service) FrostImportKey(ctx context.Context, req *pb.FrostImportKeyRequest) (*pb.FrostImportKeyResponse, error) {
	if req.Package == nil {
		return nil, status.Error(codes.InvalidArgument, "package is required")
	}

	// Importing a key package installs externally supplied secret-share
	// material, which is the same privilege ImportKey carries.
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionImport, req.Package.KeyId); err != nil {
		return nil, err
	}
	svc, err := s.frostService()
	if err != nil {
		return nil, err
	}

	pkg := req.Package
	if err := svc.FrostImportKey(ctx, &xkms.FrostImportKeyRequest{
		KeyID:              pkg.KeyId,
		Algorithm:          pkg.Algorithm,
		Threshold:          int(pkg.Threshold),
		Total:              int(pkg.Total),
		ParticipantID:      pkg.ParticipantId,
		SecretShare:        pkg.SecretShare,
		GroupPublicKey:     pkg.GroupPublicKey,
		VerificationShares: pkg.VerificationShares,
	}); err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	return &pb.FrostImportKeyResponse{
		Success:        true,
		Message:        fmt.Sprintf("key package imported successfully for participant %d", pkg.ParticipantId),
		KeyId:          pkg.KeyId,
		ParticipantId:  pkg.ParticipantId,
		GroupPublicKey: pkg.GroupPublicKey,
	}, nil
}

// FrostListKeys lists the caller's tenant's FROST keys.
func (s *Service) FrostListKeys(ctx context.Context, req *pb.FrostListKeysRequest) (*pb.FrostListKeysResponse, error) {
	// Enumerating key material is a listing, exactly as ListKeys is. There is
	// no per-key subject to name, so the resource ID is empty.
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionList, ""); err != nil {
		return nil, err
	}
	svc, err := s.frostService()
	if err != nil {
		return nil, err
	}

	keys, err := svc.FrostListKeys(ctx)
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}

	limit := int(req.Limit)
	if limit <= 0 {
		limit = frostDefaultPageSize
	}
	offset := min(max(int(req.Offset), 0), len(keys))
	end := min(offset+limit, len(keys))

	infos := make([]*pb.FrostKeyInfo, 0, end-offset)
	for i := offset; i < end; i++ {
		infos = append(infos, frostKeyInfoToProto(&keys[i]))
	}
	return &pb.FrostListKeysResponse{Keys: infos, Total: int32(len(keys))}, nil
}

// FrostGetKey describes one of the caller's tenant's FROST keys.
func (s *Service) FrostGetKey(ctx context.Context, req *pb.FrostGetKeyRequest) (*pb.FrostGetKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}

	// Reading a key's metadata is the GetKey privilege.
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionGet, req.KeyId); err != nil {
		return nil, err
	}
	svc, err := s.frostService()
	if err != nil {
		return nil, err
	}

	info, err := svc.FrostGetKey(ctx, req.KeyId)
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}
	return &pb.FrostGetKeyResponse{Key: frostKeyInfoToProto(info)}, nil
}

// FrostDeleteKey deletes one of the caller's tenant's FROST keys.
func (s *Service) FrostDeleteKey(ctx context.Context, req *pb.FrostDeleteKeyRequest) (*pb.FrostDeleteKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}

	// Destroying a share is the DeleteKey privilege.
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionDelete, req.KeyId); err != nil {
		return nil, err
	}
	svc, err := s.frostService()
	if err != nil {
		return nil, err
	}

	if err := svc.FrostDeleteKey(ctx, req.KeyId); err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}
	return &pb.FrostDeleteKeyResponse{
		Success: true,
		Message: fmt.Sprintf("key %s deleted successfully", req.KeyId),
	}, nil
}

// FrostGenerateNonces generates nonces and commitments for Round 1.
func (s *Service) FrostGenerateNonces(ctx context.Context, req *pb.FrostGenerateNoncesRequest) (*pb.FrostGenerateNoncesResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}

	// Round 1 commits this participant's share to a signing session: it is a
	// step of signing with the key, so it takes the signing permission.
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionSign, req.KeyId); err != nil {
		return nil, err
	}
	svc, err := s.frostService()
	if err != nil {
		return nil, err
	}

	nonces, err := svc.FrostGenerateNonces(ctx, req.KeyId)
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}
	return &pb.FrostGenerateNoncesResponse{
		ParticipantId:     nonces.ParticipantID,
		SessionId:         nonces.SessionID,
		HidingNonce:       nonces.Nonces.HidingNonce,
		BindingNonce:      nonces.Nonces.BindingNonce,
		HidingCommitment:  nonces.Commitments.HidingCommitment,
		BindingCommitment: nonces.Commitments.BindingCommitment,
	}, nil
}

// FrostSignRound generates a signature share for Round 2.
func (s *Service) FrostSignRound(ctx context.Context, req *pb.FrostSignRoundRequest) (*pb.FrostSignRoundResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if len(req.Message) == 0 {
		return nil, status.Error(codes.InvalidArgument, "message is required")
	}
	if len(req.HidingNonce) == 0 || len(req.BindingNonce) == 0 {
		return nil, status.Error(codes.InvalidArgument, "nonces are required")
	}
	if len(req.Commitments) == 0 {
		return nil, status.Error(codes.InvalidArgument, "commitments are required")
	}

	// Round 2 produces a signature share over the caller's message: signing.
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionSign, req.KeyId); err != nil {
		return nil, err
	}
	svc, err := s.frostService()
	if err != nil {
		return nil, err
	}

	share, err := svc.FrostSignRound(ctx, &xkms.FrostSignRoundRequest{
		KeyID:             req.KeyId,
		Message:           req.Message,
		SessionID:         req.SessionId,
		HidingNonce:       req.HidingNonce,
		BindingNonce:      req.BindingNonce,
		HidingCommitment:  req.HidingCommitment,
		BindingCommitment: req.BindingCommitment,
		Commitments:       frostCommitmentsFromProto(req.Commitments),
	})
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}
	return &pb.FrostSignRoundResponse{
		ParticipantId:  share.ParticipantID,
		SessionId:      share.SessionID,
		SignatureShare: share.Share,
	}, nil
}

// FrostAggregate combines signature shares into a final FROST signature.
func (s *Service) FrostAggregate(ctx context.Context, req *pb.FrostAggregateRequest) (*pb.FrostAggregateResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if len(req.Message) == 0 {
		return nil, status.Error(codes.InvalidArgument, "message is required")
	}
	if len(req.Commitments) == 0 {
		return nil, status.Error(codes.InvalidArgument, "commitments are required")
	}
	if len(req.Shares) == 0 {
		return nil, status.Error(codes.InvalidArgument, "shares are required")
	}

	// Aggregation is the step that yields the completed group signature, so it
	// carries the signing permission rather than a weaker read verb.
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionSign, req.KeyId); err != nil {
		return nil, err
	}
	svc, err := s.frostService()
	if err != nil {
		return nil, err
	}

	shares := make([]*frost.SignatureShare, len(req.Shares))
	for i, share := range req.Shares {
		shares[i] = &frost.SignatureShare{
			ParticipantID: share.ParticipantId,
			SessionID:     share.SessionId,
			Share:         share.Share,
		}
	}

	agg, err := svc.FrostAggregate(ctx, &xkms.FrostAggregateRequest{
		KeyID:       req.KeyId,
		Message:     req.Message,
		Commitments: frostCommitmentsFromProto(req.Commitments),
		Shares:      shares,
		Verify:      req.Verify,
	})
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}
	return &pb.FrostAggregateResponse{Signature: agg.Signature, Verified: agg.Verified}, nil
}

// FrostVerify verifies a FROST signature against the group public key.
func (s *Service) FrostVerify(ctx context.Context, req *pb.FrostVerifyRequest) (*pb.FrostVerifyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if len(req.Message) == 0 {
		return nil, status.Error(codes.InvalidArgument, "message is required")
	}
	if len(req.Signature) == 0 {
		return nil, status.Error(codes.InvalidArgument, "signature is required")
	}

	// Verification only reads the group public key: the Verify privilege.
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionVerify, req.KeyId); err != nil {
		return nil, err
	}
	svc, err := s.frostService()
	if err != nil {
		return nil, err
	}

	result, err := svc.FrostVerify(ctx, req.KeyId, req.Message, req.Signature)
	if err != nil {
		return nil, mapKeyOpError(ctx, s.xkmsService, err)
	}
	if !result.Valid {
		return &pb.FrostVerifyResponse{
			Valid:   false,
			Message: "signature verification failed: " + result.Reason,
		}, nil
	}
	return &pb.FrostVerifyResponse{Valid: true, Message: "signature is valid"}, nil
}
