// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
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
	"time"

	pb "github.com/jeremyhahn/go-keychain/api/proto/keychainv1"
	"github.com/jeremyhahn/go-keychain/pkg/backend/frost"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// FrostGenerateKey generates FROST key packages using trusted dealer model
func (s *Service) FrostGenerateKey(ctx context.Context, req *pb.FrostGenerateKeyRequest) (*pb.FrostGenerateKeyResponse, error) {
	// Validate request
	if req.Threshold < 2 {
		return nil, status.Error(codes.InvalidArgument, "threshold must be at least 2")
	}
	if req.Total < req.Threshold {
		return nil, status.Error(codes.InvalidArgument, "total must be >= threshold")
	}

	// Set defaults
	algorithm := req.Algorithm
	if algorithm == "" {
		algorithm = string(types.FrostAlgorithmEd25519)
	}

	keyID := req.KeyId
	if keyID == "" {
		keyID = fmt.Sprintf("frost-key-%d", time.Now().UnixNano())
	}

	// Get FROST backend
	be, err := s.getFrostBackend()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get FROST backend: %v", err)
	}

	if req.DealerMode {
		// Dealer mode: generate all packages using trusted dealer
		td := frost.NewTrustedDealer()
		frostConfig := frost.FrostConfig{
			Threshold:     int(req.Threshold),
			Total:         int(req.Total),
			Algorithm:     types.FrostAlgorithm(algorithm),
			ParticipantID: 1, // Not used for generation
		}

		packages, pubPkg, err := td.Generate(frostConfig)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to generate FROST packages: %v", err)
		}

		// Convert to protobuf format
		pbPackages := make([]*pb.FrostKeyPackage, len(packages))
		for i, pkg := range packages {
			vsMap := make(map[uint32][]byte)
			for id, vs := range pubPkg.VerificationShares {
				vsMap[id] = vs
			}

			var participantName string
			if i < len(req.Participants) {
				participantName = req.Participants[i]
			}

			pbPackages[i] = &pb.FrostKeyPackage{
				KeyId:              keyID,
				Algorithm:          algorithm,
				Threshold:          req.Threshold,
				Total:              req.Total,
				ParticipantId:      pkg.ParticipantID,
				ParticipantName:    participantName,
				SecretShare:        pkg.SecretShare.Value,
				GroupPublicKey:     pubPkg.GroupPublicKey,
				VerificationShares: vsMap,
			}
		}

		return &pb.FrostGenerateKeyResponse{
			KeyId:          keyID,
			Algorithm:      algorithm,
			Threshold:      req.Threshold,
			Total:          req.Total,
			GroupPublicKey: pubPkg.GroupPublicKey,
			Packages:       pbPackages,
			CreatedAt:      timestamppb.Now(),
		}, nil
	}

	// Participant mode: generate and store locally
	participantID := req.ParticipantId
	if participantID == 0 {
		return nil, status.Error(codes.InvalidArgument, "participant_id is required in participant mode (use dealer_mode=true for dealer mode)")
	}

	attrs := &types.KeyAttributes{
		CN:        keyID,
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
		FrostAttributes: &types.FrostAttributes{
			Algorithm:     types.FrostAlgorithm(algorithm),
			Threshold:     int(req.Threshold),
			Total:         int(req.Total),
			Participants:  req.Participants,
			ParticipantID: participantID,
		},
	}

	key, err := be.GenerateKey(attrs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate FROST key: %v", err)
	}

	handle := key.(*frost.FrostKeyHandle)

	return &pb.FrostGenerateKeyResponse{
		KeyId:          keyID,
		Algorithm:      algorithm,
		Threshold:      req.Threshold,
		Total:          req.Total,
		GroupPublicKey: handle.GroupPublicKey,
		ParticipantId:  participantID,
		CreatedAt:      timestamppb.Now(),
	}, nil
}

// FrostImportKey imports a FROST key package
func (s *Service) FrostImportKey(ctx context.Context, req *pb.FrostImportKeyRequest) (*pb.FrostImportKeyResponse, error) {
	if req.Package == nil {
		return nil, status.Error(codes.InvalidArgument, "package is required")
	}

	pkg := req.Package
	if pkg.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "package.key_id is required")
	}
	if len(pkg.SecretShare) == 0 {
		return nil, status.Error(codes.InvalidArgument, "package.secret_share is required")
	}
	if len(pkg.GroupPublicKey) == 0 {
		return nil, status.Error(codes.InvalidArgument, "package.group_public_key is required")
	}

	// Get FROST backend
	be, err := s.getFrostBackend()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get FROST backend: %v", err)
	}

	// Create key package
	keyPackage := &frost.KeyPackage{
		ParticipantID: pkg.ParticipantId,
		SecretShare: &frost.SecretKeyShare{
			Value: pkg.SecretShare,
		},
		GroupPublicKey:     pkg.GroupPublicKey,
		VerificationShares: pkg.VerificationShares,
		MinSigners:         uint32(pkg.Threshold),
		MaxSigners:         uint32(pkg.Total),
		Algorithm:          types.FrostAlgorithm(pkg.Algorithm),
	}

	metadata := &frost.KeyMetadata{
		KeyID:             pkg.KeyId,
		Algorithm:         types.FrostAlgorithm(pkg.Algorithm),
		Threshold:         int(pkg.Threshold),
		Total:             int(pkg.Total),
		ParticipantID:     pkg.ParticipantId,
		CreatedAt:         time.Now().Unix(),
		SecretBackendType: types.BackendTypeSoftware,
	}

	// Store key package via keystore
	ks := be.KeyStore()
	if err := ks.StoreKeyPackage(pkg.KeyId, keyPackage, metadata); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to store key package: %v", err)
	}

	return &pb.FrostImportKeyResponse{
		Success:        true,
		Message:        fmt.Sprintf("key package imported successfully for participant %d", pkg.ParticipantId),
		KeyId:          pkg.KeyId,
		ParticipantId:  pkg.ParticipantId,
		GroupPublicKey: pkg.GroupPublicKey,
	}, nil
}

// FrostListKeys lists all FROST keys
func (s *Service) FrostListKeys(ctx context.Context, req *pb.FrostListKeysRequest) (*pb.FrostListKeysResponse, error) {
	be, err := s.getFrostBackend()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get FROST backend: %v", err)
	}

	keys, err := be.ListKeys()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list keys: %v", err)
	}

	// Apply pagination
	offset := int(req.Offset)
	limit := int(req.Limit)
	if limit == 0 {
		limit = 100
	}

	end := offset + limit
	if end > len(keys) {
		end = len(keys)
	}
	if offset > len(keys) {
		offset = len(keys)
	}

	paginatedKeys := keys[offset:end]

	// Convert to protobuf format
	pbKeys := make([]*pb.FrostKeyInfo, len(paginatedKeys))
	for i, k := range paginatedKeys {
		if k.FrostAttributes != nil {
			// Get key handle to retrieve group public key
			handle, err := be.GetKey(k)
			var groupPubKey []byte
			if err == nil {
				if h, ok := handle.(*frost.FrostKeyHandle); ok {
					groupPubKey = h.GroupPublicKey
				}
			}

			pbKeys[i] = &pb.FrostKeyInfo{
				KeyId:          k.CN,
				Algorithm:      string(k.FrostAttributes.Algorithm),
				Threshold:      int32(k.FrostAttributes.Threshold),
				Total:          int32(k.FrostAttributes.Total),
				ParticipantId:  k.FrostAttributes.ParticipantID,
				GroupPublicKey: groupPubKey,
				Participants:   k.FrostAttributes.Participants,
				CreatedAt:      timestamppb.Now(),
			}
		}
	}

	return &pb.FrostListKeysResponse{
		Keys:  pbKeys,
		Total: int32(len(keys)),
	}, nil
}

// FrostGetKey retrieves information about a specific FROST key
func (s *Service) FrostGetKey(ctx context.Context, req *pb.FrostGetKeyRequest) (*pb.FrostGetKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}

	be, err := s.getFrostBackend()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get FROST backend: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:        req.KeyId,
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
	}

	key, err := be.GetKey(attrs)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "key not found: %v", err)
	}

	handle := key.(*frost.FrostKeyHandle)

	// Get full key list to find metadata
	keys, _ := be.ListKeys()
	var keyInfo *pb.FrostKeyInfo
	for _, k := range keys {
		if k.CN == req.KeyId && k.FrostAttributes != nil {
			keyInfo = &pb.FrostKeyInfo{
				KeyId:          k.CN,
				Algorithm:      string(k.FrostAttributes.Algorithm),
				Threshold:      int32(k.FrostAttributes.Threshold),
				Total:          int32(k.FrostAttributes.Total),
				ParticipantId:  handle.ParticipantID,
				GroupPublicKey: handle.GroupPublicKey,
				Participants:   k.FrostAttributes.Participants,
				CreatedAt:      timestamppb.Now(),
			}
			break
		}
	}

	if keyInfo == nil {
		keyInfo = &pb.FrostKeyInfo{
			KeyId:          req.KeyId,
			Algorithm:      string(handle.Algorithm),
			ParticipantId:  handle.ParticipantID,
			GroupPublicKey: handle.GroupPublicKey,
			CreatedAt:      timestamppb.Now(),
		}
	}

	return &pb.FrostGetKeyResponse{
		Key: keyInfo,
	}, nil
}

// FrostDeleteKey deletes a FROST key
func (s *Service) FrostDeleteKey(ctx context.Context, req *pb.FrostDeleteKeyRequest) (*pb.FrostDeleteKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}

	be, err := s.getFrostBackend()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get FROST backend: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:        req.KeyId,
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
	}

	if err := be.DeleteKey(attrs); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete key: %v", err)
	}

	return &pb.FrostDeleteKeyResponse{
		Success: true,
		Message: fmt.Sprintf("key %s deleted successfully", req.KeyId),
	}, nil
}

// FrostGenerateNonces generates nonces and commitments for Round 1
func (s *Service) FrostGenerateNonces(ctx context.Context, req *pb.FrostGenerateNoncesRequest) (*pb.FrostGenerateNoncesResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}

	be, err := s.getFrostBackend()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get FROST backend: %v", err)
	}

	noncePackage, err := be.GenerateNonces(req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate nonces: %v", err)
	}

	return &pb.FrostGenerateNoncesResponse{
		ParticipantId:     noncePackage.ParticipantID,
		SessionId:         noncePackage.SessionID,
		HidingNonce:       noncePackage.Nonces.HidingNonce,
		BindingNonce:      noncePackage.Nonces.BindingNonce,
		HidingCommitment:  noncePackage.Commitments.HidingCommitment,
		BindingCommitment: noncePackage.Commitments.BindingCommitment,
	}, nil
}

// FrostSignRound generates a signature share for Round 2
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

	be, err := s.getFrostBackend()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get FROST backend: %v", err)
	}

	// Get key to find participant ID
	attrs := &types.KeyAttributes{
		CN:        req.KeyId,
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
	}
	key, err := be.GetKey(attrs)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "key not found: %v", err)
	}
	handle := key.(*frost.FrostKeyHandle)

	// Build nonce package
	noncePackage := &frost.NoncePackage{
		ParticipantID: handle.ParticipantID,
		SessionID:     req.SessionId,
		Nonces: &frost.SigningNonces{
			HidingNonce:  req.HidingNonce,
			BindingNonce: req.BindingNonce,
		},
		Commitments: &frost.SigningCommitments{
			ParticipantID:     handle.ParticipantID,
			HidingCommitment:  req.HidingCommitment,
			BindingCommitment: req.BindingCommitment,
		},
	}

	// Build commitments list
	commitments := make([]*frost.Commitment, len(req.Commitments))
	for i, c := range req.Commitments {
		commitments[i] = &frost.Commitment{
			ParticipantID: c.ParticipantId,
			Commitments: &frost.SigningCommitments{
				ParticipantID:     c.ParticipantId,
				HidingCommitment:  c.HidingCommitment,
				BindingCommitment: c.BindingCommitment,
			},
		}
	}

	share, err := be.SignRound(req.KeyId, req.Message, noncePackage, commitments)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate signature share: %v", err)
	}

	return &pb.FrostSignRoundResponse{
		ParticipantId:  share.ParticipantID,
		SessionId:      share.SessionID,
		SignatureShare: share.Share,
	}, nil
}

// FrostAggregate combines signature shares into a final FROST signature
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

	be, err := s.getFrostBackend()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get FROST backend: %v", err)
	}

	// Build commitments list
	commitments := make([]*frost.Commitment, len(req.Commitments))
	for i, c := range req.Commitments {
		commitments[i] = &frost.Commitment{
			ParticipantID: c.ParticipantId,
			Commitments: &frost.SigningCommitments{
				ParticipantID:     c.ParticipantId,
				HidingCommitment:  c.HidingCommitment,
				BindingCommitment: c.BindingCommitment,
			},
		}
	}

	// Build shares list
	shares := make([]*frost.SignatureShare, len(req.Shares))
	for i, s := range req.Shares {
		shares[i] = &frost.SignatureShare{
			ParticipantID: s.ParticipantId,
			SessionID:     s.SessionId,
			Share:         s.Share,
		}
	}

	signature, err := be.Aggregate(req.KeyId, req.Message, commitments, shares)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to aggregate signatures: %v", err)
	}

	// Verify if requested
	verified := false
	if req.Verify {
		if err := be.Verify(req.KeyId, req.Message, signature); err == nil {
			verified = true
		}
	}

	return &pb.FrostAggregateResponse{
		Signature: signature,
		Verified:  verified,
	}, nil
}

// FrostVerify verifies a FROST signature against the group public key
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

	be, err := s.getFrostBackend()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get FROST backend: %v", err)
	}

	if err := be.Verify(req.KeyId, req.Message, req.Signature); err != nil {
		return &pb.FrostVerifyResponse{
			Valid:   false,
			Message: fmt.Sprintf("signature verification failed: %v", err),
		}, nil
	}

	return &pb.FrostVerifyResponse{
		Valid:   true,
		Message: "signature is valid",
	}, nil
}

// getFrostBackend retrieves the FROST backend from the keychain service
func (s *Service) getFrostBackend() (*frost.FrostBackend, error) {
	// Try to get a FROST backend from registered backends
	backends := keychain.Backends()
	for _, name := range backends {
		ks, err := keychain.Backend(name)
		if err != nil {
			continue
		}
		backend := ks.Backend()
		if backend.Type() == types.BackendTypeFrost {
			if fb, ok := backend.(*frost.FrostBackend); ok {
				return fb, nil
			}
		}
	}

	return nil, fmt.Errorf("no FROST backend configured")
}
