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

//go:build !frost

package grpc

import (
	"context"

	pb "github.com/jeremyhahn/go-keychain/api/proto/keychainv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var errFrostNotCompiled = status.Error(codes.Unimplemented, "FROST support not compiled - rebuild with '-tags frost'")

// FrostGenerateKey generates FROST key packages using trusted dealer model
func (s *Service) FrostGenerateKey(ctx context.Context, req *pb.FrostGenerateKeyRequest) (*pb.FrostGenerateKeyResponse, error) {
	return nil, errFrostNotCompiled
}

// FrostImportKey imports a FROST key package
func (s *Service) FrostImportKey(ctx context.Context, req *pb.FrostImportKeyRequest) (*pb.FrostImportKeyResponse, error) {
	return nil, errFrostNotCompiled
}

// FrostListKeys lists all FROST keys
func (s *Service) FrostListKeys(ctx context.Context, req *pb.FrostListKeysRequest) (*pb.FrostListKeysResponse, error) {
	return nil, errFrostNotCompiled
}

// FrostGetKey retrieves information about a specific FROST key
func (s *Service) FrostGetKey(ctx context.Context, req *pb.FrostGetKeyRequest) (*pb.FrostGetKeyResponse, error) {
	return nil, errFrostNotCompiled
}

// FrostDeleteKey deletes a FROST key
func (s *Service) FrostDeleteKey(ctx context.Context, req *pb.FrostDeleteKeyRequest) (*pb.FrostDeleteKeyResponse, error) {
	return nil, errFrostNotCompiled
}

// FrostGenerateNonces generates nonces and commitments for Round 1
func (s *Service) FrostGenerateNonces(ctx context.Context, req *pb.FrostGenerateNoncesRequest) (*pb.FrostGenerateNoncesResponse, error) {
	return nil, errFrostNotCompiled
}

// FrostSignRound generates a signature share for Round 2
func (s *Service) FrostSignRound(ctx context.Context, req *pb.FrostSignRoundRequest) (*pb.FrostSignRoundResponse, error) {
	return nil, errFrostNotCompiled
}

// FrostAggregate combines signature shares into a final FROST signature
func (s *Service) FrostAggregate(ctx context.Context, req *pb.FrostAggregateRequest) (*pb.FrostAggregateResponse, error) {
	return nil, errFrostNotCompiled
}

// FrostVerify verifies a FROST signature against the group public key
func (s *Service) FrostVerify(ctx context.Context, req *pb.FrostVerifyRequest) (*pb.FrostVerifyResponse, error) {
	return nil, errFrostNotCompiled
}
