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

	"github.com/jeremyhahn/go-xkms/pkg/api/grpc/pbconv"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// The crypto utility handlers authorize, scope the request to the caller's
// tenant and hand it to the service; keyVersionCall maps the service's
// errors to gRPC codes.

// Rewrap implements KeystoreService.Rewrap. It is gated on keys:decrypt,
// as on every transport: the caller who may read the plaintext may also
// have it encrypted under another key of its tenant.
func (s *Service) Rewrap(ctx context.Context, req *pb.RewrapRequest) (*pb.RewrapResponse, error) {
	in := pbconv.RewrapRequestFromProto(req)
	if in.Source == nil {
		in.Source = &transport.DecryptRequest{}
	}
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionDecrypt, in.Source.KeyID); err != nil {
		return nil, err
	}
	in.Source.TenantID = callerTenantID(ctx)
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.RewrapResponse, error) {
		resp, err := x.Rewrap(ctx, in)
		if err != nil {
			return nil, err
		}
		return pbconv.RewrapResponseToProto(resp), nil
	})
}

// EncryptBatch implements KeystoreService.EncryptBatch.
func (s *Service) EncryptBatch(ctx context.Context, req *pb.EncryptBatchRequest) (*pb.EncryptBatchResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionEncrypt, req.GetKeyId()); err != nil {
		return nil, err
	}
	in := pbconv.EncryptBatchRequestFromProto(req)
	in.TenantID = callerTenantID(ctx)
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.EncryptBatchResponse, error) {
		resp, err := x.EncryptBatch(ctx, in)
		if err != nil {
			return nil, err
		}
		return pbconv.EncryptBatchResponseToProto(resp), nil
	})
}

// DecryptBatch implements KeystoreService.DecryptBatch.
func (s *Service) DecryptBatch(ctx context.Context, req *pb.DecryptBatchRequest) (*pb.DecryptBatchResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionDecrypt, req.GetKeyId()); err != nil {
		return nil, err
	}
	in := pbconv.DecryptBatchRequestFromProto(req)
	in.TenantID = callerTenantID(ctx)
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.DecryptBatchResponse, error) {
		resp, err := x.DecryptBatch(ctx, in)
		if err != nil {
			return nil, err
		}
		return pbconv.DecryptBatchResponseToProto(resp), nil
	})
}

// GenerateDataKey implements KeystoreService.GenerateDataKey.
func (s *Service) GenerateDataKey(ctx context.Context, req *pb.GenerateDataKeyRequest) (*pb.GenerateDataKeyResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionEncrypt, req.GetKeyId()); err != nil {
		return nil, err
	}
	in := pbconv.GenerateDataKeyRequestFromProto(req)
	in.TenantID = callerTenantID(ctx)
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.GenerateDataKeyResponse, error) {
		resp, err := x.GenerateDataKey(ctx, in)
		if err != nil {
			return nil, err
		}
		return &pb.GenerateDataKeyResponse{Plaintext: resp.Plaintext, Wrapped: pbconv.EncryptResponseToProto(resp.Wrapped)}, nil
	})
}

// GenerateWrappedDataKey implements KeystoreService.GenerateWrappedDataKey.
func (s *Service) GenerateWrappedDataKey(ctx context.Context, req *pb.GenerateDataKeyRequest) (*pb.GenerateWrappedDataKeyResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionEncrypt, req.GetKeyId()); err != nil {
		return nil, err
	}
	in := pbconv.GenerateDataKeyRequestFromProto(req)
	in.TenantID = callerTenantID(ctx)
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.GenerateWrappedDataKeyResponse, error) {
		resp, err := x.GenerateWrappedDataKey(ctx, in)
		if err != nil {
			return nil, err
		}
		return &pb.GenerateWrappedDataKeyResponse{Wrapped: pbconv.EncryptResponseToProto(resp.Wrapped)}, nil
	})
}

// GenerateHMAC implements KeystoreService.GenerateHMAC.
func (s *Service) GenerateHMAC(ctx context.Context, req *pb.GenerateHMACRequest) (*pb.GenerateHMACResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionSign, req.GetKeyId()); err != nil {
		return nil, err
	}
	in := pbconv.GenerateHMACRequestFromProto(req)
	in.TenantID = callerTenantID(ctx)
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.GenerateHMACResponse, error) {
		resp, err := x.GenerateHMAC(ctx, in)
		if err != nil {
			return nil, err
		}
		return &pb.GenerateHMACResponse{Mac: resp.MAC, KeyVersion: resp.KeyVersion, Hash: resp.Hash}, nil
	})
}

// VerifyHMAC implements KeystoreService.VerifyHMAC.
func (s *Service) VerifyHMAC(ctx context.Context, req *pb.VerifyHMACRequest) (*pb.VerifyHMACResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionVerify, req.GetKeyId()); err != nil {
		return nil, err
	}
	in := pbconv.VerifyHMACRequestFromProto(req)
	in.TenantID = callerTenantID(ctx)
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.VerifyHMACResponse, error) {
		resp, err := x.VerifyHMAC(ctx, in)
		if err != nil {
			return nil, err
		}
		return &pb.VerifyHMACResponse{Valid: resp.Valid, KeyVersion: resp.KeyVersion}, nil
	})
}

// GenerateRandom implements KeystoreService.GenerateRandom.
func (s *Service) GenerateRandom(ctx context.Context, req *pb.GenerateRandomRequest) (*pb.GenerateRandomResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionVerify, ""); err != nil {
		return nil, err
	}
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.GenerateRandomResponse, error) {
		resp, err := x.GenerateRandom(ctx, &transport.GenerateRandomRequest{Length: int(req.GetLength())})
		if err != nil {
			return nil, err
		}
		return &pb.GenerateRandomResponse{Random: resp.Random}, nil
	})
}

// Hash implements KeystoreService.Hash.
func (s *Service) Hash(ctx context.Context, req *pb.HashRequest) (*pb.HashResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionVerify, ""); err != nil {
		return nil, err
	}
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.HashResponse, error) {
		resp, err := x.Hash(ctx, &transport.HashRequest{Data: req.GetData(), Hash: req.GetHash()})
		if err != nil {
			return nil, err
		}
		return &pb.HashResponse{Digest: resp.Digest, Hash: resp.Hash}, nil
	})
}
