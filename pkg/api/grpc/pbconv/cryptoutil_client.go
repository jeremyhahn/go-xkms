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

package pbconv

import (
	"context"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// CryptoUtilityClient implements transport.CryptoUtilityService over a
// generated KeystoreService client, for the gRPC and unix-socket transports.
type CryptoUtilityClient struct {
	// Client is the connected generated client.
	Client pb.KeystoreServiceClient
}

var _ transport.CryptoUtilityService = CryptoUtilityClient{}

// Rewrap calls KeystoreService.Rewrap.
func (c CryptoUtilityClient) Rewrap(ctx context.Context, req *transport.RewrapRequest) (*transport.RewrapResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.Rewrap(ctx, RewrapRequestToProto(req))
	if err != nil {
		return nil, err
	}
	return RewrapResponseFromProto(resp), nil
}

// EncryptBatch calls KeystoreService.EncryptBatch.
func (c CryptoUtilityClient) EncryptBatch(ctx context.Context, req *transport.EncryptBatchRequest) (*transport.EncryptBatchResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.EncryptBatch(ctx, EncryptBatchRequestToProto(req))
	if err != nil {
		return nil, err
	}
	return EncryptBatchResponseFromProto(resp), nil
}

// DecryptBatch calls KeystoreService.DecryptBatch.
func (c CryptoUtilityClient) DecryptBatch(ctx context.Context, req *transport.DecryptBatchRequest) (*transport.DecryptBatchResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.DecryptBatch(ctx, DecryptBatchRequestToProto(req))
	if err != nil {
		return nil, err
	}
	return DecryptBatchResponseFromProto(resp), nil
}

// GenerateDataKey calls KeystoreService.GenerateDataKey.
func (c CryptoUtilityClient) GenerateDataKey(ctx context.Context, req *transport.GenerateDataKeyRequest) (*transport.GenerateDataKeyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.GenerateDataKey(ctx, GenerateDataKeyRequestToProto(req))
	if err != nil {
		return nil, err
	}
	return &transport.GenerateDataKeyResponse{
		Plaintext: resp.GetPlaintext(),
		Wrapped:   EncryptResponseFromProto(resp.GetWrapped()),
	}, nil
}

// GenerateWrappedDataKey calls KeystoreService.GenerateWrappedDataKey.
func (c CryptoUtilityClient) GenerateWrappedDataKey(ctx context.Context, req *transport.GenerateDataKeyRequest) (*transport.GenerateWrappedDataKeyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.GenerateWrappedDataKey(ctx, GenerateDataKeyRequestToProto(req))
	if err != nil {
		return nil, err
	}
	return &transport.GenerateWrappedDataKeyResponse{Wrapped: EncryptResponseFromProto(resp.GetWrapped())}, nil
}

// GenerateHMAC calls KeystoreService.GenerateHMAC.
func (c CryptoUtilityClient) GenerateHMAC(ctx context.Context, req *transport.GenerateHMACRequest) (*transport.GenerateHMACResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.GenerateHMAC(ctx, GenerateHMACRequestToProto(req))
	if err != nil {
		return nil, err
	}
	return &transport.GenerateHMACResponse{MAC: resp.GetMac(), KeyVersion: resp.GetKeyVersion(), Hash: resp.GetHash()}, nil
}

// VerifyHMAC calls KeystoreService.VerifyHMAC.
func (c CryptoUtilityClient) VerifyHMAC(ctx context.Context, req *transport.VerifyHMACRequest) (*transport.VerifyHMACResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.VerifyHMAC(ctx, VerifyHMACRequestToProto(req))
	if err != nil {
		return nil, err
	}
	return &transport.VerifyHMACResponse{Valid: resp.GetValid(), KeyVersion: resp.GetKeyVersion()}, nil
}

// GenerateRandom calls KeystoreService.GenerateRandom.
func (c CryptoUtilityClient) GenerateRandom(ctx context.Context, req *transport.GenerateRandomRequest) (*transport.GenerateRandomResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.GenerateRandom(ctx, &pb.GenerateRandomRequest{Length: int32(req.Length)})
	if err != nil {
		return nil, err
	}
	return &transport.GenerateRandomResponse{Random: resp.GetRandom()}, nil
}

// Hash calls KeystoreService.Hash.
func (c CryptoUtilityClient) Hash(ctx context.Context, req *transport.HashRequest) (*transport.HashResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.Hash(ctx, &pb.HashRequest{Data: req.Data, Hash: req.Hash})
	if err != nil {
		return nil, err
	}
	return &transport.HashResponse{Digest: resp.GetDigest(), Hash: resp.GetHash()}, nil
}
