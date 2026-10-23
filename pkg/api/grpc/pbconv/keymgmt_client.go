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

// KeyManagementClient implements transport.KeyManagementService over a
// generated KeystoreService client, for the gRPC and unix-socket transports.
type KeyManagementClient struct {
	// Client is the connected generated client.
	Client pb.KeystoreServiceClient
}

var _ transport.KeyManagementService = KeyManagementClient{}

// GetPublicKey calls KeystoreService.GetPublicKey.
func (c KeyManagementClient) GetPublicKey(ctx context.Context, req *transport.GetPublicKeyRequest) (*transport.GetPublicKeyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.GetPublicKey(ctx, &pb.GetPublicKeyRequest{KeyId: req.KeyID, Version: req.Version, Backend: req.Backend})
	if err != nil {
		return nil, err
	}
	return &transport.GetPublicKeyResponse{
		KeyID:     resp.GetKeyId(),
		PublicKey: resp.GetPublicKey(),
		Algorithm: KeyAlgorithmFromProto(resp.GetAlgorithm()),
		Version:   resp.GetVersion(),
		Timestamp: resp.GetTimestamp(),
	}, nil
}

// RevokeKey calls KeystoreService.RevokeKey.
func (c KeyManagementClient) RevokeKey(ctx context.Context, req *transport.RevokeKeyRequest) (*transport.RevokeKeyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.RevokeKey(ctx, &pb.RevokeKeyRequest{KeyId: req.KeyID, Reason: req.Reason, Backend: req.Backend})
	if err != nil {
		return nil, err
	}
	return &transport.RevokeKeyResponse{
		KeyID:     resp.GetKeyId(),
		Status:    KeyStatusFromProto(resp.GetStatus()),
		Timestamp: resp.GetTimestamp(),
	}, nil
}

// UpdateKeyStatus calls KeystoreService.UpdateKeyStatus.
func (c KeyManagementClient) UpdateKeyStatus(ctx context.Context, req *transport.UpdateKeyStatusRequest) (*transport.UpdateKeyStatusResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.UpdateKeyStatus(ctx, &pb.UpdateKeyStatusRequest{
		KeyId:   req.KeyID,
		Version: req.Version,
		Status:  KeyStatusToProto(req.Status),
		Backend: req.Backend,
	})
	if err != nil {
		return nil, err
	}
	return &transport.UpdateKeyStatusResponse{
		KeyID:     resp.GetKeyId(),
		Version:   resp.GetVersion(),
		Status:    KeyStatusFromProto(resp.GetStatus()),
		Timestamp: resp.GetTimestamp(),
	}, nil
}

// GetKeyMetadata calls KeystoreService.GetKeyMetadata.
func (c KeyManagementClient) GetKeyMetadata(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyMetadataResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.GetKeyMetadata(ctx, &pb.GetKeyMetadataRequest{KeyId: req.KeyID, Backend: req.Backend})
	if err != nil {
		return nil, err
	}
	return &transport.KeyMetadataResponse{Metadata: KeyMetadataFromProto(resp.GetMetadata()), Timestamp: resp.GetTimestamp()}, nil
}

// UpdateKeyMetadata calls KeystoreService.UpdateKeyMetadata.
func (c KeyManagementClient) UpdateKeyMetadata(ctx context.Context, req *transport.UpdateKeyMetadataRequest) (*transport.KeyMetadataResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.UpdateKeyMetadata(ctx, UpdateKeyMetadataRequestToProto(req))
	if err != nil {
		return nil, err
	}
	return &transport.KeyMetadataResponse{Metadata: KeyMetadataFromProto(resp.GetMetadata()), Timestamp: resp.GetTimestamp()}, nil
}

// SetKeyPolicy calls KeystoreService.SetKeyPolicy.
func (c KeyManagementClient) SetKeyPolicy(ctx context.Context, req *transport.SetKeyPolicyRequest) (*transport.SetKeyPolicyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.SetKeyPolicy(ctx, &pb.SetKeyPolicyRequest{KeyId: req.KeyID, Policy: KeyPolicyToProto(req.Policy), Backend: req.Backend})
	if err != nil {
		return nil, err
	}
	return &transport.SetKeyPolicyResponse{KeyID: resp.GetKeyId(), PolicyVersion: resp.GetPolicyVersion(), Timestamp: resp.GetTimestamp()}, nil
}

// GetKeyPolicy calls KeystoreService.GetKeyPolicy.
func (c KeyManagementClient) GetKeyPolicy(ctx context.Context, req *transport.KeyManagementRequest) (*transport.GetKeyPolicyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.GetKeyPolicy(ctx, &pb.GetKeyPolicyRequest{KeyId: req.KeyID, Backend: req.Backend})
	if err != nil {
		return nil, err
	}
	return &transport.GetKeyPolicyResponse{Policy: KeyPolicyFromProto(resp.GetPolicy()), Timestamp: resp.GetTimestamp()}, nil
}

// DeleteKeyPolicy calls KeystoreService.DeleteKeyPolicy.
func (c KeyManagementClient) DeleteKeyPolicy(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.DeleteKeyPolicy(ctx, &pb.DeleteKeyPolicyRequest{KeyId: req.KeyID, Backend: req.Backend})
	if err != nil {
		return nil, err
	}
	return &transport.KeyManagementResponse{KeyID: resp.GetKeyId(), Timestamp: resp.GetTimestamp()}, nil
}

// SetKeyRotationPolicy calls KeystoreService.SetKeyRotationPolicy.
func (c KeyManagementClient) SetKeyRotationPolicy(ctx context.Context, req *transport.SetKeyRotationPolicyRequest) (*transport.KeyRotationPolicyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.SetKeyRotationPolicy(ctx, &pb.SetKeyRotationPolicyRequest{
		KeyId:   req.KeyID,
		Policy:  RotationPolicyToProto(req.Policy),
		Backend: req.Backend,
	})
	if err != nil {
		return nil, err
	}
	return &transport.KeyRotationPolicyResponse{
		KeyID:     resp.GetKeyId(),
		Policy:    RotationPolicyFromProto(resp.GetPolicy()),
		Timestamp: resp.GetTimestamp(),
	}, nil
}

// GetKeyRotationPolicy calls KeystoreService.GetKeyRotationPolicy.
func (c KeyManagementClient) GetKeyRotationPolicy(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyRotationPolicyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.GetKeyRotationPolicy(ctx, &pb.GetKeyRotationPolicyRequest{KeyId: req.KeyID, Backend: req.Backend})
	if err != nil {
		return nil, err
	}
	return &transport.KeyRotationPolicyResponse{
		KeyID:     resp.GetKeyId(),
		Policy:    RotationPolicyFromProto(resp.GetPolicy()),
		Timestamp: resp.GetTimestamp(),
	}, nil
}

// DeleteKeyRotationPolicy calls KeystoreService.DeleteKeyRotationPolicy.
func (c KeyManagementClient) DeleteKeyRotationPolicy(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.DeleteKeyRotationPolicy(ctx, &pb.DeleteKeyRotationPolicyRequest{KeyId: req.KeyID, Backend: req.Backend})
	if err != nil {
		return nil, err
	}
	return &transport.KeyManagementResponse{KeyID: resp.GetKeyId(), Timestamp: resp.GetTimestamp()}, nil
}

// GetSupportedAlgorithms calls KeystoreService.GetSupportedAlgorithms.
func (c KeyManagementClient) GetSupportedAlgorithms(ctx context.Context, req *transport.BackendRequest) (*transport.GetSupportedAlgorithmsResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.GetSupportedAlgorithms(ctx, &pb.GetSupportedAlgorithmsRequest{Backend: req.Backend})
	if err != nil {
		return nil, err
	}
	return &transport.GetSupportedAlgorithmsResponse{Algorithms: KeyAlgorithmNamesFromProto(resp.GetAlgorithms())}, nil
}

// BackendStatus calls KeystoreService.BackendStatus.
func (c KeyManagementClient) BackendStatus(ctx context.Context, req *transport.BackendRequest) (*transport.BackendStatusResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.BackendStatus(ctx, &pb.BackendStatusRequest{Backend: req.Backend})
	if err != nil {
		return nil, err
	}
	return BackendStatusResponseFromProto(resp), nil
}

// BackendTest calls KeystoreService.BackendTest.
func (c KeyManagementClient) BackendTest(ctx context.Context, req *transport.BackendRequest) (*transport.BackendTestResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.BackendTest(ctx, &pb.BackendTestRequest{Backend: req.Backend})
	if err != nil {
		return nil, err
	}
	return &transport.BackendTestResponse{
		Success:    resp.GetSuccess(),
		DurationMS: resp.GetDurationMs(),
		Message:    resp.GetMessage(),
		Timestamp:  resp.GetTimestamp(),
	}, nil
}

// SetKeySafety calls KeystoreService.SetKeySafety.
func (c KeyManagementClient) SetKeySafety(ctx context.Context, req *transport.SetKeySafetyRequest) (*transport.KeyManagementResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.SetKeySafety(ctx, &pb.SetKeySafetyRequest{
		KeyId:          req.KeyID,
		MaxOperations:  req.MaxOperations,
		MaxBytes:       req.MaxBytes,
		WarningPercent: req.WarningPercent,
		Backend:        req.Backend,
	})
	if err != nil {
		return nil, err
	}
	return &transport.KeyManagementResponse{KeyID: resp.GetKeyId(), Timestamp: resp.GetTimestamp()}, nil
}

// ClearKeySafety calls KeystoreService.ClearKeySafety.
func (c KeyManagementClient) ClearKeySafety(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.ClearKeySafety(ctx, &pb.ClearKeySafetyRequest{KeyId: req.KeyID, Backend: req.Backend})
	if err != nil {
		return nil, err
	}
	return &transport.KeyManagementResponse{KeyID: resp.GetKeyId(), Timestamp: resp.GetTimestamp()}, nil
}

// SafetyCheck calls KeystoreService.SafetyCheck.
func (c KeyManagementClient) SafetyCheck(ctx context.Context, req *transport.SafetyCheckRequest) (*transport.SafetyCheckResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.SafetyCheck(ctx, &pb.SafetyCheckRequest{})
	if err != nil {
		return nil, err
	}
	return &transport.SafetyCheckResponse{Warnings: SafetyWarningsFromProto(resp.GetWarnings()), Timestamp: resp.GetTimestamp()}, nil
}

// SafetyReport calls KeystoreService.SafetyReport.
func (c KeyManagementClient) SafetyReport(ctx context.Context, req *transport.SafetyReportRequest) (*transport.SafetyReportResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.SafetyReport(ctx, &pb.SafetyReportRequest{Format: req.Format})
	if err != nil {
		return nil, err
	}
	return SafetyReportResponseFromProto(resp), nil
}
