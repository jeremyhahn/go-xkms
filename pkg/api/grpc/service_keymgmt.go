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

// The key management handlers authorize, scope the request to the caller's
// tenant and hand it to the service; keyVersionCall maps the service's
// errors to gRPC codes. RBAC always applies: a key's policy only narrows
// what the permission grants.

// keyRequest returns the key-scoped request of keyID in backend, scoped to
// the caller's tenant.
func keyRequest(ctx context.Context, backend, keyID string) *transport.KeyManagementRequest {
	return &transport.KeyManagementRequest{Backend: backend, KeyID: keyID, TenantID: callerTenantID(ctx)}
}

// backendRequest returns the request of backend, scoped to the caller's
// tenant.
func backendRequest(ctx context.Context, backend string) *transport.BackendRequest {
	return &transport.BackendRequest{Backend: backend, TenantID: callerTenantID(ctx)}
}

// GetPublicKey implements KeystoreService.GetPublicKey.
func (s *Service) GetPublicKey(ctx context.Context, req *pb.GetPublicKeyRequest) (*pb.GetPublicKeyResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionGet, req.GetKeyId()); err != nil {
		return nil, err
	}
	in := &transport.GetPublicKeyRequest{Backend: req.GetBackend(), KeyID: req.GetKeyId(), Version: req.GetVersion(), TenantID: callerTenantID(ctx)}
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.GetPublicKeyResponse, error) {
		resp, err := x.GetPublicKey(ctx, in)
		if err != nil {
			return nil, err
		}
		return &pb.GetPublicKeyResponse{
			KeyId:     resp.KeyID,
			PublicKey: resp.PublicKey,
			Algorithm: pbconv.KeyAlgorithmToProto(resp.Algorithm),
			Version:   resp.Version,
			Timestamp: resp.Timestamp,
		}, nil
	})
}

// RevokeKey implements KeystoreService.RevokeKey.
func (s *Service) RevokeKey(ctx context.Context, req *pb.RevokeKeyRequest) (*pb.RevokeKeyResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionDelete, req.GetKeyId()); err != nil {
		return nil, err
	}
	in := &transport.RevokeKeyRequest{Backend: req.GetBackend(), KeyID: req.GetKeyId(), Reason: req.GetReason(), TenantID: callerTenantID(ctx)}
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.RevokeKeyResponse, error) {
		resp, err := x.RevokeKey(ctx, in)
		if err != nil {
			return nil, err
		}
		return &pb.RevokeKeyResponse{KeyId: resp.KeyID, Status: pbconv.KeyStatusToProto(resp.Status), Timestamp: resp.Timestamp}, nil
	})
}

// UpdateKeyStatus implements KeystoreService.UpdateKeyStatus.
func (s *Service) UpdateKeyStatus(ctx context.Context, req *pb.UpdateKeyStatusRequest) (*pb.UpdateKeyStatusResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionRotate, req.GetKeyId()); err != nil {
		return nil, err
	}
	in := &transport.UpdateKeyStatusRequest{
		Backend:  req.GetBackend(),
		KeyID:    req.GetKeyId(),
		Version:  req.GetVersion(),
		Status:   pbconv.KeyStatusFromProto(req.GetStatus()),
		TenantID: callerTenantID(ctx),
	}
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.UpdateKeyStatusResponse, error) {
		resp, err := x.UpdateKeyStatus(ctx, in)
		if err != nil {
			return nil, err
		}
		return &pb.UpdateKeyStatusResponse{
			KeyId:     resp.KeyID,
			Version:   resp.Version,
			Status:    pbconv.KeyStatusToProto(resp.Status),
			Timestamp: resp.Timestamp,
		}, nil
	})
}

// GetKeyMetadata implements KeystoreService.GetKeyMetadata.
func (s *Service) GetKeyMetadata(ctx context.Context, req *pb.GetKeyMetadataRequest) (*pb.GetKeyMetadataResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionGet, req.GetKeyId()); err != nil {
		return nil, err
	}
	in := keyRequest(ctx, req.GetBackend(), req.GetKeyId())
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.GetKeyMetadataResponse, error) {
		resp, err := x.GetKeyMetadata(ctx, in)
		if err != nil {
			return nil, err
		}
		return &pb.GetKeyMetadataResponse{Metadata: pbconv.KeyMetadataToProto(resp.Metadata), Timestamp: resp.Timestamp}, nil
	})
}

// UpdateKeyMetadata implements KeystoreService.UpdateKeyMetadata.
func (s *Service) UpdateKeyMetadata(ctx context.Context, req *pb.UpdateKeyMetadataRequest) (*pb.UpdateKeyMetadataResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionRotate, req.GetKeyId()); err != nil {
		return nil, err
	}
	in := pbconv.UpdateKeyMetadataRequestFromProto(req)
	in.TenantID = callerTenantID(ctx)
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.UpdateKeyMetadataResponse, error) {
		resp, err := x.UpdateKeyMetadata(ctx, in)
		if err != nil {
			return nil, err
		}
		return &pb.UpdateKeyMetadataResponse{Metadata: pbconv.KeyMetadataToProto(resp.Metadata), Timestamp: resp.Timestamp}, nil
	})
}

// SetKeyPolicy implements KeystoreService.SetKeyPolicy.
func (s *Service) SetKeyPolicy(ctx context.Context, req *pb.SetKeyPolicyRequest) (*pb.SetKeyPolicyResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionRotate, req.GetKeyId()); err != nil {
		return nil, err
	}
	in := &transport.SetKeyPolicyRequest{
		Backend:  req.GetBackend(),
		KeyID:    req.GetKeyId(),
		Policy:   pbconv.KeyPolicyFromProto(req.GetPolicy()),
		TenantID: callerTenantID(ctx),
	}
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.SetKeyPolicyResponse, error) {
		resp, err := x.SetKeyPolicy(ctx, in)
		if err != nil {
			return nil, err
		}
		return &pb.SetKeyPolicyResponse{KeyId: resp.KeyID, PolicyVersion: resp.PolicyVersion, Timestamp: resp.Timestamp}, nil
	})
}

// GetKeyPolicy implements KeystoreService.GetKeyPolicy.
func (s *Service) GetKeyPolicy(ctx context.Context, req *pb.GetKeyPolicyRequest) (*pb.GetKeyPolicyResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionGet, req.GetKeyId()); err != nil {
		return nil, err
	}
	in := keyRequest(ctx, req.GetBackend(), req.GetKeyId())
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.GetKeyPolicyResponse, error) {
		resp, err := x.GetKeyPolicy(ctx, in)
		if err != nil {
			return nil, err
		}
		return &pb.GetKeyPolicyResponse{Policy: pbconv.KeyPolicyToProto(resp.Policy), Timestamp: resp.Timestamp}, nil
	})
}

// DeleteKeyPolicy implements KeystoreService.DeleteKeyPolicy. The key falls
// back to RBAC alone.
func (s *Service) DeleteKeyPolicy(ctx context.Context, req *pb.DeleteKeyPolicyRequest) (*pb.DeleteKeyPolicyResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionDelete, req.GetKeyId()); err != nil {
		return nil, err
	}
	in := keyRequest(ctx, req.GetBackend(), req.GetKeyId())
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.DeleteKeyPolicyResponse, error) {
		resp, err := x.DeleteKeyPolicy(ctx, in)
		if err != nil {
			return nil, err
		}
		return &pb.DeleteKeyPolicyResponse{KeyId: resp.KeyID, Timestamp: resp.Timestamp}, nil
	})
}

// SetKeyRotationPolicy implements KeystoreService.SetKeyRotationPolicy.
func (s *Service) SetKeyRotationPolicy(ctx context.Context, req *pb.SetKeyRotationPolicyRequest) (*pb.SetKeyRotationPolicyResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionRotate, req.GetKeyId()); err != nil {
		return nil, err
	}
	in := &transport.SetKeyRotationPolicyRequest{
		Backend:  req.GetBackend(),
		KeyID:    req.GetKeyId(),
		Policy:   pbconv.RotationPolicyFromProto(req.GetPolicy()),
		TenantID: callerTenantID(ctx),
	}
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.SetKeyRotationPolicyResponse, error) {
		resp, err := x.SetKeyRotationPolicy(ctx, in)
		if err != nil {
			return nil, err
		}
		return &pb.SetKeyRotationPolicyResponse{KeyId: resp.KeyID, Policy: pbconv.RotationPolicyToProto(resp.Policy), Timestamp: resp.Timestamp}, nil
	})
}

// GetKeyRotationPolicy implements KeystoreService.GetKeyRotationPolicy.
func (s *Service) GetKeyRotationPolicy(ctx context.Context, req *pb.GetKeyRotationPolicyRequest) (*pb.GetKeyRotationPolicyResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionGet, req.GetKeyId()); err != nil {
		return nil, err
	}
	in := keyRequest(ctx, req.GetBackend(), req.GetKeyId())
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.GetKeyRotationPolicyResponse, error) {
		resp, err := x.GetKeyRotationPolicy(ctx, in)
		if err != nil {
			return nil, err
		}
		return &pb.GetKeyRotationPolicyResponse{KeyId: resp.KeyID, Policy: pbconv.RotationPolicyToProto(resp.Policy), Timestamp: resp.Timestamp}, nil
	})
}

// DeleteKeyRotationPolicy implements KeystoreService.DeleteKeyRotationPolicy.
func (s *Service) DeleteKeyRotationPolicy(ctx context.Context, req *pb.DeleteKeyRotationPolicyRequest) (*pb.DeleteKeyRotationPolicyResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionDelete, req.GetKeyId()); err != nil {
		return nil, err
	}
	in := keyRequest(ctx, req.GetBackend(), req.GetKeyId())
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.DeleteKeyRotationPolicyResponse, error) {
		resp, err := x.DeleteKeyRotationPolicy(ctx, in)
		if err != nil {
			return nil, err
		}
		return &pb.DeleteKeyRotationPolicyResponse{KeyId: resp.KeyID, Timestamp: resp.Timestamp}, nil
	})
}

// GetSupportedAlgorithms implements KeystoreService.GetSupportedAlgorithms.
func (s *Service) GetSupportedAlgorithms(ctx context.Context, req *pb.GetSupportedAlgorithmsRequest) (*pb.GetSupportedAlgorithmsResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionList, ""); err != nil {
		return nil, err
	}
	in := backendRequest(ctx, req.GetBackend())
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.GetSupportedAlgorithmsResponse, error) {
		resp, err := x.GetSupportedAlgorithms(ctx, in)
		if err != nil {
			return nil, err
		}
		return &pb.GetSupportedAlgorithmsResponse{Algorithms: pbconv.KeyAlgorithmNamesToProto(resp.Algorithms)}, nil
	})
}

// BackendStatus implements KeystoreService.BackendStatus.
func (s *Service) BackendStatus(ctx context.Context, req *pb.BackendStatusRequest) (*pb.BackendStatusResponse, error) {
	if err := s.authorize(ctx, auth.ResourceBackends, auth.ActionRead, ""); err != nil {
		return nil, err
	}
	in := backendRequest(ctx, req.GetBackend())
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.BackendStatusResponse, error) {
		resp, err := x.BackendStatus(ctx, in)
		if err != nil {
			return nil, err
		}
		return pbconv.BackendStatusResponseToProto(resp), nil
	})
}

// BackendTest implements KeystoreService.BackendTest.
func (s *Service) BackendTest(ctx context.Context, req *pb.BackendTestRequest) (*pb.BackendTestResponse, error) {
	if err := s.authorize(ctx, auth.ResourceBackends, auth.ActionRead, ""); err != nil {
		return nil, err
	}
	in := backendRequest(ctx, req.GetBackend())
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.BackendTestResponse, error) {
		resp, err := x.BackendTest(ctx, in)
		if err != nil {
			return nil, err
		}
		return &pb.BackendTestResponse{
			Success:    resp.Success,
			DurationMs: resp.DurationMS,
			Message:    resp.Message,
			Timestamp:  resp.Timestamp,
		}, nil
	})
}

// SetKeySafety implements KeystoreService.SetKeySafety.
func (s *Service) SetKeySafety(ctx context.Context, req *pb.SetKeySafetyRequest) (*pb.SetKeySafetyResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionRotate, req.GetKeyId()); err != nil {
		return nil, err
	}
	in := &transport.SetKeySafetyRequest{
		Backend:        req.GetBackend(),
		KeyID:          req.GetKeyId(),
		MaxOperations:  req.GetMaxOperations(),
		MaxBytes:       req.GetMaxBytes(),
		WarningPercent: req.GetWarningPercent(),
		TenantID:       callerTenantID(ctx),
	}
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.SetKeySafetyResponse, error) {
		resp, err := x.SetKeySafety(ctx, in)
		if err != nil {
			return nil, err
		}
		return &pb.SetKeySafetyResponse{KeyId: resp.KeyID, Timestamp: resp.Timestamp}, nil
	})
}

// ClearKeySafety implements KeystoreService.ClearKeySafety.
func (s *Service) ClearKeySafety(ctx context.Context, req *pb.ClearKeySafetyRequest) (*pb.ClearKeySafetyResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionRotate, req.GetKeyId()); err != nil {
		return nil, err
	}
	in := keyRequest(ctx, req.GetBackend(), req.GetKeyId())
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.ClearKeySafetyResponse, error) {
		resp, err := x.ClearKeySafety(ctx, in)
		if err != nil {
			return nil, err
		}
		return &pb.ClearKeySafetyResponse{KeyId: resp.KeyID, Timestamp: resp.Timestamp}, nil
	})
}

// SafetyCheck implements KeystoreService.SafetyCheck.
func (s *Service) SafetyCheck(ctx context.Context, _ *pb.SafetyCheckRequest) (*pb.SafetyCheckResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionGet, ""); err != nil {
		return nil, err
	}
	in := &transport.SafetyCheckRequest{TenantID: callerTenantID(ctx)}
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.SafetyCheckResponse, error) {
		resp, err := x.SafetyCheck(ctx, in)
		if err != nil {
			return nil, err
		}
		return &pb.SafetyCheckResponse{Warnings: pbconv.SafetyWarningsToProto(resp.Warnings), Timestamp: resp.Timestamp}, nil
	})
}

// SafetyReport implements KeystoreService.SafetyReport.
func (s *Service) SafetyReport(ctx context.Context, req *pb.SafetyReportRequest) (*pb.SafetyReportResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionGet, ""); err != nil {
		return nil, err
	}
	in := &transport.SafetyReportRequest{Format: req.GetFormat(), TenantID: callerTenantID(ctx)}
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.SafetyReportResponse, error) {
		resp, err := x.SafetyReport(ctx, in)
		if err != nil {
			return nil, err
		}
		return pbconv.SafetyReportResponseToProto(resp), nil
	})
}
