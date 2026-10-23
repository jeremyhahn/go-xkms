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

package embedded

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// keyManagement returns the in-process service once the transport is
// connected.
func (t *Transport) keyManagement() (transport.KeyManagementServicer, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service, nil
}

// GetPublicKey returns the DER public key of a key version.
func (t *Transport) GetPublicKey(ctx context.Context, req *transport.GetPublicKeyRequest) (*transport.GetPublicKeyResponse, error) {
	s, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return s.GetPublicKey(ctx, req)
}

// RevokeKey takes a key out of service for good.
func (t *Transport) RevokeKey(ctx context.Context, req *transport.RevokeKeyRequest) (*transport.RevokeKeyResponse, error) {
	s, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return s.RevokeKey(ctx, req)
}

// UpdateKeyStatus enables or disables a key or one of its versions.
func (t *Transport) UpdateKeyStatus(ctx context.Context, req *transport.UpdateKeyStatusRequest) (*transport.UpdateKeyStatusResponse, error) {
	s, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return s.UpdateKeyStatus(ctx, req)
}

// GetKeyMetadata returns a key's metadata.
func (t *Transport) GetKeyMetadata(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyMetadataResponse, error) {
	s, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return s.GetKeyMetadata(ctx, req)
}

// UpdateKeyMetadata updates a key's name, description and tags.
func (t *Transport) UpdateKeyMetadata(ctx context.Context, req *transport.UpdateKeyMetadataRequest) (*transport.KeyMetadataResponse, error) {
	s, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return s.UpdateKeyMetadata(ctx, req)
}

// SetKeyPolicy sets or replaces a key's access policy.
func (t *Transport) SetKeyPolicy(ctx context.Context, req *transport.SetKeyPolicyRequest) (*transport.SetKeyPolicyResponse, error) {
	s, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return s.SetKeyPolicy(ctx, req)
}

// GetKeyPolicy returns a key's access policy.
func (t *Transport) GetKeyPolicy(ctx context.Context, req *transport.KeyManagementRequest) (*transport.GetKeyPolicyResponse, error) {
	s, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return s.GetKeyPolicy(ctx, req)
}

// DeleteKeyPolicy removes a key's access policy.
func (t *Transport) DeleteKeyPolicy(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	s, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return s.DeleteKeyPolicy(ctx, req)
}

// SetKeyRotationPolicy sets or replaces a key's rotation policy.
func (t *Transport) SetKeyRotationPolicy(ctx context.Context, req *transport.SetKeyRotationPolicyRequest) (*transport.KeyRotationPolicyResponse, error) {
	s, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return s.SetKeyRotationPolicy(ctx, req)
}

// GetKeyRotationPolicy returns a key's rotation policy.
func (t *Transport) GetKeyRotationPolicy(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyRotationPolicyResponse, error) {
	s, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return s.GetKeyRotationPolicy(ctx, req)
}

// DeleteKeyRotationPolicy removes a key's rotation policy.
func (t *Transport) DeleteKeyRotationPolicy(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	s, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return s.DeleteKeyRotationPolicy(ctx, req)
}

// GetSupportedAlgorithms returns the key algorithms a backend supports.
func (t *Transport) GetSupportedAlgorithms(ctx context.Context, req *transport.BackendRequest) (*transport.GetSupportedAlgorithmsResponse, error) {
	s, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return s.GetSupportedAlgorithms(ctx, req)
}

// BackendStatus reports a backend's type, capabilities and health.
func (t *Transport) BackendStatus(ctx context.Context, req *transport.BackendRequest) (*transport.BackendStatusResponse, error) {
	s, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return s.BackendStatus(ctx, req)
}

// BackendTest runs a non-destructive seal round trip on a backend.
func (t *Transport) BackendTest(ctx context.Context, req *transport.BackendRequest) (*transport.BackendTestResponse, error) {
	s, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return s.BackendTest(ctx, req)
}

// SetKeySafety sets a symmetric AEAD key's usage limits.
func (t *Transport) SetKeySafety(ctx context.Context, req *transport.SetKeySafetyRequest) (*transport.KeyManagementResponse, error) {
	s, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return s.SetKeySafety(ctx, req)
}

// ClearKeySafety removes a key's usage limits.
func (t *Transport) ClearKeySafety(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	s, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return s.ClearKeySafety(ctx, req)
}

// SafetyCheck returns the keys at or past their usage warning threshold.
func (t *Transport) SafetyCheck(ctx context.Context, req *transport.SafetyCheckRequest) (*transport.SafetyCheckResponse, error) {
	s, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return s.SafetyCheck(ctx, req)
}

// SafetyReport returns the usage of every key with usage limits.
func (t *Transport) SafetyReport(ctx context.Context, req *transport.SafetyReportRequest) (*transport.SafetyReportResponse, error) {
	s, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return s.SafetyReport(ctx, req)
}
