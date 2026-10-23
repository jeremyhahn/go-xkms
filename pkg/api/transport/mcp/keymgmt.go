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

package mcp

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// keyManagementCall sends one key management RPC and decodes its result.
func keyManagementCall[T any](ctx context.Context, t *Transport, method string, req any) (*T, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var result T
	if err := t.rpcCall(ctx, method, req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetPublicKey returns the DER public key of a key version.
func (t *Transport) GetPublicKey(ctx context.Context, req *transport.GetPublicKeyRequest) (*transport.GetPublicKeyResponse, error) {
	return keyManagementCall[transport.GetPublicKeyResponse](ctx, t, "xkms.getPublicKey", req)
}

// RevokeKey takes a key out of service for good.
func (t *Transport) RevokeKey(ctx context.Context, req *transport.RevokeKeyRequest) (*transport.RevokeKeyResponse, error) {
	return keyManagementCall[transport.RevokeKeyResponse](ctx, t, "xkms.revokeKey", req)
}

// UpdateKeyStatus enables or disables a key or one of its versions.
func (t *Transport) UpdateKeyStatus(ctx context.Context, req *transport.UpdateKeyStatusRequest) (*transport.UpdateKeyStatusResponse, error) {
	return keyManagementCall[transport.UpdateKeyStatusResponse](ctx, t, "xkms.updateKeyStatus", req)
}

// GetKeyMetadata returns a key's metadata.
func (t *Transport) GetKeyMetadata(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyMetadataResponse, error) {
	return keyManagementCall[transport.KeyMetadataResponse](ctx, t, "xkms.getKeyMetadata", req)
}

// UpdateKeyMetadata updates a key's name, description and tags.
func (t *Transport) UpdateKeyMetadata(ctx context.Context, req *transport.UpdateKeyMetadataRequest) (*transport.KeyMetadataResponse, error) {
	return keyManagementCall[transport.KeyMetadataResponse](ctx, t, "xkms.updateKeyMetadata", req)
}

// SetKeyPolicy sets or replaces a key's access policy.
func (t *Transport) SetKeyPolicy(ctx context.Context, req *transport.SetKeyPolicyRequest) (*transport.SetKeyPolicyResponse, error) {
	return keyManagementCall[transport.SetKeyPolicyResponse](ctx, t, "xkms.setKeyPolicy", req)
}

// GetKeyPolicy returns a key's access policy.
func (t *Transport) GetKeyPolicy(ctx context.Context, req *transport.KeyManagementRequest) (*transport.GetKeyPolicyResponse, error) {
	return keyManagementCall[transport.GetKeyPolicyResponse](ctx, t, "xkms.getKeyPolicy", req)
}

// DeleteKeyPolicy removes a key's access policy.
func (t *Transport) DeleteKeyPolicy(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return keyManagementCall[transport.KeyManagementResponse](ctx, t, "xkms.deleteKeyPolicy", req)
}

// SetKeyRotationPolicy sets or replaces a key's rotation policy.
func (t *Transport) SetKeyRotationPolicy(ctx context.Context, req *transport.SetKeyRotationPolicyRequest) (*transport.KeyRotationPolicyResponse, error) {
	return keyManagementCall[transport.KeyRotationPolicyResponse](ctx, t, "xkms.setKeyRotationPolicy", req)
}

// GetKeyRotationPolicy returns a key's rotation policy.
func (t *Transport) GetKeyRotationPolicy(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyRotationPolicyResponse, error) {
	return keyManagementCall[transport.KeyRotationPolicyResponse](ctx, t, "xkms.getKeyRotationPolicy", req)
}

// DeleteKeyRotationPolicy removes a key's rotation policy.
func (t *Transport) DeleteKeyRotationPolicy(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return keyManagementCall[transport.KeyManagementResponse](ctx, t, "xkms.deleteKeyRotationPolicy", req)
}

// GetSupportedAlgorithms returns the key algorithms a backend supports.
func (t *Transport) GetSupportedAlgorithms(ctx context.Context, req *transport.BackendRequest) (*transport.GetSupportedAlgorithmsResponse, error) {
	return keyManagementCall[transport.GetSupportedAlgorithmsResponse](ctx, t, "xkms.getSupportedAlgorithms", req)
}

// BackendStatus reports a backend's type, capabilities and health.
func (t *Transport) BackendStatus(ctx context.Context, req *transport.BackendRequest) (*transport.BackendStatusResponse, error) {
	return keyManagementCall[transport.BackendStatusResponse](ctx, t, "xkms.backendStatus", req)
}

// BackendTest runs a non-destructive seal round trip on a backend.
func (t *Transport) BackendTest(ctx context.Context, req *transport.BackendRequest) (*transport.BackendTestResponse, error) {
	return keyManagementCall[transport.BackendTestResponse](ctx, t, "xkms.backendTest", req)
}

// SetKeySafety sets a symmetric AEAD key's usage limits.
func (t *Transport) SetKeySafety(ctx context.Context, req *transport.SetKeySafetyRequest) (*transport.KeyManagementResponse, error) {
	return keyManagementCall[transport.KeyManagementResponse](ctx, t, "xkms.setKeySafety", req)
}

// ClearKeySafety removes a key's usage limits.
func (t *Transport) ClearKeySafety(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return keyManagementCall[transport.KeyManagementResponse](ctx, t, "xkms.clearKeySafety", req)
}

// SafetyCheck returns the keys at or past their usage warning threshold.
func (t *Transport) SafetyCheck(ctx context.Context, req *transport.SafetyCheckRequest) (*transport.SafetyCheckResponse, error) {
	return keyManagementCall[transport.SafetyCheckResponse](ctx, t, "xkms.safetyCheck", req)
}

// SafetyReport returns the usage of every key with usage limits.
func (t *Transport) SafetyReport(ctx context.Context, req *transport.SafetyReportRequest) (*transport.SafetyReportResponse, error) {
	return keyManagementCall[transport.SafetyReportResponse](ctx, t, "xkms.safetyReport", req)
}
