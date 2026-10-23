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

package quic

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// keyManagement returns the key management client for the connection. QUIC
// serves the REST router over HTTP/3, so it shares the REST wire client.
func (t *Transport) keyManagement() (wire.KeyManagementClient, error) {
	if !t.connected {
		return wire.KeyManagementClient{}, ErrNotConnected
	}
	return wire.KeyManagementClient{Do: t.doRawRequest}, nil
}

// GetPublicKey returns the DER public key of a key version.
func (t *Transport) GetPublicKey(ctx context.Context, req *transport.GetPublicKeyRequest) (*transport.GetPublicKeyResponse, error) {
	c, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return c.GetPublicKey(ctx, req)
}

// RevokeKey takes a key out of service for good.
func (t *Transport) RevokeKey(ctx context.Context, req *transport.RevokeKeyRequest) (*transport.RevokeKeyResponse, error) {
	c, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return c.RevokeKey(ctx, req)
}

// UpdateKeyStatus enables or disables a key or one of its versions.
func (t *Transport) UpdateKeyStatus(ctx context.Context, req *transport.UpdateKeyStatusRequest) (*transport.UpdateKeyStatusResponse, error) {
	c, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return c.UpdateKeyStatus(ctx, req)
}

// GetKeyMetadata returns a key's metadata.
func (t *Transport) GetKeyMetadata(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyMetadataResponse, error) {
	c, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return c.GetKeyMetadata(ctx, req)
}

// UpdateKeyMetadata updates a key's name, description and tags.
func (t *Transport) UpdateKeyMetadata(ctx context.Context, req *transport.UpdateKeyMetadataRequest) (*transport.KeyMetadataResponse, error) {
	c, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return c.UpdateKeyMetadata(ctx, req)
}

// SetKeyPolicy sets or replaces a key's access policy.
func (t *Transport) SetKeyPolicy(ctx context.Context, req *transport.SetKeyPolicyRequest) (*transport.SetKeyPolicyResponse, error) {
	c, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return c.SetKeyPolicy(ctx, req)
}

// GetKeyPolicy returns a key's access policy.
func (t *Transport) GetKeyPolicy(ctx context.Context, req *transport.KeyManagementRequest) (*transport.GetKeyPolicyResponse, error) {
	c, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return c.GetKeyPolicy(ctx, req)
}

// DeleteKeyPolicy removes a key's access policy.
func (t *Transport) DeleteKeyPolicy(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	c, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return c.DeleteKeyPolicy(ctx, req)
}

// SetKeyRotationPolicy sets or replaces a key's rotation policy.
func (t *Transport) SetKeyRotationPolicy(ctx context.Context, req *transport.SetKeyRotationPolicyRequest) (*transport.KeyRotationPolicyResponse, error) {
	c, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return c.SetKeyRotationPolicy(ctx, req)
}

// GetKeyRotationPolicy returns a key's rotation policy.
func (t *Transport) GetKeyRotationPolicy(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyRotationPolicyResponse, error) {
	c, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return c.GetKeyRotationPolicy(ctx, req)
}

// DeleteKeyRotationPolicy removes a key's rotation policy.
func (t *Transport) DeleteKeyRotationPolicy(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	c, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return c.DeleteKeyRotationPolicy(ctx, req)
}

// GetSupportedAlgorithms returns the key algorithms a backend supports.
func (t *Transport) GetSupportedAlgorithms(ctx context.Context, req *transport.BackendRequest) (*transport.GetSupportedAlgorithmsResponse, error) {
	c, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return c.GetSupportedAlgorithms(ctx, req)
}

// BackendStatus reports a backend's type, capabilities and health.
func (t *Transport) BackendStatus(ctx context.Context, req *transport.BackendRequest) (*transport.BackendStatusResponse, error) {
	c, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return c.BackendStatus(ctx, req)
}

// BackendTest runs a non-destructive seal round trip on a backend.
func (t *Transport) BackendTest(ctx context.Context, req *transport.BackendRequest) (*transport.BackendTestResponse, error) {
	c, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return c.BackendTest(ctx, req)
}

// SetKeySafety sets a symmetric AEAD key's usage limits.
func (t *Transport) SetKeySafety(ctx context.Context, req *transport.SetKeySafetyRequest) (*transport.KeyManagementResponse, error) {
	c, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return c.SetKeySafety(ctx, req)
}

// ClearKeySafety removes a key's usage limits.
func (t *Transport) ClearKeySafety(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	c, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return c.ClearKeySafety(ctx, req)
}

// SafetyCheck returns the keys at or past their usage warning threshold.
func (t *Transport) SafetyCheck(ctx context.Context, req *transport.SafetyCheckRequest) (*transport.SafetyCheckResponse, error) {
	c, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return c.SafetyCheck(ctx, req)
}

// SafetyReport returns the usage of every key with usage limits.
func (t *Transport) SafetyReport(ctx context.Context, req *transport.SafetyReportRequest) (*transport.SafetyReportResponse, error) {
	c, err := t.keyManagement()
	if err != nil {
		return nil, err
	}
	return c.SafetyReport(ctx, req)
}
