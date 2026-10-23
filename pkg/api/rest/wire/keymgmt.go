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

package wire

import (
	"context"
	"net/http"
	"strconv"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// Key management routes that take no key ID. They sit under /backend and
// /safety so they never shadow a backend or key named like a route segment.
const (
	// SupportedAlgorithmsPath lists the key algorithms a backend supports.
	SupportedAlgorithmsPath = "/api/v1/backend/algorithms"

	// BackendStatusPath reports a backend's type, capabilities and health.
	BackendStatusPath = "/api/v1/backend/status"

	// BackendTestPath runs a non-destructive round trip on a backend.
	BackendTestPath = "/api/v1/backend/test"

	// SafetyCheckPath lists the keys at or past their usage warning.
	SafetyCheckPath = "/api/v1/safety/check"

	// SafetyReportPath reports the usage of every key with usage limits.
	SafetyReportPath = "/api/v1/safety/report"
)

// Key management actions, the last path segments of a key route.
const (
	PublicKeyAction      = "public-key"
	RevokeAction         = "revoke"
	StatusAction         = "status"
	MetadataAction       = "metadata"
	PolicyAction         = "policy"
	RotationPolicyAction = "rotation-policy"
	SafetyAction         = "safety"
)

// Compile-time check that the client serves the whole key management API.
var _ transport.KeyManagementService = KeyManagementClient{}

// KeyManagementClient serves transport.KeyManagementService over the REST
// routes. The REST and QUIC transports delegate to it with their own
// Requester. The server takes the tenant from the authenticated identity.
type KeyManagementClient struct {
	// Do performs one request against the server.
	Do Requester
}

// keyPath returns the path of an action on req's key, with its backend as
// the query.
func keyPath(req *transport.KeyManagementRequest, action string) string {
	return withBackend(KeyActionPath(req.KeyID, action), req.Backend)
}

// GetPublicKey returns the DER public key of a key version.
func (c KeyManagementClient) GetPublicKey(ctx context.Context, req *transport.GetPublicKeyRequest) (*transport.GetPublicKeyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	query := map[string]string{"backend": req.Backend}
	if req.Version != 0 {
		query["version"] = strconv.FormatUint(req.Version, 10)
	}
	var resp transport.GetPublicKeyResponse
	path := withQuery(KeyActionPath(req.KeyID, PublicKeyAction), query)
	if err := callJSON(ctx, c.Do, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RevokeKey takes a key out of service for good.
func (c KeyManagementClient) RevokeKey(ctx context.Context, req *transport.RevokeKeyRequest) (*transport.RevokeKeyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.RevokeKeyResponse
	if err := callJSON(ctx, c.Do, http.MethodPost, KeyActionPath(req.KeyID, RevokeAction), req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// UpdateKeyStatus enables or disables a key or one of its versions.
func (c KeyManagementClient) UpdateKeyStatus(ctx context.Context, req *transport.UpdateKeyStatusRequest) (*transport.UpdateKeyStatusResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.UpdateKeyStatusResponse
	if err := callJSON(ctx, c.Do, http.MethodPost, KeyActionPath(req.KeyID, StatusAction), req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetKeyMetadata returns a key's metadata.
func (c KeyManagementClient) GetKeyMetadata(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyMetadataResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.KeyMetadataResponse
	if err := callJSON(ctx, c.Do, http.MethodGet, keyPath(req, MetadataAction), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// UpdateKeyMetadata updates a key's name, description and tags.
func (c KeyManagementClient) UpdateKeyMetadata(ctx context.Context, req *transport.UpdateKeyMetadataRequest) (*transport.KeyMetadataResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.KeyMetadataResponse
	if err := callJSON(ctx, c.Do, http.MethodPut, KeyActionPath(req.KeyID, MetadataAction), req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SetKeyPolicy sets or replaces a key's access policy.
func (c KeyManagementClient) SetKeyPolicy(ctx context.Context, req *transport.SetKeyPolicyRequest) (*transport.SetKeyPolicyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.SetKeyPolicyResponse
	if err := callJSON(ctx, c.Do, http.MethodPut, KeyActionPath(req.KeyID, PolicyAction), req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetKeyPolicy returns a key's access policy.
func (c KeyManagementClient) GetKeyPolicy(ctx context.Context, req *transport.KeyManagementRequest) (*transport.GetKeyPolicyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.GetKeyPolicyResponse
	if err := callJSON(ctx, c.Do, http.MethodGet, keyPath(req, PolicyAction), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DeleteKeyPolicy removes a key's access policy.
func (c KeyManagementClient) DeleteKeyPolicy(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return c.deleteAction(ctx, req, PolicyAction)
}

// SetKeyRotationPolicy sets or replaces a key's rotation policy.
func (c KeyManagementClient) SetKeyRotationPolicy(ctx context.Context, req *transport.SetKeyRotationPolicyRequest) (*transport.KeyRotationPolicyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.KeyRotationPolicyResponse
	if err := callJSON(ctx, c.Do, http.MethodPut, KeyActionPath(req.KeyID, RotationPolicyAction), req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetKeyRotationPolicy returns a key's rotation policy.
func (c KeyManagementClient) GetKeyRotationPolicy(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyRotationPolicyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.KeyRotationPolicyResponse
	if err := callJSON(ctx, c.Do, http.MethodGet, keyPath(req, RotationPolicyAction), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DeleteKeyRotationPolicy removes a key's rotation policy.
func (c KeyManagementClient) DeleteKeyRotationPolicy(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return c.deleteAction(ctx, req, RotationPolicyAction)
}

// GetSupportedAlgorithms returns the key algorithms a backend supports.
func (c KeyManagementClient) GetSupportedAlgorithms(ctx context.Context, req *transport.BackendRequest) (*transport.GetSupportedAlgorithmsResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.GetSupportedAlgorithmsResponse
	if err := callJSON(ctx, c.Do, http.MethodGet, withBackend(SupportedAlgorithmsPath, req.Backend), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// BackendStatus reports a backend's type, capabilities and health.
func (c KeyManagementClient) BackendStatus(ctx context.Context, req *transport.BackendRequest) (*transport.BackendStatusResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.BackendStatusResponse
	if err := callJSON(ctx, c.Do, http.MethodGet, withBackend(BackendStatusPath, req.Backend), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// BackendTest runs a non-destructive seal round trip on a backend.
func (c KeyManagementClient) BackendTest(ctx context.Context, req *transport.BackendRequest) (*transport.BackendTestResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.BackendTestResponse
	if err := callJSON(ctx, c.Do, http.MethodPost, BackendTestPath, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SetKeySafety sets a symmetric AEAD key's usage limits.
func (c KeyManagementClient) SetKeySafety(ctx context.Context, req *transport.SetKeySafetyRequest) (*transport.KeyManagementResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.KeyManagementResponse
	if err := callJSON(ctx, c.Do, http.MethodPut, KeyActionPath(req.KeyID, SafetyAction), req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ClearKeySafety removes a key's usage limits.
func (c KeyManagementClient) ClearKeySafety(ctx context.Context, req *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return c.deleteAction(ctx, req, SafetyAction)
}

// SafetyCheck returns the keys at or past their usage warning threshold.
func (c KeyManagementClient) SafetyCheck(ctx context.Context, req *transport.SafetyCheckRequest) (*transport.SafetyCheckResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.SafetyCheckResponse
	if err := callJSON(ctx, c.Do, http.MethodGet, SafetyCheckPath, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SafetyReport returns the usage of every key with usage limits.
func (c KeyManagementClient) SafetyReport(ctx context.Context, req *transport.SafetyReportRequest) (*transport.SafetyReportResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.SafetyReportResponse
	path := withQuery(SafetyReportPath, map[string]string{"format": req.Format})
	if err := callJSON(ctx, c.Do, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// deleteAction removes the record an action route names on req's key.
func (c KeyManagementClient) deleteAction(ctx context.Context, req *transport.KeyManagementRequest, action string) (*transport.KeyManagementResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.KeyManagementResponse
	if err := callJSON(ctx, c.Do, http.MethodDelete, keyPath(req, action), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
