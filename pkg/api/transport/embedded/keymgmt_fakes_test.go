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

// The key management methods of the fakes in this package.

func (m *mockService) GetPublicKey(context.Context, *transport.GetPublicKeyRequest) (*transport.GetPublicKeyResponse, error) {
	return nil, nil
}

func (m *mockService) RevokeKey(context.Context, *transport.RevokeKeyRequest) (*transport.RevokeKeyResponse, error) {
	return nil, nil
}

func (m *mockService) UpdateKeyStatus(context.Context, *transport.UpdateKeyStatusRequest) (*transport.UpdateKeyStatusResponse, error) {
	return nil, nil
}

func (m *mockService) GetKeyMetadata(context.Context, *transport.KeyManagementRequest) (*transport.KeyMetadataResponse, error) {
	return nil, nil
}

func (m *mockService) UpdateKeyMetadata(context.Context, *transport.UpdateKeyMetadataRequest) (*transport.KeyMetadataResponse, error) {
	return nil, nil
}

func (m *mockService) SetKeyPolicy(context.Context, *transport.SetKeyPolicyRequest) (*transport.SetKeyPolicyResponse, error) {
	return nil, nil
}

func (m *mockService) GetKeyPolicy(context.Context, *transport.KeyManagementRequest) (*transport.GetKeyPolicyResponse, error) {
	return nil, nil
}

func (m *mockService) DeleteKeyPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockService) SetKeyRotationPolicy(context.Context, *transport.SetKeyRotationPolicyRequest) (*transport.KeyRotationPolicyResponse, error) {
	return nil, nil
}

func (m *mockService) GetKeyRotationPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyRotationPolicyResponse, error) {
	return nil, nil
}

func (m *mockService) DeleteKeyRotationPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockService) GetSupportedAlgorithms(context.Context, *transport.BackendRequest) (*transport.GetSupportedAlgorithmsResponse, error) {
	return nil, nil
}

func (m *mockService) BackendStatus(context.Context, *transport.BackendRequest) (*transport.BackendStatusResponse, error) {
	return nil, nil
}

func (m *mockService) BackendTest(context.Context, *transport.BackendRequest) (*transport.BackendTestResponse, error) {
	return nil, nil
}

func (m *mockService) SetKeySafety(context.Context, *transport.SetKeySafetyRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockService) ClearKeySafety(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockService) SafetyCheck(context.Context, *transport.SafetyCheckRequest) (*transport.SafetyCheckResponse, error) {
	return nil, nil
}

func (m *mockService) SafetyReport(context.Context, *transport.SafetyReportRequest) (*transport.SafetyReportResponse, error) {
	return nil, nil
}
