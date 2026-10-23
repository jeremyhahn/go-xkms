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

package transport

import (
	"context"
)

// The key management methods of the fakes in this package.

func (m *stubClient) GetPublicKey(context.Context, *GetPublicKeyRequest) (*GetPublicKeyResponse, error) {
	return nil, nil
}

func (m *stubClient) RevokeKey(context.Context, *RevokeKeyRequest) (*RevokeKeyResponse, error) {
	return nil, nil
}

func (m *stubClient) UpdateKeyStatus(context.Context, *UpdateKeyStatusRequest) (*UpdateKeyStatusResponse, error) {
	return nil, nil
}

func (m *stubClient) GetKeyMetadata(context.Context, *KeyManagementRequest) (*KeyMetadataResponse, error) {
	return nil, nil
}

func (m *stubClient) UpdateKeyMetadata(context.Context, *UpdateKeyMetadataRequest) (*KeyMetadataResponse, error) {
	return nil, nil
}

func (m *stubClient) SetKeyPolicy(context.Context, *SetKeyPolicyRequest) (*SetKeyPolicyResponse, error) {
	return nil, nil
}

func (m *stubClient) GetKeyPolicy(context.Context, *KeyManagementRequest) (*GetKeyPolicyResponse, error) {
	return nil, nil
}

func (m *stubClient) DeleteKeyPolicy(context.Context, *KeyManagementRequest) (*KeyManagementResponse, error) {
	return nil, nil
}

func (m *stubClient) SetKeyRotationPolicy(context.Context, *SetKeyRotationPolicyRequest) (*KeyRotationPolicyResponse, error) {
	return nil, nil
}

func (m *stubClient) GetKeyRotationPolicy(context.Context, *KeyManagementRequest) (*KeyRotationPolicyResponse, error) {
	return nil, nil
}

func (m *stubClient) DeleteKeyRotationPolicy(context.Context, *KeyManagementRequest) (*KeyManagementResponse, error) {
	return nil, nil
}

func (m *stubClient) GetSupportedAlgorithms(context.Context, *BackendRequest) (*GetSupportedAlgorithmsResponse, error) {
	return nil, nil
}

func (m *stubClient) BackendStatus(context.Context, *BackendRequest) (*BackendStatusResponse, error) {
	return nil, nil
}

func (m *stubClient) BackendTest(context.Context, *BackendRequest) (*BackendTestResponse, error) {
	return nil, nil
}

func (m *stubClient) SetKeySafety(context.Context, *SetKeySafetyRequest) (*KeyManagementResponse, error) {
	return nil, nil
}

func (m *stubClient) ClearKeySafety(context.Context, *KeyManagementRequest) (*KeyManagementResponse, error) {
	return nil, nil
}

func (m *stubClient) SafetyCheck(context.Context, *SafetyCheckRequest) (*SafetyCheckResponse, error) {
	return nil, nil
}

func (m *stubClient) SafetyReport(context.Context, *SafetyReportRequest) (*SafetyReportResponse, error) {
	return nil, nil
}
