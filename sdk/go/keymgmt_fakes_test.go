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

package xkms

import (
	"context"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// The key management methods of the fakes in this package.

func (m *noopClient) GetPublicKey(context.Context, *transport.GetPublicKeyRequest) (*transport.GetPublicKeyResponse, error) {
	return nil, nil
}

func (m *noopClient) RevokeKey(context.Context, *transport.RevokeKeyRequest) (*transport.RevokeKeyResponse, error) {
	return nil, nil
}

func (m *noopClient) UpdateKeyStatus(context.Context, *transport.UpdateKeyStatusRequest) (*transport.UpdateKeyStatusResponse, error) {
	return nil, nil
}

func (m *noopClient) GetKeyMetadata(context.Context, *transport.KeyManagementRequest) (*transport.KeyMetadataResponse, error) {
	return nil, nil
}

func (m *noopClient) UpdateKeyMetadata(context.Context, *transport.UpdateKeyMetadataRequest) (*transport.KeyMetadataResponse, error) {
	return nil, nil
}

func (m *noopClient) SetKeyPolicy(context.Context, *transport.SetKeyPolicyRequest) (*transport.SetKeyPolicyResponse, error) {
	return nil, nil
}

func (m *noopClient) GetKeyPolicy(context.Context, *transport.KeyManagementRequest) (*transport.GetKeyPolicyResponse, error) {
	return nil, nil
}

func (m *noopClient) DeleteKeyPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *noopClient) SetKeyRotationPolicy(context.Context, *transport.SetKeyRotationPolicyRequest) (*transport.KeyRotationPolicyResponse, error) {
	return nil, nil
}

func (m *noopClient) GetKeyRotationPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyRotationPolicyResponse, error) {
	return nil, nil
}

func (m *noopClient) DeleteKeyRotationPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *noopClient) GetSupportedAlgorithms(context.Context, *transport.BackendRequest) (*transport.GetSupportedAlgorithmsResponse, error) {
	return nil, nil
}

func (m *noopClient) BackendStatus(context.Context, *transport.BackendRequest) (*transport.BackendStatusResponse, error) {
	return nil, nil
}

func (m *noopClient) BackendTest(context.Context, *transport.BackendRequest) (*transport.BackendTestResponse, error) {
	return nil, nil
}

func (m *noopClient) SetKeySafety(context.Context, *transport.SetKeySafetyRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *noopClient) ClearKeySafety(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *noopClient) SafetyCheck(context.Context, *transport.SafetyCheckRequest) (*transport.SafetyCheckResponse, error) {
	return nil, nil
}

func (m *noopClient) SafetyReport(context.Context, *transport.SafetyReportRequest) (*transport.SafetyReportResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) GetPublicKey(context.Context, *transport.GetPublicKeyRequest) (*transport.GetPublicKeyResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) RevokeKey(context.Context, *transport.RevokeKeyRequest) (*transport.RevokeKeyResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) UpdateKeyStatus(context.Context, *transport.UpdateKeyStatusRequest) (*transport.UpdateKeyStatusResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) GetKeyMetadata(context.Context, *transport.KeyManagementRequest) (*transport.KeyMetadataResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) UpdateKeyMetadata(context.Context, *transport.UpdateKeyMetadataRequest) (*transport.KeyMetadataResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) SetKeyPolicy(context.Context, *transport.SetKeyPolicyRequest) (*transport.SetKeyPolicyResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) GetKeyPolicy(context.Context, *transport.KeyManagementRequest) (*transport.GetKeyPolicyResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) DeleteKeyPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) SetKeyRotationPolicy(context.Context, *transport.SetKeyRotationPolicyRequest) (*transport.KeyRotationPolicyResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) GetKeyRotationPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyRotationPolicyResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) DeleteKeyRotationPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) GetSupportedAlgorithms(context.Context, *transport.BackendRequest) (*transport.GetSupportedAlgorithmsResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) BackendStatus(context.Context, *transport.BackendRequest) (*transport.BackendStatusResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) BackendTest(context.Context, *transport.BackendRequest) (*transport.BackendTestResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) SetKeySafety(context.Context, *transport.SetKeySafetyRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) ClearKeySafety(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) SafetyCheck(context.Context, *transport.SafetyCheckRequest) (*transport.SafetyCheckResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) SafetyReport(context.Context, *transport.SafetyReportRequest) (*transport.SafetyReportResponse, error) {
	return nil, nil
}

func (m *mockService) GetPublicKey(context.Context, *GetPublicKeyRequest) (*GetPublicKeyResponse, error) {
	return nil, nil
}

func (m *mockService) RevokeKey(context.Context, *RevokeKeyRequest) (*RevokeKeyResponse, error) {
	return nil, nil
}

func (m *mockService) UpdateKeyStatus(context.Context, *UpdateKeyStatusRequest) (*UpdateKeyStatusResponse, error) {
	return nil, nil
}

func (m *mockService) GetKeyMetadata(context.Context, *KeyManagementRequest) (*KeyMetadataResponse, error) {
	return nil, nil
}

func (m *mockService) UpdateKeyMetadata(context.Context, *UpdateKeyMetadataRequest) (*KeyMetadataResponse, error) {
	return nil, nil
}

func (m *mockService) SetKeyPolicy(context.Context, *SetKeyPolicyRequest) (*SetKeyPolicyResponse, error) {
	return nil, nil
}

func (m *mockService) GetKeyPolicy(context.Context, *KeyManagementRequest) (*GetKeyPolicyResponse, error) {
	return nil, nil
}

func (m *mockService) DeleteKeyPolicy(context.Context, *KeyManagementRequest) (*KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockService) SetKeyRotationPolicy(context.Context, *SetKeyRotationPolicyRequest) (*KeyRotationPolicyResponse, error) {
	return nil, nil
}

func (m *mockService) GetKeyRotationPolicy(context.Context, *KeyManagementRequest) (*KeyRotationPolicyResponse, error) {
	return nil, nil
}

func (m *mockService) DeleteKeyRotationPolicy(context.Context, *KeyManagementRequest) (*KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockService) GetSupportedAlgorithms(context.Context, *BackendRequest) (*GetSupportedAlgorithmsResponse, error) {
	return nil, nil
}

func (m *mockService) BackendStatus(context.Context, *BackendRequest) (*BackendStatusResponse, error) {
	return nil, nil
}

func (m *mockService) BackendTest(context.Context, *BackendRequest) (*BackendTestResponse, error) {
	return nil, nil
}

func (m *mockService) SetKeySafety(context.Context, *SetKeySafetyRequest) (*KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockService) ClearKeySafety(context.Context, *KeyManagementRequest) (*KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockService) SafetyCheck(context.Context, *SafetyCheckRequest) (*SafetyCheckResponse, error) {
	return nil, nil
}

func (m *mockService) SafetyReport(context.Context, *SafetyReportRequest) (*SafetyReportResponse, error) {
	return nil, nil
}
