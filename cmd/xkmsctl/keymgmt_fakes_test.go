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

package main

import (
	"context"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// The key management methods of the fakes in this package.

func (m *mockCAClient) GetPublicKey(context.Context, *transport.GetPublicKeyRequest) (*transport.GetPublicKeyResponse, error) {
	return nil, nil
}

func (m *mockCAClient) RevokeKey(context.Context, *transport.RevokeKeyRequest) (*transport.RevokeKeyResponse, error) {
	return nil, nil
}

func (m *mockCAClient) UpdateKeyStatus(context.Context, *transport.UpdateKeyStatusRequest) (*transport.UpdateKeyStatusResponse, error) {
	return nil, nil
}

func (m *mockCAClient) GetKeyMetadata(context.Context, *transport.KeyManagementRequest) (*transport.KeyMetadataResponse, error) {
	return nil, nil
}

func (m *mockCAClient) UpdateKeyMetadata(context.Context, *transport.UpdateKeyMetadataRequest) (*transport.KeyMetadataResponse, error) {
	return nil, nil
}

func (m *mockCAClient) SetKeyPolicy(context.Context, *transport.SetKeyPolicyRequest) (*transport.SetKeyPolicyResponse, error) {
	return nil, nil
}

func (m *mockCAClient) GetKeyPolicy(context.Context, *transport.KeyManagementRequest) (*transport.GetKeyPolicyResponse, error) {
	return nil, nil
}

func (m *mockCAClient) DeleteKeyPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockCAClient) SetKeyRotationPolicy(context.Context, *transport.SetKeyRotationPolicyRequest) (*transport.KeyRotationPolicyResponse, error) {
	return nil, nil
}

func (m *mockCAClient) GetKeyRotationPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyRotationPolicyResponse, error) {
	return nil, nil
}

func (m *mockCAClient) DeleteKeyRotationPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockCAClient) GetSupportedAlgorithms(context.Context, *transport.BackendRequest) (*transport.GetSupportedAlgorithmsResponse, error) {
	return nil, nil
}

func (m *mockCAClient) BackendStatus(context.Context, *transport.BackendRequest) (*transport.BackendStatusResponse, error) {
	return nil, nil
}

func (m *mockCAClient) BackendTest(context.Context, *transport.BackendRequest) (*transport.BackendTestResponse, error) {
	return nil, nil
}

func (m *mockCAClient) SetKeySafety(context.Context, *transport.SetKeySafetyRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockCAClient) ClearKeySafety(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockCAClient) SafetyCheck(context.Context, *transport.SafetyCheckRequest) (*transport.SafetyCheckResponse, error) {
	return nil, nil
}

func (m *mockCAClient) SafetyReport(context.Context, *transport.SafetyReportRequest) (*transport.SafetyReportResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) GetPublicKey(context.Context, *transport.GetPublicKeyRequest) (*transport.GetPublicKeyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) RevokeKey(context.Context, *transport.RevokeKeyRequest) (*transport.RevokeKeyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) UpdateKeyStatus(context.Context, *transport.UpdateKeyStatusRequest) (*transport.UpdateKeyStatusResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) GetKeyMetadata(context.Context, *transport.KeyManagementRequest) (*transport.KeyMetadataResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) UpdateKeyMetadata(context.Context, *transport.UpdateKeyMetadataRequest) (*transport.KeyMetadataResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) SetKeyPolicy(context.Context, *transport.SetKeyPolicyRequest) (*transport.SetKeyPolicyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) GetKeyPolicy(context.Context, *transport.KeyManagementRequest) (*transport.GetKeyPolicyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) DeleteKeyPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) SetKeyRotationPolicy(context.Context, *transport.SetKeyRotationPolicyRequest) (*transport.KeyRotationPolicyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) GetKeyRotationPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyRotationPolicyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) DeleteKeyRotationPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) GetSupportedAlgorithms(context.Context, *transport.BackendRequest) (*transport.GetSupportedAlgorithmsResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) BackendStatus(context.Context, *transport.BackendRequest) (*transport.BackendStatusResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) BackendTest(context.Context, *transport.BackendRequest) (*transport.BackendTestResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) SetKeySafety(context.Context, *transport.SetKeySafetyRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) ClearKeySafety(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) SafetyCheck(context.Context, *transport.SafetyCheckRequest) (*transport.SafetyCheckResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) SafetyReport(context.Context, *transport.SafetyReportRequest) (*transport.SafetyReportResponse, error) {
	return nil, nil
}

func (m *mockCertClient) GetPublicKey(context.Context, *transport.GetPublicKeyRequest) (*transport.GetPublicKeyResponse, error) {
	return nil, nil
}

func (m *mockCertClient) RevokeKey(context.Context, *transport.RevokeKeyRequest) (*transport.RevokeKeyResponse, error) {
	return nil, nil
}

func (m *mockCertClient) UpdateKeyStatus(context.Context, *transport.UpdateKeyStatusRequest) (*transport.UpdateKeyStatusResponse, error) {
	return nil, nil
}

func (m *mockCertClient) GetKeyMetadata(context.Context, *transport.KeyManagementRequest) (*transport.KeyMetadataResponse, error) {
	return nil, nil
}

func (m *mockCertClient) UpdateKeyMetadata(context.Context, *transport.UpdateKeyMetadataRequest) (*transport.KeyMetadataResponse, error) {
	return nil, nil
}

func (m *mockCertClient) SetKeyPolicy(context.Context, *transport.SetKeyPolicyRequest) (*transport.SetKeyPolicyResponse, error) {
	return nil, nil
}

func (m *mockCertClient) GetKeyPolicy(context.Context, *transport.KeyManagementRequest) (*transport.GetKeyPolicyResponse, error) {
	return nil, nil
}

func (m *mockCertClient) DeleteKeyPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockCertClient) SetKeyRotationPolicy(context.Context, *transport.SetKeyRotationPolicyRequest) (*transport.KeyRotationPolicyResponse, error) {
	return nil, nil
}

func (m *mockCertClient) GetKeyRotationPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyRotationPolicyResponse, error) {
	return nil, nil
}

func (m *mockCertClient) DeleteKeyRotationPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockCertClient) GetSupportedAlgorithms(context.Context, *transport.BackendRequest) (*transport.GetSupportedAlgorithmsResponse, error) {
	return nil, nil
}

func (m *mockCertClient) BackendStatus(context.Context, *transport.BackendRequest) (*transport.BackendStatusResponse, error) {
	return nil, nil
}

func (m *mockCertClient) BackendTest(context.Context, *transport.BackendRequest) (*transport.BackendTestResponse, error) {
	return nil, nil
}

func (m *mockCertClient) SetKeySafety(context.Context, *transport.SetKeySafetyRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockCertClient) ClearKeySafety(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockCertClient) SafetyCheck(context.Context, *transport.SafetyCheckRequest) (*transport.SafetyCheckResponse, error) {
	return nil, nil
}

func (m *mockCertClient) SafetyReport(context.Context, *transport.SafetyReportRequest) (*transport.SafetyReportResponse, error) {
	return nil, nil
}
