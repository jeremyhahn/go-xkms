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

package services

import (
	"context"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// The crypto utility and key management methods of the fakes in this package.

func (m *mockCAClient) Rewrap(context.Context, *transport.RewrapRequest) (*transport.RewrapResponse, error) {
	return nil, nil
}

func (m *mockCAClient) EncryptBatch(context.Context, *transport.EncryptBatchRequest) (*transport.EncryptBatchResponse, error) {
	return nil, nil
}

func (m *mockCAClient) DecryptBatch(context.Context, *transport.DecryptBatchRequest) (*transport.DecryptBatchResponse, error) {
	return nil, nil
}

func (m *mockCAClient) GenerateDataKey(context.Context, *transport.GenerateDataKeyRequest) (*transport.GenerateDataKeyResponse, error) {
	return nil, nil
}

func (m *mockCAClient) GenerateWrappedDataKey(context.Context, *transport.GenerateDataKeyRequest) (*transport.GenerateWrappedDataKeyResponse, error) {
	return nil, nil
}

func (m *mockCAClient) GenerateHMAC(context.Context, *transport.GenerateHMACRequest) (*transport.GenerateHMACResponse, error) {
	return nil, nil
}

func (m *mockCAClient) VerifyHMAC(context.Context, *transport.VerifyHMACRequest) (*transport.VerifyHMACResponse, error) {
	return nil, nil
}

func (m *mockCAClient) GenerateRandom(context.Context, *transport.GenerateRandomRequest) (*transport.GenerateRandomResponse, error) {
	return nil, nil
}

func (m *mockCAClient) Hash(context.Context, *transport.HashRequest) (*transport.HashResponse, error) {
	return nil, nil
}

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

func (m *mockClient) Rewrap(context.Context, *transport.RewrapRequest) (*transport.RewrapResponse, error) {
	return nil, nil
}

func (m *mockClient) EncryptBatch(context.Context, *transport.EncryptBatchRequest) (*transport.EncryptBatchResponse, error) {
	return nil, nil
}

func (m *mockClient) DecryptBatch(context.Context, *transport.DecryptBatchRequest) (*transport.DecryptBatchResponse, error) {
	return nil, nil
}

func (m *mockClient) GenerateDataKey(context.Context, *transport.GenerateDataKeyRequest) (*transport.GenerateDataKeyResponse, error) {
	return nil, nil
}

func (m *mockClient) GenerateWrappedDataKey(context.Context, *transport.GenerateDataKeyRequest) (*transport.GenerateWrappedDataKeyResponse, error) {
	return nil, nil
}

func (m *mockClient) GenerateHMAC(context.Context, *transport.GenerateHMACRequest) (*transport.GenerateHMACResponse, error) {
	return nil, nil
}

func (m *mockClient) VerifyHMAC(context.Context, *transport.VerifyHMACRequest) (*transport.VerifyHMACResponse, error) {
	return nil, nil
}

func (m *mockClient) GenerateRandom(context.Context, *transport.GenerateRandomRequest) (*transport.GenerateRandomResponse, error) {
	return nil, nil
}

func (m *mockClient) Hash(context.Context, *transport.HashRequest) (*transport.HashResponse, error) {
	return nil, nil
}

func (m *mockClient) GetPublicKey(context.Context, *transport.GetPublicKeyRequest) (*transport.GetPublicKeyResponse, error) {
	return nil, nil
}

func (m *mockClient) RevokeKey(context.Context, *transport.RevokeKeyRequest) (*transport.RevokeKeyResponse, error) {
	return nil, nil
}

func (m *mockClient) UpdateKeyStatus(context.Context, *transport.UpdateKeyStatusRequest) (*transport.UpdateKeyStatusResponse, error) {
	return nil, nil
}

func (m *mockClient) GetKeyMetadata(context.Context, *transport.KeyManagementRequest) (*transport.KeyMetadataResponse, error) {
	return nil, nil
}

func (m *mockClient) UpdateKeyMetadata(context.Context, *transport.UpdateKeyMetadataRequest) (*transport.KeyMetadataResponse, error) {
	return nil, nil
}

func (m *mockClient) SetKeyPolicy(context.Context, *transport.SetKeyPolicyRequest) (*transport.SetKeyPolicyResponse, error) {
	return nil, nil
}

func (m *mockClient) GetKeyPolicy(context.Context, *transport.KeyManagementRequest) (*transport.GetKeyPolicyResponse, error) {
	return nil, nil
}

func (m *mockClient) DeleteKeyPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockClient) SetKeyRotationPolicy(context.Context, *transport.SetKeyRotationPolicyRequest) (*transport.KeyRotationPolicyResponse, error) {
	return nil, nil
}

func (m *mockClient) GetKeyRotationPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyRotationPolicyResponse, error) {
	return nil, nil
}

func (m *mockClient) DeleteKeyRotationPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockClient) GetSupportedAlgorithms(context.Context, *transport.BackendRequest) (*transport.GetSupportedAlgorithmsResponse, error) {
	return nil, nil
}

func (m *mockClient) BackendStatus(context.Context, *transport.BackendRequest) (*transport.BackendStatusResponse, error) {
	return nil, nil
}

func (m *mockClient) BackendTest(context.Context, *transport.BackendRequest) (*transport.BackendTestResponse, error) {
	return nil, nil
}

func (m *mockClient) SetKeySafety(context.Context, *transport.SetKeySafetyRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockClient) ClearKeySafety(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockClient) SafetyCheck(context.Context, *transport.SafetyCheckRequest) (*transport.SafetyCheckResponse, error) {
	return nil, nil
}

func (m *mockClient) SafetyReport(context.Context, *transport.SafetyReportRequest) (*transport.SafetyReportResponse, error) {
	return nil, nil
}

func (m *mockPIVClient) Rewrap(context.Context, *transport.RewrapRequest) (*transport.RewrapResponse, error) {
	return nil, nil
}

func (m *mockPIVClient) EncryptBatch(context.Context, *transport.EncryptBatchRequest) (*transport.EncryptBatchResponse, error) {
	return nil, nil
}

func (m *mockPIVClient) DecryptBatch(context.Context, *transport.DecryptBatchRequest) (*transport.DecryptBatchResponse, error) {
	return nil, nil
}

func (m *mockPIVClient) GenerateDataKey(context.Context, *transport.GenerateDataKeyRequest) (*transport.GenerateDataKeyResponse, error) {
	return nil, nil
}

func (m *mockPIVClient) GenerateWrappedDataKey(context.Context, *transport.GenerateDataKeyRequest) (*transport.GenerateWrappedDataKeyResponse, error) {
	return nil, nil
}

func (m *mockPIVClient) GenerateHMAC(context.Context, *transport.GenerateHMACRequest) (*transport.GenerateHMACResponse, error) {
	return nil, nil
}

func (m *mockPIVClient) VerifyHMAC(context.Context, *transport.VerifyHMACRequest) (*transport.VerifyHMACResponse, error) {
	return nil, nil
}

func (m *mockPIVClient) GenerateRandom(context.Context, *transport.GenerateRandomRequest) (*transport.GenerateRandomResponse, error) {
	return nil, nil
}

func (m *mockPIVClient) Hash(context.Context, *transport.HashRequest) (*transport.HashResponse, error) {
	return nil, nil
}

func (m *mockPIVClient) GetPublicKey(context.Context, *transport.GetPublicKeyRequest) (*transport.GetPublicKeyResponse, error) {
	return nil, nil
}

func (m *mockPIVClient) RevokeKey(context.Context, *transport.RevokeKeyRequest) (*transport.RevokeKeyResponse, error) {
	return nil, nil
}

func (m *mockPIVClient) UpdateKeyStatus(context.Context, *transport.UpdateKeyStatusRequest) (*transport.UpdateKeyStatusResponse, error) {
	return nil, nil
}

func (m *mockPIVClient) GetKeyMetadata(context.Context, *transport.KeyManagementRequest) (*transport.KeyMetadataResponse, error) {
	return nil, nil
}

func (m *mockPIVClient) UpdateKeyMetadata(context.Context, *transport.UpdateKeyMetadataRequest) (*transport.KeyMetadataResponse, error) {
	return nil, nil
}

func (m *mockPIVClient) SetKeyPolicy(context.Context, *transport.SetKeyPolicyRequest) (*transport.SetKeyPolicyResponse, error) {
	return nil, nil
}

func (m *mockPIVClient) GetKeyPolicy(context.Context, *transport.KeyManagementRequest) (*transport.GetKeyPolicyResponse, error) {
	return nil, nil
}

func (m *mockPIVClient) DeleteKeyPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockPIVClient) SetKeyRotationPolicy(context.Context, *transport.SetKeyRotationPolicyRequest) (*transport.KeyRotationPolicyResponse, error) {
	return nil, nil
}

func (m *mockPIVClient) GetKeyRotationPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyRotationPolicyResponse, error) {
	return nil, nil
}

func (m *mockPIVClient) DeleteKeyRotationPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockPIVClient) GetSupportedAlgorithms(context.Context, *transport.BackendRequest) (*transport.GetSupportedAlgorithmsResponse, error) {
	return nil, nil
}

func (m *mockPIVClient) BackendStatus(context.Context, *transport.BackendRequest) (*transport.BackendStatusResponse, error) {
	return nil, nil
}

func (m *mockPIVClient) BackendTest(context.Context, *transport.BackendRequest) (*transport.BackendTestResponse, error) {
	return nil, nil
}

func (m *mockPIVClient) SetKeySafety(context.Context, *transport.SetKeySafetyRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockPIVClient) ClearKeySafety(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockPIVClient) SafetyCheck(context.Context, *transport.SafetyCheckRequest) (*transport.SafetyCheckResponse, error) {
	return nil, nil
}

func (m *mockPIVClient) SafetyReport(context.Context, *transport.SafetyReportRequest) (*transport.SafetyReportResponse, error) {
	return nil, nil
}
