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

package pairing

import (
	"context"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// The crypto utility and key management methods of the fakes in this package.

func (m *mockTransportClient) Rewrap(context.Context, *transport.RewrapRequest) (*transport.RewrapResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) EncryptBatch(context.Context, *transport.EncryptBatchRequest) (*transport.EncryptBatchResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) DecryptBatch(context.Context, *transport.DecryptBatchRequest) (*transport.DecryptBatchResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) GenerateDataKey(context.Context, *transport.GenerateDataKeyRequest) (*transport.GenerateDataKeyResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) GenerateWrappedDataKey(context.Context, *transport.GenerateDataKeyRequest) (*transport.GenerateWrappedDataKeyResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) GenerateHMAC(context.Context, *transport.GenerateHMACRequest) (*transport.GenerateHMACResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) VerifyHMAC(context.Context, *transport.VerifyHMACRequest) (*transport.VerifyHMACResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) GenerateRandom(context.Context, *transport.GenerateRandomRequest) (*transport.GenerateRandomResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) Hash(context.Context, *transport.HashRequest) (*transport.HashResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) GetPublicKey(context.Context, *transport.GetPublicKeyRequest) (*transport.GetPublicKeyResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) RevokeKey(context.Context, *transport.RevokeKeyRequest) (*transport.RevokeKeyResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) UpdateKeyStatus(context.Context, *transport.UpdateKeyStatusRequest) (*transport.UpdateKeyStatusResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) GetKeyMetadata(context.Context, *transport.KeyManagementRequest) (*transport.KeyMetadataResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) UpdateKeyMetadata(context.Context, *transport.UpdateKeyMetadataRequest) (*transport.KeyMetadataResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) SetKeyPolicy(context.Context, *transport.SetKeyPolicyRequest) (*transport.SetKeyPolicyResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) GetKeyPolicy(context.Context, *transport.KeyManagementRequest) (*transport.GetKeyPolicyResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) DeleteKeyPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) SetKeyRotationPolicy(context.Context, *transport.SetKeyRotationPolicyRequest) (*transport.KeyRotationPolicyResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) GetKeyRotationPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyRotationPolicyResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) DeleteKeyRotationPolicy(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) GetSupportedAlgorithms(context.Context, *transport.BackendRequest) (*transport.GetSupportedAlgorithmsResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) BackendStatus(context.Context, *transport.BackendRequest) (*transport.BackendStatusResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) BackendTest(context.Context, *transport.BackendRequest) (*transport.BackendTestResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) SetKeySafety(context.Context, *transport.SetKeySafetyRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) ClearKeySafety(context.Context, *transport.KeyManagementRequest) (*transport.KeyManagementResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) SafetyCheck(context.Context, *transport.SafetyCheckRequest) (*transport.SafetyCheckResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) SafetyReport(context.Context, *transport.SafetyReportRequest) (*transport.SafetyReportResponse, error) {
	return nil, nil
}
