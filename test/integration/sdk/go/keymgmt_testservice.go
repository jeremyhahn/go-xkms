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

//go:build integration

package integration

import (
	"context"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// The crypto utility and key management methods of the test service, not implemented here.

func (m *TestXKMSService) Rewrap(context.Context, *xkms.RewrapRequest) (*xkms.RewrapResponse, error) {
	return nil, ErrNotImplemented
}

func (m *TestXKMSService) EncryptBatch(context.Context, *xkms.EncryptBatchRequest) (*xkms.EncryptBatchResponse, error) {
	return nil, ErrNotImplemented
}

func (m *TestXKMSService) DecryptBatch(context.Context, *xkms.DecryptBatchRequest) (*xkms.DecryptBatchResponse, error) {
	return nil, ErrNotImplemented
}

func (m *TestXKMSService) GenerateDataKey(context.Context, *xkms.GenerateDataKeyRequest) (*xkms.GenerateDataKeyResponse, error) {
	return nil, ErrNotImplemented
}

func (m *TestXKMSService) GenerateWrappedDataKey(context.Context, *xkms.GenerateDataKeyRequest) (*xkms.GenerateWrappedDataKeyResponse, error) {
	return nil, ErrNotImplemented
}

func (m *TestXKMSService) GenerateHMAC(context.Context, *xkms.GenerateHMACRequest) (*xkms.GenerateHMACResponse, error) {
	return nil, ErrNotImplemented
}

func (m *TestXKMSService) VerifyHMAC(context.Context, *xkms.VerifyHMACRequest) (*xkms.VerifyHMACResponse, error) {
	return nil, ErrNotImplemented
}

func (m *TestXKMSService) GenerateRandom(context.Context, *xkms.GenerateRandomRequest) (*xkms.GenerateRandomResponse, error) {
	return nil, ErrNotImplemented
}

func (m *TestXKMSService) Hash(context.Context, *xkms.HashRequest) (*xkms.HashResponse, error) {
	return nil, ErrNotImplemented
}

func (m *TestXKMSService) GetPublicKey(context.Context, *xkms.GetPublicKeyRequest) (*xkms.GetPublicKeyResponse, error) {
	return nil, ErrNotImplemented
}

func (m *TestXKMSService) RevokeKey(context.Context, *xkms.RevokeKeyRequest) (*xkms.RevokeKeyResponse, error) {
	return nil, ErrNotImplemented
}

func (m *TestXKMSService) UpdateKeyStatus(context.Context, *xkms.UpdateKeyStatusRequest) (*xkms.UpdateKeyStatusResponse, error) {
	return nil, ErrNotImplemented
}

func (m *TestXKMSService) GetKeyMetadata(context.Context, *xkms.KeyManagementRequest) (*xkms.KeyMetadataResponse, error) {
	return nil, ErrNotImplemented
}

func (m *TestXKMSService) UpdateKeyMetadata(context.Context, *xkms.UpdateKeyMetadataRequest) (*xkms.KeyMetadataResponse, error) {
	return nil, ErrNotImplemented
}

func (m *TestXKMSService) SetKeyPolicy(context.Context, *xkms.SetKeyPolicyRequest) (*xkms.SetKeyPolicyResponse, error) {
	return nil, ErrNotImplemented
}

func (m *TestXKMSService) GetKeyPolicy(context.Context, *xkms.KeyManagementRequest) (*xkms.GetKeyPolicyResponse, error) {
	return nil, ErrNotImplemented
}

func (m *TestXKMSService) DeleteKeyPolicy(context.Context, *xkms.KeyManagementRequest) (*xkms.KeyManagementResponse, error) {
	return nil, ErrNotImplemented
}

func (m *TestXKMSService) SetKeyRotationPolicy(context.Context, *xkms.SetKeyRotationPolicyRequest) (*xkms.KeyRotationPolicyResponse, error) {
	return nil, ErrNotImplemented
}

func (m *TestXKMSService) GetKeyRotationPolicy(context.Context, *xkms.KeyManagementRequest) (*xkms.KeyRotationPolicyResponse, error) {
	return nil, ErrNotImplemented
}

func (m *TestXKMSService) DeleteKeyRotationPolicy(context.Context, *xkms.KeyManagementRequest) (*xkms.KeyManagementResponse, error) {
	return nil, ErrNotImplemented
}

func (m *TestXKMSService) GetSupportedAlgorithms(context.Context, *xkms.BackendRequest) (*xkms.GetSupportedAlgorithmsResponse, error) {
	return nil, ErrNotImplemented
}

func (m *TestXKMSService) BackendStatus(context.Context, *xkms.BackendRequest) (*xkms.BackendStatusResponse, error) {
	return nil, ErrNotImplemented
}

func (m *TestXKMSService) BackendTest(context.Context, *xkms.BackendRequest) (*xkms.BackendTestResponse, error) {
	return nil, ErrNotImplemented
}

func (m *TestXKMSService) SetKeySafety(context.Context, *xkms.SetKeySafetyRequest) (*xkms.KeyManagementResponse, error) {
	return nil, ErrNotImplemented
}

func (m *TestXKMSService) ClearKeySafety(context.Context, *xkms.KeyManagementRequest) (*xkms.KeyManagementResponse, error) {
	return nil, ErrNotImplemented
}

func (m *TestXKMSService) SafetyCheck(context.Context, *xkms.SafetyCheckRequest) (*xkms.SafetyCheckResponse, error) {
	return nil, ErrNotImplemented
}

func (m *TestXKMSService) SafetyReport(context.Context, *xkms.SafetyReportRequest) (*xkms.SafetyReportResponse, error) {
	return nil, ErrNotImplemented
}
