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

// The crypto utility methods of the fakes in this package.

func (m *noopClient) Rewrap(context.Context, *transport.RewrapRequest) (*transport.RewrapResponse, error) {
	return nil, nil
}

func (m *noopClient) EncryptBatch(context.Context, *transport.EncryptBatchRequest) (*transport.EncryptBatchResponse, error) {
	return nil, nil
}

func (m *noopClient) DecryptBatch(context.Context, *transport.DecryptBatchRequest) (*transport.DecryptBatchResponse, error) {
	return nil, nil
}

func (m *noopClient) GenerateDataKey(context.Context, *transport.GenerateDataKeyRequest) (*transport.GenerateDataKeyResponse, error) {
	return nil, nil
}

func (m *noopClient) GenerateWrappedDataKey(context.Context, *transport.GenerateDataKeyRequest) (*transport.GenerateWrappedDataKeyResponse, error) {
	return nil, nil
}

func (m *noopClient) GenerateHMAC(context.Context, *transport.GenerateHMACRequest) (*transport.GenerateHMACResponse, error) {
	return nil, nil
}

func (m *noopClient) VerifyHMAC(context.Context, *transport.VerifyHMACRequest) (*transport.VerifyHMACResponse, error) {
	return nil, nil
}

func (m *noopClient) GenerateRandom(context.Context, *transport.GenerateRandomRequest) (*transport.GenerateRandomResponse, error) {
	return nil, nil
}

func (m *noopClient) Hash(context.Context, *transport.HashRequest) (*transport.HashResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) Rewrap(context.Context, *transport.RewrapRequest) (*transport.RewrapResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) EncryptBatch(context.Context, *transport.EncryptBatchRequest) (*transport.EncryptBatchResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) DecryptBatch(context.Context, *transport.DecryptBatchRequest) (*transport.DecryptBatchResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) GenerateDataKey(context.Context, *transport.GenerateDataKeyRequest) (*transport.GenerateDataKeyResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) GenerateWrappedDataKey(context.Context, *transport.GenerateDataKeyRequest) (*transport.GenerateWrappedDataKeyResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) GenerateHMAC(context.Context, *transport.GenerateHMACRequest) (*transport.GenerateHMACResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) VerifyHMAC(context.Context, *transport.VerifyHMACRequest) (*transport.VerifyHMACResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) GenerateRandom(context.Context, *transport.GenerateRandomRequest) (*transport.GenerateRandomResponse, error) {
	return nil, nil
}

func (m *mockXKMSService) Hash(context.Context, *transport.HashRequest) (*transport.HashResponse, error) {
	return nil, nil
}

func (m *mockService) Rewrap(context.Context, *RewrapRequest) (*RewrapResponse, error) {
	return nil, nil
}

func (m *mockService) EncryptBatch(context.Context, *EncryptBatchRequest) (*EncryptBatchResponse, error) {
	return nil, nil
}

func (m *mockService) DecryptBatch(context.Context, *DecryptBatchRequest) (*DecryptBatchResponse, error) {
	return nil, nil
}

func (m *mockService) GenerateDataKey(context.Context, *GenerateDataKeyRequest) (*GenerateDataKeyResponse, error) {
	return nil, nil
}

func (m *mockService) GenerateWrappedDataKey(context.Context, *GenerateDataKeyRequest) (*GenerateWrappedDataKeyResponse, error) {
	return nil, nil
}

func (m *mockService) GenerateHMAC(context.Context, *GenerateHMACRequest) (*GenerateHMACResponse, error) {
	return nil, nil
}

func (m *mockService) VerifyHMAC(context.Context, *VerifyHMACRequest) (*VerifyHMACResponse, error) {
	return nil, nil
}

func (m *mockService) GenerateRandom(context.Context, *GenerateRandomRequest) (*GenerateRandomResponse, error) {
	return nil, nil
}

func (m *mockService) Hash(context.Context, *HashRequest) (*HashResponse, error) {
	return nil, nil
}
