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

// The crypto utility methods of the fakes in this package.

func (m *stubClient) Rewrap(context.Context, *RewrapRequest) (*RewrapResponse, error) {
	return nil, nil
}

func (m *stubClient) EncryptBatch(context.Context, *EncryptBatchRequest) (*EncryptBatchResponse, error) {
	return nil, nil
}

func (m *stubClient) DecryptBatch(context.Context, *DecryptBatchRequest) (*DecryptBatchResponse, error) {
	return nil, nil
}

func (m *stubClient) GenerateDataKey(context.Context, *GenerateDataKeyRequest) (*GenerateDataKeyResponse, error) {
	return nil, nil
}

func (m *stubClient) GenerateWrappedDataKey(context.Context, *GenerateDataKeyRequest) (*GenerateWrappedDataKeyResponse, error) {
	return nil, nil
}

func (m *stubClient) GenerateHMAC(context.Context, *GenerateHMACRequest) (*GenerateHMACResponse, error) {
	return nil, nil
}

func (m *stubClient) VerifyHMAC(context.Context, *VerifyHMACRequest) (*VerifyHMACResponse, error) {
	return nil, nil
}

func (m *stubClient) GenerateRandom(context.Context, *GenerateRandomRequest) (*GenerateRandomResponse, error) {
	return nil, nil
}

func (m *stubClient) Hash(context.Context, *HashRequest) (*HashResponse, error) {
	return nil, nil
}
