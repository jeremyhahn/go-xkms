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

// The crypto utility methods of the fakes in this package.

func (m *mockService) Rewrap(context.Context, *transport.RewrapRequest) (*transport.RewrapResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.RewrapResponse{}, nil
}

func (m *mockService) EncryptBatch(context.Context, *transport.EncryptBatchRequest) (*transport.EncryptBatchResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.EncryptBatchResponse{}, nil
}

func (m *mockService) DecryptBatch(context.Context, *transport.DecryptBatchRequest) (*transport.DecryptBatchResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.DecryptBatchResponse{}, nil
}

func (m *mockService) GenerateDataKey(context.Context, *transport.GenerateDataKeyRequest) (*transport.GenerateDataKeyResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.GenerateDataKeyResponse{}, nil
}

func (m *mockService) GenerateWrappedDataKey(context.Context, *transport.GenerateDataKeyRequest) (*transport.GenerateWrappedDataKeyResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.GenerateWrappedDataKeyResponse{}, nil
}

func (m *mockService) GenerateHMAC(context.Context, *transport.GenerateHMACRequest) (*transport.GenerateHMACResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.GenerateHMACResponse{}, nil
}

func (m *mockService) VerifyHMAC(context.Context, *transport.VerifyHMACRequest) (*transport.VerifyHMACResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.VerifyHMACResponse{}, nil
}

func (m *mockService) GenerateRandom(context.Context, *transport.GenerateRandomRequest) (*transport.GenerateRandomResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.GenerateRandomResponse{}, nil
}

func (m *mockService) Hash(context.Context, *transport.HashRequest) (*transport.HashResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.HashResponse{}, nil
}
