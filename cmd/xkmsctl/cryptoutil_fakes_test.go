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

// The crypto utility methods of the fakes in this package.

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

func (m *mockBackendsClient) Rewrap(context.Context, *transport.RewrapRequest) (*transport.RewrapResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) EncryptBatch(context.Context, *transport.EncryptBatchRequest) (*transport.EncryptBatchResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) DecryptBatch(context.Context, *transport.DecryptBatchRequest) (*transport.DecryptBatchResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) GenerateDataKey(context.Context, *transport.GenerateDataKeyRequest) (*transport.GenerateDataKeyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) GenerateWrappedDataKey(context.Context, *transport.GenerateDataKeyRequest) (*transport.GenerateWrappedDataKeyResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) GenerateHMAC(context.Context, *transport.GenerateHMACRequest) (*transport.GenerateHMACResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) VerifyHMAC(context.Context, *transport.VerifyHMACRequest) (*transport.VerifyHMACResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) GenerateRandom(context.Context, *transport.GenerateRandomRequest) (*transport.GenerateRandomResponse, error) {
	return nil, nil
}

func (m *mockBackendsClient) Hash(context.Context, *transport.HashRequest) (*transport.HashResponse, error) {
	return nil, nil
}

func (m *mockCertClient) Rewrap(context.Context, *transport.RewrapRequest) (*transport.RewrapResponse, error) {
	return nil, nil
}

func (m *mockCertClient) EncryptBatch(context.Context, *transport.EncryptBatchRequest) (*transport.EncryptBatchResponse, error) {
	return nil, nil
}

func (m *mockCertClient) DecryptBatch(context.Context, *transport.DecryptBatchRequest) (*transport.DecryptBatchResponse, error) {
	return nil, nil
}

func (m *mockCertClient) GenerateDataKey(context.Context, *transport.GenerateDataKeyRequest) (*transport.GenerateDataKeyResponse, error) {
	return nil, nil
}

func (m *mockCertClient) GenerateWrappedDataKey(context.Context, *transport.GenerateDataKeyRequest) (*transport.GenerateWrappedDataKeyResponse, error) {
	return nil, nil
}

func (m *mockCertClient) GenerateHMAC(context.Context, *transport.GenerateHMACRequest) (*transport.GenerateHMACResponse, error) {
	return nil, nil
}

func (m *mockCertClient) VerifyHMAC(context.Context, *transport.VerifyHMACRequest) (*transport.VerifyHMACResponse, error) {
	return nil, nil
}

func (m *mockCertClient) GenerateRandom(context.Context, *transport.GenerateRandomRequest) (*transport.GenerateRandomResponse, error) {
	return nil, nil
}

func (m *mockCertClient) Hash(context.Context, *transport.HashRequest) (*transport.HashResponse, error) {
	return nil, nil
}
