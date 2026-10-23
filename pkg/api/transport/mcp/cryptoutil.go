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

package mcp

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// cryptoUtilityCall sends one crypto utility RPC and decodes its result.
func cryptoUtilityCall[T any](ctx context.Context, t *Transport, method string, req any) (*T, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var result T
	if err := t.rpcCall(ctx, method, req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Rewrap decrypts a ciphertext under its key and encrypts it under a target
// key on the server.
func (t *Transport) Rewrap(ctx context.Context, req *transport.RewrapRequest) (*transport.RewrapResponse, error) {
	return cryptoUtilityCall[transport.RewrapResponse](ctx, t, "xkms.rewrap", req)
}

// EncryptBatch encrypts a batch of plaintexts with one key.
func (t *Transport) EncryptBatch(ctx context.Context, req *transport.EncryptBatchRequest) (*transport.EncryptBatchResponse, error) {
	return cryptoUtilityCall[transport.EncryptBatchResponse](ctx, t, "xkms.encryptBatch", req)
}

// DecryptBatch decrypts a batch of ciphertexts with one key.
func (t *Transport) DecryptBatch(ctx context.Context, req *transport.DecryptBatchRequest) (*transport.DecryptBatchResponse, error) {
	return cryptoUtilityCall[transport.DecryptBatchResponse](ctx, t, "xkms.decryptBatch", req)
}

// GenerateDataKey returns a data key in plaintext and wrapped.
func (t *Transport) GenerateDataKey(ctx context.Context, req *transport.GenerateDataKeyRequest) (*transport.GenerateDataKeyResponse, error) {
	return cryptoUtilityCall[transport.GenerateDataKeyResponse](ctx, t, "xkms.generateDataKey", req)
}

// GenerateWrappedDataKey returns a data key only wrapped.
func (t *Transport) GenerateWrappedDataKey(ctx context.Context, req *transport.GenerateDataKeyRequest) (*transport.GenerateWrappedDataKeyResponse, error) {
	return cryptoUtilityCall[transport.GenerateWrappedDataKeyResponse](ctx, t, "xkms.generateWrappedDataKey", req)
}

// GenerateHMAC computes an HMAC with a symmetric key.
func (t *Transport) GenerateHMAC(ctx context.Context, req *transport.GenerateHMACRequest) (*transport.GenerateHMACResponse, error) {
	return cryptoUtilityCall[transport.GenerateHMACResponse](ctx, t, "xkms.generateHMAC", req)
}

// VerifyHMAC verifies an HMAC with a symmetric key.
func (t *Transport) VerifyHMAC(ctx context.Context, req *transport.VerifyHMACRequest) (*transport.VerifyHMACResponse, error) {
	return cryptoUtilityCall[transport.VerifyHMACResponse](ctx, t, "xkms.verifyHMAC", req)
}

// GenerateRandom returns random bytes from the server.
func (t *Transport) GenerateRandom(ctx context.Context, req *transport.GenerateRandomRequest) (*transport.GenerateRandomResponse, error) {
	return cryptoUtilityCall[transport.GenerateRandomResponse](ctx, t, "xkms.generateRandom", req)
}

// Hash computes a digest on the server.
func (t *Transport) Hash(ctx context.Context, req *transport.HashRequest) (*transport.HashResponse, error) {
	return cryptoUtilityCall[transport.HashResponse](ctx, t, "xkms.hash", req)
}
