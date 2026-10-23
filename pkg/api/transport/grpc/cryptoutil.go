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

package grpc

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/grpc/pbconv"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// cryptoUtility returns the crypto utility client for the connection.
func (t *Transport) cryptoUtility() (pbconv.CryptoUtilityClient, error) {
	if t.client == nil {
		return pbconv.CryptoUtilityClient{}, ErrNotConnected
	}
	return pbconv.CryptoUtilityClient{Client: t.client}, nil
}

// Rewrap decrypts a ciphertext under its key and encrypts it under a target
// key on the server.
func (t *Transport) Rewrap(ctx context.Context, req *transport.RewrapRequest) (*transport.RewrapResponse, error) {
	c, err := t.cryptoUtility()
	if err != nil {
		return nil, err
	}
	return c.Rewrap(ctx, req)
}

// EncryptBatch encrypts a batch of plaintexts with one key.
func (t *Transport) EncryptBatch(ctx context.Context, req *transport.EncryptBatchRequest) (*transport.EncryptBatchResponse, error) {
	c, err := t.cryptoUtility()
	if err != nil {
		return nil, err
	}
	return c.EncryptBatch(ctx, req)
}

// DecryptBatch decrypts a batch of ciphertexts with one key.
func (t *Transport) DecryptBatch(ctx context.Context, req *transport.DecryptBatchRequest) (*transport.DecryptBatchResponse, error) {
	c, err := t.cryptoUtility()
	if err != nil {
		return nil, err
	}
	return c.DecryptBatch(ctx, req)
}

// GenerateDataKey returns a data key in plaintext and wrapped.
func (t *Transport) GenerateDataKey(ctx context.Context, req *transport.GenerateDataKeyRequest) (*transport.GenerateDataKeyResponse, error) {
	c, err := t.cryptoUtility()
	if err != nil {
		return nil, err
	}
	return c.GenerateDataKey(ctx, req)
}

// GenerateWrappedDataKey returns a data key only wrapped.
func (t *Transport) GenerateWrappedDataKey(ctx context.Context, req *transport.GenerateDataKeyRequest) (*transport.GenerateWrappedDataKeyResponse, error) {
	c, err := t.cryptoUtility()
	if err != nil {
		return nil, err
	}
	return c.GenerateWrappedDataKey(ctx, req)
}

// GenerateHMAC computes an HMAC with a symmetric key.
func (t *Transport) GenerateHMAC(ctx context.Context, req *transport.GenerateHMACRequest) (*transport.GenerateHMACResponse, error) {
	c, err := t.cryptoUtility()
	if err != nil {
		return nil, err
	}
	return c.GenerateHMAC(ctx, req)
}

// VerifyHMAC verifies an HMAC with a symmetric key.
func (t *Transport) VerifyHMAC(ctx context.Context, req *transport.VerifyHMACRequest) (*transport.VerifyHMACResponse, error) {
	c, err := t.cryptoUtility()
	if err != nil {
		return nil, err
	}
	return c.VerifyHMAC(ctx, req)
}

// GenerateRandom returns random bytes from the server.
func (t *Transport) GenerateRandom(ctx context.Context, req *transport.GenerateRandomRequest) (*transport.GenerateRandomResponse, error) {
	c, err := t.cryptoUtility()
	if err != nil {
		return nil, err
	}
	return c.GenerateRandom(ctx, req)
}

// Hash computes a digest on the server.
func (t *Transport) Hash(ctx context.Context, req *transport.HashRequest) (*transport.HashResponse, error) {
	c, err := t.cryptoUtility()
	if err != nil {
		return nil, err
	}
	return c.Hash(ctx, req)
}
