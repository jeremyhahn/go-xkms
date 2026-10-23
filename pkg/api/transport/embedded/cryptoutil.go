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

// cryptoUtility returns the in-process service once the transport is
// connected.
func (t *Transport) cryptoUtility() (transport.CryptoUtilityServicer, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service, nil
}

// Rewrap decrypts a ciphertext under its key and encrypts it under a target
// key in-process.
func (t *Transport) Rewrap(ctx context.Context, req *transport.RewrapRequest) (*transport.RewrapResponse, error) {
	s, err := t.cryptoUtility()
	if err != nil {
		return nil, err
	}
	return s.Rewrap(ctx, req)
}

// EncryptBatch encrypts a batch of plaintexts with one key.
func (t *Transport) EncryptBatch(ctx context.Context, req *transport.EncryptBatchRequest) (*transport.EncryptBatchResponse, error) {
	s, err := t.cryptoUtility()
	if err != nil {
		return nil, err
	}
	return s.EncryptBatch(ctx, req)
}

// DecryptBatch decrypts a batch of ciphertexts with one key.
func (t *Transport) DecryptBatch(ctx context.Context, req *transport.DecryptBatchRequest) (*transport.DecryptBatchResponse, error) {
	s, err := t.cryptoUtility()
	if err != nil {
		return nil, err
	}
	return s.DecryptBatch(ctx, req)
}

// GenerateDataKey returns a data key in plaintext and wrapped.
func (t *Transport) GenerateDataKey(ctx context.Context, req *transport.GenerateDataKeyRequest) (*transport.GenerateDataKeyResponse, error) {
	s, err := t.cryptoUtility()
	if err != nil {
		return nil, err
	}
	return s.GenerateDataKey(ctx, req)
}

// GenerateWrappedDataKey returns a data key only wrapped.
func (t *Transport) GenerateWrappedDataKey(ctx context.Context, req *transport.GenerateDataKeyRequest) (*transport.GenerateWrappedDataKeyResponse, error) {
	s, err := t.cryptoUtility()
	if err != nil {
		return nil, err
	}
	return s.GenerateWrappedDataKey(ctx, req)
}

// GenerateHMAC computes an HMAC with a symmetric key.
func (t *Transport) GenerateHMAC(ctx context.Context, req *transport.GenerateHMACRequest) (*transport.GenerateHMACResponse, error) {
	s, err := t.cryptoUtility()
	if err != nil {
		return nil, err
	}
	return s.GenerateHMAC(ctx, req)
}

// VerifyHMAC verifies an HMAC with a symmetric key.
func (t *Transport) VerifyHMAC(ctx context.Context, req *transport.VerifyHMACRequest) (*transport.VerifyHMACResponse, error) {
	s, err := t.cryptoUtility()
	if err != nil {
		return nil, err
	}
	return s.VerifyHMAC(ctx, req)
}

// GenerateRandom returns random bytes.
func (t *Transport) GenerateRandom(ctx context.Context, req *transport.GenerateRandomRequest) (*transport.GenerateRandomResponse, error) {
	s, err := t.cryptoUtility()
	if err != nil {
		return nil, err
	}
	return s.GenerateRandom(ctx, req)
}

// Hash computes a digest.
func (t *Transport) Hash(ctx context.Context, req *transport.HashRequest) (*transport.HashResponse, error) {
	s, err := t.cryptoUtility()
	if err != nil {
		return nil, err
	}
	return s.Hash(ctx, req)
}
