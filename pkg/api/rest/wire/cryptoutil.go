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

package wire

import (
	"context"
	"net/http"
	"net/url"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// Crypto utility routes that take no key ID.
const (
	// RewrapPath decrypts a ciphertext and encrypts it under a target key.
	RewrapPath = "/api/v1/keys/rewrap"

	// RandomPath returns random bytes.
	RandomPath = "/api/v1/random"

	// HashPath computes a digest.
	HashPath = "/api/v1/hash"
)

// Crypto utility actions, the last path segments of a key route.
const (
	EncryptBatchAction   = "encrypt-batch"
	DecryptBatchAction   = "decrypt-batch"
	DataKeyAction        = "data-key"
	WrappedDataKeyAction = "wrapped-data-key"
	HMACAction           = "hmac"
	VerifyHMACAction     = "hmac/verify"
)

// KeyActionPath returns the path of a crypto utility action on a key.
func KeyActionPath(keyID, action string) string {
	return "/api/v1/keys/" + url.PathEscape(keyID) + "/" + action
}

// Compile-time check that the client serves the whole crypto utility API.
var _ transport.CryptoUtilityService = CryptoUtilityClient{}

// CryptoUtilityClient serves transport.CryptoUtilityService over the REST
// routes. The REST and QUIC transports delegate to it with their own
// Requester. The server takes the tenant from the authenticated identity.
type CryptoUtilityClient struct {
	// Do performs one request against the server.
	Do Requester
}

// post sends req to path and decodes the response into out.
func (c CryptoUtilityClient) post(ctx context.Context, path string, req, out any) error {
	return callJSON(ctx, c.Do, http.MethodPost, path, req, out)
}

// Rewrap decrypts a ciphertext and encrypts it under a target key.
func (c CryptoUtilityClient) Rewrap(ctx context.Context, req *transport.RewrapRequest) (*transport.RewrapResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.RewrapResponse
	if err := c.post(ctx, RewrapPath, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// EncryptBatch encrypts a batch of plaintexts with one key.
func (c CryptoUtilityClient) EncryptBatch(ctx context.Context, req *transport.EncryptBatchRequest) (*transport.EncryptBatchResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.EncryptBatchResponse
	if err := c.post(ctx, KeyActionPath(req.KeyID, EncryptBatchAction), req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DecryptBatch decrypts a batch of ciphertexts with one key.
func (c CryptoUtilityClient) DecryptBatch(ctx context.Context, req *transport.DecryptBatchRequest) (*transport.DecryptBatchResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.DecryptBatchResponse
	if err := c.post(ctx, KeyActionPath(req.KeyID, DecryptBatchAction), req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GenerateDataKey returns a data key in plaintext and wrapped.
func (c CryptoUtilityClient) GenerateDataKey(ctx context.Context, req *transport.GenerateDataKeyRequest) (*transport.GenerateDataKeyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.GenerateDataKeyResponse
	if err := c.post(ctx, KeyActionPath(req.KeyID, DataKeyAction), req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GenerateWrappedDataKey returns a data key only wrapped.
func (c CryptoUtilityClient) GenerateWrappedDataKey(ctx context.Context, req *transport.GenerateDataKeyRequest) (*transport.GenerateWrappedDataKeyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.GenerateWrappedDataKeyResponse
	if err := c.post(ctx, KeyActionPath(req.KeyID, WrappedDataKeyAction), req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GenerateHMAC computes an HMAC with a symmetric key.
func (c CryptoUtilityClient) GenerateHMAC(ctx context.Context, req *transport.GenerateHMACRequest) (*transport.GenerateHMACResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.GenerateHMACResponse
	if err := c.post(ctx, KeyActionPath(req.KeyID, HMACAction), req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// VerifyHMAC verifies an HMAC with a symmetric key.
func (c CryptoUtilityClient) VerifyHMAC(ctx context.Context, req *transport.VerifyHMACRequest) (*transport.VerifyHMACResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.VerifyHMACResponse
	if err := c.post(ctx, KeyActionPath(req.KeyID, VerifyHMACAction), req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GenerateRandom returns random bytes.
func (c CryptoUtilityClient) GenerateRandom(ctx context.Context, req *transport.GenerateRandomRequest) (*transport.GenerateRandomResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.GenerateRandomResponse
	if err := c.post(ctx, RandomPath, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Hash computes a digest.
func (c CryptoUtilityClient) Hash(ctx context.Context, req *transport.HashRequest) (*transport.HashResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.HashResponse
	if err := c.post(ctx, HashPath, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
