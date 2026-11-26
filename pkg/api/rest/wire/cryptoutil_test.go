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
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// cryptoUtilityCall is one CryptoUtilityClient verb: call sends req, and
// nilCall sends a nil request of the same type.
type cryptoUtilityCall struct {
	name     string
	req      any
	call     func(CryptoUtilityClient) (any, error)
	nilCall  func(CryptoUtilityClient) (any, error)
	path     string
	response string
	want     any
}

// cryptoUtilityCalls lists every CryptoUtilityClient verb with a request
// whose key ID needs escaping, the route it must reach, and a response with
// the value it must decode to.
func cryptoUtilityCalls(ctx context.Context) []cryptoUtilityCall {
	rewrap := &transport.RewrapRequest{Source: &transport.DecryptRequest{}, TargetKeyID: "t", TargetBackend: "pkcs11"}
	encrypt := &transport.EncryptBatchRequest{Backend: "software", KeyID: "a/b", Items: []transport.EncryptBatchItem{{Plaintext: []byte("p")}}}
	decrypt := &transport.DecryptBatchRequest{Backend: "software", KeyID: "a/b", Items: []transport.DecryptBatchItem{{Ciphertext: []byte("c")}}}
	dataKey := &transport.GenerateDataKeyRequest{Backend: "software", KeyID: "a/b", KeySize: 16}
	hmac := &transport.GenerateHMACRequest{Backend: "software", KeyID: "a/b", Data: []byte("d"), Hash: "SHA-384"}
	verify := &transport.VerifyHMACRequest{Backend: "software", KeyID: "a/b", Data: []byte("d"), MAC: []byte("m"), KeyVersion: 2}
	random := &transport.GenerateRandomRequest{Length: 8}
	hash := &transport.HashRequest{Data: []byte("d"), Hash: "SHA-512"}

	return []cryptoUtilityCall{
		{"rewrap", rewrap,
			func(c CryptoUtilityClient) (any, error) { return c.Rewrap(ctx, rewrap) },
			func(c CryptoUtilityClient) (any, error) { return c.Rewrap(ctx, nil) },
			"/api/v1/keys/rewrap", `{"source_key_version":3}`,
			&transport.RewrapResponse{SourceKeyVersion: 3}},
		{"encrypt-batch", encrypt,
			func(c CryptoUtilityClient) (any, error) { return c.EncryptBatch(ctx, encrypt) },
			func(c CryptoUtilityClient) (any, error) { return c.EncryptBatch(ctx, nil) },
			"/api/v1/keys/a%2Fb/encrypt-batch", `{"results":[{"error":"too long"}]}`,
			&transport.EncryptBatchResponse{Results: []transport.EncryptBatchResult{{Error: "too long"}}}},
		{"decrypt-batch", decrypt,
			func(c CryptoUtilityClient) (any, error) { return c.DecryptBatch(ctx, decrypt) },
			func(c CryptoUtilityClient) (any, error) { return c.DecryptBatch(ctx, nil) },
			"/api/v1/keys/a%2Fb/decrypt-batch", `{"results":[{"plaintext":"cA==","key_version":1}]}`,
			&transport.DecryptBatchResponse{Results: []transport.DecryptBatchResult{{Plaintext: []byte("p"), KeyVersion: 1}}}},
		{"data-key", dataKey,
			func(c CryptoUtilityClient) (any, error) { return c.GenerateDataKey(ctx, dataKey) },
			func(c CryptoUtilityClient) (any, error) { return c.GenerateDataKey(ctx, nil) },
			"/api/v1/keys/a%2Fb/data-key", `{"plaintext":"aw=="}`,
			&transport.GenerateDataKeyResponse{Plaintext: []byte("k")}},
		{"wrapped-data-key", dataKey,
			func(c CryptoUtilityClient) (any, error) { return c.GenerateWrappedDataKey(ctx, dataKey) },
			func(c CryptoUtilityClient) (any, error) { return c.GenerateWrappedDataKey(ctx, nil) },
			"/api/v1/keys/a%2Fb/wrapped-data-key", `{"wrapped":{}}`,
			&transport.GenerateWrappedDataKeyResponse{Wrapped: &transport.EncryptResponse{}}},
		{"hmac", hmac,
			func(c CryptoUtilityClient) (any, error) { return c.GenerateHMAC(ctx, hmac) },
			func(c CryptoUtilityClient) (any, error) { return c.GenerateHMAC(ctx, nil) },
			"/api/v1/keys/a%2Fb/hmac", `{"mac":"bQ==","key_version":2,"hash":"SHA-384"}`,
			&transport.GenerateHMACResponse{MAC: []byte("m"), KeyVersion: 2, Hash: "SHA-384"}},
		{"hmac-verify", verify,
			func(c CryptoUtilityClient) (any, error) { return c.VerifyHMAC(ctx, verify) },
			func(c CryptoUtilityClient) (any, error) { return c.VerifyHMAC(ctx, nil) },
			"/api/v1/keys/a%2Fb/hmac/verify", `{"valid":true,"key_version":2}`,
			&transport.VerifyHMACResponse{Valid: true, KeyVersion: 2}},
		{"random", random,
			func(c CryptoUtilityClient) (any, error) { return c.GenerateRandom(ctx, random) },
			func(c CryptoUtilityClient) (any, error) { return c.GenerateRandom(ctx, nil) },
			"/api/v1/random", `{"random":"cg=="}`,
			&transport.GenerateRandomResponse{Random: []byte("r")}},
		{"hash", hash,
			func(c CryptoUtilityClient) (any, error) { return c.Hash(ctx, hash) },
			func(c CryptoUtilityClient) (any, error) { return c.Hash(ctx, nil) },
			"/api/v1/hash", `{"digest":"ZA==","hash":"SHA-512"}`,
			&transport.HashResponse{Digest: []byte("d"), Hash: "SHA-512"}},
	}
}

// jsonMap is v as the recordingRequester records a request body.
func jsonMap(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	return m
}

// TestKeyActionPath proves the key ID is escaped as one path segment and
// the action is appended as is.
func TestKeyActionPath(t *testing.T) {
	assert.Equal(t, "/api/v1/keys/a%2Fb%20c/hmac/verify", KeyActionPath("a/b c", VerifyHMACAction))
	assert.Equal(t, "/api/v1/keys/k/data-key", KeyActionPath("k", DataKeyAction))
}

// TestCryptoUtilityClient_Routes proves every verb POSTs its request as the
// body to the route the server registers, and returns the response decoded
// into its transport type.
func TestCryptoUtilityClient_Routes(t *testing.T) {
	for _, tt := range cryptoUtilityCalls(context.Background()) {
		t.Run(tt.name, func(t *testing.T) {
			rec := &recordingRequester{response: tt.response}
			got, err := tt.call(CryptoUtilityClient{Do: rec.do})
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)

			sent := rec.last()
			assert.Equal(t, http.MethodPost, sent.method)
			assert.Equal(t, tt.path, sent.path)
			assert.Equal(t, jsonMap(t, tt.req), sent.body)
		})
	}
}

// TestCryptoUtilityClient_Errors proves a nil request is refused before any
// request, and a failed request and an undecodable response are returned
// with no result.
func TestCryptoUtilityClient_Errors(t *testing.T) {
	for _, tt := range cryptoUtilityCalls(context.Background()) {
		t.Run(tt.name, func(t *testing.T) {
			failingRec := &recordingRequester{err: errRequestFailed}
			failing := CryptoUtilityClient{Do: failingRec.do}

			got, err := tt.nilCall(failing)
			assert.ErrorIs(t, err, ErrNilRequest)
			assert.Nil(t, got)
			assert.Empty(t, failingRec.requests, "a nil request must not be sent")

			got, err = tt.call(failing)
			assert.ErrorIs(t, err, errRequestFailed)
			assert.Nil(t, got)

			got, err = tt.call(CryptoUtilityClient{Do: (&recordingRequester{response: `{not json`}).do})
			var decodeErr *DecodeError
			assert.ErrorAs(t, err, &decodeErr)
			assert.Nil(t, got)
		})
	}
}
