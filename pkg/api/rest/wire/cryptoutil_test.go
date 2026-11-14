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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// route is one client call and the request it must send.
type route struct {
	name   string
	call   func(context.Context) error
	method string
	path   string
}

// wireCall is one client call made with a request and with nil.
type wireCall struct {
	name            string
	withReq, nilReq func(context.Context) error
	decodes         bool
}

// assertRoutes proves each call sends its method to its path.
func assertRoutes(t *testing.T, rec *recordingRequester, routes []route) {
	t.Helper()
	for _, tt := range routes {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, tt.call(context.Background()))
			got := rec.last()
			assert.Equal(t, tt.method, got.method)
			assert.Equal(t, tt.path, got.path)
		})
	}
}

// assertFailures proves each call refuses a nil request without sending
// it, returns a failed request, and reports an undecodable answer as a
// *DecodeError when the call decodes one.
func assertFailures(t *testing.T, rec *recordingRequester, calls []wireCall) {
	t.Helper()
	ctx := context.Background()
	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			rec.requests, rec.err, rec.response = nil, nil, ""
			if c.nilReq != nil {
				assert.ErrorIs(t, c.nilReq(ctx), ErrNilRequest)
				assert.Empty(t, rec.requests, "a nil request sends nothing")
			}

			rec.err = errRequestFailed
			assert.ErrorIs(t, c.withReq(ctx), errRequestFailed)

			rec.err, rec.response = nil, "{not json"
			if c.decodes {
				var decodeErr *DecodeError
				assert.ErrorAs(t, c.withReq(ctx), &decodeErr)
			} else {
				assert.NoError(t, c.withReq(ctx), "a call without an answer ignores the body")
			}
		})
	}
}

func TestCryptoUtilityClient_Routes(t *testing.T) {
	rec := &recordingRequester{response: `{}`}
	c := CryptoUtilityClient{Do: rec.do}

	assertRoutes(t, rec, []route{
		{"rewrap", func(ctx context.Context) error {
			_, err := c.Rewrap(ctx, &transport.RewrapRequest{TargetKeyID: "k2"})
			return err
		}, http.MethodPost, "/api/v1/keys/rewrap"},
		{"encrypt batch", func(ctx context.Context) error {
			_, err := c.EncryptBatch(ctx, &transport.EncryptBatchRequest{KeyID: "a b"})
			return err
		}, http.MethodPost, "/api/v1/keys/a%20b/encrypt-batch"},
		{"decrypt batch", func(ctx context.Context) error {
			_, err := c.DecryptBatch(ctx, &transport.DecryptBatchRequest{KeyID: "k"})
			return err
		}, http.MethodPost, "/api/v1/keys/k/decrypt-batch"},
		{"data key", func(ctx context.Context) error {
			_, err := c.GenerateDataKey(ctx, &transport.GenerateDataKeyRequest{KeyID: "k"})
			return err
		}, http.MethodPost, "/api/v1/keys/k/data-key"},
		{"wrapped data key", func(ctx context.Context) error {
			_, err := c.GenerateWrappedDataKey(ctx, &transport.GenerateDataKeyRequest{KeyID: "k"})
			return err
		}, http.MethodPost, "/api/v1/keys/k/wrapped-data-key"},
		{"hmac", func(ctx context.Context) error {
			_, err := c.GenerateHMAC(ctx, &transport.GenerateHMACRequest{KeyID: "k"})
			return err
		}, http.MethodPost, "/api/v1/keys/k/hmac"},
		{"verify hmac", func(ctx context.Context) error {
			_, err := c.VerifyHMAC(ctx, &transport.VerifyHMACRequest{KeyID: "k"})
			return err
		}, http.MethodPost, "/api/v1/keys/k/hmac/verify"},
		{"random", func(ctx context.Context) error {
			_, err := c.GenerateRandom(ctx, &transport.GenerateRandomRequest{Length: 32})
			return err
		}, http.MethodPost, "/api/v1/random"},
		{"hash", func(ctx context.Context) error {
			_, err := c.Hash(ctx, &transport.HashRequest{Data: []byte("x")})
			return err
		}, http.MethodPost, "/api/v1/hash"},
	})
}

// TestCryptoUtilityClient_Bodies proves the request goes out as the JSON the
// server decodes and the answer comes back decoded.
func TestCryptoUtilityClient_Bodies(t *testing.T) {
	rec := &recordingRequester{response: `{"valid":true,"key_version":3}`}
	c := CryptoUtilityClient{Do: rec.do}

	verified, err := c.VerifyHMAC(context.Background(), &transport.VerifyHMACRequest{
		Backend: "software", KeyID: "k", Data: []byte("d"), MAC: []byte("m"), Hash: "SHA-256",
	})
	require.NoError(t, err)
	assert.Equal(t, &transport.VerifyHMACResponse{Valid: true, KeyVersion: 3}, verified)
	assert.Equal(t, map[string]any{
		"backend": "software", "key_id": "k", "data": "ZA==", "mac": "bQ==", "hash": "SHA-256",
	}, rec.last().body)

	rec.response = `{"digest":"q80=","hash":"SHA-256"}`
	digest, err := c.Hash(context.Background(), &transport.HashRequest{Data: []byte("x")})
	require.NoError(t, err)
	assert.Equal(t, &transport.HashResponse{Digest: []byte{0xab, 0xcd}, Hash: "SHA-256"}, digest)

	rec.response = `{"random":"AQID"}`
	random, err := c.GenerateRandom(context.Background(), &transport.GenerateRandomRequest{Length: 3})
	require.NoError(t, err)
	assert.Equal(t, []byte{1, 2, 3}, random.Random)
	assert.Equal(t, map[string]any{"length": 3.0}, rec.last().body)
}

func TestCryptoUtilityClient_Failures(t *testing.T) {
	rec := &recordingRequester{}
	c := CryptoUtilityClient{Do: rec.do}
	assertFailures(t, rec, []wireCall{
		{"rewrap",
			func(ctx context.Context) error { _, err := c.Rewrap(ctx, &transport.RewrapRequest{}); return err },
			func(ctx context.Context) error { _, err := c.Rewrap(ctx, nil); return err }, true},
		{"encrypt batch",
			func(ctx context.Context) error {
				_, err := c.EncryptBatch(ctx, &transport.EncryptBatchRequest{KeyID: "k"})
				return err
			},
			func(ctx context.Context) error { _, err := c.EncryptBatch(ctx, nil); return err }, true},
		{"decrypt batch",
			func(ctx context.Context) error {
				_, err := c.DecryptBatch(ctx, &transport.DecryptBatchRequest{KeyID: "k"})
				return err
			},
			func(ctx context.Context) error { _, err := c.DecryptBatch(ctx, nil); return err }, true},
		{"data key",
			func(ctx context.Context) error {
				_, err := c.GenerateDataKey(ctx, &transport.GenerateDataKeyRequest{KeyID: "k"})
				return err
			},
			func(ctx context.Context) error { _, err := c.GenerateDataKey(ctx, nil); return err }, true},
		{"wrapped data key",
			func(ctx context.Context) error {
				_, err := c.GenerateWrappedDataKey(ctx, &transport.GenerateDataKeyRequest{KeyID: "k"})
				return err
			},
			func(ctx context.Context) error { _, err := c.GenerateWrappedDataKey(ctx, nil); return err }, true},
		{"hmac",
			func(ctx context.Context) error {
				_, err := c.GenerateHMAC(ctx, &transport.GenerateHMACRequest{KeyID: "k"})
				return err
			},
			func(ctx context.Context) error { _, err := c.GenerateHMAC(ctx, nil); return err }, true},
		{"verify hmac",
			func(ctx context.Context) error {
				_, err := c.VerifyHMAC(ctx, &transport.VerifyHMACRequest{KeyID: "k"})
				return err
			},
			func(ctx context.Context) error { _, err := c.VerifyHMAC(ctx, nil); return err }, true},
		{"random",
			func(ctx context.Context) error {
				_, err := c.GenerateRandom(ctx, &transport.GenerateRandomRequest{})
				return err
			},
			func(ctx context.Context) error { _, err := c.GenerateRandom(ctx, nil); return err }, true},
		{"hash",
			func(ctx context.Context) error { _, err := c.Hash(ctx, &transport.HashRequest{}); return err },
			func(ctx context.Context) error { _, err := c.Hash(ctx, nil); return err }, true},
	})
}

func TestSigningKeyClient(t *testing.T) {
	rec := &recordingRequester{response: `{}`}
	c := SigningKeyClient{Do: rec.do}

	// A repository path holds slashes, so it travels in the query.
	assertRoutes(t, rec, []route{
		{"set", func(ctx context.Context) error {
			_, err := c.SetSigningKeyBinding(ctx, &transport.SetSigningKeyBindingRequest{})
			return err
		}, http.MethodPut, "/api/v1/attestation/signing-keys"},
		{"get", func(ctx context.Context) error {
			_, err := c.GetSigningKeyBinding(ctx, &transport.GetSigningKeyBindingRequest{Repository: "org/app"})
			return err
		}, http.MethodGet, "/api/v1/attestation/signing-keys/binding?repository=org%2Fapp"},
		{"list", func(ctx context.Context) error {
			_, err := c.ListSigningKeyBindings(ctx)
			return err
		}, http.MethodGet, "/api/v1/attestation/signing-keys"},
		{"delete", func(ctx context.Context) error {
			return c.DeleteSigningKeyBinding(ctx, &transport.DeleteSigningKeyBindingRequest{Repository: "org/app"})
		}, http.MethodDelete, "/api/v1/attestation/signing-keys/binding?repository=org%2Fapp"},
		{"resolve", func(ctx context.Context) error {
			_, err := c.ResolveSigningKey(ctx, &transport.ResolveSigningKeyRequest{Repository: "org/app"})
			return err
		}, http.MethodGet, "/api/v1/attestation/signing-keys/resolve?repository=org%2Fapp"},
	})

	assertFailures(t, rec, []wireCall{
		{"set",
			func(ctx context.Context) error {
				_, err := c.SetSigningKeyBinding(ctx, &transport.SetSigningKeyBindingRequest{})
				return err
			},
			func(ctx context.Context) error { _, err := c.SetSigningKeyBinding(ctx, nil); return err }, true},
		{"get",
			func(ctx context.Context) error {
				_, err := c.GetSigningKeyBinding(ctx, &transport.GetSigningKeyBindingRequest{})
				return err
			},
			func(ctx context.Context) error { _, err := c.GetSigningKeyBinding(ctx, nil); return err }, true},
		{"list",
			func(ctx context.Context) error { _, err := c.ListSigningKeyBindings(ctx); return err },
			nil, true},
		{"delete",
			func(ctx context.Context) error {
				return c.DeleteSigningKeyBinding(ctx, &transport.DeleteSigningKeyBindingRequest{})
			},
			func(ctx context.Context) error { return c.DeleteSigningKeyBinding(ctx, nil) }, false},
		{"resolve",
			func(ctx context.Context) error {
				_, err := c.ResolveSigningKey(ctx, &transport.ResolveSigningKeyRequest{})
				return err
			},
			func(ctx context.Context) error { _, err := c.ResolveSigningKey(ctx, nil); return err }, true},
	})
}

func TestTrustRootClient(t *testing.T) {
	assert.Equal(t, "/api/v1/trust-roots/a%2Fb", TrustRootPath("a/b"))
	assert.Equal(t, "/api/v1/trust-roots/ab/quarantine", TrustRootPath("ab", "quarantine"))

	rec := &recordingRequester{response: `{}`}
	c := TrustRootClient{Do: rec.do}
	req := &transport.TrustRootRequest{Fingerprint: "ab12"}

	assertRoutes(t, rec, []route{
		{"list all", func(ctx context.Context) error {
			_, err := c.TrustRootList(ctx, &transport.TrustRootListRequest{})
			return err
		}, http.MethodGet, "/api/v1/trust-roots"},
		{"list purpose", func(ctx context.Context) error {
			_, err := c.TrustRootList(ctx, &transport.TrustRootListRequest{Purpose: "tpm-manufacturer"})
			return err
		}, http.MethodGet, "/api/v1/trust-roots?purpose=tpm-manufacturer"},
		{"get", func(ctx context.Context) error { _, err := c.TrustRootGet(ctx, req); return err },
			http.MethodGet, "/api/v1/trust-roots/ab12"},
		{"import", func(ctx context.Context) error {
			_, err := c.TrustRootImport(ctx, &transport.TrustRootImportRequest{PEM: "pem"})
			return err
		}, http.MethodPost, "/api/v1/trust-roots"},
		{"quarantine", func(ctx context.Context) error { _, err := c.TrustRootQuarantine(ctx, req); return err },
			http.MethodPost, "/api/v1/trust-roots/ab12/quarantine"},
		{"remove", func(ctx context.Context) error { return c.TrustRootRemove(ctx, req) },
			http.MethodDelete, "/api/v1/trust-roots/ab12"},
	})

	rec.response = `{"fingerprint":"ab12","purpose":"synced"}`
	root, err := c.TrustRootQuarantine(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, &transport.TrustRoot{Fingerprint: "ab12", Purpose: "synced"}, root)

	assertFailures(t, rec, []wireCall{
		{"list",
			func(ctx context.Context) error {
				_, err := c.TrustRootList(ctx, &transport.TrustRootListRequest{})
				return err
			},
			func(ctx context.Context) error { _, err := c.TrustRootList(ctx, nil); return err }, true},
		{"get",
			func(ctx context.Context) error { _, err := c.TrustRootGet(ctx, req); return err },
			func(ctx context.Context) error { _, err := c.TrustRootGet(ctx, nil); return err }, true},
		{"import",
			func(ctx context.Context) error {
				_, err := c.TrustRootImport(ctx, &transport.TrustRootImportRequest{})
				return err
			},
			func(ctx context.Context) error { _, err := c.TrustRootImport(ctx, nil); return err }, true},
		{"quarantine",
			func(ctx context.Context) error { _, err := c.TrustRootQuarantine(ctx, req); return err },
			func(ctx context.Context) error { _, err := c.TrustRootQuarantine(ctx, nil); return err }, true},
		{"remove",
			func(ctx context.Context) error { return c.TrustRootRemove(ctx, req) },
			func(ctx context.Context) error { return c.TrustRootRemove(ctx, nil) }, false},
	})
}
