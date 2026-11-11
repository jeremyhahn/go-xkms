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

package quic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// gotResponse reduces a typed call result to whether a response came back.
func gotResponse[T any](resp *T, err error) (bool, error) {
	return resp != nil, err
}

// wrapperCall is one key management or crypto utility method of the
// transport, the request it sends and the route the REST router serves it on.
type wrapperCall struct {
	name   string
	call   func(ctx context.Context, tr *Transport) (bool, error)
	method string
	path   string
}

func keyManagementAndCryptoUtilityCalls() []wrapperCall {
	km := &transport.KeyManagementRequest{Backend: "software", KeyID: "k1"}
	be := &transport.BackendRequest{Backend: "software"}
	return []wrapperCall{
		{"GetPublicKey", func(ctx context.Context, tr *Transport) (bool, error) {
			return gotResponse(tr.GetPublicKey(ctx, &transport.GetPublicKeyRequest{Backend: "software", KeyID: "k1"}))
		}, http.MethodGet, "/api/v1/keys/k1/public-key"},
		{"RevokeKey", func(ctx context.Context, tr *Transport) (bool, error) {
			return gotResponse(tr.RevokeKey(ctx, &transport.RevokeKeyRequest{Backend: "software", KeyID: "k1"}))
		}, http.MethodPost, "/api/v1/keys/k1/revoke"},
		{"UpdateKeyStatus", func(ctx context.Context, tr *Transport) (bool, error) {
			return gotResponse(tr.UpdateKeyStatus(ctx, &transport.UpdateKeyStatusRequest{Backend: "software", KeyID: "k1"}))
		}, http.MethodPost, "/api/v1/keys/k1/status"},
		{"GetKeyMetadata", func(ctx context.Context, tr *Transport) (bool, error) {
			return gotResponse(tr.GetKeyMetadata(ctx, km))
		}, http.MethodGet, "/api/v1/keys/k1/metadata"},
		{"UpdateKeyMetadata", func(ctx context.Context, tr *Transport) (bool, error) {
			return gotResponse(tr.UpdateKeyMetadata(ctx, &transport.UpdateKeyMetadataRequest{Backend: "software", KeyID: "k1"}))
		}, http.MethodPut, "/api/v1/keys/k1/metadata"},
		{"SetKeyPolicy", func(ctx context.Context, tr *Transport) (bool, error) {
			return gotResponse(tr.SetKeyPolicy(ctx, &transport.SetKeyPolicyRequest{Backend: "software", KeyID: "k1"}))
		}, http.MethodPut, "/api/v1/keys/k1/policy"},
		{"GetKeyPolicy", func(ctx context.Context, tr *Transport) (bool, error) {
			return gotResponse(tr.GetKeyPolicy(ctx, km))
		}, http.MethodGet, "/api/v1/keys/k1/policy"},
		{"DeleteKeyPolicy", func(ctx context.Context, tr *Transport) (bool, error) {
			return gotResponse(tr.DeleteKeyPolicy(ctx, km))
		}, http.MethodDelete, "/api/v1/keys/k1/policy"},
		{"SetKeyRotationPolicy", func(ctx context.Context, tr *Transport) (bool, error) {
			return gotResponse(tr.SetKeyRotationPolicy(ctx, &transport.SetKeyRotationPolicyRequest{Backend: "software", KeyID: "k1"}))
		}, http.MethodPut, "/api/v1/keys/k1/rotation-policy"},
		{"GetKeyRotationPolicy", func(ctx context.Context, tr *Transport) (bool, error) {
			return gotResponse(tr.GetKeyRotationPolicy(ctx, km))
		}, http.MethodGet, "/api/v1/keys/k1/rotation-policy"},
		{"DeleteKeyRotationPolicy", func(ctx context.Context, tr *Transport) (bool, error) {
			return gotResponse(tr.DeleteKeyRotationPolicy(ctx, km))
		}, http.MethodDelete, "/api/v1/keys/k1/rotation-policy"},
		{"GetSupportedAlgorithms", func(ctx context.Context, tr *Transport) (bool, error) {
			return gotResponse(tr.GetSupportedAlgorithms(ctx, be))
		}, http.MethodGet, "/api/v1/backend/algorithms"},
		{"BackendStatus", func(ctx context.Context, tr *Transport) (bool, error) {
			return gotResponse(tr.BackendStatus(ctx, be))
		}, http.MethodGet, "/api/v1/backend/status"},
		{"BackendTest", func(ctx context.Context, tr *Transport) (bool, error) {
			return gotResponse(tr.BackendTest(ctx, be))
		}, http.MethodPost, "/api/v1/backend/test"},
		{"SetKeySafety", func(ctx context.Context, tr *Transport) (bool, error) {
			return gotResponse(tr.SetKeySafety(ctx, &transport.SetKeySafetyRequest{Backend: "software", KeyID: "k1", MaxOperations: 1}))
		}, http.MethodPut, "/api/v1/keys/k1/safety"},
		{"ClearKeySafety", func(ctx context.Context, tr *Transport) (bool, error) {
			return gotResponse(tr.ClearKeySafety(ctx, km))
		}, http.MethodDelete, "/api/v1/keys/k1/safety"},
		{"SafetyCheck", func(ctx context.Context, tr *Transport) (bool, error) {
			return gotResponse(tr.SafetyCheck(ctx, &transport.SafetyCheckRequest{}))
		}, http.MethodGet, "/api/v1/safety/check"},
		{"SafetyReport", func(ctx context.Context, tr *Transport) (bool, error) {
			return gotResponse(tr.SafetyReport(ctx, &transport.SafetyReportRequest{}))
		}, http.MethodGet, "/api/v1/safety/report"},
		{"Rewrap", func(ctx context.Context, tr *Transport) (bool, error) {
			return gotResponse(tr.Rewrap(ctx, &transport.RewrapRequest{Source: &transport.DecryptRequest{KeyID: "k1"}, TargetKeyID: "k2"}))
		}, http.MethodPost, "/api/v1/keys/rewrap"},
		{"EncryptBatch", func(ctx context.Context, tr *Transport) (bool, error) {
			return gotResponse(tr.EncryptBatch(ctx, &transport.EncryptBatchRequest{Backend: "software", KeyID: "k1"}))
		}, http.MethodPost, "/api/v1/keys/k1/encrypt-batch"},
		{"DecryptBatch", func(ctx context.Context, tr *Transport) (bool, error) {
			return gotResponse(tr.DecryptBatch(ctx, &transport.DecryptBatchRequest{Backend: "software", KeyID: "k1"}))
		}, http.MethodPost, "/api/v1/keys/k1/decrypt-batch"},
		{"GenerateDataKey", func(ctx context.Context, tr *Transport) (bool, error) {
			return gotResponse(tr.GenerateDataKey(ctx, &transport.GenerateDataKeyRequest{Backend: "software", KeyID: "k1"}))
		}, http.MethodPost, "/api/v1/keys/k1/data-key"},
		{"GenerateWrappedDataKey", func(ctx context.Context, tr *Transport) (bool, error) {
			return gotResponse(tr.GenerateWrappedDataKey(ctx, &transport.GenerateDataKeyRequest{Backend: "software", KeyID: "k1"}))
		}, http.MethodPost, "/api/v1/keys/k1/wrapped-data-key"},
		{"GenerateHMAC", func(ctx context.Context, tr *Transport) (bool, error) {
			return gotResponse(tr.GenerateHMAC(ctx, &transport.GenerateHMACRequest{Backend: "software", KeyID: "k1"}))
		}, http.MethodPost, "/api/v1/keys/k1/hmac"},
		{"VerifyHMAC", func(ctx context.Context, tr *Transport) (bool, error) {
			return gotResponse(tr.VerifyHMAC(ctx, &transport.VerifyHMACRequest{Backend: "software", KeyID: "k1"}))
		}, http.MethodPost, "/api/v1/keys/k1/hmac/verify"},
		{"GenerateRandom", func(ctx context.Context, tr *Transport) (bool, error) {
			return gotResponse(tr.GenerateRandom(ctx, &transport.GenerateRandomRequest{Length: 16}))
		}, http.MethodPost, "/api/v1/random"},
		{"Hash", func(ctx context.Context, tr *Transport) (bool, error) {
			return gotResponse(tr.Hash(ctx, &transport.HashRequest{Data: []byte("x")}))
		}, http.MethodPost, "/api/v1/hash"},
	}
}

// recordingTransport is a connected transport whose server records the
// method and path of each request and answers with status.
func recordingTransport(t *testing.T, status int) (tr *Transport, seen func() (string, string)) {
	t.Helper()
	var mu sync.Mutex
	var method, path string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		method, path = r.Method, r.URL.Path
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, err := w.Write([]byte(`{"key_id":"k1"}`))
		assert.NoError(t, err)
	}))
	t.Cleanup(srv.Close)
	tr = &Transport{
		config:     transport.DefaultConfig(),
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		connected:  true,
	}
	return tr, func() (string, string) {
		mu.Lock()
		defer mu.Unlock()
		return method, path
	}
}

// TestKeyManagementAndCryptoUtility_Disconnected pins that every wrapper
// refuses with ErrNotConnected, and no response, before a connection exists.
func TestKeyManagementAndCryptoUtility_Disconnected(t *testing.T) {
	tr := &Transport{config: transport.DefaultConfig()}
	for _, c := range keyManagementAndCryptoUtilityCalls() {
		t.Run(c.name, func(t *testing.T) {
			got, err := c.call(context.Background(), tr)
			require.ErrorIs(t, err, ErrNotConnected)
			assert.False(t, got)
		})
	}
}

// TestKeyManagementAndCryptoUtility_Routes pins the method and route each
// wrapper sends over the connection and that the server's answer is returned.
func TestKeyManagementAndCryptoUtility_Routes(t *testing.T) {
	for _, c := range keyManagementAndCryptoUtilityCalls() {
		t.Run(c.name, func(t *testing.T) {
			tr, seen := recordingTransport(t, http.StatusOK)
			got, err := c.call(context.Background(), tr)
			require.NoError(t, err)
			assert.True(t, got)
			method, path := seen()
			assert.Equal(t, c.method, method)
			assert.Equal(t, c.path, path)
		})
	}
}

// TestKeyManagementAndCryptoUtility_ServerError pins that a server error
// status comes back as an error with no partial response.
func TestKeyManagementAndCryptoUtility_ServerError(t *testing.T) {
	for _, c := range keyManagementAndCryptoUtilityCalls() {
		t.Run(c.name, func(t *testing.T) {
			tr, _ := recordingTransport(t, http.StatusInternalServerError)
			got, err := c.call(context.Background(), tr)
			require.Error(t, err)
			assert.False(t, got)
		})
	}
}

// TestKeyManagementAndCryptoUtility_NilRequest pins that a nil request is
// refused by the wire client before anything is sent.
func TestKeyManagementAndCryptoUtility_NilRequest(t *testing.T) {
	tr, seen := recordingTransport(t, http.StatusOK)
	_, err := tr.GetKeyMetadata(context.Background(), nil)
	require.ErrorIs(t, err, wire.ErrNilRequest)
	_, err = tr.Hash(context.Background(), nil)
	require.ErrorIs(t, err, wire.ErrNilRequest)
	method, path := seen()
	assert.Empty(t, method)
	assert.Empty(t, path)
}
