// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

package rest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	wire "github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// byokCapture is what a REST handler would decode for each ceremony call.
type byokCapture struct {
	importParams wire.GetImportParametersRequest
	wrap         wire.WrapKeyRequest
	unwrap       wire.UnwrapKeyRequest
	importKey    wire.ImportKeyRequest
}

// newByokServer decodes each ceremony body with the same types the REST
// handlers decode, and answers in the REST shape the handlers write.
func newByokServer(t *testing.T, captured *byokCapture, wrappingPEM string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		decode := func(v any) bool {
			if err := json.NewDecoder(r.Body).Decode(v); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return false
			}
			return true
		}
		switch r.URL.Path {
		case "/health":
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		case "/api/v1/keys/import-params":
			if decode(&captured.importParams) {
				json.NewEncoder(w).Encode(wire.GetImportParametersResponse{WrappingPublicKeyPEM: wrappingPEM, ImportToken: []byte("tok"), Algorithm: "RSAES_OAEP_SHA_256", KeySpec: "RSA_2048"})
			}
		case "/api/v1/keys/wrap":
			if decode(&captured.wrap) {
				json.NewEncoder(w).Encode(wire.WrapKeyResponse{WrappedKey: []byte("wrapped-by-server"), Algorithm: "RSAES_OAEP_SHA_256", Metadata: map[string]string{"k": "v"}})
			}
		case "/api/v1/keys/unwrap":
			if decode(&captured.unwrap) {
				json.NewEncoder(w).Encode(wire.UnwrapKeyResponse{KeyMaterial: []byte("unwrapped")})
			}
		case "/api/v1/keys/import":
			if decode(&captured.importKey) {
				json.NewEncoder(w).Encode(wire.ImportKeyResponse{Success: true, KeyID: captured.importKey.KeyID})
			}
		default:
			http.NotFound(w, r)
		}
	}))
}

func testWrappingKey(t *testing.T) (der []byte, pemText string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	return der, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// TestByokCeremony_BodiesReachTheHandlerTypes proves the whole ceremony over
// this transport: every body decodes into the type the REST handler decodes
// with the material and the wrapping key present, and every response comes
// back in the contract's shape. Before this the transport marshalled the
// contract struct straight onto the route, so the material arrived under a
// name the handler did not read and the wrapping key came back absent.
func TestByokCeremony_BodiesReachTheHandlerTypes(t *testing.T) {
	der, wrappingPEM := testWrappingKey(t)
	var captured byokCapture
	srv := newByokServer(t, &captured, wrappingPEM)
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()
	ctx := context.Background()

	params, err := tr.GetImportParameters(ctx, &transport.GetImportParametersRequest{Backend: "software", KeyID: "k", Algorithm: "RSAES_OAEP_SHA_256", KeyType: "symmetric", KeySize: 256})
	require.NoError(t, err)
	assert.Equal(t, der, params.WrappingPublicKey, "the PEM wrapping key must come back as DER")
	assert.Equal(t, "RSA_2048", params.KeySpec)
	assert.Equal(t, "symmetric", captured.importParams.KeyType)

	wrapped, err := tr.WrapKey(ctx, &transport.WrapKeyRequest{Backend: "software", KeyMaterial: []byte("material"), Algorithm: params.Algorithm, WrappingPublicKey: params.WrappingPublicKey, ImportToken: params.ImportToken, KeySpec: params.KeySpec})
	require.NoError(t, err)
	assert.Equal(t, []byte("material"), captured.wrap.KeyMaterial)
	assert.Contains(t, captured.wrap.WrappingPublicKeyPEM, "BEGIN PUBLIC KEY", "the wrapping key must reach the handler as PEM")
	assert.Equal(t, "RSA_2048", captured.wrap.KeySpec)
	assert.Equal(t, []byte("wrapped-by-server"), wrapped.WrappedKeyMaterial, "the wrapped material must come back under the contract's name")
	assert.Equal(t, map[string]string{"k": "v"}, wrapped.Metadata)

	unwrapped, err := tr.UnwrapKey(ctx, &transport.UnwrapKeyRequest{Backend: "software", WrappedKeyMaterial: wrapped.WrappedKeyMaterial, Algorithm: params.Algorithm, WrappingPublicKey: der, ImportToken: params.ImportToken, KeySpec: "RSA_2048", Metadata: map[string]string{"m": "1"}})
	require.NoError(t, err)
	assert.Equal(t, []byte("wrapped-by-server"), captured.unwrap.WrappedKey)
	assert.Contains(t, captured.unwrap.WrappingPublicKeyPEM, "BEGIN PUBLIC KEY")
	assert.Equal(t, map[string]string{"m": "1"}, captured.unwrap.Metadata)
	assert.Equal(t, []byte("unwrapped"), unwrapped.KeyMaterial)

	exportable := false
	imported, err := tr.ImportKey(ctx, &transport.ImportKeyRequest{Backend: "software", KeyID: "imported", KeyType: "symmetric", KeySize: 256, WrappedKeyMaterial: wrapped.WrappedKeyMaterial, Algorithm: params.Algorithm, ImportToken: params.ImportToken, Partition: "p1", Metadata: map[string]string{"origin": "test"}, Exportable: &exportable, Sensitive: true})
	require.NoError(t, err)
	assert.True(t, imported.Success)
	assert.Equal(t, []byte("wrapped-by-server"), captured.importKey.WrappedKey, "the material must reach the handler's field")
	assert.Equal(t, "p1", captured.importKey.Partition)
	assert.Equal(t, map[string]string{"origin": "test"}, captured.importKey.Metadata)
	require.NotNil(t, captured.importKey.Exportable)
	assert.False(t, *captured.importKey.Exportable)
	assert.True(t, captured.importKey.Sensitive)
}

// TestWrapKey_RefusesAWrappingKeyThatIsNotDER proves a bad wrapping key is
// refused locally, typed, before any request is sent.
func TestWrapKey_RefusesAWrappingKeyThatIsNotDER(t *testing.T) {
	var captured byokCapture
	srv := newByokServer(t, &captured, "")
	defer srv.Close()
	tr := connectFullMock(t, srv)
	defer tr.Close()

	_, err := tr.WrapKey(context.Background(), &transport.WrapKeyRequest{Backend: "software", WrappingPublicKey: []byte("wpk")})
	require.ErrorIs(t, err, wire.ErrWrappingPublicKeyNotDER)
	assert.Empty(t, captured.wrap.Backend, "nothing may be sent")
}
