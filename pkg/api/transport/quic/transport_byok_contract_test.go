// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

package quic

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	wire "github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TestByokCeremony_BodiesReachTheHandlerTypes is the QUIC half of the REST
// transport's contract test: the bodies this transport sends decode into the
// types the REST handlers decode, with the material and the wrapping key
// present, and the responses come back in the contract's shape.
func TestByokCeremony_BodiesReachTheHandlerTypes(t *testing.T) {
	var wrapBody wire.WrapKeyRequest
	var importBody wire.ImportKeyRequest
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/keys/import-params":
			json.NewEncoder(w).Encode(wire.GetImportParametersResponse{WrappingPublicKeyPEM: testWrappingPublicKeyPEM(), Algorithm: "RSAES_OAEP_SHA_256", KeySpec: "RSA_2048"})
		case "/api/v1/keys/wrap":
			require.NoError(t, json.NewDecoder(r.Body).Decode(&wrapBody))
			json.NewEncoder(w).Encode(wire.WrapKeyResponse{WrappedKey: []byte("wrapped-by-server"), Algorithm: "RSAES_OAEP_SHA_256"})
		case "/api/v1/keys/import":
			require.NoError(t, json.NewDecoder(r.Body).Decode(&importBody))
			json.NewEncoder(w).Encode(wire.ImportKeyResponse{Success: true, KeyID: importBody.KeyID})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	tr := &Transport{config: transport.DefaultConfig(), httpClient: srv.Client(), baseURL: srv.URL, connected: true}
	ctx := context.Background()

	params, err := tr.GetImportParameters(ctx, &transport.GetImportParametersRequest{Backend: "software", KeyID: "k", Algorithm: "RSAES_OAEP_SHA_256"})
	require.NoError(t, err)
	assert.NotEmpty(t, params.WrappingPublicKey, "the PEM wrapping key must come back as DER")
	assert.Equal(t, "RSA_2048", params.KeySpec)

	wrapped, err := tr.WrapKey(ctx, &transport.WrapKeyRequest{Backend: "software", KeyMaterial: []byte("material"), Algorithm: params.Algorithm, WrappingPublicKey: params.WrappingPublicKey, KeySpec: params.KeySpec})
	require.NoError(t, err)
	assert.Equal(t, []byte("material"), wrapBody.KeyMaterial)
	assert.Contains(t, wrapBody.WrappingPublicKeyPEM, "BEGIN PUBLIC KEY")
	assert.Equal(t, []byte("wrapped-by-server"), wrapped.WrappedKeyMaterial)

	imported, err := tr.ImportKey(ctx, &transport.ImportKeyRequest{Backend: "software", KeyID: "imported", KeyType: "symmetric", WrappedKeyMaterial: wrapped.WrappedKeyMaterial, Algorithm: params.Algorithm, Partition: "p1"})
	require.NoError(t, err)
	assert.True(t, imported.Success)
	assert.Equal(t, []byte("wrapped-by-server"), importBody.WrappedKey, "the material must reach the handler's field")
	assert.Equal(t, "p1", importBody.Partition)

	_, err = tr.WrapKey(ctx, &transport.WrapKeyRequest{Backend: "software", WrappingPublicKey: []byte("wpk")})
	require.ErrorIs(t, err, wire.ErrWrappingPublicKeyNotDER)
}
