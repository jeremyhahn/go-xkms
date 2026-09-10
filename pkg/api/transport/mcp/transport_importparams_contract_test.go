// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

package mcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmsmcp "github.com/jeremyhahn/go-xkms/pkg/api/mcp"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TestGetImportParameters_ParamsAndRequestAgreeOnFieldNames pins the params
// struct against the contract: every field a caller can set on the request
// has a params field of the same name, so the key type the caller declares
// is not dropped on the way to the handler.
func TestGetImportParameters_ParamsAndRequestAgreeOnFieldNames(t *testing.T) {
	notOnTheWire := map[string]bool{"tenant_id": true}
	requestTags := jsonTagSet(t, transport.GetImportParametersRequest{})
	paramsTags := jsonTagSet(t, xkmsmcp.GetImportParametersParams{})
	for tag := range requestTags {
		if notOnTheWire[tag] {
			continue
		}
		assert.Truef(t, paramsTags[tag], "transport.GetImportParametersRequest field %q has no counterpart on xkmsmcp.GetImportParametersParams", tag)
	}
	for tag := range paramsTags {
		assert.Truef(t, requestTags[tag], "params field %q has no counterpart on the request; no client of the contract can set it", tag)
	}
}

// TestGetImportParameters_KeyTypeReachesTheHandlerAndTheKeyComesBack proves
// the declared algorithm reaches the handler's params struct and the PEM
// wrapping key in the handler's result comes back as the DER the contract
// carries. Before this the transport marshalled the request and decoded the
// contract's response, so the key type went nowhere and the wrapping key came
// back empty.
func TestGetImportParameters_KeyTypeReachesTheHandlerAndTheKeyComesBack(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	expires := "2026-01-01T00:00:00Z"

	var captured xkmsmcp.GetImportParametersParams
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		if req.Method == "health" {
			data, _ := json.Marshal(map[string]string{"status": "ok"})
			return jsonrpcResponse{Result: data}
		}
		if err := json.Unmarshal(req.Params, &captured); err != nil {
			return jsonrpcResponse{ErrorText: err.Error()}
		}
		data, _ := json.Marshal(xkmsmcp.GetImportParametersResult{
			WrappingPublicKeyPEM: pemEncodePKIXPublicKey(der), ImportToken: []byte("tok"),
			Algorithm: "RSAES_OAEP_SHA_256", KeySpec: "ECC_NIST_P256", ExpiresAt: &expires,
		})
		return jsonrpcResponse{Result: data}
	})
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.GetImportParameters(context.Background(), &transport.GetImportParametersRequest{
		Backend: "software", KeyID: "k", Algorithm: "RSAES_OAEP_SHA_256", KeyType: "ecdsa", KeySize: 256, Curve: "P-256",
	})
	require.NoError(t, err)
	assert.Equal(t, "ecdsa", captured.KeyType, "the declared key type must reach the handler")
	assert.Equal(t, 256, captured.KeySize)
	assert.Equal(t, "P-256", captured.Curve)
	assert.Equal(t, der, resp.WrappingPublicKey, "the PEM wrapping key must come back as DER")
	assert.Equal(t, []byte("tok"), resp.ImportToken)
	assert.Equal(t, "ECC_NIST_P256", resp.KeySpec)
	assert.Equal(t, expires, resp.ExpiresAt)
}

// TestGetImportParameters_RefusesAResultKeyThatIsNotPEM proves a handler
// result whose wrapping key is not a PEM public key is refused with the typed
// error rather than handed to the caller as an empty or garbage key.
func TestGetImportParameters_RefusesAResultKeyThatIsNotPEM(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		if req.Method == "health" {
			data, _ := json.Marshal(map[string]string{"status": "ok"})
			return jsonrpcResponse{Result: data}
		}
		data, _ := json.Marshal(xkmsmcp.GetImportParametersResult{WrappingPublicKeyPEM: "not a key", Algorithm: "x"})
		return jsonrpcResponse{Result: data}
	})
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	_, err := tr.GetImportParameters(context.Background(), &transport.GetImportParametersRequest{Backend: "software", KeyID: "k"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrWrappingPublicKeyNotPEM), "got %v", err)

	_, err = tr.GetImportParameters(context.Background(), nil)
	assert.ErrorIs(t, err, transport.ErrInvalidRequest)
}
