// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmsmcp "github.com/jeremyhahn/go-xkms/pkg/api/mcp"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// wrappingKeyDER returns a DER-encoded PKIX public key, the encoding
// transport.WrapKeyRequest.WrappingPublicKey and UnwrapKeyRequest carry.
func wrappingKeyDER(t *testing.T) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	return der
}

// requirePEMCarriesDER asserts that pemText is a PEM block whose payload is
// exactly wantDER and which parses as a PKIX public key.
//
// This is the assertion that matters for go-xkms#255: the transport request
// carries DER bytes while the MCP params carry PEM text, so aligning the JSON
// tag names alone is not enough. A []byte assigned straight into a string field
// marshals as base64, which is non-empty and looks fine until the handler calls
// pem.Decode on it and gets nil. Asserting the decoded value, rather than that
// the field is set, is what separates the two.
func requirePEMCarriesDER(t *testing.T, pemText string, wantDER []byte) {
	t.Helper()

	require.NotEmpty(t, pemText, "the wrapping public key did not reach the handler at all")

	block, rest := pem.Decode([]byte(pemText))
	require.NotNil(t, block,
		"the wrapping public key is not PEM; the handler calls pem.Decode on it and would get nil. Got: %q", pemText)
	assert.Empty(t, rest, "trailing data after the PEM block")
	assert.Equal(t, wantDER, block.Bytes, "the PEM block does not carry the DER that was sent")

	_, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err, "the handler parses this with x509.ParsePKIXPublicKey")
}

// captureParams runs fn against a mock MCP server and returns the raw params
// JSON the transport put on the wire.
func captureParams(t *testing.T, result interface{}, fn func(tr *Transport) error) json.RawMessage {
	t.Helper()

	var captured json.RawMessage
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		if req.Method == "health" {
			data, _ := json.Marshal(map[string]string{"status": "ok"})
			return jsonrpcResponse{Result: data}
		}
		captured = req.Params
		data, _ := json.Marshal(result)
		return jsonrpcResponse{Result: data}
	})
	defer cleanup()

	tr := connectToMockServer(t, addr)
	defer tr.Close()

	require.NoError(t, fn(tr))
	require.NotEmpty(t, captured, "no params reached the server")
	return captured
}

// TestWrapKey_ParamsReachTheHandlerStruct is the regression for the WrapKey
// half of go-xkms#255. Transport.WrapKey marshalled a transport.WrapKeyRequest,
// whose wrapping key is "wrapping_public_key" holding DER bytes, while the
// handler decodes xkmsmcp.WrapKeyParams, whose field is
// "wrapping_public_key_pem" holding PEM text. WrappingPublicKeyPEM was
// therefore always "", and handleWrapKey refuses with "invalid wrapping public
// key PEM". Backend and KeySpec were dropped with it.
func TestWrapKey_ParamsReachTheHandlerStruct(t *testing.T) {
	der := wrappingKeyDER(t)
	material := []byte{0x01, 0x02, 0x03, 0x04}

	raw := captureParams(t, xkmsmcp.WrapKeyResult{WrappedKey: []byte("w")}, func(tr *Transport) error {
		_, err := tr.WrapKey(context.Background(), &transport.WrapKeyRequest{
			Backend:           "software",
			KeyMaterial:       material,
			Algorithm:         "RSAES_OAEP_SHA_256",
			WrappingPublicKey: der,
			ImportToken:       []byte("token"),
			KeySpec:           "RSA_2048",
		})
		return err
	})

	var params xkmsmcp.WrapKeyParams
	require.NoError(t, json.Unmarshal(raw, &params))

	requirePEMCarriesDER(t, params.WrappingPublicKeyPEM, der)
	assert.Equal(t, material, params.KeyMaterial)
	assert.Equal(t, "RSAES_OAEP_SHA_256", params.Algorithm)
	assert.Equal(t, []byte("token"), params.ImportToken)
	assert.Equal(t, "software", params.Backend, "backend must reach the handler so it does not silently use the default")
	assert.Equal(t, "RSA_2048", params.KeySpec, "key_spec is load-bearing for key-spec aware backends such as AWS KMS")
}

// TestUnwrapKey_ParamsReachTheHandlerStruct is the regression for the
// UnwrapKey half of go-xkms#255 -- character for character the go-xkms#159
// bug: the request names the material "wrapped_key_material", the params name
// it "wrapped_key", so WrappedKey arrived nil on every call and the handler
// refuses with "wrapped_key is required".
func TestUnwrapKey_ParamsReachTheHandlerStruct(t *testing.T) {
	der := wrappingKeyDER(t)
	wrappedMaterial := []byte{0xAA, 0xBB, 0xCC}

	raw := captureParams(t, xkmsmcp.UnwrapKeyResult{KeyMaterial: []byte("k")}, func(tr *Transport) error {
		_, err := tr.UnwrapKey(context.Background(), &transport.UnwrapKeyRequest{
			Backend:            "software",
			WrappedKeyMaterial: wrappedMaterial,
			Algorithm:          "RSAES_OAEP_SHA_256",
			ImportToken:        []byte("token"),
			WrappingPublicKey:  der,
			KeySpec:            "RSA_2048",
			Metadata:           map[string]string{"origin": "test"},
		})
		return err
	})

	var params xkmsmcp.UnwrapKeyParams
	require.NoError(t, json.Unmarshal(raw, &params))

	assert.Equal(t, wrappedMaterial, params.WrappedKey,
		"the wrapped key material must reach the handler; this is the go-xkms#159 bug repeated")
	requirePEMCarriesDER(t, params.WrappingPublicKey, der)
	assert.Equal(t, "RSAES_OAEP_SHA_256", params.Algorithm)
	assert.Equal(t, []byte("token"), params.ImportToken)
	assert.Equal(t, map[string]string{"origin": "test"}, params.Metadata)
	assert.Equal(t, "software", params.Backend)
	assert.Equal(t, "RSA_2048", params.KeySpec)
}

// TestExportKey_ParamsReachTheHandlerStruct covers the one op the audit found
// already sound, so that a later edit cannot quietly break it.
func TestExportKey_ParamsReachTheHandlerStruct(t *testing.T) {
	raw := captureParams(t, xkmsmcp.ExportKeyResult{WrappedKey: []byte("w")}, func(tr *Transport) error {
		_, err := tr.ExportKey(context.Background(), &transport.ExportKeyRequest{
			Backend:   "software",
			KeyID:     "exported.example",
			Algorithm: "RSAES_OAEP_SHA_256",
		})
		return err
	})

	var params xkmsmcp.ExportKeyParams
	require.NoError(t, json.Unmarshal(raw, &params))

	assert.Equal(t, "software", params.Backend)
	assert.Equal(t, "exported.example", params.KeyID)
	assert.Equal(t, "RSAES_OAEP_SHA_256", params.Algorithm)
}

// TestCopyKey_ParamsReachTheHandlerStruct covers copy. Every field the request
// can express must survive; the two the params struct has and the request does
// not (hash, aes_key_size) are go-xkms#155 and are not addressed here.
// KeyType, KeySize and Curve used to be among those fields too; they were
// removed from both structs because the service ignores them outright
// (go-xkms#1223), so there is nothing left for this test to assert about them.
func TestCopyKey_ParamsReachTheHandlerStruct(t *testing.T) {
	raw := captureParams(t, xkmsmcp.CopyKeyResult{Success: true}, func(tr *Transport) error {
		_, err := tr.CopyKey(context.Background(), &transport.CopyKeyRequest{
			SourceBackend: "software",
			SourceKeyID:   "src.example",
			DestBackend:   "pkcs11",
			DestKeyID:     "dst.example",
			Algorithm:     "RSAES_OAEP_SHA_256",
		})
		return err
	})

	var params xkmsmcp.CopyKeyParams
	require.NoError(t, json.Unmarshal(raw, &params))

	assert.Equal(t, "software", params.SourceBackend)
	assert.Equal(t, "src.example", params.SourceKeyID)
	assert.Equal(t, "pkcs11", params.DestBackend)
	assert.Equal(t, "dst.example", params.DestKeyID)
	assert.Equal(t, "RSAES_OAEP_SHA_256", params.Algorithm)
}
