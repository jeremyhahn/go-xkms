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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// wrappingKeyPEM returns a PEM-encoded PKIX public key, the encoding the wrap
// and unwrap params carry.
func wrappingKeyPEM(t *testing.T) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func wrapRequest(t *testing.T, params *WrapKeyParams) *JSONRPCRequest {
	t.Helper()

	paramsJSON, err := json.Marshal(params)
	require.NoError(t, err)
	return &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.wrapKey", Params: paramsJSON, ID: 1}
}

// TestHandler_WrapKey_HonoursTheNamedBackend proves the "backend" field added
// to WrapKeyParams in go-xkms#255 is a control and not a decoration.
//
// Carrying the field on the wire is only half the fix: before this, both wrap
// and unwrap ran against s.keystore -- the process default -- whatever the
// caller named. A test that only asserted the field arrived would have passed
// against a handler that ignored it, which is the exact failure mode go-xkms
// #160 warns about. So this asserts on the WRAP RESULT, which differs per
// backend: the fake provider returns "wrapped:"+material, while the default
// software backend performs a real RSA-OAEP wrap.
func TestHandler_WrapKey_HonoursTheNamedBackend(t *testing.T) {
	provider := newFakeIEProvider(&types.KeyAttributes{CN: "k"})
	server := newKeyOpsServer(t, map[string]types.KeyProvider{"ie-be": provider})

	material := []byte("secret-material")
	req := wrapRequest(t, &WrapKeyParams{
		KeyMaterial:          material,
		WrappingPublicKeyPEM: wrappingKeyPEM(t),
		Algorithm:            "RSAES_OAEP_SHA_256",
		Backend:              "ie-be",
	})

	result, err := server.handleWrapKey(context.Background(), req)
	require.NoError(t, err)

	wrapped, ok := result.(WrapKeyResult)
	require.True(t, ok, "unexpected result type %T", result)
	assert.Equal(t, append([]byte("wrapped:"), material...), wrapped.WrappedKey,
		"the wrap did not run on the named backend; it fell through to the default")
}

// TestHandler_WrapKey_UnnamedBackendStillUsesTheDefault guards the other
// direction: honouring the field must not break the callers that omit it.
func TestHandler_WrapKey_UnnamedBackendStillUsesTheDefault(t *testing.T) {
	provider := newFakeIEProvider(&types.KeyAttributes{CN: "k"})
	server := newKeyOpsServer(t, map[string]types.KeyProvider{"ie-be": provider})

	material := []byte("secret-material")
	req := wrapRequest(t, &WrapKeyParams{
		KeyMaterial:          material,
		WrappingPublicKeyPEM: wrappingKeyPEM(t),
		Algorithm:            "RSAES_OAEP_SHA_256",
	})

	result, err := server.handleWrapKey(context.Background(), req)
	require.NoError(t, err)

	wrapped, ok := result.(WrapKeyResult)
	require.True(t, ok, "unexpected result type %T", result)
	assert.False(t, bytes.HasPrefix(wrapped.WrappedKey, []byte("wrapped:")),
		"an unnamed backend must resolve to the default, not to a named one")
	assert.NotEmpty(t, wrapped.WrappedKey)
}

// TestHandler_WrapKey_RefusesAnUnknownBackend is the negative half. If the
// field were ignored, naming a backend that does not exist would quietly
// succeed against the default.
func TestHandler_WrapKey_RefusesAnUnknownBackend(t *testing.T) {
	provider := newFakeIEProvider(&types.KeyAttributes{CN: "k"})
	server := newKeyOpsServer(t, map[string]types.KeyProvider{"ie-be": provider})

	req := wrapRequest(t, &WrapKeyParams{
		KeyMaterial:          []byte("secret-material"),
		WrappingPublicKeyPEM: wrappingKeyPEM(t),
		Algorithm:            "RSAES_OAEP_SHA_256",
		Backend:              "no-such-backend",
	})

	_, err := server.handleWrapKey(context.Background(), req)
	require.Error(t, err, "a backend that does not exist must be refused, not ignored")
}

// TestHandler_UnwrapKey_HonoursTheNamedBackend is the unwrap half of the same
// property. The fake provider returns a distinguishable plaintext.
func TestHandler_UnwrapKey_HonoursTheNamedBackend(t *testing.T) {
	provider := newFakeIEProvider(&types.KeyAttributes{CN: "k"})
	provider.unwrapped = []byte("from-the-named-backend")
	server := newKeyOpsServer(t, map[string]types.KeyProvider{"ie-be": provider})

	paramsJSON, err := json.Marshal(&UnwrapKeyParams{
		WrappedKey:        []byte("wrapped-blob"),
		Algorithm:         "RSAES_OAEP_SHA_256",
		WrappingPublicKey: wrappingKeyPEM(t),
		Backend:           "ie-be",
	})
	require.NoError(t, err)

	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.unwrapKey", Params: paramsJSON, ID: 1}
	result, err := server.handleUnwrapKey(context.Background(), req)
	require.NoError(t, err)

	unwrapped, ok := result.(UnwrapKeyResult)
	require.True(t, ok, "unexpected result type %T", result)
	assert.Equal(t, []byte("from-the-named-backend"), unwrapped.KeyMaterial,
		"the unwrap did not run on the named backend")
}
