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

package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// invokeAs runs method through the server's dispatcher as a caller of
// tenant ("" for no identity) and returns the result re-encoded as JSON, so
// a test can decode it into the transport type a client would.
func invokeAs(t *testing.T, server *Server, tenant, method string, params any) (json.RawMessage, error) {
	t.Helper()
	raw, err := json.Marshal(params)
	require.NoError(t, err)
	ctx := context.Background()
	if tenant != "" {
		ctx = auth.WithIdentity(ctx, &auth.Identity{Subject: "u@" + tenant, TenantID: tenant})
	}
	result, err := server.InvokeMethod(ctx, method, raw)
	if err != nil {
		return nil, err
	}
	out, err := json.Marshal(result)
	require.NoError(t, err)
	return out, nil
}

// TestKeyVersionTools_EndToEnd drives every key-version tool through the
// dispatcher over a real service: listing, the state changes, retirement,
// a scope rotation, and key_version on sign and verify.
func TestKeyVersionTools_EndToEnd(t *testing.T) {
	server := createTestServer(t)
	_, err := mcpCall(t, server.handleGenerateKey, "xkms.generateKey", GenerateKeyParams{KeyID: "k", Backend: "software", KeyType: "signing", Algorithm: "ecdsa"})
	require.NoError(t, err)

	raw, err := invokeAs(t, server, "", "xkms.sign", SignParams{KeyID: "k", Backend: "software", Data: []byte("d")})
	require.NoError(t, err)
	var signed transport.SignResponse
	require.NoError(t, json.Unmarshal(raw, &signed))
	assert.Equal(t, uint32(1), signed.KeyVersion)

	raw, err = invokeAs(t, server, "", "xkms.rotateKey", RotateKeyParams{KeyID: "k", Backend: "software"})
	require.NoError(t, err)
	var rotated transport.RotateKeyResponse
	require.NoError(t, json.Unmarshal(raw, &rotated))
	assert.Equal(t, uint32(2), rotated.KeyVersion)

	raw, err = invokeAs(t, server, "", "xkms.verify", VerifyParams{KeyID: "k", Backend: "software", Data: []byte("d"), Signature: signed.Signature})
	require.NoError(t, err)
	var verified transport.VerifyResponse
	require.NoError(t, json.Unmarshal(raw, &verified))
	assert.True(t, verified.Valid)
	assert.Equal(t, uint32(1), verified.KeyVersion)

	raw, err = invokeAs(t, server, "", "xkms.listKeyVersions", transport.ListKeyVersionsRequest{Backend: "software", KeyID: "k"})
	require.NoError(t, err)
	var listed transport.ListKeyVersionsResponse
	require.NoError(t, json.Unmarshal(raw, &listed))
	assert.Equal(t, uint32(2), listed.CurrentVersion)
	require.Len(t, listed.Versions, 2)

	// Ordered: disable then enable, so version 1 ends enabled for the
	// disable-all/enable-all round below. A map here iterated in random order
	// and left version 1 disabled about half the time.
	for _, step := range []struct{ method, want string }{
		{"xkms.disableKeyVersion", transport.KeyVersionDisabled},
		{"xkms.enableKeyVersion", transport.KeyVersionEnabled},
	} {
		raw, err = invokeAs(t, server, "", step.method, transport.KeyVersionRequest{Backend: "software", KeyID: "k", Version: 1})
		require.NoError(t, err, step.method)
		var state transport.KeyVersionStateResponse
		require.NoError(t, json.Unmarshal(raw, &state))
		assert.Equal(t, step.want, state.State, step.method)
	}
	for _, method := range []string{"xkms.disableAllKeyVersions", "xkms.enableAllKeyVersions"} {
		raw, err = invokeAs(t, server, "", method, transport.AllKeyVersionsRequest{Backend: "software", KeyID: "k"})
		require.NoError(t, err, method)
		var all transport.AllKeyVersionsResponse
		require.NoError(t, json.Unmarshal(raw, &all))
		assert.Equal(t, []uint32{1}, all.Versions, method)
	}

	raw, err = invokeAs(t, server, "", "xkms.retireKeyVersion", transport.KeyVersionRequest{Backend: "software", KeyID: "k", Version: 1})
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"state":"retired"`)

	listedKeys, err := invokeAs(t, server, "", "xkms.listKeys", ListKeysParams{Backend: "software"})
	require.NoError(t, err)
	assert.NotContains(t, string(listedKeys), "k--v2", "a version is never listed on its own")
	assert.Contains(t, string(listedKeys), `"key_version":2`)

	raw, err = invokeAs(t, server, "", "xkms.rotateScopeKeys", nil)
	require.NoError(t, err)
	var scope transport.RotateScopeKeysResponse
	require.NoError(t, json.Unmarshal(raw, &scope))
	assert.GreaterOrEqual(t, scope.Rotated, 1)
}

// TestKeyVersionTools_MapErrors proves the tools' refusals reach JSON-RPC
// with their class's code.
func TestKeyVersionTools_MapErrors(t *testing.T) {
	server := createTestServer(t)
	_, err := mcpCall(t, server.handleGenerateKey, "xkms.generateKey", GenerateKeyParams{KeyID: "k", Backend: "software", KeyType: "signing", Algorithm: "ecdsa"})
	require.NoError(t, err)
	_, err = invokeAs(t, server, "", "xkms.rotateKey", RotateKeyParams{KeyID: "k", Backend: "software"})
	require.NoError(t, err)

	tests := []struct {
		name, method string
		params       any
		code         int
	}{
		{"missing key_id", "xkms.listKeyVersions", transport.ListKeyVersionsRequest{Backend: "software"}, ErrCodeInvalidParams},
		{"missing key", "xkms.listKeyVersions", transport.ListKeyVersionsRequest{Backend: "software", KeyID: "ghost"}, sdkssh.JSONRPCCodeNotFound},
		{"unknown version", "xkms.enableKeyVersion", transport.KeyVersionRequest{Backend: "software", KeyID: "k", Version: 9}, sdkssh.JSONRPCCodeNotFound},
		{"version zero", "xkms.disableKeyVersion", transport.KeyVersionRequest{Backend: "software", KeyID: "k"}, ErrCodeInvalidParams},
		{"disable current", "xkms.disableKeyVersion", transport.KeyVersionRequest{Backend: "software", KeyID: "k", Version: 2}, ErrCodeInternalError},
		{"version name", "xkms.retireKeyVersion", transport.KeyVersionRequest{Backend: "software", KeyID: "k--v2", Version: 1}, ErrCodeInvalidParams},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := invokeAs(t, server, "", tt.method, tt.params)
			require.Error(t, err)
			code, message := ClientError(err)
			assert.Equal(t, tt.code, code, message)
		})
	}

	// A precondition refusal keeps its message, so the caller learns why.
	_, err = invokeAs(t, server, "", "xkms.disableKeyVersion", transport.KeyVersionRequest{Backend: "software", KeyID: "k", Version: 2})
	_, message := ClientError(err)
	assert.Contains(t, message, "current version")

	_, err = invokeAs(t, server, "acme", "xkms.rotateScopeKeys", transport.RotateScopeKeysRequest{TenantID: "globex"})
	require.Error(t, err)
	code, _ := ClientError(err)
	assert.Equal(t, sdkssh.JSONRPCCodeNotFound, code, "a tenant cannot rotate another tenant")
}

// TestKeyVersionTools_UseTheCallersTenant proves the per-key tools act in
// the caller's tenant whatever tenant_id the parameters name.
func TestKeyVersionTools_UseTheCallersTenant(t *testing.T) {
	server := createTestServer(t)
	_, err := mcpCall(t, server.handleGenerateKey, "xkms.generateKey", GenerateKeyParams{KeyID: "platform-key", Backend: "software", KeyType: "signing", Algorithm: "ecdsa"})
	require.NoError(t, err)

	_, err = invokeAs(t, server, "acme", "xkms.listKeyVersions", transport.ListKeyVersionsRequest{Backend: "software", KeyID: "platform-key", TenantID: ""})
	require.Error(t, err)
	code, _ := ClientError(err)
	assert.Equal(t, sdkssh.JSONRPCCodeNotFound, code, "acme does not see the platform's key")
}
