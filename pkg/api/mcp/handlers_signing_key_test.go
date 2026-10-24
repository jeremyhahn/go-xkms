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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// newSigningKeyMCP returns a Server whose XKMSService has a Verifier.
func newSigningKeyMCP(t *testing.T) *Server {
	t.Helper()
	server := createTestServer(t)
	store, err := appraisal.NewStore(appraisal.StoreConfig{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)
	appraiser, err := appraisal.NewAppraiser(store)
	require.NoError(t, err)
	server.xkmsService.SetAttestationAppraiser(appraiser)
	return server
}

// TestSigningKeyTools_Lifecycle proves the tools reach the Verifier in the
// caller's tenant: a repository resolves to the release key, is bound,
// read, listed, resolved to its own key, and unbound.
func TestSigningKeyTools_Lifecycle(t *testing.T) {
	s := newSigningKeyMCP(t)
	repo := "acme/app"

	var resolved transport.SigningKeyResolution
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "attestation.signing_key.resolve", transport.ResolveSigningKeyRequest{Repository: repo}, &resolved))
	assert.True(t, resolved.Default)

	var bound transport.SigningKeyBinding
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "attestation.signing_key.set", transport.SetSigningKeyBindingRequest{Repository: repo, KeyID: "app-release"}, &bound))
	assert.Equal(t, "app-release", bound.KeyID)

	var got transport.SigningKeyBinding
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "attestation.signing_key.get", transport.GetSigningKeyBindingRequest{Repository: repo}, &got))
	assert.Equal(t, repo, got.Repository)

	var list transport.ListSigningKeyBindingsResponse
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "attestation.signing_key.list", struct{}{}, &list))
	require.Len(t, list.Bindings, 1)

	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "attestation.signing_key.resolve", transport.ResolveSigningKeyRequest{Repository: repo}, &resolved))
	assert.False(t, resolved.Default)
	assert.Equal(t, "app-release", resolved.KeyID)

	var deleted transport.DeleteSigningKeyBindingRequest
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "attestation.signing_key.delete", transport.DeleteSigningKeyBindingRequest{Repository: repo}, &deleted))
	assert.Equal(t, repo, deleted.Repository)
}

// TestSigningKeyTools_MapErrors proves the Verifier's errors reach the wire
// with the codes apierrors.SigningKeyClassOf assigns.
func TestSigningKeyTools_MapErrors(t *testing.T) {
	s := newSigningKeyMCP(t)
	tests := []struct {
		name, method string
		params       any
		code         int
	}{
		{"malformed params", "attestation.signing_key.get", "not an object", ErrCodeInvalidParams},
		{"malformed list params", "attestation.signing_key.list", "not an object", ErrCodeInvalidParams},
		{"invalid repository", "attestation.signing_key.resolve", transport.ResolveSigningKeyRequest{Repository: "Acme"}, ErrCodeInvalidParams},
		{"invalid key", "attestation.signing_key.set", transport.SetSigningKeyBindingRequest{Repository: "acme/app", KeyID: "a/b"}, ErrCodeInvalidParams},
		{"unbound", "attestation.signing_key.delete", transport.DeleteSigningKeyBindingRequest{Repository: "acme/app"}, sdkssh.JSONRPCCodeNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out map[string]any
			err := invokeOIDC(t, s, "acme", "alice", tt.method, tt.params, &out)
			var keyErr *KeyOpError
			require.ErrorAs(t, err, &keyErr)
			assert.Equal(t, tt.code, keyErr.Code)
		})
	}
}

// TestSigningKeyTools_WithoutTheVerifier proves every tool fails on a
// server with no Verifier wired.
func TestSigningKeyTools_WithoutTheVerifier(t *testing.T) {
	s := createTestServer(t)
	for _, method := range []string{
		"attestation.signing_key.set", "attestation.signing_key.get", "attestation.signing_key.list",
		"attestation.signing_key.delete", "attestation.signing_key.resolve",
	} {
		var out map[string]any
		err := invokeOIDC(t, s, "acme", "alice", method, transport.SetSigningKeyBindingRequest{Repository: "acme/app", KeyID: "k"}, &out)
		var keyErr *KeyOpError
		assert.ErrorAs(t, err, &keyErr, method)
	}
}
