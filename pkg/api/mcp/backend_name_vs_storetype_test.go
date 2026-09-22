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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/wrapping"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tokenABackendServer registers a real software-implemented backend under
// the name "token-a" beside the default "software" backend -- a legal,
// registrable name that is not one of the store-type keywords
// types.ParseStoreType recognises, exactly like a second PKCS#11 token named
// beside "token-b" would be. #297 measured every MCP handler here rejecting
// exactly this shape of name; #312 is the routing model that made the
// straightforward fix regress, so this file proves the whole ceremony -- not
// just the gate -- now completes against it.
func tokenABackendServer(t *testing.T) *Server {
	t.Helper()
	xkms.Reset()
	t.Cleanup(cleanupXKMS)

	build := func() xkms.Backend {
		be, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
		require.NoError(t, err)
		ks, err := xkms.New(&xkms.BackendConfig{Backend: be, CertStorage: storage.New()})
		require.NoError(t, err)
		return ks
	}

	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends: map[string]xkms.Backend{
			"software": build(),
			"token-a":  build(),
		},
		DefaultBackend: "software",
	}))

	svc, err := xkms.Get()
	require.NoError(t, err)

	server, err := NewServer(&Config{
		XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator(),
	})
	require.NoError(t, err)
	return server
}

// tokenAImportCeremony runs the same BYOK ceremony mcpImportCeremony runs
// (handlers_importkey_test.go), against backendName instead of the hard-coded
// "software", so this file can exercise it against "token-a".
func tokenAImportCeremony(t *testing.T, server *Server, backendName, keyID string, material []byte) ImportKeyParams {
	t.Helper()

	wrapAlgorithm := backend.WrappingAlgorithmRSAES_OAEP_SHA_256
	if len(material) > 190 {
		wrapAlgorithm = backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256
	}
	algorithm := string(wrapAlgorithm)

	paramsJSON, err := json.Marshal(GetImportParametersParams{
		KeyID:     keyID,
		Backend:   backendName,
		Algorithm: algorithm,
	})
	require.NoError(t, err)

	result, err := server.handleGetImportParameters(context.Background(),
		&JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.getImportParameters", Params: paramsJSON, ID: 1})
	require.NoError(t, err)

	importParams, ok := result.(GetImportParametersResult)
	require.True(t, ok)

	block, _ := pem.Decode([]byte(importParams.WrappingPublicKeyPEM))
	require.NotNil(t, block)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	rsaPub, ok := pub.(*rsa.PublicKey)
	require.True(t, ok)

	var wrapped []byte
	if wrapAlgorithm == backend.WrappingAlgorithmRSAES_OAEP_SHA_256 {
		wrapped, err = wrapping.WrapRSAOAEP(material, rsaPub, wrapAlgorithm)
	} else {
		wrapped, err = wrapping.WrapRSAAES(material, rsaPub, wrapAlgorithm)
	}
	require.NoError(t, err)

	return ImportKeyParams{
		KeyID:       keyID,
		Backend:     backendName,
		WrappedKey:  wrapped,
		Algorithm:   algorithm,
		ImportToken: importParams.ImportToken,
	}
}

// findKeyAttrsInBackend looks a key up directly through the service, so this
// file's assertions verify what a handler actually produced rather than only
// that it reported success.
func findKeyAttrsInBackend(t *testing.T, server *Server, backendName, keyID string) *types.KeyAttributes {
	t.Helper()
	b, err := server.xkmsService.LookupBackend(backendName)
	require.NoError(t, err)
	keys, err := b.ListKeys(context.Background())
	require.NoError(t, err)
	for _, k := range keys {
		if k.CN == keyID {
			return k
		}
	}
	t.Fatalf("key %q not found in backend %q", keyID, backendName)
	return nil
}

// TestMCPRoundTrip_NonKeywordBackendName runs generate, the full BYOK import
// ceremony (getImportParameters, then importKeyMaterial) and export against
// a backend registered as "token-a", and pins that every key it produces
// reports StoreType StoreSoftware -- "token-a"'s real kind -- never
// StoreUnknown and never a cast of the registry name itself.
func TestMCPRoundTrip_NonKeywordBackendName(t *testing.T) {
	server := tokenABackendServer(t)
	ctx := context.Background()

	// --- generateKey ---
	_, err := mcpCall(t, server.handleGenerateKey, "xkms.generateKey", GenerateKeyParams{
		KeyID: "token-a-generated", Backend: "token-a", KeyType: "ecdsa", Algorithm: "ecdsa", Exportable: true,
	})
	require.NoError(t, err)

	generated := findKeyAttrsInBackend(t, server, "token-a", "token-a-generated")
	assert.Equal(t, types.StoreSoftware, generated.StoreType,
		"a generated key's StoreType must report the backend's real kind")

	// --- getImportParameters / importKeyMaterial (the full BYOK ceremony) ---
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	importParams := tokenAImportCeremony(t, server, "token-a", "token-a-imported", der)
	importParams.KeyType = "ecdsa"
	importParams.Curve = "P-256"

	importJSON, err := json.Marshal(importParams)
	require.NoError(t, err)
	_, err = server.handleImportKeyMaterial(ctx,
		&JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.importKey", Params: importJSON, ID: 1})
	require.NoError(t, err)

	imported := findKeyAttrsInBackend(t, server, "token-a", "token-a-imported")
	assert.Equal(t, types.StoreSoftware, imported.StoreType,
		"an imported key's StoreType must report the backend's real kind")

	// --- exportKey ---
	exportJSON, err := json.Marshal(ExportKeyParams{
		KeyID:     "token-a-generated",
		Backend:   "token-a",
		Algorithm: string(backend.WrappingAlgorithmRSAES_OAEP_SHA_256),
	})
	require.NoError(t, err)
	_, err = server.handleExportKey(ctx,
		&JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.exportKey", Params: exportJSON, ID: 1})
	require.NoError(t, err, "export must succeed against a backend named token-a")
}
