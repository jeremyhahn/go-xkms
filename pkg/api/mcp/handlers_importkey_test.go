// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package mcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/wrapping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mcpImportCeremony runs the BYOK ceremony a caller of this transport runs:
// xkms.getImportParameters for a wrapping key and an import token, then the
// caller's own material wrapped under that key.
func mcpImportCeremony(t *testing.T, server *Server, keyID string, material []byte) ImportKeyParams {
	t.Helper()

	// RSA-OAEP carries at most a few hundred bytes under a 2048-bit wrapping
	// key, which an RSA private key's PKCS#8 encoding exceeds; the hybrid
	// RSA+AES wrap exists for exactly that material.
	wrapAlgorithm := backend.WrappingAlgorithmRSAES_OAEP_SHA_256
	if len(material) > 190 {
		wrapAlgorithm = backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256
	}
	algorithm := string(wrapAlgorithm)

	paramsJSON, err := json.Marshal(GetImportParametersParams{
		KeyID:     keyID,
		Backend:   "software",
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
		Backend:     "software",
		WrappedKey:  wrapped,
		Algorithm:   algorithm,
		ImportToken: importParams.ImportToken,
	}
}

func callImportKey(t *testing.T, server *Server, params ImportKeyParams) (interface{}, error) {
	t.Helper()

	paramsJSON, err := json.Marshal(params)
	require.NoError(t, err)

	return server.handleImportKeyMaterial(context.Background(),
		&JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.importKey", Params: paramsJSON, ID: 1})
}

// TestImportKeyMaterial_ImportsAsymmetricMaterial is the request shape this
// tool had no way to express.
//
// The handler built attributes carrying a common name and nothing else, and
// ImportKeyParams had no field that could name the key's algorithm -- its
// Algorithm is the WRAPPING algorithm. Attributes naming no algorithm reach
// the backend's import validation describing nothing, so tightening that
// validation left the tool with no request a caller could send. Naming the key
// type is what makes the tool satisfiable, and it is the same field name and
// vocabulary the gRPC and REST imports already use.
func TestImportKeyMaterial_ImportsAsymmetricMaterial(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecdsaDER, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	require.NoError(t, err)

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edDER, err := x509.MarshalPKCS8PrivateKey(edKey)
	require.NoError(t, err)

	cases := []struct {
		name     string
		keyID    string
		keyType  string
		curve    string
		material []byte
	}{
		{"ECDSA P-256", "mcp-import-ecdsa", "ecdsa", "P-256", ecdsaDER},
		{"Ed25519", "mcp-import-ed25519", "ed25519", "", edDER},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := createTestServer(t)
			defer cleanupXKMS()

			params := mcpImportCeremony(t, server, tc.keyID, tc.material)
			params.KeyType = tc.keyType
			params.Curve = tc.curve

			result, err := callImportKey(t, server, params)
			require.NoError(t, err)
			assert.NotNil(t, result)

			// The key is resolvable afterwards, which is the property an import
			// reporting success is claiming.
			resp, err := server.xkmsService.GetKey(context.Background(), "software", tc.keyID)
			require.NoError(t, err)
			assert.Equal(t, tc.keyID, resp.KeyID)
			assert.NotEmpty(t, resp.PublicKeyPEM)
		})
	}
}

// TestImportKeyMaterial_RefusesMaterialThatContradictsTheDeclaredType is
// go-xkms#53 reaching this transport: the algorithm a caller names is checked
// against the material it sends, so an Ed25519 key declared as ECDSA is
// refused here exactly as it is on every other caller of the import path.
func TestImportKeyMaterial_RefusesMaterialThatContradictsTheDeclaredType(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edDER, err := x509.MarshalPKCS8PrivateKey(edKey)
	require.NoError(t, err)

	params := mcpImportCeremony(t, server, "mcp-import-mismatch", edDER)
	params.KeyType = "ecdsa"
	params.Curve = "P-256"

	_, err = callImportKey(t, server, params)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected Ed25519 key")
}

// TestImportKeyMaterial_RequiresAKeyType records that the algorithm has no
// honest default: it cannot be recovered from wrapped material at this layer,
// and guessing one stores the key under an identifier that does not describe
// it. The refusal names the field the caller omitted.
func TestImportKeyMaterial_RequiresAKeyType(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	require.NoError(t, err)

	params := mcpImportCeremony(t, server, "mcp-import-no-keytype", der)

	_, err = callImportKey(t, server, params)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "key_type")
}

// TestImportKeyMaterial_CarriesTheDeclaredKeySize proves key_size reaches the
// service rather than being dropped for the RSA-2048 default. An RSA-3072 key
// imported without it is refused by the backend's own size check with "RSA key
// size mismatch key is 3072 bits but attributes specify 2048", which names
// neither the field nor what to send.
func TestImportKeyMaterial_CarriesTheDeclaredKeySize(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 3072)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)

	params := mcpImportCeremony(t, server, "mcp-import-rsa-3072", der)
	params.KeyType = "rsa"
	params.KeySize = 3072

	_, err = callImportKey(t, server, params)
	require.NoError(t, err)

	resp, err := server.xkmsService.GetKey(context.Background(), "software", "mcp-import-rsa-3072")
	require.NoError(t, err)
	assert.NotEmpty(t, resp.PublicKeyPEM)
}

// TestImportKeyMaterial_RefusesACurveItCannotResolve proves the curve reaches
// the service too. A name the service cannot parse is refused rather than
// silently replaced by P-256: a caller that asks for P-384 and is given P-256
// has had a parameter dropped, not defaulted.
func TestImportKeyMaterial_RefusesACurveItCannotResolve(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	require.NoError(t, err)

	params := mcpImportCeremony(t, server, "mcp-import-bad-curve", der)
	params.KeyType = "ecdsa"
	params.Curve = "brainpoolP256r1"

	_, err = callImportKey(t, server, params)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid curve")
}
