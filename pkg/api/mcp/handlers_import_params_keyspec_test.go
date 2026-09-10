// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func callGetImportParameters(t *testing.T, server *Server, params GetImportParametersParams) (GetImportParametersResult, error) {
	t.Helper()
	paramsJSON, err := json.Marshal(params)
	require.NoError(t, err)
	result, err := server.handleGetImportParameters(context.Background(),
		&JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.getImportParameters", Params: paramsJSON, ID: 1})
	if err != nil {
		return GetImportParametersResult{}, err
	}
	out, ok := result.(GetImportParametersResult)
	require.True(t, ok)
	return out, nil
}

// TestGetImportParameters_KeySpecNamesTheDeclaredAlgorithm proves the first
// half of the BYOK ceremony can now tell the caller what to send: the key
// type, size and curve the caller declares reach the backend, which names the
// spec the import will check the material against. The params used to carry
// no such field, so every answer was UNKNOWN.
func TestGetImportParameters_KeySpecNamesTheDeclaredAlgorithm(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	for name, tc := range map[string]struct {
		params GetImportParametersParams
		want   string
	}{
		"rsa 2048":         {params: GetImportParametersParams{KeyType: "rsa", KeySize: 2048}, want: "RSA_2048"},
		"rsa 4096":         {params: GetImportParametersParams{KeyType: "rsa", KeySize: 4096}, want: "RSA_4096"},
		"ecdsa P-384":      {params: GetImportParametersParams{KeyType: "ecdsa", Curve: "P-384"}, want: "ECC_NIST_P384"},
		"ed25519":          {params: GetImportParametersParams{KeyType: "ed25519"}, want: "ED25519"},
		"symmetric 256":    {params: GetImportParametersParams{KeyType: "symmetric", KeySize: 256}, want: "AES_256"},
		"aes 128":          {params: GetImportParametersParams{KeyType: "aes", KeySize: 128}, want: "AES_128"},
		"nothing declared": {params: GetImportParametersParams{}, want: "UNKNOWN"},
	} {
		t.Run(name, func(t *testing.T) {
			tc.params.KeyID = "spec-" + name
			tc.params.Backend = "software"
			tc.params.Algorithm = "RSAES_OAEP_SHA_256"
			result, err := callGetImportParameters(t, server, tc.params)
			require.NoError(t, err)
			assert.Equal(t, tc.want, result.KeySpec)
			assert.Contains(t, result.WrappingPublicKeyPEM, "BEGIN PUBLIC KEY")
			assert.NotEmpty(t, result.ImportToken)
		})
	}
}

// TestGetImportParameters_RefusesAPurposeAsTheKeyType proves the params take
// the import's vocabulary: a purpose name is not an algorithm and is refused
// before the backend mints anything.
func TestGetImportParameters_RefusesAPurposeAsTheKeyType(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	_, err := callGetImportParameters(t, server, GetImportParametersParams{KeyID: "spec-purpose", Backend: "software", Algorithm: "RSAES_OAEP_SHA_256", KeyType: "signing"})
	require.Error(t, err)
}
