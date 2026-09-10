// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

func mcpExportMaterial(t *testing.T, server *Server, keyID string) (*transport.ExportKeyMaterialResponse, error) {
	t.Helper()
	paramsJSON, err := json.Marshal(&transport.ExportKeyMaterialRequest{KeyID: keyID, Backend: "software"})
	require.NoError(t, err)
	result, err := server.handleExportKeyMaterial(context.Background(),
		&JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.exportKeyMaterial", Params: paramsJSON, ID: 1})
	if err != nil {
		return nil, err
	}
	resp, ok := result.(*transport.ExportKeyMaterialResponse)
	require.True(t, ok)
	return resp, nil
}

// TestImportKeyMaterial_ExportableFalseIsHonoured proves the MCP import
// carries the caller's exportability choice through to the service: secret
// material imported with exportable=false cannot be read back, while an
// import that says nothing keeps the write-once exportable default.
func TestImportKeyMaterial_ExportableFalseIsHonoured(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	material := make([]byte, 32)
	for i := range material {
		material[i] = byte(0xA0 + i)
	}

	params := mcpImportCeremony(t, server, "mcp-non-exportable", material)
	params.KeyType = "symmetric"
	params.KeySize = 256
	exportable := false
	params.Exportable = &exportable
	_, err := callImportKey(t, server, params)
	require.NoError(t, err)
	_, err = mcpExportMaterial(t, server, "mcp-non-exportable")
	require.Error(t, err, "a key imported non-exportable must not be read back")

	params = mcpImportCeremony(t, server, "mcp-default", material)
	params.KeyType = "symmetric"
	params.KeySize = 256
	_, err = callImportKey(t, server, params)
	require.NoError(t, err)
	exported, err := mcpExportMaterial(t, server, "mcp-default")
	require.NoError(t, err)
	assert.Equal(t, material, exported.KeyMaterial)
}

// TestImportKeyMaterial_SensitiveIsHonoured proves the sensitive flag reaches
// the record through the MCP import.
func TestImportKeyMaterial_SensitiveIsHonoured(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	params := mcpImportCeremony(t, server, "mcp-sensitive", make([]byte, 32))
	params.KeyType = "symmetric"
	params.KeySize = 256
	params.Sensitive = true
	_, err := callImportKey(t, server, params)
	require.NoError(t, err)
	_, err = mcpExportMaterial(t, server, "mcp-sensitive")
	require.Error(t, err)
}
