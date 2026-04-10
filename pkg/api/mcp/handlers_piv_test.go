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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleListPIVSlots_InvalidParams(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.listPIVSlots",
		Params:  json.RawMessage(`not valid json`),
		ID:      1,
	}

	result, err := server.handleListPIVSlots(req)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "invalid params")
}

func TestHandleListPIVSlots_ValidParams_NoXKMS(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	params := json.RawMessage(`{"backend": "software"}`)
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.listPIVSlots",
		Params:  params,
		ID:      1,
	}

	result, err := server.handleListPIVSlots(req)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to list PIV slots")
}

func TestHandleGetPIVCertificate_InvalidParams(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.getPIVCertificate",
		Params:  json.RawMessage(`{invalid`),
		ID:      1,
	}

	result, err := server.handleGetPIVCertificate(req)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "invalid params")
}

func TestHandleGetPIVCertificate_ValidParams_NoXKMS(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	params := json.RawMessage(`{"backend": "software", "slot": "9a", "format": "pem"}`)
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.getPIVCertificate",
		Params:  params,
		ID:      1,
	}

	result, err := server.handleGetPIVCertificate(req)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to get PIV certificate")
}

func TestHandleStorePIVCertificate_InvalidParams(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.storePIVCertificate",
		Params:  json.RawMessage(`<<broken>>`),
		ID:      1,
	}

	result, err := server.handleStorePIVCertificate(req)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "invalid params")
}

func TestHandleStorePIVCertificate_ValidParams_NoXKMS(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	params := json.RawMessage(`{"backend": "software", "slot": "9a", "certificate": "Y2VydA==", "format": "pem"}`)
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.storePIVCertificate",
		Params:  params,
		ID:      1,
	}

	result, err := server.handleStorePIVCertificate(req)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to store PIV certificate")
}

func TestHandleDeletePIVCertificate_InvalidParams(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.deletePIVCertificate",
		Params:  json.RawMessage(`[1, 2, 3]`),
		ID:      1,
	}

	result, err := server.handleDeletePIVCertificate(req)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "invalid params")
}

func TestHandleDeletePIVCertificate_ValidParams_NoXKMS(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	params := json.RawMessage(`{"backend": "software", "slot": "9a"}`)
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.deletePIVCertificate",
		Params:  params,
		ID:      1,
	}

	result, err := server.handleDeletePIVCertificate(req)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to delete PIV certificate")
}

func TestHandleGeneratePIVKey_InvalidParams(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.generatePIVKey",
		Params:  json.RawMessage(`"just a string"`),
		ID:      1,
	}

	result, err := server.handleGeneratePIVKey(req)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "invalid params")
}

func TestHandleGeneratePIVKey_ValidParams_NoXKMS(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	params := json.RawMessage(`{"backend": "software", "slot": "9a", "algorithm": "ecdsap256", "subject": "CN=Test"}`)
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.generatePIVKey",
		Params:  params,
		ID:      1,
	}

	result, err := server.handleGeneratePIVKey(req)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to generate PIV key")
}

func TestHandleImportPIVCertificate_InvalidParams(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.importPIVCertificate",
		Params:  json.RawMessage(`{{{`),
		ID:      1,
	}

	result, err := server.handleImportPIVCertificate(req)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "invalid params")
}

func TestHandleImportPIVCertificate_ValidParams_NoXKMS(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	params := json.RawMessage(`{"backend": "software", "slot": "9a", "certificate": "Y2VydA==", "format": "pem"}`)
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.importPIVCertificate",
		Params:  params,
		ID:      1,
	}

	result, err := server.handleImportPIVCertificate(req)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to import PIV certificate")
}

func TestHandleExportPIVCertificate_InvalidParams(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.exportPIVCertificate",
		Params:  json.RawMessage(`true`),
		ID:      1,
	}

	result, err := server.handleExportPIVCertificate(req)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "invalid params")
}

func TestHandleExportPIVCertificate_ValidParams_NoXKMS(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	params := json.RawMessage(`{"backend": "software", "slot": "9a", "format": "pem"}`)
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.exportPIVCertificate",
		Params:  params,
		ID:      1,
	}

	result, err := server.handleExportPIVCertificate(req)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to export PIV certificate")
}

func TestHandleGeneratePIVCSR_InvalidParams(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.generatePIVCSR",
		Params:  json.RawMessage(`42`),
		ID:      1,
	}

	result, err := server.handleGeneratePIVCSR(req)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "invalid params")
}

func TestHandleGeneratePIVCSR_ValidParams_NoXKMS(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	params := json.RawMessage(`{"backend": "software", "slot": "9a", "subject": "CN=Test"}`)
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.generatePIVCSR",
		Params:  params,
		ID:      1,
	}

	result, err := server.handleGeneratePIVCSR(req)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to generate PIV CSR")
}

func TestHandleListPIVSlots_EmptyParams(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.listPIVSlots",
		Params:  json.RawMessage(`{}`),
		ID:      1,
	}

	// Empty JSON object unmarshals successfully into ListPIVSlotsRequest
	// with zero-value fields. The call proceeds to the xkms layer,
	// which fails because no PIV backend is registered with an empty name.
	result, err := server.handleListPIVSlots(req)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to list PIV slots")
}

func TestHandleListPIVSlots_NullParams(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.listPIVSlots",
		Params:  nil,
		ID:      1,
	}

	// nil RawMessage causes json.Unmarshal to fail
	result, err := server.handleListPIVSlots(req)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "invalid params")
}
