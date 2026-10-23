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
	"crypto/x509"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/keypolicy"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// createKeyManagementServer returns a test server whose service has the key
// policy store, an ECDSA key "signer" and an AES-256-GCM key "aead".
func createKeyManagementServer(t *testing.T) (*Server, *xkms.XKMSService) {
	t.Helper()
	server := createTestServer(t)
	svc, err := xkms.Get()
	require.NoError(t, err)
	store, err := keypolicy.NewStore(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	svc.SetKeyPolicyStore(store)
	for id, alg := range map[string]string{"signer": "ecdsa", "aead": "aes-256-gcm"} {
		_, err := mcpCall(t, server.handleGenerateKey, "xkms.generateKey", GenerateKeyParams{KeyID: id, Backend: "software", KeyType: "signing", Algorithm: alg})
		require.NoError(t, err)
	}
	return server, svc
}

// TestKeyManagementTools_EndToEnd drives the key management methods through
// the MCP dispatch against the real service.
func TestKeyManagementTools_EndToEnd(t *testing.T) {
	server, _ := createKeyManagementServer(t)

	raw, err := invokeAs(t, server, "", "xkms.getPublicKey", transport.GetPublicKeyRequest{Backend: "software", KeyID: "signer"})
	require.NoError(t, err)
	var pub transport.GetPublicKeyResponse
	require.NoError(t, json.Unmarshal(raw, &pub))
	_, err = x509.ParsePKIXPublicKey(pub.PublicKey)
	require.NoError(t, err)

	raw, err = invokeAs(t, server, "", "xkms.setKeyPolicy", transport.SetKeyPolicyRequest{Backend: "software", KeyID: "signer", Policy: &transport.KeyPolicy{MaxUsageCount: 3}})
	require.NoError(t, err)
	var set transport.SetKeyPolicyResponse
	require.NoError(t, json.Unmarshal(raw, &set))
	assert.Equal(t, uint64(1), set.PolicyVersion)

	raw, err = invokeAs(t, server, "", "xkms.getKeyPolicy", transport.KeyManagementRequest{Backend: "software", KeyID: "signer"})
	require.NoError(t, err)
	var policy transport.GetKeyPolicyResponse
	require.NoError(t, json.Unmarshal(raw, &policy))
	require.NotNil(t, policy.Policy)
	assert.Equal(t, uint64(3), policy.Policy.MaxUsageCount)

	_, err = invokeAs(t, server, "", "xkms.setKeySafety", transport.SetKeySafetyRequest{Backend: "software", KeyID: "aead", MaxOperations: 100})
	require.NoError(t, err)
	raw, err = invokeAs(t, server, "", "xkms.safetyReport", transport.SafetyReportRequest{Format: "json"})
	require.NoError(t, err)
	var report transport.SafetyReportResponse
	require.NoError(t, json.Unmarshal(raw, &report))
	assert.Len(t, report.AllItems, 1)

	raw, err = invokeAs(t, server, "", "xkms.backendStatus", transport.BackendRequest{Backend: "software"})
	require.NoError(t, err)
	var status transport.BackendStatusResponse
	require.NoError(t, json.Unmarshal(raw, &status))
	assert.NotEmpty(t, status.Status)

	raw, err = invokeAs(t, server, "", "xkms.revokeKey", transport.RevokeKeyRequest{Backend: "software", KeyID: "signer", Reason: "retired"})
	require.NoError(t, err)
	var revoked transport.RevokeKeyResponse
	require.NoError(t, json.Unmarshal(raw, &revoked))
	assert.Equal(t, transport.KeyStatusCompromised, revoked.Status)
}

// TestKeyManagementTools_MapErrors proves each refusal reaches the caller as
// the JSON-RPC code its class promises.
func TestKeyManagementTools_MapErrors(t *testing.T) {
	server, svc := createKeyManagementServer(t)

	tests := []struct {
		name, method string
		params       any
		code         int
	}{
		{"symmetric public key", "xkms.getPublicKey", transport.GetPublicKeyRequest{Backend: "software", KeyID: "aead"}, ErrCodeInvalidParams},
		{"missing key", "xkms.getPublicKey", transport.GetPublicKeyRequest{Backend: "software", KeyID: "ghost"}, sdkssh.JSONRPCCodeNotFound},
		{"require mfa", "xkms.setKeyPolicy", transport.SetKeyPolicyRequest{Backend: "software", KeyID: "signer", Policy: &transport.KeyPolicy{RequireMFA: true}}, ErrCodeMethodNotFound},
		{"report format", "xkms.safetyReport", transport.SafetyReportRequest{Format: "xml"}, ErrCodeInvalidParams},
		{"unsettable status", "xkms.updateKeyStatus", transport.UpdateKeyStatusRequest{Backend: "software", KeyID: "signer", Status: transport.KeyStatusCompromised}, ErrCodeInvalidParams},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := invokeAs(t, server, "", tt.method, tt.params)
			require.Error(t, err)
			code, message := ClientError(err)
			assert.Equal(t, tt.code, code, message)
		})
	}

	// A revoked key stays revoked, and the refusal keeps its message.
	_, err := invokeAs(t, server, "", "xkms.revokeKey", transport.RevokeKeyRequest{Backend: "software", KeyID: "signer"})
	require.NoError(t, err)
	_, err = invokeAs(t, server, "", "xkms.updateKeyStatus", transport.UpdateKeyStatusRequest{Backend: "software", KeyID: "signer", Status: transport.KeyStatusEnabled})
	require.Error(t, err)
	code, message := ClientError(err)
	assert.Equal(t, ErrCodeInternalError, code)
	assert.NotEmpty(t, message)

	svc.SetKeyPolicyStore(nil)
	_, err = invokeAs(t, server, "", "xkms.setKeySafety", transport.SetKeySafetyRequest{Backend: "software", KeyID: "aead", MaxOperations: 10})
	require.Error(t, err)
	code, message = ClientError(err)
	assert.Equal(t, ErrCodeServiceUnavailable, code, message)
}
