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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmpolicytest"
	"github.com/jeremyhahn/go-xkms/pkg/tpmpolicy"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// newTPMPolicyMCP returns a Server whose XKMSService has a TPM policy service
// without a TPM, and that policy service.
func newTPMPolicyMCP(t *testing.T) (*Server, *tpmpolicy.Service) {
	t.Helper()
	server := createTestServer(t)
	policies, _ := tpmpolicytest.NewOffline(t)
	server.xkmsService.SetTPMPolicyService(policies)
	return server, policies
}

// invokeTPM calls method as a caller of tenant and decodes its result into
// out.
func invokeTPM(t *testing.T, s *Server, tenant, method, params string, out any) error {
	t.Helper()
	result, err := s.InvokeMethod(platformScopeMCPCtx(tenant), method, json.RawMessage(params))
	if err != nil {
		return err
	}
	raw, err := json.Marshal(result)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, out))
	return nil
}

// TestTPMPolicyTools_ServeTheCallersTenant proves the tools reach the policy
// service in the caller's tenant.
func TestTPMPolicyTools_ServeTheCallersTenant(t *testing.T) {
	s, policies := newTPMPolicyMCP(t)
	require.NoError(t, policies.Assign(context.Background(), "acme", tpmpolicy.ObjectKey, "signer", "", nil))

	var list transport.TPMPolicyListResponse
	require.NoError(t, invokeTPM(t, s, "acme", "tpm.policy.list", `{}`, &list))
	assert.Empty(t, list.Policies)

	var obj transport.TPMObjectPolicyResponse
	require.NoError(t, invokeTPM(t, s, "acme", "tpm.object.policy", `{"key_id":"signer"}`, &obj))
	assert.Equal(t, "key/signer", obj.ObjectID)

	var objects transport.TPMPolicyObjectsResponse
	require.NoError(t, invokeTPM(t, s, "acme", "tpm.policy.objects", `{"name":"platform"}`, &objects))
	assert.Equal(t, []string{"key/signer"}, objects.Objects)

	var mode transport.TenantTPMModeResponse
	require.NoError(t, invokeTPM(t, s, qrdbsdk.SystemTenantID, "xkms.setTenantTPMMode", `{"tenant_id":"globex","mode":"none"}`, &mode))
	assert.Equal(t, "none", mode.Mode)
	require.NoError(t, invokeTPM(t, s, qrdbsdk.SystemTenantID, "xkms.getTenantTPMMode", `{"tenant_id":"globex"}`, &mode))
	assert.Equal(t, "none", mode.Mode)
}

// TestTPMPolicyTools_MapErrors proves the service's errors reach the wire
// with the codes apierrors.TPMPolicyClassOf assigns.
func TestTPMPolicyTools_MapErrors(t *testing.T) {
	s, _ := newTPMPolicyMCP(t)
	tests := []struct {
		name, tenant, method, params string
		code                         int
	}{
		{"unknown object", "acme", "tpm.object.policy", `{"key_id":"missing"}`, sdkssh.JSONRPCCodeNotFound},
		{"invalid bank", "acme", "tpm.policy.create", `{"name":"boot","bank":"md5","pcrs":[7]}`, ErrCodeInvalidParams},
		{"another tenant", "acme", "tpm.policy.list", `{"tenant_id":"globex"}`, sdkssh.JSONRPCCodeNotFound},
		{"tenant mode is system scope", "acme", "xkms.getTenantTPMMode", `{"tenant_id":"acme"}`, sdkssh.JSONRPCCodeNotFound},
		{"missing tenant id", qrdbsdk.SystemTenantID, "xkms.tenantVTPMStatus", `{}`, ErrCodeInvalidParams},
		{"invalid mode", qrdbsdk.SystemTenantID, "xkms.setTenantTPMMode", `{"tenant_id":"acme","mode":"cloud"}`, ErrCodeInvalidParams},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out map[string]any
			err := invokeTPM(t, s, tt.tenant, tt.method, tt.params, &out)
			var keyErr *KeyOpError
			require.ErrorAs(t, err, &keyErr)
			assert.Equal(t, tt.code, keyErr.Code, "%v", err)
		})
	}
}

// TestTPMPolicyTools_WithoutTheService proves the tools answer "not
// configured" on a server with no TPM policy service.
func TestTPMPolicyTools_WithoutTheService(t *testing.T) {
	s := createTestServer(t)
	var out map[string]any
	err := invokeTPM(t, s, qrdbsdk.SystemTenantID, "tpm.policy.delete", `{"name":"boot"}`, &out)
	var keyErr *KeyOpError
	require.ErrorAs(t, err, &keyErr)
	assert.Equal(t, ErrCodeServiceUnavailable, keyErr.Code)
}
