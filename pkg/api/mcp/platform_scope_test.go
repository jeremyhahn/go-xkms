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
	"io"
	"log/slog"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmpolicytest"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// MCP side of go-xkms#1226 and #1227: every platform-global method is refused
// to a tenant-local Admin with the not-found code and the unknown-tenant
// message, and still served to the platform identity.

const platformScopeSecret = "credentials/pkcs11-pin"

// newPlatformScopeMCP returns a Server whose XKMSService is composed with an
// unsealed system barrier, a PIN backend with both PINs set, a platform store
// holding one credential, a TPM policy service (whose tenant TPM mode and
// vTPM methods are platform-scoped) and a manual credential service.
func newPlatformScopeMCP(t *testing.T) *Server {
	t.Helper()
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := createTestServer(t)

	hashCfg := qrdbsdk.DefaultHashConfig()
	hashCfg.Time, hashCfg.Memory, hashCfg.Threads = 1, 8*1024, 1
	pins, err := qrdbsdk.NewSoftwareBackend(nil, hashCfg)
	require.NoError(t, err)
	require.NoError(t, pins.SetSOPIN("", "so-pin-123456"))
	require.NoError(t, pins.SetUserPIN("so-pin-123456", "user-pin-123456"))

	store, err := seal.NewPlatformStore(storage.NewMemory(), logger)
	require.NoError(t, err)
	require.NoError(t, store.Put(ctx, platformScopeSecret, []byte("platform-secret")))

	policies, _ := tpmpolicytest.NewOffline(t)

	credSvc, err := credentialspkg.New(&credentialspkg.Config{Strategy: credentialspkg.StrategyManual}, nil, nil, logger)
	require.NoError(t, err)

	server.xkmsService.SetPINManager(pins)
	server.xkmsService.SetPlatformStore(store)
	server.xkmsService.SetTPMPolicyService(policies)
	server.xkmsService.SetCredentialService(credSvc)
	return server
}

// platformScopeMethods is every MCP method #1226 and #1227 name, with params
// that pass each handler's own validation.
var platformScopeMethods = map[string]string{
	"sealStore.put":      `{"name":"credentials/pkcs11-pin","secret":"b3ZlcndyaXR0ZW4="}`,
	"sealStore.get":      `{"name":"credentials/pkcs11-pin"}`,
	"sealStore.delete":   `{"name":"credentials/pkcs11-pin"}`,
	"sealStore.list":     `{}`,
	"sealStore.reseal":   `{"name":"credentials/pkcs11-pin"}`,
	"sealStore.status":   `{}`,
	"credentials.submit": `{"name":"pkcs11-pin","value":"c2VjcmV0"}`,

	"xkms.setSOPIN":         `{"current_so_pin":"so-pin-123456","new_so_pin":"so-pin-654321"}`,
	"xkms.setUserPIN":       `{"so_pin":"so-pin-123456","new_user_pin":"user-pin-654321"}`,
	"xkms.changeSOPIN":      `{"current_so_pin":"so-pin-123456","new_so_pin":"so-pin-654321"}`,
	"xkms.changeUserPIN":    `{"current_user_pin":"user-pin-123456","new_user_pin":"user-pin-654321"}`,
	"xkms.verifySOPIN":      `{"so_pin":"so-pin-123456"}`,
	"xkms.verifyUserPIN":    `{"user_pin":"user-pin-123456"}`,
	"xkms.getLockoutStatus": `{}`,
	"xkms.resetLockout":     `{"so_pin":"so-pin-123456"}`,

	"xkms.listPIVSlots":         `{"backend":"software"}`,
	"xkms.getPIVCertificate":    `{"backend":"software","slot":"9a","format":"pem"}`,
	"xkms.storePIVCertificate":  `{"backend":"software","slot":"9a","certificate":"eA==","format":"pem"}`,
	"xkms.deletePIVCertificate": `{"backend":"software","slot":"9a"}`,
	"xkms.generatePIVKey":       `{"backend":"software","slot":"9a","algorithm":"ecdsap256","subject":"server"}`,
	"xkms.importPIVCertificate": `{"backend":"software","slot":"9a","certificate":"eA==","format":"pem"}`,
	"xkms.exportPIVCertificate": `{"backend":"software","slot":"9a","format":"pem"}`,
	"xkms.generatePIVCSR":       `{"backend":"software","slot":"9a","subject":"server"}`,

	"xkms.getTenantTPMMode": `{"tenant_id":"tenant-b"}`,
	"xkms.setTenantTPMMode": `{"tenant_id":"tenant-b","mode":"none"}`,
	"xkms.tenantVTPMStatus": `{"tenant_id":"tenant-b"}`,
	"xkms.tenantVTPMStart":  `{"tenant_id":"tenant-b"}`,
	"xkms.tenantVTPMStop":   `{"tenant_id":"tenant-b"}`,
}

func platformScopeMCPCtx(tenantID string) context.Context {
	return auth.WithIdentity(context.Background(), &auth.Identity{Subject: "admin@" + tenantID, TenantID: tenantID, Roles: []string{"admin"}})
}

// TestPlatformScopeMCP_TenantAdminRefused: each method answers a tenant Admin
// with the not-found code and the unknown-tenant message.
func TestPlatformScopeMCP_TenantAdminRefused(t *testing.T) {
	server := newPlatformScopeMCP(t)
	for method, params := range platformScopeMethods {
		t.Run(method, func(t *testing.T) {
			_, err := server.InvokeMethod(platformScopeMCPCtx("tenant-a"), method, json.RawMessage(params))
			require.Error(t, err)
			var keyErr *KeyOpError
			require.ErrorAs(t, err, &keyErr)
			assert.Equal(t, sdkssh.JSONRPCCodeNotFound, keyErr.Code, "%v", err)
			assert.ErrorIs(t, err, qrdbsdk.ErrTenantMissing)
		})
	}
}

// TestPlatformScopeMCP_SystemAdminServed: the platform identity passes the
// gate on every method. Past the gate some methods fail on their own
// preconditions (an initialized barrier cannot be initialized again); none may
// answer with the binding's refusal, so the methods share one server.
func TestPlatformScopeMCP_SystemAdminServed(t *testing.T) {
	server := newPlatformScopeMCP(t)
	for method, params := range platformScopeMethods {
		t.Run(method, func(t *testing.T) {
			_, err := server.InvokeMethod(platformScopeMCPCtx(qrdbsdk.SystemTenantID), method, json.RawMessage(params))
			assert.NotErrorIs(t, err, qrdbsdk.ErrTenantMissing)
		})
	}
}

// TestPlatformScopeMCP_SystemAdminReadsTheCredential proves the platform
// identity is actually served, not merely unrefused.
func TestPlatformScopeMCP_SystemAdminReadsTheCredential(t *testing.T) {
	server := newPlatformScopeMCP(t)
	result, err := server.InvokeMethod(platformScopeMCPCtx(qrdbsdk.SystemTenantID), "sealStore.get", json.RawMessage(platformScopeMethods["sealStore.get"]))
	require.NoError(t, err)
	raw, err := json.Marshal(result)
	require.NoError(t, err)
	assert.Contains(t, string(raw), "cGxhdGZvcm0tc2VjcmV0") // base64("platform-secret")
}
