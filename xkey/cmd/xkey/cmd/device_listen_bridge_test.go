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

package cmd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// listBackendsClient answers ListBackends so the bridge has something real to
// return; every other call falls through to the shared not-implemented base.
type listBackendsClient struct {
	baseSDKClient
	backends []transport.BackendInfo
}

func (c *listBackendsClient) ListBackends(_ context.Context, _ ...transport.ListOption) (*transport.ListBackendsResponse, error) {
	return &transport.ListBackendsResponse{Backends: c.backends}, nil
}

// newListenHandler builds a listen handler with a software attestor and the
// given bridge.
func newListenHandler(t *testing.T, bridge *pairing.Bridge) *listenRequestHandler {
	t.Helper()
	handler, err := newListenRequestHandler(newTestLogger(), nil, pairing.AttestationModeSoftware, bridge)
	require.NoError(t, err)
	return handler
}

// newTestBridge builds a bridge over the given client.
func newTestBridge(t *testing.T, client transport.Client) *pairing.Bridge {
	t.Helper()
	bridge, err := pairing.NewBridge(client, &pairing.BridgeConfig{Logger: newTestLogger()})
	require.NoError(t, err)
	return bridge
}

// decodeListenResponse decodes the raw JSON-RPC bytes a handler returns.
func decodeListenResponse(t *testing.T, raw []byte) *pairingproto.Response {
	t.Helper()
	resp, err := pairingproto.DecodeResponse(raw)
	require.NoError(t, err)
	return resp
}

func TestListenHandler_PingIsServedLocally(t *testing.T) {
	handler := newListenHandler(t, nil)

	raw, err := handler.HandleRequest(context.Background(), mustEncodeRequest(t, pairingproto.MethodPing, nil))
	require.NoError(t, err)

	resp := decodeListenResponse(t, raw)
	require.Nil(t, resp.Error)

	result, err := pairingproto.DecodeResult[pairingproto.PingResult](resp)
	require.NoError(t, err)
	assert.True(t, result.Pong)
}

// TestListenHandler_WithoutBridgeRejectsRemoteMethods documents the fallback
// when xkmsd is not enabled: the phone gets an explicit method-not-found
// rather than a silent hang.
func TestListenHandler_WithoutBridgeRejectsRemoteMethods(t *testing.T) {
	handler := newListenHandler(t, nil)

	raw, err := handler.HandleRequest(context.Background(),
		mustEncodeRequest(t, pairingproto.MethodRemoteListBackends, nil))
	require.NoError(t, err)

	resp := decodeListenResponse(t, raw)
	require.NotNil(t, resp.Error)
	assert.Equal(t, pairingproto.ErrorCodeMethodNotFound, resp.Error.Code)
}

// TestListenHandler_BridgeServesRemoteMethods is the regression guard for the
// gap this command had: only ping and attestation were served, so every other
// remote.* method the phone sends came back as method-not-found.
func TestListenHandler_BridgeServesRemoteMethods(t *testing.T) {
	client := &listBackendsClient{
		backends: []transport.BackendInfo{{ID: "software", Type: "software"}},
	}
	handler := newListenHandler(t, newTestBridge(t, client))

	raw, err := handler.HandleRequest(context.Background(),
		mustEncodeRequest(t, pairingproto.MethodRemoteListBackends, nil))
	require.NoError(t, err)

	resp := decodeListenResponse(t, raw)
	require.Nil(t, resp.Error, "the bridge must answer remote.listBackends")

	result, err := pairingproto.DecodeResult[pairingproto.RemoteListBackendsResult](resp)
	require.NoError(t, err)
	require.Len(t, result.Backends, 1)
	assert.Equal(t, "software", result.Backends[0].Name)
}

// TestListenHandler_LocalAttestationWinsOverBridge proves the locally
// configured attestor still answers remote.attestDevice: the laptop's own TPM
// produces the quote, not xkmsd.
func TestListenHandler_LocalAttestationWinsOverBridge(t *testing.T) {
	handler := newListenHandler(t, newTestBridge(t, &listBackendsClient{}))

	nonce := make([]byte, 32)
	raw, err := handler.HandleRequest(context.Background(),
		mustEncodeRequest(t, pairingproto.MethodRemoteAttestDevice, &pairingproto.RemoteAttestDeviceParams{Nonce: nonce}))
	require.NoError(t, err)

	resp := decodeListenResponse(t, raw)
	require.Nil(t, resp.Error)

	result, err := pairingproto.DecodeResult[pairingproto.RemoteAttestDeviceResult](resp)
	require.NoError(t, err)
	assert.Equal(t, "software", result.SecurityLevel,
		"the software attestor configured on the handler must produce the result")
}

// mustEncodeRequest encodes a JSON-RPC request for the handler under test.
func mustEncodeRequest(t *testing.T, method string, params interface{}) []byte {
	t.Helper()
	raw, err := pairingproto.EncodeRequest(pairingproto.NewRequest(method, params))
	require.NoError(t, err)
	return raw
}

func TestSetBridgeBackupStores_WiresOpenedStores(t *testing.T) {
	sources := &backupSources{
		trust:     &trustStoreAdapter{},
		oath:      &oathStoreAdapter{},
		passwords: &passwordStoreAdapter{},
	}
	cfg := &pairing.BridgeConfig{}

	setBridgeBackupStores(cfg, sources)

	assert.Same(t, sources.trust, cfg.BackupTrustStore)
	assert.Same(t, sources.oath, cfg.BackupOATH)
	assert.Same(t, sources.passwords, cfg.BackupPasswords)
}

func TestSetBridgeBackupStores_LeavesUnopenedStoresUnset(t *testing.T) {
	cfg := &pairing.BridgeConfig{}
	setBridgeBackupStores(cfg, nil)
	assert.True(t, cfg.BackupTrustStore == nil)

	// A store that failed to open stays a nil interface, never a typed nil,
	// so the bridge reports it as not configured. assert.Nil would accept
	// a typed nil, hence the direct comparisons.
	setBridgeBackupStores(cfg, &backupSources{oath: &oathStoreAdapter{}})
	assert.True(t, cfg.BackupTrustStore == nil)
	assert.NotNil(t, cfg.BackupOATH)
	assert.True(t, cfg.BackupPasswords == nil)
}

// TestListenBridge_SecretBackupFollowsSyncExportDecision verifies that
// remote.createBackup of the password vault or OATH secrets is refused by
// the same session decision that refuses remote.sync*: the --allow-sync flag,
// overridden by a sealed enterprise policy. The stores are zero-value
// adapters, so a refusal that read one before deciding would fail loudly.
func TestListenBridge_SecretBackupFollowsSyncExportDecision(t *testing.T) {
	sealedDeny := &xkeyconfig.VerifiedPolicy{State: xkeyconfig.PolicySealedVerified, Policy: xkeyconfig.PolicySection{
		LockPhoneSyncPolicy:        true,
		PhoneSyncAllowSecretExport: false,
	}}
	tests := []struct {
		name           string
		sessionAllowed bool
		policy         *xkeyconfig.VerifiedPolicy
		params         pairingproto.RemoteCreateBackupParams
	}{
		{
			name:   "passwords without --allow-sync",
			policy: &xkeyconfig.VerifiedPolicy{State: xkeyconfig.PolicyUnsealed},
			params: pairingproto.RemoteCreateBackupParams{IncludePasswords: true, Password: "pw"},
		},
		{
			name:   "oath without --allow-sync",
			policy: &xkeyconfig.VerifiedPolicy{State: xkeyconfig.PolicyUnsealed},
			params: pairingproto.RemoteCreateBackupParams{IncludeOATH: true, Password: "pw"},
		},
		{
			name:           "passwords with --allow-sync, denied by policy",
			sessionAllowed: true,
			policy:         sealedDeny,
			params:         pairingproto.RemoteCreateBackupParams{IncludePasswords: true, IncludeOATH: true, Password: "pw"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &pairing.BridgeConfig{
				Logger:       newTestLogger(),
				SyncApproval: newSessionSyncApproval("Pixel", allowPhoneSyncExport(tt.sessionAllowed, tt.policy), discardLogger()),
			}
			setBridgeBackupStores(cfg, &backupSources{oath: &oathStoreAdapter{}, passwords: &passwordStoreAdapter{}})
			bridge, err := pairing.NewBridge(&listBackendsClient{}, cfg)
			require.NoError(t, err)
			handler := newListenHandler(t, bridge)

			raw, err := handler.HandleRequest(context.Background(),
				mustEncodeRequest(t, pairingproto.MethodRemoteCreateBackup, tt.params))
			require.NoError(t, err)

			resp := decodeListenResponse(t, raw)
			require.NotNil(t, resp.Error, "a secret-bearing backup must be refused")
			assert.Equal(t, pairingproto.ErrorCodeSyncNotApproved, resp.Error.Code)
		})
	}
}
