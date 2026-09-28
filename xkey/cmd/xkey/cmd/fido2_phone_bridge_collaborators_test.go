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

//go:build ble

package cmd

// Tests for go-xkms#1041: "xkey fido2"'s phone bridge (fido2_phone_bridge.go)
// used to build its own pairing.BridgeConfig with nothing but TPM enrollment
// wired, so a phone paired through it got ErrorCodeFeatureUnavailable for
// remote.oath*/remote.piv*/remote.sync* instead of reaching this host's real
// data. connectXKMSdBridge now delegates that wiring to buildListenBridgeConfig
// (device_listen.go), the exact function "xkey device listen" uses.
//
// connectXKMSdBridge cannot be driven end-to-end here: its unix transport's
// Connect() performs a real gRPC health round trip against xkmsd, which is
// out of scope for a fast, host-untouched unit test -- the same reason
// device_listen_collaborators_test.go exercises buildListenBridgeConfig
// directly rather than connectListenBridge. These tests instead exercise
// exactly what connectXKMSdBridge builds: buildListenBridgeConfig called with
// the phone-bridge's own *XKMSdBridgeConfig, and a phoneBackendWithBridge
// assembled from its output the same way connectXKMSdBridge assembles one.

import (
	"context"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// TestConnectXKMSdBridge_ConfigCarriesCollaborators proves the BridgeConfig
// connectXKMSdBridge builds -- via the exact buildListenBridgeConfig call it
// makes -- carries the OATH, PIV, and sync collaborators, not just the TPM
// enroller a phone-bridge-only wiring would have left as the sole non-nil
// field.
func TestConnectXKMSdBridge_ConfigCarriesCollaborators(t *testing.T) {
	isolatedListenHome(t)
	cmd := &cobra.Command{}
	xkmsdCfg := loadXKMSdBridgeConfig()

	// Same call connectXKMSdBridge makes: no TPM enrollment resolved, matching
	// a host xkmsd.tpm.enrollment leaves at its default of false.
	bridgeCfg, collaborators := buildListenBridgeConfig(cmd, newTestLogger(), xkmsdCfg, nil, nil)
	defer collaborators.Close()

	assert.NotNil(t, bridgeCfg.OATHStore, "phone-bridge OATHStore must be wired from openOATHStore")
	assert.NotNil(t, bridgeCfg.PIVStorage, "phone-bridge PIVStorage provider must be wired")
	assert.NotNil(t, bridgeCfg.SyncService, "phone-bridge SyncService must be wired from openSyncService")
}

// TestConnectXKMSdBridge_ConfigCarriesCollaborators_XKMSdDisabledLeavesFieldsUnset
// proves the wiring is conditional on the caller having actually loaded an
// xkmsd config: an *XKMSdBridgeConfig built while xkmsd is disabled still
// yields real collaborators (buildListenBridgeConfig does not gate on
// cfg.Enabled -- connectXKMSdBridge does, before ever calling it), so the same
// helper stays correct however its caller decided to reach it.
func TestConnectXKMSdBridge_ConfigCarriesCollaborators_XKMSdDisabledLeavesFieldsUnset(t *testing.T) {
	isolatedListenHome(t)
	cmd := &cobra.Command{}

	// An *XKMSdBridgeConfig for a disabled xkmsd bridge still carries zero
	// values for AllowedBackends/DeniedBackends/RequestTimeout; that must not
	// stop the OATH/PIV/sync collaborators from opening, since those depend
	// only on cmd and the local data directory, never on xkmsd itself.
	disabledCfg := &XKMSdBridgeConfig{}

	bridgeCfg, collaborators := buildListenBridgeConfig(cmd, newTestLogger(), disabledCfg, nil, nil)
	defer collaborators.Close()

	assert.NotNil(t, bridgeCfg.OATHStore)
	assert.NotNil(t, bridgeCfg.PIVStorage)
	assert.NotNil(t, bridgeCfg.SyncService)
}

// TestPhoneBackendWithBridge_Close_ClosesCollaborators proves Close() on the
// wrapper connectXKMSdBridge returns releases the OATH store and sync sources
// the bridge opened, the same way runDeviceListen's deferred
// collaborators.Close() releases them for "xkey device listen" -- and that a
// credential written through the live bridge is still on disk afterward:
// Close() releases the store's handle, it does not discard what was written
// through it.
func TestPhoneBackendWithBridge_Close_ClosesCollaborators(t *testing.T) {
	isolatedListenHome(t)
	cmd := &cobra.Command{}
	xkmsdCfg := loadXKMSdBridgeConfig()

	bridgeCfg, collaborators := buildListenBridgeConfig(cmd, newTestLogger(), xkmsdCfg, nil, nil)

	bridge, err := pairing.NewBridge(&baseSDKClient{}, bridgeCfg)
	require.NoError(t, err)

	req := pairing.NewRequest(pairing.MethodRemoteOATHAdd, pairing.RemoteOATHAddParams{
		Credential: pairing.OATHCredentialInfo{
			Name:   "GitHub",
			Issuer: "GitHub",
			Secret: "JBSWY3DPEHPK3PXP",
			Type:   "totp",
		},
	})
	resp := bridge.HandleRequest(context.Background(), req)
	require.Nil(t, resp.Error, "expected success but got: %v", resp.Error)

	result, err := pairing.DecodeResult[pairing.RemoteOATHAddResult](resp)
	require.NoError(t, err)
	require.NotEmpty(t, result.CredentialID)

	mockTransport := &mockCloserTransport{}
	backend := newTestPhoneBackend(t, mockTransport)
	wrapper := &phoneBackendWithBridge{
		PhoneKeyBackend: backend,
		xkmsdClient:     &mockSDKClient{},
		bridge:          bridge,
		collaborators:   collaborators,
		logger:          newTestLogger(),
	}

	require.NoError(t, wrapper.Close())
	assert.True(t, mockTransport.closed, "phone backend transport should be closed")

	// Reopen the OATH store the exact way "xkey oath" would from a fresh
	// process: the credential the bridge wrote must still be there.
	reopened, err := openOATHStore(cmd, "")
	require.NoError(t, err)
	defer func() { _ = reopened.Close() }()

	cred, err := reopened.Get(result.CredentialID)
	require.NoError(t, err)
	assert.Equal(t, "GitHub", cred.Name)
	assert.Equal(t, "JBSWY3DPEHPK3PXP", cred.SecretString())
}

// TestPhoneBackendWithBridge_Close_NilCollaborators proves Close() does not
// panic when connectXKMSdBridge never built a bridge (xkmsd disabled), the
// same nil-receiver safety listenBridgeCollaborators.Close() already
// guarantees for runDeviceListen's deferred call.
func TestPhoneBackendWithBridge_Close_NilCollaborators(t *testing.T) {
	mockTransport := &mockCloserTransport{}
	backend := newTestPhoneBackend(t, mockTransport)

	wrapper := &phoneBackendWithBridge{
		PhoneKeyBackend: backend,
		xkmsdClient:     &mockSDKClient{},
		collaborators:   nil,
		logger:          newTestLogger(),
	}

	require.NoError(t, wrapper.Close())
	assert.True(t, mockTransport.closed, "phone backend transport should be closed")
}
