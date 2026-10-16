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
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// stubAttestationTPM stands in for an already-open attestation TPM. Only its
// identity matters: resolveListenEnroller must hand back the same handle
// rather than opening the device a second time, and must never call into it,
// so the embedded interface is deliberately nil.
type stubAttestationTPM struct {
	xkms.TrustedPlatformModule
}

// These tests cover which TPM `xkey device listen` hands the bridge for TCG
// device enrollment. The defect they guard is a bridge built with no TPM at
// all, which makes every enrollment request report the feature as
// unconfigured regardless of what the host has.

// TestResolveListenEnroller covers the ways enrollment ends up unavailable:
// it was not asked for, the host has no TPM, or the host has one that will
// not open. None of them may produce a handle the caller would try to close.
func TestResolveListenEnroller(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
		device  string
	}{
		{
			name:    "disabled offers no TPM",
			enabled: false,
			device:  filepath.Join(t.TempDir(), "irrelevant"),
		},
		{
			name:    "enabled on a host with no TPM",
			enabled: true,
			device:  filepath.Join(t.TempDir(), "no-such-tpm"),
		},
		{
			name:    "enabled on a host whose TPM will not open",
			enabled: true,
			device:  t.TempDir(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enroller, closer, _ := resolveListenEnroller(tt.enabled, nil, tt.device, "", newTestLogger())

			assert.Nil(t, enroller, "an unusable TPM must leave enrollment unavailable")
			assert.Nil(t, closer, "nothing was opened, so there is nothing to close")
		})
	}
}

// TestResolveListenEnroller_ReusesTheAttestationTPM proves the device is
// opened once. When the attestor already holds this host's TPM, enrollment
// shares that handle and does not take ownership of closing it — the
// attestor's own deferred Close still owns it.
func TestResolveListenEnroller_ReusesTheAttestationTPM(t *testing.T) {
	attestTPM := &stubAttestationTPM{}

	enroller, closer, _ := resolveListenEnroller(true, attestTPM, "/dev/does-not-matter", "", newTestLogger())

	assert.Same(t, attestTPM, enroller, "the already-open TPM must be reused")
	assert.Nil(t, closer, "the attestor still owns the handle")
}

// TestConnectListenBridge_DisabledXKMSdServesNoBridge documents that the
// enroller is irrelevant when xkmsd is off: without a client there is no
// bridge to configure at all.
func TestConnectListenBridge_DisabledXKMSdServesNoBridge(t *testing.T) {
	client, bridge, collaborators, err := connectListenBridge(&cobra.Command{}, newTestLogger(), testListenDevice, nil, nil, pairing.AlwaysApproveSync)

	require.NoError(t, err)
	assert.Nil(t, client)
	assert.Nil(t, bridge)
	assert.Nil(t, collaborators)
}

// TestListenHandler_WithoutAnEnrollmentTPM_ReportsUnavailable is the
// end-to-end shape of the "no TPM" outcome as the phone sees it: an explicit
// attestation-unsupported error rather than a failure.
func TestListenHandler_WithoutAnEnrollmentTPM_ReportsUnavailable(t *testing.T) {
	bridge, err := pairing.NewBridge(&listBackendsClient{}, &pairing.BridgeConfig{
		Logger: newTestLogger(),
		TPM:    nil,
	})
	require.NoError(t, err)

	handler := newListenHandler(t, bridge)
	raw, err := handler.HandleRequest(context.Background(),
		mustEncodeRequest(t, pairingproto.MethodRemoteGetTCGCSRIDevID, map[string]any{"backend": "tpm2"}))
	require.NoError(t, err)

	resp := decodeListenResponse(t, raw)
	require.NotNil(t, resp.Error)
	assert.Equal(t, pairingproto.ErrorCodeAttestUnsupported, resp.Error.Code)
}
