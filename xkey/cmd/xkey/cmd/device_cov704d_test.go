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
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// errC704dQuoteFailed is the fault c704dQuoteFailTPM reports from Quote.
var errC704dQuoteFailed = errors.New("c704d: quote failed")

// c704dQuoteFailTPM is a TPM whose Quote always fails, so the laptop
// attestor's TPM2 path reaches its generation-failure branch. Only Quote is
// ever called by the attestor; every other method is the nil embedded
// interface and would panic if reached.
type c704dQuoteFailTPM struct {
	xkms.TrustedPlatformModule
}

func (c704dQuoteFailTPM) Quote([]uint, []byte) (xkms.Quote, error) {
	return xkms.Quote{}, errC704dQuoteFailed
}

// c704dEnableXKMSd points the xkmsd bridge configuration at address, with
// the harness's TLS material, for the rest of the test.
func c704dEnableXKMSd(t *testing.T, address string) {
	t.Helper()
	resetViperForTest(t)
	cfg := testBridgeConfig(address)
	viper.Set("xkmsd.enabled", true)
	viper.Set("xkmsd.protocol", cfg.Protocol)
	viper.Set("xkmsd.address", cfg.Address)
	viper.Set("xkmsd.connect_timeout", cfg.ConnectTimeout)
	viper.Set("xkmsd.tls_ca_file", cfg.TLSCAFile)
	viper.Set("xkmsd.tls_cert_file", cfg.TLSCertFile)
	viper.Set("xkmsd.tls_key_file", cfg.TLSKeyFile)
}

// c704dAttest sends remote.attestDevice with params to handler and returns
// the decoded response.
func c704dAttest(t *testing.T, handler *listenRequestHandler, params interface{}) *pairingproto.Response {
	t.Helper()
	raw, err := handler.HandleRequest(context.Background(),
		mustEncodeRequest(t, pairingproto.MethodRemoteAttestDevice, params))
	require.NoError(t, err)
	return decodeListenResponse(t, raw)
}

func TestConnectListenBridge_DisabledReturnsNoBridge(t *testing.T) {
	resetViperForTest(t)
	viper.Set("xkmsd.enabled", false)

	client, bridge, collaborators, err := connectListenBridge(&cobra.Command{}, discardLogger(), testListenDevice, nil, nil, nil)

	require.NoError(t, err)
	assert.Nil(t, client)
	assert.Nil(t, bridge)
	assert.Nil(t, collaborators, "no bridge means no collaborators to close")
}

func TestConnectListenBridge_UnsupportedProtocolRefuses(t *testing.T) {
	resetViperForTest(t)
	viper.Set("xkmsd.enabled", true)
	viper.Set("xkmsd.protocol", "websocket")

	client, bridge, _, err := connectListenBridge(&cobra.Command{}, discardLogger(), testListenDevice, nil, nil, nil)

	require.ErrorIs(t, err, ErrXKMSdConnectionFailed)
	require.ErrorIs(t, err, ErrXKMSdUnsupportedProtocol)
	assert.Nil(t, client)
	assert.Nil(t, bridge)
}

// TestConnectListenBridge_ServesRemoteMethodsFromXKMSd dials a real xkmsd
// and proves the returned bridge forwards remote.* requests to it.
func TestConnectListenBridge_ServesRemoteMethodsFromXKMSd(t *testing.T) {
	isolatedListenHome(t)
	address, _ := startTestXKMSd(t)
	c704dEnableXKMSd(t, address)

	client, bridge, collaborators, err := connectListenBridge(&cobra.Command{}, discardLogger(), testListenDevice, nil, nil, pairing.AlwaysApproveSync)
	require.NoError(t, err)
	require.NotNil(t, client)
	require.NotNil(t, bridge)
	defer func() { require.NoError(t, client.Close()) }()
	defer collaborators.Close()

	handler := newListenHandler(t, bridge)
	raw, err := handler.HandleRequest(context.Background(),
		mustEncodeRequest(t, pairingproto.MethodRemoteListBackends, nil))
	require.NoError(t, err)

	resp := decodeListenResponse(t, raw)
	require.Nil(t, resp.Error, "the bridge must serve remote.listBackends from xkmsd")
	_, err = pairingproto.DecodeResult[pairingproto.RemoteListBackendsResult](resp)
	require.NoError(t, err)
}

func TestRunDeviceRelay_ServesWithXKMSdBridge(t *testing.T) {
	cmd, out := pairedRelayCommand(t, "50ms")
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "attestation-mode", "software"))
	address, _ := startTestXKMSd(t)
	c704dEnableXKMSd(t, address)

	require.NoError(t, runDeviceRelay(cmd, nil))

	assert.Contains(t, out.String(), "xkmsd bridge: enabled (full remote.* method set)")
	assert.Contains(t, out.String(), "Relay timeout reached")
}

func TestRunDeviceRelay_RefusesWhenXKMSdBridgeCannotConnect(t *testing.T) {
	cmd, out := pairedRelayCommand(t, "50ms")
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "attestation-mode", "software"))
	resetViperForTest(t)
	viper.Set("xkmsd.enabled", true)
	viper.Set("xkmsd.protocol", "websocket")

	err := runDeviceRelay(cmd, nil)

	require.ErrorIs(t, err, ErrXKMSdConnectionFailed)
	assert.NotContains(t, out.String(), "TCP pairing relay listening")
}

func TestRunDeviceRelay_EmptyDeviceListIsNotPaired(t *testing.T) {
	isolateDeviceBarrierHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{}))
	cmd := relayCommand(t)
	out := &strings.Builder{}
	cmd.SetOut(out)

	err := runDeviceRelay(cmd, nil)

	require.ErrorIs(t, err, ErrDeviceNotPaired)
	assert.Contains(t, out.String(), "No paired devices")
}

func TestRunDeviceRelay_CorruptDevicesFileFailsToLoad(t *testing.T) {
	isolateDeviceBarrierHome(t)
	path, err := getDevicesConfigPath()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte("devices: [unterminated"), 0o600))

	err = runDeviceRelay(relayCommand(t), nil)

	require.ErrorIs(t, err, ErrDeviceConfigLoadFailed)
	assert.NotErrorIs(t, err, ErrDeviceNotPaired)
}

func TestResolveListenTargetDevice_DefaultDeviceIsSelected(t *testing.T) {
	cfg := &DevicesConfig{
		DefaultDevice: "Second",
		Devices: []PairedDevice{
			{Name: "First", NoisePublicKey: validNoisePublicKeyForTest(t), LocalNoisePrivateKey: validLocalNoisePrivateKeyForTest(t)},
			{Name: "Second", NoisePublicKey: validNoisePublicKeyForTest(t), LocalNoisePrivateKey: validLocalNoisePrivateKeyForTest(t)},
		},
	}

	device, _, localKey, err := resolveListenTargetDevice(cfg, "", nil, discardLogger())
	require.NoError(t, err)
	defer localKey.Destroy()

	assert.Equal(t, "Second", device.Name)
}

func TestResolveListenTargetDevice_Refusals(t *testing.T) {
	validPublic := validNoisePublicKeyForTest(t)
	validPrivate := validLocalNoisePrivateKeyForTest(t)

	tests := []struct {
		name    string
		cfg     *DevicesConfig
		filter  string
		wantErr error
	}{
		{
			name:    "default device missing",
			cfg:     &DevicesConfig{DefaultDevice: "Gone", Devices: []PairedDevice{{Name: "A"}, {Name: "B"}}},
			wantErr: ErrDeviceNoDefaultDevice,
		},
		{
			name:    "default device ambiguous",
			cfg:     &DevicesConfig{DefaultDevice: "A", Devices: []PairedDevice{{Name: "A"}, {Name: "A"}}},
			wantErr: ErrDeviceNameAmbiguous,
		},
		{
			name:    "pinned key wrong length",
			cfg:     &DevicesConfig{Devices: []PairedDevice{{Name: "A", NoisePublicKey: base64.StdEncoding.EncodeToString([]byte("short"))}}},
			wantErr: ErrDevicePinInvalid,
		},
		{
			name:    "local key missing",
			cfg:     &DevicesConfig{Devices: []PairedDevice{{Name: "A", NoisePublicKey: validPublic}}},
			filter:  "A",
			wantErr: pairing.ErrNoiseKeyEmpty,
		},
		{
			name: "sealed local key without a barrier",
			cfg: &DevicesConfig{Devices: []PairedDevice{{
				Name: "A", NoisePublicKey: validPublic,
				LocalNoisePrivateKey: pairing.NoiseKeySealedPrefix + validPrivate,
			}}},
			wantErr: ErrDeviceListenFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			device, remote, localKey, err := resolveListenTargetDevice(tt.cfg, tt.filter, nil, discardLogger())

			require.ErrorIs(t, err, tt.wantErr)
			assert.Nil(t, device)
			assert.Nil(t, remote)
			assert.Nil(t, localKey)
		})
	}
}

func TestResolveListenTargetDevice_UndecodablePinnedKey(t *testing.T) {
	cfg := &DevicesConfig{Devices: []PairedDevice{{Name: "A", NoisePublicKey: "!!not base64!!"}}}

	_, _, _, err := resolveListenTargetDevice(cfg, "", nil, discardLogger())

	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
	assert.Equal(t, "failed to decode phone public key", wrapped.Msg)
}

func TestListenHandler_AttestDeviceErrorCodes(t *testing.T) {
	tests := []struct {
		name     string
		tpm      xkms.TrustedPlatformModule
		mode     pairing.AttestationMode
		params   interface{}
		wantCode int
	}{
		{
			name:     "undecodable parameters",
			mode:     pairing.AttestationModeSoftware,
			params:   map[string]interface{}{"nonce": 42},
			wantCode: pairingproto.ErrorCodeInvalidParams,
		},
		{
			name:     "nonce not 32 bytes",
			mode:     pairing.AttestationModeSoftware,
			params:   &pairingproto.RemoteAttestDeviceParams{Nonce: make([]byte, 8)},
			wantCode: pairingproto.ErrorCodeInvalidParams,
		},
		{
			name:     "tpm2 required but absent",
			mode:     pairing.AttestationModeTPM2,
			params:   &pairingproto.RemoteAttestDeviceParams{Nonce: make([]byte, 32)},
			wantCode: pairingproto.ErrorCodeAttestUnsupported,
		},
		{
			name:     "tpm2 quote fails",
			tpm:      c704dQuoteFailTPM{},
			mode:     pairing.AttestationModeTPM2,
			params:   &pairingproto.RemoteAttestDeviceParams{Nonce: make([]byte, 32)},
			wantCode: pairingproto.ErrorCodeAttestFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, err := newListenRequestHandler(discardLogger(), tt.tpm, tt.mode, nil)
			require.NoError(t, err)

			resp := c704dAttest(t, handler, tt.params)

			require.NotNil(t, resp.Error)
			assert.Equal(t, tt.wantCode, resp.Error.Code)
		})
	}
}
