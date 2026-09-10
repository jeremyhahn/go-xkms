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

//go:build ble

package cmd

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation/attesttest"
	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// fakePairingTransport is the in-memory pairing transport: discovery returns
// one canned device, connecting is a no-op, and the encrypted channel is the
// initiator half of an attesttest memory pair served by an attesttest.Phone.
type fakePairingTransport struct {
	*attesttest.MemTransport
	device    phone.ScanResult
	connected string
}

func (t *fakePairingTransport) Scan(context.Context) ([]phone.ScanResult, error) {
	return []phone.ScanResult{t.device}, nil
}

func (t *fakePairingTransport) ScanAll(context.Context) ([]phone.ScanResult, error) {
	return []phone.ScanResult{t.device}, nil
}

func (t *fakePairingTransport) Connect(_ context.Context, address string) error {
	t.connected = address
	return nil
}

func (t *fakePairingTransport) Disconnect() error { return nil }

// pairFlow is one driven run of runDevicePair: a phone simulator on the other
// end of a memory transport, the devices file and the trust store replaced
// by seams, and what the command saved captured for assertion.
type pairFlow struct {
	device *attesttest.Phone
	saved  *DevicesConfig
	saves  int
	done   chan error
}

// newPairFlow wires runDevicePair to a simulated phone. The phone's attested
// key chains to phoneCA; the command trusts trustCA, so passing the same CA
// twice makes attestation succeed and two different CAs make it fail at chain
// verification. existing is what the devices file held before the run (nil
// for a first pairing); policy is the user plane of devices.yaml.
func newPairFlow(t *testing.T, phoneCA, trustCA *attesttest.CA, existing *DevicesConfig) *pairFlow {
	t.Helper()

	// The enterprise plane: an unsealed personal config directory, so the
	// user plane in devices.yaml decides, exactly as on a personal machine.
	xkeyconfig.SetConfigDir(t.TempDir())
	t.Cleanup(xkeyconfig.ResetConfigDir)
	withLoadedConfig(t, xkeyconfig.DefaultConfig())

	dak := attesttest.NewDAK(t, phoneCA, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())
	device := attesttest.NewPhone(t, dak)
	device.Name = "Test Pixel"

	initiator, responder := attesttest.NewMemTransportPair()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	done := make(chan error, 1)
	// Pairing is two encrypted exchanges: pairing.confirm, then the attestation.
	device.Serve(ctx, t, responder, false, 2, done)

	flow := &pairFlow{device: device, done: done}
	previous := pairSeams
	t.Cleanup(func() { pairSeams = previous })
	pairSeams = pairingSeams{
		newTransport: func(*phone.BLETransportConfig) (pairingTransport, error) {
			return &fakePairingTransport{
				MemTransport: initiator,
				device:       phone.ScanResult{Address: "AA:BB:CC:DD:EE:FF", LocalName: "Test Pixel"},
			}, nil
		},
		loadDevices: func() (*DevicesConfig, error) {
			if existing == nil {
				return nil, os.ErrNotExist
			}
			return existing, nil
		},
		saveDevices: func(cfg *DevicesConfig) error {
			flow.saves++
			copied := *cfg
			copied.Devices = append([]PairedDevice(nil), cfg.Devices...)
			flow.saved = &copied
			return nil
		},
		loadTrust: func() (*attestation.Trust, error) {
			return &attestation.Trust{Pool: trustCA.Pool()}, nil
		},
	}
	return flow
}

// pairCommand returns a pair command with the flags runDevicePair reads,
// targeting the simulated phone by name so no prompt is ever shown.
func pairCommand(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "pair"}
	cmd.Flags().String("device", "", "")
	cmd.Flags().Duration("timeout", 5*time.Second, "")
	cmd.Flags().Bool("force", false, "")
	addSOPINFlags(cmd)
	require.NoError(t, cmd.Flags().Set("device", "Test Pixel"))
	return cmd
}

// TestRunDevicePair_RefusesAnUnattestableDeviceBeforeSavingUnderDefaultPolicy
// drives the whole command: under the default policy an attestation that
// fails returns before anything is written. The assertion is on the devices
// file the command would have saved, not on the return value alone, so a
// regression that ignores the attestation error, or saves before verifying,
// is caught here even while every helper's own test stays green.
func TestRunDevicePair_RefusesAnUnattestableDeviceBeforeSavingUnderDefaultPolicy(t *testing.T) {
	phoneCA := attesttest.NewCA(t, "Phone Attestation Root")
	strangerCA := attesttest.NewCA(t, "Some Other Root")
	flow := newPairFlow(t, phoneCA, strangerCA, nil)

	err := runDevicePair(pairCommand(t), nil)

	require.Error(t, err, "a device whose attestation chain does not lead to a trusted root must be refused")
	require.False(t, errors.Is(err, ErrPairingPolicyRefused), "the refusal must be the attestation, not the policy plane: %v", err)
	assert.Nil(t, flow.saved, "nothing may be written for a refused device")
	assert.Equal(t, 0, flow.saves)
	require.NoError(t, <-flow.done, "the phone simulator must have served both exchanges")
}

// TestRunDevicePair_SavesAnUnattestableDeviceWithoutClaimsWhenPolicyAllowsIt
// drives the command with the user plane opted in: the same failing
// attestation now completes the pairing, and the saved record carries the
// Noise identity but no attestation claim of any kind.
func TestRunDevicePair_SavesAnUnattestableDeviceWithoutClaimsWhenPolicyAllowsIt(t *testing.T) {
	phoneCA := attesttest.NewCA(t, "Phone Attestation Root")
	strangerCA := attesttest.NewCA(t, "Some Other Root")
	flow := newPairFlow(t, phoneCA, strangerCA, devicesAllowing(true))

	require.NoError(t, runDevicePair(pairCommand(t), nil))

	require.NotNil(t, flow.saved, "policy allows the pairing, so the record must be saved")
	assert.Equal(t, 1, flow.saves)
	require.Len(t, flow.saved.Devices, 1)
	record := flow.saved.Devices[0]
	assert.Equal(t, "Test Pixel", record.Name)
	assert.Equal(t, "AA:BB:CC:DD:EE:FF", record.Address)
	assert.NotEmpty(t, record.NoisePublicKey)
	assert.NotEmpty(t, record.LocalNoisePrivateKey)
	assert.Equal(t, "Test Pixel", flow.saved.DefaultDevice)
	assert.Empty(t, record.DeviceFingerprint, "no verified evidence, no fingerprint")
	assert.Empty(t, record.SecurityLevel, "no verified evidence, no security level")
	assert.False(t, record.BootStateVerified, "no verified evidence, no boot state")
	assert.Zero(t, record.AttestationProtocolVersion)
	assert.True(t, record.LastDeviceAttestationTime.IsZero())
	require.NoError(t, <-flow.done)
}

// TestRunDevicePair_SavesAVerifiedAttestationUnderDefaultPolicy is the
// positive path: the phone's chain leads to the trusted root, the pairing
// completes under the default policy, and the record carries the verified
// fingerprint the phone derived independently.
func TestRunDevicePair_SavesAVerifiedAttestationUnderDefaultPolicy(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	flow := newPairFlow(t, ca, ca, nil)

	require.NoError(t, runDevicePair(pairCommand(t), nil))

	require.NotNil(t, flow.saved)
	require.Len(t, flow.saved.Devices, 1)
	record := flow.saved.Devices[0]
	assert.Equal(t, hex.EncodeToString(flow.device.DAK.Fingerprint()), record.DeviceFingerprint,
		"the stored fingerprint must be the one the phone derived from its own key")
	assert.Equal(t, phone.AttestProtocolV2, record.AttestationProtocolVersion)
	assert.NotEmpty(t, record.SecurityLevel)
	assert.False(t, record.LastDeviceAttestationTime.IsZero())
	require.NoError(t, <-flow.done)
}
