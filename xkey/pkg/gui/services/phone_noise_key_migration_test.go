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

package services

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// legacyKeyFixture generates a real Noise static key and returns its raw
// private scalar and the pre-#42 plaintext-base64 form devices.yaml used to
// store, so a test can seed a legacy record that Connect must still be able
// to read.
func legacyKeyFixture(t *testing.T) (raw []byte, encoded string) {
	t.Helper()
	key, err := phone.GenerateStaticKey()
	require.NoError(t, err)
	defer key.Destroy()
	raw = append([]byte(nil), key.Private...)
	encoded = base64.StdEncoding.EncodeToString(raw)
	return raw, encoded
}

// TestPhoneService_Connect_MigratesALegacyPlaintextKeyToSealedStorage is the
// #42 migration contract: a record written before #42 is read once as
// plaintext, and the moment Connect has that key in hand and a barrier is
// available, the record on disk is rewritten to the sealed form. The BLE
// hardware this sandbox lacks means Connect itself still fails past this
// point (ErrPhoneBLEUnavailable / ErrPhoneConnectFailed), which is not the
// behaviour under test -- the migration already happened by then.
func TestPhoneService_Connect_MigratesALegacyPlaintextKeyToSealedStorage(t *testing.T) {
	raw, legacyEncoded := legacyKeyFixture(t)
	remoteRaw, _ := legacyKeyFixture(t) // a distinct 32 bytes, standing in for the phone's public key
	home := tpcbSetupPhoneConfig(t, &phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:                 "LegacyPhone",
				Address:              "AA:AA:AA:AA:AA:AA",
				LocalNoisePrivateKey: legacyEncoded,
				NoisePublicKey:       base64.StdEncoding.EncodeToString(remoteRaw),
			},
		},
	})
	require.False(t, pairing.IsSealedNoiseKey(legacyEncoded), "the fixture must start out as legacy plaintext")

	svc := NewPhoneService()
	svc.SetContext(context.Background())
	svc.SetBarrierService(newUnsealedTestBarrierService(t))

	err := svc.Connect("LegacyPhone")
	require.Error(t, err, "no BLE hardware is available in this sandbox")
	assert.False(t, errors.Is(err, ErrPhoneBarrierRequired),
		"the barrier was available, so the failure must not be attributed to it")

	raw2, readErr := os.ReadFile(filepath.Join(home, ".xkey", devicesConfigFileName))
	require.NoError(t, readErr)
	var cfg phoneConfig
	require.NoError(t, yaml.Unmarshal(raw2, &cfg))
	require.Len(t, cfg.Devices, 1)

	migrated := cfg.Devices[0].LocalNoisePrivateKey
	assert.True(t, pairing.IsSealedNoiseKey(migrated),
		"Connect must have re-sealed and rewritten the record before failing at the BLE step")
	assert.NotContains(t, string(raw2), legacyEncoded,
		"the legacy plaintext base64 must not still be present anywhere on disk")

	// And the migrated form still unseals back to the same key.
	barrier := svc.noiseKeyBarrier()
	require.NotNil(t, barrier)
	buf, unsealErr := pairing.UnsealLocalNoiseKey(barrier, migrated)
	require.NoError(t, unsealErr)
	defer buf.Destroy()
	assert.Equal(t, raw, buf.Bytes())
}

// TestPhoneService_Connect_SealedKeyWithNoBarrierRefuses is the refusal half:
// once a device's record is sealed, Connect must not read it as plaintext
// just because no barrier happens to be wired up for this call.
func TestPhoneService_Connect_SealedKeyWithNoBarrierRefuses(t *testing.T) {
	barrierSvc := newUnsealedTestBarrierService(t)
	raw, _ := legacyKeyFixture(t)
	sealed, err := pairing.SealLocalNoiseKey(barrierSvc.GetBarrier(), raw)
	require.NoError(t, err)

	tpcbSetupPhoneConfig(t, &phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:                 "SealedPhone",
				Address:              "BB:BB:BB:BB:BB:BB",
				LocalNoisePrivateKey: sealed,
				NoisePublicKey:       base64.StdEncoding.EncodeToString(raw),
			},
		},
	})

	svc := NewPhoneService()
	svc.SetContext(context.Background())
	// Deliberately no SetBarrierService: nothing is wired up for this call.

	connErr := svc.Connect("SealedPhone")
	require.Error(t, connErr)
	assert.ErrorIs(t, connErr, ErrPhoneBarrierRequired,
		"a sealed key must never be read as plaintext just because no barrier is available")
}

// TestPhoneService_Connect_SealedKeyWithSealedBarrierRefuses covers the other
// sealed-barrier case: the BarrierService is wired and was initialized, but
// it has been re-sealed since (e.g. an app lock), so noiseKeyBarrier reports
// no usable barrier and this service refuses rather than falling back to
// plaintext -- the #42 owner ruling that a barrier which EXISTS but cannot
// currently be opened is always a refusal, never a downgrade.
func TestPhoneService_Connect_SealedKeyWithSealedBarrierRefuses(t *testing.T) {
	barrierSvc := newUnsealedTestBarrierService(t)
	raw, _ := legacyKeyFixture(t)
	sealed, err := pairing.SealLocalNoiseKey(barrierSvc.GetBarrier(), raw)
	require.NoError(t, err)
	require.NoError(t, barrierSvc.Seal())

	tpcbSetupPhoneConfig(t, &phoneConfig{
		Devices: []phoneConfigDevice{
			{
				Name:                 "ReSealedPhone",
				Address:              "CC:CC:CC:CC:CC:CC",
				LocalNoisePrivateKey: sealed,
				NoisePublicKey:       base64.StdEncoding.EncodeToString(raw),
			},
		},
	})

	svc := NewPhoneService()
	svc.SetContext(context.Background())
	svc.SetBarrierService(barrierSvc)

	connErr := svc.Connect("ReSealedPhone")
	require.Error(t, connErr)
	assert.ErrorIs(t, connErr, ErrPhoneBarrierRequired,
		"a re-sealed barrier must refuse to read a sealed key, never fall back to plaintext")
}
