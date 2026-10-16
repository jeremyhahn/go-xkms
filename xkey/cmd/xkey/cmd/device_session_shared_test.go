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

package cmd

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// sealedDeviceKey initializes a barrier under password and returns priv
// sealed under it, as pairing stores a LocalNoisePrivateKey.
func sealedDeviceKey(t *testing.T, password string, priv []byte) string {
	t.Helper()
	isolateDeviceBarrierHome(t)
	initDeviceBarrier(t, password)

	barrier, closeBarrier, err := openDeviceBarrierWithPassword(password)
	require.NoError(t, err)
	defer closeBarrier()

	sealed, err := pairing.SealLocalNoiseKey(barrier, priv)
	require.NoError(t, err)
	return sealed
}

func TestUnsealDeviceLocalKey_SealedKeyUnsealsWithTheBarrierPassword(t *testing.T) {
	priv := bytes.Repeat([]byte{0x42}, 32)
	device := &PairedDevice{LocalNoisePrivateKey: sealedDeviceKey(t, "barrier-pass", priv)}
	t.Setenv("XKEY_BARRIER_PASSWORD", "barrier-pass")

	key, err := unsealDeviceLocalKey(device, discardLogger())
	require.NoError(t, err)
	defer key.Destroy()
	got, err := secure.CopyOut(key)
	require.NoError(t, err)
	defer secure.Wipe(got)
	assert.Equal(t, priv, got)
}

func TestUnsealDeviceLocalKey_SealedKeyWithoutPasswordIsAFormMismatch(t *testing.T) {
	device := &PairedDevice{LocalNoisePrivateKey: sealedDeviceKey(t, "barrier-pass", bytes.Repeat([]byte{0x42}, 32))}

	_, err := unsealDeviceLocalKey(device, discardLogger())
	require.ErrorIs(t, err, ErrSessionKeyDecode)
	assert.ErrorIs(t, err, pairing.ErrNoiseKeyFormMismatch)
}

func TestUnsealDeviceLocalKey_SealedKeyWithWrongPasswordFails(t *testing.T) {
	device := &PairedDevice{LocalNoisePrivateKey: sealedDeviceKey(t, "barrier-pass", bytes.Repeat([]byte{0x42}, 32))}
	t.Setenv("XKEY_BARRIER_PASSWORD", "wrong-pass")

	_, err := unsealDeviceLocalKey(device, discardLogger())
	require.ErrorIs(t, err, ErrSessionKeyDecode)
}
