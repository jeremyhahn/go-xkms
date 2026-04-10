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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeviceRelayCmd_Structure(t *testing.T) {
	assert.Equal(t, "relay", deviceRelayCmd.Use)
	assert.Equal(t, "Start TCP pairing relay server", deviceRelayCmd.Short)
	assert.NotEmpty(t, deviceRelayCmd.Long)
	assert.NotNil(t, deviceRelayCmd.RunE)
}

func TestDeviceRelayCmd_Flags(t *testing.T) {
	listenFlag := deviceRelayCmd.Flags().Lookup("listen")
	require.NotNil(t, listenFlag, "listen flag must exist")
	assert.Equal(t, "string", listenFlag.Value.Type())

	qrFlag := deviceRelayCmd.Flags().Lookup("qr")
	require.NotNil(t, qrFlag, "qr flag must exist")
	assert.Equal(t, "bool", qrFlag.Value.Type())
}

func TestDeviceRelayCmd_FlagDefaults(t *testing.T) {
	listenFlag := deviceRelayCmd.Flags().Lookup("listen")
	require.NotNil(t, listenFlag)
	assert.Equal(t, ":8444", listenFlag.DefValue)

	qrFlag := deviceRelayCmd.Flags().Lookup("qr")
	require.NotNil(t, qrFlag)
	assert.Equal(t, "false", qrFlag.DefValue)
}

func TestDeviceRelayCmd_Registered(t *testing.T) {
	found := false
	for _, sub := range deviceCmd.Commands() {
		if sub == deviceRelayCmd {
			found = true
			break
		}
	}
	assert.True(t, found, "deviceRelayCmd must be a subcommand of deviceCmd")
}

func TestDeviceRelayErrors(t *testing.T) {
	t.Run("start_failed", func(t *testing.T) {
		assert.Equal(t, "device: relay server start failed", ErrDeviceRelayStartFailed.Error())
	})

	t.Run("stop_failed", func(t *testing.T) {
		assert.Equal(t, "device: relay server stop failed", ErrDeviceRelayStopFailed.Error())
	})

	t.Run("distinct_errors", func(t *testing.T) {
		assert.NotEqual(t, ErrDeviceRelayStartFailed, ErrDeviceRelayStopFailed)
		assert.NotErrorIs(t, ErrDeviceRelayStartFailed, ErrDeviceRelayStopFailed)
	})
}

func TestRelayHostname(t *testing.T) {
	name := relayHostname()
	assert.NotEmpty(t, name, "relayHostname must return a non-empty string")
	assert.LessOrEqual(t, len(name), 64, "hostname must be truncated to 64 characters")
}
