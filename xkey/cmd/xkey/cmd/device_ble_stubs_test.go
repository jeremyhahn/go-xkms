//go:build !ble

package cmd

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

// TestDeviceBLEStubs_ReturnBLEUnavailable checks that, in a build without
// the ble tag, every phone-facing command still exists and fails with the
// typed ErrDeviceBLEUnavailable instead of silently doing nothing.
func TestDeviceBLEStubs_ReturnBLEUnavailable(t *testing.T) {
	commands := map[string]*cobra.Command{
		"backup to-device":   backupToDeviceCmd,
		"backup from-device": backupFromDeviceCmd,
		"device attest":      deviceAttestCmd,
		"device device-info": deviceInfoCmd,
		"device listen":      deviceListenCmd,
		"device pair":        devicePairCmd,
		"device scan":        deviceScanCmd,
		"device share":       deviceShareCmd,
		"device import":      deviceImportCmd,
	}
	for name, c := range commands {
		t.Run(name, func(t *testing.T) {
			assert.Contains(t, c.Long, "-tags ble", "the help must say how to enable BLE")
			assert.ErrorIs(t, c.RunE(c, []string{"a", "b"}), ErrDeviceBLEUnavailable)
		})
	}
}
