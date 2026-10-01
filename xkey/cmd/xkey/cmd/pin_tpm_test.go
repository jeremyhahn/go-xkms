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
	"errors"
	"io/fs"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/localtpm"
)

// TestOpenTPMModule_DeviceNotFound proves that a hardware-mode open against
// a device path that does not exist fails with the typed WrappedError
// introduced by the errors.New -> typed-error migration (#700), reachable
// with errors.As, rather than an untyped fmt.Errorf value.
func TestOpenTPMModule_DeviceNotFound(t *testing.T) {
	logger := slog.Default()
	dataDir := t.TempDir()
	missingDevice := filepath.Join(dataDir, "no-such-tpm-device")

	tpm, closer, err := openTPMModule(logger, dataDir, missingDevice, false /* useSimulator */)

	require.Error(t, err)
	assert.Nil(t, tpm)
	assert.Nil(t, closer)

	var devErr *localtpm.DeviceError
	require.True(t, errors.As(err, &devErr), "err = %v, want *localtpm.DeviceError", err)
	assert.Equal(t, missingDevice, devErr.Device)
	assert.Contains(t, err.Error(), missingDevice)
	assert.ErrorIs(t, err, fs.ErrNotExist, "the error unwraps to the os.Stat cause")
}
