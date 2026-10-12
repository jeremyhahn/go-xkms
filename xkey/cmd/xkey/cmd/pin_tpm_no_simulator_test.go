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

//go:build !tpm_simulator

package cmd

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

// TestOpenTPMModule_SimulatorUnavailable proves that requesting the
// in-process simulator in a build without TPM simulator support fails with
// pkg/tpm2.ErrSimulatorNotAvailable, reachable with errors.Is, rather than an
// untyped error. localtpm's typed errors pass through openTPMModule unwrapped,
// as TestOpenTPMModule_DeviceNotFound shows for a missing device. This lives
// behind !tpm_simulator (#985): with the tag present the simulator is compiled
// in and openTPMModule succeeds, so this proof does not apply.
func TestOpenTPMModule_SimulatorUnavailable(t *testing.T) {
	logger := slog.Default()
	dataDir := t.TempDir()

	tpm, closer, err := openTPMModule(logger, dataDir, "", true /* useSimulator */)

	require.Error(t, err)
	assert.Nil(t, tpm)
	assert.Nil(t, closer)
	assert.ErrorIs(t, err, tpm2.ErrSimulatorNotAvailable)
}
