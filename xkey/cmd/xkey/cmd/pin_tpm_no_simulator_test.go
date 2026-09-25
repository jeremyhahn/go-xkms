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
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOpenTPMModule_SimulatorUnavailable proves that requesting the
// in-process simulator in a build without TPM simulator support fails with
// the typed WrappedError wrapping pkg/tpm2.ErrSimulatorNotAvailable,
// reachable with errors.Is, rather than an untyped fmt.Errorf value. This
// lives behind !tpm_simulator (#985): with the tag present the simulator is
// compiled in and openTPMModule succeeds, so this proof does not apply.
func TestOpenTPMModule_SimulatorUnavailable(t *testing.T) {
	logger := slog.Default()
	dataDir := t.TempDir()

	tpm, closer, err := openTPMModule(logger, dataDir, "", true /* useSimulator */)

	require.Error(t, err)
	assert.Nil(t, tpm)
	assert.Nil(t, closer)

	var wrapped *WrappedError
	require.True(t, errors.As(err, &wrapped), "err = %v, want *WrappedError", err)
	assert.Contains(t, err.Error(), "open tpm")
}
