//go:build tpm_simulator

package cmd

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// TestExtensionServe_TPM2BarrierTheSimulatorCannotUnsealRefusesToStart runs
// serve over a tpm2 barrier on a fresh simulator: the auto-unseal policy is
// unavailable on a TPM that was never enrolled, so serve falls back to a
// direct unseal with the simulator, which cannot open the planted root key,
// and serve refuses to start with the typed unseal error.
func TestExtensionServe_TPM2BarrierTheSimulatorCannotUnsealRefusesToStart(t *testing.T) {
	dataDir := isolateServeHome(t)
	writeSealedRootKey(t, dataDir, "tpm2")
	socketPath := filepath.Join(privateTempDir(t), "serve.sock")

	cmd := serveRunCmd(t, socketPath, false)
	require.NoError(t, cmd.Flags().Set("tpm-simulator", "true"))

	err := cmd.Execute()
	require.ErrorIs(t, err, ErrServeBarrierUnsealFailed)
	assert.NotErrorIs(t, err, ErrServeTPMOpenFailed, "the simulator opened; the unseal itself failed")
	assert.NoFileExists(t, socketPath)
	assertSimulatorReleased(t)
}

// assertSimulatorReleased fails the test unless the process-wide simulator
// can be opened again: an open simulator holds go-tpm-tools' global lock, so
// a TPM a failed command leaked blocks every later simulator test.
func assertSimulatorReleased(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	opened := make(chan error, 1)
	go func() {
		sim, err := xkms.OpenSimulator()
		if err == nil {
			err = sim.Close()
		}
		opened <- err
	}()
	select {
	case err := <-opened:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal("the simulator is still held: the command did not release its TPM")
	}
}
