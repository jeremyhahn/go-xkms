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
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// isolateServeHome points xKey's home at a fresh directory with local app
// access switched on, and returns the home's data directory.
func isolateServeHome(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	xhome.SetRoot(root)
	t.Cleanup(xhome.ResetRoot)
	enableLocalAppAccessForTest(t)
	return filepath.Join(root, "data")
}

// serveRunCmd builds `xkey extension serve` over the flags the real command
// registers, listening on socketPath and logging only errors.
func serveRunCmd(t *testing.T, socketPath string, noBarrier bool) *cobra.Command {
	t.Helper()
	cmd := newTestServeCmd()
	cmd.RunE = runExtensionServe
	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Flags().Set("socket", socketPath))
	require.NoError(t, cmd.Flags().Set("log-level", "error"))
	require.NoError(t, cmd.Flags().Set("no-barrier", strconv.FormatBool(noBarrier)))
	return cmd
}

// startServe runs cmd until its socket appears and returns a client for it
// together with a stop function. Stopping cancels the run and requires a
// clean exit; it is idempotent and also runs at cleanup.
func startServe(t *testing.T, cmd *cobra.Command, socketPath string) (*ipc.Client, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- cmd.ExecuteContext(ctx) }()

	exited := false
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			if exited {
				return
			}
			select {
			case err := <-done:
				assert.NoError(t, err, "serve should stop cleanly")
			case <-time.After(10 * time.Second):
				t.Error("serve did not stop after its context was cancelled")
			}
		})
	}
	t.Cleanup(stop)

	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		select {
		case err := <-done:
			exited = true
			t.Fatalf("serve exited before listening: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("serve never opened its socket")
		}
	}

	client := ipc.NewClient(socketPath)
	t.Cleanup(func() { assert.NoError(t, client.Close()) })
	return client, stop
}

// requireLockState asserts the lock state the running daemon reports.
func requireLockState(t *testing.T, client *ipc.Client, want string) {
	t.Helper()
	resp, err := client.Status()
	require.NoError(t, err)
	require.Equal(t, ipc.StatusOK, resp.Status, resp.Error)
	require.Equal(t, want, resp.Action)
}

// TestExtensionServe_ReopensAnExistingPassphraseBarrier is the restart path:
// the first run initializes the barrier, and every later run must unseal that
// same barrier with the same password -- or refuse to start.
func TestExtensionServe_ReopensAnExistingPassphraseBarrier(t *testing.T) {
	dataDir := isolateServeHome(t)
	const password = "serve-barrier-password"
	socketPath := filepath.Join(privateTempDir(t), "serve.sock")

	t.Setenv(barrierPasswordSource.envVar, password)
	_, stop := startServe(t, serveRunCmd(t, socketPath, false), socketPath)
	stop()

	strategy, err := readBarrierStrategy(dataDir)
	require.NoError(t, err)
	require.Equal(t, "passphrase", string(strategy))

	t.Run("the same password from a file unseals it", func(t *testing.T) {
		t.Setenv(barrierPasswordSource.envVar, "")
		passwordFile := filepath.Join(t.TempDir(), "barrier-password")
		require.NoError(t, os.WriteFile(passwordFile, []byte(password+"\nignored second line\n"), 0o600))

		socketPath := filepath.Join(privateTempDir(t), "serve.sock")
		cmd := serveRunCmd(t, socketPath, false)
		require.NoError(t, cmd.Flags().Set("barrier-password-file", passwordFile))
		client, _ := startServe(t, cmd, socketPath)
		requireLockState(t, client, ipc.ActionUnlocked)
	})

	t.Run("a wrong password refuses to start", func(t *testing.T) {
		t.Setenv(barrierPasswordSource.envVar, "not-the-password")
		socketPath := filepath.Join(privateTempDir(t), "serve.sock")

		err := serveRunCmd(t, socketPath, false).Execute()
		require.ErrorIs(t, err, ErrServeBarrierUnsealFailed)
		assert.NoFileExists(t, socketPath)
	})

	t.Run("an unreadable password file refuses to start", func(t *testing.T) {
		t.Setenv(barrierPasswordSource.envVar, "")
		socketPath := filepath.Join(privateTempDir(t), "serve.sock")
		cmd := serveRunCmd(t, socketPath, false)
		require.NoError(t, cmd.Flags().Set("barrier-password-file", filepath.Join(t.TempDir(), "absent")))

		err := cmd.Execute()
		require.ErrorIs(t, err, ErrServeBarrierPasswordRequired)
		assert.NoFileExists(t, socketPath)
	})
}

// TestExtensionServe_RefusesABarrierItCannotDispatch proves an initialized
// barrier whose sealing strategy cannot be determined, or is not one serve
// knows, stops the daemon before it listens.
func TestExtensionServe_RefusesABarrierItCannotDispatch(t *testing.T) {
	tests := []struct {
		name    string
		rootKey string
		want    []error
	}{
		{
			name:    "unknown strategy",
			rootKey: `{"version":1,"strategy":"rot13","sealed_data":{},"created_at":"2026-01-01T00:00:00Z"}`,
			want:    []error{ErrServeStrategyUnsupported},
		},
		{
			name:    "root key names no strategy",
			rootKey: `{"version":1,"sealed_data":{},"created_at":"2026-01-01T00:00:00Z"}`,
			want:    []error{ErrServeStrategyReadFailed, ErrServeRootKeyMissingStrategy},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataDir := isolateServeHome(t)
			writeBarrierRootKey(t, dataDir, []byte(tt.rootKey))
			socketPath := filepath.Join(privateTempDir(t), "serve.sock")

			err := serveRunCmd(t, socketPath, false).Execute()
			for _, want := range tt.want {
				require.ErrorIs(t, err, want)
			}
			assert.NoFileExists(t, socketPath)
		})
	}
}

// TestExtensionServe_TPM2BarrierWithoutATPMRefusesToStart covers a tpm2
// barrier with no auto-unseal policy on a host with no TPM: the fallback to a
// direct TPM unseal has nothing to open, so serve refuses to start.
func TestExtensionServe_TPM2BarrierWithoutATPMRefusesToStart(t *testing.T) {
	dataDir := isolateServeHome(t)
	writeSealedRootKey(t, dataDir, "tpm2")
	socketPath := filepath.Join(privateTempDir(t), "serve.sock")

	cmd := serveRunCmd(t, socketPath, false)
	require.NoError(t, cmd.Flags().Set("tpm-device", "/nonexistent/tpmrm0"))

	err := cmd.Execute()
	require.ErrorIs(t, err, ErrServeTPMOpenFailed)
	assert.NoFileExists(t, socketPath)
}

// TestExtensionServe_LocksAtStartupWhenAUserPINIsSet proves a daemon started
// over a device with a user PIN comes up locked, with or without a barrier,
// and that the user PIN -- not anything else -- unlocks it over IPC.
func TestExtensionServe_LocksAtStartupWhenAUserPINIsSet(t *testing.T) {
	for _, noBarrier := range []bool{true, false} {
		t.Run("no-barrier="+strconv.FormatBool(noBarrier), func(t *testing.T) {
			dataDir := isolateServeHome(t)
			t.Setenv(barrierPasswordSource.envVar, "serve-barrier-password")

			// A device gets its barrier on first start and its PINs later.
			socketPath := filepath.Join(privateTempDir(t), "serve.sock")
			_, stop := startServe(t, serveRunCmd(t, socketPath, noBarrier), socketPath)
			stop()

			pins, err := createPINService(dataDir)
			require.NoError(t, err)
			require.NoError(t, pins.SetSOPIN("", "so-pin-12345678"))
			require.NoError(t, pins.SetUserPIN("so-pin-12345678", "user-pin-1234"))

			socketPath = filepath.Join(privateTempDir(t), "serve.sock")
			client, _ := startServe(t, serveRunCmd(t, socketPath, noBarrier), socketPath)
			requireLockState(t, client, ipc.ActionLocked)

			resp, err := client.Unlock("not-the-pin")
			require.NoError(t, err)
			assert.NotEqual(t, ipc.StatusOK, resp.Status)
			requireLockState(t, client, ipc.ActionLocked)

			resp, err = client.Unlock("user-pin-1234")
			require.NoError(t, err)
			require.Equal(t, ipc.StatusOK, resp.Status, resp.Error)
			requireLockState(t, client, ipc.ActionUnlocked)
		})
	}
}

// TestExtensionServe_RefusesAnUnusablePINStateDirectory proves serve stops
// with a typed error when the PIN state directory cannot be created.
func TestExtensionServe_RefusesAnUnusablePINStateDirectory(t *testing.T) {
	isolateServeHome(t)
	blocker := filepath.Join(t.TempDir(), "a-file")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	socketPath := filepath.Join(privateTempDir(t), "serve.sock")

	cmd := serveRunCmd(t, socketPath, true)
	require.NoError(t, cmd.Flags().Set("pin-state", filepath.Join(blocker, "pin")))

	err := cmd.Execute()
	require.ErrorIs(t, err, ErrServePINManagerInitFailed)
	assert.NoFileExists(t, socketPath)
}

// sealEnterprisePolicy seals cfg's policy under testSOPIN in the isolated
// configuration directory, makes cfg the loaded configuration, and supplies
// the SO PIN the way a headless deployment does.
func sealEnterprisePolicy(t *testing.T, cfg *config.Config) {
	t.Helper()
	configDir := config.ConfigDir()
	require.NoError(t, os.MkdirAll(configDir, 0o700))
	require.NoError(t, config.WritePolicyHMAC(&cfg.Policy, testSOPIN, config.PolicyHMACPath(configDir)))
	withLoadedConfig(t, cfg)
	t.Setenv(soPINEnvVar, testSOPIN)
}

// TestExtensionServe_HonoursTheSealedEnterprisePolicy proves a verified
// enterprise policy governs the daemon: it can switch the extension off
// entirely, and its authentication requirement overrides the operator's
// --no-auth.
func TestExtensionServe_HonoursTheSealedEnterprisePolicy(t *testing.T) {
	t.Run("a disabled extension refuses to start", func(t *testing.T) {
		isolateServeHome(t)
		cfg := config.DefaultConfig()
		cfg.Policy.ExtensionEnabled = false
		sealEnterprisePolicy(t, cfg)
		socketPath := filepath.Join(privateTempDir(t), "serve.sock")

		err := serveRunCmd(t, socketPath, true).Execute()
		require.ErrorIs(t, err, ErrServeIPCStartFailed)
		assert.Contains(t, err.Error(), "disabled by enterprise policy")
		assert.NoFileExists(t, socketPath)
	})

	t.Run("required authentication overrides --no-auth", func(t *testing.T) {
		isolateServeHome(t)
		cfg := config.DefaultConfig()
		cfg.Policy.ExtensionRequireAuthentication = true
		cfg.Policy.ExtensionRequirePairing = true
		sealEnterprisePolicy(t, cfg)
		socketPath := filepath.Join(privateTempDir(t), "serve.sock")

		cmd := serveRunCmd(t, socketPath, true)
		require.NoError(t, cmd.Flags().Set("no-auth", "true"))
		require.NoError(t, cmd.Flags().Set("no-pairing", "true"))
		client, _ := startServe(t, cmd, socketPath)

		resp, err := client.AutofillPolicy()
		require.NoError(t, err)
		require.Equal(t, ipc.StatusOK, resp.Status, resp.Error)
		require.NotNil(t, resp.Autofill)
		require.NotNil(t, resp.Autofill.Policy)
		assert.True(t, resp.Autofill.Policy.RequireAuthentication, "--no-auth must not relax a sealed requirement")
	})
}
