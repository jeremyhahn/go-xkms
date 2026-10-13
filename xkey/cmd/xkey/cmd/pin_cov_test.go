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
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// provisionPINs sets the SO PIN and the user PIN in the isolated store.
func provisionPINs(t *testing.T) {
	t.Helper()

	pipePIN(t, "so-pin-one", "so-pin-one")
	_, err := runPINCmd(t, runPINSetSO)
	require.NoError(t, err)

	pipePIN(t, "so-pin-one", "user-pin-one", "user-pin-one")
	_, err = runPINCmd(t, runPINSetUser)
	require.NoError(t, err)
}

// pinCommands are every PIN command that reads or writes the store.
var pinCommands = map[string]func(*cobra.Command, []string) error{
	"set-so":        runPINSetSO,
	"set-user":      runPINSetUser,
	"change-so":     runPINChangeSO,
	"change-user":   runPINChangeUser,
	"reset-lockout": runPINResetLockout,
	"verify":        runPINVerify,
	"status":        runPINStatus,
}

func TestPINCommands_UnresolvableDataDirReportsResolveFailure(t *testing.T) {
	for name, run := range pinCommands {
		t.Run(name, func(t *testing.T) {
			isolatePIN(t)
			pinDataDir = ""
			// A home below a regular file can neither be found nor created.
			blocker := filepath.Join(t.TempDir(), "regular-file")
			require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
			t.Setenv(xhome.EnvHome, filepath.Join(blocker, "home"))
			xhome.ResetRoot()
			t.Cleanup(xhome.ResetRoot)
			pipePIN(t, "some-pin", "some-pin", "some-pin")

			_, err := runPINCmd(t, run)

			var pinErr *PINCommandError
			require.ErrorAs(t, err, &pinErr)
			assert.Equal(t, "resolve_data_dir", pinErr.Operation)
		})
	}
}

func TestPINSetCommands_UnusableDataDirIsRejected(t *testing.T) {
	for _, name := range []string{"set-so", "set-user"} {
		t.Run(name, func(t *testing.T) {
			isolatePIN(t)
			file := filepath.Join(t.TempDir(), "regular-file")
			require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))
			pinDataDir = file
			pipePIN(t, "some-pin", "some-pin", "some-pin")

			_, err := runPINCmd(t, pinCommands[name])

			var pinErr *PINCommandError
			require.ErrorAs(t, err, &pinErr)
		})
	}
}

func TestPINCommands_PromptFailuresLeaveStoreUnchanged(t *testing.T) {
	tests := []struct {
		name       string
		run        func(*cobra.Command, []string) error
		verifyType string
		lines      []string
		wantErr    error
	}{
		{name: "set-so without current PIN", run: runPINSetSO, wantErr: ErrPINCmdEmpty},
		{name: "set-user without SO PIN", run: runPINSetUser, wantErr: ErrPINCmdEmpty},
		{name: "set-user mismatched new PIN", run: runPINSetUser, lines: []string{"so-pin-one", "new-a", "new-b"}, wantErr: ErrPINCmdMismatch},
		{name: "change-so without current PIN", run: runPINChangeSO, wantErr: ErrPINCmdEmpty},
		{name: "change-so mismatched new PIN", run: runPINChangeSO, lines: []string{"so-pin-one", "new-a", "new-b"}, wantErr: ErrPINCmdMismatch},
		{name: "change-user without current PIN", run: runPINChangeUser, wantErr: ErrPINCmdEmpty},
		{name: "change-user mismatched new PIN", run: runPINChangeUser, lines: []string{"user-pin-one", "new-a", "new-b"}, wantErr: ErrPINCmdMismatch},
		{name: "reset-lockout without SO PIN", run: runPINResetLockout, wantErr: ErrPINCmdEmpty},
		{name: "verify so without PIN", run: runPINVerify, verifyType: "so", wantErr: ErrPINCmdEmpty},
		{name: "verify user without PIN", run: runPINVerify, verifyType: "user", wantErr: ErrPINCmdEmpty},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := isolatePIN(t)
			provisionPINs(t)
			if tt.verifyType != "" {
				pinVerifyType = tt.verifyType
			}
			pipePIN(t, tt.lines...)

			_, err := runPINCmd(t, tt.run)
			require.ErrorIs(t, err, tt.wantErr)

			svc, err := openPINService(dir)
			require.NoError(t, err)
			require.NoError(t, svc.VerifySOPIN("so-pin-one"), "a failed prompt must not change the SO PIN")
			require.NoError(t, svc.VerifyUserPIN("user-pin-one"), "a failed prompt must not change the user PIN")
		})
	}
}

func TestRunPINVerify_InvalidUserPINReportsInvalid(t *testing.T) {
	isolatePIN(t)
	provisionPINs(t)
	pinVerifyType = "user"
	pipePIN(t, "wrong-pin")

	out, err := runPINCmd(t, runPINVerify)

	var pinErr *PINCommandError
	require.ErrorAs(t, err, &pinErr)
	assert.Equal(t, "verify_user", pinErr.Operation)
	assert.Contains(t, out, "User PIN: INVALID")
}

func TestPINCommands_AppLockCounterWriteFailureIsReported(t *testing.T) {
	tests := []struct {
		name      string
		run       func(*cobra.Command, []string) error
		lines     []string
		operation string
	}{
		{name: "set-user", run: runPINSetUser, lines: []string{"so-pin-one", "user-pin-two", "user-pin-two"}, operation: "set_user"},
		{name: "reset-lockout", run: runPINResetLockout, lines: []string{"so-pin-one"}, operation: "reset_lockout"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := isolatePIN(t)
			provisionPINs(t)
			// A non-empty directory where the counter file goes cannot be
			// replaced by the counter write.
			counter := filepath.Join(dir, "pin", "unlock_attempts")
			require.NoError(t, os.RemoveAll(counter))
			require.NoError(t, os.MkdirAll(filepath.Join(counter, "occupied"), 0o700))
			pipePIN(t, tt.lines...)

			out, err := runPINCmd(t, tt.run)

			var pinErr *PINCommandError
			require.ErrorAs(t, err, &pinErr)
			assert.Equal(t, tt.operation, pinErr.Operation)
			assert.NotContains(t, out, "successfully")
		})
	}
}

func TestRunPINStatus_ReportsLiveDaemonLockout(t *testing.T) {
	isolatePIN(t)
	socketPath := startTestDaemon(t, &stateTestHandler{pin: &ipc.PINStateResult{
		Initialized:     true,
		SOPINSet:        true,
		UserPINSet:      true,
		Strategy:        "software",
		FailedAttempts:  5,
		MaxAttempts:     5,
		IsLocked:        true,
		RecoverySeconds: 90,
	}})
	cmd := stateTestCmd(t, socketPath, sourceAuto)
	var out bytes.Buffer
	cmd.SetOut(&out)

	require.NoError(t, runPINStatus(cmd, nil))
	assert.Contains(t, out.String(), "Failed attempts:  5 / 5")
	assert.Contains(t, out.String(), "Locked:           Yes")
	assert.Contains(t, out.String(), "Recovery in:      1m30s")
}

func TestRunPINStatus_DaemonFailureIsNotDowngradedToDisk(t *testing.T) {
	isolatePIN(t)
	socketPath := startTestDaemon(t, &stateTestHandler{err: assertError{}})
	cmd := stateTestCmd(t, socketPath, sourceAuto)
	cmd.SetOut(&bytes.Buffer{})

	err := runPINStatus(cmd, nil)
	require.ErrorIs(t, err, ErrStateDaemonQueryFailed)
}
