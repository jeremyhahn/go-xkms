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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

var errVaultServer = errors.New("vault: credential rejected")

// newVaultTestClient returns a mock password client with the vault secret
// environment variables cleared, so only what the test itself sets reaches
// the command.
func newVaultTestClient(t *testing.T) *mockPasswordStoreClient {
	t.Helper()
	t.Setenv("XKEY_VAULT_PASSPHRASE", "")
	t.Setenv("XKEY_VAULT_RECOVERY_CODE", "")
	return newMockPasswordStoreClient()
}

// runPasswordVault executes "xkey password vault <args>" against mock and
// returns the command output and error.
func runPasswordVault(t *testing.T, mock *mockPasswordStoreClient, args ...string) (string, error) {
	t.Helper()
	resetCommandFlagsForTest(t, RootCmd)
	resetPasswordFlags()
	withMockPasswordClient(t, mock)

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs(append([]string{"password", "vault"}, args...))
	err := RootCmd.Execute()
	return buf.String(), err
}

func enrolledVaultFactor(recoveryCode string) *transport.PasswordVaultEnrollResponse {
	return &transport.PasswordVaultEnrollResponse{
		Factor:       transport.PasswordVaultFactor{ID: "f-1", Factor: "passphrase", Label: "laptop"},
		RecoveryCode: recoveryCode,
	}
}

func TestPasswordVaultStatus(t *testing.T) {
	mock := newVaultTestClient(t)
	mock.vaultStatusResp = &transport.PasswordVaultStatusResponse{
		Initialized: true,
		Factors: []transport.PasswordVaultFactor{
			{ID: "f-1", Factor: "passphrase", Label: "laptop", CreatedAt: "2026-09-30T00:00:00Z"},
		},
	}

	out, err := runPasswordVault(t, mock, "status")
	require.NoError(t, err)
	assert.Contains(t, out, "Initialized:  Yes")
	assert.Contains(t, out, "Unlocked:     No")
	assert.Contains(t, out, "f-1")
	assert.Contains(t, out, "laptop")
}

func TestPasswordVaultStatus_ServerError(t *testing.T) {
	mock := newVaultTestClient(t)
	mock.vaultStatusErr = errVaultServer

	_, err := runPasswordVault(t, mock, "status")
	assert.ErrorIs(t, err, ErrPasswordVaultStatusFailed)
	assert.ErrorIs(t, err, errVaultServer)
}

func TestPasswordVaultEnroll_FirstEnrollmentShowsRecoveryCode(t *testing.T) {
	mock := newVaultTestClient(t)
	mock.vaultEnrollResp = enrolledVaultFactor("ABCD-EFGH")
	stubStdin(t, []byte("correct horse\n"), nil)

	out, err := runPasswordVault(t, mock, "enroll", "--passphrase-stdin", "--label", "laptop")
	require.NoError(t, err)
	require.NotNil(t, mock.lastEnrollReq)
	assert.Equal(t, "passphrase", mock.lastEnrollReq.Factor)
	assert.Equal(t, "correct horse", mock.lastEnrollReq.Passphrase)
	assert.Equal(t, "laptop", mock.lastEnrollReq.Label)
	assert.Contains(t, out, "ABCD-EFGH")
	assert.Contains(t, out, "it will not be shown again")
}

func TestPasswordVaultEnroll_LaterEnrollmentHasNoRecoveryBanner(t *testing.T) {
	mock := newVaultTestClient(t)
	mock.vaultEnrollResp = enrolledVaultFactor("")
	t.Setenv("XKEY_VAULT_PASSPHRASE", "second phrase")

	out, err := runPasswordVault(t, mock, "enroll")
	require.NoError(t, err)
	assert.Equal(t, "second phrase", mock.lastEnrollReq.Passphrase)
	assert.NotContains(t, out, "RECOVERY CODE")
}

func TestPasswordVaultEnroll_Errors(t *testing.T) {
	t.Run("no passphrase", func(t *testing.T) {
		mock := newVaultTestClient(t)
		_, err := runPasswordVault(t, mock, "enroll")
		assert.ErrorIs(t, err, ErrPasswordMissingPassphrase)
		assert.Nil(t, mock.lastEnrollReq)
	})
	t.Run("empty stdin", func(t *testing.T) {
		mock := newVaultTestClient(t)
		stubStdin(t, []byte("\n"), nil)
		_, err := runPasswordVault(t, mock, "enroll", "--passphrase-stdin")
		assert.ErrorIs(t, err, ErrPasswordPassphraseStdinEmpty)
	})
	t.Run("server error", func(t *testing.T) {
		mock := newVaultTestClient(t)
		mock.vaultEnrollErr = errVaultServer
		t.Setenv("XKEY_VAULT_PASSPHRASE", "correct horse")
		_, err := runPasswordVault(t, mock, "enroll")
		assert.ErrorIs(t, err, ErrPasswordVaultEnrollFailed)
	})
}

func TestPasswordVaultRotate_KeepsCurrentLabel(t *testing.T) {
	mock := newVaultTestClient(t)
	mock.vaultStatusResp = &transport.PasswordVaultStatusResponse{
		Factors: []transport.PasswordVaultFactor{{ID: "f-1", Factor: "passphrase", Label: "laptop"}},
	}
	mock.vaultEnrollResp = enrolledVaultFactor("")
	t.Setenv("XKEY_VAULT_PASSPHRASE", "rotated phrase")

	_, err := runPasswordVault(t, mock, "rotate", "--factor-id", "f-1")
	require.NoError(t, err)
	require.NotNil(t, mock.lastRotateReq)
	assert.Equal(t, "f-1", mock.lastRotateReq.FactorID)
	assert.Equal(t, "rotated phrase", mock.lastRotateReq.Passphrase)
	assert.Equal(t, "laptop", mock.lastRotateReq.Label)
}

func TestPasswordVaultRotate_Errors(t *testing.T) {
	t.Run("missing factor id", func(t *testing.T) {
		mock := newVaultTestClient(t)
		t.Setenv("XKEY_VAULT_PASSPHRASE", "rotated phrase")
		_, err := runPasswordVault(t, mock, "rotate")
		assert.ErrorIs(t, err, ErrPasswordMissingFactorID)
	})
	t.Run("status error withholds the rotation", func(t *testing.T) {
		mock := newVaultTestClient(t)
		mock.vaultStatusErr = errVaultServer
		t.Setenv("XKEY_VAULT_PASSPHRASE", "rotated phrase")
		_, err := runPasswordVault(t, mock, "rotate", "--factor-id", "f-1")
		assert.ErrorIs(t, err, ErrPasswordVaultRotateFailed)
		assert.Nil(t, mock.lastRotateReq)
	})
}

func TestPasswordVaultRemove(t *testing.T) {
	mock := newVaultTestClient(t)

	out, err := runPasswordVault(t, mock, "remove", "--factor-id", "f-2")
	require.NoError(t, err)
	require.NotNil(t, mock.lastRemoveReq)
	assert.Equal(t, "f-2", mock.lastRemoveReq.FactorID)
	assert.Contains(t, out, "Vault factor f-2 removed.")
}

func TestPasswordVaultRemove_Errors(t *testing.T) {
	mock := newVaultTestClient(t)
	_, err := runPasswordVault(t, mock, "remove")
	assert.ErrorIs(t, err, ErrPasswordMissingFactorID)

	mock.vaultRemoveErr = errVaultServer
	_, err = runPasswordVault(t, mock, "remove", "--factor-id", "f-2")
	assert.ErrorIs(t, err, ErrPasswordVaultRemoveFailed)
}

func TestPasswordVaultRecover(t *testing.T) {
	mock := newVaultTestClient(t)
	mock.vaultEnrollResp = enrolledVaultFactor("NEW-CODE")
	stubStdin(t, []byte("OLD-CODE\n"), nil)
	t.Setenv("XKEY_VAULT_PASSPHRASE", "fresh phrase")

	out, err := runPasswordVault(t, mock, "recover", "--recovery-code-stdin", "--label", "desktop")
	require.NoError(t, err)
	require.NotNil(t, mock.lastRecoverReq)
	assert.Equal(t, "OLD-CODE", mock.lastRecoverReq.RecoveryCode)
	assert.Equal(t, "fresh phrase", mock.lastRecoverReq.Passphrase)
	assert.Equal(t, "desktop", mock.lastRecoverReq.Label)
	assert.Contains(t, out, "NEW-CODE")
	assert.Contains(t, out, "it will not be shown again")
}

func TestPasswordVaultRecover_Errors(t *testing.T) {
	t.Run("both secrets on stdin", func(t *testing.T) {
		mock := newVaultTestClient(t)
		_, err := runPasswordVault(t, mock, "recover", "--recovery-code-stdin", "--passphrase-stdin")
		assert.ErrorIs(t, err, ErrPasswordVaultSingleStdin)
	})
	t.Run("missing recovery code", func(t *testing.T) {
		mock := newVaultTestClient(t)
		t.Setenv("XKEY_VAULT_PASSPHRASE", "fresh phrase")
		_, err := runPasswordVault(t, mock, "recover")
		assert.ErrorIs(t, err, ErrPasswordMissingRecoveryCode)
	})
	t.Run("missing passphrase", func(t *testing.T) {
		mock := newVaultTestClient(t)
		t.Setenv("XKEY_VAULT_RECOVERY_CODE", "OLD-CODE")
		_, err := runPasswordVault(t, mock, "recover")
		assert.ErrorIs(t, err, ErrPasswordMissingPassphrase)
		assert.Nil(t, mock.lastRecoverReq)
	})
	t.Run("server error", func(t *testing.T) {
		mock := newVaultTestClient(t)
		mock.vaultEnrollErr = errVaultServer
		t.Setenv("XKEY_VAULT_RECOVERY_CODE", "OLD-CODE")
		t.Setenv("XKEY_VAULT_PASSPHRASE", "fresh phrase")
		_, err := runPasswordVault(t, mock, "recover")
		assert.ErrorIs(t, err, ErrPasswordVaultRecoverFailed)
	})
}

func TestPasswordUnlock_PINFlagServesOnlyAPasskey(t *testing.T) {
	// password unlock takes a vault factor: the security key PIN is there
	// only for --passkey, and alone it is refused (see
	// TestPasswordVaultPasskey_FlagRefusals).
	assert.NotNil(t, passwordUnlockCmd.Flags().Lookup("passphrase-stdin"))
	assert.NotNil(t, passwordUnlockCmd.Flags().Lookup(vaultPasskeyFlag))
	assert.NotNil(t, passwordUnlockCmd.Flags().Lookup(pinFlagStdin))
	assert.Nil(t, passwordUnlockCmd.Flags().Lookup("pin"), "a PIN is never a value flag")
}
