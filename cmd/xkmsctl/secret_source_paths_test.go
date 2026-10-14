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

// secret_source_paths_test.go pins where platform put and password vault
// recover take their secrets from: a file, and a stdin that cannot be read.
package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withFailingSecretStdin makes every secret read from stdin fail.
func withFailingSecretStdin(t *testing.T) {
	t.Helper()
	original := secretStdin
	secretStdin = failingReader{}
	t.Cleanup(func() { secretStdin = original })
}

func TestPlatformPutCmd_SecretFromFile(t *testing.T) {
	resetCmdFlags(t, platformPutCmd)
	t.Cleanup(func() { resetCmdFlags(t, platformPutCmd) })
	mock := &mockPlatformClient{}
	withGlobalConfig(t, newPlatformConfig(mock))
	path := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(path, []byte("from-file"), 0600))
	require.NoError(t, platformPutCmd.Flags().Set("file", path))

	captureStdout(t, func() { platformPutCmd.Run(platformPutCmd, []string{"tls-key"}) })
	require.NotNil(t, mock.gotPutReq)
	assert.Equal(t, "from-file", string(mock.gotPutReq.Secret))
}

func TestPlatformPutCmd_RefusesUnreadableStdin(t *testing.T) {
	resetCmdFlags(t, platformPutCmd)
	t.Cleanup(func() { resetCmdFlags(t, platformPutCmd) })
	mock := &mockPlatformClient{}
	withGlobalConfig(t, newPlatformConfig(mock))
	withFailingSecretStdin(t)
	require.NoError(t, platformPutCmd.Flags().Set("value", "-"))

	code := captureExit(t, func() { platformPutCmd.Run(platformPutCmd, []string{"db-password"}) })
	assert.Equal(t, 1, code)
	assert.Nil(t, mock.gotPutReq, "nothing is stored without a secret")
}

func TestPasswordVaultRecoverCmd_RefusesUnreadableRecoveryCode(t *testing.T) {
	resetCmdFlags(t, passwordVaultRecoverCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordVaultRecoverCmd) })
	mock := &mockPasswordClient{}
	withGlobalConfig(t, newPasswordConfig(mock))
	withFailingSecretStdin(t)
	require.NoError(t, passwordVaultRecoverCmd.Flags().Set("recovery-code", "-"))
	require.NoError(t, passwordVaultRecoverCmd.Flags().Set("passphrase", "fresh phrase"))

	code := captureExit(t, func() { passwordVaultRecoverCmd.Run(passwordVaultRecoverCmd, nil) })
	assert.Equal(t, 1, code)
	assert.Nil(t, mock.gotRecoverReq, "no recovery is attempted without a code")
}
