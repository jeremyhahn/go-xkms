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

//go:build tpm_simulator

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// useTPMSimulator points the TPM key source at the in-process simulator.
func useTPMSimulator(t *testing.T) {
	t.Helper()
	original := tpmBackendConfig
	tpmBackendConfig = func(_ string, blobs storage.Backend) map[string]interface{} {
		return map[string]interface{}{"use_simulator": true, "key_storage": blobs}
	}
	t.Cleanup(func() { tpmBackendConfig = original })
}

func TestKeyFactorVault_TPMOnTheSimulator(t *testing.T) {
	useTPMSimulator(t)
	server := newVaultServer(t)
	keystore := t.TempDir()

	setFlags(t, passwordVaultEnrollCmd, map[string]string{
		keyFactorFlag: "tpm", tpmKeystoreFlag: keystore, keyIDFlag: "vault-tpm", tpmCreateFlag: "true",
	})
	out := captureStdout(t, func() { passwordVaultEnrollCmd.Run(passwordVaultEnrollCmd, nil) })
	assert.Contains(t, out, "RECOVERY CODE")
	var policy string
	for _, f := range server.status(t).Factors {
		if f.Factor == "tpm" {
			policy = f.KeyRef.TPMPolicy
		}
	}
	assert.Equal(t, "platform", policy)

	server.lock(t)
	setFlags(t, passwordUnlockCmd, map[string]string{keyUnlockFlag: "true", tpmKeystoreFlag: keystore})
	out = captureStdout(t, func() { passwordUnlockCmd.Run(passwordUnlockCmd, nil) })
	assert.Contains(t, out, "unlocked")
	require.True(t, server.status(t).Unlocked)
}

func TestKeyFactorVault_TPMNamedPolicyNeedsXkey(t *testing.T) {
	useTPMSimulator(t)
	setFlags(t, passwordVaultEnrollCmd, map[string]string{
		keyFactorFlag: "tpm", tpmKeystoreFlag: t.TempDir(), keyIDFlag: "k", tpmCreateFlag: "true", tpmPolicyFlag: "boot-state",
	})
	_, _, err := resolveVaultKeySource(passwordVaultEnrollCmd, "", vaultNewFactor)
	assert.ErrorIs(t, err, ErrVaultTPMNamedPolicy)
}
