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

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/localtpm"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/localtpmtest"
)

// simPCR is the PCR the test policy selects: an application PCR a
// locality-0 caller may extend.
const simPCR = 23

// sharedTPM is the simulator host every command of a test uses. The
// simulator's NV state lives only while it is open, so the test keeps it open
// and the commands' Close is a no-op.
type sharedTPM struct{ *localtpm.Host }

func (sharedTPM) Close() error { return nil }

// useTPMSimulator points the TPM key source at the in-process simulator,
// with its data directory in dataDir, and returns the open host.
func useTPMSimulator(t *testing.T, dataDir string) *localtpm.Host {
	t.Helper()
	host := localtpmtest.OpenSimulator(t, dataDir, openFileStore)
	original := openTPMHost
	openTPMHost = func(string, string) (vaultTPM, error) { return sharedTPM{host}, nil }
	t.Cleanup(func() { openTPMHost = original })
	return host
}

// tpmFactorRef returns the key reference of the vault's TPM factor.
func tpmFactorRef(t *testing.T, server *vaultServer) transport.PasswordVaultKeyRef {
	t.Helper()
	for _, f := range server.status(t).Factors {
		if f.Factor == "tpm" {
			return f.KeyRef
		}
	}
	require.Fail(t, "no TPM factor enrolled")
	return transport.PasswordVaultKeyRef{}
}

func TestKeyFactorVault_TPMOnTheSimulator(t *testing.T) {
	dataDir := t.TempDir()
	useTPMSimulator(t, dataDir)
	server := newVaultServer(t)

	setFlags(t, passwordVaultEnrollCmd, map[string]string{
		keyFactorFlag: "tpm", tpmDataDirFlag: dataDir, keyIDFlag: "vault-tpm", tpmCreateFlag: "true",
	})
	out := captureStdout(t, func() { passwordVaultEnrollCmd.Run(passwordVaultEnrollCmd, nil) })
	assert.Contains(t, out, "RECOVERY CODE")
	assert.Equal(t, "platform", tpmFactorRef(t, server).TPMPolicy)

	server.lock(t)
	setFlags(t, passwordUnlockCmd, map[string]string{keyUnlockFlag: "true", tpmDataDirFlag: dataDir})
	out = captureStdout(t, func() { passwordUnlockCmd.Run(passwordUnlockCmd, nil) })
	assert.Contains(t, out, "unlocked")
	require.True(t, server.status(t).Unlocked)
}

// TestKeyFactorVault_TPMUnderANamedPolicy creates the vault key under a
// named policy in the data directory's registry -- as `xkey tpm policy
// create` makes it -- and unlocks through it; once the PCR drifts the TPM
// refuses the key.
func TestKeyFactorVault_TPMUnderANamedPolicy(t *testing.T) {
	dataDir := t.TempDir()
	host := useTPMSimulator(t, dataDir)
	server := newVaultServer(t)

	_, err := host.TPMPolicyCreate(t.Context(), &transport.TPMPolicyCreateRequest{
		Name:     "boot",
		Branches: []transport.TPMPolicyBranch{transport.TPMPolicyPCRBranch("sha256", []uint{simPCR})},
	})
	require.NoError(t, err)

	setFlags(t, passwordVaultEnrollCmd, map[string]string{
		keyFactorFlag: "tpm", tpmDataDirFlag: dataDir, keyIDFlag: "vault-boot", tpmCreateFlag: "true", tpmPolicyFlag: "boot",
	})
	out := captureStdout(t, func() { passwordVaultEnrollCmd.Run(passwordVaultEnrollCmd, nil) })
	assert.Contains(t, out, "RECOVERY CODE")
	assert.Equal(t, "boot", tpmFactorRef(t, server).TPMPolicy)

	// The registry records the key against the policy.
	objects, err := host.TPMPolicyObjects(t.Context(), &transport.TPMPolicyRequest{Name: "boot"})
	require.NoError(t, err)
	assert.Equal(t, []string{"key/vault-boot"}, objects.Objects)

	server.lock(t)
	setFlags(t, passwordUnlockCmd, map[string]string{keyUnlockFlag: "true", tpmDataDirFlag: dataDir})
	out = captureStdout(t, func() { passwordUnlockCmd.Run(passwordUnlockCmd, nil) })
	assert.Contains(t, out, "unlocked")
	require.True(t, server.status(t).Unlocked)

	// A platform change: the TPM refuses the key, so the unlock fails.
	require.NoError(t, host.TPM().ExtendPCR(simPCR, "sha256", []byte("platform change")))
	server.lock(t)
	setFlags(t, passwordUnlockCmd, map[string]string{keyUnlockFlag: "true", tpmDataDirFlag: dataDir})
	source, cleanup, err := resolveVaultKeySource(passwordUnlockCmd, "", vaultUnlock)
	require.NoError(t, err)
	defer cleanup()
	cl, done, err := createPasswordClient(server.cfg)
	require.NoError(t, err)
	defer done()
	_, err = source(t.Context(), cl)
	assert.Error(t, err, "the TPM enforces the policy on use")
}

func TestKeyFactorVault_TPMUnknownPolicyIsRefused(t *testing.T) {
	dataDir := t.TempDir()
	useTPMSimulator(t, dataDir)
	setFlags(t, passwordVaultEnrollCmd, map[string]string{
		keyFactorFlag: "tpm", tpmDataDirFlag: dataDir, keyIDFlag: "k", tpmCreateFlag: "true", tpmPolicyFlag: "no-such-policy",
	})
	_, _, err := resolveVaultKeySource(passwordVaultEnrollCmd, "", vaultNewFactor)
	assert.Error(t, err)
}
