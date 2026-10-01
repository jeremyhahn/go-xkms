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
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgxkms "github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// testPIVBarrierPassword unseals the barrier withSoftwarePIVKeyStore makes.
const testPIVBarrierPassword = "piv-key-store-pw"

// withSoftwarePIVKeyStore gives the software PIV backend its key store: an
// isolated xKey home whose passphrase barrier encrypts the store, the
// barrier password in XKEY_BARRIER_PASSWORD, and a fresh xkms service and
// PIV manager (restored afterwards), so no test reaches the host's home.
func withSoftwarePIVKeyStore(t *testing.T) string {
	t.Helper()
	home := isolatedBackupHome(t)
	t.Setenv(xhome.EnvHome, "")
	initTestOATHBarrier(t, home, testPIVBarrierPassword)
	t.Setenv("XKEY_BARRIER_PASSWORD", testPIVBarrierPassword)
	newPIVProcess()
	t.Cleanup(newPIVProcess)
	return home
}

// newPIVProcess drops the in-process xkms service and PIV manager, as a new
// xkey process starts without them.
func newPIVProcess() {
	xkms.Reset()
	pkgxkms.ResetPIV()
}

// TestSoftwarePIV_KeyOutlivesTheProcess generates a software PIV key, then,
// in what is to xkey a new process, signs a CSR with it: the key lives in
// xKey's encrypted key store, not in the generating process's memory.
func TestSoftwarePIV_KeyOutlivesTheProcess(t *testing.T) {
	withFilePIVStorage(t)

	gen := newPIVGenerateCmd(t)
	gen.SetOut(&bytes.Buffer{})
	require.NoError(t, runPivGenerate(gen, []string{string(xkms.PIVSlotAuthentication)}))

	newPIVProcess()

	csrCmd, _ := newPIVCSRTestCmd(t, "piv-user")
	out := filepath.Join(t.TempDir(), "piv.csr")
	require.NoError(t, csrCmd.Flags().Set("output", out))
	require.NoError(t, runPivCSR(csrCmd, []string{string(xkms.PIVSlotAuthentication)}))

	data, err := os.ReadFile(out)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	require.NoError(t, csr.CheckSignature(), "the CSR is signed by the slot's persisted key")

	storage, err := createPIVStorage(mustBuildPIVConfig(t, nil), slog.Default())
	require.NoError(t, err)
	slotCert, err := storage.Retrieve(xkms.PIVSlotAuthentication)
	require.NoError(t, err)
	assert.Equal(t, slotCert.PublicKey, csr.PublicKey, "the generated key, not a new one, signed")
}

// TestSoftwarePIV_RequiresTheEncryptedKeyStore proves the software backend
// refuses to make a key it could not keep: without a barrier there is no
// encrypted key store.
func TestSoftwarePIV_RequiresTheEncryptedKeyStore(t *testing.T) {
	isolatedBackupHome(t)
	t.Setenv(xhome.EnvHome, "")
	newPIVProcess()
	t.Cleanup(newPIVProcess)

	err := ensureSoftwarePIVKeyStore(newPIVGenerateCmd(t), slog.Default())
	assert.ErrorIs(t, err, ErrPIVSoftwareKeyStoreRequiresBarrier)
}

// TestSoftwarePIV_WrongBarrierPasswordRefused proves the key store is not
// opened without the barrier's password.
func TestSoftwarePIV_WrongBarrierPasswordRefused(t *testing.T) {
	withSoftwarePIVKeyStore(t)
	t.Setenv("XKEY_BARRIER_PASSWORD", "not-the-password")

	err := ensureSoftwarePIVKeyStore(newPIVGenerateCmd(t), slog.Default())
	assert.ErrorIs(t, err, ErrBarrierStoreOpenFailed)
}
