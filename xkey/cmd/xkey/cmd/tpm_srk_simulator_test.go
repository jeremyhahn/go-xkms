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

package cmd

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testSRKUserPIN is a test-local literal; no real PIN is ever written.
const testSRKUserPIN = "test-user-pin-994"

// writeSRKPINFile writes pin plus a trailing newline to a 0600 file, as a
// systemd credential or an operator's echo would.
func writeSRKPINFile(t *testing.T, pin string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pin")
	require.NoError(t, os.WriteFile(path, []byte(pin+"\n"), 0o600))
	return path
}

// runSRKEnroll runs `xkey tpm srk enroll` with args and stdin and returns
// its output and error.
func runSRKEnroll(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	c := newTPMSRKCmd()
	var out bytes.Buffer
	c.SetOut(&out)
	c.SetErr(&out)
	c.SetIn(strings.NewReader(stdin))
	c.SetArgs(append([]string{"enroll"}, args...))
	err := c.Execute()
	return out.String(), err
}

// installTPMForSRK runs `xkey tpm install` on the simulator with no
// --auth, so the SO PIN is empty.
func installTPMForSRK(t *testing.T) {
	t.Helper()
	withProvisionedSimulatorTPM(t)
	setVar(t, &tpmCfg.outputFormat, "text")
	setVar(t, &installHierarchyAuth, "")
	setVar(t, &installPCRBank, "sha256")
	setVar(t, &installGoldenPCRs, "0,7")
	setVar(t, &installPlatformPCRs, "")
	_, _, err := runTPMSubcommand(runTPMInstall)
	require.NoError(t, err)
}

// createSRKCredential opens the fido2 tpm2 backend with pin as the
// Platform SRK auth and creates one credential key.
func createSRKCredential(t *testing.T, pin string) error {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend, err := createFIDO2TPM2KeyBackend(&FIDO2Config{TPMDevice: "", PlatformSRKPIN: pin}, logger)
	if err != nil {
		return err
	}
	defer func() { assert.NoError(t, backend.Close()) }()
	const coseES256 = -7
	handle, publicKey, err := backend.GenerateCredentialKey(coseES256, []byte("ruling-993-credential"))
	if err != nil {
		return err
	}
	assert.NotEmpty(t, publicKey)
	assert.NotNil(t, handle)
	return nil
}

// TestTPMSRKEnrollPINFileThenFIDO2 is rulings 993 and 994: after `tpm
// install` (no --auth, so an empty SO PIN), `tpm srk enroll --pin-file`
// enrols the Platform SRK and fido2 --backend tpm2 creates a credential
// with that PIN as the Platform SRK auth.
func TestTPMSRKEnrollPINFileThenFIDO2(t *testing.T) {
	installTPMForSRK(t)

	out, err := runSRKEnroll(t, "", "--pin-file", writeSRKPINFile(t, testSRKUserPIN))
	require.NoError(t, err)
	assert.Contains(t, out, "enrolled")
	assert.NotContains(t, out, testSRKUserPIN)

	require.NoError(t, createSRKCredential(t, testSRKUserPIN))
}

// TestTPMSRKEnrollPINStdin enrols with the user PIN on stdin.
func TestTPMSRKEnrollPINStdin(t *testing.T) {
	installTPMForSRK(t)

	out, err := runSRKEnroll(t, testSRKUserPIN+"\n", "--pin-stdin")
	require.NoError(t, err)
	assert.NotContains(t, out, testSRKUserPIN)

	require.NoError(t, createSRKCredential(t, testSRKUserPIN))
}

// TestTPMSRKEnrollIdempotent: a second enrol reports already enrolled and
// succeeds.
func TestTPMSRKEnrollIdempotent(t *testing.T) {
	installTPMForSRK(t)
	pinFile := writeSRKPINFile(t, testSRKUserPIN)

	_, err := runSRKEnroll(t, "", "--pin-file", pinFile)
	require.NoError(t, err)
	out, err := runSRKEnroll(t, "", "--pin-file", pinFile)
	require.NoError(t, err)
	assert.Contains(t, out, "already enrolled")
}

// TestTPMSRKEnrollWrongPINFailsFIDO2: fido2 with a PIN other than the
// enrolled one cannot use the Platform SRK.
func TestTPMSRKEnrollWrongPINFailsFIDO2(t *testing.T) {
	installTPMForSRK(t)

	_, err := runSRKEnroll(t, "", "--pin-file", writeSRKPINFile(t, testSRKUserPIN))
	require.NoError(t, err)

	err = createSRKCredential(t, "test-wrong-pin")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "test-wrong-pin")
}
