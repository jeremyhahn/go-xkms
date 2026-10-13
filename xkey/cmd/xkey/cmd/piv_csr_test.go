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
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

func TestRunPivCSR_WritesCSRToCommandOutput(t *testing.T) {
	withFilePIVStorage(t)
	gen := newPIVGenerateCmd(t)
	gen.SetOut(&bytes.Buffer{})
	require.NoError(t, runPivGenerate(gen, []string{string(xkms.PIVSlotDigitalSignature)}))

	csrCmd, out := newPIVCSRTestCmd(t, "signer@example.com")
	require.NoError(t, runPivCSR(csrCmd, []string{string(xkms.PIVSlotDigitalSignature)}))

	block, _ := pem.Decode(out.Bytes())
	require.NotNil(t, block, "without --output the PEM CSR goes to the command output")
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	require.Equal(t, "signer@example.com", csr.Subject.CommonName)
	require.NoError(t, csr.CheckSignature())
}

func TestRunPivCSR_EmptySlotIsRefused(t *testing.T) {
	withFilePIVStorage(t)

	csrCmd, out := newPIVCSRTestCmd(t, "nobody@example.com")
	err := runPivCSR(csrCmd, []string{string(xkms.PIVSlotKeyManagement)})
	require.Error(t, err, "a slot without a key cannot sign a CSR")
	require.Empty(t, out.String())
}

func TestRunPivCSR_UnwritableOutputPath(t *testing.T) {
	withFilePIVStorage(t)
	gen := newPIVGenerateCmd(t)
	gen.SetOut(&bytes.Buffer{})
	require.NoError(t, runPivGenerate(gen, []string{string(xkms.PIVSlotAuthentication)}))

	csrCmd, _ := newPIVCSRTestCmd(t, "user@example.com")
	missingDir := filepath.Join(t.TempDir(), "missing", "req.csr")
	require.NoError(t, setFlagForTest(t, csrCmd.Flags(), "output", missingDir))

	err := runPivCSR(csrCmd, []string{string(xkms.PIVSlotAuthentication)})
	require.ErrorIs(t, err, ErrPIVCSROutputFailed)
}

func TestRunPivCSR_EmptyPKCS11PINFromStdinIsRefused(t *testing.T) {
	withFilePIVStorage(t)
	stubStdin(t, []byte("\n"), nil)

	csrCmd, _ := newPIVCSRTestCmd(t, "user@example.com")
	csrCmd.Flags().Bool("pkcs11-pin-stdin", false, "")
	require.NoError(t, setFlagForTest(t, csrCmd.Flags(), "pkcs11-pin-stdin", "true"))

	err := runPivCSR(csrCmd, []string{string(xkms.PIVSlotAuthentication)})
	require.ErrorIs(t, err, ErrPIVPKCS11PINStdinEmpty)
}
