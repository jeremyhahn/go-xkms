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
	"testing"

	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

func TestRunPivGenerate_EmptyPKCS11SOPINFromStdinIsRefused(t *testing.T) {
	withFilePIVStorage(t)
	stubStdin(t, []byte("\r\n"), nil)

	gen := newPIVGenerateCmd(t)
	gen.Flags().Bool("pkcs11-so-pin-stdin", false, "")
	require.NoError(t, setFlagForTest(t, gen.Flags(), "pkcs11-so-pin-stdin", "true"))

	err := runPivGenerate(gen, []string{string(xkms.PIVSlotAuthentication)})
	require.ErrorIs(t, err, ErrPIVPKCS11SOPINStdinEmpty)
}

func TestRunPivGenerate_UnknownBackendIsRejected(t *testing.T) {
	withFilePIVStorage(t)

	gen := newPIVGenerateCmd(t)
	gen.Flags().String("backend", "", "")
	require.NoError(t, setFlagForTest(t, gen.Flags(), "backend", "floppy"))
	var out bytes.Buffer
	gen.SetOut(&out)

	err := runPivGenerate(gen, []string{string(xkms.PIVSlotAuthentication)})
	require.ErrorIs(t, err, ErrPIVStorageCreationFailed)
	require.ErrorIs(t, err, ErrPIVInvalidBackend)
	require.Empty(t, out.String())
}
