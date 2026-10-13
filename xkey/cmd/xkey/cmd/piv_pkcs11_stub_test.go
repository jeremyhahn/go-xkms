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

//go:build !pkcs11

package cmd

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// In a build without the pkcs11 tag, every PIV command that asks for the
// PKCS#11 backend or storage must say which build tag it needs.

func TestRunPivGenerate_PKCS11BackendNeedsBuildTag(t *testing.T) {
	withFilePIVStorage(t)

	gen := newPIVGenerateCmd(t)
	gen.Flags().String("backend", "", "")
	require.NoError(t, setFlagForTest(t, gen.Flags(), "backend", string(PIVBackendPKCS11)))
	gen.SetOut(&bytes.Buffer{})

	err := runPivGenerate(gen, []string{string(xkms.PIVSlotAuthentication)})
	require.ErrorIs(t, err, ErrPIVPKCS11BuildTagRequired)
}

func TestRunPivGenerate_PKCS11StorageNeedsBuildTag(t *testing.T) {
	withFilePIVStorage(t)

	gen := newPIVGenerateCmd(t)
	gen.Flags().String("piv-storage", "", "")
	gen.Flags().String("pkcs11-library", "", "")
	require.NoError(t, setFlagForTest(t, gen.Flags(), "piv-storage", string(PIVStorageTypePKCS11)))
	require.NoError(t, setFlagForTest(t, gen.Flags(), "pkcs11-library", "/usr/lib/softhsm/libsofthsm2.so"))
	gen.Flags().String("pkcs11-token", "", "")
	require.NoError(t, setFlagForTest(t, gen.Flags(), "pkcs11-token", "xkey"))
	gen.SetOut(&bytes.Buffer{})

	err := runPivGenerate(gen, []string{string(xkms.PIVSlotAuthentication)})
	require.ErrorIs(t, err, ErrPIVStorageCreationFailed)
	require.ErrorIs(t, err, ErrPIVPKCS11BuildTagRequired)
}

func TestRunPivCSR_PKCS11BackendNeedsBuildTag(t *testing.T) {
	withFilePIVStorage(t)

	csrCmd, _ := newPIVCSRTestCmd(t, "user@example.com")
	csrCmd.Flags().String("backend", "", "")
	require.NoError(t, setFlagForTest(t, csrCmd.Flags(), "backend", string(PIVBackendPKCS11)))

	err := runPivCSR(csrCmd, []string{string(xkms.PIVSlotAuthentication)})
	require.ErrorIs(t, err, ErrPIVPKCS11BuildTagRequired)
}
