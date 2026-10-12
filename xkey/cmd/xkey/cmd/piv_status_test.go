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

package cmd

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// runPIVStatusForTest runs `piv status` on a detached command, resolving
// the storage configuration entirely from loadedConfig.PIV, and returns
// what it printed.
func runPIVStatusForTest(t *testing.T) string {
	t.Helper()
	cmd := &cobra.Command{RunE: runPIVStatus}
	var out bytes.Buffer
	cmd.SetOut(&out)
	require.NoError(t, runPIVStatus(cmd, nil))
	return out.String()
}

// TestRunPIVStatus_ListsOccupiedAndEmptySlots proves status shows the
// stored certificate's subject against its slot, marks every other primary
// slot empty, and counts the occupied slots.
func TestRunPIVStatus_ListsOccupiedAndEmptySlots(t *testing.T) {
	storagePath := withPIVStoragePath(t)
	cert := storeTestPIVCertificate(t, xkms.PIVSlot("9a"))
	require.NotEmpty(t, cert.Subject.CommonName)

	out := runPIVStatusForTest(t)

	assert.Contains(t, out, "Storage Path:      "+storagePath)
	assert.Contains(t, out, fmt.Sprintf("[9a] %s\n", xkms.PIVSlotName(xkms.PIVSlot("9a"))))
	assert.Contains(t, out, "Subject:  ")
	assert.Contains(t, out, cert.Subject.CommonName)
	for _, slot := range xkms.PIVPrimarySlots() {
		if slot == xkms.PIVSlot("9a") {
			continue
		}
		assert.Contains(t, out, fmt.Sprintf("[%s] %s - Empty", slot, xkms.PIVSlotName(slot)))
	}
	assert.Contains(t, out, "Total Certificates: 1/4")
}

// TestRunPIVStatus_ReportsUnusableStorageWithoutFailing proves status is a
// report, not a gate: storage that cannot be opened is printed as the
// storage status after the configured location, and the command succeeds.
func TestRunPIVStatus_ReportsUnusableStorageWithoutFailing(t *testing.T) {
	tests := []struct {
		name      string
		piv       xkeyconfig.PIVConfig
		location  string
		wantError string
	}{
		{
			name:      "pkcs11 storage without a library",
			piv:       xkeyconfig.PIVConfig{Backend: string(PIVBackendPKCS11), Storage: string(PIVStorageTypePKCS11), PKCS11Token: "piv-token"},
			location:  "PKCS#11 Token:     piv-token",
			wantError: ErrPIVPKCS11LibraryRequired.Error(),
		},
		{
			name:     "tpm2 storage on a missing device",
			piv:      xkeyconfig.PIVConfig{Backend: string(PIVBackendTPM2), Storage: string(PIVStorageTypeTPM2), TPMDevice: "/nonexistent/xkey-test-tpm0"},
			location: "TPM Device:        /nonexistent/xkey-test-tpm0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			previous := loadedConfig
			cfg := xkeyconfig.DefaultConfig()
			cfg.PIV = tt.piv
			loadedConfig = cfg
			t.Cleanup(func() { loadedConfig = previous })

			out := runPIVStatusForTest(t)

			assert.Contains(t, out, tt.location)
			assert.Contains(t, out, "Storage Status:    Error - "+tt.wantError)
			assert.NotContains(t, out, "Slot Status:")
		})
	}
}
