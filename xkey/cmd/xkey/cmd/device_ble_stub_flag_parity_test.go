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
	"sort"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

// TestBLEStubFlagParity pins the flag set of every xkey command that ships
// both a ble implementation (e.g. device_attest.go) and a !ble stub (e.g.
// device_attest_stub.go). Both implementations register their flags through
// a single shared, untagged registerXxxFlags function (e.g.
// device_attest_flags.go), so this test runs unchanged under both
// `-tags ble` and its absence: a passing run under one build tag and a
// failing run under the other is exactly the drift go-xkms#1318 fixed --
// this test exists to catch it if it comes back.
func TestBLEStubFlagParity(t *testing.T) {
	tests := []struct {
		name  string
		cmd   *cobra.Command
		flags []string
	}{
		{
			name:  "backup to-device",
			cmd:   backupToDeviceCmd,
			flags: []string{"device", "timeout", "password-stdin", "trust-store", "oath-store", "password-store", "barrier-password-stdin", "barrier-password-file"},
		},
		{
			name:  "backup from-device",
			cmd:   backupFromDeviceCmd,
			flags: []string{"device", "timeout", "password-stdin", "key-stdin", "trust-store", "oath-store", "password-store", "barrier-password-stdin", "barrier-password-file"},
		},
		{
			name:  "device attest",
			cmd:   deviceAttestCmd,
			flags: []string{"device", "no-verify", "timeout"},
		},
		{
			name:  "device listen",
			cmd:   deviceListenCmd,
			flags: []string{"device", "name", "timeout", "attestation-mode", "tpm-device", "tpm-enrollment", "tpm-pcr-bank", "allow-sync", "so-pin-stdin", "barrier-password-stdin", "barrier-password-file"},
		},
		{
			name:  "device pair",
			cmd:   devicePairCmd,
			flags: []string{"device", "timeout", "force", "so-pin-stdin", "barrier-password-stdin", "barrier-password-file"},
		},
		{
			name:  "device scan",
			cmd:   deviceScanCmd,
			flags: []string{"timeout"},
		},
		{
			name:  "oath sync",
			cmd:   oathSyncPhoneCmd,
			flags: []string{"device", "timeout", "store", "barrier-password-stdin", "barrier-password-file"},
		},
		{
			name:  "oath push",
			cmd:   oathPushPhoneCmd,
			flags: []string{"device", "timeout", "store", "barrier-password-stdin", "barrier-password-file"},
		},
		{
			name:  "oath pull",
			cmd:   oathPullPhoneCmd,
			flags: []string{"device", "timeout", "store", "barrier-password-stdin", "barrier-password-file"},
		},
		{
			name:  "piv phone-list",
			cmd:   pivDeviceListCmd,
			flags: []string{"device", "timeout"},
		},
		{
			name:  "piv phone-push-cert",
			cmd:   pivDevicePushCertCmd,
			flags: []string{"device", "timeout"},
		},
		{
			name:  "piv phone-pull-cert",
			cmd:   pivDevicePullCertCmd,
			flags: []string{"device", "timeout", "output"},
		},
		{
			name:  "piv phone-generate",
			cmd:   pivDeviceGenerateKeyCmd,
			flags: []string{"device", "timeout", "algorithm"},
		},
		{
			name:  "device share",
			cmd:   deviceShareCmd,
			flags: []string{"device", "label", "timeout"},
		},
		{
			name:  "device import",
			cmd:   deviceImportCmd,
			flags: []string{"backend", "device", "timeout"},
		},
		{
			name:  "device sync",
			cmd:   deviceSyncCmd,
			flags: []string{"trust-store", "oath", "passwords", "all", "device", "dry-run", "timeout", "barrier-password-stdin", "barrier-password-file"},
		},
		{
			name:  "device sync-status",
			cmd:   deviceSyncStatusCmd,
			flags: []string{"device", "timeout", "barrier-password-stdin", "barrier-password-file"},
		},
		{
			name:  "device sync-push",
			cmd:   deviceSyncPushCmd,
			flags: []string{"trust-store", "oath", "passwords", "all", "device", "dry-run", "timeout", "barrier-password-stdin", "barrier-password-file"},
		},
		{
			name:  "device sync-pull",
			cmd:   deviceSyncPullCmd,
			flags: []string{"trust-store", "oath", "passwords", "all", "device", "dry-run", "timeout", "barrier-password-stdin", "barrier-password-file"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := append([]string(nil), tt.flags...)
			sort.Strings(want)

			var got []string
			tt.cmd.Flags().VisitAll(func(f *pflag.Flag) {
				got = append(got, f.Name)
			})
			sort.Strings(got)

			assert.Equal(t, want, got, "%s: flag set must match between the ble and !ble implementations", tt.cmd.CommandPath())
		})
	}
}
