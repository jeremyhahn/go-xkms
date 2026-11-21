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

//go:build integration && fido2

package fido2

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRequireDeviceFallbackReachesCLI checks that when RequireDevice falls
// back to the virtual authenticator, the xkmsctl subprocesses the CLI tests
// start see the same switch (FIDO2_USE_VIRTUAL=true). Without it the CLI
// enumerates hidraw and fails on hosts with no FIDO2 hardware.
func TestRequireDeviceFallbackReachesCLI(t *testing.T) {
	t.Setenv("FIDO2_USE_VIRTUAL", "")

	cfg := LoadFIDO2TestConfig()
	require.False(t, cfg.UseVirtualDevice())

	cfg.RequireDevice(t)

	if cfg.UseVirtualDevice() {
		require.Equal(t, "true", os.Getenv("FIDO2_USE_VIRTUAL"),
			"virtual fallback must be visible to xkmsctl subprocesses")
	}
}
