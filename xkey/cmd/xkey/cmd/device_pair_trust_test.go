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

//go:build ble

package cmd

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// TestLoadPairingAttestationTrust_EmptyStore exercises the real
// openTrustStore + attestation.LoadTrust path against a fresh, empty
// on-disk trust store: no embedded/custom roots configured, so the loaded
// Trust carries none, but the load itself must succeed.
func TestLoadPairingAttestationTrust_EmptyStore(t *testing.T) {
	resetViperForTest(t)
	dir := t.TempDir()
	viper.Set("trust.store_path", dir)

	trust, err := loadPairingAttestationTrust()
	require.NoError(t, err)
	require.NotNil(t, trust)
}
