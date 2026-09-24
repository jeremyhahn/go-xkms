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

//go:build azurekv

package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInitializePlatformStore_AzureKVNotConfiguredFailsClosed proves the
// azurekv credential strategy fails closed with a typed error when
// backends.azurekv is not configured.
//
// Unlike awskms/gcpkms, there is no accompanying mock-client round-trip test
// here: pkg/backend/azurekv's own mock (MockKeyVaultClient) does not
// implement the Secrets API GetSymmetricKey/GenerateSymmetricKey resolve
// through (see azurekv_symmetric_test.go's newLocalSymmetricKey doc comment
// -- that package's own unit suite injects key material directly for the
// same reason and defers the real round trip to the emulator-backed
// test/integration/azurekv suite). buildAzureKVPlatformSealer calls
// ensureSealKey, which calls GetSymmetricKey/GenerateSymmetricKey, so the
// same limitation applies here: a genuine round-trip proof for azurekv
// needs that emulator suite, not a unit test.
func TestInitializePlatformStore_AzureKVNotConfiguredFailsClosed(t *testing.T) {
	s := newMinimalServer(t, platformStoreTestConfig("azurekv"))
	// Backends.AzureKV left nil.

	err := s.initializePlatformStore()
	require.Error(t, err)
	assert.Nil(t, s.platformStore)

	var unavailableErr *ErrPlatformStoreStrategyUnavailable
	require.ErrorAs(t, err, &unavailableErr)
	assert.Equal(t, "azurekv", unavailableErr.Strategy)
}
