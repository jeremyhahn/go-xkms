//go:build vault

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

package xkms

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// A config vault.NewBackend rejects yields a nil interface, not one holding a
// nil pointer.
func TestNewVaultKeyProvider_InvalidConfigReturnsNil(t *testing.T) {
	kp, err := newVaultKeyProvider(map[string]interface{}{})
	require.Error(t, err)
	require.True(t, kp == nil, "the factory must return a nil KeyProvider, got %#v", kp)
}
