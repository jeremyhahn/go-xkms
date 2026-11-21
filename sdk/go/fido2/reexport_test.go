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

package fido2

import (
	"testing"

	"github.com/stretchr/testify/require"

	pkgfido2 "github.com/jeremyhahn/go-xkms/pkg/fido2"
)

// TestReexport_ErrNoDeviceFound pins that the SDK sentinel is the pkg/fido2
// sentinel, so errors.Is matches across the boundary.
func TestReexport_ErrNoDeviceFound(t *testing.T) {
	require.Same(t, pkgfido2.ErrNoDeviceFound, ErrNoDeviceFound)
}
