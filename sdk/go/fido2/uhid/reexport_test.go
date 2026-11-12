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

package uhid

import (
	"testing"

	"github.com/stretchr/testify/require"

	pkguhid "github.com/jeremyhahn/go-xkms/pkg/fido2/uhid"
)

// TestReexport_UHIDNames pins that the SDK names xkey tests use are the
// pkg/fido2/uhid names, not copies.
func TestReexport_UHIDNames(t *testing.T) {
	require.Same(t, pkguhid.ErrDeviceAlreadyCreated, ErrDeviceAlreadyCreated)
	require.Same(t, pkguhid.ErrInvalidPacket, ErrInvalidPacket)
	require.Equal(t, pkguhid.MaxReportDescriptorSize, MaxReportDescriptorSize)
	require.Equal(t,
		pkguhid.SerializeCreate2Request(pkguhid.DefaultCreateConfig()),
		SerializeCreate2Request(DefaultCreateConfig()))
	require.Equal(t,
		pkguhid.SerializeInput2Request([]byte{1, 2, 3}),
		SerializeInput2Request([]byte{1, 2, 3}))
}
