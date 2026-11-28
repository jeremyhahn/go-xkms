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

package xkms

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	pkgxkms "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

func TestReexport_PivSlotCN(t *testing.T) {
	slots := []pivcert.PIVSlot{
		pivcert.PIVSlotAuthentication,
		pivcert.PIVSlotDigitalSignature,
		pivcert.PIVSlotKeyManagement,
		pivcert.PIVSlotCardAuthentication,
		pivcert.PIVSlot("zz"),
	}
	for _, slot := range slots {
		got := PivSlotCN(slot)
		require.NotEmpty(t, got, "slot %s", slot)
		require.Equal(t, pkgxkms.PivSlotCN(slot), got, "slot %s", slot)
	}
}
