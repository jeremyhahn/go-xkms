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

package rest

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/stretchr/testify/assert"
)

// TestIsCrossTenantAccess tests the isCrossTenantAccess helper function.
func TestIsCrossTenantAccess(t *testing.T) {
	t.Run("nil identity allows access", func(t *testing.T) {
		assert.False(t, isCrossTenantAccess(nil, "tenant-a"))
	})

	t.Run("system-level identity allows access", func(t *testing.T) {
		identity := &auth.Identity{Subject: "so-user", TenantID: ""}
		assert.False(t, isCrossTenantAccess(identity, "tenant-a"))
	})

	t.Run("same tenant allows access", func(t *testing.T) {
		identity := &auth.Identity{Subject: "user1", TenantID: "tenant-a"}
		assert.False(t, isCrossTenantAccess(identity, "tenant-a"))
	})

	t.Run("different tenant denies access", func(t *testing.T) {
		identity := &auth.Identity{Subject: "user1", TenantID: "tenant-a"}
		assert.True(t, isCrossTenantAccess(identity, "tenant-b"))
	})

	t.Run("target with no tenant allows access", func(t *testing.T) {
		identity := &auth.Identity{Subject: "user1", TenantID: "tenant-a"}
		assert.False(t, isCrossTenantAccess(identity, ""))
	})
}
