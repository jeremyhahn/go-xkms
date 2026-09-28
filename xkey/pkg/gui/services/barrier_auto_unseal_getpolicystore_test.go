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

package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestBarrierAutoUnsealService_GetPolicyStore_NeverSetReturnsNil covers the
// branch taken when the atomic policy-store pointer was never populated
// (a zero-value service, distinct from NewBarrierAutoUnsealService, which
// always stores a pointer even for a nil store).
func TestBarrierAutoUnsealService_GetPolicyStore_NeverSetReturnsNil(t *testing.T) {
	s := &BarrierAutoUnsealService{}
	assert.Nil(t, s.getPolicyStore())
}

// TestBarrierAutoUnsealService_GetPolicyStore_ReturnsStoredValue covers the
// branch where SetPolicyStore populated the pointer.
func TestBarrierAutoUnsealService_GetPolicyStore_ReturnsStoredValue(t *testing.T) {
	s := NewBarrierAutoUnsealService(nil)
	assert.Nil(t, s.getPolicyStore(), "nil store passed to the constructor is still a stored value")
}
