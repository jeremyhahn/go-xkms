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

package staticpw

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPasswordScope_IsValid_Personal(t *testing.T) {
	assert.True(t, ScopePersonal.IsValid())
}

func TestPasswordScope_IsValid_Shared(t *testing.T) {
	assert.True(t, ScopeShared.IsValid())
}

func TestPasswordScope_IsValid_All(t *testing.T) {
	assert.True(t, ScopeAll.IsValid())
}

func TestPasswordScope_IsValid_Empty(t *testing.T) {
	assert.False(t, PasswordScope("").IsValid())
}

func TestPasswordScope_IsValid_Unknown(t *testing.T) {
	assert.False(t, PasswordScope("bogus").IsValid())
}

func TestPasswordScope_StringValues(t *testing.T) {
	assert.Equal(t, "personal", string(ScopePersonal))
	assert.Equal(t, "shared", string(ScopeShared))
	assert.Equal(t, "all", string(ScopeAll))
}
