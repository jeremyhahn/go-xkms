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

package custodian

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCustodianMember_HasReceived(t *testing.T) {
	t.Run("returns false when not received", func(t *testing.T) {
		m := &CustodianMember{
			UserID: "user-1",
		}
		assert.False(t, m.HasReceived())
	})

	t.Run("returns true when received", func(t *testing.T) {
		now := time.Now().UTC()
		m := &CustodianMember{
			UserID:     "user-1",
			ReceivedAt: &now,
		}
		assert.True(t, m.HasReceived())
	})
}

func TestCustodianGroup_IsFull(t *testing.T) {
	t.Run("not full when members less than total", func(t *testing.T) {
		g := &CustodianGroup{
			Total: 3,
			Members: []CustodianMember{
				{UserID: "user-1"},
			},
		}
		assert.False(t, g.IsFull())
	})

	t.Run("full when members equal total", func(t *testing.T) {
		g := &CustodianGroup{
			Total: 2,
			Members: []CustodianMember{
				{UserID: "user-1"},
				{UserID: "user-2"},
			},
		}
		assert.True(t, g.IsFull())
	})

	t.Run("full when members exceed total", func(t *testing.T) {
		g := &CustodianGroup{
			Total: 1,
			Members: []CustodianMember{
				{UserID: "user-1"},
				{UserID: "user-2"},
			},
		}
		assert.True(t, g.IsFull())
	})

	t.Run("not full with zero members", func(t *testing.T) {
		g := &CustodianGroup{
			Total:   3,
			Members: []CustodianMember{},
		}
		assert.False(t, g.IsFull())
	})
}

func TestCustodianGroup_ReceivedCount(t *testing.T) {
	t.Run("zero when no members received", func(t *testing.T) {
		g := &CustodianGroup{
			Members: []CustodianMember{
				{UserID: "user-1"},
				{UserID: "user-2"},
			},
		}
		assert.Equal(t, 0, g.ReceivedCount())
	})

	t.Run("counts only received members", func(t *testing.T) {
		now := time.Now().UTC()
		g := &CustodianGroup{
			Members: []CustodianMember{
				{UserID: "user-1", ReceivedAt: &now},
				{UserID: "user-2"},
				{UserID: "user-3", ReceivedAt: &now},
			},
		}
		assert.Equal(t, 2, g.ReceivedCount())
	})

	t.Run("zero with empty members", func(t *testing.T) {
		g := &CustodianGroup{
			Members: []CustodianMember{},
		}
		assert.Equal(t, 0, g.ReceivedCount())
	})
}

func TestCustodianGroup_HasMember(t *testing.T) {
	g := &CustodianGroup{
		Members: []CustodianMember{
			{UserID: "user-1"},
			{UserID: "user-2"},
		},
	}

	t.Run("returns true for existing member", func(t *testing.T) {
		assert.True(t, g.HasMember("user-1"))
		assert.True(t, g.HasMember("user-2"))
	})

	t.Run("returns false for non-existing member", func(t *testing.T) {
		assert.False(t, g.HasMember("user-3"))
		assert.False(t, g.HasMember(""))
	})
}

func TestCustodianGroup_GetMember(t *testing.T) {
	g := &CustodianGroup{
		Members: []CustodianMember{
			{UserID: "user-1", Username: "alice"},
			{UserID: "user-2", Username: "bob"},
		},
	}

	t.Run("returns member for existing user", func(t *testing.T) {
		member := g.GetMember("user-2")
		require.NotNil(t, member)
		assert.Equal(t, "bob", member.Username)
	})

	t.Run("returns nil for non-existing user", func(t *testing.T) {
		member := g.GetMember("user-3")
		assert.Nil(t, member)
	})
}

func TestCustodianGroup_Validate(t *testing.T) {
	t.Run("valid group", func(t *testing.T) {
		g := &CustodianGroup{
			ID:        "group-1",
			Name:      "Test Group",
			Purpose:   PurposeBarrier,
			Threshold: 2,
			Total:     3,
		}
		assert.NoError(t, g.Validate())
	})

	t.Run("valid group with threshold equal to total", func(t *testing.T) {
		g := &CustodianGroup{
			ID:        "group-1",
			Name:      "Test Group",
			Purpose:   PurposeBarrier,
			Threshold: 3,
			Total:     3,
		}
		assert.NoError(t, g.Validate())
	})

	t.Run("empty ID", func(t *testing.T) {
		g := &CustodianGroup{
			Name:      "Test Group",
			Purpose:   PurposeBarrier,
			Threshold: 2,
			Total:     3,
		}
		assert.ErrorIs(t, g.Validate(), ErrEmptyGroupID)
	})

	t.Run("empty name", func(t *testing.T) {
		g := &CustodianGroup{
			ID:        "group-1",
			Purpose:   PurposeBarrier,
			Threshold: 2,
			Total:     3,
		}
		assert.ErrorIs(t, g.Validate(), ErrEmptyGroupName)
	})

	t.Run("empty purpose", func(t *testing.T) {
		g := &CustodianGroup{
			ID:        "group-1",
			Name:      "Test Group",
			Threshold: 2,
			Total:     3,
		}
		assert.ErrorIs(t, g.Validate(), ErrInvalidPurpose)
	})

	t.Run("threshold less than 2", func(t *testing.T) {
		g := &CustodianGroup{
			ID:        "group-1",
			Name:      "Test Group",
			Purpose:   PurposeBarrier,
			Threshold: 1,
			Total:     3,
		}
		assert.ErrorIs(t, g.Validate(), ErrInvalidThreshold)
	})

	t.Run("threshold zero", func(t *testing.T) {
		g := &CustodianGroup{
			ID:        "group-1",
			Name:      "Test Group",
			Purpose:   PurposeBarrier,
			Threshold: 0,
			Total:     3,
		}
		assert.ErrorIs(t, g.Validate(), ErrInvalidThreshold)
	})

	t.Run("total less than threshold", func(t *testing.T) {
		g := &CustodianGroup{
			ID:        "group-1",
			Name:      "Test Group",
			Purpose:   PurposeBarrier,
			Threshold: 3,
			Total:     2,
		}
		assert.ErrorIs(t, g.Validate(), ErrInvalidTotalShares)
	})
}

func TestConstants(t *testing.T) {
	t.Run("purpose constants are defined", func(t *testing.T) {
		assert.Equal(t, "barrier", PurposeBarrier)
		assert.Equal(t, "signing-key", PurposeSigningKey)
		assert.Equal(t, "backup", PurposeBackup)
	})

	t.Run("method constants are defined", func(t *testing.T) {
		assert.Equal(t, "fido2", MethodFIDO2)
		assert.Equal(t, "pkcs11", MethodPKCS11)
		assert.Equal(t, "manual", MethodManual)
	})
}
