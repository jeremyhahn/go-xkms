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

package mem

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestZero_ClearsData(t *testing.T) {
	buf := make([]byte, 16)
	for i := range buf {
		buf[i] = 0xFF
	}
	Zero(buf)
	for i, b := range buf {
		assert.Equal(t, byte(0), b, "byte at index %d should be zero", i)
	}
}

func TestZero_EmptySlice(t *testing.T) {
	assert.NotPanics(t, func() {
		Zero([]byte{})
	})
}

func TestZero_NilSlice(t *testing.T) {
	assert.NotPanics(t, func() {
		Zero(nil)
	})
}

func TestZero_SingleByte(t *testing.T) {
	buf := []byte{0xAB}
	Zero(buf)
	assert.Equal(t, byte(0), buf[0])
}

func TestZero_LargeSlice(t *testing.T) {
	buf := make([]byte, 1024)
	for i := range buf {
		buf[i] = 0xFF
	}
	Zero(buf)
	for i, b := range buf {
		assert.Equal(t, byte(0), b, "byte at index %d should be zero", i)
	}
}

func TestZero_ModifiesBackingArray(t *testing.T) {
	// Allocate a backing array and create a slice from it.
	// After Zero, the original backing array must be zeroed,
	// proving Zero operates in-place rather than on a copy.
	backing := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	slice := backing[:]
	Zero(slice)
	for i, b := range backing {
		require.Equal(t, byte(0), b, "backing array byte at index %d should be zero", i)
	}
}
