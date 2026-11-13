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

package entities

import (
	"hash/fnv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStringToEntityID_NonZero(t *testing.T) {
	inputs := []string{
		"a",
		"hello",
		"kid-12345",
		"tenant-xyz",
	}

	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			id := StringToEntityID(input)
			assert.NotZero(t, id, "non-empty string must produce non-zero ID")
		})
	}
}

func TestStringToEntityID_EmptyString(t *testing.T) {
	id := StringToEntityID("")

	// FNV-1a offset basis for 64-bit is non-zero (14695981039346656037),
	// so even an empty string produces a non-zero hash.
	h := fnv.New64a()
	h.Write([]byte(""))
	expected := h.Sum64()

	assert.Equal(t, expected, id)
	assert.NotZero(t, id, "FNV-1a of empty string is the offset basis, which is non-zero")
}
