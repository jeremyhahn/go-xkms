// Copyright (c) 2026 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

package wire

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestPCRValuesToHex proves the raw-byte PCR map the REST wire format carries
// converts to the SDK's hex-encoded representation, index by index, and that
// an empty input round-trips to an empty (non-nil) map rather than nil.
func TestPCRValuesToHex(t *testing.T) {
	in := map[int][]byte{
		0:  {0x00, 0x01, 0x02},
		7:  {0xde, 0xad, 0xbe, 0xef},
		23: {},
	}

	got := PCRValuesToHex(in)

	assert.Equal(t, hex.EncodeToString([]byte{0x00, 0x01, 0x02}), got[0])
	assert.Equal(t, "deadbeef", got[7])
	assert.Equal(t, "", got[23])
	assert.Len(t, got, 3)
}

// TestPCRValuesToHex_EmptyInput proves an empty (or nil) input map produces
// an empty, non-nil output map rather than propagating a nil map that would
// marshal to JSON `null` instead of `{}`.
func TestPCRValuesToHex_EmptyInput(t *testing.T) {
	got := PCRValuesToHex(nil)
	assert.NotNil(t, got)
	assert.Empty(t, got)

	got = PCRValuesToHex(map[int][]byte{})
	assert.NotNil(t, got)
	assert.Empty(t, got)
}
