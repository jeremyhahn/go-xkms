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

package pairing

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// defaultTestMTU is a reasonable MTU for test purposes (BLE GATT default).
const defaultTestMTU = 247

func TestFragmentConstants(t *testing.T) {
	assert.Equal(t, 7, FragmentHeaderSize)
	assert.Equal(t, 0x01, FlagFirstFragment)
	assert.Equal(t, 0x02, FlagLastFragment)
	assert.Equal(t, 0x03, FlagSingleFragment)
}

func TestNewFragmenter(t *testing.T) {
	tests := []struct {
		name        string
		mtu         int
		expectedMTU int
	}{
		{"normal MTU", 247, 247},
		{"minimum MTU", MinMTU, MinMTU},
		{"below minimum MTU", 10, MinMTU},
		{"zero MTU", 0, MinMTU},
		{"negative MTU", -100, MinMTU},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFragmenter(tt.mtu)
			require.NotNil(t, f)
			assert.Equal(t, tt.expectedMTU, f.MTU())
		})
	}
}

func TestFragmenter_SetMTU(t *testing.T) {
	f := NewFragmenter(100)
	assert.Equal(t, 100, f.MTU())

	f.SetMTU(200)
	assert.Equal(t, 200, f.MTU())

	f.SetMTU(10)
	assert.Equal(t, 200, f.MTU()) // Unchanged - below minimum
}

func TestFragmenter_Fragment_EmptyMessage(t *testing.T) {
	f := NewFragmenter(100)

	fragments, err := f.Fragment([]byte{})
	require.NoError(t, err)
	require.Len(t, fragments, 1)

	frag, err := DecodeFragment(fragments[0])
	require.NoError(t, err)
	assert.Equal(t, byte(FlagSingleFragment), frag.Flags)
	assert.Equal(t, uint16(0), frag.Length)
}

func TestFragmenter_Fragment_SingleFragment(t *testing.T) {
	mtu := 100
	f := NewFragmenter(mtu)
	maxPayload := mtu - FragmentHeaderSize

	message := bytes.Repeat([]byte{0xAB}, maxPayload)

	fragments, err := f.Fragment(message)
	require.NoError(t, err)
	require.Len(t, fragments, 1)

	frag, err := DecodeFragment(fragments[0])
	require.NoError(t, err)
	assert.Equal(t, byte(FlagSingleFragment), frag.Flags)
	assert.Equal(t, message, frag.Payload)
}

func TestFragmenter_Fragment_MultipleFragments(t *testing.T) {
	mtu := 50
	f := NewFragmenter(mtu)
	maxPayload := mtu - FragmentHeaderSize

	message := bytes.Repeat([]byte{0xCD}, maxPayload*3-5)

	fragments, err := f.Fragment(message)
	require.NoError(t, err)
	require.Len(t, fragments, 3)

	// First fragment
	frag0, err := DecodeFragment(fragments[0])
	require.NoError(t, err)
	assert.Equal(t, byte(FlagFirstFragment), frag0.Flags)
	assert.Equal(t, uint16(0), frag0.Sequence)
	assert.Equal(t, uint16(3), frag0.Total)

	// Middle fragment
	frag1, err := DecodeFragment(fragments[1])
	require.NoError(t, err)
	assert.Equal(t, byte(0), frag1.Flags)
	assert.Equal(t, uint16(1), frag1.Sequence)

	// Last fragment
	frag2, err := DecodeFragment(fragments[2])
	require.NoError(t, err)
	assert.Equal(t, byte(FlagLastFragment), frag2.Flags)
	assert.Equal(t, uint16(2), frag2.Sequence)
}

func TestDecodeFragment_TooShort(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03}

	_, err := DecodeFragment(data)
	assert.ErrorIs(t, err, ErrInvalidFragment)
}

func TestDecodeFragment_LengthMismatch(t *testing.T) {
	// Header claims 10 bytes, but only 5 available
	data := []byte{FlagSingleFragment, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0A, 'h', 'e', 'l', 'l', 'o'}

	_, err := DecodeFragment(data)
	assert.ErrorIs(t, err, ErrInvalidFragment)
}

func TestReassembler_NewReassembler(t *testing.T) {
	r := NewReassembler()
	require.NotNil(t, r)
	assert.False(t, r.IsComplete())

	received, total := r.Progress()
	assert.Equal(t, uint16(0), received)
	assert.Equal(t, uint16(0), total)
}

func TestReassembler_Reset(t *testing.T) {
	r := NewReassembler()

	frag := &Fragment{
		Flags:    FlagFirstFragment,
		Sequence: 0,
		Total:    2,
		Length:   5,
		Payload:  []byte("hello"),
	}
	_, err := r.AddFragment(frag)
	require.NoError(t, err)

	r.Reset()

	received, total := r.Progress()
	assert.Equal(t, uint16(0), received)
	assert.Equal(t, uint16(0), total)
}

func TestReassembler_SingleFragment(t *testing.T) {
	r := NewReassembler()

	frag := &Fragment{
		Flags:    FlagSingleFragment,
		Sequence: 0,
		Total:    1,
		Length:   5,
		Payload:  []byte("hello"),
	}

	complete, err := r.AddFragment(frag)
	require.NoError(t, err)
	assert.True(t, complete)

	message, err := r.Assemble()
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), message)
}

func TestReassembler_MultipleFragments_InOrder(t *testing.T) {
	r := NewReassembler()

	fragments := []*Fragment{
		{Flags: FlagFirstFragment, Sequence: 0, Total: 3, Length: 5, Payload: []byte("hello")},
		{Flags: 0, Sequence: 1, Total: 3, Length: 1, Payload: []byte(" ")},
		{Flags: FlagLastFragment, Sequence: 2, Total: 3, Length: 5, Payload: []byte("world")},
	}

	for i, frag := range fragments {
		complete, err := r.AddFragment(frag)
		require.NoError(t, err)
		if i < 2 {
			assert.False(t, complete)
		} else {
			assert.True(t, complete)
		}
	}

	message, err := r.Assemble()
	require.NoError(t, err)
	assert.Equal(t, []byte("hello world"), message)
}

func TestReassembler_MultipleFragments_OutOfOrder(t *testing.T) {
	r := NewReassembler()

	// Send fragments out of order: 2, 0, 1
	fragments := []*Fragment{
		{Flags: FlagLastFragment, Sequence: 2, Total: 3, Length: 5, Payload: []byte("world")},
		{Flags: FlagFirstFragment, Sequence: 0, Total: 3, Length: 5, Payload: []byte("hello")},
		{Flags: 0, Sequence: 1, Total: 3, Length: 1, Payload: []byte(" ")},
	}

	var complete bool
	var err error
	for _, frag := range fragments {
		complete, err = r.AddFragment(frag)
		require.NoError(t, err)
	}
	assert.True(t, complete)

	message, err := r.Assemble()
	require.NoError(t, err)
	assert.Equal(t, []byte("hello world"), message)
}

func TestReassembler_InvalidSequenceNumber(t *testing.T) {
	r := NewReassembler()

	frag := &Fragment{
		Flags:    FlagFirstFragment,
		Sequence: 5,
		Total:    3,
		Length:   5,
		Payload:  []byte("hello"),
	}

	_, err := r.AddFragment(frag)
	assert.ErrorIs(t, err, ErrSequenceNumber)
}

func TestReassembler_AssembleIncomplete(t *testing.T) {
	r := NewReassembler()

	frag := &Fragment{
		Flags:    FlagFirstFragment,
		Sequence: 0,
		Total:    3,
		Length:   5,
		Payload:  []byte("hello"),
	}
	_, err := r.AddFragment(frag)
	require.NoError(t, err)

	_, err = r.Assemble()
	assert.ErrorIs(t, err, ErrFragmentationError)
}

func TestFragmentRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		mtu     int
		msgSize int
	}{
		{"small message", defaultTestMTU, 100},
		{"large message", defaultTestMTU, 5000},
		{"minimum MTU", MinMTU, 500},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := make([]byte, tt.msgSize)
			_, err := rand.Read(original)
			require.NoError(t, err)

			f := NewFragmenter(tt.mtu)
			fragments, err := f.Fragment(original)
			require.NoError(t, err)

			r := NewReassembler()
			for _, fragData := range fragments {
				frag, err := DecodeFragment(fragData)
				require.NoError(t, err)
				_, err = r.AddFragment(frag)
				require.NoError(t, err)
			}

			assert.True(t, r.IsComplete())

			reassembled, err := r.Assemble()
			require.NoError(t, err)
			assert.Equal(t, original, reassembled)
		})
	}
}

func BenchmarkFragment(b *testing.B) {
	f := NewFragmenter(defaultTestMTU)
	message := make([]byte, 10000)
	rand.Read(message)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = f.Fragment(message)
	}
}

func BenchmarkReassemble(b *testing.B) {
	f := NewFragmenter(defaultTestMTU)
	message := make([]byte, 10000)
	rand.Read(message)
	fragments, _ := f.Fragment(message)

	decodedFragments := make([]*Fragment, len(fragments))
	for i, fragData := range fragments {
		decodedFragments[i], _ = DecodeFragment(fragData)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := NewReassembler()
		for _, frag := range decodedFragments {
			r.AddFragment(frag)
		}
		r.Assemble()
	}
}

// --- Fragmentation edge case tests for coverage ---

func TestFragmenter_Fragment_MTUTooSmall(t *testing.T) {
	// Create a fragmenter with MTU equal to header size so maxPayload = 0.
	// We bypass the constructor's clamp by directly setting the mtu field.
	f := &Fragmenter{mtu: FragmentHeaderSize}

	_, err := f.Fragment([]byte("test"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMTUTooSmall)
}

func TestReassembler_AddFragment_AlreadyComplete(t *testing.T) {
	// Add a single-fragment message, then add another fragment after completion.
	r := NewReassembler()

	complete, err := r.AddFragment(&Fragment{
		Flags:    FlagSingleFragment,
		Sequence: 0,
		Total:    1,
		Length:   4,
		Payload:  []byte("test"),
	})
	require.NoError(t, err)
	assert.True(t, complete)

	// Adding a fragment after completion should return true immediately.
	complete, err = r.AddFragment(&Fragment{
		Flags:    0,
		Sequence: 0,
		Total:    1,
		Length:   4,
		Payload:  []byte("dupe"),
	})
	require.NoError(t, err)
	assert.True(t, complete)
}

func TestReassembler_AddFragment_DuplicateFragment(t *testing.T) {
	// Add the same fragment twice -- the duplicate should be skipped.
	r := NewReassembler()

	frag := &Fragment{
		Flags:    FlagFirstFragment,
		Sequence: 0,
		Total:    2,
		Length:   4,
		Payload:  []byte("part"),
	}

	complete, err := r.AddFragment(frag)
	require.NoError(t, err)
	assert.False(t, complete)

	// Add duplicate of the same fragment.
	complete, err = r.AddFragment(frag)
	require.NoError(t, err)
	assert.False(t, complete) // still not complete, waiting for fragment 1

	// Verify received count didn't increase.
	received, total := r.Progress()
	assert.Equal(t, uint16(1), received)
	assert.Equal(t, uint16(2), total)
}

func TestReassembler_AddFragment_TotalMismatch(t *testing.T) {
	// First fragment says total=2, then another first fragment says total=3.
	r := NewReassembler()

	_, err := r.AddFragment(&Fragment{
		Flags:    FlagFirstFragment,
		Sequence: 0,
		Total:    2,
		Length:   4,
		Payload:  []byte("part"),
	})
	require.NoError(t, err)

	_, err = r.AddFragment(&Fragment{
		Flags:    FlagFirstFragment,
		Sequence: 0,
		Total:    3, // mismatched total
		Length:   4,
		Payload:  []byte("part"),
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSequenceNumber)
}

func TestReassembler_Assemble_MissingFragment(t *testing.T) {
	// Mark reassembler as complete but with a missing fragment in the map.
	r := NewReassembler()

	// Add fragment 0 and 2 of 3, but mark complete manually to trigger
	// the missing fragment path in Assemble.
	r.mu.Lock()
	r.fragments[0] = []byte("part0")
	r.fragments[2] = []byte("part2")
	r.totalExpected = 3
	r.received = 3
	r.complete = true
	r.mu.Unlock()

	_, err := r.Assemble()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSequenceNumber)
}

func TestFragmenter_Fragment_TooManyFragments(t *testing.T) {
	// Create a fragmenter with minimum MTU (maxPayload = 16 bytes per fragment).
	// Message needs > 65535 fragments = > 65535 * 16 = 1,048,560 bytes.
	f := NewFragmenter(MinMTU)
	message := make([]byte, 65536*16+1) // Just over the limit

	_, err := f.Fragment(message)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrFragmentationError)
}
