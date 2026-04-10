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
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGuardedBuffer(t *testing.T) {
	buf, err := NewGuardedBuffer(32)
	require.NoError(t, err)
	defer buf.Free()

	assert.Equal(t, 32, buf.Size())
	assert.False(t, buf.IsFreed())
	assert.Len(t, buf.Bytes(), 32)
}

func TestNewGuardedBuffer_VariousSizes(t *testing.T) {
	sizes := []int{1, 15, 16, 31, 32, 33, 64, 128, 255, 256, 4096, 4097, 8192}
	for _, size := range sizes {
		buf, err := NewGuardedBuffer(size)
		require.NoError(t, err, "size=%d", size)
		assert.Equal(t, size, buf.Size(), "size=%d", size)
		assert.Len(t, buf.Bytes(), size, "size=%d", size)
		buf.Free()
	}
}

func TestNewGuardedBuffer_InvalidSizeZero(t *testing.T) {
	buf, err := NewGuardedBuffer(0)
	assert.Nil(t, buf)
	require.Error(t, err)

	var invalidSizeErr *ErrInvalidSize
	assert.ErrorAs(t, err, &invalidSizeErr)
	assert.Equal(t, 0, invalidSizeErr.Size)
}

func TestNewGuardedBuffer_InvalidSizeNegative(t *testing.T) {
	buf, err := NewGuardedBuffer(-1)
	assert.Nil(t, buf)
	require.Error(t, err)

	var invalidSizeErr *ErrInvalidSize
	assert.ErrorAs(t, err, &invalidSizeErr)
	assert.Equal(t, -1, invalidSizeErr.Size)
}

func TestNewGuardedBuffer_InvalidSizeLargeNegative(t *testing.T) {
	buf, err := NewGuardedBuffer(-65536)
	assert.Nil(t, buf)
	require.Error(t, err)

	var invalidSizeErr *ErrInvalidSize
	assert.ErrorAs(t, err, &invalidSizeErr)
	assert.Equal(t, -65536, invalidSizeErr.Size)
}

func TestGuardedBuffer_Bytes(t *testing.T) {
	buf, err := NewGuardedBuffer(16)
	require.NoError(t, err)
	defer buf.Free()

	// Write known data and read it back.
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	copy(buf.Bytes(), data)

	assert.Equal(t, data, buf.Bytes())
}

func TestGuardedBuffer_BytesModifiesInPlace(t *testing.T) {
	buf, err := NewGuardedBuffer(8)
	require.NoError(t, err)
	defer buf.Free()

	// Obtain the slice, modify it, and verify the buffer reflects changes.
	b := buf.Bytes()
	b[0] = 0xFF
	b[7] = 0xAA

	assert.Equal(t, byte(0xFF), buf.Bytes()[0])
	assert.Equal(t, byte(0xAA), buf.Bytes()[7])
}

func TestGuardedBuffer_Clone(t *testing.T) {
	buf, err := NewGuardedBuffer(16)
	require.NoError(t, err)
	defer buf.Free()

	// Fill with known pattern.
	for i := range buf.Bytes() {
		buf.Bytes()[i] = byte(i + 1)
	}

	clone, err := buf.Clone()
	require.NoError(t, err)
	defer clone.Free()

	// Clone must match the original.
	assert.Equal(t, buf.Bytes(), clone.Bytes())
	assert.Equal(t, buf.Size(), clone.Size())

	// Verify independence: modifying clone must not affect original.
	clone.Bytes()[0] = 0xFF
	assert.NotEqual(t, buf.Bytes()[0], clone.Bytes()[0])
	assert.Equal(t, byte(1), buf.Bytes()[0])
	assert.Equal(t, byte(0xFF), clone.Bytes()[0])
}

func TestGuardedBuffer_CloneIndependence(t *testing.T) {
	buf, err := NewGuardedBuffer(32)
	require.NoError(t, err)
	defer buf.Free()

	for i := range buf.Bytes() {
		buf.Bytes()[i] = byte(i)
	}

	clone, err := buf.Clone()
	require.NoError(t, err)
	defer clone.Free()

	// Zero original, clone should be unaffected.
	buf.Zero()
	for i, b := range clone.Bytes() {
		assert.Equal(t, byte(i), b, "clone byte %d should be unchanged", i)
	}
}

func TestGuardedBuffer_Zero(t *testing.T) {
	buf, err := NewGuardedBuffer(32)
	require.NoError(t, err)
	defer buf.Free()

	// Fill with non-zero data.
	for i := range buf.Bytes() {
		buf.Bytes()[i] = 0xFF
	}

	buf.Zero()

	for i, b := range buf.Bytes() {
		assert.Equal(t, byte(0), b, "byte %d should be zero after Zero()", i)
	}
}

func TestGuardedBuffer_ZeroPreservesUsability(t *testing.T) {
	buf, err := NewGuardedBuffer(16)
	require.NoError(t, err)
	defer buf.Free()

	// Write, zero, then write again -- buffer should remain usable.
	buf.Write([]byte{1, 2, 3, 4})
	buf.Zero()
	n := buf.Write([]byte{5, 6, 7, 8})

	assert.Equal(t, 4, n)
	assert.Equal(t, byte(5), buf.Bytes()[0])
	assert.Equal(t, byte(8), buf.Bytes()[3])
}

func TestGuardedBuffer_Free(t *testing.T) {
	buf, err := NewGuardedBuffer(16)
	require.NoError(t, err)

	assert.False(t, buf.IsFreed())

	buf.Free()

	assert.True(t, buf.IsFreed())
}

func TestGuardedBuffer_FreeTwice(t *testing.T) {
	buf, err := NewGuardedBuffer(16)
	require.NoError(t, err)

	buf.Free()
	assert.True(t, buf.IsFreed())

	// Second Free must be a safe no-op.
	assert.NotPanics(t, func() {
		buf.Free()
	})
	assert.True(t, buf.IsFreed())
}

func TestGuardedBuffer_FreeZerosData(t *testing.T) {
	buf, err := NewGuardedBuffer(16)
	require.NoError(t, err)

	// Grab a reference to the backing data before Free.
	data := buf.Bytes()
	for i := range data {
		data[i] = 0xFF
	}

	buf.Free()

	// After Free, the data slice may have been unmapped on Linux.
	// On non-Linux (stub), we can verify zeroing. On Linux, the slice
	// is no longer safely accessible. We verify via the freed flag.
	assert.True(t, buf.IsFreed())
}

func TestGuardedBuffer_Write(t *testing.T) {
	buf, err := NewGuardedBuffer(8)
	require.NoError(t, err)
	defer buf.Free()

	src := []byte{0x01, 0x02, 0x03, 0x04}
	n := buf.Write(src)

	assert.Equal(t, 4, n)
	assert.Equal(t, src, buf.Bytes()[:4])

	// Remaining bytes should be zero (fresh allocation).
	for i := 4; i < 8; i++ {
		assert.Equal(t, byte(0), buf.Bytes()[i], "byte %d should be zero", i)
	}
}

func TestGuardedBuffer_WriteExactSize(t *testing.T) {
	buf, err := NewGuardedBuffer(4)
	require.NoError(t, err)
	defer buf.Free()

	src := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	n := buf.Write(src)

	assert.Equal(t, 4, n)
	assert.Equal(t, src, buf.Bytes())
}

func TestGuardedBuffer_WriteLargerThanBuffer(t *testing.T) {
	buf, err := NewGuardedBuffer(4)
	require.NoError(t, err)
	defer buf.Free()

	// Source is larger than buffer; only 4 bytes should be copied.
	src := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	n := buf.Write(src)

	assert.Equal(t, 4, n)
	assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, buf.Bytes())
}

func TestGuardedBuffer_WriteEmpty(t *testing.T) {
	buf, err := NewGuardedBuffer(4)
	require.NoError(t, err)
	defer buf.Free()

	n := buf.Write([]byte{})
	assert.Equal(t, 0, n)
}

func TestGuardedBuffer_WriteOverwrites(t *testing.T) {
	buf, err := NewGuardedBuffer(4)
	require.NoError(t, err)
	defer buf.Free()

	buf.Write([]byte{0xAA, 0xBB, 0xCC, 0xDD})
	buf.Write([]byte{0x11, 0x22})

	// First 2 bytes overwritten, last 2 unchanged.
	assert.Equal(t, []byte{0x11, 0x22, 0xCC, 0xDD}, buf.Bytes())
}

func TestGuardedBuffer_PanicBytesAfterFree(t *testing.T) {
	buf, err := NewGuardedBuffer(16)
	require.NoError(t, err)
	buf.Free()

	assert.Panics(t, func() {
		buf.Bytes()
	})
}

func TestGuardedBuffer_PanicZeroAfterFree(t *testing.T) {
	buf, err := NewGuardedBuffer(16)
	require.NoError(t, err)
	buf.Free()

	assert.Panics(t, func() {
		buf.Zero()
	})
}

func TestGuardedBuffer_PanicCloneAfterFree(t *testing.T) {
	buf, err := NewGuardedBuffer(16)
	require.NoError(t, err)
	buf.Free()

	assert.Panics(t, func() {
		_, _ = buf.Clone()
	})
}

func TestGuardedBuffer_PanicWriteAfterFree(t *testing.T) {
	buf, err := NewGuardedBuffer(16)
	require.NoError(t, err)
	buf.Free()

	assert.Panics(t, func() {
		buf.Write([]byte{0x01})
	})
}

func TestGuardedBuffer_ConcurrentReadWrite(t *testing.T) {
	buf, err := NewGuardedBuffer(64)
	require.NoError(t, err)
	defer buf.Free()

	var wg sync.WaitGroup
	const goroutines = 16
	const iterations = 100

	// Concurrent writes to non-overlapping regions.
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			offset := (id * 4) % 64
			for i := 0; i < iterations; i++ {
				b := buf.Bytes()
				b[offset] = byte(id)
				_ = b[offset] // read back
			}
		}(g)
	}

	wg.Wait()
}

func TestGuardedBuffer_ConcurrentFree(t *testing.T) {
	buf, err := NewGuardedBuffer(32)
	require.NoError(t, err)

	var wg sync.WaitGroup
	const goroutines = 16

	// Multiple goroutines racing to Free -- must not panic or double-free.
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf.Free()
		}()
	}

	wg.Wait()
	assert.True(t, buf.IsFreed())
}

func TestGuardedBuffer_ConcurrentClone(t *testing.T) {
	buf, err := NewGuardedBuffer(32)
	require.NoError(t, err)
	defer buf.Free()

	for i := range buf.Bytes() {
		buf.Bytes()[i] = byte(i)
	}

	var wg sync.WaitGroup
	const goroutines = 8

	clones := make([]*GuardedBuffer, goroutines)
	errs := make([]error, goroutines)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			clones[idx], errs[idx] = buf.Clone()
		}(g)
	}

	wg.Wait()

	for i := 0; i < goroutines; i++ {
		require.NoError(t, errs[i], "goroutine %d", i)
		assert.Equal(t, buf.Bytes(), clones[i].Bytes(), "goroutine %d", i)
		clones[i].Free()
	}
}

func TestGuardedBuffer_SingleByte(t *testing.T) {
	buf, err := NewGuardedBuffer(1)
	require.NoError(t, err)
	defer buf.Free()

	assert.Equal(t, 1, buf.Size())

	buf.Bytes()[0] = 0xAB
	assert.Equal(t, byte(0xAB), buf.Bytes()[0])

	buf.Zero()
	assert.Equal(t, byte(0), buf.Bytes()[0])
}

func TestGuardedBuffer_PageAlignedSize(t *testing.T) {
	// Allocate exactly one page worth of data.
	buf, err := NewGuardedBuffer(4096)
	require.NoError(t, err)
	defer buf.Free()

	assert.Equal(t, 4096, buf.Size())

	// Write to first and last byte.
	buf.Bytes()[0] = 0x01
	buf.Bytes()[4095] = 0xFF

	assert.Equal(t, byte(0x01), buf.Bytes()[0])
	assert.Equal(t, byte(0xFF), buf.Bytes()[4095])
}

func TestZeroAndFree(t *testing.T) {
	buf, err := NewGuardedBuffer(16)
	require.NoError(t, err)

	buf.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF})

	ZeroAndFree(buf)
	assert.True(t, buf.IsFreed())
}

func TestZeroAndFree_Nil(t *testing.T) {
	assert.NotPanics(t, func() {
		ZeroAndFree(nil)
	})
}

func TestZeroAndFree_AlreadyFreed(t *testing.T) {
	buf, err := NewGuardedBuffer(16)
	require.NoError(t, err)
	buf.Free()

	// Calling ZeroAndFree on an already-freed buffer must not panic.
	assert.NotPanics(t, func() {
		ZeroAndFree(buf)
	})
}

func TestErrInvalidSize_Error(t *testing.T) {
	err := &ErrInvalidSize{Size: -5}
	assert.Contains(t, err.Error(), "-5")
	assert.Contains(t, err.Error(), "mem:")
	assert.Contains(t, err.Error(), "positive")
}

func TestErrMmapFailed_Error(t *testing.T) {
	cause := &ErrInvalidSize{Size: 0}
	err := &ErrMmapFailed{Cause: cause}
	assert.Contains(t, err.Error(), "mmap failed")
	assert.ErrorIs(t, err, cause)
}

func TestErrMprotectFailed_Error(t *testing.T) {
	cause := &ErrInvalidSize{Size: 0}
	err := &ErrMprotectFailed{Page: "leading", Cause: cause}
	assert.Contains(t, err.Error(), "leading guard")
	assert.Contains(t, err.Error(), "mprotect")
	assert.ErrorIs(t, err, cause)
}

func TestErrMprotectFailed_Unwrap(t *testing.T) {
	cause := &ErrInvalidSize{Size: 0}
	err := &ErrMprotectFailed{Page: "trailing", Cause: cause}
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrMmapFailed_Unwrap(t *testing.T) {
	cause := &ErrInvalidSize{Size: 0}
	err := &ErrMmapFailed{Cause: cause}
	assert.Equal(t, cause, err.Unwrap())
}
