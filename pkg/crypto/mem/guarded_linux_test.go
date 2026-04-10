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

//go:build linux

package mem

import (
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFreeGuardedMemory_NilRegion(t *testing.T) {
	// Calling freeGuardedMemory on a buffer with nil region must be a no-op.
	g := &GuardedBuffer{
		data:   nil,
		region: nil,
		size:   0,
	}
	assert.NotPanics(t, func() {
		freeGuardedMemory(g)
	})
}

func TestNewGuardedBuffer_LinuxMmapRegion(t *testing.T) {
	buf, err := NewGuardedBuffer(100)
	require.NoError(t, err)
	defer buf.Free()

	// On Linux, the region field must be populated.
	assert.NotNil(t, buf.region)

	// The region must be larger than the data (includes guard pages).
	dataPages := (100 + pageSize - 1) / pageSize
	expectedTotal := (dataPages + 2) * pageSize
	assert.Len(t, buf.region, expectedTotal)
}

func TestGuardedBuffer_FreeNilsRegion(t *testing.T) {
	buf, err := NewGuardedBuffer(64)
	require.NoError(t, err)

	assert.NotNil(t, buf.region)

	buf.Free()

	assert.Nil(t, buf.region)
	assert.Nil(t, buf.data)
	assert.True(t, buf.IsFreed())
}

func TestGuardedBuffer_PageSize(t *testing.T) {
	// Verify that the cached pageSize matches the OS.
	assert.Greater(t, pageSize, 0)
	assert.Equal(t, 0, pageSize%4096, "page size should be a multiple of 4096")
}

// saveSyscalls saves the current syscall function variables and returns
// a restore function that resets them to their original values.
func saveSyscalls() func() {
	origMmap := sysCallMmap
	origMunmap := sysCallMunmap
	origMprotect := sysCallMprotect
	origMlock := sysCallMlock
	origMunlock := sysCallMunlock
	return func() {
		sysCallMmap = origMmap
		sysCallMunmap = origMunmap
		sysCallMprotect = origMprotect
		sysCallMlock = origMlock
		sysCallMunlock = origMunlock
	}
}

func TestNewGuardedBuffer_MmapFailure(t *testing.T) {
	restore := saveSyscalls()
	defer restore()

	sysCallMmap = func(fd int, offset int64, length int, prot int, flags int) ([]byte, error) {
		return nil, unix.ENOMEM
	}

	buf, err := NewGuardedBuffer(32)
	assert.Nil(t, buf)
	require.Error(t, err)

	var mmapErr *ErrMmapFailed
	assert.ErrorAs(t, err, &mmapErr)
	assert.ErrorIs(t, mmapErr.Cause, unix.ENOMEM)
}

func TestNewGuardedBuffer_LeadingMprotectFailure(t *testing.T) {
	restore := saveSyscalls()
	defer restore()

	var munmapCalled atomic.Bool

	// Let mmap succeed but fail on the first mprotect call (leading guard).
	sysCallMprotect = func(b []byte, prot int) error {
		return unix.EINVAL
	}
	sysCallMunmap = func(b []byte) error {
		munmapCalled.Store(true)
		return unix.Munmap(b)
	}

	buf, err := NewGuardedBuffer(32)
	assert.Nil(t, buf)
	require.Error(t, err)

	var mprotectErr *ErrMprotectFailed
	assert.ErrorAs(t, err, &mprotectErr)
	assert.Equal(t, "leading", mprotectErr.Page)
	assert.ErrorIs(t, mprotectErr.Cause, unix.EINVAL)

	// Verify cleanup: munmap must have been called to release the region.
	assert.True(t, munmapCalled.Load(), "munmap should be called on mprotect failure")
}

func TestNewGuardedBuffer_TrailingMprotectFailure(t *testing.T) {
	restore := saveSyscalls()
	defer restore()

	var callCount atomic.Int32
	var munmapCalled atomic.Bool

	// Let the first mprotect call (leading guard) succeed, fail on the second (trailing).
	sysCallMprotect = func(b []byte, prot int) error {
		if callCount.Add(1) == 1 {
			return unix.Mprotect(b, prot) // leading: real call
		}
		return unix.EPERM // trailing: fail
	}
	sysCallMunmap = func(b []byte) error {
		munmapCalled.Store(true)
		return unix.Munmap(b)
	}

	buf, err := NewGuardedBuffer(32)
	assert.Nil(t, buf)
	require.Error(t, err)

	var mprotectErr *ErrMprotectFailed
	assert.ErrorAs(t, err, &mprotectErr)
	assert.Equal(t, "trailing", mprotectErr.Page)
	assert.ErrorIs(t, mprotectErr.Cause, unix.EPERM)

	// Verify cleanup: munmap must have been called.
	assert.True(t, munmapCalled.Load(), "munmap should be called on trailing mprotect failure")
}

func TestGuardedBuffer_CloneFailure(t *testing.T) {
	// Create a valid buffer first, then inject mmap failure so Clone's
	// internal NewGuardedBuffer call fails.
	buf, err := NewGuardedBuffer(16)
	require.NoError(t, err)
	defer buf.Free()

	buf.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF})

	restore := saveSyscalls()
	defer restore()

	sysCallMmap = func(fd int, offset int64, length int, prot int, flags int) ([]byte, error) {
		return nil, unix.ENOMEM
	}

	clone, err := buf.Clone()
	assert.Nil(t, clone)
	require.Error(t, err)

	var mmapErr *ErrMmapFailed
	assert.ErrorAs(t, err, &mmapErr)
}
