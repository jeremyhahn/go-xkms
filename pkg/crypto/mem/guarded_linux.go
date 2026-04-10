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
	"os"

	"golang.org/x/sys/unix"
)

// pageSize caches the OS page size at init time.
var pageSize = os.Getpagesize()

// Syscall function variables allow tests to inject failures without
// modifying the host system. Production code uses the real syscalls.
var (
	sysCallMmap     = unix.Mmap
	sysCallMunmap   = unix.Munmap
	sysCallMprotect = unix.Mprotect
	sysCallMlock    = unix.Mlock
	sysCallMunlock  = unix.Munlock
)

// newGuardedBuffer allocates guarded memory using mmap with guard pages.
//
// Memory layout: [guard page | data pages | guard page]
//
// The leading and trailing guard pages are set to PROT_NONE, causing a
// SIGSEGV on any read or write attempt. This provides immediate crash
// detection for buffer overflows and underflows.
//
// The data pages are locked into physical RAM via mlock to prevent the
// kernel from swapping sensitive key material to disk. If mlock fails
// (e.g., due to RLIMIT_MEMLOCK), the allocation proceeds without
// locking -- the guard pages still provide overflow protection.
func newGuardedBuffer(size int) (*GuardedBuffer, error) {
	if size <= 0 {
		return nil, &ErrInvalidSize{Size: size}
	}

	// Round up data to the next page boundary, then add 2 guard pages.
	dataPages := (size + pageSize - 1) / pageSize
	totalSize := (dataPages + 2) * pageSize

	// Allocate an anonymous private mapping.
	region, err := sysCallMmap(-1, 0, totalSize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return nil, &ErrMmapFailed{Cause: err}
	}

	// Set the leading guard page to PROT_NONE.
	if err := sysCallMprotect(region[:pageSize], unix.PROT_NONE); err != nil {
		_ = sysCallMunmap(region)
		return nil, &ErrMprotectFailed{Page: "leading", Cause: err}
	}

	// Set the trailing guard page to PROT_NONE.
	trailingStart := (dataPages + 1) * pageSize
	if err := sysCallMprotect(region[trailingStart:], unix.PROT_NONE); err != nil {
		_ = sysCallMunmap(region)
		return nil, &ErrMprotectFailed{Page: "trailing", Cause: err}
	}

	// Lock the data pages into RAM to prevent swapping.
	// Failure here is non-fatal: guard pages still protect the region.
	dataRegion := region[pageSize : pageSize+dataPages*pageSize]
	_ = sysCallMlock(dataRegion)

	// The usable slice is the first `size` bytes of the data region.
	data := region[pageSize : pageSize+size]

	return &GuardedBuffer{
		data:   data,
		region: region,
		size:   size,
	}, nil
}

// freeGuardedMemory unlocks and unmaps the guarded memory region.
func freeGuardedMemory(g *GuardedBuffer) {
	if g.region == nil {
		return
	}

	// Unlock the data pages. Errors are ignored during cleanup.
	dataPages := (g.size + pageSize - 1) / pageSize
	dataRegion := g.region[pageSize : pageSize+dataPages*pageSize]
	_ = sysCallMunlock(dataRegion)

	// Unmap the entire region including guard pages.
	_ = sysCallMunmap(g.region)

	g.region = nil
	g.data = nil
}
