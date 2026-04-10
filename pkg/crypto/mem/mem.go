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

// Package mem provides memory safety utilities for secure handling of
// sensitive cryptographic material such as keys, nonces, and passwords.
//
// GuardedBuffer allocates OS-protected memory with guard pages to detect
// buffer overflows and mlock to prevent swapping to disk. On platforms
// without mmap support, it falls back to a plain heap allocation with
// guaranteed zeroing on free.
package mem

// Zero overwrites the byte slice with zeros.
// This is used to clear sensitive data like keys and passwords from memory.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
