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

package file

import (
	"path/filepath"
	"strings"
)

// The go-qrdb file engine does not store a key verbatim as a path: keys are
// arbitrary bytes, so the engine maps each key to a filesystem-safe path,
// percent-escaping every byte that is not printable ASCII plus '%' itself and
// any leading '.' of a segment. '/' keeps its meaning as a directory
// separator. A CA certificate stored under `certs/QuicBaaS Root CA.pem` thus
// lands on disk as `certs/QuicBaaS%20Root%20CA.pem`.
//
// This package is the only part of xkms that needs the on-disk path — it
// chmods the file the engine just wrote to widen `certs/*` to 0644 — so it
// mirrors the engine's encoding here. go-qrdb keeps its codec unexported and
// exposes no path accessor; adding one is the structurally superior fix and is
// the recommended upstream change, at which point encodeKeyToPath should be
// deleted in favour of it.
//
// TestKeyPathMatchesEngineLayout is the anti-drift guard: it writes through the
// real engine and asserts keyPath resolves to the file the engine actually
// created, so any change to the engine's encoding fails the xkms build rather
// than silently resurrecting the "no such file or directory" chmod failure.

const hexUpper = "0123456789ABCDEF"

// isSafeKeyByte reports whether c may appear verbatim in a path segment.
// Safe = printable ASCII excluding '%' (the escape marker) and '/' (the
// segment separator, handled explicitly by encodeKeyToPath).
func isSafeKeyByte(c byte) bool {
	return c > 0x20 && c < 0x7f && c != '%' && c != '/'
}

// encodeKeyToPath renders a storage key as the filesystem-safe, '/'-delimited
// relative path the go-qrdb file engine stores it at.
func encodeKeyToPath(key string) string {
	var b strings.Builder
	b.Grow(len(key) + 8)
	segStart := true
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c == '/':
			b.WriteByte('/')
			segStart = true
			continue
		case isSafeKeyByte(c) && !(segStart && c == '.'):
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexUpper[c>>4])
			b.WriteByte(hexUpper[c&0x0f])
		}
		segStart = false
	}
	return b.String()
}

// keyPath returns the absolute on-disk path holding the value for key.
func (f *FileStorage) keyPath(key string) string {
	return filepath.Join(f.rootDir, filepath.FromSlash(encodeKeyToPath(key)))
}
