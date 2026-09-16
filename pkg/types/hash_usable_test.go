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

package types

import (
	"crypto"
	"testing"

	_ "crypto/sha1"
	_ "crypto/sha256"
)

// HashUsable must answer for the process it is running in, so it is asserted
// against the digest itself rather than against an expected constant: the same
// test is meaningful with and without GODEBUG=fips140=only, which is the point
// (go-xkms#292).
func TestHashUsable_AgreesWithActuallyHashing(t *testing.T) {
	for _, h := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		want := canHash(h)
		if got := HashUsable(h); got != want {
			t.Errorf("HashUsable(%v) = %v, but hashing with it %s",
				h, got, map[bool]string{true: "succeeds", false: "panics"}[want])
		}
	}
}

// An approved digest must never be withdrawn. If this fails, the probe is
// over-restricting and has broken a working capability.
func TestHashUsable_ApprovedDigestsAlwaysUsable(t *testing.T) {
	for _, h := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		if !HashUsable(h) {
			t.Errorf("HashUsable(%v) = false; approved digests must remain available in every mode", h)
		}
	}
}

// The answer is cached, so it must not drift between calls.
func TestHashUsable_IsStable(t *testing.T) {
	first := HashUsable(crypto.SHA1)
	for range 5 {
		if HashUsable(crypto.SHA1) != first {
			t.Fatal("HashUsable changed answer between calls")
		}
	}
}

// An unlinked digest is not usable, and asking must not panic. No file in
// this package (or its test files) imports crypto/md4, so crypto.MD4 is
// never registered in this test binary; the assertion pins that fact rather
// than skipping around it, so a future import that links MD4 fails this test
// instead of silently going untested.
func TestHashUsable_UnlinkedDigest(t *testing.T) {
	if HashUsable(crypto.MD4) {
		t.Fatal("crypto.MD4 is unexpectedly linked in this test binary; update this test for the newly available digest")
	}
}

// The KDF bridge must report exactly what the process can compute. This is the
// regression for the panic: X963 advertised SHA-1 and derived with it, which
// took the process down under GODEBUG=fips140=only.
func TestKDFBridge_ReportsOnlyUsableHashes(t *testing.T) {
	for name, bridge := range kdfBridges {
		for hashName, h := range bridge.hashes {
			got, ok := bridge.hash(hashName)
			if !ok {
				continue
			}
			if got != h {
				t.Errorf("%v/%s resolved to %v, want %v", name, hashName, got, h)
			}
			if !canHash(got) {
				t.Errorf("%v/%s reported %v as available, but hashing with it panics",
					name, hashName, got)
			}
		}
	}
}

// canHash reports whether h survives a real digest computation, independently
// of HashUsable so the test is not merely asserting the implementation against
// itself.
func canHash(h crypto.Hash) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	if !h.Available() {
		return false
	}
	d := h.New()
	d.Write([]byte{0})
	_ = d.Sum(nil)
	return true
}
