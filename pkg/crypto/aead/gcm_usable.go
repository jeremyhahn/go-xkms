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

package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"sync"
)

// arbitraryIVGCMUsable caches the probe. The FIPS posture is fixed when the
// process starts — GODEBUG=fips140 is read once by the runtime — so one
// answer holds for the life of the process.
var arbitraryIVGCMUsable = sync.OnceValue(probeArbitraryIVGCM)

// ArbitraryIVGCMUsable reports whether this process can construct and use an
// AES-GCM AEAD that takes an externally supplied IV — the construction NewGCM
// builds and every caller of it depends on.
//
// Under GODEBUG=fips140=only, Go's crypto/cipher refuses cipher.NewGCM and
// cipher.NewGCMWithTagSize outright ("use of GCM with arbitrary IVs is not
// allowed in FIPS 140-only mode"); under fips140=on the identical
// construction works. crypto/fips140.Enabled cannot separate the two modes —
// it reports true under both — and the standard library exports no predicate
// for the only mode, so the runtime is asked directly: the probe performs a
// throwaway construction and seal once and caches the answer. This is the
// same disposition types.HashUsable took for the digest form of this problem
// (#292, #303): probe the operation the caller is about to perform, because
// no static predicate agrees with the runtime in all three modes.
//
// The mechanism itself is FIPS-approved (SP 800-38D); what the only mode
// forbids is the IV arriving from outside the FIPS module boundary. A false
// return therefore means "this process cannot perform arbitrary-IV GCM", not
// "GCM is unapproved" — cipher.NewGCMWithRandomNonce keeps working, but it
// produces an incompatible ciphertext framing and cannot honour a
// caller-chosen IV, so it is not a substitute for the construction probed
// here.
func ArbitraryIVGCMUsable() bool {
	return arbitraryIVGCMUsable()
}

// probeArbitraryIVGCM performs a throwaway arbitrary-IV AES-GCM seal and
// reports whether the runtime permitted it.
//
// The seal is probed as well as the construction because the SHA-1 form of
// this defect showed a runtime may admit a constructor and refuse the
// operation (sha1.New succeeds where Write panics). Today crypto/cipher
// refuses at construction with an error; the recover guard converts a future
// panicking refusal into the same false rather than a crash.
func probeArbitraryIVGCM() (usable bool) {
	defer func() {
		if recover() != nil {
			usable = false
		}
	}()

	// The key value is irrelevant to the probe: the restriction being
	// measured attaches to the GCM construction, not to any particular key.
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		return false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return false
	}
	gcm.Seal(nil, make([]byte, gcm.NonceSize()), []byte{0}, nil)
	return true
}
