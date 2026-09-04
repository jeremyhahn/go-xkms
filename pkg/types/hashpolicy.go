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
	"crypto/fips140"
	"sort"
	"sync"
	"sync/atomic"
)

// weakHashes are the digests whose collision resistance is broken, so a
// signature or certificate produced over one is forgeable: MD4 and MD5
// (practical chosen-prefix collisions), SHA-1 (SHAttered / shambles), the
// MD5+SHA1 concatenation TLS 1.1 and earlier used for the CertificateVerify
// digest, and RIPEMD-160, which has no current standards approval and a
// 160-bit digest.
//
// NIST SP 800-131A Rev. 2 disallows all of them for digital signature
// generation. That prohibition is scoped to *signature* use: the same
// document keeps SHA-1 acceptable for non-signature applications such as
// key derivation and HMAC, which is why the ANSI X9.63 / SP 800-56A
// concatenation KDFs in kdf.go accept SHA-1 unconditionally and are not
// governed by this set. This set governs the general-purpose hash tables —
// AvailableHashes and ParseHash — which feed the signing, certificate, and
// TPM attestation paths.
var weakHashes = map[crypto.Hash]struct{}{
	crypto.MD4:       {},
	crypto.MD5:       {},
	crypto.SHA1:      {},
	crypto.MD5SHA1:   {},
	crypto.RIPEMD160: {},
}

// allowWeakHashes is the process-wide weak-hash policy, and it refuses by
// default:
//
//   - Absent configuration (a library embedding xkms, a test, a daemon whose
//     YAML says nothing about it): the broken digests are refused. Secure by
//     default is the only safe default for a policy that decides whether this
//     process will produce a forgeable signature.
//   - crypto.allow_weak_hashes: true: the operator opts in explicitly, the
//     composition root calls SetAllowWeakHashes, and the digests resolve. This
//     is the documented legacy-interop and PKCS#11-conformance escape hatch —
//     a deployment that has to sign with SHA-1 says so, in writing, in its
//     configuration.
//   - FIPS mode: refused whatever the configuration says. FIPS 140-3 does not
//     approve these digests, and an approved-algorithm boundary that a YAML
//     file could widen would not be a boundary. SetAllowWeakHashes enforces
//     this, so the rule holds for every caller, not just the daemon.
//
// FIPS mode is selected by the Go toolchain, not by xkms configuration: build
// with GOFIPS140=<version> and/or run with GODEBUG=fips140=on|only. Refusing
// by default keeps the two consistent: the configuration can only ever move
// the policy within what the deployed binary already permits.
//
// Note that "refused" governs whether a weak digest is *performed*, not
// whether it is *advertised*. The PKCS#11 module still lists its SHA-1 and MD5
// mechanisms in C_GetMechanismList when this policy refuses them, exactly as it
// does under FIPS mode, so a caller learns the mechanism exists and is told it
// is unavailable rather than being lied to about the module's shape.
//
// It is an atomic rather than a mutex-guarded field because it is read on
// every hash lookup and written at most once, at startup, before any request
// is served.
var allowWeakHashes atomic.Bool

// init seeds the refusing default. It is unconditional: the FIPS-mode check
// lives in SetAllowWeakHashes, which is the only way the policy can ever be
// loosened.
func init() {
	allowWeakHashes.Store(false)
}

// SetAllowWeakHashes applies the configured weak-hash policy. The composition
// root calls it once with crypto.allow_weak_hashes, before any request is
// served; tests use it to exercise both postures.
//
// In FIPS mode a request to admit the broken digests is ignored, because the
// approved-algorithm set is fixed by the validated module rather than by the
// caller. Tightening always takes effect.
func SetAllowWeakHashes(allow bool) {
	if allow && fips140.Enabled() {
		return
	}
	allowWeakHashes.Store(allow)
}

// AllowWeakHashes reports whether the process-wide weak-hash policy currently
// admits the collision-broken digests.
func AllowWeakHashes() bool {
	return allowWeakHashes.Load()
}

// FIPSMode reports whether the process is running under the Go FIPS 140-3
// validated module (GOFIPS140 build selector and/or GODEBUG=fips140=on|only).
func FIPSMode() bool {
	return fips140.Enabled()
}

// IsWeakHash reports whether h is one of the digests whose collision
// resistance is broken, independent of the current policy.
func IsWeakHash(h crypto.Hash) bool {
	_, weak := weakHashes[h]
	return weak
}

// IsWeakHashName reports whether name resolves to one of the collision-broken
// digests, independent of the current weak-hash policy.
//
// It exists because ParseHash deliberately collapses "refused by policy" and
// "not a hash at all" into a single zero result, which is right for callers
// that only need to know whether they can hash — and wrong for a caller that
// must refuse a specific weak digest with a specific error whatever the policy
// says. RSA-OAEP is the case in point: SHA-1 OAEP is refused unconditionally
// here, and the caller has to be able to say so rather than report the name as
// unrecognized.
func IsWeakHashName(name string) bool {
	h, ok := normalizedHashNames[normalizeHashName(name)]
	return ok && IsWeakHash(h)
}

// WeakHashNames returns the canonical names of the weak digests, sorted, for
// diagnostics and operator-facing messages.
func WeakHashNames() []string {
	names := make([]string, 0, len(weakHashes))
	for h := range weakHashes {
		names = append(names, h.String())
	}
	sort.Strings(names)
	return names
}

// hashPermitted reports whether h may be handed to a caller: its
// implementation must be linked into this binary (crypto.Hash.New panics
// rather than erroring for an unlinked hash) and it must either be
// collision-resistant or explicitly re-admitted by the weak-hash policy.
func hashPermitted(h crypto.Hash) bool {
	if !h.Available() {
		return false
	}
	return !IsWeakHash(h) || allowWeakHashes.Load()
}

// hashUsability caches, per crypto.Hash, whether this process can actually
// compute a digest with it.
var hashUsability sync.Map // crypto.Hash -> bool

// HashUsable reports whether h can compute a digest in THIS process, as
// opposed to merely being linked into the binary.
//
// # Why crypto.Hash.Available is not enough
//
// Available reports linkage. Under GODEBUG=fips140=only the Go standard
// library keeps a refused digest linked and lets New() succeed, then PANICS on
// the first Write. Measured on go1.26.7:
//
//	mode            fips140.Enabled()  SHA1.Available()  SHA-1 Write+Sum
//	(none)          false              true              ok
//	fips140=on      true               true              ok
//	fips140=only    true               true              PANIC
//
// So a caller that checks Available and then hashes still dies, which is how
// the KDF bridge took the process down for a caller who named SHA-1
// (go-xkms#292).
//
// # Why it is not a FIPS predicate either
//
// The table above is also why this cannot be `if fips140.Enabled()`. Enabled
// is true under BOTH fips140=on and fips140=only, but SHA-1 works under `on`.
// Gating on it would withdraw a digest that the process can perfectly well
// compute -- failing closed rather than open, but still reporting a capability
// the runtime does not have. And the fail-OPEN direction is worse and already
// recorded: GODEBUG=fips140=off turns Enabled false on a GOFIPS140-built
// binary (#219).
//
// There is no exported predicate for "fips140=only", so the only answer that
// is right in all three modes is to ask the runtime directly.
//
// # How
//
// It hashes one byte behind a recover, once per crypto.Hash, and caches the
// answer. The probe is the same operation the caller is about to perform, so
// it cannot disagree with it -- and it keeps working if the standard library
// later refuses a different digest, where a hardcoded list would go stale.
func HashUsable(h crypto.Hash) bool {
	if !h.Available() {
		return false
	}
	if cached, ok := hashUsability.Load(h); ok {
		return cached.(bool)
	}
	usable := probeHash(h)
	hashUsability.Store(h, usable)
	return usable
}

// probeHash reports whether h survives a real digest computation.
func probeHash(h crypto.Hash) (usable bool) {
	defer func() {
		if recover() != nil {
			usable = false
		}
	}()

	digest := h.New()
	// The panic is on Write, not New, so the probe has to do both.
	digest.Write([]byte{0})
	_ = digest.Sum(nil)
	return true
}
