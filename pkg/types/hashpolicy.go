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
