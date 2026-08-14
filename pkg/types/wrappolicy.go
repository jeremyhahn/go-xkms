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
	"crypto/fips140"
	"sort"
	"sync/atomic"
)

// legacyKeyWrapAlgorithms are the key-wrap constructions that authenticate
// nothing, mapped to the reason each is refused unless an operator opts in.
//
// All three are sanctioned by PKCS#11 v3.2 for C_WrapKey and C_UnwrapKey
// (section 6.10 for the AES-CBC pair, section 6.1 for CKM_RSA_PKCS), so
// refusing them is a deployment policy and not a conformance deviation. What
// they have in common is that the unwrapping side cannot tell a blob the
// wrapping side produced from a blob an attacker made up, and C_UnwrapKey is
// reachable remotely over every transport: gRPC, QUIC, MCP, the unix socket and
// REST. That turns each of them into an oracle in the classic sense.
//
// The measurements behind this table were taken against this codebase, not
// assumed from the literature:
//
//   - AES_CBC_PAD: 215 random 48-byte blobs were submitted before one unwrapped
//     without error, which is the ~1-in-256 rate a PKCS#7 last-byte check
//     predicts. That accept/reject bit is exactly Vaudenay's padding oracle,
//     and it recovers plaintext under the wrapping key one byte at a time.
//   - AES_CBC: no check at all. A random 48-byte blob unwrapped into 32 bytes
//     of key material with a nil error on the first try, so the "oracle" needs
//     no search: submit a ciphertext, receive its decryption as a new key.
//   - RSA_PKCS1_V1_5: the PKCS#1 v1.5 conformance check is the Bleichenbacher
//     oracle, and its Marvin refinement makes the timing side alone sufficient.
//
// The service already withholds every *additional* bit about why a blob was
// refused (see xkms.ErrUnwrapCiphertextRejected), which is as far as the
// diagnostics can be narrowed while the mechanism is still performed. The one
// remaining bit -- succeeded or not -- is the oracle's whole answer, so only
// refusing the mechanism closes it.
var legacyKeyWrapAlgorithms = map[KeyWrapAlgorithm]string{
	WrapRSAPKCS1v15: "PKCS#1 v1.5 encryption authenticates nothing and its conformance check is the Bleichenbacher/Marvin decryption oracle (RFC 8017 section 7.2.2)",
	WrapAESCBCPad:   "PKCS#7 unpadding authenticates nothing and its accept/reject answer is the Vaudenay padding oracle",
	WrapAESCBC:      "unpadded CBC authenticates nothing at all, so any blob unwraps into key material and an unwrap success is not evidence of anything",
}

// allowLegacyKeyWrap is the process-wide policy for the constructions in
// legacyKeyWrapAlgorithms, and it refuses by default on exactly the terms
// allowWeakHashes does:
//
//   - Absent configuration: refused. Each of these mechanisms turns
//     C_UnwrapKey — reachable over every transport with a caller-supplied blob
//     — into a decryption oracle, so refusing is the only safe default.
//   - crypto.allow_legacy_key_wrap: true: the operator opts in explicitly and
//     the composition root calls SetAllowLegacyKeyWrap. This is the documented
//     escape hatch for an application that requires one of them.
//   - FIPS mode: refused whatever the configuration says, because an
//     approved-mechanism boundary a YAML file could widen would not be a
//     boundary.
//
// It is an atomic rather than a mutex-guarded field for the same reason
// allowWeakHashes is: it is read on every wrap and unwrap and written at most
// once, at startup, before any request is served.
var allowLegacyKeyWrap atomic.Bool

// init seeds the refusing default. It is unconditional: the FIPS-mode check
// lives in SetAllowLegacyKeyWrap, which is the only way the policy can ever be
// loosened.
func init() {
	allowLegacyKeyWrap.Store(false)
}

// SetAllowLegacyKeyWrap applies the configured legacy key-wrap policy. The
// composition root calls it once with crypto.allow_legacy_key_wrap, before any
// request is served; tests use it to exercise both postures.
//
// In FIPS mode a request to re-admit RSA_PKCS1_V1_5, AES_CBC_PAD and AES_CBC
// is ignored, because the approved mechanism set is fixed by the validated
// module rather than by the caller. Tightening always takes effect.
//
// It deliberately does not re-admit RSAES_OAEP_SHA_1: OAEP has no legacy blobs
// to read in this codebase, so there is no interop argument for it, and it is
// refused unconditionally by ResolveOAEPHash and by the wrap mechanism table.
func SetAllowLegacyKeyWrap(allow bool) {
	if allow && fips140.Enabled() {
		return
	}
	allowLegacyKeyWrap.Store(allow)
}

// AllowLegacyKeyWrap reports whether the process-wide policy currently admits
// the unauthenticated key-wrap constructions.
func AllowLegacyKeyWrap() bool {
	return allowLegacyKeyWrap.Load()
}

// IsLegacyKeyWrapAlgorithm reports whether alg names one of the unauthenticated
// key-wrap constructions, independent of the current policy.
func IsLegacyKeyWrapAlgorithm(alg KeyWrapAlgorithm) bool {
	_, legacy := legacyKeyWrapAlgorithms[alg]
	return legacy
}

// LegacyKeyWrapReason returns the reason alg is gated, for the operator-facing
// refusal. The second result is false when alg is not gated at all.
func LegacyKeyWrapReason(alg KeyWrapAlgorithm) (string, bool) {
	reason, legacy := legacyKeyWrapAlgorithms[alg]
	return reason, legacy
}

// LegacyKeyWrapNames returns the canonical names of the gated constructions,
// sorted, for diagnostics and operator-facing messages.
func LegacyKeyWrapNames() []string {
	names := make([]string, 0, len(legacyKeyWrapAlgorithms))
	for alg := range legacyKeyWrapAlgorithms {
		names = append(names, string(alg))
	}
	sort.Strings(names)
	return names
}
