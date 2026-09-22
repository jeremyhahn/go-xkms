// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package server

import (
	"github.com/awnumar/memguard"

	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
	"github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// The raw memguard import above is forced, not a convenience:
// bootstrap.DecodeP256StaticKey and bootstrap.EncodeP256StaticKey
// (go-truststrap v0.4.0-alpha's p256proto.{Decode,Encode}StaticKey) take a
// *memguard.LockedBuffer directly, and secure.Buffer wraps its LockedBuffer
// in an unexported field with no accessor -- correctly, since exposing it
// would hand back the handle the boundary exists to withhold. Filed as
// jeremyhahn/go-truststrap#60; secure-analyzer exemption until it lands.
//
// This is the ONLY file in the package that imports memguard, and
// decodeP256StaticKey/encodeP256StaticKeyHex are the only two functions that
// need to: every other P-256 (and all Noise) custody code in
// bootstrap_key_custody.go works with sdk/go/secure buffers and plain []byte
// it wipes with secure.Wipe, and calls into these two helpers for the one
// step go-truststrap's API forces through raw memguard.

// Suite resolution for the bootstrap listener.
//
// The listener speaks both handshake suites and dispatches per connection on
// the suite byte in the client's first frame, so it needs a static key for
// each suite it intends to offer. Which suites it CAN offer is a property of
// the binary: Noise_NK mandates X25519, which SP 800-56A Rev. 3 does not
// approve, so a FIPS build cannot run it and go-truststrap refuses it at key
// generation.
//
// Before this, the listener loaded the Noise key unconditionally and gave up
// when that failed. In a FIPS build it therefore bound no listener at all --
// not a refused handshake, but no bootstrap service on the port -- even though
// the approved suite was available in the same binary and needed only a key.
// That is go-xkms#269 and go-trusted-platform#209.
//
// Availability is resolved HERE, while the listener is being configured, and
// not at key generation inside the accept loop: an operator learns once, at
// startup, that their build can serve no suite, instead of learning it from
// every client that later fails to connect.

// ensureSuiteAvailable resolves whether this binary can run a suite. It is a
// variable for the same reason go-truststrap makes its own DH helpers
// variables: the "no suite at all" path is reachable in a real deployment
// (a FIPS build whose approved suite the library also refused) but not
// reproducible from a test binary, whose build tags are fixed at compile time.
// Injecting the refusal is the only way to cover the branch in either build.
var ensureSuiteAvailable = bootstrap.EnsureSuiteAvailable

// bootstrapKeys holds the static keys the bootstrap listener offers. Either
// field may be nil, meaning that suite is not offered; loadBootstrapKeys
// guarantees at least one is set.
//
// Both keys hold their private scalar in protected memory outside the Go heap,
// and both are aliased in place by every handshake the listener runs. Ownership
// therefore follows the same rule as the Noise key always has: it moves to the
// Server when the started listener is published, and only a confirmed drain
// permits destroying them.
type bootstrapKeys struct {
	noise *bootstrap.NoiseStaticKey
	p256  *bootstrap.P256StaticKey
}

// destroy releases both keys' protected pages. It is safe on a nil receiver
// and on nil fields, so an early return may call it unconditionally.
func (k *bootstrapKeys) destroy() {
	if k == nil {
		return
	}
	k.noise.Destroy()
	k.p256.Destroy()
}

// loadBootstrapKeys resolves which handshake suites this binary can offer and
// loads a static key for each.
//
// It distinguishes two failures that must not be conflated:
//
//   - A suite UNAVAILABLE in this build is skipped. That is the expected state
//     of Noise_NK under FIPS and is not an operator error.
//   - A suite that is available but whose CONFIGURED key will not load is a
//     hard failure, returned as-is. Falling through to the other suite would
//     silently downgrade a misconfigured deployment to a wire every one of its
//     existing clients would fail to speak, and the operator would see only a
//     working listener.
//
// When no suite survives, the result is ErrNoBootstrapSuite carrying the
// reason each one was rejected.
func (s *Server) loadBootstrapKeys() (*bootstrapKeys, error) {
	keys := &bootstrapKeys{}

	noiseUnavailable := ensureSuiteAvailable(bootstrap.SuiteNoiseNK)
	if noiseUnavailable == nil {
		key, err := s.loadNoiseStaticKey()
		if err != nil {
			return nil, err
		}
		keys.noise = key
	} else {
		s.logger.Info("bootstrap: Noise_NK is unavailable in this build; offering the approved suite only",
			"reason", noiseUnavailable)
	}

	p256Unavailable := ensureSuiteAvailable(bootstrap.SuiteP256AESGCM)
	if p256Unavailable == nil {
		key, err := s.loadP256StaticKey()
		if err != nil {
			keys.destroy()
			return nil, err
		}
		keys.p256 = key
	}

	if keys.noise == nil && keys.p256 == nil {
		return nil, &ErrNoBootstrapSuite{Noise: noiseUnavailable, P256: p256Unavailable}
	}

	return keys, nil
}

// loadP256StaticKey (custody for the P-256 bootstrap static key,
// go-xkms#35) lives in bootstrap_key_custody.go, alongside its Noise
// counterpart.

// decodeP256StaticKey moves a hex-encoded private scalar into protected memory
// and decodes it there, so the sensitive hex form never sits in an ordinary
// heap slice for longer than the caller's own buffer.
//
// The length is checked before the buffer is built rather than left to the
// decoder, so memguard is never asked to size a protected buffer from input
// this function has not looked at.
//
// Note what this check CANNOT catch: a Curve25519 scalar and a P-256 scalar are
// both 32 bytes, so both encode to exactly this many hex characters. A Noise key
// pasted into the P-256 field is the right length and decodes to a valid, wrong
// key -- the server then serves a responder key no client has pinned. Nothing at
// this layer can distinguish the two; use `xkmsctl bootstrap noise show-p256-key`
// to confirm the public key matches what clients were given.
func decodeP256StaticKey(hexKey []byte) (*bootstrap.P256StaticKey, error) {
	if len(hexKey) != bootstrap.P256HexKeySize {
		return nil, &ErrP256KeyLength{Got: len(hexKey), Want: bootstrap.P256HexKeySize}
	}

	// NewBufferFromBytes wipes hexKey as it copies, which is why the callers'
	// own deferred wipe is a backstop for the untrimmed remainder rather than
	// the primary erasure.
	buf := memguard.NewBufferFromBytes(hexKey)
	defer buf.Destroy()

	return bootstrap.DecodeP256StaticKey(buf)
}

// encodeP256StaticKeyHex is decodeP256StaticKey's inverse: it hex-encodes
// key's private scalar and hands the result back as a *secure.Buffer, so
// bootstrap_key_custody.go's sealing/persisting paths (go-xkms#35) can reach
// go-truststrap's P-256 encode step without importing memguard themselves.
//
// The memguard.LockedBuffer bootstrap.EncodeP256StaticKey writes into is
// destroyed before this function returns; the hex bytes it produced are
// copied into the returned secure.Buffer (which itself wipes and copies
// under the hood) rather than handed back as that LockedBuffer, for the same
// reason decodeP256StaticKey never hands one to its own caller -- the
// LockedBuffer handle is exactly what the secure-analyzer exemption above
// stays scoped to this file for. The caller owns the returned buffer and
// must Destroy it.
func encodeP256StaticKeyHex(key *bootstrap.P256StaticKey) (*secure.Buffer, error) {
	memBuf := memguard.NewBuffer(bootstrap.P256HexKeySize)
	defer memBuf.Destroy()

	if err := bootstrap.EncodeP256StaticKey(memBuf, key); err != nil {
		return nil, err
	}

	// NewBufferFromBytes copies memBuf.Bytes() into the new secure.Buffer and
	// wipes the source in place; the deferred memBuf.Destroy() above then
	// unmaps the (already wiped) protected pages.
	return secure.NewBufferFromBytes(memBuf.Bytes())
}
