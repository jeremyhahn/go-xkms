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

package bootstrap

import (
	"errors"
	"fmt"
	"sync"

	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
	"github.com/jeremyhahn/go-truststrap/pkg/p256proto"
)

// Bootstrap suite identifiers, as they travel on the wire.
//
// The bootstrap listener speaks both handshakes and selects per connection on
// the suite byte in the client's first frame. These are re-exported from
// p256proto, which reserves both values precisely so the two suites cannot
// collide on the wire.
const (
	// SuiteNoiseNK is Noise_NK_25519_ChaChaPoly_SHA256. It mandates X25519 and
	// is therefore NOT FIPS-approved; it is unavailable in a `fips` build.
	SuiteNoiseNK = p256proto.SuiteNoiseNK

	// SuiteP256AESGCM is TSBOOT1_P256_AESGCM_SHA256, the approved suite. It is
	// available in every build.
	SuiteP256AESGCM = p256proto.SuiteP256AESGCM
)

// ErrSuiteUnavailable reports that this binary cannot run the named bootstrap
// suite. It is the sentinel to test with errors.Is; the wrapped error carries
// the reason from go-truststrap.
var ErrSuiteUnavailable = errors.New("bootstrap: suite unavailable in this build")

// noiseAvailability caches the one-time answer to "can this binary run the
// Noise suite", along with the reason when it cannot.
var noiseAvailability struct {
	once sync.Once
	err  error
}

// EnsureSuiteAvailable reports whether this binary can run the given bootstrap
// suite, returning a typed error naming the suite when it cannot.
//
// It exists so a deployment that cannot work fails while it is being
// CONFIGURED rather than at key generation or, worse, per connection at
// dispatch. go-trusted-platform#209 asks for exactly that: a FIPS build with no
// usable suite should say so once, actionably, at startup -- not construct a
// server that binds a listener and then refuses every handshake.
//
// # It asks the library, it does not consult a FIPS predicate
//
// The obvious implementation is `if fips.Compiled() { ... }`, and it is wrong
// for the reason recorded on the certstore thumbprint (go-xkms#212/#219): a
// FIPS predicate cannot answer "is this artifact FIPS-constrained".
// GODEBUG=fips140=off turns fips.Compiled() false on a GOFIPS140-built binary,
// so a guard written that way fails OPEN for exactly the artifacts the policy
// most cares about -- and a guard that cannot fire in its advertised case is
// itself the defect, because the next reader takes it for working.
//
// Availability here is instead DERIVED from go-truststrap, which is the only
// component entitled to answer it. Its Noise DH lives in a file built
// `//go:build fips`, whose entry points return ErrFIPSUnsupported, so the
// answer is a compile-time property of the binary. Attempting the operation and
// classifying the result reads that property directly and cannot disagree with
// the code that will actually run the handshake. If go-truststrap later
// supports Noise under some FIPS configuration, this answer changes with it,
// where a predicate restated here would quietly go stale.
//
// The probe generates and immediately destroys one key, once per process, and
// the result is cached.
func EnsureSuiteAvailable(suite byte) error {
	switch suite {
	case SuiteP256AESGCM:
		// P-256 with AES-GCM and SHA-256 is approved, so it is available in
		// every build. It is still probed rather than assumed, for the same
		// reason the Noise arm is: the library is the authority, not this
		// comment.
		key, err := p256proto.GenerateStaticKey()
		if err != nil {
			return fmt.Errorf("%w: TSBOOT1_P256_AESGCM_SHA256: %w", ErrSuiteUnavailable, err)
		}
		key.Destroy()
		return nil

	case SuiteNoiseNK:
		noiseAvailability.once.Do(func() {
			key, err := noiseproto.GenerateStaticKey()
			if err != nil {
				noiseAvailability.err = err
				return
			}
			key.Destroy()
		})
		if noiseAvailability.err != nil {
			return fmt.Errorf("%w: Noise_NK_25519_ChaChaPoly_SHA256 needs X25519, which SP 800-56A Rev. 3 does not approve; use SuiteP256AESGCM: %w",
				ErrSuiteUnavailable, noiseAvailability.err)
		}
		return nil

	default:
		return fmt.Errorf("%w: unknown suite 0x%02x", ErrSuiteUnavailable, suite)
	}
}
