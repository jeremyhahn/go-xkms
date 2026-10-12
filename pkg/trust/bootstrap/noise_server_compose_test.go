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

import "testing"

// TestReExportsCompose is the consumer's-eye test this package did not have.
//
// go-quicbaas and go-trusted-platform reach the Noise_NK server through these
// re-exports and never through go-truststrap directly, so nothing inside this
// repository exercises the combination. The protected-memory migration changed
// NoiseStaticKey to a type the config cannot accept, and no build, test or lint
// here could see it — a consumer would have found it at their next bump.
func TestReExportsCompose(t *testing.T) {
	key, err := GenerateNoiseStaticKey()

	// A build that cannot run Noise has no Noise key to compose with, so the
	// contract to check there is the refusal itself. This is an assertion, not
	// a skip: "the generator quietly returns a key in a build with no X25519"
	// is a real regression, and it is the one this branch still catches.
	if !noiseRunnable(t) {
		if err == nil {
			key.Destroy()
			t.Fatal("a build that cannot run Noise must not return a Noise key")
		}
		return
	}

	if err != nil {
		t.Fatalf("GenerateNoiseStaticKey: %v", err)
	}
	defer key.Destroy()

	// Exactly what a consumer writes. If this stops compiling, the re-exports
	// have drifted apart again.
	cfg := &NoiseServerConfig{
		ListenAddr: "127.0.0.1:0",
		StaticKey:  key,
	}

	if got := cfg.StaticKey.PublicBytes(); len(got) == 0 {
		t.Fatal("the configured static key has no public half")
	}
}

// noiseRunnable reports whether this binary can run the Noise_NK suite. It is
// false in a FIPS build by either mechanism: the `fips` build tag, which
// compiles go-truststrap's X25519 out, and GOFIPS140 with
// GODEBUG=fips140=only, where crypto/ecdh refuses X25519 at run time.
func noiseRunnable(t *testing.T) bool {
	t.Helper()
	return EnsureSuiteAvailable(SuiteNoiseNK) == nil
}
