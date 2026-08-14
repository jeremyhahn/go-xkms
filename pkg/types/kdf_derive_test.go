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
	"bytes"
	"crypto"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/kdf"
)

// mustHex decodes a hex literal from a published test vector.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding test vector %q: %v", s, err)
	}
	return b
}

// TestDeriveFromKeyMaterialMatchesRFC5869 checks the function every backend's
// SymmetricKeyDeriver implementation funnels through against the published
// HKDF-SHA256 vectors in RFC 5869 Appendix A.
//
// These are the three SHA-256 cases (A.1, A.2, A.3). The SHA-1 cases (A.4-A.7)
// are deliberately omitted: prfKDFHashes holds the HMAC-based KDFs to a
// 256-bit digest floor, so SHA-1 is not a PRF this stack will select for HKDF,
// and pinning bytes for a configuration the service layer refuses would pin
// nothing anyone can reach.
func TestDeriveFromKeyMaterialMatchesRFC5869(t *testing.T) {
	tests := []struct {
		name string
		ikm  string
		salt string
		info string
		okm  string
	}{
		{
			name: "RFC 5869 A.1 basic case with SHA-256",
			ikm:  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt: "000102030405060708090a0b0c",
			info: "f0f1f2f3f4f5f6f7f8f9",
			okm: "3cb25f25faacd57a90434f64d0362f2a" +
				"2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
				"34007208d5b887185865",
		},
		{
			name: "RFC 5869 A.2 longer inputs and outputs with SHA-256",
			ikm: "000102030405060708090a0b0c0d0e0f" +
				"101112131415161718191a1b1c1d1e1f" +
				"202122232425262728292a2b2c2d2e2f" +
				"303132333435363738393a3b3c3d3e3f" +
				"404142434445464748494a4b4c4d4e4f",
			salt: "606162636465666768696a6b6c6d6e6f" +
				"707172737475767778797a7b7c7d7e7f" +
				"808182838485868788898a8b8c8d8e8f" +
				"909192939495969798999a9b9c9d9e9f" +
				"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
			info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
				"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
				"d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
				"e0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
				"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			okm: "b11e398dc80327a1c8e7f78c596a4934" +
				"4f012eda2d4efad8a050cc4c19afa97c" +
				"59045a99cac7827271cb41c65e590e09" +
				"da3275600c2f09b8367793a9aca3db71" +
				"cc30c58179ec3e87c14c01d5c1f3434f" +
				"1d87",
		},
		{
			name: "RFC 5869 A.3 zero-length salt and info with SHA-256",
			ikm:  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt: "",
			info: "",
			okm: "8da4e775a563c18f715f802a063c5a31" +
				"b8a11f5c5ee1879ec3454e5f3c738d2d" +
				"9d201395faa4b61a96c8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := mustHex(t, tt.okm)

			got, err := DeriveFromKeyMaterial(mustHex(t, tt.ikm), &kdf.KDFParams{
				Algorithm: kdf.AlgorithmHKDF,
				Hash:      crypto.SHA256,
				Salt:      mustHex(t, tt.salt),
				Info:      mustHex(t, tt.info),
				KeyLength: len(want),
			})
			if err != nil {
				t.Fatalf("DeriveFromKeyMaterial: %v", err)
			}

			if !bytes.Equal(got, want) {
				t.Fatalf("derived key does not match the published vector:\n  got  %x\n  want %x", got, want)
			}
		})
	}
}

// TestDeriveFromKeyMaterialMatchesGolangHKDF cross-checks the same function
// against golang.org/x/crypto/hkdf over inputs that are not published vectors.
//
// The published vectors pin three fixed points; this pins the whole mapping of
// salt and info onto the construction, which is what a backend derivation
// actually varies.
func TestDeriveFromKeyMaterialMatchesGolangHKDF(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x9E}, 32)
	salt := []byte("go-xkms/types/kdf/salt")
	info := []byte("go-xkms/types/kdf/info")

	got, err := DeriveFromKeyMaterial(ikm, &kdf.KDFParams{
		Algorithm: kdf.AlgorithmHKDF,
		Hash:      crypto.SHA256,
		Salt:      salt,
		Info:      info,
		KeyLength: 48,
	})
	if err != nil {
		t.Fatalf("DeriveFromKeyMaterial: %v", err)
	}

	want := make([]byte, 48)
	if _, err := io.ReadFull(hkdf.New(crypto.SHA256.New, ikm, salt, info), want); err != nil {
		t.Fatalf("computing the HKDF oracle: %v", err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("derived key does not match RFC 5869 HKDF-SHA256 over the same inputs:\n  got  %x\n  want %x", got, want)
	}
}

// TestDeriveFromKeyMaterialSeparatesInputs is the assertion that survives even
// when no oracle is available: each input the caller varies must change the
// output.
//
// The key material case is the one that matters most here. Two different base
// keys derived under identical salt and info must not collide, or the key the
// caller gets is not a function of the key they named — which is exactly the
// failure mode of deriving from a key's label instead of its material.
func TestDeriveFromKeyMaterialSeparatesInputs(t *testing.T) {
	base := &kdf.KDFParams{
		Algorithm: kdf.AlgorithmHKDF,
		Hash:      crypto.SHA256,
		Salt:      []byte("constant-salt"),
		Info:      []byte("constant-info"),
		KeyLength: 32,
	}

	derive := func(t *testing.T, ikm []byte, p kdf.KDFParams) []byte {
		t.Helper()
		out, err := DeriveFromKeyMaterial(ikm, &p)
		if err != nil {
			t.Fatalf("DeriveFromKeyMaterial: %v", err)
		}
		return out
	}

	first := derive(t, bytes.Repeat([]byte{0x01}, 32), *base)

	t.Run("different key material", func(t *testing.T) {
		second := derive(t, bytes.Repeat([]byte{0x02}, 32), *base)
		if bytes.Equal(first, second) {
			t.Fatalf("two different keys derived the same bytes (%x) under identical salt and info; "+
				"the derived key is not a function of the key it was derived from", first)
		}
	})

	t.Run("different salt only", func(t *testing.T) {
		p := *base
		p.Salt = []byte("a-different-salt")
		if bytes.Equal(first, derive(t, bytes.Repeat([]byte{0x01}, 32), p)) {
			t.Fatal("changing only the salt produced the same key; the salt contributes nothing " +
				"to the extract step, so rotating salts is not rotating keys")
		}
	})

	t.Run("different info only", func(t *testing.T) {
		p := *base
		p.Info = []byte("a-different-info")
		if bytes.Equal(first, derive(t, bytes.Repeat([]byte{0x01}, 32), p)) {
			t.Fatal("changing only the info produced the same key; every purpose an application " +
				"separates with the info string would share one key")
		}
	})
}

// TestDeriveFromKeyMaterialSP800108Modes proves all three SP 800-108r1 modes
// are reachable through this entry point and that each produces its own key.
//
// The byte-exact NIST CAVP vectors for counter, feedback and double-pipeline
// mode are pinned where the construction lives, in
// pkg/crypto/kdf/sp800108_cavp_vectors_test.go; duplicating them here would
// re-test the same code through one more call. What this function adds is that
// the mode selection actually reaches the adapter: a dispatch that collapsed
// two modes onto one adapter would derive a different key than the caller
// asked for and raise no error.
func TestDeriveFromKeyMaterialSP800108Modes(t *testing.T) {
	kdk := bytes.Repeat([]byte{0x4C}, 32)

	// 64 bytes is two SHA-256 iterations. One iteration is not enough to tell
	// counter mode from feedback mode apart — see the second sub-test.
	newParams := func(alg kdf.KDFAlgorithm) *kdf.KDFParams {
		p := &kdf.KDFParams{
			Algorithm: alg,
			Hash:      crypto.SHA256,
			Label:     []byte("purpose"),
			Context:   []byte("context"),
			KeyLength: 64,
		}
		if alg == kdf.AlgorithmSP800108Feedback {
			// K(0). It is feedback mode's own input and no other mode accepts
			// it; the adapter rejects an IV supplied to the others.
			p.IV = []byte("feedback-initial-value")
		}
		return p
	}

	t.Run("each mode derives its own key", func(t *testing.T) {
		outputs := make(map[kdf.KDFAlgorithm][]byte)
		for _, alg := range []kdf.KDFAlgorithm{
			kdf.AlgorithmSP800108Counter,
			kdf.AlgorithmSP800108Feedback,
			kdf.AlgorithmSP800108DoublePipeline,
		} {
			out, err := DeriveFromKeyMaterial(kdk, newParams(alg))
			if err != nil {
				t.Fatalf("DeriveFromKeyMaterial(%s): %v", alg, err)
			}
			if len(out) != 64 {
				t.Fatalf("%s derived %d bytes, want 64", alg, len(out))
			}
			outputs[alg] = out
		}

		for a, outA := range outputs {
			for b, outB := range outputs {
				if a >= b {
					continue
				}
				if bytes.Equal(outA, outB) {
					t.Fatalf("%s and %s derived identical keys from the same inputs; the mode is not "+
						"reaching the adapter, so a caller asking for one gets the other", a, b)
				}
			}
		}
	})

	t.Run("feedback with an empty IV and one iteration equals counter mode", func(t *testing.T) {
		// This is a property of SP 800-108r1, not a defect, and it is pinned so
		// that a future reader who trips over it does not "fix" the adapters.
		//
		// §4.2 defines feedback mode as K(0) = IV and
		// K(i) = PRF(K_IN, K(i-1) || [i] || Label || 0x00 || Context || [L]),
		// and allows IV to be the empty string. §4.1 defines counter mode as
		// K(i) = PRF(K_IN, [i] || Label || 0x00 || Context || [L]). With an
		// empty IV the two PRF inputs are byte-identical for i = 1, so a
		// single-iteration derivation must coincide. They diverge from the
		// second iteration onward, which is what the sub-test above exercises.
		params := func(alg kdf.KDFAlgorithm) *kdf.KDFParams {
			return &kdf.KDFParams{
				Algorithm: alg,
				Hash:      crypto.SHA256,
				Label:     []byte("purpose"),
				Context:   []byte("context"),
				KeyLength: 32,
			}
		}

		counter, err := DeriveFromKeyMaterial(kdk, params(kdf.AlgorithmSP800108Counter))
		if err != nil {
			t.Fatalf("counter mode: %v", err)
		}
		feedback, err := DeriveFromKeyMaterial(kdk, params(kdf.AlgorithmSP800108Feedback))
		if err != nil {
			t.Fatalf("feedback mode: %v", err)
		}

		if !bytes.Equal(counter, feedback) {
			t.Fatalf("feedback mode with an empty K(0) diverged from counter mode at the first "+
				"iteration; SP 800-108r1 §4.1 and §4.2 give both the same PRF input there:\n"+
				"  counter  %x\n  feedback %x", counter, feedback)
		}
	})
}

// TestDeriveFromKeyMaterialRejectsBadInput covers the refusals.
//
// Empty key material is the important one. Every construction here derives
// happily from zero bytes and returns a well-formed key that anyone can
// recompute, which is indistinguishable from success at every layer above.
func TestDeriveFromKeyMaterialRejectsBadInput(t *testing.T) {
	valid := &kdf.KDFParams{
		Algorithm: kdf.AlgorithmHKDF,
		Hash:      crypto.SHA256,
		KeyLength: 32,
	}

	t.Run("empty key material", func(t *testing.T) {
		_, err := DeriveFromKeyMaterial(nil, valid)
		if !errors.Is(err, ErrEmptyKeyMaterial) {
			t.Fatalf("got %v, want ErrEmptyKeyMaterial; deriving from zero bytes succeeds and "+
				"returns a key an attacker can recompute", err)
		}
	})

	t.Run("nil parameters", func(t *testing.T) {
		_, err := DeriveFromKeyMaterial([]byte("some key material"), nil)
		if !errors.Is(err, ErrUnsupportedKDFAlgorithm) {
			t.Fatalf("got %v, want ErrUnsupportedKDFAlgorithm", err)
		}
	})

	t.Run("algorithm with no implementation", func(t *testing.T) {
		_, err := DeriveFromKeyMaterial([]byte("some key material"), &kdf.KDFParams{
			Algorithm: kdf.KDFAlgorithm("NOT-A-KDF"),
			Hash:      crypto.SHA256,
			KeyLength: 32,
		})
		if !errors.Is(err, ErrUnsupportedKDFAlgorithm) {
			t.Fatalf("got %v, want ErrUnsupportedKDFAlgorithm", err)
		}
	})

	t.Run("password-based KDFs are not reachable here", func(t *testing.T) {
		// kdf.NewAdapter refuses PBKDF2 and Argon2 deliberately: their cost
		// parameters make them unsuitable for a key-derivation path that has
		// no way to carry them. A caller naming one must be told so, not
		// silently given an HKDF key.
		for _, alg := range []kdf.KDFAlgorithm{kdf.AlgorithmPBKDF2, kdf.AlgorithmArgon2id} {
			if _, err := DeriveFromKeyMaterial([]byte("some key material"), &kdf.KDFParams{
				Algorithm: alg,
				Hash:      crypto.SHA256,
				KeyLength: 32,
			}); !errors.Is(err, ErrUnsupportedKDFAlgorithm) {
				t.Errorf("%s: got %v, want ErrUnsupportedKDFAlgorithm", alg, err)
			}
		}
	})
}
