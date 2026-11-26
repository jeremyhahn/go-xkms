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

package aead

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"os"
	"os/exec"
	"testing"
)

// TestNewGCMForFreshEncrypt_AgreesWithArbitraryIVGCMUsable exercises every
// (tagSize, callerNonce) combination against whatever this process actually
// is -- the default process, GODEBUG=fips140=on, or GODEBUG=fips140=only --
// so it is meaningful, and its assertions differ, however the test binary is
// invoked, rather than skipping when the process is not the one combination
// it was written for. When this process can construct arbitrary-IV GCM
// (default and fips140=on), every combination is the classic NewGCM
// construction. When it cannot (fips140=only), see
// TestArbitraryIVGCMUnavailable_UnderFIPSOnly for the substitution and
// fail-closed cases this process cannot exercise directly.
func TestNewGCMForFreshEncrypt_AgreesWithArbitraryIVGCMUsable(t *testing.T) {
	usable := ArbitraryIVGCMUsable()

	for _, tt := range []struct {
		name        string
		tagSize     int
		callerNonce bool
	}{
		{"full tag, generated nonce", 0, false},
		{"full tag, caller nonce", 16, true},
		{"truncated tag, generated nonce", 12, false},
		{"truncated tag, caller nonce", 12, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			gcm, randomNonce, err := NewGCMForFreshEncrypt(testBlock(t), tt.tagSize, tt.callerNonce)

			if usable {
				if err != nil {
					t.Fatalf("NewGCMForFreshEncrypt: %v", err)
				}
				if randomNonce {
					t.Fatalf("randomNonce = true, want false: this process can construct arbitrary-IV GCM")
				}
				if gcm.NonceSize() != 12 {
					t.Fatalf("NonceSize() = %d, want 12 (classic GCM)", gcm.NonceSize())
				}
				return
			}

			// fips140=only: only the full-tag, generated-nonce combination
			// has a substitute construction.
			if tt.tagSize == 0 && !tt.callerNonce {
				if err != nil {
					t.Fatalf("NewGCMForFreshEncrypt: %v", err)
				}
				if !randomNonce {
					t.Fatal("randomNonce = false, want true: fips140=only substitutes NewGCMWithRandomNonce here")
				}
				if gcm.NonceSize() != 0 {
					t.Fatalf("NonceSize() = %d, want 0 (cipher.NewGCMWithRandomNonce)", gcm.NonceSize())
				}
				return
			}
			if !errors.Is(err, ErrArbitraryIVGCMUnavailable) {
				t.Fatalf("NewGCMForFreshEncrypt error = %v, want ErrArbitraryIVGCMUnavailable", err)
			}
		})
	}
}

// TestNewGCMForDecrypt_ExplicitModeAgreesWithArbitraryIVGCMUsable pins the
// non-random path of NewGCMForDecrypt against whatever this process actually
// is: when it can construct arbitrary-IV GCM, a legacy explicit-nonce
// ciphertext (the only kind this format produced before FIPS 140-only
// support) opens exactly as NewGCM alone would open it; when it cannot
// (fips140=only), the construction itself is refused, which is the
// fail-closed behavior TestArbitraryIVGCMUnavailable_UnderFIPSOnly pins
// directly.
func TestNewGCMForDecrypt_ExplicitModeAgreesWithArbitraryIVGCMUsable(t *testing.T) {
	block := testBlock(t)
	nonce := make([]byte, 12)
	plaintext := []byte("legacy explicit-nonce ciphertext")
	aad := []byte("aad")

	opener, err := NewGCMForDecrypt(block, 0, false)

	if !ArbitraryIVGCMUsable() {
		if !errors.Is(err, ErrArbitraryIVGCMUnavailable) {
			t.Fatalf("NewGCMForDecrypt(randomNonce=false) error = %v, want ErrArbitraryIVGCMUnavailable", err)
		}
		return
	}
	if err != nil {
		t.Fatalf("NewGCMForDecrypt: %v", err)
	}

	sealer, err := NewGCM(block, 0)
	if err != nil {
		t.Fatalf("NewGCM: %v", err)
	}
	sealed := sealer.Seal(nil, nonce, plaintext, aad)

	got, err := opener.Open(nil, nonce, sealed, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext = %q, want %q", got, plaintext)
	}
}

// TestNewGCMForDecrypt_RandomNonceRejectsTruncatedTag pins that a
// ciphertext claiming randomNonce with anything but the full tag is
// refused: cipher.NewGCMWithRandomNonce has no truncated-tag construction,
// so that combination cannot be a ciphertext this process (or any version
// of it) ever produced.
func TestNewGCMForDecrypt_RandomNonceRejectsTruncatedTag(t *testing.T) {
	_, err := NewGCMForDecrypt(testBlock(t), 12, true)
	if !errors.Is(err, ErrInvalidGCMTagSize) {
		t.Fatalf("NewGCMForDecrypt(tagSize=12, randomNonce=true) error = %v, want ErrInvalidGCMTagSize", err)
	}
}

// forceArbitraryIVGCMUnavailable makes ArbitraryIVGCMUsable report false for
// the rest of the test, as it does in a GODEBUG=fips140=only process, so the
// FIPS-only dispatch counts toward this process's coverage. The subprocess
// test above is still what proves the probe itself under fips140=only.
func forceArbitraryIVGCMUnavailable(t *testing.T) {
	t.Helper()
	saved := arbitraryIVGCMUsable
	arbitraryIVGCMUsable = func() bool { return false }
	t.Cleanup(func() { arbitraryIVGCMUsable = saved })
}

func TestNewGCMForFreshEncrypt_ArbitraryIVUnavailable(t *testing.T) {
	tests := []struct {
		name        string
		tagSize     int
		callerNonce bool
		wantErr     error
	}{
		{name: "default tag", tagSize: 0},
		{name: "explicit full tag", tagSize: GCMFullTagSize},
		{name: "caller nonce", tagSize: 0, callerNonce: true, wantErr: ErrArbitraryIVGCMUnavailable},
		{name: "truncated tag", tagSize: 12, wantErr: ErrArbitraryIVGCMUnavailable},
		{name: "invalid tag", tagSize: 11, wantErr: ErrInvalidGCMTagSize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			forceArbitraryIVGCMUnavailable(t)
			block := testBlock(t)

			gcm, randomNonce, err := NewGCMForFreshEncrypt(block, tt.tagSize, tt.callerNonce)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("error = %v, want %v", err, tt.wantErr)
				}
				if gcm != nil || randomNonce {
					t.Fatalf("got gcm=%v randomNonce=%t alongside the error, want nil and false", gcm, randomNonce)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewGCMForFreshEncrypt: %v", err)
			}
			if !randomNonce || gcm.NonceSize() != 0 {
				t.Fatalf("randomNonce=%t NonceSize=%d, want true and 0", randomNonce, gcm.NonceSize())
			}

			plaintext := []byte("fresh encryption")
			opener, err := NewGCMForDecrypt(block, tt.tagSize, true)
			if err != nil {
				t.Fatalf("NewGCMForDecrypt(randomNonce=true): %v", err)
			}
			got, err := opener.Open(nil, nil, gcm.Seal(nil, nil, plaintext, nil), nil)
			if err != nil || !bytes.Equal(got, plaintext) {
				t.Fatalf("round trip = %q, %v; want %q", got, err, plaintext)
			}
		})
	}
}

func TestNewGCMForDecrypt_Refusals(t *testing.T) {
	tests := []struct {
		name        string
		unavailable bool
		tagSize     int
		randomNonce bool
		wantErr     error
	}{
		{name: "random nonce invalid tag", tagSize: 11, randomNonce: true, wantErr: ErrInvalidGCMTagSize},
		{name: "explicit nonce without arbitrary-IV GCM", unavailable: true, randomNonce: false, wantErr: ErrArbitraryIVGCMUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.unavailable {
				forceArbitraryIVGCMUnavailable(t)
			}
			gcm, err := NewGCMForDecrypt(testBlock(t), tt.tagSize, tt.randomNonce)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if gcm != nil {
				t.Fatalf("got gcm %v alongside the error, want nil", gcm)
			}
		})
	}
}

// TestSplitJoinGCMWithRandomNonce_RoundTrip pins that Split and Join are
// inverses across the field boundaries EncryptedData actually stores into
// (Nonce, Ciphertext, Tag), for both empty and non-empty plaintext.
func TestSplitJoinGCMWithRandomNonce_RoundTrip(t *testing.T) {
	block := testBlock(t)
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		t.Fatalf("cipher.NewGCMWithRandomNonce: %v", err)
	}

	for _, plaintext := range [][]byte{[]byte("split and join across the AEAD boundary"), {}} {
		sealed := gcm.Seal(nil, nil, plaintext, []byte("aad"))

		nonce, ciphertext, tag, err := SplitGCMWithRandomNonce(sealed)
		if err != nil {
			t.Fatalf("SplitGCMWithRandomNonce: %v", err)
		}
		if len(nonce) != GCMRandomNonceSize {
			t.Fatalf("nonce length = %d, want %d", len(nonce), GCMRandomNonceSize)
		}
		if len(tag) != GCMFullTagSize {
			t.Fatalf("tag length = %d, want %d", len(tag), GCMFullTagSize)
		}
		if len(ciphertext) != len(plaintext) {
			t.Fatalf("ciphertext length = %d, want %d (plaintext length, since GCM does not pad)", len(ciphertext), len(plaintext))
		}

		joined := JoinGCMWithRandomNonce(nonce, ciphertext, tag)
		if !bytes.Equal(joined, sealed) {
			t.Fatalf("JoinGCMWithRandomNonce did not reproduce Seal's output:\ngot  %x\nwant %x", joined, sealed)
		}

		got, err := gcm.Open(nil, nil, joined, []byte("aad"))
		if err != nil {
			t.Fatalf("Open(joined): %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("plaintext = %q, want %q", got, plaintext)
		}
	}
}

// TestSplitGCMWithRandomNonce_RefusesShortInput is the bad-input case: an
// input shorter than nonce+tag overhead cannot have come from
// cipher.NewGCMWithRandomNonce's Seal, whatever produced it.
func TestSplitGCMWithRandomNonce_RefusesShortInput(t *testing.T) {
	for _, n := range []int{0, 1, GCMRandomNonceSize, GCMRandomNonceSize + GCMFullTagSize - 1} {
		if _, _, _, err := SplitGCMWithRandomNonce(make([]byte, n)); err == nil {
			t.Fatalf("SplitGCMWithRandomNonce(%d bytes) succeeded, want an error", n)
		}
	}
}

// TestArbitraryIVGCMUnavailable_UnderFIPSOnly re-execs the test binary under
// GODEBUG=fips140=only, the one mode where NewGCMForFreshEncrypt and
// NewGCMForDecrypt must diverge from NewGCM, to exercise the substitution,
// the fail-closed refusals, and the Split/Join round trip in the process
// state where they actually matter. See
// TestArbitraryIVGCMUsable_UnderFIPSModes in gcm_usable_test.go for why this
// has to be a subprocess rather than an in-process toggle.
func TestArbitraryIVGCMUnavailable_UnderFIPSOnly(t *testing.T) {
	if mode := os.Getenv("XKMS_FIPS_RANDOM_NONCE_SUBPROCESS"); mode != "" {
		if ArbitraryIVGCMUsable() {
			t.Fatal("ArbitraryIVGCMUsable() = true under fips140=only")
		}

		block := testBlock(t)
		plaintext := []byte("fresh encryption under fips140=only")
		aad := []byte("aad")

		// The default Encrypt path: no caller nonce, full tag -- the
		// combination NewGCMWithRandomNonce supports -- must switch
		// construction and report randomNonce true.
		gcm, randomNonce, err := NewGCMForFreshEncrypt(block, 0, false)
		if err != nil {
			t.Fatalf("NewGCMForFreshEncrypt(tagSize=0, callerNonce=false): %v", err)
		}
		if !randomNonce {
			t.Fatal("randomNonce = false, want true under fips140=only with no caller nonce")
		}
		if gcm.NonceSize() != 0 {
			t.Fatalf("NonceSize() = %d, want 0 (cipher.NewGCMWithRandomNonce)", gcm.NonceSize())
		}

		sealed := gcm.Seal(nil, nil, plaintext, aad)
		nonce, ciphertext, tag, err := SplitGCMWithRandomNonce(sealed)
		if err != nil {
			t.Fatalf("SplitGCMWithRandomNonce: %v", err)
		}

		// The ciphertext round-trips through NewGCMForDecrypt exactly as
		// EncryptedData would carry it: Nonce, Ciphertext and Tag stored
		// separately, GCMNonceMode recording randomNonce true.
		opener, err := NewGCMForDecrypt(block, 0, true)
		if err != nil {
			t.Fatalf("NewGCMForDecrypt(randomNonce=true): %v", err)
		}
		got, err := opener.Open(nil, nil, JoinGCMWithRandomNonce(nonce, ciphertext, tag), aad)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("plaintext = %q, want %q", got, plaintext)
		}

		// A caller-supplied nonce fails closed rather than relaying the
		// runtime's own refusal from inside NewGCM.
		if _, _, err := NewGCMForFreshEncrypt(block, 0, true); !errors.Is(err, ErrArbitraryIVGCMUnavailable) {
			t.Fatalf("NewGCMForFreshEncrypt(callerNonce=true) error = %v, want ErrArbitraryIVGCMUnavailable", err)
		}

		// A truncated tag fails closed too: NewGCMWithRandomNonce has no
		// truncated-tag construction.
		if _, _, err := NewGCMForFreshEncrypt(block, 12, false); !errors.Is(err, ErrArbitraryIVGCMUnavailable) {
			t.Fatalf("NewGCMForFreshEncrypt(tagSize=12) error = %v, want ErrArbitraryIVGCMUnavailable", err)
		}

		// A legacy explicit-nonce ciphertext cannot be opened either: this
		// process cannot construct the arbitrary-IV GCM that would open it.
		if _, err := NewGCMForDecrypt(block, 0, false); !errors.Is(err, ErrArbitraryIVGCMUnavailable) {
			t.Fatalf("NewGCMForDecrypt(randomNonce=false) error = %v, want ErrArbitraryIVGCMUnavailable", err)
		}

		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestArbitraryIVGCMUnavailable_UnderFIPSOnly$", "-test.v")
	cmd.Env = append(os.Environ(), "XKMS_FIPS_RANDOM_NONCE_SUBPROCESS=only", "GODEBUG=fips140=only")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fips140=only subprocess failed: %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte("PASS")) {
		t.Fatalf("fips140=only subprocess did not pass:\n%s", out)
	}
	if bytes.Contains(out, []byte("panic:")) {
		t.Fatalf("fips140=only subprocess panicked:\n%s", out)
	}
}
