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

package wrapping

import (
	"bytes"
	"errors"
	"testing"
)

// rfc5649Vectors are the two worked examples in RFC 5649 section 6, which is
// the only oracle for AES-KWP that is independent of this implementation: it
// fixes the Alternative Initial Value, the padding and the wrapping rounds
// against a published expected ciphertext, so a wrap that is self-consistent
// but wrong cannot pass.
//
// The first wraps 20 octets (not a multiple of 8, so real padding is applied);
// the second wraps 7 octets, which lands in RFC 5649's single-block special
// case where the whole wrap is one AES call.
var rfc5649Vectors = []struct {
	name       string
	kek        string
	plaintext  string
	ciphertext string
}{
	{
		name:       "20 octets under a 192-bit KEK",
		kek:        "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8",
		plaintext:  "c37b7e6492584340bed12207808941155068f738",
		ciphertext: "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a",
	},
	{
		name:       "7 octets under a 192-bit KEK",
		kek:        "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8",
		plaintext:  "466f7250617369",
		ciphertext: "afbeb0f07dfbf5419200f2ccb50bb24f",
	},
}

// TestWrapAESKWP_RFC5649Vectors checks WrapAESKWP against the published
// ciphertexts in RFC 5649 section 6. PKCS#11 v3.2 section 6.10.5 defines
// CKM_AES_KEY_WRAP_PAD as exactly this construction, so these vectors are what
// makes the mechanism interoperable rather than merely reversible.
func TestWrapAESKWP_RFC5649Vectors(t *testing.T) {
	for _, v := range rfc5649Vectors {
		t.Run(v.name, func(t *testing.T) {
			kek := mustHex(t, v.kek)
			plaintext := mustHex(t, v.plaintext)
			expected := mustHex(t, v.ciphertext)

			wrapped, err := WrapAESKWP(plaintext, kek)
			if err != nil {
				t.Fatalf("WrapAESKWP: %v", err)
			}
			if !bytes.Equal(wrapped, expected) {
				t.Fatalf("WrapAESKWP produced %x, RFC 5649 section 6 gives %x", wrapped, expected)
			}
		})
	}
}

// TestUnwrapAESKWP_RFC5649Vectors checks UnwrapAESKWP against the same
// published vectors, starting from the RFC's ciphertext rather than from
// anything this package produced. A wrap and an unwrap that share the same
// mistake round-trip perfectly with each other; only the published ciphertext
// distinguishes them.
func TestUnwrapAESKWP_RFC5649Vectors(t *testing.T) {
	for _, v := range rfc5649Vectors {
		t.Run(v.name, func(t *testing.T) {
			kek := mustHex(t, v.kek)
			expected := mustHex(t, v.plaintext)

			recovered, err := UnwrapAESKWP(mustHex(t, v.ciphertext), kek)
			if err != nil {
				t.Fatalf("UnwrapAESKWP: %v", err)
			}
			if !bytes.Equal(recovered, expected) {
				t.Fatalf("UnwrapAESKWP recovered %x, RFC 5649 section 6 gives %x", recovered, expected)
			}
		})
	}
}

// TestWrapAESKWP_AcceptsAESKeyLengths proves the mechanism works at the three
// key lengths CKM_AES_KEY_WRAP_PAD is advertised for, wrapping payloads that
// are not multiples of 8 -- the case RFC 3394 (WrapAESKW) cannot express at
// all and the reason the padded variant exists.
//
// The oracle here is WrapAESKW: the padded blob must NOT equal the unpadded
// one for the same block-aligned input, because the two constructions differ
// in their initial value and in the extra length-carrying block. Routing
// CKM_AES_KEY_WRAP_PAD to RFC 3394 would be a silent substitution this catches.
func TestWrapAESKWP_AcceptsAESKeyLengths(t *testing.T) {
	for _, keyLen := range []int{16, 24, 32} {
		kek := bytes.Repeat([]byte{byte(keyLen)}, keyLen)

		for _, payloadLen := range []int{1, 7, 8, 15, 16, 17, 24, 32} {
			payload := bytes.Repeat([]byte{0xb7}, payloadLen)

			wrapped, err := WrapAESKWP(payload, kek)
			if err != nil {
				t.Fatalf("WrapAESKWP kek=%d payload=%d: %v", keyLen, payloadLen, err)
			}

			// RFC 5649 prefixes one 8-byte AIV block to the padded plaintext.
			wantLen := 8 + ((payloadLen + 7) / 8 * 8)
			if len(wrapped) != wantLen {
				t.Fatalf("WrapAESKWP kek=%d payload=%d produced %d bytes, want %d",
					keyLen, payloadLen, len(wrapped), wantLen)
			}

			recovered, err := UnwrapAESKWP(wrapped, kek)
			if err != nil {
				t.Fatalf("UnwrapAESKWP kek=%d payload=%d: %v", keyLen, payloadLen, err)
			}
			if !bytes.Equal(recovered, payload) {
				t.Fatalf("UnwrapAESKWP kek=%d payload=%d recovered %x, want %x",
					keyLen, payloadLen, recovered, payload)
			}

			// Where RFC 3394 also applies, the two must differ.
			if payloadLen >= 16 && payloadLen%8 == 0 {
				unpadded, err := WrapAESKW(payload, kek)
				if err != nil {
					t.Fatalf("WrapAESKW kek=%d payload=%d: %v", keyLen, payloadLen, err)
				}
				if bytes.Equal(wrapped, unpadded) {
					t.Fatalf("WrapAESKWP kek=%d payload=%d produced the RFC 3394 blob; "+
						"the padded and unpadded constructions must differ", keyLen, payloadLen)
				}
			}
		}
	}
}

// TestUnwrapAESKWP_RejectsTamperedVector proves the AIV check actually fires:
// a single flipped bit in an RFC 5649 ciphertext must be refused rather than
// yielding whatever plaintext falls out of the rounds.
func TestUnwrapAESKWP_RejectsTamperedVector(t *testing.T) {
	for _, v := range rfc5649Vectors {
		t.Run(v.name, func(t *testing.T) {
			kek := mustHex(t, v.kek)
			ciphertext := mustHex(t, v.ciphertext)
			ciphertext[0] ^= 0x01

			if _, err := UnwrapAESKWP(ciphertext, kek); err == nil {
				t.Fatal("UnwrapAESKWP accepted a ciphertext with a flipped bit")
			}
		})
	}
}

// TestUnwrapAESKWP_RejectsWrongKEK proves unwrapping under the wrong key is an
// error and not a silent return of garbage.
func TestUnwrapAESKWP_RejectsWrongKEK(t *testing.T) {
	v := rfc5649Vectors[0]
	wrongKEK := mustHex(t, v.kek)
	wrongKEK[0] ^= 0xff

	if _, err := UnwrapAESKWP(mustHex(t, v.ciphertext), wrongKEK); err == nil {
		t.Fatal("UnwrapAESKWP accepted a blob under the wrong KEK")
	}
}

// TestWrapAESKWP_RefusesEmptyPlaintext is the bad-input half of the RFC 5649
// lower bound, and the success half is one octet above it -- the smallest
// input the construction is defined for.
//
// RFC 5649 section 4.1 wraps "a plaintext, Q, of m octets" and records m in
// the message length indicator half of the AIV; there is no m=0 encoding, and
// section 4.2 refuses an MLI below 1 on the way back. Without the guard the
// arithmetic degenerates instead of failing: the padded length is zero, the
// 8-octet special case does not apply, n is zero so the 6*n wrapping rounds
// never execute, and WrapAESKWP returns the bare unencrypted AIV under a nil
// error. UnwrapAESKWP then refuses that blob, so an empty key would appear to
// wrap and prove unrecoverable later, at whatever peer held it.
func TestWrapAESKWP_RefusesEmptyPlaintext(t *testing.T) {
	kek := bytes.Repeat([]byte{0x5a}, 32)

	for _, empty := range [][]byte{nil, {}} {
		wrapped, err := WrapAESKWP(empty, kek)
		if err == nil {
			t.Fatalf("WrapAESKWP accepted %d-octet plaintext and returned %x", len(empty), wrapped)
		}
		if wrapped != nil {
			t.Fatalf("WrapAESKWP returned %x alongside its error; a refusal must yield no blob", wrapped)
		}
		var emptyErr *EmptyInputError
		if !errors.As(err, &emptyErr) {
			t.Fatalf("WrapAESKWP returned %T (%v), want *EmptyInputError to match WrapAESKW", err, err)
		}
		if emptyErr.Field != "plaintext" {
			t.Fatalf("EmptyInputError names field %q, want %q", emptyErr.Field, "plaintext")
		}
	}

	// One octet, the smallest m RFC 5649 defines, must still round-trip: the
	// guard rejects the degenerate case and nothing above it.
	wrapped, err := WrapAESKWP([]byte{0x2f}, kek)
	if err != nil {
		t.Fatalf("WrapAESKWP refused the 1-octet minimum: %v", err)
	}
	if len(wrapped) != 16 {
		t.Fatalf("WrapAESKWP produced %d bytes for 1 octet, want 16 (AIV plus one padded block)", len(wrapped))
	}
	recovered, err := UnwrapAESKWP(wrapped, kek)
	if err != nil {
		t.Fatalf("UnwrapAESKWP: %v", err)
	}
	if !bytes.Equal(recovered, []byte{0x2f}) {
		t.Fatalf("UnwrapAESKWP recovered %x, want 2f", recovered)
	}
}
