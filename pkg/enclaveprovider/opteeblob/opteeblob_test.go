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

package opteeblob_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/jeremyhahn/go-xkms/pkg/enclaveprovider/opteeblob"
)

// testVector is one entry of testdata/vectors.json. Every field is hex. The
// TA unique keys are test values, never a real device's, and are not derived
// from any HUK: they are inputs to go-xkms's HKDF (README §6).
type testVector struct {
	Name        string `json:"name"`
	TAUniqueKey string `json:"ta_unique_key"`
	TAUUID      string `json:"ta_uuid"`
	KDFInfo     string `json:"kdf_info"`
	Key         string `json:"key"`
	Nonce       string `json:"nonce"`
	Plaintext   string `json:"plaintext"`
	AAD         string `json:"aad"`
	Blob        string `json:"blob"`
}

// decodedVector is a testVector with its fields decoded.
type decodedVector struct {
	name                                          string
	ta                                            opteeblob.TAUUID
	taKey, info, key, nonce, plaintext, aad, blob []byte
}

func loadVectors(t *testing.T) []decodedVector {
	t.Helper()
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var raw []testVector
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("no vectors")
	}
	vectors := make([]decodedVector, 0, len(raw))
	for _, v := range raw {
		d := decodedVector{name: v.Name}
		uuid := mustHex(t, v.TAUUID)
		if len(uuid) != opteeblob.UUIDSize {
			t.Fatalf("%s: TA UUID is %d bytes", v.Name, len(uuid))
		}
		copy(d.ta[:], uuid)
		d.taKey = mustHex(t, v.TAUniqueKey)
		d.info = mustHex(t, v.KDFInfo)
		d.key = mustHex(t, v.Key)
		d.nonce = mustHex(t, v.Nonce)
		d.plaintext = mustHex(t, v.Plaintext)
		d.aad = mustHex(t, v.AAD)
		d.blob = mustHex(t, v.Blob)
		vectors = append(vectors, d)
	}
	return vectors
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

// rfc5869Key is HKDF-SHA-256 written out from RFC 5869 §2.2 and §2.3 for a
// 32-byte output, with no salt: an implementation independent of
// crypto/hkdf to check DeriveKey against.
func rfc5869Key(ikm, info []byte) []byte {
	extract := hmac.New(sha256.New, make([]byte, sha256.Size))
	extract.Write(ikm)
	prk := extract.Sum(nil)
	expand := hmac.New(sha256.New, prk)
	expand.Write(info)
	expand.Write([]byte{0x01})
	return expand.Sum(nil)
}

func TestVectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.name, func(t *testing.T) {
			if got := []byte(opteeblob.KDFInfo(v.ta)); !bytes.Equal(got, v.info) {
				t.Fatalf("kdf_info = %x, want %x", got, v.info)
			}
			key, err := opteeblob.DeriveKey(v.taKey, v.ta)
			if err != nil {
				t.Fatalf("DeriveKey: %v", err)
			}
			if !bytes.Equal(key, v.key) {
				t.Fatalf("key = %x, want %x", key, v.key)
			}
			if want := rfc5869Key(v.taKey, v.info); !bytes.Equal(key, want) {
				t.Fatalf("key = %x, RFC 5869 gives %x", key, want)
			}
			if got := opteeblob.Enc0AAD(v.ta); !bytes.Equal(got, v.aad) {
				t.Fatalf("aad = %x, want %x", got, v.aad)
			}
			blob, err := opteeblob.SealWithNonce(key, v.ta, v.nonce, v.plaintext)
			if err != nil {
				t.Fatalf("SealWithNonce: %v", err)
			}
			if !bytes.Equal(blob, v.blob) {
				t.Fatalf("blob = %x, want %x", blob, v.blob)
			}
			plaintext, err := opteeblob.Unseal(key, v.ta, v.blob)
			if err != nil {
				t.Fatalf("Unseal: %v", err)
			}
			if !bytes.Equal(plaintext, v.plaintext) {
				t.Fatalf("plaintext = %x, want %x", plaintext, v.plaintext)
			}
		})
	}
}

// TestFixedEncodings checks the hand-written protected header and
// Enc_structure bytes against the CBOR library's core deterministic encoding.
func TestFixedEncodings(t *testing.T) {
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	header, err := enc.Marshal(map[int64]int64{1: 3, -65537: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opteeblob.ProtectedHeader, header) {
		t.Fatalf("protected header = %x, want %x", opteeblob.ProtectedHeader, header)
	}
	ta := opteeblob.TAUUID{0xfe, 0x01, 0x02}
	aad, err := enc.Marshal([]any{"Encrypt0", header, ta[:]})
	if err != nil {
		t.Fatal(err)
	}
	if got := opteeblob.Enc0AAD(ta); !bytes.Equal(got, aad) {
		t.Fatalf("Enc_structure = %x, want %x", got, aad)
	}
}

func TestSealRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, opteeblob.KeySize)
	ta := opteeblob.TAUUID{1, 2, 3, 4}
	plaintext := []byte("a secret the TA keeps")
	first, err := opteeblob.Seal(key, ta, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	second, err := opteeblob.Seal(key, ta, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("two seals of one plaintext are equal: the nonce repeated")
	}
	for _, blob := range [][]byte{first, second} {
		got, err := opteeblob.Unseal(key, ta, blob)
		if err != nil {
			t.Fatalf("Unseal: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("plaintext = %q, want %q", got, plaintext)
		}
	}
	if want := 3 + len(opteeblob.ProtectedHeader) + 3 + opteeblob.NonceSize + 2 + len(plaintext) + opteeblob.TagSize; len(first) != want {
		t.Fatalf("blob is %d bytes, want %d", len(first), want)
	}
}

func TestKeyLengthErrors(t *testing.T) {
	ta := opteeblob.TAUUID{}
	for _, size := range []int{0, 16, 31, 33} {
		key := make([]byte, size)
		if _, err := opteeblob.Seal(key, ta, []byte("x")); !errors.Is(err, opteeblob.ErrKeyLength) {
			t.Errorf("Seal with a %d-byte key: %v, want ErrKeyLength", size, err)
		}
		if _, err := opteeblob.Unseal(key, ta, nil); !errors.Is(err, opteeblob.ErrKeyLength) {
			t.Errorf("Unseal with a %d-byte key: %v, want ErrKeyLength", size, err)
		}
		if _, err := opteeblob.DeriveKey(key, ta); !errors.Is(err, opteeblob.ErrTAUniqueKeyLength) {
			t.Errorf("DeriveKey with a %d-byte TA unique key: %v, want ErrTAUniqueKeyLength", size, err)
		}
	}
}

func TestDeriveKeyBindsTheTA(t *testing.T) {
	taKey := make([]byte, opteeblob.TAUniqueKeySize)
	first, err := opteeblob.DeriveKey(taKey, opteeblob.TAUUID{1})
	if err != nil {
		t.Fatal(err)
	}
	second, err := opteeblob.DeriveKey(taKey, opteeblob.TAUUID{2})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("two TAs derived the same key from one TA unique key")
	}
}

// blobParts builds a blob from its parts, each already CBOR-encoded where it
// is a raw message, so a test can break exactly one rule.
func blobParts(t *testing.T, number uint64, protected []byte, unprotected any, ciphertext []byte) []byte {
	t.Helper()
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := enc.Marshal(cbor.Tag{Number: number, Content: []any{protected, unprotected, ciphertext}})
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

func encoded(t *testing.T, v any) []byte {
	t.Helper()
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	b, err := enc.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func flip(blob []byte, i int) []byte {
	out := bytes.Clone(blob)
	out[i] ^= 0x01
	return out
}

// assertRefused checks that Unseal refused with want, returned no
// plaintext, and gave an error whose message formats and leads with want's.
func assertRefused(t *testing.T, plaintext []byte, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("Unseal: %v, want %v", err, want)
	}
	if plaintext != nil {
		t.Fatalf("Unseal returned a plaintext with %v", err)
	}
	if msg := err.Error(); !strings.HasPrefix(msg, want.Error()) {
		t.Fatalf("Unseal error %q does not lead with %q", msg, want.Error())
	}
}

func TestUnsealErrors(t *testing.T) {
	v := loadVectors(t)[0]
	if len(v.plaintext) == 0 {
		t.Fatal("the first vector must have a plaintext")
	}
	nonce := v.nonce
	iv := map[int64][]byte{5: nonce}
	ciphertext := v.blob[len(v.blob)-len(v.plaintext)-opteeblob.TagSize:]
	ciphertextStart := len(v.blob) - len(ciphertext)
	nonceStart := 3 + len(opteeblob.ProtectedHeader) + 3

	// The nonce's bstr head written in two bytes instead of one.
	nonMinimal := append(bytes.Clone(v.blob[:nonceStart-1]), 0x58, opteeblob.NonceSize)
	nonMinimal = append(nonMinimal, v.blob[nonceStart:]...)

	tests := []struct {
		name string
		ta   opteeblob.TAUUID
		blob []byte
		want error
	}{
		{"empty", v.ta, nil, opteeblob.ErrTruncated},
		{"cut in the ciphertext", v.ta, v.blob[:len(v.blob)-1], opteeblob.ErrTruncated},
		{"cut in the header", v.ta, v.blob[:nonceStart+4], opteeblob.ErrTruncated},
		{"ciphertext shorter than the tag", v.ta, blobParts(t, 16, opteeblob.ProtectedHeader, iv, ciphertext[:opteeblob.TagSize-1]), opteeblob.ErrTruncated},
		{"another CBOR tag", v.ta, blobParts(t, 17, opteeblob.ProtectedHeader, iv, ciphertext), opteeblob.ErrMalformed},
		{"untagged", v.ta, v.blob[1:], opteeblob.ErrMalformed},
		{"four elements", v.ta, encoded(t, cbor.Tag{Number: 16, Content: []any{opteeblob.ProtectedHeader, iv, ciphertext, nil}}), opteeblob.ErrMalformed},
		{"trailing byte", v.ta, append(bytes.Clone(v.blob), 0x00), opteeblob.ErrMalformed},
		{"not deterministic", v.ta, nonMinimal, opteeblob.ErrMalformed},
		{"version 2", v.ta, blobParts(t, 16, encoded(t, map[int64]int64{1: 3, -65537: 2}), iv, ciphertext), opteeblob.ErrVersion},
		{"A128GCM", v.ta, blobParts(t, 16, encoded(t, map[int64]int64{1: 1, -65537: 1}), iv, ciphertext), opteeblob.ErrAlgorithm},
		{"no version", v.ta, blobParts(t, 16, encoded(t, map[int64]int64{1: 3}), iv, ciphertext), opteeblob.ErrHeader},
		{"text version", v.ta, blobParts(t, 16, encoded(t, map[int64]any{1: 3, -65537: "1"}), iv, ciphertext), opteeblob.ErrHeader},
		{"no algorithm", v.ta, blobParts(t, 16, encoded(t, map[int64]int64{-65537: 1}), iv, ciphertext), opteeblob.ErrHeader},
		{"extra protected parameter", v.ta, blobParts(t, 16, encoded(t, map[int64]int64{1: 3, 3: 0, -65537: 1}), iv, ciphertext), opteeblob.ErrHeader},
		{"empty protected header", v.ta, blobParts(t, 16, []byte{}, iv, ciphertext), opteeblob.ErrHeader},
		{"protected header not a map", v.ta, blobParts(t, 16, []byte{0x01}, iv, ciphertext), opteeblob.ErrHeader},
		{"no IV", v.ta, blobParts(t, 16, opteeblob.ProtectedHeader, map[int64][]byte{}, ciphertext), opteeblob.ErrHeader},
		{"extra unprotected parameter", v.ta, blobParts(t, 16, opteeblob.ProtectedHeader, map[int64]any{1: 3, 5: nonce}, ciphertext), opteeblob.ErrHeader},
		{"11-byte IV", v.ta, blobParts(t, 16, opteeblob.ProtectedHeader, map[int64][]byte{5: nonce[:11]}, ciphertext), opteeblob.ErrHeader},
		{"text IV", v.ta, blobParts(t, 16, opteeblob.ProtectedHeader, map[int64]string{5: string(nonce)}, ciphertext), opteeblob.ErrHeader},
		{"unprotected header not a map", v.ta, blobParts(t, 16, opteeblob.ProtectedHeader, 5, ciphertext), opteeblob.ErrHeader},
		{"flipped tag byte", v.ta, flip(v.blob, len(v.blob)-1), opteeblob.ErrAuthentication},
		{"flipped ciphertext byte", v.ta, flip(v.blob, ciphertextStart), opteeblob.ErrAuthentication},
		{"flipped nonce byte", v.ta, flip(v.blob, nonceStart), opteeblob.ErrAuthentication},
		{"flipped external AAD byte", opteeblob.TAUUID(flip(v.ta[:], 15)), v.blob, opteeblob.ErrAuthentication},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plaintext, err := opteeblob.Unseal(v.key, tt.ta, tt.blob)
			assertRefused(t, plaintext, err, tt.want)
		})
	}

	t.Run("wrong key", func(t *testing.T) {
		if _, err := opteeblob.Unseal(flip(v.key, 0), v.ta, v.blob); !errors.Is(err, opteeblob.ErrAuthentication) {
			t.Fatalf("Unseal: %v, want ErrAuthentication", err)
		}
	})
}

// TestUnsealEncodingErrors pins the §2 header bytes and §5's core
// deterministic encoding beyond the nonce head TestUnsealErrors covers.
func TestUnsealEncodingErrors(t *testing.T) {
	v := loadVectors(t)[0]
	iv := map[int64][]byte{5: v.nonce}
	ciphertext := v.blob[len(v.blob)-len(v.plaintext)-opteeblob.TagSize:]
	ciphertextStart := len(v.blob) - len(ciphertext)
	if v.blob[ciphertextStart-2] != 0x58 {
		t.Fatalf("vector 1's ciphertext head is %x, want a 58 xx head", v.blob[ciphertextStart-2:ciphertextStart])
	}

	// The ciphertext's bstr head written in three bytes instead of two.
	wideCiphertext := append(bytes.Clone(v.blob[:ciphertextStart-2]), 0x59, 0x00, byte(len(ciphertext)))
	wideCiphertext = append(wideCiphertext, ciphertext...)
	// CBOR tag 16 written in two bytes instead of one.
	wideTag := append([]byte{0xd8, 0x10}, v.blob[1:]...)
	// The array of three written with an indefinite length.
	indefinite := append([]byte{0xd0, 0x9f}, v.blob[2:]...)
	indefinite = append(indefinite, 0xff)

	tests := []struct {
		name string
		blob []byte
		want error
	}{
		{"protected keys out of order", blobParts(t, 16, []byte{0xa2, 0x3a, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x03}, iv, ciphertext), opteeblob.ErrHeader},
		{"non-minimal version", blobParts(t, 16, []byte{0xa2, 0x01, 0x03, 0x3a, 0x00, 0x01, 0x00, 0x00, 0x18, 0x01}, iv, ciphertext), opteeblob.ErrHeader},
		{"non-minimal algorithm", blobParts(t, 16, []byte{0xa2, 0x01, 0x18, 0x03, 0x3a, 0x00, 0x01, 0x00, 0x00, 0x01}, iv, ciphertext), opteeblob.ErrHeader},
		{"non-minimal ciphertext head", wideCiphertext, opteeblob.ErrMalformed},
		{"non-minimal tag head", wideTag, opteeblob.ErrMalformed},
		{"indefinite-length array", indefinite, opteeblob.ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plaintext, err := opteeblob.Unseal(v.key, v.ta, tt.blob)
			assertRefused(t, plaintext, err, tt.want)
		})
	}
}

// TestUnsealErrorOrder pins §5's order: a blob that breaks two rules is
// refused with the error of the rule listed first.
func TestUnsealErrorOrder(t *testing.T) {
	v := loadVectors(t)[0]
	iv := map[int64][]byte{5: v.nonce}
	ciphertext := v.blob[len(v.blob)-len(v.plaintext)-opteeblob.TagSize:]
	short := ciphertext[:opteeblob.TagSize-1]
	version2 := encoded(t, map[int64]int64{1: 3, -65537: 2})
	nonceStart := 3 + len(opteeblob.ProtectedHeader) + 3
	nonMinimal := append(bytes.Clone(v.blob[:nonceStart-1]), 0x58, opteeblob.NonceSize)
	nonMinimal = append(nonMinimal, v.blob[nonceStart:]...)

	tests := []struct {
		name string
		key  []byte
		blob []byte
		want error
	}{
		{"short key before truncation", v.key[:31], v.blob[:10], opteeblob.ErrKeyLength},
		{"short ciphertext before version", v.key, blobParts(t, 16, version2, iv, short), opteeblob.ErrTruncated},
		{"short ciphertext before algorithm", v.key, blobParts(t, 16, encoded(t, map[int64]int64{1: 1, -65537: 1}), iv, short), opteeblob.ErrTruncated},
		{"short ciphertext before IV", v.key, blobParts(t, 16, opteeblob.ProtectedHeader, map[int64][]byte{5: v.nonce[:11]}, short), opteeblob.ErrTruncated},
		{"version before algorithm", v.key, blobParts(t, 16, encoded(t, map[int64]int64{1: 1, -65537: 2}), iv, ciphertext), opteeblob.ErrVersion},
		{"version before extra parameter", v.key, blobParts(t, 16, encoded(t, map[int64]int64{1: 3, 3: 0, -65537: 2}), iv, ciphertext), opteeblob.ErrVersion},
		{"algorithm before extra parameter", v.key, blobParts(t, 16, encoded(t, map[int64]int64{1: 1, 3: 0, -65537: 1}), iv, ciphertext), opteeblob.ErrAlgorithm},
		{"version before IV", v.key, blobParts(t, 16, version2, map[int64][]byte{5: v.nonce[:11]}, ciphertext), opteeblob.ErrVersion},
		{"encoding before authentication", flip(v.key, 0), nonMinimal, opteeblob.ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plaintext, err := opteeblob.Unseal(tt.key, v.ta, tt.blob)
			assertRefused(t, plaintext, err, tt.want)
		})
	}
}

// TestUnsealDerivedKeyMismatch pins §1 through §5: a key derived from
// another TA unique key, for another TA or under another label does not
// unseal the blob.
func TestUnsealDerivedKeyMismatch(t *testing.T) {
	v := loadVectors(t)[0]
	otherTA := opteeblob.TAUUID(flip(v.ta[:], 0))
	otherUnique, err := opteeblob.DeriveKey(flip(v.taKey, 0), v.ta)
	if err != nil {
		t.Fatal(err)
	}
	forOtherTA, err := opteeblob.DeriveKey(v.taKey, otherTA)
	if err != nil {
		t.Fatal(err)
	}
	info := bytes.Clone(v.info)
	if got := len(info); got != 45 {
		t.Fatalf("kdf_info is %d bytes, want 45", got)
	}
	if !bytes.Equal(info[:28], []byte("go-xkms optee-sealed-blob v1")) || info[28] != 0x00 || !bytes.Equal(info[29:], v.ta[:]) {
		t.Fatalf("kdf_info = %x, want label || 00 || TA UUID", info)
	}
	info[27] = '2' // "go-xkms optee-sealed-blob v2"
	otherLabel := rfc5869Key(v.taKey, info)

	tests := []struct {
		name string
		key  []byte
	}{
		{"another TA unique key", otherUnique},
		{"another TA", forOtherTA},
		{"another label", otherLabel},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if bytes.Equal(tt.key, v.key) {
				t.Fatal("the mismatched derivation gave the vector's key")
			}
			plaintext, err := opteeblob.Unseal(tt.key, v.ta, v.blob)
			if !errors.Is(err, opteeblob.ErrAuthentication) {
				t.Fatalf("Unseal: %v, want ErrAuthentication", err)
			}
			if plaintext != nil {
				t.Fatal("Unseal returned a plaintext")
			}
		})
	}
}
