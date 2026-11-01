//go:build integration && vault

package integration

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// transitPrefix opens every Transit text ciphertext: "vault:v<N>:".
const transitPrefix = "vault:v"

// tamperTransitCiphertext returns a copy of a Transit text ciphertext
// (vault:v<N>:<standard base64 of nonce‖ciphertext‖tag>) with one bit of the
// decoded body flipped. Flipping a byte of the base64 text instead can land in
// the unused low bits of the final character before the padding, which a
// non-strict decoder ignores, leaving the authenticated bytes unchanged.
func tamperTransitCiphertext(t testing.TB, ciphertext []byte) []byte {
	t.Helper()
	text := string(ciphertext)
	if !strings.HasPrefix(text, transitPrefix) {
		t.Fatalf("tamperTransitCiphertext: %q has no %q prefix", text, transitPrefix)
	}
	sep := strings.Index(text[len(transitPrefix):], ":")
	if sep < 0 {
		t.Fatalf("tamperTransitCiphertext: %q has no version separator", text)
	}
	prefixLen := len(transitPrefix) + sep + 1
	body, err := base64.StdEncoding.DecodeString(text[prefixLen:])
	if err != nil {
		t.Fatalf("tamperTransitCiphertext: body of %q is not standard base64: %v", text, err)
	}
	if len(body) == 0 {
		t.Fatalf("tamperTransitCiphertext: %q has an empty body", text)
	}
	body[len(body)/2] ^= 0x01
	return []byte(text[:prefixLen] + base64.StdEncoding.EncodeToString(body))
}

// fatalRecorder captures a t.Fatalf from the helper without failing the
// enclosing test.
type fatalRecorder struct {
	testing.TB
	msg string
}

func (r *fatalRecorder) Helper() {}

func (r *fatalRecorder) Fatalf(format string, args ...any) {
	r.msg = format
	panic(r)
}

func runTamper(r *fatalRecorder, ciphertext []byte) (out []byte, failed bool) {
	defer func() {
		if rec := recover(); rec != nil {
			if rec != r {
				panic(rec)
			}
			failed = true
		}
	}()
	return tamperTransitCiphertext(r, ciphertext), false
}

func TestTamperTransitCiphertext_ChangesDecodedBytes(t *testing.T) {
	// Lengths covering every remainder mod 3, so the encoded body ends with
	// no padding, "=" and "==".
	for _, n := range []int{1, 2, 3, 4, 5, 6, 28, 29, 30, 31, 44, 45} {
		for fill := 0; fill < 256; fill += 51 {
			plain := bytes.Repeat([]byte{byte(fill)}, n)
			in := []byte("vault:v1:" + base64.StdEncoding.EncodeToString(plain))

			out := tamperTransitCiphertext(t, in)

			require.True(t, bytes.HasPrefix(out, []byte("vault:v1:")), "prefix kept for n=%d", n)
			decoded, err := base64.StdEncoding.DecodeString(string(out[len("vault:v1:"):]))
			require.NoError(t, err)
			assert.Len(t, decoded, n)
			assert.NotEqual(t, plain, decoded, "decoded bytes changed for n=%d fill=%d", n, fill)
		}
	}
}

func TestTamperTransitCiphertext_KeepsMultiDigitVersion(t *testing.T) {
	in := []byte("vault:v12:" + base64.StdEncoding.EncodeToString([]byte("nonce-ciphertext-tag")))

	out := tamperTransitCiphertext(t, in)

	assert.True(t, bytes.HasPrefix(out, []byte("vault:v12:")))
	assert.NotEqual(t, in, out)
}

func TestTamperTransitCiphertext_RejectsMalformedInput(t *testing.T) {
	cases := map[string]string{
		"no prefix":        base64.StdEncoding.EncodeToString([]byte("body")),
		"no separator":     "vault:v1",
		"not base64":       "vault:v1:!!!not-base64!!!",
		"empty body":       "vault:v1:",
		"empty input":      "",
		"truncated base64": "vault:v1:QUJD=",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			r := &fatalRecorder{TB: t}
			_, failed := runTamper(r, []byte(in))
			assert.True(t, failed, "malformed input %q must fail through Fatalf", in)
			assert.True(t, strings.HasPrefix(r.msg, "tamperTransitCiphertext:"), "message %q names the helper", r.msg)
		})
	}
}
