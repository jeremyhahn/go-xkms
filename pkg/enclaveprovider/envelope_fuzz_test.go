package enclaveprovider

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// FuzzDecodeEnvelope is go-xkms's counterpart of go-enclave's FuzzParseBlob
// (docs/enclaveprovider/tpm-equivalence.md row 5). decodeEnvelope never
// panics, never writes its input, refuses only with the envelope sentinels,
// and anything it accepts re-encodes to the same body.
func FuzzDecodeEnvelope(f *testing.F) {
	header := []byte{'X', 'K', 'E', 'P', envelopeVersion, byte(purposeKey)}
	valid, err := encodeEnvelope(purposeKey, fullSealedData(), testKey)
	if err != nil {
		f.Fatal(err)
	}
	empty, err := encodeEnvelope(purposeKey, &types.SealedData{}, testKey)
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range [][]byte{
		valid,
		empty,
		nil,
		make([]byte, sha256.Size+5),
		bodyOf([]byte("XKEQ"), header[4:], emptyFields, u32(0)),
		bodyOf(header[:4], []byte{2, byte(purposeKey)}, emptyFields, u32(0)),
		bodyOf(header[:5], []byte{byte(purposeRoot)}, emptyFields, u32(0)),
		bodyOf(header[:5], []byte{9}, emptyFields, u32(0)),
		bodyOf(header, u32(1<<20)),
		bodyOf(header, u32(0xffffffff)),
		bodyOf(header, emptyFields),
		bodyOf(header, emptyFields, u32(0), []byte{0}),
		bodyOf(header, emptyFields, u32(1000)),
		bodyOf(header, emptyFields, u32(1), field("a"), u32(5)),
		bodyOf(header, emptyFields, u32(2), field("b"), field(""), field("a"), field("")),
		bodyOf(header, emptyFields, u32(2), field("a"), field(""), field("a"), field("")),
		valid[:len(valid)-1],
		append(bytes.Clone(valid), 0),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, blob []byte) {
		before := bytes.Clone(blob)
		env, err := decodeEnvelope(blob, purposeKey)
		if !bytes.Equal(blob, before) {
			t.Fatal("decodeEnvelope wrote its input")
		}
		if err != nil {
			if env != nil {
				t.Fatal("refusal returned an envelope")
			}
			if !errors.Is(err, ErrMalformedEnvelope) && !errors.Is(err, ErrEnvelopeTooLarge) && !errors.Is(err, ErrWrongPurpose) {
				t.Fatalf("refusal outside the envelope sentinels: %v", err)
			}
			if !errors.Is(err, enclave.ErrSealedAuthentication) {
				t.Fatalf("refusal is not sealed-data authentication: %v", err)
			}
			return
		}
		if !bytes.Equal(env.body, blob[:len(blob)-sha256.Size]) || !bytes.Equal(env.tag, blob[len(blob)-sha256.Size:]) {
			t.Fatal("accepted envelope does not split into the input's body and tag")
		}
		again, err := encodeEnvelope(purposeKey, env.sealed, testKey)
		if err != nil {
			t.Fatalf("accepted envelope does not re-encode: %v", err)
		}
		if bytes.Equal(again[:len(again)-sha256.Size], env.body) {
			return
		}
		redecoded, err := decodeEnvelope(again, purposeKey)
		if err != nil {
			t.Fatalf("re-encoded envelope is refused: %v", err)
		}
		if !reflect.DeepEqual(redecoded.sealed, env.sealed) {
			t.Fatal("re-encoded envelope decodes to another value")
		}
	})
}
