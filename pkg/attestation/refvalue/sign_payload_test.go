package refvalue

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// TestSignKeepsUnregisteredExtension checks that a CoRIM carrying an
// unregistered top-level extension is signed over its original bytes: the
// COSE payload equals the input, so no field is dropped under the signature.
func TestSignKeepsUnregisteredExtension(t *testing.T) {
	var fields map[int]cbor.RawMessage
	if err := cbor.Unmarshal(buildUnsigned(t, buildCoMID(t), nil), &fields); err != nil {
		t.Fatalf("decode unsigned CoRIM as a map: %v", err)
	}
	fields[99] = cbor.RawMessage{0x63, 'e', 'x', 't'}
	unsigned, err := cbor.Marshal(fields)
	if err != nil {
		t.Fatalf("encode extended CoRIM: %v", err)
	}

	key := newKey(t, elliptic.P256())
	signed, err := Sign(context.Background(), unsigned, key, cose.AlgorithmES256, testSignerName)
	if err != nil {
		// Refusing the extension is also acceptable.
		return
	}
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(signed); err != nil {
		t.Fatalf("decode signed CoRIM: %v", err)
	}
	if !bytes.Equal(msg.Payload, unsigned) {
		t.Fatalf("COSE payload differs from the input CoRIM: extension dropped under the signature")
	}
	if _, err := VerifySigned(signed, VerifyOptions{PublicKey: key.Public()}); err != nil {
		t.Fatalf("VerifySigned: %v", err)
	}
}
