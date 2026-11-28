package refvalue

import (
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/veraison/corim/corim"
	"github.com/veraison/go-cose"
)

// malformedCoMIDCorim is an unsigned CoRIM (ID "x") whose one CoMID tag
// carries a bare CBOR tag head: the outer document is well formed, the
// embedded CoMID is not.
const malformedCoMIDCorim = "a2006178018144d901fac0"

// TestSignRejectsMalformedEmbeddedCoMID checks that Sign refuses a CoRIM
// whose embedded CoMID is malformed instead of signing it.
func TestSignRejectsMalformedEmbeddedCoMID(t *testing.T) {
	in, err := hex.DecodeString(malformedCoMIDCorim)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Sign panicked: %v", r)
		}
	}()
	out, err := Sign(context.Background(), in, newKey(t, elliptic.P256()), cose.AlgorithmES256, testSignerName)
	if err == nil {
		t.Fatalf("Sign = %x, want ErrMalformed", out)
	}
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("Sign error = %v, want ErrMalformed", err)
	}
}

// TestVerifySignedRejectsMalformedEmbeddedCoMID checks that a validly signed
// CoRIM with a malformed embedded CoMID returns ErrMalformed, not a panic.
func TestVerifySignedRejectsMalformedEmbeddedCoMID(t *testing.T) {
	in, err := hex.DecodeString(malformedCoMIDCorim)
	if err != nil {
		t.Fatal(err)
	}
	key := newKey(t, elliptic.P256())
	coseSigner, err := cose.NewSigner(cose.AlgorithmES256, key)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := corim.NewMeta().SetSigner(testSignerName, nil).ToCBOR()
	if err != nil {
		t.Fatal(err)
	}
	msg := cose.NewSign1Message()
	msg.Payload = in
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	msg.Headers.Protected[cose.HeaderLabelContentType] = corim.ContentType
	msg.Headers.Protected[corim.HeaderLabelCorimMeta] = meta
	if err := msg.Sign(rand.Reader, corim.NoExternalData, coseSigner); err != nil {
		t.Fatal(err)
	}
	signed, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("VerifySigned panicked: %v", r)
		}
	}()
	if _, err := VerifySigned(signed, VerifyOptions{PublicKey: key.Public()}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("VerifySigned error = %v, want ErrMalformed", err)
	}
}
