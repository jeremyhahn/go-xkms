package refvalue

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/veraison/go-cose"
)

const testSignerName = "Example Release Signer"

func TestSignRoundTrip(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 key: %v", err)
	}
	cases := []struct {
		name string
		alg  cose.Algorithm
		key  crypto.Signer
	}{
		{"ES256", cose.AlgorithmES256, newKey(t, elliptic.P256())},
		{"ES384", cose.AlgorithmES384, newKey(t, elliptic.P384())},
		{"EdDSA", cose.AlgorithmEdDSA, edKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			unsigned := buildUnsigned(t, buildCoMID(t), nil)
			signed, err := Sign(context.Background(), unsigned, tc.key, tc.alg, testSignerName)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			m, err := VerifySigned(signed, VerifyOptions{PublicKey: tc.key.Public()})
			if err != nil {
				t.Fatalf("VerifySigned: %v", err)
			}
			checkManifest(t, m)
		})
	}
}

func TestSignWrongKeyFailsVerify(t *testing.T) {
	unsigned := buildUnsigned(t, buildCoMID(t), nil)
	signed, err := Sign(context.Background(), unsigned, newKey(t, elliptic.P256()), cose.AlgorithmES256, testSignerName)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	other := newKey(t, elliptic.P256())
	if _, err := VerifySigned(signed, VerifyOptions{PublicKey: other.Public()}); !errors.Is(err, ErrSignature) {
		t.Fatalf("VerifySigned with the wrong key: got %v, want ErrSignature", err)
	}
}

func TestSignRefusesNilSigner(t *testing.T) {
	unsigned := buildUnsigned(t, buildCoMID(t), nil)
	if _, err := Sign(context.Background(), unsigned, nil, cose.AlgorithmES256, testSignerName); !errors.Is(err, ErrNilSigner) {
		t.Fatalf("got %v, want ErrNilSigner", err)
	}
}

// opaqueSigner is a crypto.Signer whose public key go-cose does not know.
type opaqueSigner struct{}

func (opaqueSigner) Public() crypto.PublicKey { return struct{}{} }

func (opaqueSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("opaque signer cannot sign")
}

func TestSignRefusesUnsupportedKey(t *testing.T) {
	unsigned := buildUnsigned(t, buildCoMID(t), nil)
	if _, err := Sign(context.Background(), unsigned, opaqueSigner{}, cose.AlgorithmES256, testSignerName); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("got %v, want ErrUnsupportedKey", err)
	}
}

func TestSignRefusesMalformedCoRIM(t *testing.T) {
	if _, err := Sign(context.Background(), []byte{0xff, 0x00}, newKey(t, elliptic.P256()), cose.AlgorithmES256, testSignerName); !errors.Is(err, ErrMalformed) {
		t.Fatalf("got %v, want ErrMalformed", err)
	}
}

func TestSignHonoursCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	unsigned := buildUnsigned(t, buildCoMID(t), nil)
	if _, err := Sign(ctx, unsigned, newKey(t, elliptic.P256()), cose.AlgorithmES256, testSignerName); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}
