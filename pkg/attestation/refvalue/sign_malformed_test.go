package refvalue

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/veraison/go-cose"
)

// TestSignRejectsMalformedCBOR checks that hostile CoRIM bytes (a bare tag
// head, an indefinite-length or huge declared map) return ErrMalformed
// without a panic or a large allocation.
func TestSignRejectsMalformedCBOR(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"bare tag":         {0xc0},
		"huge map":         {0xba, 0xff, 0xff, 0xff, 0xff},
		"huge array":       {0x9b, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"huge byte string": {0x5a, 0xff, 0xff, 0xff, 0xff},
		"trailing bytes":   {0xa0, 0x00},
		"empty":            {},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Sign panicked: %v", r)
				}
			}()
			out, err := Sign(context.Background(), in, key, cose.AlgorithmES256, "signer")
			if err == nil {
				t.Fatalf("Sign(%x) = %x, want an error", in, out)
			}
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("Sign(%x) error = %v, want ErrMalformed", in, err)
			}
		})
	}
}
