package refvalue

import (
	"context"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/veraison/corim/corim"
	"github.com/veraison/go-cose"
	"github.com/veraison/swid"
)

// Each case is an unsigned CoRIM {0: "x", 1: [tag]} whose one tag is not a
// valid CoMID, CoSWID or CoTS; Sign must refuse it before signing.
func TestSignRejectsInvalidEmbeddedTagTypes(t *testing.T) {
	for _, tc := range []struct{ name, in string }{
		{"untagged integer", "a200617801814101"},
		{"empty CoSWID", "a2006178018144d901f9a0"},
		{"CoSWID not a map", "a2006178018144d901f901"},
		{"empty CoTS", "a2006178018144d901fba0"},
		{"CoTS not a map", "a2006178018144d901fb01"},
		{"unknown tag 509", "a2006178018144d901fd00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, err := hex.DecodeString(tc.in)
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
		})
	}
}

func TestSignAcceptsValidCoSWID(t *testing.T) {
	tag, err := swid.NewTag("com.example.fw-1.0", "fw", "1.0")
	if err != nil {
		t.Fatal(err)
	}
	ent, err := swid.NewEntity("Example", swid.RoleTagCreator)
	if err != nil {
		t.Fatal(err)
	}
	if err := tag.AddEntity(*ent); err != nil {
		t.Fatal(err)
	}
	in, err := corim.NewUnsignedCorim().SetID("x").AddCoswid(*tag).ToCBOR()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(context.Background(), in, newKey(t, elliptic.P256()), cose.AlgorithmES256, testSignerName); err != nil {
		t.Fatalf("Sign valid CoSWID: %v", err)
	}
}
