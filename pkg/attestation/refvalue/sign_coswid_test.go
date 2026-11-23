package refvalue

import (
	"context"
	"crypto/elliptic"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

// coswidCoRIM wraps a hand-built concise-swid-tag map in an unsigned CoRIM
// (id "x", one tag) so a test controls exactly which CoSWID keys are present.
func coswidCoRIM(t *testing.T, tag map[int]any) []byte {
	t.Helper()
	body, err := cbor.Marshal(tag)
	if err != nil {
		t.Fatal(err)
	}
	embedded := append([]byte{0xd9, 0x01, 0xf9}, body...)
	out, err := cbor.Marshal(map[int]any{0: "x", 1: []any{embedded}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// coswidTag is a minimal valid concise-swid-tag: tag-id, tag-version,
// software-name and one entity whose role is the given value.
func coswidTag(role any) map[int]any {
	return map[int]any{
		0:  "i",
		12: 0,
		1:  "n",
		2:  map[int]any{31: "e", 33: role},
	}
}

func signCoSWID(t *testing.T, in []byte) error {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Sign panicked: %v", r)
		}
	}()
	_, err := Sign(context.Background(), in, newKey(t, elliptic.P256()), cose.AlgorithmES256, testSignerName)
	return err
}

func TestSignCoSWIDTagCreatorRole(t *testing.T) {
	for _, tc := range []struct {
		name string
		role any
	}{
		{"text role notTagCreator", "notTagCreator"},
		{"text role with spaces", "x tagCreator"},
		{"text role tagCreator", "tagCreator"},
		{"text roles array", []any{"tagCreator", "x"}},
		{"other code point", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := signCoSWID(t, coswidCoRIM(t, coswidTag(tc.role)))
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("Sign error = %v, want ErrMalformed", err)
			}
		})
	}
	for _, tc := range []struct {
		name string
		role any
	}{
		{"code point 1", 1},
		{"array with code point 1", []any{"x", 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := signCoSWID(t, coswidCoRIM(t, coswidTag(tc.role))); err != nil {
				t.Fatalf("Sign error = %v, want nil", err)
			}
		})
	}
}

func TestSignCoSWIDTagVersion(t *testing.T) {
	absent := coswidTag(1)
	delete(absent, 12)
	err := signCoSWID(t, coswidCoRIM(t, absent))
	if !errors.Is(err, ErrMalformed) || !errors.Is(err, ErrCoSWIDTagVersion) {
		t.Fatalf("Sign without tag-version: error = %v, want ErrMalformed and ErrCoSWIDTagVersion", err)
	}
	if err := signCoSWID(t, coswidCoRIM(t, coswidTag(1))); err != nil {
		t.Fatalf("Sign with tag-version 0: error = %v, want nil", err)
	}
}
