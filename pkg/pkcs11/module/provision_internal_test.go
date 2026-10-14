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

package module

import (
	"bytes"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"testing"
)

func TestECPublicKeyFromPoint(t *testing.T) {
	// Every input is fixed bytes: a random point's X[0] can make the bare
	// point parse as a complete OCTET STRING and change which error comes back.
	// The P-256 base point is a valid point; its X[0] is 0x6B, so the bare
	// point reads as an OCTET STRING longer than its input.
	params := elliptic.P256().Params()
	raw := make([]byte, 65)
	raw[0] = 0x04
	params.Gx.FillBytes(raw[1:33])
	params.Gy.FillBytes(raw[33:])
	wrapped := mustMarshalOctetString(t, raw)
	// A complete OCTET STRING whose content is not a point on the curve.
	notAPoint := mustMarshalOctetString(t, []byte{0x04, 0x01})

	pub, err := ecPublicKeyFromPoint(elliptic.P256(), wrapped)
	if err != nil {
		t.Fatalf("round trip failed: %v", err)
	}
	if got, err := pub.Bytes(); err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("round trip decoded a different point: %v", err)
	}

	for _, tc := range []struct {
		name       string
		curve      elliptic.Curve
		ecPoint    []byte
		wantDERErr bool
	}{
		{name: "unwrapped point", curve: elliptic.P256(), ecPoint: raw, wantDERErr: true},
		{name: "trailing bytes", curve: elliptic.P256(), ecPoint: append(append([]byte(nil), wrapped...), 0), wantDERErr: true},
		{name: "empty", curve: elliptic.P256(), ecPoint: nil, wantDERErr: true},
		{name: "octet string that is not a point", curve: elliptic.P256(), ecPoint: notAPoint},
		{name: "P-256 point on P-384", curve: elliptic.P384(), ecPoint: wrapped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ecPublicKeyFromPoint(tc.curve, tc.ecPoint)
			var provErr *ProvisionError
			if !errors.As(err, &provErr) || provErr.Step != "decode CKA_EC_POINT" {
				t.Fatalf("err = %v, want a decode CKA_EC_POINT ProvisionError", err)
			}
			if got := errors.Is(err, ErrProvisionECPoint); got != tc.wantDERErr {
				t.Fatalf("errors.Is(err, ErrProvisionECPoint) = %v, want %v (err = %v)", got, tc.wantDERErr, err)
			}
		})
	}
}

func mustMarshalOctetString(t *testing.T, b []byte) []byte {
	t.Helper()
	der, err := asn1.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
