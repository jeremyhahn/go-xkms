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

package securityevent_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/securityevent"
)

func digestRecord() securityevent.Record {
	return securityevent.Record{
		Count:   2,
		Dropped: 3,
		Entries: []securityevent.Entry{
			{At: 0x01020304, Kind: 1, What: 7, Result: 0},
			{At: 0x01020310, Kind: 3, What: 9, Result: 2},
		},
	}
}

func encodedRecord(t *testing.T) []byte {
	t.Helper()
	cs, err := securityevent.Encode(digestRecord())
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return cs
}

// TestDetachedDigest_SHA256Vector pins the RFC 9711 §4.2.18.2 array:
// 0x82 (array of 2), 0x2F (COSE alg -16, SHA-256), 0x58 0x20 (bstr of 32),
// then SHA-256 over the Claims-Set bytes themselves, with no wrapping.
func TestDetachedDigest_SHA256Vector(t *testing.T) {
	cs := encodedRecord(t)
	sum := sha256.Sum256(cs)
	want := append([]byte{0x82, 0x2F, 0x58, 0x20}, sum[:]...)

	got, err := securityevent.DetachedDigest(cs, securityevent.AlgSHA256)
	if err != nil {
		t.Fatalf("DetachedDigest: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("DetachedDigest = %x, want %x", got, want)
	}
}

func TestVerifyDetached_RoundTrip(t *testing.T) {
	cs := encodedRecord(t)
	for _, alg := range []int{securityevent.AlgSHA256, securityevent.AlgSHA384, securityevent.AlgSHA512} {
		dsd, err := securityevent.DetachedDigest(cs, alg)
		if err != nil {
			t.Fatalf("alg %d: DetachedDigest: %v", alg, err)
		}
		rec, err := securityevent.VerifyDetached(cs, dsd)
		if err != nil {
			t.Fatalf("alg %d: VerifyDetached: %v", alg, err)
		}
		if !reflect.DeepEqual(rec, digestRecord()) {
			t.Fatalf("alg %d: record = %+v", alg, rec)
		}
	}
}

// TestVerifyDetached_TextAlgorithm: §4.2.18.2 allows the registry's string
// name as well as its integer.
func TestVerifyDetached_TextAlgorithm(t *testing.T) {
	cs := encodedRecord(t)
	sum := sha512.Sum384(cs)
	// 0x82, text(7) "SHA-384", bstr(48).
	dsd := append([]byte{0x82, 0x67}, "SHA-384"...)
	dsd = append(dsd, 0x58, 0x30)
	dsd = append(dsd, sum[:]...)
	if _, err := securityevent.VerifyDetached(cs, dsd); err != nil {
		t.Fatalf("VerifyDetached: %v", err)
	}
}

func TestVerifyDetached_Refusals(t *testing.T) {
	cs := encodedRecord(t)
	good, err := securityevent.DetachedDigest(cs, securityevent.AlgSHA256)
	if err != nil {
		t.Fatalf("DetachedDigest: %v", err)
	}

	tampered := append([]byte(nil), cs...)
	tampered[len(tampered)-1] ^= 0x01

	flipped := append([]byte(nil), good...)
	flipped[len(flipped)-1] ^= 0x01

	short := append([]byte{0x82, 0x2F, 0x58, 0x1F}, good[4:35]...)
	sha1 := append([]byte{0x82, 0x20, 0x58, 0x20}, good[4:]...) // alg -1: not a hash
	three := append([]byte{0x83, 0x2F, 0x58, 0x20}, append(append([]byte(nil), good[4:]...), 0x00)...)
	textDigest := append([]byte{0x82, 0x2F, 0x78, 0x20}, good[4:]...)

	cases := []struct {
		name string
		cs   []byte
		dsd  []byte
		want error
	}{
		{"record changed", tampered, good, securityevent.ErrDigestMismatch},
		{"digest changed", cs, flipped, securityevent.ErrDigestMismatch},
		{"digest wrong length", cs, short, securityevent.ErrMalformedDigest},
		{"not a hash algorithm", cs, sha1, securityevent.ErrUnsupportedAlgorithm},
		{"three elements", cs, three, securityevent.ErrMalformedDigest},
		{"digest not a bstr", cs, textDigest, securityevent.ErrMalformedDigest},
		{"not CBOR", cs, []byte{0xFF}, securityevent.ErrMalformedDigest},
		{"empty", cs, nil, securityevent.ErrMalformedDigest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := securityevent.VerifyDetached(tc.cs, tc.dsd); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestVerifyDetached_DigestBeforeDecode: a record whose digest matches but
// which is not a valid Claims-Set is still refused by Decode.
func TestVerifyDetached_DigestBeforeDecode(t *testing.T) {
	bad := []byte{0xA0} // an empty map: no claim
	dsd, err := securityevent.DetachedDigest(bad, securityevent.AlgSHA256)
	if err != nil {
		t.Fatalf("DetachedDigest: %v", err)
	}
	if _, err := securityevent.VerifyDetached(bad, dsd); !errors.Is(err, securityevent.ErrMissingKey) {
		t.Fatalf("err = %v, want ErrMissingKey", err)
	}
}

func TestDetachedDigest_UnsupportedAlgorithm(t *testing.T) {
	if _, err := securityevent.DetachedDigest(encodedRecord(t), -7); !errors.Is(err, securityevent.ErrUnsupportedAlgorithm) {
		t.Fatalf("err = %v, want ErrUnsupportedAlgorithm", err)
	}
}
