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

package dice

import (
	"encoding/hex"
	"testing"
)

// The encoding path runs once per certificate issued and the decoding path
// runs once per certificate verified, so on an enrollment burst both are on
// the CA's critical path. These benchmarks exist so a change to the field
// walk -- which is hand-rolled rather than delegated to a struct tag -- is
// measured rather than assumed.

func BenchmarkMarshalTcbInfo(b *testing.B) {
	info := benchTcbInfo()

	b.ReportAllocs()
	for b.Loop() {
		if _, err := MarshalTcbInfo(info); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseTcbInfo(b *testing.B) {
	der, err := hex.DecodeString(vecTcbInfoFull)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for b.Loop() {
		if _, err := ParseTcbInfo(der); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMarshalUeid(b *testing.B) {
	value := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	b.ReportAllocs()
	for b.Loop() {
		if _, err := MarshalUeid(value); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseUeid(b *testing.B) {
	der, err := hex.DecodeString(vecUeid)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for b.Loop() {
		if _, err := ParseUeid(der); err != nil {
			b.Fatal(err)
		}
	}
}

// The UCCS path is now on the same critical path and costs more than the
// others: a CBOR decode with the strict options on top of the DER unwrap. Both
// directions are measured because a CA re-encoding evidence pays for the
// encode and every verification pays for the decode.

func BenchmarkMarshalUccsEvidence(b *testing.B) {
	claims := benchClaimsSet()

	b.ReportAllocs()
	for b.Loop() {
		if _, err := MarshalUccsEvidence(claims); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseUccsEvidence(b *testing.B) {
	der, err := hex.DecodeString(vecUccsEvidenceNonceAndUeid)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for b.Loop() {
		if _, err := ParseUccsEvidence(der); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOperationalFlagsBitString(b *testing.B) {
	flags := OperationalFlags{NotSecure: true, Debug: true}

	b.ReportAllocs()
	for b.Loop() {
		_ = flags.BitString()
	}
}

// benchTcbInfo is the fully populated structure, built once outside the loop.
func benchTcbInfo() *TcbInfo {
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}
	svn, layer, index := 1, 0, 0
	return &TcbInfo{
		Vendor:     "Automate The Things",
		Model:      "AVR-DICE",
		Version:    "1.0.0",
		SVN:        &svn,
		Layer:      &layer,
		Index:      &index,
		FWIDs:      []FWID{{HashAlg: oidSHA256, Digest: digest}},
		Flags:      &OperationalFlags{NotSecure: true},
		VendorInfo: make([]byte, 16),
		Type:       []byte("avr"),
	}
}

// benchClaimsSet is the claims set a device echoes: the nonce plus a ueid, the
// shape vecUccsEvidenceNonceAndUeid pins.
func benchClaimsSet() *ClaimsSet {
	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = byte(0xA0 + i)
	}
	return &ClaimsSet{
		Nonce: nonce,
		Other: map[int64][]byte{256: {0x48, 1, 2, 3, 4, 5, 6, 7, 8}},
	}
}
