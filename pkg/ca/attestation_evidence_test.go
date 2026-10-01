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

package ca

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"testing"
	"time"
)

func validEvidence() AttestationEvidence {
	return AttestationEvidence{
		VerdictID:          "verdict-42",
		PCRDigestAlgorithm: crypto.SHA384,
		PCRDigest:          bytes.Repeat([]byte{0xab}, 48),
		AttestedAt:         time.Date(2026, 10, 1, 12, 30, 15, 900, time.FixedZone("x", 3600)),
	}
}

func TestAttestationEvidence_RoundTrip(t *testing.T) {
	ext, err := CreateAttestationEvidenceExtension(validEvidence())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if ext.Critical || !ext.Id.Equal(OIDAttestationEvidence) {
		t.Fatalf("extension = %+v, want non-critical tp-attestationEvidence", ext)
	}
	got, ok, err := ParseAttestationEvidenceExtension(&x509.Certificate{Extensions: []pkix.Extension{ext}})
	if err != nil || !ok {
		t.Fatalf("parse: ok=%v err=%v", ok, err)
	}
	want := validEvidence()
	if got.VerdictID != want.VerdictID || got.PCRDigestAlgorithm != crypto.SHA384 || !bytes.Equal(got.PCRDigest, want.PCRDigest) {
		t.Errorf("got %+v", got)
	}
	// Encoded in UTC at second precision.
	if !got.AttestedAt.Equal(want.AttestedAt.Truncate(time.Second)) || got.AttestedAt.Location() != time.UTC {
		t.Errorf("AttestedAt = %v", got.AttestedAt)
	}
}

func TestAttestationEvidence_Absent(t *testing.T) {
	got, ok, err := ParseAttestationEvidenceExtension(&x509.Certificate{})
	if got != nil || ok || err != nil {
		t.Fatalf("got %v %v %v, want absent", got, ok, err)
	}
	if _, _, err := ParseAttestationEvidenceExtension(nil); !errors.Is(err, ErrInvalidAttestationEvidence) {
		t.Fatalf("nil certificate: err = %v", err)
	}
}

func TestAttestationEvidence_CreateRefusals(t *testing.T) {
	cases := map[string]func(*AttestationEvidence){
		"empty verdict":    func(e *AttestationEvidence) { e.VerdictID = " " },
		"sha1":             func(e *AttestationEvidence) { e.PCRDigestAlgorithm = crypto.SHA1; e.PCRDigest = make([]byte, 20) },
		"no algorithm":     func(e *AttestationEvidence) { e.PCRDigestAlgorithm = 0 },
		"short digest":     func(e *AttestationEvidence) { e.PCRDigest = e.PCRDigest[:32] },
		"zero attested at": func(e *AttestationEvidence) { e.AttestedAt = time.Time{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := validEvidence()
			mutate(&e)
			if _, err := CreateAttestationEvidenceExtension(e); !errors.Is(err, ErrInvalidAttestationEvidence) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestAttestationEvidence_ParseRefusals(t *testing.T) {
	good, err := CreateAttestationEvidenceExtension(validEvidence())
	if err != nil {
		t.Fatal(err)
	}
	unknownAlg, err := asn1.Marshal(attestationEvidenceASN1{
		VerdictID: "v", PCRDigestAlgorithm: asn1.ObjectIdentifier{1, 2, 3}, PCRDigest: make([]byte, 32), AttestedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	critical := good
	critical.Critical = true

	cases := map[string][]pkix.Extension{
		"duplicate":         {good, good},
		"critical":          {critical},
		"not der":           {{Id: OIDAttestationEvidence, Value: []byte{0xff}}},
		"trailing data":     {{Id: OIDAttestationEvidence, Value: append(append([]byte{}, good.Value...), 0x00)}},
		"unknown algorithm": {{Id: OIDAttestationEvidence, Value: unknownAlg}},
	}
	for name, exts := range cases {
		t.Run(name, func(t *testing.T) {
			_, ok, err := ParseAttestationEvidenceExtension(&x509.Certificate{Extensions: exts})
			if !ok || !errors.Is(err, ErrInvalidAttestationEvidence) {
				t.Fatalf("ok=%v err=%v", ok, err)
			}
		})
	}
}
