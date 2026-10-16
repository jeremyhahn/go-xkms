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

package attestation

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/veraison/swid"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/evidence"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"
)

// predictBank is one bank PredictPCRs is exercised in, with the
// known-answer value of PCR 4 once "bootloader-v2" replaces "bootloader-v1"
// in predictLog: H(H(0…0 ‖ H("bootloader-v2")) ‖ H(00000000)).
type predictBank struct {
	alg     tpm2.TPMAlgID
	hash    crypto.Hash
	swidAlg uint64
	kat     string
}

var predictBanks = []predictBank{
	{tpm2.TPMAlgSHA256, crypto.SHA256, swid.Sha256, "b0e211134515054cab054fe7aede7fca3802b1190e34cad53b9c3876144ee182"},
	{tpm2.TPMAlgSHA384, crypto.SHA384, swid.Sha384, "99a618e86a8f623080689f665c4441026d605551d3150b62c3b223c0832b785a6ec467a3693de329a5a3f9240cee50d0"},
}

func digestOf(h crypto.Hash, data string) []byte {
	x := h.New()
	x.Write([]byte(data))
	return x.Sum(nil)
}

// predictLog is a log extending a bootloader and a separator into PCR 4
// and a Secure Boot event into PCR 7.
func predictLog(b predictBank) *evidence.EventLog {
	event := func(index, pcr int, data string) evidence.Event {
		return evidence.Event{Index: index, PCR: pcr, Type: 1, Digests: map[tpm2.TPMAlgID][]byte{b.alg: digestOf(b.hash, data)}}
	}
	return &evidence.EventLog{
		SpecID: evidence.SpecID{DigestSizes: map[tpm2.TPMAlgID]int{b.alg: b.hash.Size()}},
		Events: []evidence.Event{
			event(1, 4, "bootloader-v1"),
			event(2, 7, "secureboot"),
			event(3, 4, "\x00\x00\x00\x00"),
		},
	}
}

// predictManifest states a final PCR 7 value and a component replacing the
// first event of PCR 4.
func predictManifest(b predictBank) *refvalue.Manifest {
	first := uint64(0)
	return &refvalue.Manifest{ReferenceValues: []refvalue.ReferenceValue{
		{Measurements: []refvalue.Measurement{{
			Key:     refvalue.MeasurementKey{Kind: refvalue.KeyKindUint, Uint: 7, String: "7"},
			Digests: []refvalue.Digest{{Algorithm: b.swidAlg, Value: digestOf(b.hash, "pcr7-final")}},
		}}},
		{Environment: refvalue.Environment{Index: &first}, Measurements: []refvalue.Measurement{{
			Key:     refvalue.MeasurementKey{Kind: refvalue.KeyKindUint, Uint: 4, String: "4"},
			Digests: []refvalue.Digest{{Algorithm: b.swidAlg, Value: digestOf(b.hash, "bootloader-v2")}},
		}}},
	}}
}

// livePCRs are the PCR values a platform that booted predictLog reports,
// plus PCR 9, which no reference value names.
func livePCRs(t *testing.T, b predictBank, log *evidence.EventLog) map[int][]byte {
	t.Helper()
	replayed, err := log.Replay(b.alg)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	return map[int][]byte{4: replayed[4], 7: replayed[7], 9: bytes.Repeat([]byte{9}, b.hash.Size())}
}

func TestPredictPCRs(t *testing.T) {
	for _, b := range predictBanks {
		t.Run(b.hash.String(), func(t *testing.T) {
			log := predictLog(b)
			current := livePCRs(t, b, log)
			got, err := PredictPCRs(log, predictManifest(b), b.alg, current)
			if err != nil {
				t.Fatalf("PredictPCRs: %v", err)
			}
			if hex.EncodeToString(got[4]) != b.kat {
				t.Fatalf("PCR 4 = %x, want %s", got[4], b.kat)
			}
			if !bytes.Equal(got[7], digestOf(b.hash, "pcr7-final")) {
				t.Fatalf("PCR 7 = %x, want the manifest's final value", got[7])
			}
			if !bytes.Equal(got[9], current[9]) || len(got) != 3 {
				t.Fatalf("prediction = %x, want PCR 9 kept at its live value", got)
			}
		})
	}
}

func TestPredictPCRs_FinalValuesNeedNoLog(t *testing.T) {
	b := predictBanks[0]
	got, err := PredictPCRs(nil, predictManifest(b), b.alg, map[int][]byte{7: make([]byte, 32)})
	if err != nil || !bytes.Equal(got[7], digestOf(b.hash, "pcr7-final")) {
		t.Fatalf("PredictPCRs = %x, %v", got, err)
	}
}

func TestPredictPCRs_Refusals(t *testing.T) {
	b := predictBanks[0]
	log := predictLog(b)
	current := livePCRs(t, b, log)
	withPCR := func(pcr int, value []byte) map[int][]byte {
		out := map[int][]byte{}
		for k, v := range current {
			out[k] = v
		}
		out[pcr] = value
		return out
	}
	ambiguous := predictManifest(b)
	ambiguous.ReferenceValues[0].Measurements[0].Digests = append(ambiguous.ReferenceValues[0].Measurements[0].Digests,
		refvalue.Digest{Algorithm: b.swidAlg, Value: digestOf(b.hash, "other")})
	conflicting := predictManifest(b)
	conflicting.ReferenceValues[0].Measurements[0].Key = refvalue.MeasurementKey{Kind: refvalue.KeyKindUint, Uint: 4, String: "4"}
	missingEvent := predictManifest(b)
	beyond := uint64(5)
	missingEvent.ReferenceValues[1].Environment.Index = &beyond
	noDigest := predictManifest(b)
	noDigest.ReferenceValues[1].Measurements[0].Digests = nil

	tests := []struct {
		name    string
		log     *evidence.EventLog
		m       *refvalue.Manifest
		bank    tpm2.TPMAlgID
		current map[int][]byte
		want    error
	}{
		{"unsupported bank", log, predictManifest(b), tpm2.TPMAlgSHA1, current, ErrUnsupportedPCRBank},
		{"nothing referenced", log, predictManifest(b), b.alg, map[int][]byte{9: current[9]}, ErrNoReferencedPCR},
		{"two final values", log, ambiguous, b.alg, current, ErrAmbiguousReference},
		{"final value and component", log, conflicting, b.alg, current, ErrConflictingReference},
		{"component without a digest", log, noDigest, b.alg, current, refvalue.ErrComponentDigest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := PredictPCRs(tt.log, tt.m, tt.bank, tt.current); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}

	evidenceTests := []struct {
		name    string
		log     *evidence.EventLog
		current map[int][]byte
		want    evidence.Class
	}{
		{"log does not reproduce the live PCR", log, withPCR(4, make([]byte, 32)), evidence.ClassForged},
		{"no log", nil, current, evidence.ClassAbsent},
	}
	for _, tt := range evidenceTests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := PredictPCRs(tt.log, predictManifest(b), b.alg, tt.current)
			var evErr *evidence.Error
			if !errors.As(err, &evErr) || evErr.Class != tt.want {
				t.Fatalf("err = %v, want evidence class %v", err, tt.want)
			}
		})
	}

	t.Run("component of an event the log lacks", func(t *testing.T) {
		_, err := PredictPCRs(log, missingEvent, b.alg, current)
		var subErr *evidence.SubstitutionError
		if !errors.As(err, &subErr) || subErr.PCR != 4 || subErr.Ordinal != 5 {
			t.Fatalf("err = %v, want *evidence.SubstitutionError for PCR 4 event 5", err)
		}
	})
}
