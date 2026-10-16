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

package evidence

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

// logBuilder writes a TCG PC Client crypto-agile event log.
type logBuilder struct {
	buf  bytes.Buffer
	algs []tpm2.TPMAlgID
}

func (b *logBuilder) u16(v uint16) { _ = binary.Write(&b.buf, binary.LittleEndian, v) }
func (b *logBuilder) u32(v uint32) { _ = binary.Write(&b.buf, binary.LittleEndian, v) }

var algSize = map[tpm2.TPMAlgID]int{tpm2.TPMAlgSHA1: 20, tpm2.TPMAlgSHA256: 32, tpm2.TPMAlgSHA384: 48}
var algHash = map[tpm2.TPMAlgID]crypto.Hash{tpm2.TPMAlgSHA256: crypto.SHA256, tpm2.TPMAlgSHA384: crypto.SHA384}

// header writes the legacy record and its Spec ID event declaring algs.
func newLog(algs ...tpm2.TPMAlgID) *logBuilder {
	b := &logBuilder{algs: algs}
	var spec bytes.Buffer
	spec.Write(specIDSignature)
	_ = binary.Write(&spec, binary.LittleEndian, uint32(0)) // platform class
	spec.Write([]byte{0, 2, 0, 2})                          // minor, major, errata, uintn
	_ = binary.Write(&spec, binary.LittleEndian, uint32(len(algs)))
	for _, a := range algs {
		_ = binary.Write(&spec, binary.LittleEndian, uint16(a))
		_ = binary.Write(&spec, binary.LittleEndian, uint16(algSize[a]))
	}
	spec.WriteByte(2)
	spec.Write([]byte{0xAA, 0xBB})
	b.u32(0)
	b.u32(EventNoAction)
	b.buf.Write(make([]byte, legacyDigestSize))
	b.u32(uint32(spec.Len()))
	b.buf.Write(spec.Bytes())
	return b
}

// event writes a TCG_PCR_EVENT2 whose digests are each bank's hash of data.
func (b *logBuilder) event(pcr int, typ uint32, data []byte) {
	b.u32(uint32(pcr))
	b.u32(typ)
	b.u32(uint32(len(b.algs)))
	for _, a := range b.algs {
		b.u16(uint16(a))
		if h, ok := algHash[a]; ok {
			b.buf.Write(digestOf(h, data))
		} else {
			b.buf.Write(make([]byte, algSize[a]))
		}
	}
	b.u32(uint32(len(data)))
	b.buf.Write(data)
}

const (
	evPostCode  = 0x00000001
	evSeparator = 0x00000004
)

func extend(h crypto.Hash, pcr []byte, data ...[]byte) []byte {
	for _, d := range data {
		x := h.New()
		x.Write(pcr)
		x.Write(digestOf(h, d))
		pcr = x.Sum(nil)
	}
	return pcr
}

func sampleLog() []byte {
	b := newLog(tpm2.TPMAlgSHA1, tpm2.TPMAlgSHA256, tpm2.TPMAlgSHA384)
	b.event(0, EventNoAction, append(append([]byte(nil), startupLocalitySignature...), 3))
	b.event(0, evPostCode, []byte("crtm"))
	b.event(7, evPostCode, []byte("secureboot"))
	b.event(0, evSeparator, []byte{0, 0, 0, 0})
	b.event(7, evSeparator, []byte{0, 0, 0, 0})
	return b.buf.Bytes()
}

func expectedPCRs(h crypto.Hash) map[int][]byte {
	pcr0 := make([]byte, h.Size())
	pcr0[h.Size()-1] = 3
	return map[int][]byte{
		0: extend(h, pcr0, []byte("crtm"), []byte{0, 0, 0, 0}),
		7: extend(h, make([]byte, h.Size()), []byte("secureboot"), []byte{0, 0, 0, 0}),
	}
}

func TestParseEventLog(t *testing.T) {
	log, err := ParseEventLog(sampleLog())
	if err != nil {
		t.Fatalf("ParseEventLog: %v", err)
	}
	if len(log.Events) != 5 || log.Events[0].Index != 1 || log.Events[2].PCR != 7 || string(log.Events[1].Data) != "crtm" {
		t.Fatalf("events = %+v", log.Events)
	}
	if log.SpecID.SpecVersionMajor != 2 || log.SpecID.UintnSize != 2 || len(log.SpecID.Algorithms) != 3 ||
		log.SpecID.DigestSizes[tpm2.TPMAlgSHA384] != 48 || !bytes.Equal(log.SpecID.VendorInfo, []byte{0xAA, 0xBB}) {
		t.Fatalf("spec id = %+v", log.SpecID)
	}
}

func TestReplayAndVerifyEventLog(t *testing.T) {
	log, err := ParseEventLog(sampleLog())
	if err != nil {
		t.Fatal(err)
	}
	for bank, h := range algHash {
		want := expectedPCRs(h)
		got, err := log.Replay(bank)
		if err != nil {
			t.Fatalf("Replay(%v): %v", bank, err)
		}
		if len(got) != 2 || !bytes.Equal(got[0], want[0]) || !bytes.Equal(got[7], want[7]) {
			t.Fatalf("Replay(%v) = %x, want %x", bank, got, want)
		}
		quoted := map[int][]byte{0: want[0], 7: want[7], 14: make([]byte, h.Size()), 17: ResetValue(17, h.Size())}
		if err := VerifyEventLog(log, bank, quoted); err != nil {
			t.Fatalf("VerifyEventLog(%v): %v", bank, err)
		}
		quoted[7] = append([]byte(nil), want[0]...)
		quoted[14] = ResetValue(17, h.Size())
		wantClass(t, VerifyEventLog(log, bank, quoted), ClassForged, CheckEventLog, "quoted PCR [7,14]")
	}
}

func TestReplay_Failures(t *testing.T) {
	log, err := ParseEventLog(sampleLog())
	if err != nil {
		t.Fatal(err)
	}
	_, err = log.Replay(tpm2.TPMAlgSHA1)
	wantClass(t, err, ClassAbsent, CheckEventLog, "not accepted for replay")
	_, err = log.Replay(tpm2.TPMAlgSHA512)
	wantClass(t, err, ClassAbsent, CheckEventLog, "carries no digests")

	b := newLog(tpm2.TPMAlgSHA256)
	b.event(4, evPostCode, []byte("x"))
	partial, err := ParseEventLog(b.buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	partial.Events[0].Digests = map[tpm2.TPMAlgID][]byte{}
	_, err = partial.Replay(tpm2.TPMAlgSHA256)
	wantClass(t, err, ClassForged, CheckEventLog, "carries no digest")

	wantClass(t, VerifyEventLog(nil, tpm2.TPMAlgSHA256, map[int][]byte{0: nil}), ClassAbsent, CheckEventLog, "no event log")
	wantClass(t, VerifyEventLog(log, tpm2.TPMAlgSHA256, nil), ClassAbsent, CheckEventLog, "no quoted PCR")
	wantClass(t, VerifyEventLog(log, tpm2.TPMAlgSHA1, map[int][]byte{0: nil}), ClassAbsent, CheckEventLog, "not accepted")
}

func TestReplayWith_SubstitutesInPlace(t *testing.T) {
	log, err := ParseEventLog(sampleLog())
	if err != nil {
		t.Fatal(err)
	}
	for _, bank := range []tpm2.TPMAlgID{tpm2.TPMAlgSHA256, tpm2.TPMAlgSHA384} {
		h := algHash[bank]
		component := digestOf(h, []byte("secureboot-v2"))
		got, err := log.ReplayWith(bank, []Substitution{{PCR: 7, Ordinal: 0, Digest: component}})
		if err != nil {
			t.Fatalf("ReplayWith(%v): %v", bank, err)
		}
		// The replaced event is followed by the recorded separator.
		x := h.New()
		x.Write(make([]byte, h.Size()))
		x.Write(component)
		want7 := extend(h, x.Sum(nil), []byte{0, 0, 0, 0})
		if !bytes.Equal(got[7], want7) {
			t.Fatalf("ReplayWith(%v) PCR 7 = %x, want %x", bank, got[7], want7)
		}
		if !bytes.Equal(got[0], expectedPCRs(h)[0]) {
			t.Fatalf("ReplayWith(%v) changed PCR 0, which no substitution names", bank)
		}
	}
}

func TestReplayWith_Refusals(t *testing.T) {
	log, err := ParseEventLog(sampleLog())
	if err != nil {
		t.Fatal(err)
	}
	digest := digestOf(crypto.SHA256, []byte("x"))
	tests := []struct {
		name string
		subs []Substitution
		want string
	}{
		{"wrong length", []Substitution{{PCR: 7, Ordinal: 0, Digest: digest[:20]}}, "digest length"},
		{"twice", []Substitution{{PCR: 7, Ordinal: 0, Digest: digest}, {PCR: 7, Ordinal: 0, Digest: digest}}, "substituted twice"},
		{"beyond the PCR's events", []Substitution{{PCR: 7, Ordinal: 2, Digest: digest}}, "no such event"},
		{"PCR the log never extends", []Substitution{{PCR: 9, Ordinal: 0, Digest: digest}}, "no such event"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := log.ReplayWith(tpm2.TPMAlgSHA256, tt.subs)
			var subErr *SubstitutionError
			if !errors.As(err, &subErr) || !strings.Contains(subErr.Error(), tt.want) {
				t.Fatalf("ReplayWith = %v, want *SubstitutionError containing %q", err, tt.want)
			}
		})
	}
	_, err = log.ReplayWith(tpm2.TPMAlgSHA1, []Substitution{{PCR: 7, Digest: digest}})
	wantClass(t, err, ClassAbsent, CheckEventLog, "not accepted for replay")
}

func TestResetValue(t *testing.T) {
	if !bytes.Equal(ResetValue(0, 4), []byte{0, 0, 0, 0}) || !bytes.Equal(ResetValue(17, 2), []byte{0xFF, 0xFF}) || !bytes.Equal(ResetValue(23, 1), []byte{0}) {
		t.Fatal("ResetValue")
	}
}

func TestParseEventLog_Malformed(t *testing.T) {
	good := sampleLog()
	legacyLen := 4 + 4 + legacyDigestSize + 4
	specLen := int(binary.LittleEndian.Uint32(good[legacyLen-4:]))
	firstEvent := legacyLen + specLen

	mutate := func(f func([]byte) []byte) []byte { return f(append([]byte(nil), good...)) }
	put32 := func(b []byte, off int, v uint32) []byte { binary.LittleEndian.PutUint32(b[off:], v); return b }
	put16 := func(b []byte, off int, v uint16) []byte { binary.LittleEndian.PutUint16(b[off:], v); return b }
	algOff := legacyLen + 16 + 4 + 4 // Spec ID algorithm-count field

	dupHeader := newLog(tpm2.TPMAlgSHA256, tpm2.TPMAlgSHA256).buf.Bytes()
	badSize := newLog(tpm2.TPMAlgSHA256).buf.Bytes()
	badSize = put16(badSize, algOff+4+2, 20)

	cases := map[string][]byte{
		"empty":               nil,
		"not no-action":       mutate(func(b []byte) []byte { return put32(b, 4, 1) }),
		"bad signature":       mutate(func(b []byte) []byte { b[legacyLen] = 'X'; return b }),
		"zero algorithms":     mutate(func(b []byte) []byte { return put32(b, algOff, 0) }),
		"too many algorithms": mutate(func(b []byte) []byte { return put32(b, algOff, MaxAlgorithms+1) }),
		"zero digest size":    mutate(func(b []byte) []byte { return put16(b, algOff+4+2, 0) }),
		"duplicate alg":       dupHeader,
		"wrong digest size":   badSize,
		"truncated header":    good[:legacyLen+10],
		"truncated event":     good[:len(good)-2],
		"pcr out of range":    mutate(func(b []byte) []byte { return put32(b, firstEvent, 24) }),
		"too many digests":    mutate(func(b []byte) []byte { return put32(b, firstEvent+8, 9) }),
		"undeclared alg":      mutate(func(b []byte) []byte { return put16(b, firstEvent+12, 0x0099) }),
		"duplicate digest":    mutate(func(b []byte) []byte { return put16(b, firstEvent+12+2+20, uint16(tpm2.TPMAlgSHA1)) }),
		"oversized data":      mutate(func(b []byte) []byte { return put32(b, firstEvent+12+2+20+2+32+2+48, MaxEventDataSize+1) }),
		"oversized header":    mutate(func(b []byte) []byte { return put32(b, legacyLen-4, MaxEventDataSize+1) }),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseEventLog(data)
			var le *EventLogError
			if !errors.As(err, &le) || !errors.Is(err, ErrEventLogMalformed) || le.Error() == "" {
				t.Fatalf("error = %v, want *EventLogError", err)
			}
			t.Log(err)
		})
	}
}

func TestParseEventLog_TooManyEvents(t *testing.T) {
	b := newLog(tpm2.TPMAlgSHA256)
	for i := 0; i <= MaxEvents; i++ {
		b.event(1, evPostCode, nil)
	}
	_, err := ParseEventLog(b.buf.Bytes())
	if !errors.Is(err, ErrEventLogMalformed) {
		t.Fatalf("error = %v, want ErrEventLogMalformed", err)
	}
}
