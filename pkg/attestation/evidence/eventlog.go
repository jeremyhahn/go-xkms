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
	"crypto/subtle"
	"encoding/binary"
	"strconv"

	"github.com/google/go-tpm/tpm2"
)

// The TCG PC Client Platform Firmware Profile (PFP) crypto-agile event log
// format. The first record is a legacy TCG_PCClientPCREvent (SHA-1 shaped)
// whose event data is the TCG_EfiSpecIDEvent naming every digest algorithm
// in the log and its size; every following record is a TCG_PCR_EVENT2
// carrying one digest per active bank. All integers are little-endian.
const (
	// EventNoAction is EV_NO_ACTION: informational, never extended.
	EventNoAction uint32 = 0x00000003

	// MaxEventDataSize bounds the event data of one record. Real entries
	// (EFI signature databases) are tens of kilobytes; the bound keeps a
	// hostile 32-bit size from driving a huge allocation.
	MaxEventDataSize = 1 << 20

	// MaxEvents bounds the number of records in one log.
	MaxEvents = 1 << 16

	// MaxAlgorithms bounds the number of digest algorithms a Spec ID event
	// may declare.
	MaxAlgorithms = 16

	// maxDigestSize is the largest digest any TPM bank produces (SHA-512).
	maxDigestSize = 64

	// legacyDigestSize is the SHA-1 digest of the legacy header record.
	legacyDigestSize = 20

	// pcrCount is the number of PCRs a PC Client TPM implements.
	pcrCount = 24
)

var (
	// specIDSignature identifies the TCG_EfiSpecIDEvent of a crypto-agile log.
	specIDSignature = []byte("Spec ID Event03\x00")

	// startupLocalitySignature identifies the EV_NO_ACTION event recording
	// the locality TPM2_Startup ran at, which sets PCR 0's initial value.
	startupLocalitySignature = []byte("StartupLocality\x00")
)

// bankHash maps the banks this package replays to their hash. SHA-1 is
// deliberately absent, as it is from the quote checks.
var bankHash = map[tpm2.TPMAlgID]crypto.Hash{
	tpm2.TPMAlgSHA256: crypto.SHA256,
	tpm2.TPMAlgSHA384: crypto.SHA384,
	tpm2.TPMAlgSHA512: crypto.SHA512,
}

// SpecID is the parsed TCG_EfiSpecIDEvent of a crypto-agile log.
type SpecID struct {
	PlatformClass    uint32
	SpecVersionMinor uint8
	SpecVersionMajor uint8
	SpecErrata       uint8
	UintnSize        uint8
	// DigestSizes maps every algorithm the log carries to its digest size.
	DigestSizes map[tpm2.TPMAlgID]int
	// Algorithms lists the algorithms in declaration order.
	Algorithms []tpm2.TPMAlgID
	VendorInfo []byte
}

// Event is one TCG_PCR_EVENT2 record.
type Event struct {
	// Index is the record's position in the log; the Spec ID header is 0.
	Index int
	// PCR is the register the event extends.
	PCR int
	// Type is the TCG event type (EV_*).
	Type uint32
	// Digests holds one digest per bank the record carries.
	Digests map[tpm2.TPMAlgID][]byte
	// Data is the raw event data.
	Data []byte
}

// EventLog is a parsed crypto-agile event log.
type EventLog struct {
	SpecID SpecID
	Events []Event
}

// logReader reads little-endian fields with exact-length checks.
type logReader struct {
	data   []byte
	offset int
	event  int
}

func (r *logReader) fail(reason string) *EventLogError {
	return &EventLogError{Offset: r.offset, Event: r.event, Reason: reason}
}

func (r *logReader) remaining() int { return len(r.data) - r.offset }

func (r *logReader) bytes(n int, what string) ([]byte, error) {
	if n < 0 || n > r.remaining() {
		return nil, r.fail("truncated " + what + ": need " + strconv.Itoa(n) + " bytes, have " + strconv.Itoa(r.remaining()))
	}
	out := r.data[r.offset : r.offset+n]
	r.offset += n
	return out, nil
}

func (r *logReader) u8(what string) (uint8, error) {
	b, err := r.bytes(1, what)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (r *logReader) u16(what string) (uint16, error) {
	b, err := r.bytes(2, what)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}

func (r *logReader) u32(what string) (uint32, error) {
	b, err := r.bytes(4, what)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

// eventData reads a 32-bit size followed by that many bytes of event data.
func (r *logReader) eventData() ([]byte, error) {
	size, err := r.u32("event data size")
	if err != nil {
		return nil, err
	}
	if size > MaxEventDataSize {
		return nil, r.fail("event data size " + strconv.FormatUint(uint64(size), 10) + " exceeds the " + strconv.Itoa(MaxEventDataSize) + "-byte maximum")
	}
	data, err := r.bytes(int(size), "event data")
	if err != nil {
		return nil, err
	}
	return bytes.Clone(data), nil
}

// ParseEventLog parses a TCG PC Client crypto-agile event log. Digest sizes
// come from the Spec ID header, never from guesses; a record naming an
// algorithm the header did not declare is malformed. Every failure is an
// *EventLogError.
func ParseEventLog(data []byte) (*EventLog, error) {
	r := &logReader{data: data}
	spec, err := r.specID()
	if err != nil {
		return nil, err
	}
	log := &EventLog{SpecID: *spec}
	for r.remaining() > 0 {
		if len(log.Events) >= MaxEvents {
			return nil, r.fail("log holds more than " + strconv.Itoa(MaxEvents) + " events")
		}
		r.event = len(log.Events) + 1
		ev, err := r.event2(spec)
		if err != nil {
			return nil, err
		}
		log.Events = append(log.Events, *ev)
	}
	return log, nil
}

// specID parses the legacy header record and its TCG_EfiSpecIDEvent.
func (r *logReader) specID() (*SpecID, error) {
	pcr, err := r.u32("header PCR index")
	if err != nil {
		return nil, err
	}
	eventType, err := r.u32("header event type")
	if err != nil {
		return nil, err
	}
	if pcr != 0 || eventType != EventNoAction {
		return nil, r.fail("first record is not an EV_NO_ACTION event on PCR 0; not a crypto-agile log")
	}
	if _, err := r.bytes(legacyDigestSize, "header digest"); err != nil {
		return nil, err
	}
	data, err := r.eventData()
	if err != nil {
		return nil, err
	}

	// Read the Spec ID event in place so failures report absolute offsets;
	// the reader ends where the header record does.
	h := &logReader{data: r.data[:r.offset], offset: r.offset - len(data)}
	signature, err := h.bytes(len(specIDSignature), "Spec ID signature")
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(signature, specIDSignature) {
		return nil, h.fail("header does not carry the \"Spec ID Event03\" signature")
	}
	spec := &SpecID{DigestSizes: map[tpm2.TPMAlgID]int{}}
	if spec.PlatformClass, err = h.u32("platform class"); err != nil {
		return nil, err
	}
	if spec.SpecVersionMinor, err = h.u8("spec version minor"); err != nil {
		return nil, err
	}
	if spec.SpecVersionMajor, err = h.u8("spec version major"); err != nil {
		return nil, err
	}
	if spec.SpecErrata, err = h.u8("spec errata"); err != nil {
		return nil, err
	}
	if spec.UintnSize, err = h.u8("uintn size"); err != nil {
		return nil, err
	}
	count, err := h.u32("algorithm count")
	if err != nil {
		return nil, err
	}
	if count == 0 || count > MaxAlgorithms {
		return nil, h.fail("Spec ID event declares " + strconv.FormatUint(uint64(count), 10) + " algorithms; want 1.." + strconv.Itoa(MaxAlgorithms))
	}
	for i := uint32(0); i < count; i++ {
		alg, err := h.u16("algorithm id")
		if err != nil {
			return nil, err
		}
		size, err := h.u16("digest size")
		if err != nil {
			return nil, err
		}
		if size == 0 || size > maxDigestSize {
			return nil, h.fail("algorithm 0x" + strconv.FormatUint(uint64(alg), 16) + " declares a " + strconv.Itoa(int(size)) + "-byte digest")
		}
		id := tpm2.TPMAlgID(alg)
		if _, dup := spec.DigestSizes[id]; dup {
			return nil, h.fail("algorithm 0x" + strconv.FormatUint(uint64(alg), 16) + " declared twice")
		}
		if want, ok := bankDigestLength[id]; ok && want != int(size) {
			return nil, h.fail("algorithm 0x" + strconv.FormatUint(uint64(alg), 16) + " declares a " + strconv.Itoa(int(size)) + "-byte digest; it produces " + strconv.Itoa(want))
		}
		spec.DigestSizes[id] = int(size)
		spec.Algorithms = append(spec.Algorithms, id)
	}
	vendorSize, err := h.u8("vendor info size")
	if err != nil {
		return nil, err
	}
	vendor, err := h.bytes(int(vendorSize), "vendor info")
	if err != nil {
		return nil, err
	}
	spec.VendorInfo = bytes.Clone(vendor)
	return spec, nil
}

// event2 parses one TCG_PCR_EVENT2 record.
func (r *logReader) event2(spec *SpecID) (*Event, error) {
	pcr, err := r.u32("PCR index")
	if err != nil {
		return nil, err
	}
	if pcr >= pcrCount {
		return nil, r.fail("PCR index " + strconv.FormatUint(uint64(pcr), 10) + " is out of range")
	}
	eventType, err := r.u32("event type")
	if err != nil {
		return nil, err
	}
	count, err := r.u32("digest count")
	if err != nil {
		return nil, err
	}
	if count > uint32(len(spec.Algorithms)) {
		return nil, r.fail("record carries " + strconv.FormatUint(uint64(count), 10) + " digests; the header declares " + strconv.Itoa(len(spec.Algorithms)) + " algorithms")
	}
	ev := &Event{Index: r.event, PCR: int(pcr), Type: eventType, Digests: make(map[tpm2.TPMAlgID][]byte, count)}
	for i := uint32(0); i < count; i++ {
		alg, err := r.u16("digest algorithm")
		if err != nil {
			return nil, err
		}
		id := tpm2.TPMAlgID(alg)
		size, ok := spec.DigestSizes[id]
		if !ok {
			return nil, r.fail("digest algorithm 0x" + strconv.FormatUint(uint64(alg), 16) + " is not declared in the Spec ID header")
		}
		if _, dup := ev.Digests[id]; dup {
			return nil, r.fail("digest algorithm 0x" + strconv.FormatUint(uint64(alg), 16) + " appears twice in one record")
		}
		digest, err := r.bytes(size, "digest")
		if err != nil {
			return nil, err
		}
		ev.Digests[id] = bytes.Clone(digest)
	}
	if ev.Data, err = r.eventData(); err != nil {
		return nil, err
	}
	return ev, nil
}

// Replay recomputes the PCR values of one bank from the log. EV_NO_ACTION
// events are not extended; a StartupLocality EV_NO_ACTION event sets PCR 0's
// initial value to its locality (PFP §192.0.2.3). Every other register the log
// touches starts from zero. The result holds only registers the log touched.
func (l *EventLog) Replay(bank tpm2.TPMAlgID) (map[int][]byte, error) {
	hash, ok := bankHash[bank]
	if !ok {
		return nil, absent(CheckEventLog, "PCR bank 0x"+strconv.FormatUint(uint64(bank), 16)+" is not accepted for replay")
	}
	if _, ok := l.SpecID.DigestSizes[bank]; !ok {
		return nil, absent(CheckEventLog, "event log carries no digests for PCR bank 0x"+strconv.FormatUint(uint64(bank), 16))
	}
	size := hash.Size()
	pcrs := make(map[int][]byte)
	for _, ev := range l.Events {
		if ev.Type == EventNoAction {
			if ev.PCR == 0 && len(ev.Data) == len(startupLocalitySignature)+1 && bytes.HasPrefix(ev.Data, startupLocalitySignature) {
				initial := make([]byte, size)
				initial[size-1] = ev.Data[len(startupLocalitySignature)]
				pcrs[0] = initial
			}
			continue
		}
		digest, ok := ev.Digests[bank]
		if !ok {
			return nil, forged(CheckEventLog, "event "+strconv.Itoa(ev.Index)+" carries no digest for the replayed bank")
		}
		current, ok := pcrs[ev.PCR]
		if !ok {
			current = make([]byte, size)
		}
		h := hash.New()
		h.Write(current)
		h.Write(digest)
		pcrs[ev.PCR] = h.Sum(nil)
	}
	return pcrs, nil
}

// ResetValue returns a PCR's power-on reset value in a bank of the given
// size: all zeros, except the dynamic-launch registers 17-22, which reset to
// all ones until a dynamic launch zeroes them.
func ResetValue(pcr, size int) []byte {
	value := make([]byte, size)
	if pcr >= 17 && pcr <= 22 {
		for i := range value {
			value[i] = 0xFF
		}
	}
	return value
}

// VerifyEventLog proves that the log explains the quoted PCR values: every
// quoted register the log touches must equal the replayed value, and every
// quoted register it does not touch must still hold its reset value. The
// comparison is constant-time per register; every mismatching index is
// reported. quoted should be values already proven by a quote
// (Quote.VerifyPCRValues).
func VerifyEventLog(log *EventLog, bank tpm2.TPMAlgID, quoted map[int][]byte) error {
	if log == nil {
		return absent(CheckEventLog, "no event log in evidence")
	}
	if len(quoted) == 0 {
		return absent(CheckEventLog, "no quoted PCR values to compare the event log against")
	}
	replayed, err := log.Replay(bank)
	if err != nil {
		return err
	}
	size := bankHash[bank].Size()
	var mismatched []int
	for _, idx := range sortedKeys(quoted) {
		want, ok := replayed[idx]
		if !ok {
			want = ResetValue(idx, size)
		}
		got := quoted[idx]
		if len(got) != len(want) || subtle.ConstantTimeCompare(got, want) != 1 {
			mismatched = append(mismatched, idx)
		}
	}
	if len(mismatched) > 0 {
		return forged(CheckEventLog, "event log replay does not reproduce quoted PCR "+FormatIndices(mismatched))
	}
	return nil
}
