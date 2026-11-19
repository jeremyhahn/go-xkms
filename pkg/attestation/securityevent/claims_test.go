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
	"encoding/hex"
	"errors"
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/securityevent"
)

// claimKey is ClaimKey (-71765) in CBOR: major type 1 carries -1-n, so
// 71764 = 0x00011854, which needs the four-byte argument (0x3a).
const claimKey = "3a00011854"

// pinnedEntry is {1: 0x01020304, 2: 1, 3: 2, 4: 3}:
//
//	a4           map of 4 pairs
//	01 1a01020304  at: four-byte uint 0x01020304
//	02 01          kind: 1
//	03 02          what: 2
//	04 03          result: 3
const pinnedEntry = "a4011a01020304020103020403"

// pinnedHex is the Claims-Set {ClaimKey: {1: 1, 2: 2, 3: [pinnedEntry]}}:
//
//	a1           map of 1 pair
//	3a00011854   ClaimKey
//	a3           record: map of 3 pairs
//	01 01        count: 1
//	02 02        dropped: 2
//	03 81        entries: array of 1
//	a4...        pinnedEntry
const pinnedHex = "a1" + claimKey + "a3" + "0101" + "0202" + "0381" + pinnedEntry

var pinnedRecord = securityevent.Record{
	Count:   1,
	Dropped: 2,
	Entries: []securityevent.Entry{{At: 0x01020304, Kind: 1, What: 2, Result: 3}},
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad test hex %q: %v", s, err)
	}
	return b
}

func TestClaimKeyIsPrivateUse(t *testing.T) {
	// RFC 8392 §9.1: integer claim keys below -65536 are private use.
	if securityevent.ClaimKey >= -65536 {
		t.Fatalf("ClaimKey %d is not in the CWT private-use range", securityevent.ClaimKey)
	}
}

func TestPinnedVector(t *testing.T) {
	got, err := securityevent.Encode(pinnedRecord)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if hex.EncodeToString(got) != pinnedHex {
		t.Fatalf("Encode = %x, want %s", got, pinnedHex)
	}
	rec, err := securityevent.Decode(mustHex(t, pinnedHex))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !reflect.DeepEqual(rec, pinnedRecord) {
		t.Fatalf("Decode = %+v, want %+v", rec, pinnedRecord)
	}
}

func TestEmptyRecord(t *testing.T) {
	// {ClaimKey: {1: 0, 2: 0, 3: []}}
	const want = "a1" + claimKey + "a3" + "0100" + "0200" + "0380"
	got, err := securityevent.Encode(securityevent.Record{})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if hex.EncodeToString(got) != want {
		t.Fatalf("Encode = %x, want %s", got, want)
	}
	rec, err := securityevent.Decode(got)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !reflect.DeepEqual(rec, securityevent.Record{}) {
		t.Fatalf("Decode = %+v, want the empty record", rec)
	}
}

func TestRoundTrip(t *testing.T) {
	full := securityevent.Record{Count: securityevent.MaxEntries, Dropped: 0xFFFF}
	for i := 0; i < securityevent.MaxEntries; i++ {
		full.Entries = append(full.Entries, securityevent.Entry{
			At: uint32(i) * 0x01010101, Kind: uint8(i), What: uint8(255 - i), Result: uint8(i / 2),
		})
	}
	maxEntry := securityevent.Record{
		Count:   1,
		Entries: []securityevent.Entry{{At: 0xFFFFFFFF, Kind: 0xFF, What: 0xFF, Result: 0xFF}},
	}
	for name, rec := range map[string]securityevent.Record{
		"pinned": pinnedRecord, "empty": {}, "full": full, "max entry": maxEntry,
	} {
		t.Run(name, func(t *testing.T) {
			b, err := securityevent.Encode(rec)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			got, err := securityevent.Decode(b)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if !reflect.DeepEqual(got, rec) {
				t.Fatalf("round trip = %+v, want %+v", got, rec)
			}
		})
	}
}

func TestDroppedSaturates(t *testing.T) {
	// The device saturates dropped at 0xFFFF: that value is the widest
	// the format holds, and one more is out of range.
	b, err := securityevent.Encode(securityevent.Record{Dropped: 0xFFFF})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	const want = "a1" + claimKey + "a3" + "0100" + "0219ffff" + "0380"
	if hex.EncodeToString(b) != want {
		t.Fatalf("Encode = %x, want %s", b, want)
	}
	rec, err := securityevent.Decode(b)
	if err != nil || rec.Dropped != 0xFFFF {
		t.Fatalf("Decode = %+v, %v; want Dropped 0xFFFF", rec, err)
	}
	over := "a1" + claimKey + "a3" + "0100" + "021a00010000" + "0380"
	if _, err := securityevent.Decode(mustHex(t, over)); !errors.Is(err, securityevent.ErrOutOfRange) {
		t.Fatalf("Decode(dropped 0x10000) = %v, want ErrOutOfRange", err)
	}
}

func TestEncodeRefusesCountMismatch(t *testing.T) {
	rec := securityevent.Record{Count: 2, Entries: pinnedRecord.Entries}
	if _, err := securityevent.Encode(rec); !errors.Is(err, securityevent.ErrCountMismatch) {
		t.Fatalf("Encode = %v, want ErrCountMismatch", err)
	}
}

func TestDecodeRefusals(t *testing.T) {
	const emptyRec = "a3" + "0100" + "0200" + "0380"
	cases := []struct {
		name string
		hex  string
		want error
	}{
		{"empty input", "", securityevent.ErrMalformed},
		{"not CBOR", "ff", securityevent.ErrMalformed},
		{"truncated", pinnedHex[:len(pinnedHex)-2], securityevent.ErrMalformed},
		{"trailing bytes", pinnedHex + "00", securityevent.ErrMalformed},
		{"tagged", "c1" + pinnedHex, securityevent.ErrMalformed},
		{"top is an array", "8100", securityevent.ErrMalformed},
		{"record is not a map", "a1" + claimKey + "00", securityevent.ErrMalformed},
		{"entries is not an array", "a1" + claimKey + "a3" + "0100" + "0200" + "0300", securityevent.ErrMalformed},
		{"entry is not a map", "a1" + claimKey + "a3" + "0101" + "0200" + "0381" + "00", securityevent.ErrMalformed},
		{"duplicate key", "a1" + claimKey + "a4" + "0100" + "0100" + "0200" + "0380", securityevent.ErrMalformed},
		{"text value", "a1" + claimKey + "a3" + "016161" + "0200" + "0380", securityevent.ErrMalformed},

		{"unknown top key", "a2" + "0100" + claimKey + emptyRec, securityevent.ErrUnknownKey},
		{"unknown record key", "a1" + claimKey + "a4" + "0100" + "0200" + "0380" + "0400", securityevent.ErrUnknownKey},
		{"text record key", "a1" + claimKey + "a4" + "0100" + "0200" + "0380" + "616100", securityevent.ErrUnknownKey},
		{"unknown entry key", "a1" + claimKey + "a3" + "0101" + "0200" + "0381" + "a5" + "0100" + "0200" + "0300" + "0400" + "0500", securityevent.ErrUnknownKey},

		{"no claim", "a0", securityevent.ErrMissingKey},
		{"no dropped", "a1" + claimKey + "a2" + "0100" + "0380", securityevent.ErrMissingKey},
		{"no result", "a1" + claimKey + "a3" + "0101" + "0200" + "0381" + "a3" + "0100" + "0200" + "0300", securityevent.ErrMissingKey},

		{"count 256", "a1" + claimKey + "a3" + "01190100" + "0200" + "0380", securityevent.ErrOutOfRange},
		{"negative count", "a1" + claimKey + "a3" + "0120" + "0200" + "0380", securityevent.ErrOutOfRange},
		{"at 2^32", "a1" + claimKey + "a3" + "0101" + "0200" + "0381" + "a4" + "011b0000000100000000" + "0200" + "0300" + "0400", securityevent.ErrOutOfRange},
		{"kind 256", "a1" + claimKey + "a3" + "0101" + "0200" + "0381" + "a4" + "0100" + "02190100" + "0300" + "0400", securityevent.ErrOutOfRange},
		{"what 256", "a1" + claimKey + "a3" + "0101" + "0200" + "0381" + "a4" + "0100" + "0200" + "03190100" + "0400", securityevent.ErrOutOfRange},
		{"result 256", "a1" + claimKey + "a3" + "0101" + "0200" + "0381" + "a4" + "0100" + "0200" + "0300" + "04190100", securityevent.ErrOutOfRange},

		{"count above entries", "a1" + claimKey + "a3" + "0102" + "0200" + "0381" + pinnedEntry, securityevent.ErrCountMismatch},
		{"count below entries", "a1" + claimKey + "a3" + "0100" + "0200" + "0381" + pinnedEntry, securityevent.ErrCountMismatch},

		{"non-shortest count", "a1" + claimKey + "a3" + "011801" + "0200" + "0381" + pinnedEntry, securityevent.ErrNotDeterministic},
		{"indefinite entries", "a1" + claimKey + "a3" + "0100" + "0200" + "039fff", securityevent.ErrNotDeterministic},
		{"indefinite top map", "bf" + claimKey + emptyRec + "ff", securityevent.ErrNotDeterministic},
		{"keys out of order", "a1" + claimKey + "a3" + "0200" + "0100" + "0380", securityevent.ErrNotDeterministic},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := securityevent.Decode(mustHex(t, tc.hex))
			if !errors.Is(err, tc.want) {
				t.Fatalf("Decode(%s) = %v, want %v", tc.hex, err, tc.want)
			}
		})
	}
}
