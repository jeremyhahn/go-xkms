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

package tpm2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"runtime"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/stretchr/testify/require"
)

// maxParserAllocation bounds what one hostile parse may allocate in these
// tests. Without the bounds checks, a single 0xFFFFFFFF length field asked
// make for 4 GiB.
const maxParserAllocation = 16 << 20

// idevidCSRHeaderLen is the TCG_CSR_IDEVID header (StructVer, Contents,
// SigSz) that precedes the TCG_IDEVID_CONTENT header in the wire form.
const idevidCSRHeaderLen = 12

// idevidContentFixedFields is the number of four-byte fields before the
// first length field in TCG_IDEVID_CONTENT (StructVer, HashAlgoId, HashSz).
const idevidContentFixedFields = 3

// packedTestCSR returns a well-formed packed TCG_CSR_IDEVID built from
// createTestIDevIDContent.
func packedTestCSR(t testing.TB) []byte {
	t.Helper()
	signature := []byte("mock-signature")
	csr := &TCG_CSR_IDEVID{CsrContents: *createTestIDevIDContent(), Signature: signature}
	binary.BigEndian.PutUint32(csr.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.SigSz[:], uint32(len(signature)))
	packed, err := PackIDevIDCSR(csr)
	require.NoError(t, err)
	return packed
}

// allocatedDuring reports the bytes the process allocated while fn ran.
func allocatedDuring(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// TestUnmarshalIDevIDCSR_HugeLengthFieldIsRefusedWithoutAllocating sets each
// of the thirteen content length fields, and the signature length, to
// 0xFFFFFFFF in an otherwise valid CSR. Each must be refused with a typed
// error naming the field, before its buffer is made.
func TestUnmarshalIDevIDCSR_HugeLengthFieldIsRefusedWithoutAllocating(t *testing.T) {
	valid := packedTestCSR(t)
	_, err := UnmarshalIDevIDCSR(valid)
	require.NoError(t, err, "the unmodified CSR must parse")

	type target struct {
		field  string
		offset int
	}
	targets := []target{{field: "Signature", offset: 8}}
	contentFields := []string{
		"ProdModel", "ProdSerial", "ProdCaData", "BootEvntLog", "EkCert",
		"AttestPub", "AtCreateTkt", "AtCertifyInfo", "AtCertifyInfoSig",
		"SigningPub", "SgnCertifyInfo", "SgnCertifyInfoSig", "Pad",
	}
	for i, field := range contentFields {
		targets = append(targets, target{
			field:  field,
			offset: idevidCSRHeaderLen + (idevidContentFixedFields+i)*4,
		})
	}

	for _, tc := range targets {
		t.Run(tc.field, func(t *testing.T) {
			hostile := bytes.Clone(valid)
			binary.BigEndian.PutUint32(hostile[tc.offset:], 0xFFFFFFFF)

			var parseErr error
			allocated := allocatedDuring(func() {
				_, parseErr = UnmarshalIDevIDCSR(hostile)
			})

			var sizeErr *IDevIDCSRFieldSizeError
			require.ErrorAs(t, parseErr, &sizeErr)
			require.Equal(t, tc.field, sizeErr.Field)
			require.Equal(t, uint32(0xFFFFFFFF), sizeErr.Declared)
			require.ErrorIs(t, parseErr, io.ErrUnexpectedEOF)
			require.Less(t, allocated, uint64(maxParserAllocation),
				"a hostile %s length allocated %d bytes", tc.field, allocated)
		})
	}
}

func TestUnmarshalIDevIDCSR_RefusesOversizedInput(t *testing.T) {
	oversized := make([]byte, MaxIDevIDCSRSize+1)
	_, err := UnmarshalIDevIDCSR(oversized)

	var tooLarge *IDevIDCSRTooLargeError
	require.ErrorAs(t, err, &tooLarge)
	require.Equal(t, MaxIDevIDCSRSize+1, tooLarge.Size)
	require.Equal(t, MaxIDevIDCSRSize, tooLarge.Max)
}

func TestUnpackIDevIDContent_RefusesOversizedInput(t *testing.T) {
	_, err := UnpackIDevIDContent(bytes.NewReader(make([]byte, MaxIDevIDCSRSize+1)))
	var tooLarge *IDevIDCSRTooLargeError
	require.ErrorAs(t, err, &tooLarge)
}

// TestUnpackIDevIDCSR_HugeSizeFieldIsRefusedWithoutAllocating covers the
// struct-to-native unpacker: its size fields and data slices are
// independent, so a size larger than its slice must be refused as corrupt
// before the destination buffer is made.
func TestUnpackIDevIDCSR_HugeSizeFieldIsRefusedWithoutAllocating(t *testing.T) {
	sizeFields := append([]string{"SigSz"}, idevidContentSizeFields...)
	for _, szField := range sizeFields {
		t.Run(szField, func(t *testing.T) {
			csr := &TCG_CSR_IDEVID{}
			var target reflect.Value
			if szField == "SigSz" {
				target = reflect.ValueOf(csr).Elem().FieldByName(szField)
			} else {
				target = reflect.ValueOf(&csr.CsrContents).Elem().FieldByName(szField)
			}
			arr, ok := target.Addr().Interface().(*[4]byte)
			require.True(t, ok)
			binary.BigEndian.PutUint32(arr[:], 0xFFFFFFFF)

			var err error
			allocated := allocatedDuring(func() {
				_, err = UnpackIDevIDCSR(csr)
			})
			require.ErrorIs(t, err, store.ErrCorruptCopy)
			require.Less(t, allocated, uint64(maxParserAllocation))
		})
	}
}

// FuzzUnmarshalIDevIDCSR drives the parser with arbitrary input. Whatever it
// is given, it must not panic, must refuse input it cannot fully account
// for with an error, and must never return fields adding up to more than
// the input held.
func FuzzUnmarshalIDevIDCSR(f *testing.F) {
	valid := packedTestCSR(f)
	f.Add(valid)
	f.Add([]byte{})
	f.Add(valid[:idevidCSRHeaderLen])
	for _, offset := range []int{8, idevidCSRHeaderLen + 3*4, idevidCSRHeaderLen + 15*4} {
		hostile := bytes.Clone(valid)
		binary.BigEndian.PutUint32(hostile[offset:], 0xFFFFFFFF)
		f.Add(hostile)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		csr, err := UnmarshalIDevIDCSR(data)
		if err != nil {
			var sizeErr *IDevIDCSRFieldSizeError
			if errors.As(err, &sizeErr) && int64(sizeErr.Declared) <= int64(sizeErr.Remaining) {
				t.Fatalf("field size error for a length that fits: %+v", sizeErr)
			}
			return
		}
		c := csr.CsrContents
		total := len(csr.Signature) + len(c.ProdModel) + len(c.ProdSerial) +
			len(c.ProdCaData) + len(c.BootEvntLog) + len(c.EkCert) +
			len(c.AttestPub) + len(c.AtCreateTkt) + len(c.AtCertifyInfo) +
			len(c.AtCertifyInfoSig) + len(c.SigningPub) + len(c.SgnCertifyInfo) +
			len(c.SgnCertifyInfoSig) + len(c.Pad)
		if total > len(data) {
			t.Fatalf("parsed %d bytes of fields from %d bytes of input", total, len(data))
		}
	})
}
