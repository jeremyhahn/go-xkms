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
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/stretchr/testify/require"
)

// TestUnpackIDevIDContent_TruncationSweep proves every field read inside
// UnpackIDevIDContent -- the 16 fixed-size header fields and the 13
// variable-length fields that follow, each read via its own
// binary.Read/io.ReadFull call with its own "if err != nil { return nil,
// err }" -- actually checks the error it gets back instead of silently
// returning a zero-valued field. createTestIDevIDContent populates every
// field (including every *Sz-declared variable-length field) with distinct
// non-empty data, so a wire form built from it exercises the read for each
// field in turn as the sweep truncates one byte earlier each time; a read
// whose error check was dropped would let a short buffer succeed with a
// truncated or zero-valued tail field instead of failing.
func TestUnpackIDevIDContent_TruncationSweep(t *testing.T) {
	content := createTestIDevIDContent()

	packed, err := PackIDevIDContent(content)
	require.NoError(t, err)
	require.NotEmpty(t, packed)

	for n := 0; n < len(packed); n++ {
		reader := bytes.NewReader(packed[:n])
		_, err := UnpackIDevIDContent(reader)
		require.Errorf(t, err, "truncating the wire form to %d of %d bytes must fail, not silently succeed with a short or zero-valued field", n, len(packed))
	}

	reader := bytes.NewReader(packed)
	unpacked, err := UnpackIDevIDContent(reader)
	require.NoError(t, err, "the untruncated wire form must still unpack")
	require.Equal(t, content.ProdModel, unpacked.ProdModel)
	require.Equal(t, content.SgnCertifyInfoSig, unpacked.SgnCertifyInfoSig)
	require.Equal(t, content.Pad, unpacked.Pad)
}

// idevidContentSizeFields names every TCG_IDEVID_CONTENT field that
// declares the length of a corresponding variable-length data field, in the
// order UnpackIDevIDCSR copies them.
var idevidContentSizeFields = []string{
	"ProdModelSz",
	"ProdSerialSz",
	"ProdCaDataSz",
	"BootEvntLogSz",
	"EkCertSZ",
	"AttestPubSZ",
	"AtCreateTktSZ",
	"AtCertifyInfoSZ",
	"AtCertifyInfoSignatureSZ",
	"SigningPubSZ",
	"SgnCertifyInfoSZ",
	"SgnCertifyInfoSignatureSZ",
	"PadSz",
}

// TestUnpackIDevIDCSR_CorruptSizeMismatch proves UnpackIDevIDCSR's copy of
// each variable-length field checks the number of bytes actually copied
// against the field's declared size, rather than trusting the size field
// unconditionally. TCG_CSR_IDEVID.CsrContents carries the declared size and
// the backing data as two independent fields (unlike the wire form, which
// derives one from the other), so a CSR whose size field disagrees with its
// data slice's actual length -- corruption, or a hand-built CSR -- must be
// rejected with store.ErrCorruptCopy, never silently truncated or
// zero-padded.
func TestUnpackIDevIDCSR_CorruptSizeMismatch(t *testing.T) {
	for _, szField := range idevidContentSizeFields {
		t.Run(szField, func(t *testing.T) {
			csr := &TCG_CSR_IDEVID{}

			v := reflect.ValueOf(&csr.CsrContents).Elem()
			f := v.FieldByName(szField)
			require.True(t, f.IsValid(), "field %s must exist on TCG_IDEVID_CONTENT", szField)
			arr, ok := f.Addr().Interface().(*[4]byte)
			require.True(t, ok, "field %s must be a [4]byte size field", szField)
			binary.BigEndian.PutUint32(arr[:], 4)

			_, err := UnpackIDevIDCSR(csr)
			require.ErrorIs(t, err, store.ErrCorruptCopy,
				"%s declaring a 4-byte field with no backing data must be detected as corrupt, not silently zero-padded", szField)
		})
	}
}
