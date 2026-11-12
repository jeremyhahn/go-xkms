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

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The trusted-firmware alias certificate's measurements claim (the
// device-attest-01 possession vector) and the application evidence it holds.
const (
	tfwMeasurements = "81821901025854a50050bcc710071a6653c1967ef0d3d5ede421016374667702a21" +
		"81f6374667718210103a111a20782015820ba7816bf8f01cfea414140de5dae2223b00361a3961" +
		"77a9cb410ff61f20015ad1818636170700c00"
	tfwApplicationEvidence = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
)

func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// tfwCoswid is the vector's evidence CoSWID as a map a case changes one
// field of (RFC 9393 keys: tag-id 0, software-name 1, entity 2, evidence 3,
// tag-version 12).
func tfwCoswid(t *testing.T) map[int64]any {
	t.Helper()
	return map[int64]any{
		0:  hexBytes(t, "bcc710071a6653c1967ef0d3d5ede421"),
		1:  "tfw",
		2:  map[int64]any{31: "tfw", 33: 1},
		3:  map[int64]any{17: tfwFile(t)},
		12: 0,
	}
}

// tfwFile is the vector's one file-entry: fs-name 24, hash 7.
func tfwFile(t *testing.T) map[int64]any {
	t.Helper()
	return map[int64]any{24: "app", 7: []any{1, hexBytes(t, tfwApplicationEvidence)}}
}

func coreCBOR(t *testing.T, v any) []byte {
	t.Helper()
	mode, err := cbor.CoreDetEncOptions().EncMode()
	require.NoError(t, err)
	encoded, err := mode.Marshal(v)
	require.NoError(t, err)
	return encoded
}

func measurementsClaim(t *testing.T, coswid any) []byte {
	t.Helper()
	return coreCBOR(t, []any{[]any{258, coreCBOR(t, coswid)}})
}

func TestApplicationEvidenceReadsTheTrustedFirmwareVector(t *testing.T) {
	vector := hexBytes(t, tfwMeasurements)
	require.Equal(t, vector, measurementsClaim(t, tfwCoswid(t)), "the helpers must encode the vector's shape")

	evidence, err := ApplicationEvidence(vector)
	require.NoError(t, err)
	assert.Equal(t, hexBytes(t, tfwApplicationEvidence), evidence)

	producers := map[string]func(coswid map[int64]any){
		"a text tag-id":             func(coswid map[int64]any) { coswid[0] = "tfw-app-1" },
		"another tag-version":       func(coswid map[int64]any) { coswid[12] = 3 },
		"a tag-creator among roles": func(coswid map[int64]any) { coswid[2] = map[int64]any{31: "tfw", 33: []any{1, 2}} },
	}
	for name, edit := range producers {
		t.Run("accepts "+name, func(t *testing.T) {
			coswid := tfwCoswid(t)
			edit(coswid)
			evidence, err := ApplicationEvidence(measurementsClaim(t, coswid))
			require.NoError(t, err)
			assert.Equal(t, hexBytes(t, tfwApplicationEvidence), evidence)
		})
	}
}

func TestApplicationEvidenceRefusesEveryShapeViolation(t *testing.T) {
	coswid := coreCBOR(t, tfwCoswid(t))
	evidence := hexBytes(t, tfwApplicationEvidence)
	withCoswid := func(edit func(coswid map[int64]any)) []byte {
		changed := tfwCoswid(t)
		edit(changed)
		return measurementsClaim(t, changed)
	}
	withFile := func(edit func(file map[int64]any)) []byte {
		file := tfwFile(t)
		edit(file)
		return withCoswid(func(coswid map[int64]any) { coswid[3] = map[int64]any{17: file} })
	}
	withEntity := func(entity any) []byte {
		return withCoswid(func(coswid map[int64]any) { coswid[2] = entity })
	}

	cases := map[string][]byte{
		"trailing bytes after the claim": append(hexBytes(t, tfwMeasurements), 0x00),
		"no entries":                     coreCBOR(t, []any{}),
		"two entries":                    coreCBOR(t, []any{[]any{258, coswid}, []any{258, coswid}}),
		"a map of entries":               coreCBOR(t, map[int64]any{258: coswid}),
		"an entry of three items":        coreCBOR(t, []any{[]any{258, coswid, 0}}),
		"content-format 60":              coreCBOR(t, []any{[]any{60, coswid}}),
		"a text payload":                 coreCBOR(t, []any{[]any{258, "app"}}),
		"a payload that is not CBOR":     coreCBOR(t, []any{[]any{258, []byte{0xff}}}),
		"trailing bytes in the payload":  coreCBOR(t, []any{[]any{258, append(coswid, 0x00)}}),
		"a tagged CoSWID":                measurementsClaim(t, cbor.Tag{Number: 1398229316, Content: tfwCoswid(t)}),
		"a non-preferred content-type":   append([]byte{0x81, 0x82, 0x1a, 0x00, 0x00, 0x01, 0x02, 0x58, byte(len(coswid))}, coswid...),
		"a payload CoSWID": withCoswid(func(coswid map[int64]any) {
			coswid[6] = coswid[3]
			delete(coswid, 3)
		}),
		"no files":               withCoswid(func(coswid map[int64]any) { coswid[3] = map[int64]any{} }),
		"an empty file list":     withCoswid(func(coswid map[int64]any) { coswid[3] = map[int64]any{17: []any{}} }),
		"two files":              withCoswid(func(coswid map[int64]any) { coswid[3] = map[int64]any{17: []any{tfwFile(t), tfwFile(t)}} }),
		"a directory":            withCoswid(func(coswid map[int64]any) { coswid[3] = map[int64]any{17: tfwFile(t), 16: map[int64]any{24: "bin"}} }),
		"an extra CoSWID field":  withCoswid(func(coswid map[int64]any) { coswid[13] = "1.0" }),
		"no tag-id":              withCoswid(func(coswid map[int64]any) { delete(coswid, 0) }),
		"an integer tag-id":      withCoswid(func(coswid map[int64]any) { coswid[0] = 7 }),
		"a 15-byte tag-id":       withCoswid(func(coswid map[int64]any) { coswid[0] = make([]byte, 15) }),
		"no tag-version":         withCoswid(func(coswid map[int64]any) { delete(coswid, 12) }),
		"a text tag-version":     withCoswid(func(coswid map[int64]any) { coswid[12] = "0" }),
		"no software-name":       withCoswid(func(coswid map[int64]any) { delete(coswid, 1) }),
		"a bstr software-name":   withCoswid(func(coswid map[int64]any) { coswid[1] = []byte("tfw") }),
		"no entity":              withCoswid(func(coswid map[int64]any) { delete(coswid, 2) }),
		"a text entity":          withEntity("tfw"),
		"no entity-name":         withEntity(map[int64]any{33: 1}),
		"an integer entity-name": withEntity(map[int64]any{31: 1, 33: 1}),
		"no entity role":         withEntity(map[int64]any{31: "tfw"}),
		"a role not tag-creator": withEntity(map[int64]any{31: "tfw", 33: 2}),
		"a byte-string role":     withEntity(map[int64]any{31: "tfw", 33: []any{1, []byte{2}}}),
		"an extra entity field":  withEntity(map[int64]any{31: "tfw", 32: "https://example.com", 33: 1}),
		"a bstr fs-name":         withFile(func(file map[int64]any) { file[24] = []byte("app") }),
		"an fs-name not app":     withFile(func(file map[int64]any) { file[24] = "boot" }),
		"no fs-name":             withFile(func(file map[int64]any) { delete(file, 24) }),
		"no hash":                withFile(func(file map[int64]any) { delete(file, 7) }),
		"a size beside the hash": withFile(func(file map[int64]any) { file[20] = 4096 }),
		"sha-384":                withFile(func(file map[int64]any) { file[7] = []any{7, evidence} }),
		"a 31-byte digest":       withFile(func(file map[int64]any) { file[7] = []any{1, evidence[:31]} }),
		"a 33-byte digest":       withFile(func(file map[int64]any) { file[7] = []any{1, append(evidence, 0x00)} }),
	}
	for name, measurements := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := ApplicationEvidence(measurements)
			assert.ErrorIs(t, err, ErrMeasurementsShape)
			assert.Nil(t, got)
		})
	}
}

func TestVerifyApplicationReference(t *testing.T) {
	reference := hexBytes(t, tfwApplicationEvidence)
	withEvidence := func(evidence []byte) chainOption {
		coswid := tfwCoswid(t)
		coswid[3] = map[int64]any{17: map[int64]any{24: "app", 7: []any{1, evidence}}}
		return withClaim(ClaimMeasurements, measurementsClaim(t, coswid))
	}
	referenced := func(chain *testChain, ref []byte) *VerifyOptions {
		options := defaultOptions(chain)
		options.ApplicationReference = ref
		return options
	}

	t.Run("accepts the registered application", func(t *testing.T) {
		chain := newTestChain(t, withEvidence(reference))
		evidence, err := Verify(chain.certs(), referenced(chain, reference))
		require.NoError(t, err)
		assert.NotNil(t, evidence)
	})

	t.Run("refuses another application", func(t *testing.T) {
		other := append([]byte(nil), reference...)
		other[0] ^= 0xff
		chain := newTestChain(t, withEvidence(other))
		evidence, err := Verify(chain.certs(), referenced(chain, reference))
		assert.ErrorIs(t, err, ErrApplicationEvidenceMismatch)
		assert.Nil(t, evidence)
	})

	t.Run("refuses a leaf without a measurements claim", func(t *testing.T) {
		chain := newTestChain(t)
		evidence, err := Verify(chain.certs(), referenced(chain, reference))
		assert.ErrorIs(t, err, ErrApplicationEvidenceMismatch)
		assert.Nil(t, evidence)
	})

	t.Run("refuses a measurements claim that is not the shape", func(t *testing.T) {
		chain := newTestChain(t, withClaim(ClaimMeasurements, coreCBOR(t, []any{})))
		evidence, err := Verify(chain.certs(), referenced(chain, reference))
		assert.ErrorIs(t, err, ErrMeasurementsShape)
		assert.Nil(t, evidence)
	})

	t.Run("refuses a reference that is not 32 bytes", func(t *testing.T) {
		chain := newTestChain(t, withEvidence(reference))
		for _, ref := range [][]byte{{}, reference[:31], append(append([]byte(nil), reference...), 0)} {
			evidence, err := Verify(chain.certs(), referenced(chain, ref))
			assert.ErrorIs(t, err, ErrInvalidApplicationReference)
			assert.Nil(t, evidence)
		}
	})

	t.Run("is unchanged without a reference", func(t *testing.T) {
		for name, chain := range map[string]*testChain{
			"no measurements claim":    newTestChain(t),
			"another application":      newTestChain(t, withEvidence(make([]byte, 32))),
			"a claim not of the shape": newTestChain(t, withClaim(ClaimMeasurements, coreCBOR(t, []any{}))),
		} {
			t.Run(name, func(t *testing.T) {
				_, err := Verify(chain.certs(), defaultOptions(chain))
				require.NoError(t, err)
			})
		}
	})
}
