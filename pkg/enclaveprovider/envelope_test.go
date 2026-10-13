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

package enclaveprovider

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// testKey is a fixed 32-byte key for envelope tests.
var testKey = bytes.Repeat([]byte{0x42}, enclave.RootKeyBytes)

// fullSealedData sets every field the envelope carries.
func fullSealedData() *types.SealedData {
	return &types.SealedData{
		Backend:    types.BackendTypeTPM2,
		KeyID:      "seal-key",
		Ciphertext: []byte("ciphertext"),
		Nonce:      []byte("nonce"),
		Tag:        []byte("tag"),
		WrappedDEK: []byte("wrapped"),
		TPMPublic:  []byte("public"),
		TPMPrivate: []byte("private"),
		KeyVersion: 7,
		Metadata: map[string][]byte{
			"tpm:handle": []byte("0x81000002"),
			"aws:ctx":    []byte("context"),
		},
	}
}

func TestEnvelope_RoundTripKeepsEveryField(t *testing.T) {
	want := fullSealedData()
	blob, err := encodeEnvelope(purposeRoot, want, testKey)
	require.NoError(t, err)

	env, err := decodeEnvelope(blob, purposeRoot)
	require.NoError(t, err)
	require.Equal(t, want, env.sealed)
	require.NoError(t, env.verify(testKey))
}

func TestEnvelope_EmptyFieldsDecodeAsNil(t *testing.T) {
	blob, err := encodeEnvelope(purposeKey, &types.SealedData{Backend: types.BackendTypeSoftware}, testKey)
	require.NoError(t, err)

	env, err := decodeEnvelope(blob, purposeKey)
	require.NoError(t, err)
	require.Equal(t, &types.SealedData{Backend: types.BackendTypeSoftware}, env.sealed)
}

func TestEnvelope_DecodeDoesNotAliasBlob(t *testing.T) {
	blob, err := encodeEnvelope(purposeKey, fullSealedData(), testKey)
	require.NoError(t, err)
	original := bytes.Clone(blob)

	env, err := decodeEnvelope(blob, purposeKey)
	require.NoError(t, err)
	env.sealed.Ciphertext[0] ^= 0xff
	env.body[0] ^= 0xff
	env.tag[0] ^= 0xff
	require.Equal(t, original, blob, "decoding must neither retain nor modify the caller's blob")
}

func TestEnvelope_TooLargeToEncode(t *testing.T) {
	sd := &types.SealedData{Ciphertext: make([]byte, maxEnvelopeSize)}
	_, err := encodeEnvelope(purposeKey, sd, testKey)
	require.ErrorIs(t, err, ErrEnvelopeTooLarge)
}

func TestEnvelope_TagRejectsAnotherKey(t *testing.T) {
	blob, err := encodeEnvelope(purposeKey, fullSealedData(), testKey)
	require.NoError(t, err)
	env, err := decodeEnvelope(blob, purposeKey)
	require.NoError(t, err)

	err = env.verify(bytes.Repeat([]byte{0x43}, enclave.RootKeyBytes))
	require.ErrorIs(t, err, enclave.ErrSealedAuthentication)
	require.ErrorIs(t, err, ErrEnvelopeTag)
}

// bodyOf returns an envelope body built from parts, tagged under testKey.
func bodyOf(parts ...[]byte) []byte {
	body := bytes.Join(parts, nil)
	tag, err := envelopeTag(testKey, body)
	if err != nil {
		panic(err)
	}
	return append(body, tag...)
}

func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

func field(s string) []byte { return append(u32(uint32(len(s))), s...) }

// emptyFields is the eight sealed-data fields, all empty, and a zero key
// version.
var emptyFields = bytes.Repeat(u32(0), 9)

func TestDecodeEnvelope_RefusesWhatEncodeNeverWrites(t *testing.T) {
	header := []byte{'X', 'K', 'E', 'P', envelopeVersion, byte(purposeKey)}
	valid, err := encodeEnvelope(purposeKey, fullSealedData(), testKey)
	require.NoError(t, err)

	cases := []struct {
		name  string
		blob  []byte
		cause error
	}{
		{"nil", nil, ErrMalformedEnvelope},
		{"shorter than a header and tag", make([]byte, sha256.Size+5), ErrMalformedEnvelope},
		{"larger than the bound", make([]byte, maxEnvelopeSize+1), ErrMalformedEnvelope},
		{"bad magic", bodyOf([]byte("XKEQ"), header[4:], emptyFields, u32(0)), ErrMalformedEnvelope},
		{"unknown version", bodyOf(header[:4], []byte{2, byte(purposeKey)}, emptyFields, u32(0)), ErrMalformedEnvelope},
		{"sealed root", bodyOf(header[:5], []byte{byte(purposeRoot)}, emptyFields, u32(0)), ErrWrongPurpose},
		{"unknown purpose", bodyOf(header[:5], []byte{9}, emptyFields, u32(0)), ErrWrongPurpose},
		{"field longer than the envelope", bodyOf(header, u32(1<<20)), ErrMalformedEnvelope},
		{"field length past int32", bodyOf(header, u32(0xffffffff)), ErrMalformedEnvelope},
		{"metadata count missing", bodyOf(header, emptyFields), ErrMalformedEnvelope},
		{"trailing byte", bodyOf(header, emptyFields, u32(0), []byte{0}), ErrMalformedEnvelope},
		{"metadata count larger than the envelope", bodyOf(header, emptyFields, u32(1000)), ErrMalformedEnvelope},
		{"metadata entry truncated", bodyOf(header, emptyFields, u32(1), field("a"), u32(5)), ErrMalformedEnvelope},
		{"metadata names out of order", bodyOf(header, emptyFields, u32(2), field("b"), field(""), field("a"), field("")), ErrMalformedEnvelope},
		{"metadata name repeated", bodyOf(header, emptyFields, u32(2), field("a"), field(""), field("a"), field("")), ErrMalformedEnvelope},
		{"truncated", valid[:len(valid)-1], ErrMalformedEnvelope},
		{"extended", append(bytes.Clone(valid), 0), ErrMalformedEnvelope},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, err := decodeEnvelope(tc.blob, purposeKey)
			require.Nil(t, env)
			require.ErrorIs(t, err, enclave.ErrSealedAuthentication)
			require.ErrorIs(t, err, tc.cause)
		})
	}
}

func TestDecodeEnvelope_AcceptsOrderedMetadata(t *testing.T) {
	header := []byte{'X', 'K', 'E', 'P', envelopeVersion, byte(purposeKey)}
	blob := bodyOf(header, emptyFields, u32(2), field("a"), field("1"), field("b"), field(""))

	env, err := decodeEnvelope(blob, purposeKey)
	require.NoError(t, err)
	require.Equal(t, map[string][]byte{"a": []byte("1"), "b": nil}, env.sealed.Metadata)
}
