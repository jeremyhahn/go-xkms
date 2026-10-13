// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC

package store

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPlatformPolicyPin_RoundTrip proves a pin survives the on-disk encoding
// byte for byte. The PIN branch of the platform policy rebuilds a PolicyOR
// operand from these fields, so a single altered bit makes an object
// unrecoverable rather than merely mis-reported.
func TestPlatformPolicyPin_RoundTrip(t *testing.T) {
	digest := bytes.Repeat([]byte{0xA5}, 32)

	pin := &PlatformPolicyPin{
		PCRBank:   0x000B, // TPM_ALG_SHA256
		PCRIndex:  16,
		PCRDigest: digest,
	}

	encoded, err := pin.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, platformPolicyPinHeaderLen+len(digest), len(encoded))
	assert.Equal(t, platformPolicyPinMagic, string(encoded[0:4]),
		"the record must be self-identifying")
	assert.Equal(t, PlatformPolicyPinVersion, encoded[4])

	decoded, err := UnmarshalPlatformPolicyPin(encoded)
	require.NoError(t, err)
	assert.Equal(t, pin.PCRBank, decoded.PCRBank)
	assert.Equal(t, pin.PCRIndex, decoded.PCRIndex)
	assert.Equal(t, pin.PCRDigest, decoded.PCRDigest)

	// The decoded digest must not alias the input buffer: a caller that
	// reuses the record slice must not be able to mutate a live pin.
	encoded[platformPolicyPinHeaderLen] ^= 0xFF
	assert.Equal(t, digest, decoded.PCRDigest)
}

// TestPlatformPolicyPin_Marshal_InvalidInput covers the rejection contract of
// MarshalBinary: a record that does not carry a usable PCR digest must not be
// written, because a later read of it would silently produce the wrong
// PolicyOR operand.
func TestPlatformPolicyPin_Marshal_InvalidInput(t *testing.T) {
	var nilPin *PlatformPolicyPin
	out, err := nilPin.MarshalBinary()
	assert.Nil(t, out)
	assert.IsType(t, &PlatformPolicyPinFormatError{}, err)

	out, err = (&PlatformPolicyPin{PCRBank: 0x000B, PCRIndex: 16}).MarshalBinary()
	assert.Nil(t, out)
	assert.IsType(t, &PlatformPolicyPinFormatError{}, err)

	out, err = (&PlatformPolicyPin{
		PCRDigest: bytes.Repeat([]byte{0x01}, platformPolicyPinMaxDigest+1),
	}).MarshalBinary()
	assert.Nil(t, out)
	assert.IsType(t, &PlatformPolicyPinFormatError{}, err)
}

// TestUnmarshalPlatformPolicyPin_Rejections proves a damaged, foreign or
// newer record is reported instead of being interpreted. Guessing at these
// bytes would hand the TPM a PolicyOR operand the object was never created
// with, turning a legible storage error into an opaque authorization failure.
func TestUnmarshalPlatformPolicyPin_Rejections(t *testing.T) {
	valid, err := (&PlatformPolicyPin{
		PCRBank:   0x000B,
		PCRIndex:  16,
		PCRDigest: bytes.Repeat([]byte{0x5A}, 32),
	}).MarshalBinary()
	require.NoError(t, err)

	truncatedHeader := valid[:platformPolicyPinHeaderLen-1]

	badMagic := append([]byte(nil), valid...)
	badMagic[0] = 'Z'

	badVersion := append([]byte(nil), valid...)
	badVersion[4] = PlatformPolicyPinVersion + 1

	shortBody := valid[:len(valid)-1]

	longBody := append(append([]byte(nil), valid...), 0x00)

	zeroDigestLen := append([]byte(nil), valid...)
	zeroDigestLen[11], zeroDigestLen[12] = 0x00, 0x00

	oversizedDigestLen := append([]byte(nil), valid...)
	oversizedDigestLen[11], oversizedDigestLen[12] = 0xFF, 0xFF

	for name, record := range map[string][]byte{
		"empty":                {},
		"truncated header":     truncatedHeader,
		"bad magic":            badMagic,
		"short body":           shortBody,
		"trailing bytes":       longBody,
		"zero digest length":   zeroDigestLen,
		"oversized digest len": oversizedDigestLen,
	} {
		t.Run(name, func(t *testing.T) {
			pin, err := UnmarshalPlatformPolicyPin(record)
			assert.Nil(t, pin)
			assert.IsType(t, &PlatformPolicyPinFormatError{}, err)
		})
	}

	t.Run("unsupported version", func(t *testing.T) {
		pin, err := UnmarshalPlatformPolicyPin(badVersion)
		assert.Nil(t, pin)
		require.IsType(t, &PlatformPolicyPinVersionError{}, err)
		assert.Contains(t, err.Error(), "unsupported platform policy pin record version")
	})
}

// TestBlobStore_Delete_RemovesPlatformPolicyPin proves the pin record shares
// the lifetime of the object it describes. A pin left behind after a delete
// would be picked up by the next object created under the same CN, which would
// then be authorized against a policy it was never created with.
func TestBlobStore_Delete_RemovesPlatformPolicyPin(t *testing.T) {
	fb := newTestBlobStore(t)
	attrs := &types.KeyAttributes{CN: "pinned-sealed-object"}

	pin := &PlatformPolicyPin{
		PCRBank:   0x000B,
		PCRIndex:  16,
		PCRDigest: bytes.Repeat([]byte{0x33}, 32),
	}
	record, err := pin.MarshalBinary()
	require.NoError(t, err)

	require.NoError(t, fb.Save(attrs, []byte("private"), types.FSExtension(FSEXT_PRIVATE_BLOB), true))
	require.NoError(t, fb.Save(attrs, []byte("public"), types.FSExtension(FSEXT_PUBLIC_BLOB), true))
	require.NoError(t, fb.Save(attrs, record, types.FSExtension(FSEXT_PLATFORM_POLICY), true))

	stored, err := fb.Get(attrs, types.FSExtension(FSEXT_PLATFORM_POLICY))
	require.NoError(t, err)
	assert.Equal(t, record, stored)

	require.NoError(t, fb.Delete(attrs))

	_, err = fb.Get(attrs, types.FSExtension(FSEXT_PLATFORM_POLICY))
	assert.ErrorIs(t, err, ErrBlobNotFound, "deleting the object must delete its platform policy pin")
}
