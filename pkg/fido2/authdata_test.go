// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package fido2

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ctap2Encode encodes v using the CTAP2 canonical CBOR profile, the
// encoding a conforming FIDO2 authenticator emits.
func ctap2Encode(t *testing.T, v interface{}) []byte {
	t.Helper()

	mode, err := cbor.CTAP2EncOptions().EncMode()
	require.NoError(t, err)

	encoded, err := mode.Marshal(v)
	require.NoError(t, err)
	return encoded
}

// coseP256Key returns a CTAP2-canonical COSE_Key for an EC2 P-256 public
// key, matching what an authenticator places in attested credential data.
func coseP256Key(t *testing.T) []byte {
	t.Helper()

	return ctap2Encode(t, map[int]interface{}{
		1:  2,                              // kty: EC2
		3:  -7,                             // alg: ES256
		-1: 1,                              // crv: P-256
		-2: bytes.Repeat([]byte{0xA1}, 32), // x
		-3: bytes.Repeat([]byte{0xB2}, 32), // y
	})
}

// attestedCredData assembles attested credential data from its parts. The
// credential ID length field is emitted verbatim from declaredLen so tests
// can forge a length that disagrees with the credential ID that follows.
func attestedCredData(declaredLen int, credentialID, coseKey []byte) []byte {
	out := make([]byte, 0, aaguidLen+credentialIDLenFieldLen+len(credentialID)+len(coseKey))
	out = append(out, bytes.Repeat([]byte{0x5E}, aaguidLen)...)
	out = binary.BigEndian.AppendUint16(out, uint16(declaredLen))
	out = append(out, credentialID...)
	out = append(out, coseKey...)
	return out
}

// buildAuthData assembles authenticator data from the fixed header plus the
// optional attested credential data and extension sections. The caller sets
// flags explicitly so tests can exercise flag/section disagreement.
func buildAuthData(flags byte, attested, extensions []byte) []byte {
	out := make([]byte, 0, authDataHeaderLen+len(attested)+len(extensions))
	out = append(out, bytes.Repeat([]byte{0x11}, authDataRPIDHashLen)...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, 42) // signCount
	out = append(out, attested...)
	out = append(out, extensions...)
	return out
}

// validAttestedCredData returns well-formed attested credential data with a
// 16-byte credential ID.
func validAttestedCredData(t *testing.T) []byte {
	t.Helper()

	credentialID := bytes.Repeat([]byte{0xCD}, 16)
	return attestedCredData(len(credentialID), credentialID, coseP256Key(t))
}

// TestParseAuthDataExtensions_NoExtensionFlag verifies that a clear ED flag
// is the one and only case that reports "no extensions" without an error.
func TestParseAuthDataExtensions_NoExtensionFlag(t *testing.T) {
	tests := []struct {
		name     string
		authData []byte
	}{
		{
			name:     "bare assertion auth data",
			authData: buildAuthData(FlagUserPresent, nil, nil),
		},
		{
			name:     "attested credential data without extensions",
			authData: buildAuthData(FlagUserPresent|FlagAttestedCredentialData, validAttestedCredData(t), nil),
		},
		{
			name:     "minimum length auth data",
			authData: make([]byte, authDataHeaderLen),
		},
		{
			name: "extension bytes present but ED flag clear are ignored",
			authData: buildAuthData(FlagUserPresent, nil,
				ctap2Encode(t, map[string]interface{}{ExtensionHMACSecret: true})),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extensions, err := ParseAuthDataExtensions(tt.authData)
			require.NoError(t, err)
			assert.Nil(t, extensions)
		})
	}
}

// TestParseAuthDataExtensions_AssertionHMACSecret verifies the primary use
// case: extracting the hmac-secret output from GetAssertion authenticator
// data, which carries extensions but no attested credential data.
func TestParseAuthDataExtensions_AssertionHMACSecret(t *testing.T) {
	hmacOutput := bytes.Repeat([]byte{0x7F}, 32)
	authData := buildAuthData(
		FlagUserPresent|FlagUserVerified|FlagExtensionData,
		nil,
		ctap2Encode(t, map[string]interface{}{ExtensionHMACSecret: hmacOutput}),
	)

	extensions, err := ParseAuthDataExtensions(authData)
	require.NoError(t, err)
	require.Len(t, extensions, 1)

	output, ok := extensions[ExtensionHMACSecret].([]byte)
	require.True(t, ok, "hmac-secret output must decode to a byte string")
	assert.Equal(t, hmacOutput, output)
}

// TestParseAuthDataExtensions_AttestedCredDataHMACSecret verifies that the
// variable-length COSE public key is skipped correctly so the extension map
// that follows it is found. This is the case the previous implementation
// could not handle.
func TestParseAuthDataExtensions_AttestedCredDataHMACSecret(t *testing.T) {
	authData := buildAuthData(
		FlagUserPresent|FlagAttestedCredentialData|FlagExtensionData,
		validAttestedCredData(t),
		ctap2Encode(t, map[string]interface{}{ExtensionHMACSecret: true}),
	)

	extensions, err := ParseAuthDataExtensions(authData)
	require.NoError(t, err)
	require.Len(t, extensions, 1)
	assert.Equal(t, true, extensions[ExtensionHMACSecret])
}

// TestParseAuthDataExtensions_CredentialIDLengths verifies the COSE key is
// located correctly across credential ID sizes, including the empty and
// maximum-length boundaries.
func TestParseAuthDataExtensions_CredentialIDLengths(t *testing.T) {
	for _, credIDLen := range []int{0, 1, 16, 64, maxCredentialIDLen} {
		t.Run("credential ID of "+strconv.Itoa(credIDLen)+" bytes", func(t *testing.T) {
			credentialID := bytes.Repeat([]byte{0xCD}, credIDLen)
			authData := buildAuthData(
				FlagAttestedCredentialData|FlagExtensionData,
				attestedCredData(credIDLen, credentialID, coseP256Key(t)),
				ctap2Encode(t, map[string]interface{}{ExtensionHMACSecret: true}),
			)

			extensions, err := ParseAuthDataExtensions(authData)
			require.NoError(t, err)
			assert.Equal(t, true, extensions[ExtensionHMACSecret])
		})
	}
}

// TestParseAuthDataExtensions_MultipleExtensions verifies that every entry
// of a multi-extension map is returned, including extensions this package
// does not know about.
func TestParseAuthDataExtensions_MultipleExtensions(t *testing.T) {
	hmacOutput := bytes.Repeat([]byte{0x3C}, 64)
	authData := buildAuthData(
		FlagUserPresent|FlagAttestedCredentialData|FlagExtensionData,
		validAttestedCredData(t),
		ctap2Encode(t, map[string]interface{}{
			ExtensionHMACSecret:   hmacOutput,
			ExtensionCredProtect:  2,
			ExtensionLargeBlobKey: bytes.Repeat([]byte{0x0F}, 32),
		}),
	)

	extensions, err := ParseAuthDataExtensions(authData)
	require.NoError(t, err)
	require.Len(t, extensions, 3)

	assert.Equal(t, hmacOutput, extensions[ExtensionHMACSecret])
	assert.EqualValues(t, 2, extensions[ExtensionCredProtect])
	assert.Equal(t, bytes.Repeat([]byte{0x0F}, 32), extensions[ExtensionLargeBlobKey])
}

// TestParseAuthDataExtensions_UnknownExtension verifies an extension this
// package has no constant for is still surfaced rather than dropped.
func TestParseAuthDataExtensions_UnknownExtension(t *testing.T) {
	authData := buildAuthData(
		FlagExtensionData,
		nil,
		ctap2Encode(t, map[string]interface{}{"thirdPartyPayment": true}),
	)

	extensions, err := ParseAuthDataExtensions(authData)
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"thirdPartyPayment": true}, extensions)
}

// TestParseAuthDataExtensions_EmptyExtensionMap verifies an empty map is
// returned as an empty non-nil map, distinguishing it from a clear ED flag.
func TestParseAuthDataExtensions_EmptyExtensionMap(t *testing.T) {
	authData := buildAuthData(FlagExtensionData, nil, ctap2Encode(t, map[string]interface{}{}))

	extensions, err := ParseAuthDataExtensions(authData)
	require.NoError(t, err)
	require.NotNil(t, extensions, "an empty extension map must not be reported as absent")
	assert.Empty(t, extensions)
}

// TestParseAuthDataExtensions_Malformed verifies that every truncated or
// malformed input yields a typed error. A silent (nil, nil) for malformed
// data would hand callers "no extensions" for data they must reject.
func TestParseAuthDataExtensions_Malformed(t *testing.T) {
	coseKey := coseP256Key(t)
	credentialID := bytes.Repeat([]byte{0xCD}, 16)
	extensionMap := ctap2Encode(t, map[string]interface{}{ExtensionHMACSecret: true})

	tests := []struct {
		name     string
		authData []byte
		wantErr  error
	}{
		{
			name:     "empty input",
			authData: nil,
			wantErr:  ErrAuthDataTooShort,
		},
		{
			name:     "truncated rp ID hash",
			authData: bytes.Repeat([]byte{0x11}, 10),
			wantErr:  ErrAuthDataTooShort,
		},
		{
			name:     "header one byte short",
			authData: bytes.Repeat([]byte{0x11}, authDataHeaderLen-1),
			wantErr:  ErrAuthDataTooShort,
		},
		{
			name:     "attested credential data truncated inside aaguid",
			authData: buildAuthData(FlagAttestedCredentialData|FlagExtensionData, bytes.Repeat([]byte{0x5E}, 8), nil),
			wantErr:  ErrInvalidAttestedCredentialData,
		},
		{
			name:     "credential ID length field truncated",
			authData: buildAuthData(FlagAttestedCredentialData|FlagExtensionData, bytes.Repeat([]byte{0x5E}, aaguidLen+1), nil),
			wantErr:  ErrInvalidAttestedCredentialData,
		},
		{
			name: "credential ID longer than the buffer",
			authData: buildAuthData(FlagAttestedCredentialData|FlagExtensionData,
				attestedCredData(64, credentialID, nil), nil),
			wantErr: ErrInvalidAttestedCredentialData,
		},
		{
			name: "credential ID length above the 1023 byte maximum",
			authData: buildAuthData(FlagAttestedCredentialData|FlagExtensionData,
				attestedCredData(maxCredentialIDLen+1, bytes.Repeat([]byte{0xCD}, maxCredentialIDLen+1), coseKey), nil),
			wantErr: ErrInvalidAttestedCredentialData,
		},
		{
			name: "COSE key absent",
			authData: buildAuthData(FlagAttestedCredentialData|FlagExtensionData,
				attestedCredData(len(credentialID), credentialID, nil), nil),
			wantErr: ErrInvalidCOSEKey,
		},
		{
			name: "COSE key truncated",
			authData: buildAuthData(FlagAttestedCredentialData|FlagExtensionData,
				attestedCredData(len(credentialID), credentialID, coseKey[:len(coseKey)-5]), nil),
			wantErr: ErrInvalidCOSEKey,
		},
		{
			name: "COSE key is not a map",
			authData: buildAuthData(FlagAttestedCredentialData|FlagExtensionData,
				attestedCredData(len(credentialID), credentialID, ctap2Encode(t, []int{1, 2, 3})),
				extensionMap),
			wantErr: ErrInvalidCOSEKey,
		},
		{
			name: "COSE key is a text string",
			authData: buildAuthData(FlagAttestedCredentialData|FlagExtensionData,
				attestedCredData(len(credentialID), credentialID, ctap2Encode(t, "not-a-key")),
				extensionMap),
			wantErr: ErrInvalidCOSEKey,
		},
		{
			name: "COSE key uses an indefinite length map",
			authData: buildAuthData(FlagAttestedCredentialData|FlagExtensionData,
				attestedCredData(len(credentialID), credentialID, []byte{0xBF, 0x01, 0x02, 0xFF}),
				extensionMap),
			wantErr: ErrInvalidCOSEKey,
		},
		{
			name:     "extension data flag set with no extension bytes",
			authData: buildAuthData(FlagExtensionData, nil, nil),
			wantErr:  ErrInvalidExtensions,
		},
		{
			name: "extension data flag set with no extension bytes after attested credential data",
			authData: buildAuthData(FlagAttestedCredentialData|FlagExtensionData,
				attestedCredData(len(credentialID), credentialID, coseKey), nil),
			wantErr: ErrInvalidExtensions,
		},
		{
			name:     "extension map truncated",
			authData: buildAuthData(FlagExtensionData, nil, extensionMap[:len(extensionMap)-1]),
			wantErr:  ErrInvalidExtensions,
		},
		{
			name:     "extension map is not a map",
			authData: buildAuthData(FlagExtensionData, nil, ctap2Encode(t, []string{ExtensionHMACSecret})),
			wantErr:  ErrInvalidExtensions,
		},
		{
			name:     "extension map is CBOR null",
			authData: buildAuthData(FlagExtensionData, nil, []byte{0xF6}),
			wantErr:  ErrInvalidExtensions,
		},
		{
			name:     "extension map uses an indefinite length",
			authData: buildAuthData(FlagExtensionData, nil, []byte{0xBF, 0x61, 0x61, 0xF5, 0xFF}),
			wantErr:  ErrInvalidExtensions,
		},
		{
			name: "extension map has duplicate keys",
			// {"a": true, "a": false}
			authData: buildAuthData(FlagExtensionData, nil, []byte{0xA2, 0x61, 0x61, 0xF5, 0x61, 0x61, 0xF4}),
			wantErr:  ErrInvalidExtensions,
		},
		{
			name:     "extension map has a non text string key",
			authData: buildAuthData(FlagExtensionData, nil, ctap2Encode(t, map[int]bool{1: true})),
			wantErr:  ErrInvalidExtensions,
		},
		{
			name:     "trailing bytes after the extension map",
			authData: buildAuthData(FlagExtensionData, nil, append(append([]byte{}, extensionMap...), 0x00, 0x00)),
			wantErr:  ErrAuthDataTrailingBytes,
		},
		{
			name: "zero filled buffer with AT and ED flags",
			// The COSE key position holds CBOR unsigned zero, which is
			// well-formed but is not a COSE_Key map.
			authData: func() []byte {
				b := make([]byte, 100)
				b[authDataRPIDHashLen] = FlagAttestedCredentialData | FlagExtensionData
				binary.BigEndian.PutUint16(b[53:55], 16)
				return b
			}(),
			wantErr: ErrInvalidCOSEKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extensions, err := ParseAuthDataExtensions(tt.authData)
			require.Error(t, err, "malformed authenticator data must never parse cleanly")
			assert.ErrorIs(t, err, tt.wantErr)
			assert.Nil(t, extensions)
		})
	}
}

// TestParseAuthDataExtensions_ErrorsAreDistinct guards against the sentinel
// errors collapsing onto one another, since callers switch on them.
func TestParseAuthDataExtensions_ErrorsAreDistinct(t *testing.T) {
	sentinels := []error{
		ErrAuthDataTooShort,
		ErrInvalidAttestedCredentialData,
		ErrInvalidCOSEKey,
		ErrInvalidExtensions,
		ErrAuthDataTrailingBytes,
	}

	seen := make(map[string]bool, len(sentinels))
	for _, err := range sentinels {
		require.NotEmpty(t, err.Error())
		assert.False(t, seen[err.Error()], "duplicate sentinel message: %s", err.Error())
		seen[err.Error()] = true
	}
}

// TestParseAuthDataExtensions_TruncationAtEveryOffset asserts the parser
// never panics and never reports success for a prefix of valid
// authenticator data, which is the shape a partial USB HID read produces.
func TestParseAuthDataExtensions_TruncationAtEveryOffset(t *testing.T) {
	authData := buildAuthData(
		FlagUserPresent|FlagAttestedCredentialData|FlagExtensionData,
		validAttestedCredData(t),
		ctap2Encode(t, map[string]interface{}{ExtensionHMACSecret: bytes.Repeat([]byte{0x7F}, 32)}),
	)

	for cut := 0; cut < len(authData); cut++ {
		extensions, err := ParseAuthDataExtensions(authData[:cut])
		require.Error(t, err, "truncated at %d bytes must fail", cut)
		assert.Nil(t, extensions)
	}

	extensions, err := ParseAuthDataExtensions(authData)
	require.NoError(t, err)
	assert.Len(t, extensions, 1)
}

// TestParseAuthDataExtensions_DoesNotAliasInput verifies the returned
// extension values are decoded copies, so a caller holding the map cannot
// be affected by later reuse of the authenticator data buffer.
func TestParseAuthDataExtensions_DoesNotAliasInput(t *testing.T) {
	hmacOutput := bytes.Repeat([]byte{0x7F}, 32)
	authData := buildAuthData(
		FlagExtensionData,
		nil,
		ctap2Encode(t, map[string]interface{}{ExtensionHMACSecret: hmacOutput}),
	)

	extensions, err := ParseAuthDataExtensions(authData)
	require.NoError(t, err)

	output := extensions[ExtensionHMACSecret].([]byte)
	require.Equal(t, hmacOutput, output)

	for i := range authData {
		authData[i] = 0xFF
	}
	assert.Equal(t, hmacOutput, output, "decoded extension output must not alias the input buffer")
}

// TestMustDecMode_InvalidOptions verifies the decode mode builder rejects
// invalid options rather than returning a silently degraded decoder.
func TestMustDecMode_InvalidOptions(t *testing.T) {
	assert.Panics(t, func() {
		mustDecMode(cbor.DecOptions{MaxNestedLevels: -1})
	})

	assert.NotPanics(t, func() {
		assert.NotNil(t, mustDecMode(cbor.DecOptions{}))
	})
}

// TestIsCBORMap verifies the major type check used to reject COSE keys and
// extension payloads that are well-formed CBOR but the wrong type.
func TestIsCBORMap(t *testing.T) {
	tests := []struct {
		name string
		raw  cbor.RawMessage
		want bool
	}{
		{name: "empty", raw: nil, want: false},
		{name: "unsigned int", raw: cbor.RawMessage{0x00}, want: false},
		{name: "byte string", raw: cbor.RawMessage{0x41, 0x00}, want: false},
		{name: "text string", raw: cbor.RawMessage{0x61, 0x61}, want: false},
		{name: "array", raw: cbor.RawMessage{0x80}, want: false},
		{name: "empty map", raw: cbor.RawMessage{0xA0}, want: true},
		{name: "one entry map", raw: cbor.RawMessage{0xA1, 0x01, 0x02}, want: true},
		{name: "indefinite length map header", raw: cbor.RawMessage{0xBF}, want: true},
		{name: "tag", raw: cbor.RawMessage{0xC0}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isCBORMap(tt.raw))
		})
	}
}

// TestDecodeItem verifies the single-item decoder reports the exact byte
// span it consumed, which is what lets the parser skip the COSE key.
func TestDecodeItem(t *testing.T) {
	t.Run("reports consumed bytes and leaves the remainder", func(t *testing.T) {
		item := ctap2Encode(t, map[string]interface{}{"a": true})
		input := append(append([]byte{}, item...), 0xDE, 0xAD)

		raw, consumed, err := decodeItem(input)
		require.NoError(t, err)
		assert.Equal(t, len(item), consumed)
		assert.Equal(t, cbor.RawMessage(item), raw)
	})

	t.Run("rejects empty input", func(t *testing.T) {
		raw, consumed, err := decodeItem(nil)
		assert.ErrorIs(t, err, ErrCBORTruncated)
		assert.Nil(t, raw)
		assert.Zero(t, consumed)
	})

	t.Run("rejects a truncated item", func(t *testing.T) {
		_, _, err := decodeItem([]byte{0xA1, 0x61})
		assert.Error(t, err)
	})
}
