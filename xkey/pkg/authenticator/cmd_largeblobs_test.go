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

package authenticator

import (
	"crypto/hmac"
	"crypto/sha256"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// createTestAuthenticatorWithLargeBlobs builds an authenticator with
// authenticatorLargeBlobs enabled and a small MaxLargeBlobArray so storage
// limit tests do not need large payloads. enablePIN controls whether a PIN
// (and therefore write authentication) is configured.
func createTestAuthenticatorWithLargeBlobs(t *testing.T, enablePIN bool) *Authenticator {
	t.Helper()

	config := DefaultConfig()
	config.UserPresenceHandler = NewAutoGrantHandler()
	config.Storage = NewMemoryStorage()
	config.EnableLargeBlobs = true
	config.MaxLargeBlobArray = 128
	config.EnablePIN = enablePIN

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	return auth
}

// largeBlobsSetRequest builds a CBOR-encoded authenticatorLargeBlobs Set
// request. length and pinUvAuthParam/Protocol are only included when non-nil
// so tests can exercise the "missing field" paths.
func largeBlobsSetRequest(t *testing.T, offset uint32, fragment []byte, length *uint32, pinUvAuthParam []byte, pinUvAuthProtocol uint8) []byte {
	t.Helper()

	req := map[int]interface{}{
		largeBlobsKeySet:    fragment,
		largeBlobsKeyOffset: offset,
	}
	if length != nil {
		req[largeBlobsKeyLength] = *length
	}
	if pinUvAuthParam != nil {
		req[largeBlobsKeyPinUvAuthParam] = pinUvAuthParam
		req[largeBlobsKeyPinUvAuthProtocol] = pinUvAuthProtocol
	}

	data, err := cbor.Marshal(req)
	require.NoError(t, err)
	return data
}

// largeBlobsGetRequest builds a CBOR-encoded authenticatorLargeBlobs Get
// request.
func largeBlobsGetRequest(t *testing.T, get, offset uint32) []byte {
	t.Helper()

	req := map[int]interface{}{
		largeBlobsKeyGet:    get,
		largeBlobsKeyOffset: offset,
	}
	data, err := cbor.Marshal(req)
	require.NoError(t, err)
	return data
}

// decodeLargeBlobsGetResponse extracts the fragment from a successful Get
// response.
func decodeLargeBlobsGetResponse(t *testing.T, resp []byte) []byte {
	t.Helper()

	require.Equal(t, byte(StatusOK), resp[0])
	var respMap map[int]interface{}
	require.NoError(t, cbor.Unmarshal(resp[1:], &respMap))

	fragment, ok := respMap[largeBlobsResponseKeyFragment].([]byte)
	require.True(t, ok, "response missing large blob fragment")
	return fragment
}

// buildValidArray returns a serialized large blob array (arbitrary payload
// of the requested length, followed by its truncated SHA-256 checksum) that
// passes validateSerializedLargeBlobArray. total must be at least
// minSerializedLargeBlobArray.
func buildValidArray(total int) []byte {
	payload := make([]byte, total-largeBlobChecksumLength)
	for i := range payload {
		payload[i] = byte(i)
	}
	sum := sha256.Sum256(payload)
	return append(payload, sum[:largeBlobChecksumLength]...)
}

// TestLargeBlobs_Disabled_ReturnsNotImplemented proves the command is
// unreachable unless EnableLargeBlobs is set, mirroring every other
// optional-feature gate in this package.
func TestLargeBlobs_Disabled_ReturnsNotImplemented(t *testing.T) {
	auth := createTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	_, err := auth.ProcessCBOR(CmdLargeBlobs, nil)
	require.ErrorIs(t, err, ErrNotImplemented)
}

// TestLargeBlobs_GetInitialArray proves that before any Set has completed,
// Get returns the CTAP 2.1 §6.10.2-defined initial (empty) serialized large
// blob array, unauthenticated.
func TestLargeBlobs_GetInitialArray(t *testing.T) {
	auth := createTestAuthenticatorWithLargeBlobs(t, false)
	defer func() { _ = auth.Close() }()

	resp, err := auth.ProcessCBOR(CmdLargeBlobs, largeBlobsGetRequest(t, 64, 0))
	require.NoError(t, err)

	fragment := decodeLargeBlobsGetResponse(t, resp)
	require.Equal(t, initialLargeBlobArray(), fragment)
	require.NoError(t, validateSerializedLargeBlobArray(fragment))
}

// TestLargeBlobs_SetGet_SingleFragment_RoundTrip proves a Set that fits in
// one fragment can be read back byte-for-byte via Get.
func TestLargeBlobs_SetGet_SingleFragment_RoundTrip(t *testing.T) {
	auth := createTestAuthenticatorWithLargeBlobs(t, false)
	defer func() { _ = auth.Close() }()

	array := buildValidArray(40)
	length := uint32(len(array))

	setResp, err := auth.ProcessCBOR(CmdLargeBlobs, largeBlobsSetRequest(t, 0, array, &length, nil, 0))
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), setResp[0])

	getResp, err := auth.ProcessCBOR(CmdLargeBlobs, largeBlobsGetRequest(t, uint32(len(array)), 0))
	require.NoError(t, err)
	require.Equal(t, array, decodeLargeBlobsGetResponse(t, getResp))
}

// TestLargeBlobs_SetGet_MultiFragment_RoundTrip proves a Set spread across
// two fragments assembles correctly, and that Get in turn can be read back
// across two fragments.
func TestLargeBlobs_SetGet_MultiFragment_RoundTrip(t *testing.T) {
	auth := createTestAuthenticatorWithLargeBlobs(t, false)
	defer func() { _ = auth.Close() }()

	array := buildValidArray(60)
	length := uint32(len(array))
	first, second := array[:30], array[30:]

	resp, err := auth.ProcessCBOR(CmdLargeBlobs, largeBlobsSetRequest(t, 0, first, &length, nil, 0))
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	resp, err = auth.ProcessCBOR(CmdLargeBlobs, largeBlobsSetRequest(t, uint32(len(first)), second, nil, nil, 0))
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	// Read it back across two Get fragments.
	getResp, err := auth.ProcessCBOR(CmdLargeBlobs, largeBlobsGetRequest(t, 30, 0))
	require.NoError(t, err)
	part1 := decodeLargeBlobsGetResponse(t, getResp)

	getResp, err = auth.ProcessCBOR(CmdLargeBlobs, largeBlobsGetRequest(t, 30, 30))
	require.NoError(t, err)
	part2 := decodeLargeBlobsGetResponse(t, getResp)

	require.Equal(t, array, append(part1, part2...))
}

// TestLargeBlobs_Get_OffsetOutOfRange proves a Get whose offset lies beyond
// the stored array is refused rather than silently returning nothing.
func TestLargeBlobs_Get_OffsetOutOfRange(t *testing.T) {
	auth := createTestAuthenticatorWithLargeBlobs(t, false)
	defer func() { _ = auth.Close() }()

	_, err := auth.ProcessCBOR(CmdLargeBlobs, largeBlobsGetRequest(t, 16, 1000))
	require.ErrorIs(t, err, ErrLargeBlobsInvalidOffset)
	require.Equal(t, byte(StatusInvalidParameter), errorToStatus(err))
}

// TestLargeBlobs_Get_InvalidLength proves a Get requesting more than the
// authenticator's fragment limit is refused.
func TestLargeBlobs_Get_InvalidLength(t *testing.T) {
	auth := createTestAuthenticatorWithLargeBlobs(t, false)
	defer func() { _ = auth.Close() }()

	tooLarge := auth.maxLargeBlobFragmentLength() + 1
	_, err := auth.ProcessCBOR(CmdLargeBlobs, largeBlobsGetRequest(t, tooLarge, 0))
	require.ErrorIs(t, err, ErrLargeBlobsInvalidLength)
	require.Equal(t, byte(StatusInvalidLength), errorToStatus(err))
}

// TestLargeBlobs_Get_ZeroLength_Succeeds proves CTAP 2.1 §6.10.2 permits a
// zero-length get: it is a valid request for an empty substring, not an
// error, and must not be confused with a get exceeding the fragment limit.
func TestLargeBlobs_Get_ZeroLength_Succeeds(t *testing.T) {
	auth := createTestAuthenticatorWithLargeBlobs(t, false)
	defer func() { _ = auth.Close() }()

	resp, err := auth.ProcessCBOR(CmdLargeBlobs, largeBlobsGetRequest(t, 0, 0))
	require.NoError(t, err)
	require.Empty(t, decodeLargeBlobsGetResponse(t, resp))
}

// TestLargeBlobs_Get_RejectsLength proves a Get carrying the Set-only length
// parameter is refused with CTAP1_ERR_INVALID_PARAMETER rather than silently
// ignored.
func TestLargeBlobs_Get_RejectsLength(t *testing.T) {
	auth := createTestAuthenticatorWithLargeBlobs(t, false)
	defer func() { _ = auth.Close() }()

	req := map[int]interface{}{
		largeBlobsKeyGet:    uint32(16),
		largeBlobsKeyOffset: uint32(0),
		largeBlobsKeyLength: uint32(32),
	}
	data, err := cbor.Marshal(req)
	require.NoError(t, err)

	_, err = auth.ProcessCBOR(CmdLargeBlobs, data)
	require.ErrorIs(t, err, ErrInvalidParameter)
	require.Equal(t, byte(StatusInvalidParameter), errorToStatus(err))
}

// TestLargeBlobs_Get_RejectsPinUvAuthParams proves a Get carrying the
// Set-only pinUvAuthParam/pinUvAuthProtocol parameters is refused with
// CTAP1_ERR_INVALID_PARAMETER.
func TestLargeBlobs_Get_RejectsPinUvAuthParams(t *testing.T) {
	auth := createTestAuthenticatorWithLargeBlobs(t, false)
	defer func() { _ = auth.Close() }()

	req := map[int]interface{}{
		largeBlobsKeyGet:               uint32(16),
		largeBlobsKeyOffset:            uint32(0),
		largeBlobsKeyPinUvAuthParam:    make([]byte, PINAuthSizeV1),
		largeBlobsKeyPinUvAuthProtocol: uint8(PINProtocol1),
	}
	data, err := cbor.Marshal(req)
	require.NoError(t, err)

	_, err = auth.ProcessCBOR(CmdLargeBlobs, data)
	require.ErrorIs(t, err, ErrInvalidParameter)
	require.Equal(t, byte(StatusInvalidParameter), errorToStatus(err))
}

// TestLargeBlobs_Set_MissingLengthAtOffsetZero proves the first fragment of a
// write must declare the total length.
func TestLargeBlobs_Set_MissingLengthAtOffsetZero(t *testing.T) {
	auth := createTestAuthenticatorWithLargeBlobs(t, false)
	defer func() { _ = auth.Close() }()

	_, err := auth.ProcessCBOR(CmdLargeBlobs, largeBlobsSetRequest(t, 0, []byte("fragment"), nil, nil, 0))
	require.ErrorIs(t, err, ErrLargeBlobsMissingLength)
	require.Equal(t, byte(StatusInvalidParameter), errorToStatus(err))
}

// TestLargeBlobs_Set_TruncatedArray_TooShort proves a declared total length
// too small to hold even the empty array's checksum is rejected immediately,
// before any fragment is accepted.
func TestLargeBlobs_Set_TruncatedArray_TooShort(t *testing.T) {
	auth := createTestAuthenticatorWithLargeBlobs(t, false)
	defer func() { _ = auth.Close() }()

	length := uint32(minSerializedLargeBlobArray - 1)
	_, err := auth.ProcessCBOR(CmdLargeBlobs, largeBlobsSetRequest(t, 0, []byte{0x01}, &length, nil, 0))
	require.ErrorIs(t, err, ErrLargeBlobsInvalidLength)
	require.Equal(t, byte(StatusInvalidLength), errorToStatus(err))
}

// TestLargeBlobs_Set_LengthExceedsStorage proves a declared total length
// beyond the authenticator's configured storage limit is refused with
// CTAP2_ERR_LARGE_BLOB_STORAGE_FULL.
func TestLargeBlobs_Set_LengthExceedsStorage(t *testing.T) {
	auth := createTestAuthenticatorWithLargeBlobs(t, false)
	defer func() { _ = auth.Close() }()

	length := uint32(auth.config.MaxLargeBlobArray + 1)
	_, err := auth.ProcessCBOR(CmdLargeBlobs, largeBlobsSetRequest(t, 0, []byte{0x01}, &length, nil, 0))
	require.ErrorIs(t, err, ErrLargeBlobsStorageFull)
	require.Equal(t, byte(StatusLargeBlobStorageFull), errorToStatus(err))
}

// TestLargeBlobs_Set_UnexpectedOffset proves a non-zero-offset fragment that
// does not continue an in-progress write — whether none is in progress, or
// the offset skips or repeats bytes — is refused rather than silently
// accepted at the wrong position.
func TestLargeBlobs_Set_UnexpectedOffset(t *testing.T) {
	auth := createTestAuthenticatorWithLargeBlobs(t, false)
	defer func() { _ = auth.Close() }()

	// No write in progress at all.
	_, err := auth.ProcessCBOR(CmdLargeBlobs, largeBlobsSetRequest(t, 10, []byte("x"), nil, nil, 0))
	require.ErrorIs(t, err, ErrLargeBlobsInvalidSeq)
	require.Equal(t, byte(StatusInvalidSeq), errorToStatus(err))

	// Start a write expecting the next fragment at offset 30.
	array := buildValidArray(60)
	length := uint32(len(array))
	_, err = auth.ProcessCBOR(CmdLargeBlobs, largeBlobsSetRequest(t, 0, array[:30], &length, nil, 0))
	require.NoError(t, err)

	// Wrong offset: skips ahead.
	_, err = auth.ProcessCBOR(CmdLargeBlobs, largeBlobsSetRequest(t, 35, array[35:], nil, nil, 0))
	require.ErrorIs(t, err, ErrLargeBlobsInvalidSeq)
}

// TestLargeBlobs_Set_FragmentOverflowsDeclaredLength proves a fragment that
// would extend the accumulated write past the declared total length is
// refused rather than silently truncated or overrun.
func TestLargeBlobs_Set_FragmentOverflowsDeclaredLength(t *testing.T) {
	auth := createTestAuthenticatorWithLargeBlobs(t, false)
	defer func() { _ = auth.Close() }()

	length := uint32(40)
	_, err := auth.ProcessCBOR(CmdLargeBlobs, largeBlobsSetRequest(t, 0, make([]byte, 30), &length, nil, 0))
	require.NoError(t, err)

	// 30 bytes already received; this fragment claims 20 more, totaling 50 > 40.
	_, err = auth.ProcessCBOR(CmdLargeBlobs, largeBlobsSetRequest(t, 30, make([]byte, 20), nil, nil, 0))
	require.ErrorIs(t, err, ErrLargeBlobsSetExceedsLength)
	require.Equal(t, byte(StatusInvalidParameter), errorToStatus(err))
}

// TestLargeBlobs_Set_NonZeroOffsetRejectsLength proves a non-zero-offset
// fragment carrying the offset-0-only length parameter is refused with
// CTAP1_ERR_INVALID_PARAMETER rather than silently ignored.
func TestLargeBlobs_Set_NonZeroOffsetRejectsLength(t *testing.T) {
	auth := createTestAuthenticatorWithLargeBlobs(t, false)
	defer func() { _ = auth.Close() }()

	array := buildValidArray(60)
	length := uint32(len(array))
	_, err := auth.ProcessCBOR(CmdLargeBlobs, largeBlobsSetRequest(t, 0, array[:30], &length, nil, 0))
	require.NoError(t, err)

	secondLength := uint32(len(array))
	_, err = auth.ProcessCBOR(CmdLargeBlobs, largeBlobsSetRequest(t, 30, array[30:], &secondLength, nil, 0))
	require.ErrorIs(t, err, ErrInvalidParameter)
	require.Equal(t, byte(StatusInvalidParameter), errorToStatus(err))
}

// TestLargeBlobs_Set_BadChecksum proves a completed write whose trailing
// checksum does not match its payload is rejected and never becomes the
// stored array.
func TestLargeBlobs_Set_BadChecksum(t *testing.T) {
	auth := createTestAuthenticatorWithLargeBlobs(t, false)
	defer func() { _ = auth.Close() }()

	array := buildValidArray(40)
	array[len(array)-1] ^= 0xFF // corrupt the checksum
	length := uint32(len(array))

	_, err := auth.ProcessCBOR(CmdLargeBlobs, largeBlobsSetRequest(t, 0, array, &length, nil, 0))
	require.ErrorIs(t, err, ErrLargeBlobsChecksumInvalid)
	require.Equal(t, byte(StatusIntegrityFailure), errorToStatus(err))

	// The bad write must not have replaced the stored array.
	getResp, err := auth.ProcessCBOR(CmdLargeBlobs, largeBlobsGetRequest(t, 64, 0))
	require.NoError(t, err)
	require.Equal(t, initialLargeBlobArray(), decodeLargeBlobsGetResponse(t, getResp))
}

// TestLargeBlobs_Set_MissingAuthWhenPINSet proves that once a PIN is set, a
// Set fragment with no pinUvAuthParam is refused rather than applied
// unauthenticated.
func TestLargeBlobs_Set_MissingAuthWhenPINSet(t *testing.T) {
	auth := createTestAuthenticatorWithLargeBlobs(t, true)
	defer func() { _ = auth.Close() }()
	require.NoError(t, auth.SetInitialPIN("1234"))

	array := buildValidArray(40)
	length := uint32(len(array))

	_, err := auth.ProcessCBOR(CmdLargeBlobs, largeBlobsSetRequest(t, 0, array, &length, nil, 0))
	require.ErrorIs(t, err, ErrPINRequired)
	require.Equal(t, byte(StatusPINRequired), errorToStatus(err))
}

// TestLargeBlobs_Set_InvalidAuthParam proves a syntactically present but
// wrong pinUvAuthParam is refused with CTAP2_ERR_PIN_AUTH_INVALID, and that a
// token lacking the lbw permission is refused the same way.
func TestLargeBlobs_Set_InvalidAuthParam(t *testing.T) {
	auth := createTestAuthenticatorWithLargeBlobs(t, true)
	defer func() { _ = auth.Close() }()
	require.NoError(t, auth.SetInitialPIN("1234"))

	array := buildValidArray(40)
	length := uint32(len(array))

	t.Run("garbage HMAC", func(t *testing.T) {
		garbage := make([]byte, PINAuthSizeV1)
		_, err := auth.ProcessCBOR(CmdLargeBlobs,
			largeBlobsSetRequest(t, 0, array, &length, garbage, PINProtocol1))
		require.ErrorIs(t, err, ErrPINAuthInvalid)
		require.Equal(t, byte(StatusPINAuthInvalid), errorToStatus(err))
	})

	t.Run("token missing lbw permission", func(t *testing.T) {
		token := authzTestToken()
		auth.mu.Lock()
		auth.pinState.protocol = livePinTokenGrant(token, PINPermissionMakeCredential)
		auth.mu.Unlock()

		authParam := hmacTruncated(token, largeBlobsPinAuthMessage(0, array))
		_, err := auth.ProcessCBOR(CmdLargeBlobs,
			largeBlobsSetRequest(t, 0, array, &length, authParam, PINProtocol1))
		require.ErrorIs(t, err, ErrPINAuthInvalid)
	})
}

// TestLargeBlobs_Set_ValidAuth_Succeeds proves a Set fragment carrying a
// correctly computed pinUvAuthParam, from a token holding the lbw permission,
// is accepted and stored.
func TestLargeBlobs_Set_ValidAuth_Succeeds(t *testing.T) {
	auth := createTestAuthenticatorWithLargeBlobs(t, true)
	defer func() { _ = auth.Close() }()
	require.NoError(t, auth.SetInitialPIN("1234"))

	token := authzTestToken()
	auth.mu.Lock()
	auth.pinState.protocol = livePinTokenGrant(token, PINPermissionLargeBlobWrite)
	auth.mu.Unlock()

	array := buildValidArray(40)
	length := uint32(len(array))
	authParam := hmacTruncated(token, largeBlobsPinAuthMessage(0, array))

	resp, err := auth.ProcessCBOR(CmdLargeBlobs,
		largeBlobsSetRequest(t, 0, array, &length, authParam, PINProtocol1))
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	getResp, err := auth.ProcessCBOR(CmdLargeBlobs, largeBlobsGetRequest(t, uint32(len(array)), 0))
	require.NoError(t, err)
	require.Equal(t, array, decodeLargeBlobsGetResponse(t, getResp))
}

// TestLargeBlobs_GetSetConflict proves that a request naming neither, or
// both, of get and set is refused rather than guessing the caller's intent.
func TestLargeBlobs_GetSetConflict(t *testing.T) {
	auth := createTestAuthenticatorWithLargeBlobs(t, false)
	defer func() { _ = auth.Close() }()

	neither := map[int]interface{}{largeBlobsKeyOffset: uint32(0)}
	data, err := cbor.Marshal(neither)
	require.NoError(t, err)
	_, err = auth.ProcessCBOR(CmdLargeBlobs, data)
	require.ErrorIs(t, err, ErrLargeBlobsGetSetConflict)

	both := map[int]interface{}{
		largeBlobsKeyGet:    uint32(16),
		largeBlobsKeySet:    []byte("x"),
		largeBlobsKeyOffset: uint32(0),
	}
	data, err = cbor.Marshal(both)
	require.NoError(t, err)
	_, err = auth.ProcessCBOR(CmdLargeBlobs, data)
	require.ErrorIs(t, err, ErrLargeBlobsGetSetConflict)
	require.Equal(t, byte(StatusInvalidParameter), errorToStatus(err))
}

// TestLargeBlobs_MissingOffset proves offset is required on every request,
// per CTAP 2.1 §6.10.1.
func TestLargeBlobs_MissingOffset(t *testing.T) {
	auth := createTestAuthenticatorWithLargeBlobs(t, false)
	defer func() { _ = auth.Close() }()

	req := map[int]interface{}{largeBlobsKeyGet: uint32(16)}
	data, err := cbor.Marshal(req)
	require.NoError(t, err)

	_, err = auth.ProcessCBOR(CmdLargeBlobs, data)
	require.ErrorIs(t, err, ErrLargeBlobsMissingOffset)
	require.Equal(t, byte(StatusInvalidParameter), errorToStatus(err))
}

// TestInitialLargeBlobArray_IsValid proves the spec-defined initial array
// itself satisfies validateSerializedLargeBlobArray, so a fresh
// authenticator's Get response is never rejected by its own validation rule.
func TestInitialLargeBlobArray_IsValid(t *testing.T) {
	array := initialLargeBlobArray()
	require.Len(t, array, minSerializedLargeBlobArray)
	require.NoError(t, validateSerializedLargeBlobArray(array))
}

// TestValidateSerializedLargeBlobArray_TooShort proves data shorter than the
// minimum valid array is rejected without attempting a checksum comparison.
func TestValidateSerializedLargeBlobArray_TooShort(t *testing.T) {
	err := validateSerializedLargeBlobArray(make([]byte, minSerializedLargeBlobArray-1))
	require.ErrorIs(t, err, ErrLargeBlobsInvalidLength)
}

// TestToUint32 exercises the CBOR integer coercion helper with both valid and
// invalid inputs.
func TestToUint32(t *testing.T) {
	tests := []struct {
		name    string
		in      interface{}
		want    uint32
		wantErr bool
	}{
		{"uint64 in range", uint64(42), 42, false},
		{"int in range", int(7), 7, false},
		{"uint8", uint8(255), 255, false},
		{"negative int rejected", int(-1), 0, true},
		{"negative int64 rejected", int64(-1), 0, true},
		{"uint64 overflow rejected", uint64(1) << 40, 0, true},
		{"unsupported type rejected", "not a number", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := toUint32(tt.in)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// TestLargeBlobsPinAuthMessage_KnownAnswer pins the exact byte layout CTAP
// 2.1 §6.10.2 requires for the pinUvAuthParam authentication message:
//
//	32×0xff || h'0c00' || uint32LittleEndian(offset) || SHA-256(fragment)
//
// so a regression reintroducing the single-byte "0x0c only" bug (fixed here)
// can never again pass silently: any real platform's pinUvAuthParam would
// then be computed over a different message and every write would fail.
func TestLargeBlobsPinAuthMessage_KnownAnswer(t *testing.T) {
	fragment := []byte("known-answer-fragment")
	offset := uint32(0x01020304)

	got := largeBlobsPinAuthMessage(offset, fragment)

	want := make([]byte, 0, 32+2+4+sha256.Size)
	for i := 0; i < 32; i++ {
		want = append(want, 0xFF)
	}
	want = append(want, 0x0c, 0x00)
	want = append(want, 0x04, 0x03, 0x02, 0x01) // uint32LE(0x01020304)
	sum := sha256.Sum256(fragment)
	want = append(want, sum[:]...)

	require.Equal(t, want, got)
	require.Len(t, got, 32+2+4+sha256.Size)
}

// TestLargeBlobs_AlwaysUV_RequiresAuthWithoutPIN proves the alwaysUv option
// forces write authentication even when no PIN is configured at all: CTAP
// 2.1 §6.10.2 requires verification whenever alwaysUv is present and true,
// independent of EnablePIN/IsPINSet.
func TestLargeBlobs_AlwaysUV_RequiresAuthWithoutPIN(t *testing.T) {
	config := DefaultConfig()
	config.UserPresenceHandler = NewAutoGrantHandler()
	config.Storage = NewMemoryStorage()
	config.EnableLargeBlobs = true
	config.MaxLargeBlobArray = 128
	config.EnablePIN = false
	config.AlwaysUV = true

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	require.False(t, auth.IsPINSet())

	array := buildValidArray(40)
	length := uint32(len(array))
	_, err = auth.ProcessCBOR(CmdLargeBlobs, largeBlobsSetRequest(t, 0, array, &length, nil, 0))
	require.ErrorIs(t, err, ErrPINRequired)
	require.Equal(t, byte(StatusPINRequired), errorToStatus(err))
}

// TestLargeBlobs_Set_PinUvAuthProtocol_AbsentVsUnsupported proves an absent
// pinUvAuthProtocol and an unsupported one are reported with different CTAP2
// status codes, per CTAP 2.1 §6.10.2: CTAP2_ERR_MISSING_PARAMETER for the
// former, CTAP1_ERR_INVALID_PARAMETER for the latter.
func TestLargeBlobs_Set_PinUvAuthProtocol_AbsentVsUnsupported(t *testing.T) {
	auth := createTestAuthenticatorWithLargeBlobs(t, true)
	defer func() { _ = auth.Close() }()
	require.NoError(t, auth.SetInitialPIN("1234"))

	array := buildValidArray(40)
	length := uint32(len(array))

	t.Run("absent protocol", func(t *testing.T) {
		req := map[int]interface{}{
			largeBlobsKeySet:            array,
			largeBlobsKeyOffset:         uint32(0),
			largeBlobsKeyLength:         length,
			largeBlobsKeyPinUvAuthParam: make([]byte, PINAuthSizeV1),
		}
		data, err := cbor.Marshal(req)
		require.NoError(t, err)

		_, err = auth.ProcessCBOR(CmdLargeBlobs, data)
		require.ErrorIs(t, err, ErrLargeBlobsMissingPinUvAuthProtocol)
		require.Equal(t, byte(StatusMissingParameter), errorToStatus(err))
	})

	t.Run("unsupported protocol", func(t *testing.T) {
		_, err := auth.ProcessCBOR(CmdLargeBlobs,
			largeBlobsSetRequest(t, 0, array, &length, make([]byte, PINAuthSizeV1), 99))
		require.ErrorIs(t, err, ErrUnsupportedPINProtocol)
		require.Equal(t, byte(StatusInvalidParameter), errorToStatus(err))
	})
}

// TestLargeBlobs_Set_OrderingBeforeAuth proves a request that both violates
// an ordering check (offset/sequence/length) and carries invalid
// authentication reports the ordering failure, matching CTAP 2.1 §6.10.2's
// requirement that those conditions are evaluated before the fragment is
// authenticated.
func TestLargeBlobs_Set_OrderingBeforeAuth(t *testing.T) {
	auth := createTestAuthenticatorWithLargeBlobs(t, true)
	defer func() { _ = auth.Close() }()
	require.NoError(t, auth.SetInitialPIN("1234"))

	token := authzTestToken()
	auth.mu.Lock()
	auth.pinState.protocol = livePinTokenGrant(token, PINPermissionLargeBlobWrite)
	auth.mu.Unlock()

	array := buildValidArray(60)
	length := uint32(40)
	firstFragment := array[:30]
	authParam := hmacTruncated(token, largeBlobsPinAuthMessage(0, firstFragment))

	_, err := auth.ProcessCBOR(CmdLargeBlobs,
		largeBlobsSetRequest(t, 0, firstFragment, &length, authParam, PINProtocol1))
	require.NoError(t, err)

	// This fragment overflows the declared length (an ordering violation) and
	// also carries a garbage pinUvAuthParam (an authentication violation). The
	// ordering error must win.
	garbage := make([]byte, PINAuthSizeV1)
	_, err = auth.ProcessCBOR(CmdLargeBlobs,
		largeBlobsSetRequest(t, 30, array[30:], nil, garbage, PINProtocol1))
	require.ErrorIs(t, err, ErrLargeBlobsSetExceedsLength)
	require.NotErrorIs(t, err, ErrPINAuthInvalid)
}

// hmacTruncated computes the PIN protocol 1 pinUvAuthParam (HMAC-SHA-256
// truncated to 16 bytes) of msg under token, mirroring
// verifyPinUvAuthTokenHMACLocked's V1 branch.
func hmacTruncated(token, msg []byte) []byte {
	mac := hmac.New(sha256.New, token)
	mac.Write(msg)
	return mac.Sum(nil)[:PINAuthSizeV1]
}
