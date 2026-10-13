// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC

package tpm2

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// TestLoadRejectsSealedObject pins which TPM2_Load failures blame the sealed
// object. The response codes are the wire values the reference simulator
// returns (see sealed_data_authentication_simulator_test.go) and the
// authorization and resource codes a real TPM returns instead.
func TestLoadRejectsSealedObject(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"TPM_RC_INTEGRITY on inPrivate", tpm2.TPMRC(0x1df), true},
		{"TPM_RC_INSUFFICIENT on inPublic", tpm2.TPMRC(0x2da), true},
		{"TPM_RC_SIZE on inPublic", tpm2.TPMRC(0x2d5), true},
		{"TPM_RC_BINDING on inPublic", tpm2.TPMRC(0x2e5), true},
		{"TPM_RC_SENSITIVE", tpm2.TPMRCSensitive, true},
		{"area larger than any TPM creates", checkLoadAreaSizes(make([]byte, maxLoadAreaSize+1), nil), true},
		{"wrapped TPM_RC_INTEGRITY", &errs.Wrapped{Msg: "load", Err: tpm2.TPMRC(0x1df)}, true},
		{"TPM_RC_AUTH_FAIL on session 1", tpm2.TPMRC(0x98e), false},
		{"TPM_RC_POLICY_FAIL on session 1", tpm2.TPMRC(0x99d), false},
		{"TPM_RC_HANDLE on the parent", tpm2.TPMRC(0x18b), false},
		{"TPM_RC_LOCKOUT", tpm2.TPMRCLockout, false},
		{"TPM_RC_OBJECT_MEMORY", tpm2.TPMRCObjectMemory, false},
		{"TPM_RC_RETRY", tpm2.TPMRCRetry, false},
		{"TPM_RC_FAILURE", tpm2.TPMRCFailure, false},
		{"blob not found", store.ErrBlobNotFound, false},
		{"transport", errors.New("read /dev/tpmrm0: device not configured"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, loadRejectsSealedObject(tc.err))

			classified := classifyLoadError(tc.err)
			require.ErrorIs(t, classified, tc.err, "the native cause must stay reachable")
			require.Equal(t, tc.want, errors.Is(classified, types.ErrSealedDataAuthentication))
			require.Equal(t, tc.want, errors.Is(classified, ErrSealedObjectRejected))
		})
	}
}

// TestSealAADBinding_RoundTrip proves a secret bound to AAD opens only for
// that AAD, and that a secret sealed without AAD opens only without it.
func TestSealAADBinding_RoundTrip(t *testing.T) {
	aad := []byte("volume=root")
	data := []byte("root key")

	bound, owned, err := bindSealAAD(rand.Reader, data, aad)
	require.NoError(t, err)
	require.True(t, owned)
	require.Len(t, bound, sealedAADHeaderSize+len(data))

	got, err := openSealAAD(bytes.Clone(bound), aad)
	require.NoError(t, err)
	require.Equal(t, data, got)

	for name, presented := range map[string][]byte{"wrong AAD": []byte("volume=evil"), "no AAD": nil} {
		t.Run(name, func(t *testing.T) {
			_, err := openSealAAD(bytes.Clone(bound), presented)
			require.ErrorIs(t, err, types.ErrSealedDataAuthentication)
		})
	}

	t.Run("truncated binding", func(t *testing.T) {
		_, err := openSealAAD(bytes.Clone(bound[:sealedAADHeaderSize-1]), aad)
		require.ErrorIs(t, err, types.ErrSealedDataAuthentication)
	})

	t.Run("no AAD is unchanged", func(t *testing.T) {
		plain, owned, err := bindSealAAD(rand.Reader, data, nil)
		require.NoError(t, err)
		require.False(t, owned)
		require.Equal(t, data, plain, "a seal without AAD keeps the format earlier builds wrote")

		got, err := openSealAAD(bytes.Clone(plain), nil)
		require.NoError(t, err)
		require.Equal(t, data, got)

		_, err = openSealAAD(bytes.Clone(plain), aad)
		require.ErrorIs(t, err, types.ErrSealedDataAuthentication)
	})

	t.Run("data that begins with the magic is wrapped", func(t *testing.T) {
		tricky := append(bytes.Clone(sealedAADMagic), []byte("payload")...)
		wrapped, owned, err := bindSealAAD(rand.Reader, tricky, nil)
		require.NoError(t, err)
		require.True(t, owned)
		got, err := openSealAAD(wrapped, nil)
		require.NoError(t, err)
		require.Equal(t, tricky, got)
	})
}

// errShortRead is a random source that fails.
var errShortRead = errors.New("entropy source failed")

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errShortRead }

// TestSealAADBinding_Refusals proves the binding refuses data it cannot fit
// and surfaces a failing random source for a nil-data seal.
func TestSealAADBinding_Refusals(t *testing.T) {
	_, _, err := bindSealAAD(rand.Reader, make([]byte, maxSealedDataSize-sealedAADHeaderSize+1), []byte("aad"))
	require.ErrorIs(t, err, ErrSealAADTooLarge)

	fits, _, err := bindSealAAD(rand.Reader, make([]byte, maxSealedDataSize-sealedAADHeaderSize), []byte("aad"))
	require.NoError(t, err)
	require.Len(t, fits, maxSealedDataSize)

	_, _, err = bindSealAAD(failingReader{}, nil, []byte("aad"))
	require.ErrorIs(t, err, errShortRead)

	random, _, err := bindSealAAD(rand.Reader, nil, []byte("aad"))
	require.NoError(t, err)
	require.Len(t, random, sealedAADHeaderSize+32)
}

// TestCheckLoadAreaSizes pins the bounds: each area up to maxLoadAreaSize
// and both together up to maxLoadAreasSize pass; one byte more on either
// area, or on the pair, is refused.
func TestCheckLoadAreaSizes(t *testing.T) {
	require.NoError(t, checkLoadAreaSizes(make([]byte, maxLoadAreaSize), make([]byte, maxLoadAreasSize-maxLoadAreaSize)))
	require.NoError(t, checkLoadAreaSizes(make([]byte, maxLoadAreasSize-maxLoadAreaSize), make([]byte, maxLoadAreaSize)))
	require.ErrorIs(t, checkLoadAreaSizes(make([]byte, maxLoadAreaSize+1), nil), ErrObjectAreaTooLarge)
	require.ErrorIs(t, checkLoadAreaSizes(nil, make([]byte, maxLoadAreaSize+1)), ErrObjectAreaTooLarge)
	require.ErrorIs(t, checkLoadAreaSizes(make([]byte, maxLoadAreaSize), make([]byte, maxLoadAreasSize-maxLoadAreaSize+1)), ErrObjectAreaTooLarge)
	require.ErrorIs(t, checkLoadAreaSizes(make([]byte, maxLoadAreaSize), make([]byte, maxLoadAreaSize)), ErrObjectAreaTooLarge,
		"two maximal areas no longer fit one TPM2_Load command")
}

// TestUnsealRejectsObject pins which TPM2_Unseal failures say the object is
// not sealed data: TPM_RC_TYPE or TPM_RC_ATTRIBUTES on handle 1 only. Every
// authorization failure is session-scoped and must not match.
func TestUnsealRejectsObject(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"TPM_RC_TYPE on the item handle", tpm2.TPMRC(0x18a), true},
		{"TPM_RC_ATTRIBUTES on the item handle", tpm2.TPMRC(0x182), true},
		{"wrapped TPM_RC_TYPE on the item handle", &errs.Wrapped{Msg: "unseal", Err: tpm2.TPMRC(0x18a)}, true},
		{"TPM_RC_TYPE on handle 2", tpm2.TPMRC(0x28a), false},
		{"TPM_RC_TYPE on parameter 1", tpm2.TPMRC(0x1ca), false},
		{"TPM_RC_HANDLE on the item handle", tpm2.TPMRC(0x18b), false},
		{"TPM_RC_POLICY_FAIL on session 1", tpm2.TPMRC(0x99d), false},
		{"TPM_RC_AUTH_FAIL on session 1", tpm2.TPMRC(0x98e), false},
		{"TPM_RC_BAD_AUTH on session 1", tpm2.TPMRC(0x9a2), false},
		{"TPM_RC_LOCKOUT", tpm2.TPMRCLockout, false},
		{"transport", errors.New("broken pipe"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, unsealRejectsObject(tc.err))
			classified := classifyUnsealError(tc.err)
			require.ErrorIs(t, classified, tc.err)
			require.Equal(t, tc.want, errors.Is(classified, types.ErrSealedDataAuthentication))
		})
	}
}
