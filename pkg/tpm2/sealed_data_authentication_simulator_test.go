//go:build tpm_simulator
// +build tpm_simulator

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC

package tpm2

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// objectPassword is the UserAuth every password-protected object in these
// tests is sealed with.
var objectPassword = []byte("object-password")

// sealForAuthTest seals plaintext under a password-protected object beneath
// the SSRK and returns the sealed data.
func sealForAuthTest(t *testing.T, h *simHarness, cn string, plaintext, aad []byte) *types.SealedData {
	t.Helper()
	sealed, err := h.TPM.Seal(context.Background(), plaintext, &types.SealOptions{
		KeyAttributes: sealedKeyAttrs(t, h, cn, false, mustPassword(t, objectPassword)),
		AAD:           aad,
	})
	require.NoError(t, err)
	return sealed
}

// unsealOpts builds fresh unseal options for the object cn: Seal and Unseal
// mutate the key attributes they are handed, so each call gets its own.
func unsealOpts(t *testing.T, h *simHarness, cn string, aad []byte) *types.UnsealOptions {
	t.Helper()
	return &types.UnsealOptions{
		KeyAttributes: sealedKeyAttrs(t, h, cn, false, mustPassword(t, objectPassword)),
		AAD:           aad,
	}
}

func cloneTPMSealed(sealed *types.SealedData) *types.SealedData {
	c := *sealed
	c.TPMPublic = bytes.Clone(sealed.TPMPublic)
	c.TPMPrivate = bytes.Clone(sealed.TPMPrivate)
	return &c
}

// TestUnseal_SealedDataAuthentication_Simulator proves every way a sealed
// object can be wrong -- on a real TPM 2.0 (the reference simulator) -- is
// reported as types.ErrSealedDataAuthentication, with TPM2_Load's response
// code still reachable where the TPM refused the object.
func TestUnseal_SealedDataAuthentication_Simulator(t *testing.T) {
	h := newSimHarness(t, nil)
	const cn = "sealed-auth"
	aad := []byte("volume=root")
	sealed := sealForAuthTest(t, h, cn, []byte("tpm sealed root key"), aad)

	other := sealForAuthTest(t, h, "sealed-auth-other", []byte("another object"), nil)

	cases := []struct {
		name     string
		mutate   func(s *types.SealedData) []byte
		rejected bool
	}{
		{"private area bit flipped", func(s *types.SealedData) []byte {
			s.TPMPrivate[len(s.TPMPrivate)-1] ^= 0x01
			return aad
		}, true},
		{"private area integrity HMAC bit flipped", func(s *types.SealedData) []byte {
			s.TPMPrivate[4] ^= 0x80
			return aad
		}, true},
		{"private area truncated", func(s *types.SealedData) []byte {
			s.TPMPrivate = s.TPMPrivate[:len(s.TPMPrivate)-1]
			return aad
		}, true},
		{"private area extended", func(s *types.SealedData) []byte {
			s.TPMPrivate = append(s.TPMPrivate, 0x00)
			return aad
		}, true},
		{"public area bit flipped", func(s *types.SealedData) []byte {
			s.TPMPublic[len(s.TPMPublic)-1] ^= 0x01
			return aad
		}, true},
		{"public area truncated", func(s *types.SealedData) []byte {
			s.TPMPublic = s.TPMPublic[:len(s.TPMPublic)-1]
			return aad
		}, true},
		{"public area extended", func(s *types.SealedData) []byte {
			s.TPMPublic = append(s.TPMPublic, 0x00)
			return aad
		}, true},
		{"public area of another object", func(s *types.SealedData) []byte {
			s.TPMPublic = bytes.Clone(other.TPMPublic)
			return aad
		}, true},
		{"private area of another object", func(s *types.SealedData) []byte {
			s.TPMPrivate = bytes.Clone(other.TPMPrivate)
			return aad
		}, true},
		{"AAD mismatch", func(s *types.SealedData) []byte {
			return []byte("volume=evil")
		}, false},
		{"AAD omitted", func(s *types.SealedData) []byte {
			return nil
		}, false},
		{"wrong backend", func(s *types.SealedData) []byte {
			s.Backend = types.BackendTypePKCS11
			return aad
		}, false},
		{"malformed: private area missing", func(s *types.SealedData) []byte {
			s.TPMPrivate = nil
			return aad
		}, false},
		{"malformed: public area missing", func(s *types.SealedData) []byte {
			s.TPMPublic = nil
			return aad
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := cloneTPMSealed(sealed)
			presentedAAD := tc.mutate(mutated)

			out, err := h.TPM.Unseal(context.Background(), mutated, unsealOpts(t, h, cn, presentedAAD))
			require.Nil(t, out, "bad sealed data must not produce plaintext")
			require.ErrorIs(t, err, types.ErrSealedDataAuthentication)
			require.Equal(t, tc.rejected, errors.Is(err, ErrSealedObjectRejected), "err: %v", err)
			if tc.rejected {
				var rc tpm2.TPMRC
				require.True(t, errors.As(err, &rc), "the TPM response code must stay reachable: %v", err)
			}
		})
	}

	t.Run("object sealed under a different parent", func(t *testing.T) {
		platformSRK := createPlatformPolicySRK(t, h, nil)
		foreign, err := h.TPM.Seal(context.Background(), []byte("under the platform SRK"), &types.SealOptions{
			KeyAttributes: sealedKeyAttrsUnder(platformSRK, "sealed-auth-foreign", mustPassword(t, objectPassword)),
		})
		require.NoError(t, err)

		out, err := h.TPM.Unseal(context.Background(), foreign, unsealOpts(t, h, "sealed-auth-foreign", nil))
		require.Nil(t, out)
		require.ErrorIs(t, err, types.ErrSealedDataAuthentication)
		require.ErrorIs(t, err, ErrSealedObjectRejected)
		require.ErrorIs(t, err, tpm2.TPMRCIntegrity)
	})

	t.Run("sealed without AAD, unsealed with AAD", func(t *testing.T) {
		out, err := h.TPM.Unseal(context.Background(), cloneTPMSealed(other), unsealOpts(t, h, "sealed-auth-other", aad))
		require.Nil(t, out)
		require.ErrorIs(t, err, types.ErrSealedDataAuthentication)
	})

	t.Run("untouched object with its AAD unseals", func(t *testing.T) {
		got, err := h.TPM.Unseal(context.Background(), cloneTPMSealed(sealed), unsealOpts(t, h, cn, aad))
		require.NoError(t, err)
		require.Equal(t, []byte("tpm sealed root key"), got)
	})
}

// TestUnseal_SealedDataAuthentication_FromStorage proves a sealed object
// tampered with in the key store, rather than handed in inline, is reported
// the same way.
func TestUnseal_SealedDataAuthentication_FromStorage(t *testing.T) {
	h := newSimHarness(t, nil)
	const cn = "sealed-auth-stored"
	sealed, err := h.TPM.Seal(context.Background(), []byte("stored secret"), &types.SealOptions{
		KeyAttributes: sealedKeyAttrs(t, h, cn, false, mustPassword(t, objectPassword)),
		Backend:       h.Backend,
	})
	require.NoError(t, err)

	attrs := sealedKeyAttrs(t, h, cn, false, mustPassword(t, objectPassword))
	priv := bytes.Clone(sealed.TPMPrivate)
	priv[len(priv)-1] ^= 0x01
	require.NoError(t, h.Backend.Save(attrs, priv, store.FSEXT_PRIVATE_BLOB, true))

	fromStore := *sealed
	fromStore.TPMPublic = nil
	fromStore.TPMPrivate = nil
	opts := unsealOpts(t, h, cn, nil)
	opts.Backend = h.Backend
	out, err := h.TPM.Unseal(context.Background(), &fromStore, opts)
	require.Nil(t, out)
	require.ErrorIs(t, err, types.ErrSealedDataAuthentication)
	require.ErrorIs(t, err, ErrSealedObjectRejected)
	require.ErrorIs(t, err, ErrUnsealFailed)
}

// TestUnseal_EnvironmentFailuresAreNotAuthentication_Simulator proves TPM
// authorization failures -- a PCR policy the platform no longer satisfies, a
// wrong UserAuth -- a missing stored object and a cancelled context are never
// reported as sealed-data authentication failures.
func TestUnseal_EnvironmentFailuresAreNotAuthentication_Simulator(t *testing.T) {
	t.Run("PCR policy no longer satisfied", func(t *testing.T) {
		h := newSimHarness(t, nil)
		sealed, err := h.TPM.Seal(context.Background(), []byte("pcr bound"), &types.SealOptions{
			KeyAttributes: sealedKeyAttrs(t, h, "env-pcr", true, nil),
		})
		require.NoError(t, err)

		got, err := h.TPM.Unseal(context.Background(), cloneTPMSealed(sealed), &types.UnsealOptions{
			KeyAttributes: sealedKeyAttrs(t, h, "env-pcr", true, nil),
		})
		require.NoError(t, err, "baseline: the unchanged platform unseals")
		require.Equal(t, []byte("pcr bound"), got)

		h.extendPlatformPCR(t, []byte("a-different-boot"))
		out, err := h.TPM.Unseal(context.Background(), cloneTPMSealed(sealed), &types.UnsealOptions{
			KeyAttributes: sealedKeyAttrs(t, h, "env-pcr", true, nil),
		})
		require.Nil(t, out)
		require.Error(t, err)
		require.NotErrorIs(t, err, types.ErrSealedDataAuthentication, "a PCR change is the environment, not forgery")
		var rc tpm2.TPMRC
		require.True(t, errors.As(err, &rc), "the TPM's policy refusal must stay reachable: %v", err)
	})

	t.Run("wrong UserAuth", func(t *testing.T) {
		h := newSimHarness(t, nil)
		sealed := sealForAuthTest(t, h, "env-password", []byte("password bound"), nil)
		out, err := h.TPM.Unseal(context.Background(), sealed, &types.UnsealOptions{
			KeyAttributes: sealedKeyAttrs(t, h, "env-password", false, mustPassword(t, []byte("not-the-password"))),
		})
		require.Nil(t, out)
		require.Error(t, err)
		require.NotErrorIs(t, err, types.ErrSealedDataAuthentication, "a wrong UserAuth is the environment, not forgery")
		require.ErrorIs(t, err, tpm2.TPMRCAuthFail)
	})

	t.Run("stored object missing", func(t *testing.T) {
		h := newSimHarness(t, nil)
		sealed := sealForAuthTest(t, h, "env-missing", []byte("x"), nil)
		fromStore := *sealed
		fromStore.TPMPublic = nil
		fromStore.TPMPrivate = nil
		opts := unsealOpts(t, h, "env-never-sealed", nil)
		opts.Backend = h.Backend
		out, err := h.TPM.Unseal(context.Background(), &fromStore, opts)
		require.Nil(t, out)
		require.ErrorIs(t, err, ErrUnsealFailed)
		require.NotErrorIs(t, err, types.ErrSealedDataAuthentication)
	})

	t.Run("cancelled context with tampered data", func(t *testing.T) {
		h := newSimHarness(t, nil)
		sealed := sealForAuthTest(t, h, "env-ctx", []byte("x"), nil)
		tampered := cloneTPMSealed(sealed)
		tampered.TPMPrivate[0] ^= 0x01
		tampered.Backend = types.BackendTypeVault

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := h.TPM.Unseal(ctx, tampered, unsealOpts(t, h, "env-ctx", nil))
		require.ErrorIs(t, err, context.Canceled)
		require.NotErrorIs(t, err, types.ErrSealedDataAuthentication)
	})
}

// TestSeal_AADBinding_Simulator covers the AAD binding's own edges on a real
// TPM: a nil-data seal with AAD round-trips its random secret, data that
// begins with the binding's magic round-trips without AAD, and data too large
// for the binding is refused before the TPM is asked.
func TestSeal_AADBinding_Simulator(t *testing.T) {
	h := newSimHarness(t, nil)
	aad := []byte("context")

	t.Run("nil data with AAD seals a random secret", func(t *testing.T) {
		sealed := sealForAuthTest(t, h, "aad-random", nil, aad)
		got, err := h.TPM.Unseal(context.Background(), sealed, unsealOpts(t, h, "aad-random", aad))
		require.NoError(t, err)
		require.Len(t, got, 32)
		require.NotEqual(t, make([]byte, 32), got)
	})

	t.Run("data beginning with the magic, no AAD", func(t *testing.T) {
		data := append(bytes.Clone(sealedAADMagic), []byte("payload")...)
		sealed := sealForAuthTest(t, h, "aad-magic", data, nil)
		got, err := h.TPM.Unseal(context.Background(), sealed, unsealOpts(t, h, "aad-magic", nil))
		require.NoError(t, err)
		require.Equal(t, data, got)
	})

	t.Run("data too large for the binding", func(t *testing.T) {
		_, err := h.TPM.Seal(context.Background(), make([]byte, 81), &types.SealOptions{
			KeyAttributes: sealedKeyAttrs(t, h, "aad-too-large", false, mustPassword(t, objectPassword)),
			AAD:           aad,
		})
		require.ErrorIs(t, err, ErrSealAADTooLarge)
	})
}

// TestSeal_PresetSealData_Simulator proves a Seal with nil data seals the
// SealData the caller preset on the key attributes -- with AAD bound to it,
// and with a magic-prefixed preset wrapped like any other magic-prefixed
// data -- instead of replacing it with a random secret.
func TestSeal_PresetSealData_Simulator(t *testing.T) {
	h := newSimHarness(t, nil)
	aad := []byte("volume=root")

	seal := func(t *testing.T, cn string, preset, aad []byte) *types.SealedData {
		t.Helper()
		attrs := sealedKeyAttrs(t, h, cn, false, mustPassword(t, objectPassword))
		attrs.SealData = types.NewSealData(preset)
		sealed, err := h.TPM.Seal(context.Background(), nil, &types.SealOptions{KeyAttributes: attrs, AAD: aad})
		require.NoError(t, err)
		return sealed
	}

	t.Run("preset data with AAD", func(t *testing.T) {
		sealed := seal(t, "preset-aad", []byte("preset payload"), aad)
		got, err := h.TPM.Unseal(context.Background(), sealed, unsealOpts(t, h, "preset-aad", aad))
		require.NoError(t, err)
		require.Equal(t, []byte("preset payload"), got, "the preset payload, not a random secret, must be sealed")

		_, err = h.TPM.Unseal(context.Background(), cloneTPMSealed(sealed), unsealOpts(t, h, "preset-aad", nil))
		require.ErrorIs(t, err, types.ErrSealedDataAuthentication)
	})

	t.Run("preset data that forges a binding, no AAD", func(t *testing.T) {
		chosenAAD := []byte("attacker-chosen")
		forged, owned, err := bindSealAAD(nil, []byte("payload"), chosenAAD)
		require.NoError(t, err)
		require.True(t, owned)

		sealed := seal(t, "preset-forged", forged, nil)
		got, err := h.TPM.Unseal(context.Background(), sealed, unsealOpts(t, h, "preset-forged", nil))
		require.NoError(t, err)
		require.Equal(t, forged, got, "a preset that looks like a binding is sealed as data, not as a binding")

		_, err = h.TPM.Unseal(context.Background(), cloneTPMSealed(sealed), unsealOpts(t, h, "preset-forged", chosenAAD))
		require.ErrorIs(t, err, types.ErrSealedDataAuthentication, "the forged binding must not authenticate its AAD")
	})
}

// TestUnseal_OversizedAndForeignObjects_Simulator proves oversized areas are
// refused before they reach the TPM, and that an object which loads but is
// not sealed data -- a TPM AES key -- is reported as sealed-data
// authentication too.
func TestUnseal_OversizedAndForeignObjects_Simulator(t *testing.T) {
	h := newSimHarness(t, nil)
	const cn = "sealed-oversized"
	sealed := sealForAuthTest(t, h, cn, []byte("x"), nil)

	for name, mutate := range map[string]func(s *types.SealedData){
		"public area oversized": func(s *types.SealedData) {
			s.TPMPublic = append(s.TPMPublic, make([]byte, 5000)...)
		},
		"private area oversized": func(s *types.SealedData) {
			s.TPMPrivate = append(s.TPMPrivate, make([]byte, 5000)...)
		},
		"both areas extended to the per-area limit": func(s *types.SealedData) {
			s.TPMPublic = append(s.TPMPublic, make([]byte, maxLoadAreaSize-len(s.TPMPublic))...)
			s.TPMPrivate = append(s.TPMPrivate, make([]byte, maxLoadAreaSize-len(s.TPMPrivate))...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := cloneTPMSealed(sealed)
			mutate(mutated)
			out, err := h.TPM.Unseal(context.Background(), mutated, unsealOpts(t, h, cn, nil))
			require.Nil(t, out)
			require.ErrorIs(t, err, types.ErrSealedDataAuthentication)
			require.ErrorIs(t, err, ErrObjectAreaTooLarge)
		})
	}

	t.Run("oversized area in storage", func(t *testing.T) {
		stored, err := h.TPM.Seal(context.Background(), []byte("stored"), &types.SealOptions{
			KeyAttributes: sealedKeyAttrs(t, h, "sealed-oversized-stored", false, mustPassword(t, objectPassword)),
			Backend:       h.Backend,
		})
		require.NoError(t, err)
		attrs := sealedKeyAttrs(t, h, "sealed-oversized-stored", false, mustPassword(t, objectPassword))
		require.NoError(t, h.Backend.Save(attrs, append(bytes.Clone(stored.TPMPublic), make([]byte, 5000)...), store.FSEXT_PUBLIC_BLOB, true))

		bothAttrs := sealedKeyAttrs(t, h, "sealed-oversized-both", false, mustPassword(t, objectPassword))
		both, err := h.TPM.Seal(context.Background(), []byte("stored"), &types.SealOptions{KeyAttributes: bothAttrs, Backend: h.Backend})
		require.NoError(t, err)
		bothAttrs = sealedKeyAttrs(t, h, "sealed-oversized-both", false, mustPassword(t, objectPassword))
		require.NoError(t, h.Backend.Save(bothAttrs, append(bytes.Clone(both.TPMPublic), make([]byte, maxLoadAreaSize-len(both.TPMPublic))...), store.FSEXT_PUBLIC_BLOB, true))
		require.NoError(t, h.Backend.Save(bothAttrs, append(bytes.Clone(both.TPMPrivate), make([]byte, maxLoadAreaSize-len(both.TPMPrivate))...), store.FSEXT_PRIVATE_BLOB, true))
		bothFromStore := *both
		bothFromStore.TPMPublic, bothFromStore.TPMPrivate = nil, nil
		bothOpts := unsealOpts(t, h, "sealed-oversized-both", nil)
		bothOpts.Backend = h.Backend
		_, err = h.TPM.Unseal(context.Background(), &bothFromStore, bothOpts)
		require.ErrorIs(t, err, types.ErrSealedDataAuthentication)
		require.ErrorIs(t, err, ErrObjectAreaTooLarge)

		fromStore := *stored
		fromStore.TPMPublic, fromStore.TPMPrivate = nil, nil
		opts := unsealOpts(t, h, "sealed-oversized-stored", nil)
		opts.Backend = h.Backend
		_, err = h.TPM.Unseal(context.Background(), &fromStore, opts)
		require.ErrorIs(t, err, types.ErrSealedDataAuthentication)
		require.ErrorIs(t, err, ErrObjectAreaTooLarge)
	})

	t.Run("an AES key object is not sealed data", func(t *testing.T) {
		attrs := childKeyAttrs(t, h, "not-sealed-aes", x509.RSA, types.KeyTypeHMAC)
		require.NoError(t, h.TPM.CreateSecretKey(attrs, h.Backend))

		opts := &types.UnsealOptions{
			KeyAttributes: childKeyAttrs(t, h, "not-sealed-aes", x509.RSA, types.KeyTypeHMAC),
			Backend:       h.Backend,
		}
		out, err := h.TPM.Unseal(context.Background(), &types.SealedData{Backend: types.BackendTypeTPM2, KeyID: "not-sealed-aes"}, opts)
		require.Nil(t, out)
		require.ErrorIs(t, err, types.ErrSealedDataAuthentication)
		require.ErrorIs(t, err, ErrSealedObjectRejected)
		require.ErrorIs(t, err, tpm2.TPMRCType)
	})
}

// TestSeal_AADEnvelopeDoesNotLeakIntoOptions_Simulator proves the AAD
// envelope stays inside one Seal call: the caller's key attributes come back
// holding the plaintext they held before -- after a successful seal and
// after a failed one -- so a second Seal (or a retry) with the same options
// seals the same plaintext rather than wrapping the envelope again.
func TestSeal_AADEnvelopeDoesNotLeakIntoOptions_Simulator(t *testing.T) {
	h := newSimHarness(t, nil)
	aad := []byte("volume=root")
	preset := bytes.Repeat([]byte{0x5a}, 40)

	t.Run("preset sealed twice with the same options", func(t *testing.T) {
		attrs := sealedKeyAttrs(t, h, "envelope-reuse", false, mustPassword(t, objectPassword))
		attrs.SealData = types.NewSealData(preset)
		opts := &types.SealOptions{KeyAttributes: attrs, AAD: aad}

		for round := 1; round <= 2; round++ {
			sealed, err := h.TPM.Seal(context.Background(), nil, opts)
			require.NoError(t, err, "round %d: a 40-byte preset must seal again with the same options", round)
			require.Equal(t, preset, attrs.SealData.Bytes(), "round %d: the caller's preset must come back untouched", round)

			got, err := h.TPM.Unseal(context.Background(), sealed, unsealOpts(t, h, "envelope-reuse", aad))
			require.NoError(t, err)
			require.Equal(t, preset, got, "round %d: the original plaintext, not an earlier envelope", round)
		}
	})

	t.Run("failed seal then retry", func(t *testing.T) {
		attrs := sealedKeyAttrs(t, h, "envelope-retry", false, mustPassword(t, objectPassword))
		attrs.SealData = types.NewSealData(preset)
		opts := &types.SealOptions{KeyAttributes: attrs, AAD: aad, Backend: "not a key backend"}

		_, err := h.TPM.Seal(context.Background(), nil, opts)
		require.ErrorIs(t, err, ErrInvalidSealBackend)
		require.Equal(t, preset, attrs.SealData.Bytes(), "a failed seal must leave the preset untouched")

		opts.Backend = nil
		sealed, err := h.TPM.Seal(context.Background(), nil, opts)
		require.NoError(t, err)
		got, err := h.TPM.Unseal(context.Background(), sealed, unsealOpts(t, h, "envelope-retry", aad))
		require.NoError(t, err)
		require.Equal(t, preset, got)
	})

	t.Run("data argument with AAD", func(t *testing.T) {
		attrs := sealedKeyAttrs(t, h, "envelope-data", false, mustPassword(t, objectPassword))
		_, err := h.TPM.Seal(context.Background(), []byte("explicit data"), &types.SealOptions{KeyAttributes: attrs, AAD: aad})
		require.NoError(t, err)
		require.Equal(t, []byte("explicit data"), attrs.SealData.Bytes(), "the attributes hold the data, never the envelope")
	})
}
