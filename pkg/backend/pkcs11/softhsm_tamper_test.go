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

//go:build pkcs11

package pkcs11

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"
)

// minTamperClassifyingSoftHSM is the first SoftHSM release whose C_Decrypt
// answers an AES-GCM tag mismatch with CKR_ENCRYPTED_DATA_INVALID rather than
// the ambiguous CKR_GENERAL_ERROR (go-xkms#1418). scripts/build-softhsm.sh
// pins it for every image this repository tests with.
var minTamperClassifyingSoftHSM = pkcs11.Version{Major: 2, Minor: 7}

// TestSupportedSoftHSM_ReportsTamperAsSealedDataAuthentication proves, on the
// SoftHSM the repository's images ship, that tampered PKCS#11 sealed data is
// reported as types.ErrSealedDataAuthentication -- with the token's own
// CKR_ENCRYPTED_DATA_INVALID reachable -- for every way the ciphertext the
// token sees can be wrong. It first requires the module to be SoftHSM 2.7.0
// or later: an image that regressed to the distribution's 2.6.1 fails here,
// naming the script that builds the supported release, instead of letting
// tamper silently go unclassified.
func TestSupportedSoftHSM_ReportsTamperAsSealedDataAuthentication(t *testing.T) {
	b, keyA := newSealingBackend(t, "seal-supported-softhsm", "seal-supported-softhsm-a")
	keyB := secondSealingKey(t, b, "seal-supported-softhsm-b")

	info, err := b.p11ctx.GetInfo()
	require.NoError(t, err)
	version := info.LibraryVersion
	require.Truef(t,
		version.Major > minTamperClassifyingSoftHSM.Major ||
			(version.Major == minTamperClassifyingSoftHSM.Major && version.Minor >= minTamperClassifyingSoftHSM.Minor),
		"SoftHSM %d.%d cannot report PKCS#11 tamper (it answers a GCM tag mismatch with CKR_GENERAL_ERROR); "+
			"build %d.%d or later with scripts/build-softhsm.sh",
		version.Major, version.Minor, minTamperClassifyingSoftHSM.Major, minTamperClassifyingSoftHSM.Minor)

	ctx := context.Background()
	aad := []byte("tenant=acme,purpose=barrier")
	sealed, err := b.Seal(ctx, []byte("hsm sealed root key"), &types.SealOptions{KeyAttributes: keyA, AAD: aad})
	require.NoError(t, err)

	for name, mutate := range map[string]func(s *types.SealedData) *types.UnsealOptions{
		"ciphertext bit flipped": func(s *types.SealedData) *types.UnsealOptions {
			s.Ciphertext[0] ^= 0x01
			return &types.UnsealOptions{KeyAttributes: keyA, AAD: aad}
		},
		"tag bit flipped": func(s *types.SealedData) *types.UnsealOptions {
			s.Tag[len(s.Tag)-1] ^= 0x80
			return &types.UnsealOptions{KeyAttributes: keyA, AAD: aad}
		},
		"nonce bit flipped": func(s *types.SealedData) *types.UnsealOptions {
			s.Nonce[0] ^= 0x01
			return &types.UnsealOptions{KeyAttributes: keyA, AAD: aad}
		},
		"truncated": func(s *types.SealedData) *types.UnsealOptions {
			s.Ciphertext = s.Ciphertext[:len(s.Ciphertext)-1]
			return &types.UnsealOptions{KeyAttributes: keyA, AAD: aad}
		},
		"extended": func(s *types.SealedData) *types.UnsealOptions {
			s.Ciphertext = append(s.Ciphertext, 0x00)
			return &types.UnsealOptions{KeyAttributes: keyA, AAD: aad}
		},
		"AAD mismatch": func(s *types.SealedData) *types.UnsealOptions {
			return &types.UnsealOptions{KeyAttributes: keyA, AAD: []byte("tenant=evil")}
		},
		"AAD omitted": func(s *types.SealedData) *types.UnsealOptions {
			return &types.UnsealOptions{KeyAttributes: keyA}
		},
		"foreign key reaching the token": func(s *types.SealedData) *types.UnsealOptions {
			s.KeyID = ""
			return &types.UnsealOptions{KeyAttributes: keyB, AAD: aad}
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := cloneSealedData(sealed)
			opts := mutate(mutated)

			out, err := b.Unseal(ctx, mutated, opts)
			require.Nil(t, out, "tampered sealed data must not produce plaintext")
			require.ErrorIs(t, err, types.ErrSealedDataAuthentication)
			require.ErrorIs(t, err, ErrCiphertextRejected)
			require.ErrorIs(t, err, pkcs11.Error(pkcs11.CKR_ENCRYPTED_DATA_INVALID),
				"SoftHSM %d.%d's own answer must stay reachable", version.Major, version.Minor)
		})
	}

	got, err := b.Unseal(ctx, sealed, &types.UnsealOptions{KeyAttributes: keyA, AAD: aad})
	require.NoError(t, err, "the untouched envelope must still unseal")
	require.Equal(t, []byte("hsm sealed root key"), got)
}
