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

//go:build frost

package xkms

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/frost"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/pkcs8"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestNewFROSTKeyProvider_PlaintextDenied proves that, with no protected key
// store source configured, newFROSTKeyProvider fails closed with the pkcs8
// backend's typed plaintext-denial error rather than silently persisting the
// FROST wrapping key in the clear (go-xkms#1237). This is the exact failure
// reported in #1237: the factory built its internal PKCS#8 secret store with
// no way to ever allow plaintext, so seal.EnsurePrivateSealKey always failed.
func TestNewFROSTKeyProvider_PlaintextDenied(t *testing.T) {
	_, err := newFROSTKeyProvider(map[string]interface{}{})
	require.Error(t, err)
	require.True(t, errors.Is(err, pkcs8.ErrPlaintextKeyNotAllowed),
		"expected pkcs8.ErrPlaintextKeyNotAllowed, got %v (%T)", err, err)

	// A nil config map must behave identically to an empty one: fail closed,
	// never fall back to plaintext by omission.
	_, err = newFROSTKeyProvider(nil)
	require.Error(t, err)
	require.True(t, errors.Is(err, pkcs8.ErrPlaintextKeyNotAllowed),
		"expected pkcs8.ErrPlaintextKeyNotAllowed, got %v (%T)", err, err)
}

// A threshold above the participant total is rejected by frost.NewBackend,
// and the factory returns a nil interface, not one holding a nil pointer.
func TestNewFROSTKeyProvider_ThresholdAboveTotalReturnsNil(t *testing.T) {
	kp, err := newFROSTKeyProvider(map[string]interface{}{
		"allow_plaintext_keys": true,
		"threshold":            4,
		"total":                3,
	})
	require.Error(t, err)
	require.True(t, kp == nil, "the factory must return a nil KeyProvider, got %#v", kp)
}

// TestNewFROSTKeyProvider_AllowPlaintextKeys_GenerateAndSign builds two FROST
// providers through the real factory (one per participant, mirroring a
// genuine multi-node deployment), each with "allow_plaintext_keys": true for
// its in-memory secret store -- the same opt-in newPKCS8KeyProvider exposes
// for the standalone pkcs8 backend, given here because the ephemeral,
// in-memory storage this test uses is not persisted anywhere plaintext could
// leak. It then drives a full 2-of-2 threshold-signing round: trusted-dealer
// keygen, secret-share import, nonce generation, signing, aggregation and
// verification -- proving the factory produces a fully working backend, not
// just one that avoids the plaintext error.
func TestNewFROSTKeyProvider_AllowPlaintextKeys_GenerateAndSign(t *testing.T) {
	const keyID = "register-frost-roundtrip-key"
	message := []byte("go-xkms#1237 register_frost.go factory round trip")

	newParticipant := func(participantID int) *frost.FrostBackend {
		kp, err := newFROSTKeyProvider(map[string]interface{}{
			"allow_plaintext_keys": true,
			"threshold":            2,
			"total":                2,
			"participant_id":       participantID,
		})
		require.NoError(t, err)
		fb, ok := kp.(*frost.FrostBackend)
		require.True(t, ok, "newFROSTKeyProvider must return a *frost.FrostBackend, got %T", kp)
		return fb
	}

	fb1 := newParticipant(1)
	fb2 := newParticipant(2)

	// Trusted-dealer keygen produces one package per participant, sharing a
	// single group polynomial -- the same call pkg/api/rest's dealer-mode
	// FrostGenerateKeyHandler makes.
	dealer := frost.NewTrustedDealer()
	packages, pubPkg, err := dealer.Generate(frost.FrostConfig{
		Threshold:     2,
		Total:         2,
		Algorithm:     types.FrostAlgorithmEd25519,
		ParticipantID: 1,
	})
	require.NoError(t, err)
	require.Len(t, packages, 2)

	storePackage := func(fb *frost.FrostBackend, pkg *frost.KeyPackage) {
		metadata := &frost.KeyMetadata{
			KeyID:             keyID,
			Algorithm:         types.FrostAlgorithmEd25519,
			Threshold:         2,
			Total:             2,
			ParticipantID:     pkg.ParticipantID,
			CreatedAt:         time.Now().Unix(),
			SecretBackendType: types.BackendTypeSoftware,
		}
		require.NoError(t, fb.KeyStore().StoreKeyPackage(context.Background(), keyID, pkg, metadata))
	}
	storePackage(fb1, packages[0])
	storePackage(fb2, packages[1])

	nonces1, err := fb1.GenerateNonces(keyID)
	require.NoError(t, err)
	nonces2, err := fb2.GenerateNonces(keyID)
	require.NoError(t, err)

	commitments := []*frost.Commitment{
		{ParticipantID: nonces1.ParticipantID, Commitments: nonces1.Commitments},
		{ParticipantID: nonces2.ParticipantID, Commitments: nonces2.Commitments},
	}

	share1, err := fb1.SignRound(keyID, message, nonces1, commitments)
	require.NoError(t, err)
	share2, err := fb2.SignRound(keyID, message, nonces2, commitments)
	require.NoError(t, err)

	shares := []*frost.SignatureShare{share1, share2}

	signature, err := fb1.Aggregate(keyID, message, commitments, shares)
	require.NoError(t, err)
	require.NotEmpty(t, signature)

	require.NoError(t, fb1.Verify(keyID, message, signature))

	_ = pubPkg
}
