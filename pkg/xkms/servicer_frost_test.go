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

//go:build frost

package xkms

import (
	"context"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/frost"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/pkcs8"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// These tests pin the tenant scoping of the FROST service methods
// (go-xkms#1231): a FROST key belongs to the tenant that created or imported
// it, every method that names a key resolves it inside the caller's tenant,
// and another tenant's key is the same ErrKeyNotFound a missing key is.

const (
	frostTenantA = "tenant-a"
	frostTenantB = "tenant-b"
)

// setupFrostService initializes the service with a real FROST backend --
// sealing secret shares under an in-memory PKCS#8 key, as the "pkcs8"
// secret_backend does in production -- next to a software backend.
func setupFrostService(t *testing.T) *XKMSService {
	t.Helper()
	Reset()
	t.Cleanup(Reset)

	secrets, err := pkcs8.NewBackend(&pkcs8.Config{KeyStorage: storage.New(), AllowPlaintextKeys: true})
	require.NoError(t, err)
	sealer, ok := secrets.(types.SealingKeyProvider)
	require.True(t, ok)
	sealKey := frost.AsymmetricSecretSealKeyAttributes(types.StoreSoftware)
	require.NoError(t, seal.EnsurePrivateSealKey(context.Background(), secrets, sealKey))
	provider, err := frost.NewBackend(&frost.Config{
		PublicStorage:           storage.New(),
		SecretBackend:           sealer,
		SecretSealKeyAttributes: sealKey,
		EnableNonceTracking:     true,
	})
	require.NoError(t, err)
	frostBackend, err := New(&BackendConfig{Backend: provider, CertStorage: storage.New()})
	require.NoError(t, err)

	factory, ok := GetBackendFactory(BackendSoftware)
	require.True(t, ok)
	software, err := factory(map[string]interface{}{"key_dir": "memory"})
	require.NoError(t, err)
	softwareBackend, err := New(&BackendConfig{Backend: software, CertStorage: storage.New()})
	require.NoError(t, err)

	require.NoError(t, Initialize(&ServiceConfig{
		Backends:       map[string]Backend{"frost": frostBackend, "software": softwareBackend},
		DefaultBackend: "software",
	}))
	svc, err := Get()
	require.NoError(t, err)
	return svc
}

// frostGenerate creates a 2-of-3 participant-1 key keyID as the caller on ctx.
func frostGenerate(t *testing.T, svc *XKMSService, ctx context.Context, keyID string) *FrostGenerateKeyResponse {
	t.Helper()
	resp, err := svc.FrostGenerateKey(ctx, &FrostGenerateKeyRequest{
		KeyID: keyID, Threshold: 2, Total: 3, ParticipantID: 1,
	})
	require.NoError(t, err)
	return resp
}

// frostImport imports pkg as keyID for the caller on ctx.
func frostImport(t *testing.T, svc *XKMSService, ctx context.Context, keyID string, pkg FrostParticipantPackage) {
	t.Helper()
	require.NoError(t, svc.FrostImportKey(ctx, &FrostImportKeyRequest{
		KeyID:              keyID,
		Algorithm:          string(types.FrostAlgorithmEd25519),
		Threshold:          2,
		Total:              3,
		ParticipantID:      pkg.ParticipantID,
		SecretShare:        pkg.SecretShare,
		GroupPublicKey:     pkg.GroupPublicKey,
		VerificationShares: pkg.VerificationShares,
	}))
}

// frostKeyCalls is every FROST service method that names a key, invoked as
// the caller on ctx naming keyID.
var frostKeyCalls = map[string]func(svc *XKMSService, ctx context.Context, keyID string) error{
	"get": func(svc *XKMSService, ctx context.Context, keyID string) error {
		_, err := svc.FrostGetKey(ctx, keyID)
		return err
	},
	"delete": func(svc *XKMSService, ctx context.Context, keyID string) error {
		return svc.FrostDeleteKey(ctx, keyID)
	},
	"nonces": func(svc *XKMSService, ctx context.Context, keyID string) error {
		_, err := svc.FrostGenerateNonces(ctx, keyID)
		return err
	},
	"sign": func(svc *XKMSService, ctx context.Context, keyID string) error {
		_, err := svc.FrostSignRound(ctx, &FrostSignRoundRequest{
			KeyID: keyID, Message: []byte("m"), HidingNonce: []byte{1}, BindingNonce: []byte{1},
			Commitments: []*frost.Commitment{{ParticipantID: 1, Commitments: &frost.SigningCommitments{}}},
		})
		return err
	},
	"aggregate": func(svc *XKMSService, ctx context.Context, keyID string) error {
		_, err := svc.FrostAggregate(ctx, &FrostAggregateRequest{
			KeyID: keyID, Message: []byte("m"),
			Commitments: []*frost.Commitment{{ParticipantID: 1, Commitments: &frost.SigningCommitments{}}},
			Shares:      []*frost.SignatureShare{{ParticipantID: 1, Share: []byte{1}}},
		})
		return err
	},
	"verify": func(svc *XKMSService, ctx context.Context, keyID string) error {
		_, err := svc.FrostVerify(ctx, keyID, []byte("m"), []byte("signature"))
		return err
	},
}

func TestFrostService_CrossTenantRefusalEqualsGenuineMiss(t *testing.T) {
	for name, call := range frostKeyCalls {
		t.Run(name, func(t *testing.T) {
			svc := setupFrostService(t)
			frostGenerate(t, svc, identityCtx(frostTenantB), "b-key")

			crossErr := call(svc, identityCtx(frostTenantA), "b-key")
			missErr := call(svc, identityCtx(frostTenantA), "no-such-key")
			require.Error(t, crossErr, "tenant A reached tenant B's FROST key")
			assert.ErrorIs(t, crossErr, ErrKeyNotFound)
			assert.Equal(t, missErr.Error(), crossErr.Error(),
				"a cross-tenant refusal must read exactly like a genuine miss")

			_, err := svc.FrostGetKey(identityCtx(frostTenantB), "b-key")
			assert.NoError(t, err, "tenant B's key must survive")
		})
	}
}

func TestFrostService_KeyIDsAreTenantLocal(t *testing.T) {
	svc := setupFrostService(t)
	a := frostGenerate(t, svc, identityCtx(frostTenantA), "shared")
	b := frostGenerate(t, svc, identityCtx(frostTenantB), "shared")
	require.NotEqual(t, a.GroupPublicKey, b.GroupPublicKey)

	gotA, err := svc.FrostGetKey(identityCtx(frostTenantA), "shared")
	require.NoError(t, err)
	assert.Equal(t, a.GroupPublicKey, gotA.GroupPublicKey)
	gotB, err := svc.FrostGetKey(identityCtx(frostTenantB), "shared")
	require.NoError(t, err)
	assert.Equal(t, b.GroupPublicKey, gotB.GroupPublicKey)

	require.NoError(t, svc.FrostDeleteKey(identityCtx(frostTenantA), "shared"))
	_, err = svc.FrostGetKey(identityCtx(frostTenantB), "shared")
	assert.NoError(t, err, "deleting tenant A's key must leave tenant B's")
}

func TestFrostService_ListKeys(t *testing.T) {
	svc := setupFrostService(t)
	frostGenerate(t, svc, identityCtx(frostTenantA), "a-2")
	frostGenerate(t, svc, identityCtx(frostTenantA), "a-1")
	frostGenerate(t, svc, identityCtx(frostTenantB), "b-1")
	frostGenerate(t, svc, context.Background(), "platform-1")

	ids := func(keys []FrostKeyInfo) []string {
		out := make([]string, 0, len(keys))
		for _, k := range keys {
			out = append(out, k.KeyID)
		}
		return out
	}

	keys, err := svc.FrostListKeys(identityCtx(frostTenantA))
	require.NoError(t, err)
	assert.Equal(t, []string{"a-1", "a-2"}, ids(keys), "a tenant lists only its own keys, in key ID order")
	assert.NotEmpty(t, keys[0].GroupPublicKey)
	assert.False(t, keys[0].CreatedAt.IsZero(), "CreatedAt is the stored creation time")

	for name, ctx := range map[string]context.Context{
		"no identity":     context.Background(),
		"system identity": identityCtx(qrdbsdk.SystemTenantID),
	} {
		t.Run(name, func(t *testing.T) {
			keys, err := svc.FrostListKeys(ctx)
			require.NoError(t, err)
			assert.Equal(t, []string{"a-1", "a-2", "b-1", "platform-1"}, ids(keys),
				"a platform-scoped caller lists every tenant's keys")
		})
	}

	_, err = svc.FrostGetKey(context.Background(), "a-1")
	assert.ErrorIs(t, err, ErrKeyNotFound, "a bare key ID names a platform key")
	_, err = svc.FrostGetKey(context.Background(), "platform-1")
	assert.NoError(t, err)
}

func TestFrostService_ImportLandsInCallersTenant(t *testing.T) {
	svc := setupFrostService(t)
	b := frostGenerate(t, svc, identityCtx(frostTenantB), "k")

	dealt, err := svc.FrostGenerateKey(identityCtx(frostTenantA), &FrostGenerateKeyRequest{
		KeyID: "k", Threshold: 2, Total: 3, DealerMode: true, Participants: []string{"p1", "p2", "p3"},
	})
	require.NoError(t, err)
	require.Len(t, dealt.Packages, 3)
	assert.Equal(t, "p2", dealt.Packages[1].ParticipantName)
	frostImport(t, svc, identityCtx(frostTenantA), "k", dealt.Packages[1])

	gotA, err := svc.FrostGetKey(identityCtx(frostTenantA), "k")
	require.NoError(t, err)
	assert.Equal(t, dealt.GroupPublicKey, gotA.GroupPublicKey)
	assert.Equal(t, uint32(2), gotA.ParticipantID)

	gotB, err := svc.FrostGetKey(identityCtx(frostTenantB), "k")
	require.NoError(t, err)
	assert.Equal(t, b.GroupPublicKey, gotB.GroupPublicKey, "an import must not replace another tenant's share")
}

// TestFrostService_ThresholdSignatureWithinTenant drives a full 2-of-3
// signature inside one tenant, re-importing each participant's package before
// the round that needs its share.
func TestFrostService_ThresholdSignatureWithinTenant(t *testing.T) {
	svc := setupFrostService(t)
	ctx := identityCtx(frostTenantA)
	message := []byte("go-xkms#1231")

	dealt, err := svc.FrostGenerateKey(ctx, &FrostGenerateKeyRequest{KeyID: "k", Threshold: 2, Total: 3, DealerMode: true})
	require.NoError(t, err)
	p1, p2 := dealt.Packages[0], dealt.Packages[1]

	frostImport(t, svc, ctx, "k", p1)
	n1, err := svc.FrostGenerateNonces(ctx, "k")
	require.NoError(t, err)
	frostImport(t, svc, ctx, "k", p2)
	n2, err := svc.FrostGenerateNonces(ctx, "k")
	require.NoError(t, err)

	commitments := []*frost.Commitment{
		{ParticipantID: n1.ParticipantID, Commitments: n1.Commitments},
		{ParticipantID: n2.ParticipantID, Commitments: n2.Commitments},
	}
	sign := func(n *frost.NoncePackage) *frost.SignatureShare {
		share, err := svc.FrostSignRound(ctx, &FrostSignRoundRequest{
			KeyID: "k", Message: message, SessionID: n.SessionID,
			HidingNonce: n.Nonces.HidingNonce, BindingNonce: n.Nonces.BindingNonce,
			HidingCommitment: n.Commitments.HidingCommitment, BindingCommitment: n.Commitments.BindingCommitment,
			Commitments: commitments,
		})
		require.NoError(t, err)
		return share
	}
	frostImport(t, svc, ctx, "k", p1)
	s1 := sign(n1)
	frostImport(t, svc, ctx, "k", p2)
	s2 := sign(n2)

	agg, err := svc.FrostAggregate(ctx, &FrostAggregateRequest{
		KeyID: "k", Message: message, Commitments: commitments,
		Shares: []*frost.SignatureShare{s1, s2}, Verify: true,
	})
	require.NoError(t, err)
	assert.True(t, agg.Verified)

	valid, err := svc.FrostVerify(ctx, "k", message, agg.Signature)
	require.NoError(t, err)
	assert.True(t, valid.Valid)

	tampered, err := svc.FrostVerify(ctx, "k", []byte("tampered"), agg.Signature)
	require.NoError(t, err, "a signature that does not verify is a result, not an error")
	assert.False(t, tampered.Valid)
	assert.NotEmpty(t, tampered.Reason)

	_, err = svc.FrostVerify(identityCtx(frostTenantB), "k", message, agg.Signature)
	assert.ErrorIs(t, err, ErrKeyNotFound, "another tenant cannot verify against tenant A's group key")
}

func TestFrostService_ValidationRefusals(t *testing.T) {
	svc := setupFrostService(t)
	ctx := identityCtx(frostTenantA)

	tests := map[string]func() error{
		"generate nil": func() error { _, err := svc.FrostGenerateKey(ctx, nil); return err },
		"threshold": func() error {
			_, err := svc.FrostGenerateKey(ctx, &FrostGenerateKeyRequest{Threshold: 1, Total: 3, DealerMode: true})
			return err
		},
		"total": func() error {
			_, err := svc.FrostGenerateKey(ctx, &FrostGenerateKeyRequest{Threshold: 3, Total: 2, DealerMode: true})
			return err
		},
		"participant id": func() error {
			_, err := svc.FrostGenerateKey(ctx, &FrostGenerateKeyRequest{KeyID: "k", Threshold: 2, Total: 3})
			return err
		},
		"traversal key id": func() error {
			_, err := svc.FrostGenerateKey(ctx, &FrostGenerateKeyRequest{KeyID: "../tenant-b:k", Threshold: 2, Total: 3, ParticipantID: 1})
			return err
		},
		"empty key id": func() error { _, err := svc.FrostGetKey(ctx, ""); return err },
		"import without share": func() error {
			return svc.FrostImportKey(ctx, &FrostImportKeyRequest{KeyID: "k", GroupPublicKey: []byte{1}})
		},
		"import without group key": func() error {
			return svc.FrostImportKey(ctx, &FrostImportKeyRequest{KeyID: "k", SecretShare: []byte{1}})
		},
		"import without key id": func() error { return svc.FrostImportKey(ctx, &FrostImportKeyRequest{}) },
		"sign without message": func() error {
			_, err := svc.FrostSignRound(ctx, &FrostSignRoundRequest{KeyID: "k"})
			return err
		},
		"sign without nonces": func() error {
			_, err := svc.FrostSignRound(ctx, &FrostSignRoundRequest{KeyID: "k", Message: []byte("m")})
			return err
		},
		"sign without commitments": func() error {
			_, err := svc.FrostSignRound(ctx, &FrostSignRoundRequest{KeyID: "k", Message: []byte("m"), HidingNonce: []byte{1}, BindingNonce: []byte{1}})
			return err
		},
		"aggregate without shares": func() error {
			_, err := svc.FrostAggregate(ctx, &FrostAggregateRequest{KeyID: "k", Message: []byte("m"), Commitments: []*frost.Commitment{{}}})
			return err
		},
		"verify without signature": func() error {
			_, err := svc.FrostVerify(ctx, "k", []byte("m"), nil)
			return err
		},
		"tenant id with separator": func() error {
			_, err := svc.FrostGetKey(identityCtx("a/b"), "k")
			return err
		},
	}
	for name, call := range tests {
		t.Run(name, func(t *testing.T) {
			err := call()
			require.Error(t, err)
			if name == "generate nil" {
				assert.ErrorIs(t, err, ErrNilConfig)
				return
			}
			var validation *ErrValidation
			assert.ErrorAs(t, err, &validation)
		})
	}
}

func TestFrostService_NotConfigured(t *testing.T) {
	svc := setupDeriveService(t)

	_, err := svc.FrostListKeys(context.Background())
	assert.ErrorIs(t, err, ErrFrostNotConfigured)
	_, err = svc.FrostGenerateKey(context.Background(), &FrostGenerateKeyRequest{Threshold: 2, Total: 3, DealerMode: true})
	assert.ErrorIs(t, err, ErrFrostNotConfigured, "dealer mode is refused on a deployment without FROST")
}

func TestFrostKeyError(t *testing.T) {
	assert.Equal(t, ErrKeyNotFound, frostKeyError(&frost.KeyNotFoundError{KeyID: "tenant-a:k"}),
		"a miss is the bare sentinel, carrying no storage key ID")
	assert.ErrorIs(t, frostKeyError(frost.ErrKeyAlreadyExists), ErrKeyAlreadyExists)
	var validation *ErrValidation
	assert.ErrorAs(t, frostKeyError(&frost.KeyIDError{KeyID: "x", Err: frost.ErrInvalidAttributes}), &validation)
	assert.ErrorIs(t, frostKeyError(frost.ErrInvalidSignature), ErrOperationFailed)
}
