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

package xkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"sync"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	tpmstore "github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// releaseResolution is the resolution of an unbound repository.
func releaseResolution() *appraisal.SigningKeyResolution {
	return &appraisal.SigningKeyResolution{Repository: "acme/app", KeyID: appraisal.ReleaseSigningKeyID, Default: true}
}

// releasePublicKey returns the public half of tenant's release key.
func releasePublicKey(t *testing.T, svc *XKMSService, tenant string) crypto.PublicKey {
	t.Helper()
	pub, err := svc.SigningPublicKey(context.Background(), tenant, releaseResolution())
	require.NoError(t, err, tenant)
	return pub
}

func TestProvisionReleaseKey_GeneratesInTheTenantScope(t *testing.T) {
	svc := setupDeriveService(t)

	require.NoError(t, svc.provisionReleaseKey(context.Background(), "tenant-a", ""))
	pub, ok := releasePublicKey(t, svc, "tenant-a").(*ecdsa.PublicKey)
	require.True(t, ok, "the release key is ECDSA")
	assert.Equal(t, elliptic.P256(), pub.Curve)

	_, err := svc.SigningPublicKey(context.Background(), "tenant-b", releaseResolution())
	require.ErrorIs(t, err, ErrKeyNotFound, "provisioning tenant-a never gives tenant-b a key")
}

func TestProvisionReleaseKey_KeepsAnExistingKey(t *testing.T) {
	svc := setupDeriveService(t)
	existing := generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID)

	require.NoError(t, svc.provisionReleaseKey(context.Background(), "tenant-a", ""))
	assert.True(t, existing.(*ecdsa.PublicKey).Equal(releasePublicKey(t, svc, "tenant-a")), "an existing release key is never replaced")
}

func TestProvisionReleaseKey_Errors(t *testing.T) {
	svc := setupDeriveService(t)

	err := svc.provisionReleaseKey(context.Background(), "tenant-a", "no-such-backend")
	var provisionErr *ReleaseKeyProvisionError
	require.ErrorAs(t, err, &provisionErr)
	assert.Equal(t, "tenant-a", provisionErr.TenantID)
	assert.Contains(t, provisionErr.Error(), "tenant-a")
	require.ErrorIs(t, err, provisionErr.Err)
}

func TestReleaseKeySigner_ProvisionsOnFirstUse(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()

	first, err := svc.releaseKeySigner(ctx, "tenant-a", releaseResolution())
	require.NoError(t, err)
	again, err := svc.releaseKeySigner(ctx, "tenant-a", releaseResolution())
	require.NoError(t, err)
	assert.True(t, first.Public().(*ecdsa.PublicKey).Equal(again.Public()), "the second use signs with the provisioned key")
}

func TestReleaseKeySigner_Errors(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()

	_, err := svc.releaseKeySigner(ctx, "tenant-a", nil)
	require.ErrorIs(t, err, appraisal.ErrNilRequest)

	bound := &appraisal.SigningKeyResolution{Repository: "acme/app", KeyID: "deleted-key"}
	_, err = svc.releaseKeySigner(ctx, "tenant-a", bound)
	require.ErrorIs(t, err, ErrKeyNotFound, "a binding to a key the tenant does not hold is never provisioned")

	for _, system := range []string{qrdbsdk.SystemTenantID, ""} {
		_, err = svc.releaseKeySigner(ctx, system, releaseResolution())
		require.ErrorIs(t, err, ErrKeyNotFound, "system tenant %q is never provisioned (owner ruling 165)", system)
	}
	_, err = svc.SigningPublicKey(ctx, qrdbsdk.SystemTenantID, releaseResolution())
	require.ErrorIs(t, err, ErrKeyNotFound)
}

func TestSignCoRIM_ReleaseKeyGenerateFailure(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	errGenerate := errors.New("key generation hardware failure")
	store := newMockKeyStore("software")
	store.generateErr = errGenerate
	require.NoError(t, Initialize(&ServiceConfig{
		Backends:       map[string]Backend{"software": store},
		DefaultBackend: "software",
	}))
	svc, err := Get()
	require.NoError(t, err)
	ctx := withSigningKeys(t, svc, corimSignPermission)

	_, err = svc.SignCoRIM(ctx, signCoRIMRequest(t))
	require.ErrorIs(t, err, errGenerate)
	var provisionErr *ReleaseKeyProvisionError
	require.ErrorAs(t, err, &provisionErr)
	assert.Equal(t, "tenant-a", provisionErr.TenantID)
}

// A tenant-scoped TPM backend refuses to generate over an existing key with
// a BlobWriteError wrapping ErrBlobExists, not ErrKeyAlreadyExists: of two
// concurrent first uses, the one that loses still finds the key the other
// made and signs with it.
func TestProvisionReleaseKey_KeepsAKeyOnABlobCollision(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	store := newMockKeyStore("software")
	store.generateErr = &tpmstore.BlobWriteError{Name: "release-signing-key", Cause: tpmstore.ErrBlobExists}
	require.NoError(t, Initialize(&ServiceConfig{
		Backends:       map[string]Backend{"software": store},
		DefaultBackend: "software",
	}))
	svc, err := Get()
	require.NoError(t, err)
	ctx := withSigningKeys(t, svc, corimSignPermission)

	require.NoError(t, svc.provisionReleaseKey(ctx, "tenant-a", ""))
}

// lateListingBackend models the loser of a release-key race between two
// instances sharing storage: the winner has published the key material, so
// generate collides, but the tenant record is not yet written, so the first
// misses listings return nothing.
type lateListingBackend struct {
	Backend
	collide bool
	misses  int
	lists   int
}

func (b *lateListingBackend) GenerateECDSA(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if b.collide {
		return nil, ErrKeyAlreadyExists
	}
	return b.Backend.GenerateECDSA(ctx, attrs)
}

func (b *lateListingBackend) ListKeys(ctx context.Context) ([]*types.KeyAttributes, error) {
	b.lists++
	if b.lists <= b.misses {
		return nil, nil
	}
	return b.Backend.ListKeys(ctx)
}

func TestProvisionReleaseKey_CollisionWaitsForTheWinnersKey(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	backoff := releaseKeyResolveBackoff
	releaseKeyResolveBackoff = 0
	t.Cleanup(func() { releaseKeyResolveBackoff = backoff })

	factory, ok := GetBackendFactory(BackendSoftware)
	require.True(t, ok)
	provider, err := factory(map[string]interface{}{"key_dir": "memory"})
	require.NoError(t, err)
	inner, err := New(&BackendConfig{Backend: provider, CertStorage: storage.New()})
	require.NoError(t, err)
	late := &lateListingBackend{Backend: inner}
	require.NoError(t, Initialize(&ServiceConfig{
		Backends:       map[string]Backend{"software": late},
		DefaultBackend: "software",
	}))
	svc, err := Get()
	require.NoError(t, err)
	wireKeyVersionStore(t)

	winner := generateSigningKey(t, svc, "tenant-a", appraisal.ReleaseSigningKeyID)
	late.collide, late.misses, late.lists = true, 5, 0

	signer, err := svc.releaseKeySigner(context.Background(), "tenant-a", releaseResolution())
	require.NoError(t, err, "the loser of a collision signs once the winner's key resolves")
	assert.True(t, winner.(*ecdsa.PublicKey).Equal(signer.Public()), "the loser signs with the winner's key")
	assert.Greater(t, late.lists, late.misses, "the lookup is retried past the listings that miss the key")
}

func TestSignCoRIM_SystemTenantIsNeverProvisioned(t *testing.T) {
	svc := setupDeriveService(t)
	withSigningKeys(t, svc, corimSignPermission)
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "release-manager", TenantID: qrdbsdk.SystemTenantID})

	_, err := svc.SignCoRIM(ctx, signCoRIMRequest(t))
	require.ErrorIs(t, err, ErrKeyNotFound)
	_, err = svc.SigningPublicKey(context.Background(), qrdbsdk.SystemTenantID, releaseResolution())
	require.ErrorIs(t, err, ErrKeyNotFound, "the system tenant never gets a release key (owner ruling 165)")
}

func TestSignCoRIM_ConcurrentFirstUsesProvisionOneKey(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := withSigningKeys(t, svc, corimSignPermission)

	const callers = 8
	signed := make([][]byte, callers)
	failures := make([]error, callers)
	var wg sync.WaitGroup
	for i := range callers {
		req := signCoRIMRequest(t)
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := svc.SignCoRIM(ctx, req)
			if err != nil {
				failures[i] = err
				return
			}
			signed[i] = resp.CoRIM
		}()
	}
	wg.Wait()

	release := releasePublicKey(t, svc, "tenant-a")
	for i := range callers {
		require.NoError(t, failures[i], "caller %d", i)
		verifyCoRIM(t, signed[i], release)
	}
}
