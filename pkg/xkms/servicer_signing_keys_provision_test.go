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
		require.ErrorIs(t, err, ErrKeyNotFound, "system tenant %q is never provisioned (owner-queue item 153)", system)
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

func TestSignCoRIM_SystemTenantIsNeverProvisioned(t *testing.T) {
	svc := setupDeriveService(t)
	withSigningKeys(t, svc, corimSignPermission)
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "release-manager", TenantID: qrdbsdk.SystemTenantID})

	_, err := svc.SignCoRIM(ctx, signCoRIMRequest(t))
	require.ErrorIs(t, err, ErrKeyNotFound)
	_, err = svc.SigningPublicKey(context.Background(), qrdbsdk.SystemTenantID, releaseResolution())
	require.ErrorIs(t, err, ErrKeyNotFound, "the system tenant's release key is owner-queue item 153")
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
