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
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// remoteKeyProvider generates keys whose private material never leaves the
// provider, as AWS KMS, Azure Key Vault and GCP KMS do: GenerateKey returns
// (nil, nil) and the key is reachable only through Signer.
type remoteKeyProvider struct {
	types.KeyProvider
	generated atomic.Int32
}

func (p *remoteKeyProvider) GenerateKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if _, err := p.KeyProvider.GenerateKey(ctx, attrs); err != nil {
		return nil, err
	}
	p.generated.Add(1)
	return nil, nil
}

func remoteKeyService(t *testing.T) (*XKMSService, *remoteKeyProvider) {
	t.Helper()
	Reset()
	t.Cleanup(Reset)
	factory, ok := GetBackendFactory(BackendSoftware)
	require.True(t, ok)
	inner, err := factory(map[string]interface{}{"key_dir": "memory"})
	require.NoError(t, err)
	provider := &remoteKeyProvider{KeyProvider: inner}
	b, err := New(&BackendConfig{Backend: provider, CertStorage: storage.New()})
	require.NoError(t, err)
	require.NoError(t, Initialize(&ServiceConfig{Backends: map[string]Backend{"software": b}, DefaultBackend: "software"}))
	svc, err := Get()
	require.NoError(t, err)
	wireKeyVersionStore(t)
	return svc, provider
}

func TestSignCoRIM_ProvisionsANonExtractableReleaseKey(t *testing.T) {
	svc, provider := remoteKeyService(t)
	ctx := withSigningKeys(t, svc, corimSignPermission)

	first, err := svc.SignCoRIM(ctx, signCoRIMRequest(t))
	require.NoError(t, err, "first use provisions a key the backend never hands out")
	again, err := svc.SignCoRIM(ctx, signCoRIMRequest(t))
	require.NoError(t, err)

	assert.Equal(t, int32(1), provider.generated.Load(), "the release key is generated once")
	release := releasePublicKey(t, svc, "tenant-a")
	verifyCoRIM(t, first.CoRIM, release)
	verifyCoRIM(t, again.CoRIM, release)
}
