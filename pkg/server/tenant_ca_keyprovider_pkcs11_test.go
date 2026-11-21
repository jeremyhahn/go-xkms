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

package server

import (
	"context"
	"crypto/ecdsa"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-xkms/internal/softhsmtest"
	pkcs11backend "github.com/jeremyhahn/go-xkms/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTenantCAKeyFactory_PKCS11ConcurrentPassesMakeOneKey runs provisioning
// passes for one tenant at once against a real PKCS#11 token (SoftHSM2).
// The token does not refuse a second key pair with the same CKA_ID and
// CKA_LABEL, so only a claim taken before generation keeps the passes from
// each making one: the token must end with exactly one login CA key for the
// tenant, and every pass must resolve that key.
func TestTenantCAKeyFactory_PKCS11ConcurrentPassesMakeOneKey(t *testing.T) {
	ctx := context.Background()
	token := softhsmtest.Provision(t, "tenant-login-ca-claim")
	pin, err := types.NewLiteralSecretValue(ctx, []byte(token.UserPIN))
	require.NoError(t, err)
	provider, err := pkcs11backend.NewBackend(&pkcs11backend.Config{
		CN:          "pkcs11-backend",
		Library:     token.Library,
		TokenLabel:  token.Label,
		PIN:         pin,
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	})
	require.NoError(t, err)
	require.NoError(t, provider.Login())
	base, err := xkms.New(&xkms.BackendConfig{Backend: provider, CertStorage: storage.New()})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, base.Close()) })

	const passes = 8
	claims := storage.New() // the shared storage every node's factory claims in
	factories := make([]*tenantCAKeyFactory, passes)
	for i := range factories {
		factories[i] = newTenantCAKeyFactory()
		require.NoError(t, factories[i].Bind(base, claims))
	}

	var (
		wg    sync.WaitGroup
		start = make(chan struct{})
		errs  = make([]error, passes)
	)
	for i, f := range factories {
		wg.Add(1)
		go func(i int, f *tenantCAKeyFactory) {
			defer wg.Done()
			<-start
			errs[i] = f.EnsureTenant(ctx, "tenant-a")
		}(i, f)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		require.NoError(t, err, "pass %d", i)
	}

	listed, err := provider.ListKeys(ctx)
	require.NoError(t, err)
	var keys int
	for _, attrs := range listed {
		if tenant, ok := tenantLoginCAKeyTenant(attrs); ok && tenant == "tenant-a" {
			keys++
		}
	}
	assert.Equal(t, 1, keys, "concurrent passes must leave one login CA key on the token")

	pub, cert := tenantLoginCA(t, factories[0], "tenant-a")
	for _, f := range factories[1:] {
		other, _ := tenantLoginCA(t, f, "tenant-a")
		assert.True(t, pub.(*ecdsa.PublicKey).Equal(other), "every pass must resolve the one key")
	}
	assert.True(t, pub.(*ecdsa.PublicKey).Equal(cert.PublicKey), "the certificate must be over that key")
}
