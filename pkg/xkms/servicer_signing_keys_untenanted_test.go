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

package xkms

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// typedProvider is a software key provider that reports another backend's
// type, so provisioning is judged by the type alone.
type typedProvider struct {
	types.KeyProvider
	kind types.BackendType
}

func (p *typedProvider) Type() types.BackendType { return p.kind }

// TestSignCoRIM_RefusesAReleaseKeyOnBackendsThatDropTheTenant proves first
// use on Vault, PKCS#11, the phone, or a TPM without tenant scopes, whose
// generate and list paths drop the tenant, refuses before any key is written
// and leaves another tenant's release key as it was.
func TestSignCoRIM_RefusesAReleaseKeyOnBackendsThatDropTheTenant(t *testing.T) {
	for _, kind := range []types.BackendType{
		types.BackendTypeVault, types.BackendTypePKCS11, types.BackendTypePhone, types.BackendTypeTPM2,
	} {
		t.Run(string(kind), func(t *testing.T) {
			provider, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
			require.NoError(t, err)
			typed := &typedProvider{KeyProvider: provider, kind: kind}
			Reset()
			t.Cleanup(Reset)
			b, err := New(&BackendConfig{Backend: typed, CertStorage: storage.New()})
			require.NoError(t, err)
			require.NoError(t, Initialize(&ServiceConfig{Backends: map[string]Backend{"software": b}, DefaultBackend: "software"}))
			svc, err := Get()
			require.NoError(t, err)
			wireKeyVersionStore(t)
			ctx := withSigningKeys(t, svc, corimSignPermission)

			other := generateSigningKey(t, svc, "tenant-b", releaseResolution().KeyID)
			before, err := typed.ListKeys(context.Background())
			require.NoError(t, err)

			_, err = svc.SignCoRIM(ctx, signCoRIMRequest(t))
			var provision *ReleaseKeyProvisionError
			require.ErrorAs(t, err, &provision)
			assert.ErrorIs(t, err, ErrReleaseKeyBackendUnsupported)
			assert.Equal(t, "tenant-a", provision.TenantID)

			after, err := typed.ListKeys(context.Background())
			require.NoError(t, err)
			assert.ElementsMatch(t, before, after, "no key is written")
			assert.Equal(t, other, releasePublicKey(t, svc, "tenant-b"), "tenant-b's release key is unchanged")
		})
	}
}
