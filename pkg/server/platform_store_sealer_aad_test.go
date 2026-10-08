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

package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestPlatformStoreSealers_BindCallerAAD proves both platform-store adapters
// replace only the key identity they own and pass the caller's AAD through:
// a value unseals with the AAD it was sealed under and fails sealed-data
// authentication with a different or a missing one.
func TestPlatformStoreSealers_BindCallerAAD(t *testing.T) {
	fixedInner, fixedAttrs := fixedKeyAttrsSealerTestBackend(t)
	policyInner, err := seal.NewSecretSealer([]byte("platform-store-secret"))
	require.NoError(t, err)

	adapters := map[string]types.Sealer{
		"fixedKeyAttrsSealer":  &fixedKeyAttrsSealer{inner: fixedInner, attrs: fixedAttrs},
		"PlatformPolicySealer": seal.NewPlatformPolicySealer(policyInner, "platform-store-object", nil),
	}
	aad := []byte("record=pkcs11-pin")
	for name, sealer := range adapters {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			sealed, err := sealer.Seal(ctx, []byte("platform secret"), &types.SealOptions{AAD: aad})
			require.NoError(t, err)

			got, err := sealer.Unseal(ctx, sealed, &types.UnsealOptions{AAD: aad})
			require.NoError(t, err)
			require.Equal(t, []byte("platform secret"), got)

			_, err = sealer.Unseal(ctx, sealed, &types.UnsealOptions{AAD: []byte("record=other")})
			require.ErrorIs(t, err, types.ErrSealedDataAuthentication, "a different AAD must not authenticate")

			_, err = sealer.Unseal(ctx, sealed, nil)
			require.ErrorIs(t, err, types.ErrSealedDataAuthentication, "a missing AAD must not authenticate")

			plain, err := sealer.Seal(ctx, []byte("no aad"), nil)
			require.NoError(t, err)
			got, err = sealer.Unseal(ctx, plain, nil)
			require.NoError(t, err, "nil options still seal and unseal without AAD")
			require.Equal(t, []byte("no aad"), got)
		})
	}
}
