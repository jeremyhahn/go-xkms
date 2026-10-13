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

//go:build tpm_simulator

package vaulttoken

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmblobtest"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/vaultkey"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// newTPMBackend is a TPM 2.0 key backend on the in-process simulator.
func newTPMBackend(t *testing.T) xkms.Backend {
	t.Helper()
	kp, err := tpm2backend.NewBackend(&tpm2backend.Config{UseSimulator: true, Keys: tpmblobtest.New(t)})
	require.NoError(t, err)
	b, err := xkms.New(&xkms.BackendConfig{Backend: kp, CertStorage: storage.New()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })
	return b
}

// TestTPMFactor_EnrollUnlockOnTheSimulator runs a TPM key factor -- EC
// (TPM2_ECDH_ZGen) and RSA (TPM2_RSA_Decrypt, OAEP-SHA-256) -- end to end:
// the private key never leaves the TPM, and the secret it recovers opens
// the vault. The key is under the backend's default named policy
// ("platform": PCR 16 or the key's password).
func TestTPMFactor_EnrollUnlockOnTheSimulator(t *testing.T) {
	for name, rsaKey := range map[string]bool{"EC": false, "RSA": true} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			b := newTPMBackend(t)
			newKey(t, b, "vault-tpm", rsaKey, false)
			lookup := backends{"tpm2": b}.lookup
			ref := transport.PasswordVaultKeyRef{Backend: "tpm2", KeyID: "vault-tpm", TPMPolicy: types.TPMPolicyPlatform}
			v := newVault(t)

			key, err := Resolve(ctx, lookup, FactorTPM, ref)
			require.NoError(t, err)
			cred, err := EnrollCredential(FactorTPM, key, "this machine")
			require.NoError(t, err)
			enrolled := v.enroll(t, cred)
			assert.Equal(t, types.TPMPolicyPlatform, enrolled.KeyRef.TPMPolicy)
			require.NoError(t, Verify(ctx, key.Token, enrolled))
			require.NoError(t, v.svc.PasswordStoreLock(v.ctx))

			unlock, err := Find(ctx, lookup, v.factors(t))
			require.NoError(t, err)
			require.NoError(t, v.unlock(unlock))
		})
	}
}

// TestTPMFactor_AnotherTPMsKeyIsTheWrongToken proves a key on another TPM
// (or another key on the same one) cannot recover the secret.
func TestTPMFactor_AnotherTPMsKeyIsTheWrongToken(t *testing.T) {
	ctx := context.Background()
	b := newTPMBackend(t)
	newKey(t, b, "vault-tpm", false, false)
	newKey(t, b, "other-tpm", false, false)
	lookup := backends{"tpm2": b}.lookup
	v := newVault(t)

	key, err := Resolve(ctx, lookup, FactorTPM, transport.PasswordVaultKeyRef{Backend: "tpm2", KeyID: "vault-tpm"})
	require.NoError(t, err)
	cred, err := EnrollCredential(FactorTPM, key, "")
	require.NoError(t, err)
	enrolled := v.enroll(t, cred)

	other, err := Resolve(ctx, lookup, FactorTPM, transport.PasswordVaultKeyRef{Backend: "tpm2", KeyID: "other-tpm"})
	require.NoError(t, err)
	assert.ErrorIs(t, Verify(ctx, other.Token, enrolled), vaultkey.ErrWrongKey)
}
