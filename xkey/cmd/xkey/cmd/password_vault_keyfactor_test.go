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

package cmd

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	pkgstorage "github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	pkgxkms "github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/jeremyhahn/go-xkms/sdk/go/vaulttoken"
)

// useKeyBackend makes the key-factor verbs see one software backend named
// name holding an EC key keyID, instead of xKey's local key store.
func useKeyBackend(t *testing.T, name, keyID string) {
	t.Helper()
	kp, err := software.NewBackend(&software.Config{KeyStorage: pkgstorage.New()})
	require.NoError(t, err)
	b, err := pkgxkms.New(&pkgxkms.BackendConfig{Backend: kp, CertStorage: pkgstorage.New()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })
	_, err = b.GenerateECDSA(context.Background(), &types.KeyAttributes{
		CN: keyID, KeyType: types.KeyTypeEncryption, StoreType: b.Type(),
		KeyAlgorithm: x509.ECDSA, ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	})
	require.NoError(t, err)
	original := localKeyBackends
	localKeyBackends = func(*cobra.Command) (vaulttoken.Lookup, error) {
		return func(n string) (pkgxkms.Backend, error) {
			if n == name {
				return b, nil
			}
			return nil, errNoBackendHere
		}, nil
	}
	t.Cleanup(func() { localKeyBackends = original })
}

var errNoBackendHere = errors.New("no such backend here")

func TestPasswordVaultKeyFactor_EnrollThenUnlockEndToEnd(t *testing.T) {
	server := newVaultServerClient(t)
	useKeyBackend(t, "tpm2", "vault-tpm")

	out, _, err := runPasswordCmd(t, "vault", "enroll", "--key-factor", "tpm", "--key-backend", "tpm2",
		"--key-id", "vault-tpm", "--tpm-policy", "platform", "--label", "this laptop")
	require.NoError(t, err)
	assert.Contains(t, out, "RECOVERY CODE", "a key factor can initialize the vault")
	factors := server.status(t).Factors
	var key bool
	for _, f := range factors {
		if f.Factor == "tpm" {
			key = true
			assert.Equal(t, "platform", f.KeyRef.TPMPolicy)
			assert.Equal(t, "vault-tpm", f.KeyRef.KeyID)
		}
	}
	assert.True(t, key)

	server.lock(t)
	out, _, err = runPasswordCmd(t, "unlock", "--key")
	require.NoError(t, err)
	assert.Contains(t, out, "Password store unlocked.")
	assert.True(t, server.status(t).Unlocked)
}

func TestPasswordVaultKeyFactor_Refusals(t *testing.T) {
	server := newVaultServerClient(t)
	useKeyBackend(t, "tpm2", "vault-tpm")

	_, _, err := runPasswordCmd(t, "vault", "enroll", "--key-factor", "tpm", "--key-id", "vault-tpm")
	assert.ErrorIs(t, err, ErrPasswordKeyBackendRequired)

	_, _, err = runPasswordCmd(t, "vault", "enroll", "--key-factor", "tpm", "--key-backend", "tpm2", "--key-id", "vault-tpm", "--passkey")
	assert.ErrorIs(t, err, ErrPasswordKeyFactorConflict)

	_, _, err = runPasswordCmd(t, "vault", "enroll", "--key-factor", "tpm", "--key-backend", "hsm", "--key-id", "vault-tpm")
	var backendErr *vaulttoken.BackendError
	assert.ErrorAs(t, err, &backendErr, "a backend xKey does not run")

	_, _, err = runPasswordCmd(t, "vault", "enroll", "--key-factor", "certificate", "--key-backend", "tpm2", "--key-id", "vault-tpm")
	assert.ErrorIs(t, err, vaulttoken.ErrCertificateRequired)
	assert.False(t, server.status(t).Initialized, "nothing is enrolled after a refusal")

	// A vault without a key factor has nothing to unlock with.
	t.Setenv("XKEY_VAULT_PASSPHRASE", "first passphrase")
	_, _, err = runPasswordCmd(t, "vault", "enroll")
	require.NoError(t, err)
	server.lock(t)
	t.Setenv("XKEY_VAULT_PASSPHRASE", "")
	_, _, err = runPasswordCmd(t, "unlock", "--key")
	assert.ErrorIs(t, err, vaulttoken.ErrNoKeyFactor)

	// An unreachable key store is reported.
	localKeyBackends = func(*cobra.Command) (vaulttoken.Lookup, error) { return nil, errNoBackendHere }
	_, _, err = runPasswordCmd(t, "unlock", "--key")
	assert.ErrorIs(t, err, errNoBackendHere)
}

func TestPasswordVaultKeyFactor_RecoverWithAKey(t *testing.T) {
	server := newVaultServerClient(t)
	t.Setenv("XKEY_VAULT_PASSPHRASE", "first passphrase")
	out, _, err := runPasswordCmd(t, "vault", "enroll")
	require.NoError(t, err)
	code := recoveryCodeFrom(t, out)
	server.lock(t)
	t.Setenv("XKEY_VAULT_PASSPHRASE", "")

	useKeyBackend(t, "pkcs11", pkgxkms.PivSlotCN(vaulttoken.PIVSlot))
	t.Setenv("XKEY_VAULT_RECOVERY_CODE", code)
	out, _, err = runPasswordCmd(t, "vault", "recover", "--key-factor", "piv", "--key-backend", "pkcs11")
	require.NoError(t, err)
	assert.Contains(t, out, "RECOVERY CODE")
	assert.True(t, server.status(t).Unlocked)
}
