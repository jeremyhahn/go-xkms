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

//go:build pkcs11

package main

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/internal/softhsmtest"
	pkcs11backend "github.com/jeremyhahn/go-xkms/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestKeyFactorVault_PIVOnSoftHSM enrolls and unlocks with the slot 9d key
// of a PKCS#11 token -- SoftHSM standing in for a PIV card's module.
func TestKeyFactorVault_PIVOnSoftHSM(t *testing.T) {
	token := softhsmtest.Provision(t, "vault-piv")
	kp, err := pkcs11backend.NewBackend(&pkcs11backend.Config{
		Library: token.Library, TokenLabel: token.Label,
		PIN:        types.NewLiteralSecretValue([]byte(token.UserPIN)),
		KeyStorage: storage.New(), CertStorage: storage.New(),
	})
	require.NoError(t, err)
	require.NoError(t, kp.Login())
	_, err = kp.GenerateKey(context.Background(), &types.KeyAttributes{
		CN: xkms.PivSlotCN("9d"), KeyType: types.KeyTypeEncryption, StoreType: types.StorePKCS11,
		KeyAlgorithm: x509.ECDSA, ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	})
	require.NoError(t, err)

	server := newVaultServer(t)
	flags := map[string]string{
		pkcs11LibraryFlag: token.Library, pkcs11TokenFlag: token.Label, keyPINFlag: token.UserPIN,
	}
	enroll := map[string]string{keyFactorFlag: "piv"}
	for k, v := range flags {
		enroll[k] = v
	}
	setFlags(t, passwordVaultEnrollCmd, enroll)
	out := captureStdout(t, func() { passwordVaultEnrollCmd.Run(passwordVaultEnrollCmd, nil) })
	assert.Contains(t, out, "RECOVERY CODE")

	server.lock(t)
	unlock := map[string]string{keyUnlockFlag: "true"}
	for k, v := range flags {
		unlock[k] = v
	}
	setFlags(t, passwordUnlockCmd, unlock)
	out = captureStdout(t, func() { passwordUnlockCmd.Run(passwordUnlockCmd, nil) })
	assert.Contains(t, out, "unlocked")
	assert.True(t, server.status(t).Unlocked)
}
