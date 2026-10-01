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

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/vaultkey"
	"github.com/jeremyhahn/go-xkms/pkg/vaulttoken"
)

// writeKeyPair writes an EC P-256 key and a self-signed certificate for it
// as PEM files, as an operator's client certificate would be, and returns
// their paths.
func writeKeyPair(t *testing.T) (keyFile, certFile string) {
	t.Helper()
	dir := t.TempDir()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(k)
	require.NoError(t, err)
	keyFile = filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "alice"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	require.NoError(t, err)
	certFile = filepath.Join(dir, "cert.pem")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600))
	return keyFile, certFile
}

func setFlags(t *testing.T, cmd *cobra.Command, flags map[string]string) {
	t.Helper()
	resetCmdFlags(t, cmd)
	t.Cleanup(func() { resetCmdFlags(t, cmd) })
	for k, v := range flags {
		require.NoError(t, cmd.Flags().Set(k, v))
	}
}

func TestKeyFactorVault_CertificateEnrollThenUnlockEndToEnd(t *testing.T) {
	server := newVaultServer(t)
	keyFile, certFile := writeKeyPair(t)

	setFlags(t, passwordVaultEnrollCmd, map[string]string{
		keyFactorFlag: "certificate", keyFileFlag: keyFile, certFileFlag: certFile, "label": "mtls cert",
	})
	out := captureStdout(t, func() { passwordVaultEnrollCmd.Run(passwordVaultEnrollCmd, nil) })
	assert.Contains(t, out, "RECOVERY CODE")
	assert.Contains(t, out, "certificate")
	var enrolled bool
	for _, f := range server.status(t).Factors {
		if f.Factor == "certificate" {
			enrolled = true
			assert.Contains(t, f.CertificateSubject, "alice")
		}
	}
	require.True(t, enrolled)

	server.lock(t)
	setFlags(t, passwordUnlockCmd, map[string]string{keyUnlockFlag: "true", keyFileFlag: keyFile})
	out = captureStdout(t, func() { passwordUnlockCmd.Run(passwordUnlockCmd, nil) })
	assert.Contains(t, out, "unlocked")
	assert.True(t, server.status(t).Unlocked, "the key's recovered secret opened the session")
}

func TestKeyFactorVault_WrongAndMissingKey(t *testing.T) {
	server := newVaultServer(t)
	keyFile, _ := writeKeyPair(t)
	otherKey, _ := writeKeyPair(t)

	setFlags(t, passwordVaultEnrollCmd, map[string]string{keyFactorFlag: "piv", keyFileFlag: keyFile})
	source, cleanup, err := resolveVaultKeySource(passwordVaultEnrollCmd, "", vaultNewFactor)
	require.NoError(t, err)
	defer cleanup()
	_, err = enrollVaultFactor(server.cfg, source)
	require.NoError(t, err)
	server.lock(t)

	// Another key recovers nothing; the client says so before sending.
	setFlags(t, passwordUnlockCmd, map[string]string{keyUnlockFlag: "true", keyFileFlag: otherKey})
	unlock, cleanup2, err := resolveVaultKeySource(passwordUnlockCmd, "", vaultUnlock)
	require.NoError(t, err)
	defer cleanup2()
	cl, done, err := createPasswordClient(server.cfg)
	require.NoError(t, err)
	defer done()
	_, err = unlock(context.Background(), cl)
	assert.ErrorIs(t, err, vaultkey.ErrWrongKey)

	// A missing key file never gets that far.
	setFlags(t, passwordUnlockCmd, map[string]string{keyUnlockFlag: "true", keyFileFlag: filepath.Join(t.TempDir(), "absent.pem")})
	_, _, err = resolveVaultKeySource(passwordUnlockCmd, "", vaultUnlock)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestKeyFactorVault_FlagRefusals(t *testing.T) {
	keyFile, certFile := writeKeyPair(t)
	junk := filepath.Join(t.TempDir(), "junk.pem")
	require.NoError(t, os.WriteFile(junk, []byte("not pem"), 0o600))

	cases := []struct {
		name  string
		flags map[string]string
		want  error
	}{
		{"no key source", map[string]string{keyFactorFlag: "piv"}, ErrVaultKeySourceRequired},
		{"two key sources", map[string]string{keyFactorFlag: "piv", keyFileFlag: keyFile, tpmKeystoreFlag: t.TempDir()}, ErrVaultKeyConflict},
		{"with a passkey", map[string]string{keyFactorFlag: "piv", keyFileFlag: keyFile, "passkey": "true"}, ErrVaultKeyConflict},
		{"not a key", map[string]string{keyFactorFlag: "piv", keyFileFlag: junk}, ErrVaultKeyFileInvalid},
		{"not a certificate", map[string]string{keyFactorFlag: "certificate", keyFileFlag: keyFile, certFileFlag: junk}, ErrVaultKeyFileInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setFlags(t, passwordVaultEnrollCmd, tc.flags)
			_, _, err := resolveVaultKeySource(passwordVaultEnrollCmd, "", vaultNewFactor)
			assert.ErrorIs(t, err, tc.want)
		})
	}

	// A certificate factor needs the certificate, and it must be the key's.
	setFlags(t, passwordVaultEnrollCmd, map[string]string{keyFactorFlag: "certificate", keyFileFlag: keyFile})
	source, cleanup, err := resolveVaultKeySource(passwordVaultEnrollCmd, "", vaultNewFactor)
	require.NoError(t, err)
	defer cleanup()
	_, err = source(context.Background(), nil)
	assert.ErrorIs(t, err, vaulttoken.ErrCertificateRequired)

	otherKey, _ := writeKeyPair(t)
	setFlags(t, passwordVaultEnrollCmd, map[string]string{keyFactorFlag: "certificate", keyFileFlag: otherKey, certFileFlag: certFile})
	source, cleanup3, err := resolveVaultKeySource(passwordVaultEnrollCmd, "", vaultNewFactor)
	require.NoError(t, err)
	defer cleanup3()
	_, err = source(context.Background(), nil)
	assert.ErrorIs(t, err, vaulttoken.ErrCertificateMismatch)

	// No key factor asked for: the passphrase and passkey paths run.
	setFlags(t, passwordVaultEnrollCmd, nil)
	source, _, err = resolveVaultKeySource(passwordVaultEnrollCmd, "", vaultNewFactor)
	assert.NoError(t, err)
	assert.Nil(t, source)
}
