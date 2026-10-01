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

package vaulttoken

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/internal/softhsmtest"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	pkcs11backend "github.com/jeremyhahn/go-xkms/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/vaultkey"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// newSoftHSMBackend is a PKCS#11 key backend on a freshly provisioned
// SoftHSM token -- the fixture standing in for a smart card or HSM.
func newSoftHSMBackend(t *testing.T, label string) xkms.Backend {
	t.Helper()
	token := softhsmtest.Provision(t, label)
	kp, err := pkcs11backend.NewBackend(&pkcs11backend.Config{
		Library:     token.Library,
		TokenLabel:  token.Label,
		PIN:         types.NewLiteralSecretValue([]byte(token.UserPIN)),
		SOPIN:       types.NewLiteralSecretValue([]byte(token.SOPIN)),
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	})
	require.NoError(t, err)
	require.NoError(t, kp.Login())
	b, err := xkms.New(&xkms.BackendConfig{Backend: kp, CertStorage: storage.New()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })
	return b
}

// TestPKCS11Factor_EnrollUnlockOnSoftHSM runs the PIV and certificate
// factors on a PKCS#11 token with EC keys: the slot 9d key and a
// certificate's key agree (C_DeriveKey, CKM_ECDH1_DERIVE) without leaving
// the token.
func TestPKCS11Factor_EnrollUnlockOnSoftHSM(t *testing.T) {
	cases := []struct {
		factor string
		ref    transport.PasswordVaultKeyRef
		cn     string
		cert   bool
	}{
		{FactorPIV, transport.PasswordVaultKeyRef{Backend: "pkcs11"}, xkms.PivSlotCN(PIVSlot), false},
		{FactorCertificate, transport.PasswordVaultKeyRef{Backend: "pkcs11", KeyID: "alice-mtls"}, "alice-mtls", true},
	}
	for _, tc := range cases {
		t.Run(tc.factor, func(t *testing.T) {
			ctx := context.Background()
			b := newSoftHSMBackend(t, "vault-"+tc.factor)
			newKey(t, b, tc.cn, false, tc.cert)
			lookup := backends{"pkcs11": b}.lookup
			v := newVault(t)

			key, err := Resolve(ctx, lookup, tc.factor, tc.ref)
			require.NoError(t, err)
			cred, err := EnrollCredential(tc.factor, key, "token")
			require.NoError(t, err)
			enrolled := v.enroll(t, cred)
			require.NoError(t, Verify(ctx, key.Token, enrolled))
			require.NoError(t, v.svc.PasswordStoreLock(v.ctx))

			unlock, err := Find(ctx, lookup, v.factors(t))
			require.NoError(t, err)
			require.NoError(t, v.unlock(unlock))
		})
	}
}

// TestPKCS11Factor_TokenWithoutOAEP256IsCaughtAtEnrollment proves why the
// clients self-test a token before enrolling it: SoftHSM 2.6 decrypts RSA-OAEP with
// SHA-1 only, so an RSA key on it can never recover an RSA-OAEP-256
// secret. Verify reports it at once, and the client removes the factor
// instead of leaving the user a factor that cannot open.
func TestPKCS11Factor_TokenWithoutOAEP256IsCaughtAtEnrollment(t *testing.T) {
	ctx := context.Background()
	b := newSoftHSMBackend(t, "vault-rsa")
	newKey(t, b, "rsa-key", true, false)
	v := newVault(t)

	_, err := Resolve(ctx, backends{"pkcs11": b}.lookup, FactorCertificate, transport.PasswordVaultKeyRef{Backend: "pkcs11", KeyID: "rsa-key"})
	require.ErrorIs(t, err, ErrCertificateRequired)
	key, err := Resolve(ctx, backends{"pkcs11": b}.lookup, FactorTPM, transport.PasswordVaultKeyRef{Backend: "pkcs11", KeyID: "rsa-key"})
	require.NoError(t, err)
	var selfTestErr *SelfTestError
	assert.ErrorAs(t, SelfTest(ctx, key.Token), &selfTestErr, "refused before anything is enrolled")

	// Enrolled anyway, Verify reports it.
	cred, err := EnrollCredential(FactorPIV, key, "")
	require.NoError(t, err)
	enrolled := v.enroll(t, cred)
	assert.Error(t, Verify(ctx, key.Token, enrolled), "the token cannot decrypt RSA-OAEP-256")
}

// TestPKCS11Factor_AnotherTokenIsRefused proves another token carrying a
// key under the same name is not the factor's token.
func TestPKCS11Factor_AnotherTokenIsRefused(t *testing.T) {
	ctx := context.Background()
	mine := newSoftHSMBackend(t, "vault-mine")
	other := newSoftwareBackend(t)
	cn := xkms.PivSlotCN(PIVSlot)
	newKey(t, mine, cn, false, false)
	newKey(t, other, cn, false, false)
	v := newVault(t)

	key, err := Resolve(ctx, backends{"pkcs11": mine}.lookup, FactorPIV, transport.PasswordVaultKeyRef{Backend: "pkcs11"})
	require.NoError(t, err)
	cred, err := EnrollCredential(FactorPIV, key, "")
	require.NoError(t, err)
	enrolled := v.enroll(t, cred)

	_, err = Find(ctx, backends{"pkcs11": other}.lookup, []transport.PasswordVaultFactor{enrolled})
	assert.ErrorIs(t, err, ErrTokenNotFound)
	otherKey, err := Resolve(ctx, backends{"pkcs11": other}.lookup, FactorPIV, transport.PasswordVaultKeyRef{Backend: "pkcs11"})
	require.NoError(t, err)
	assert.ErrorIs(t, Verify(ctx, otherKey.Token, enrolled), vaultkey.ErrWrongKey)
}
