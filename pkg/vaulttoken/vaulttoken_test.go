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

package vaulttoken

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/vaulttest/vaultservice"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/vaultkey"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

var errNoBackend = errors.New("backend not configured")

// backends is a client's configured key backends.
type backends map[string]xkms.Backend

func (b backends) lookup(name string) (xkms.Backend, error) {
	if be, ok := b[name]; ok {
		return be, nil
	}
	return nil, errNoBackend
}

func newSoftwareBackend(t *testing.T) xkms.Backend {
	t.Helper()
	kp, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	require.NoError(t, err)
	b, err := xkms.New(&xkms.BackendConfig{Backend: kp, CertStorage: storage.New()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })
	return b
}

// newKey generates an EC P-256 or RSA-2048 key named cn in b and, with
// withCert, stores a self-signed certificate for it.
func newKey(t *testing.T, b xkms.Backend, cn string, rsaKey, withCert bool) {
	t.Helper()
	ctx := context.Background()
	attrs := &types.KeyAttributes{CN: cn, KeyType: types.KeyTypeEncryption, StoreType: b.Type()}
	var err error
	if rsaKey {
		attrs.KeyAlgorithm = x509.RSA
		attrs.RSAAttributes = &types.RSAAttributes{KeySize: 2048}
		_, err = b.GenerateRSA(ctx, attrs)
	} else {
		attrs.KeyAlgorithm = x509.ECDSA
		attrs.ECCAttributes = &types.ECCAttributes{Curve: elliptic.P256()}
		_, err = b.GenerateECDSA(ctx, attrs)
	}
	require.NoError(t, err)
	if withCert {
		signer, err := b.Signer(ctx, attrs)
		require.NoError(t, err)
		require.NoError(t, b.SaveCert(ctx, cn, selfSigned(t, signer, cn)))
	}
}

func selfSigned(t *testing.T, signer crypto.Signer, cn string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// vault is a user's vault on a real vault service.
type vault struct {
	svc *xkms.XKMSService
	ctx context.Context
}

func newVault(t *testing.T) *vault {
	t.Helper()
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "alice", TenantID: vaultservice.Tenant})
	return &vault{svc: vaultservice.New(t).Service, ctx: ctx}
}

func (v *vault) enroll(t *testing.T, cred transport.PasswordVaultCredential) transport.PasswordVaultFactor {
	t.Helper()
	resp, err := v.svc.PasswordVaultEnroll(v.ctx, &transport.PasswordVaultEnrollRequest{PasswordVaultCredential: cred})
	require.NoError(t, err)
	return resp.Factor
}

func (v *vault) factors(t *testing.T) []transport.PasswordVaultFactor {
	t.Helper()
	status, err := v.svc.PasswordVaultStatus(v.ctx)
	require.NoError(t, err)
	return status.Factors
}

func (v *vault) unlock(cred transport.PasswordVaultCredential) error {
	return v.svc.PasswordStoreUnlock(v.ctx, &transport.PasswordStoreUnlockRequest{PasswordVaultCredential: cred})
}

// TestKeyFactor_EnrollVerifyLockUnlock runs every key factor type, EC and
// RSA, through a real vault service: resolve the token, enroll it, verify
// it recovers the enrolled secret, lock, find it from the vault status
// alone and unlock.
func TestKeyFactor_EnrollVerifyLockUnlock(t *testing.T) {
	cases := []struct {
		factor string
		ref    transport.PasswordVaultKeyRef
		cn     string
		cert   bool
	}{
		{FactorPIV, transport.PasswordVaultKeyRef{Backend: "piv"}, xkms.PivSlotCN(PIVSlot), false},
		{FactorCertificate, transport.PasswordVaultKeyRef{Backend: "software", KeyID: "alice-mtls"}, "alice-mtls", true},
		{FactorTPM, transport.PasswordVaultKeyRef{Backend: "software", KeyID: "vault-key", TPMPolicy: "platform"}, "vault-key", false},
	}
	for _, tc := range cases {
		for _, rsaKey := range []bool{false, true} {
			name := tc.factor + map[bool]string{false: "/EC", true: "/RSA"}[rsaKey]
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				b := newSoftwareBackend(t)
				newKey(t, b, tc.cn, rsaKey, tc.cert)
				lookup := backends{tc.ref.Backend: b}.lookup
				v := newVault(t)

				key, err := Resolve(ctx, lookup, tc.factor, tc.ref)
				require.NoError(t, err)
				assert.Equal(t, tc.cert, key.Certificate != nil)
				cred, err := EnrollCredential(tc.factor, key, "my "+tc.factor)
				require.NoError(t, err)
				if tc.cert {
					assert.NotEmpty(t, cred.Certificate)
				} else {
					assert.NotEmpty(t, cred.PublicKey)
				}

				enrolled := v.enroll(t, cred)
				require.NoError(t, Verify(ctx, key.Token, enrolled))
				assert.Equal(t, tc.cn, enrolled.KeyRef.KeyID)
				require.NoError(t, v.svc.PasswordStoreLock(v.ctx))

				unlock, err := Find(ctx, lookup, v.factors(t))
				require.NoError(t, err)
				assert.Equal(t, enrolled.KeyFingerprint, unlock.KeyFingerprint)
				require.NoError(t, v.unlock(unlock))
			})
		}
	}
}

// TestKeyFactor_WrongToken proves another key is detected client-side,
// before anything is sent: by Find (no token of this vault is here) and by
// UnlockCredential (this token holds no factor's key).
func TestKeyFactor_WrongToken(t *testing.T) {
	ctx := context.Background()
	ref := transport.PasswordVaultKeyRef{Backend: "software", KeyID: "vault-key"}
	mine, other := newSoftwareBackend(t), newSoftwareBackend(t)
	newKey(t, mine, "vault-key", false, false)
	newKey(t, other, "vault-key", false, false)
	v := newVault(t)

	key, err := Resolve(ctx, backends{"software": mine}.lookup, FactorTPM, ref)
	require.NoError(t, err)
	cred, err := EnrollCredential(FactorTPM, key, "")
	require.NoError(t, err)
	enrolled := v.enroll(t, cred)
	require.NoError(t, v.svc.PasswordStoreLock(v.ctx))

	// Same backend name and key ID, different key.
	_, err = Find(ctx, backends{"software": other}.lookup, v.factors(t))
	assert.ErrorIs(t, err, ErrTokenNotFound)

	otherKey, err := Resolve(ctx, backends{"software": other}.lookup, FactorTPM, ref)
	require.NoError(t, err)
	_, err = UnlockCredential(ctx, otherKey.Token, v.factors(t))
	assert.ErrorIs(t, err, vaultkey.ErrWrongKey)
	assert.ErrorIs(t, Verify(ctx, otherKey.Token, enrolled), vaultkey.ErrWrongKey)
}

// TestKeyFactor_MissingToken proves an absent card, key or backend is
// ErrTokenNotFound, and a vault without key factors ErrNoKeyFactor.
func TestKeyFactor_MissingToken(t *testing.T) {
	ctx := context.Background()
	b := newSoftwareBackend(t)
	newKey(t, b, "vault-key", false, false)
	v := newVault(t)
	key, err := Resolve(ctx, backends{"software": b}.lookup, FactorTPM, transport.PasswordVaultKeyRef{Backend: "software", KeyID: "vault-key"})
	require.NoError(t, err)
	cred, err := EnrollCredential(FactorTPM, key, "")
	require.NoError(t, err)
	v.enroll(t, cred)
	require.NoError(t, v.svc.PasswordStoreLock(v.ctx))

	_, err = Find(ctx, backends{}.lookup, v.factors(t))
	assert.ErrorIs(t, err, ErrTokenNotFound, "the backend is not configured here")
	_, err = Find(ctx, backends{"software": newSoftwareBackend(t)}.lookup, v.factors(t))
	assert.ErrorIs(t, err, ErrTokenNotFound, "the key is not in this backend")

	_, err = Find(ctx, backends{}.lookup, []transport.PasswordVaultFactor{{Factor: "passphrase"}})
	assert.ErrorIs(t, err, ErrNoKeyFactor)
	_, err = UnlockCredential(ctx, key.Token, []transport.PasswordVaultFactor{{Factor: "passkey"}})
	assert.ErrorIs(t, err, ErrNoKeyFactor)
}

func TestResolve_Refusals(t *testing.T) {
	ctx := context.Background()
	b := newSoftwareBackend(t)
	newKey(t, b, "no-cert", false, false)
	newKey(t, b, "with-cert", false, true)
	newKey(t, b, "other", false, false)
	lookup := backends{"software": b}.lookup

	_, err := Resolve(ctx, lookup, "passkey", transport.PasswordVaultKeyRef{Backend: "software", KeyID: "no-cert"})
	assert.ErrorIs(t, err, ErrUnknownFactor)
	_, err = Resolve(ctx, lookup, FactorTPM, transport.PasswordVaultKeyRef{Backend: "software"})
	assert.ErrorIs(t, err, ErrKeyRequired)
	_, err = Resolve(ctx, lookup, FactorCertificate, transport.PasswordVaultKeyRef{Backend: "software", KeyID: "no-cert"})
	assert.ErrorIs(t, err, ErrCertificateRequired)
	_, err = Resolve(ctx, lookup, FactorTPM, transport.PasswordVaultKeyRef{Backend: "hsm", KeyID: "no-cert"})
	var backendErr *BackendError
	assert.ErrorAs(t, err, &backendErr)
	_, err = Resolve(ctx, lookup, FactorTPM, transport.PasswordVaultKeyRef{Backend: "software", KeyID: "absent"})
	var keyErr *KeyError
	assert.ErrorAs(t, err, &keyErr)

	// A certificate stored under a key's ID that is not that key's.
	otherSigner, err := b.Signer(ctx, &types.KeyAttributes{CN: "other", KeyType: types.KeyTypeEncryption, StoreType: b.Type(), KeyAlgorithm: x509.ECDSA, ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()}})
	require.NoError(t, err)
	require.NoError(t, b.SaveCert(ctx, "no-cert", selfSigned(t, otherSigner, "imposter")))
	_, err = Resolve(ctx, lookup, FactorCertificate, transport.PasswordVaultKeyRef{Backend: "software", KeyID: "no-cert"})
	assert.ErrorIs(t, err, ErrCertificateMismatch)
}

// TestKeyFactor_ServerRejectsAForgedSecret proves the vault, not the
// client, decides: a credential naming a factor with a secret the private
// key did not recover is rejected.
func TestKeyFactor_ServerRejectsAForgedSecret(t *testing.T) {
	ctx := context.Background()
	b := newSoftwareBackend(t)
	newKey(t, b, "vault-key", true, false)
	v := newVault(t)
	key, err := Resolve(ctx, backends{"software": b}.lookup, FactorTPM, transport.PasswordVaultKeyRef{Backend: "software", KeyID: "vault-key"})
	require.NoError(t, err)
	cred, err := EnrollCredential(FactorTPM, key, "")
	require.NoError(t, err)
	enrolled := v.enroll(t, cred)
	require.NoError(t, v.svc.PasswordStoreLock(v.ctx))

	forged := transport.PasswordVaultCredential{Factor: FactorTPM, KeyFingerprint: enrolled.KeyFingerprint, Secret: make([]byte, vaultkey.SecretLength)}
	assert.ErrorIs(t, v.unlock(forged), staticpw.ErrVaultCredentialRejected)
}

func TestSelfTest(t *testing.T) {
	ctx := context.Background()
	b := newSoftwareBackend(t)
	newKey(t, b, "ok", false, false)
	key, err := Resolve(ctx, backends{"software": b}.lookup, FactorTPM, transport.PasswordVaultKeyRef{Backend: "software", KeyID: "ok"})
	require.NoError(t, err)
	require.NoError(t, SelfTest(ctx, key.Token))

	var selfTestErr *SelfTestError
	assert.ErrorAs(t, SelfTest(ctx, brokenToken{key.Token}), &selfTestErr)
}

// brokenToken is a token whose key agreement answers garbage, as a token
// that cannot perform the algorithm does.
type brokenToken struct{ vaultkey.Token }

func (b brokenToken) DeriveKeyECDH(context.Context, []byte, *types.KDFParams) ([]byte, error) {
	return make([]byte, vaultkey.SecretLength), nil
}

// foreignKeyToken is a token whose public key is not a type x509 can
// encode, as a backend answering with a key no factor can use does.
type foreignKeyToken struct{ vaultkey.Token }

func (foreignKeyToken) Public() crypto.PublicKey { return struct{}{} }

// TestKeyFactor_UnusablePublicKey proves a token whose public key cannot be
// encoded is refused by every entry point, with nothing produced.
func TestKeyFactor_UnusablePublicKey(t *testing.T) {
	ctx := context.Background()
	b := newSoftwareBackend(t)
	newKey(t, b, "vault-key", false, false)
	ref := transport.PasswordVaultKeyRef{Backend: "software", KeyID: "vault-key"}
	key, err := Resolve(ctx, backends{"software": b}.lookup, FactorTPM, ref)
	require.NoError(t, err)
	tok := foreignKeyToken{key.Token}

	cred, err := EnrollCredential(FactorTPM, &Key{Token: tok, Ref: ref}, "label")
	var keyErr *KeyError
	require.ErrorAs(t, err, &keyErr)
	assert.Equal(t, ref, keyErr.Ref)
	assert.ErrorContains(t, err, "vaulttoken: key vault-key in software: ")
	assert.Empty(t, cred)

	assert.ErrorIs(t, SelfTest(ctx, tok), vaultkey.ErrUnsupportedKey)

	cred, err = UnlockCredential(ctx, tok, []transport.PasswordVaultFactor{{Factor: FactorTPM}})
	assert.ErrorIs(t, err, vaultkey.ErrInvalidPublicKey)
	assert.Empty(t, cred)
}

// TestErrors_KeepTheirCause proves each wrapping error names what failed and
// still matches its cause with errors.Is.
func TestErrors_KeepTheirCause(t *testing.T) {
	ctx := context.Background()
	b := newSoftwareBackend(t)
	newKey(t, b, "ok", false, false)
	lookup := backends{"software": b}.lookup

	_, err := Resolve(ctx, lookup, FactorTPM, transport.PasswordVaultKeyRef{Backend: "hsm", KeyID: "ok"})
	assert.ErrorIs(t, err, errNoBackend)
	assert.EqualError(t, err, "vaulttoken: backend hsm: "+errNoBackend.Error())

	cause := errors.New("no such key")
	keyErr := &KeyError{Ref: transport.PasswordVaultKeyRef{Backend: "software", KeyID: "absent"}, Err: cause}
	assert.ErrorIs(t, keyErr, cause)
	assert.EqualError(t, keyErr, "vaulttoken: key absent in software: no such key")

	key, err := Resolve(ctx, lookup, FactorTPM, transport.PasswordVaultKeyRef{Backend: "software", KeyID: "ok"})
	require.NoError(t, err)
	err = SelfTest(ctx, brokenToken{key.Token})
	assert.ErrorIs(t, err, vaultkey.ErrWrongKey)
	assert.EqualError(t, err, "vaulttoken: the token cannot open a secret sealed to its key: "+vaultkey.ErrWrongKey.Error())
}
