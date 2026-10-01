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

package staticpw

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/vaultkey"
)

// keyHolder is a client holding a key factor's private key.
type keyHolder struct {
	priv crypto.Signer
	tok  vaultkey.Token
}

func newECHolder(t *testing.T) *keyHolder {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tok, err := vaultkey.NewKeyToken(k)
	require.NoError(t, err)
	return &keyHolder{priv: k, tok: tok}
}

func newRSAHolder(t *testing.T) *keyHolder {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tok, err := vaultkey.NewKeyToken(k)
	require.NoError(t, err)
	return &keyHolder{priv: k, tok: tok}
}

func (h *keyHolder) publicKeyDER(t *testing.T) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(h.priv.Public())
	require.NoError(t, err)
	return der
}

func (h *keyHolder) certificateDER(t *testing.T) []byte {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "alice@example.com"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, h.priv.Public(), h.priv)
	require.NoError(t, err)
	return der
}

// enrollCred is the credential a client sends to enroll h as a factor.
func (h *keyHolder) enrollCred(t *testing.T, typ FactorType) VaultCredential {
	t.Helper()
	cred := VaultCredential{Type: typ, Label: string(typ) + " key", KeyRef: VaultKeyRef{Backend: "software", KeyID: "vault-" + string(typ)}}
	if typ == FactorCertificate {
		cred.Certificate = h.certificateDER(t)
	} else {
		cred.PublicKey = h.publicKeyDER(t)
	}
	if typ == FactorTPM {
		cred.KeyRef.TPMPolicy = "platform"
	}
	return cred
}

// unlockCred recovers f's secret with h's token, as a client does.
func (h *keyHolder) unlockCred(t *testing.T, f VaultFactorInfo) (VaultCredential, error) {
	t.Helper()
	secret, err := vaultkey.Open(context.Background(), h.tok, vaultkey.Factor{
		Fingerprint: f.KeyFingerprint, Algorithm: f.KeyAlgorithm, Challenge: f.KeyChallenge, Check: f.KeyCheck,
	})
	if err != nil {
		return VaultCredential{}, err
	}
	return VaultCredential{Type: f.Type, KeyFingerprint: f.KeyFingerprint, Secret: secret}, nil
}

// TestKeyFactor_EnrollAndUnlock covers every key factor type with an EC and
// an RSA key: the first enrollment initializes the vault, a lock closes it,
// and the private-key holder's recovered secret opens it again.
func TestKeyFactor_EnrollAndUnlock(t *testing.T) {
	for _, typ := range []FactorType{FactorPIV, FactorCertificate, FactorTPM} {
		for name, holder := range map[string]func(*testing.T) *keyHolder{"EC": newECHolder, "RSA": newRSAHolder} {
			t.Run(string(typ)+"/"+name, func(t *testing.T) {
				mgr, _, _ := vaultFixture(t)
				ctx := context.Background()
				h := holder(t)

				res, err := mgr.EnrollFactor(ctx, "tenant-a", "alice", h.enrollCred(t, typ))
				require.NoError(t, err)
				require.NotEmpty(t, res.RecoveryCode, "a key factor can initialize the vault")
				f := res.Factor
				assert.Equal(t, typ, f.Type)
				assert.Len(t, f.KeyFingerprint, 64)
				assert.NotEmpty(t, f.KeyChallenge)
				assert.Equal(t, "vault-"+string(typ), f.KeyRef.KeyID)
				if typ == FactorCertificate {
					assert.Contains(t, f.CertificateSubject, "alice@example.com")
				}

				store := unlocked(t, mgr, "tenant-a", "alice")
				require.NoError(t, store.Add(&StaticPassword{Name: "bank", Password: "pw"}))
				require.NoError(t, mgr.LockUser("tenant-a", "alice"))

				cred, err := h.unlockCred(t, f)
				require.NoError(t, err)
				require.NoError(t, mgr.UnlockUser(ctx, "tenant-a", "alice", cred))
				got, err := scoped(t, mgr, "tenant-a", "alice").Get("bank")
				require.NoError(t, err)
				assert.Equal(t, "pw", got.Password)
			})
		}
	}
}

// TestKeyFactor_WrongTokenIsRefused proves another key cannot unlock: the
// client detects it before sending (vaultkey.ErrWrongKey), and a secret
// from another key is rejected by the server without saying why.
func TestKeyFactor_WrongTokenIsRefused(t *testing.T) {
	mgr, _, _ := vaultFixture(t)
	ctx := context.Background()
	right, wrong := newECHolder(t), newECHolder(t)
	res, err := mgr.EnrollFactor(ctx, "tenant-a", "alice", right.enrollCred(t, FactorPIV))
	require.NoError(t, err)
	require.NoError(t, mgr.LockUser("tenant-a", "alice"))

	_, err = wrong.unlockCred(t, res.Factor)
	assert.ErrorIs(t, err, vaultkey.ErrWrongKey)

	bogus := VaultCredential{Type: FactorPIV, KeyFingerprint: res.Factor.KeyFingerprint, Secret: bytes.Repeat([]byte{7}, vaultkey.SecretLength)}
	assert.ErrorIs(t, mgr.UnlockUser(ctx, "tenant-a", "alice", bogus), ErrVaultCredentialRejected)

	// The right secret presented as the wrong factor type opens nothing.
	cred, err := right.unlockCred(t, res.Factor)
	require.NoError(t, err)
	cred.Type = FactorTPM
	assert.ErrorIs(t, mgr.UnlockUser(ctx, "tenant-a", "alice", cred), ErrVaultCredentialRejected)
}

// TestKeyFactor_ServerCannotUnlockAlone proves the tenant barrier holds no
// key factor's secret: everything stored for the factor -- challenge and
// key-check value included -- does not contain it, and the DEK unwraps only
// with the secret the private key recovers.
func TestKeyFactor_ServerCannotUnlockAlone(t *testing.T) {
	mgr, _, raw := vaultFixture(t)
	ctx := context.Background()
	h := newRSAHolder(t)
	res, err := mgr.EnrollFactor(ctx, "tenant-a", "alice", h.enrollCred(t, FactorCertificate))
	require.NoError(t, err)
	cred, err := h.unlockCred(t, res.Factor)
	require.NoError(t, err)

	vault, err := scope.PersonalPrefix("tenant-a", VaultFeature, "alice")
	require.NoError(t, err)
	require.NoError(t, raw.Scan(ctx, vault, func(key string, value []byte) error {
		assert.False(t, bytes.Contains(value, cred.Secret), "factor %s stores its secret", key)
		return nil
	}))
}

func TestKeyFactor_EnrollmentRefusals(t *testing.T) {
	mgr, _, _ := vaultFixture(t)
	ctx := context.Background()
	h := newECHolder(t)

	noCert := h.enrollCred(t, FactorCertificate)
	noCert.Certificate = nil
	noCert.PublicKey = h.publicKeyDER(t)
	_, err := mgr.EnrollFactor(ctx, "tenant-a", "alice", noCert)
	assert.ErrorIs(t, err, ErrVaultInvalidCredential, "a certificate factor needs the certificate")

	junk := VaultCredential{Type: FactorTPM, PublicKey: []byte("not a key")}
	_, err = mgr.EnrollFactor(ctx, "tenant-a", "alice", junk)
	assert.ErrorIs(t, err, ErrVaultInvalidCredential)
	var keyErr *VaultKeyError
	assert.ErrorAs(t, err, &keyErr)

	_, err = mgr.EnrollFactor(ctx, "tenant-a", "alice", h.enrollCred(t, FactorPIV))
	require.NoError(t, err)
	_, err = mgr.EnrollFactor(ctx, "tenant-a", "alice", h.enrollCred(t, FactorTPM))
	assert.ErrorIs(t, err, ErrVaultKeyExists, "one key is one factor, whatever its type")

	// A malformed unlock credential is refused before any unwrap.
	assert.ErrorIs(t, mgr.UnlockUser(ctx, "tenant-a", "alice", VaultCredential{Type: FactorPIV, Secret: []byte{1}}), ErrVaultInvalidCredential)
}

// TestKeyFactor_RotateAndRemove proves a key factor rotates to a new key
// and is removable while another factor remains.
func TestKeyFactor_RotateAndRemove(t *testing.T) {
	mgr, _, _ := vaultFixture(t)
	ctx := context.Background()
	unlocked(t, mgr, "tenant-a", "alice")
	oldKey, newKey := newECHolder(t), newECHolder(t)

	res, err := mgr.EnrollFactor(ctx, "tenant-a", "alice", oldKey.enrollCred(t, FactorTPM))
	require.NoError(t, err)
	rotated, err := mgr.RotateFactor(ctx, "tenant-a", "alice", res.Factor.ID, newKey.enrollCred(t, FactorTPM))
	require.NoError(t, err)
	require.NoError(t, mgr.LockUser("tenant-a", "alice"))

	_, err = oldKey.unlockCred(t, rotated.Factor)
	assert.ErrorIs(t, err, vaultkey.ErrWrongKey)
	cred, err := newKey.unlockCred(t, rotated.Factor)
	require.NoError(t, err)
	require.NoError(t, mgr.UnlockUser(ctx, "tenant-a", "alice", cred))

	require.NoError(t, mgr.RemoveFactor(ctx, "tenant-a", "alice", rotated.Factor.ID))
	require.NoError(t, mgr.LockUser("tenant-a", "alice"))
	assert.ErrorIs(t, mgr.UnlockUser(ctx, "tenant-a", "alice", cred), ErrVaultCredentialRejected)
}

// TestKeyFactor_RecoverWithAKey proves the recovery code can enroll a key
// factor when the others are lost.
func TestKeyFactor_RecoverWithAKey(t *testing.T) {
	mgr, _, _ := vaultFixture(t)
	ctx := context.Background()
	first, err := mgr.EnrollFactor(ctx, "tenant-a", "alice", pass("alice"))
	require.NoError(t, err)
	require.NoError(t, mgr.LockUser("tenant-a", "alice"))

	h := newECHolder(t)
	res, err := mgr.RecoverVault(ctx, "tenant-a", "alice", []byte(first.RecoveryCode), h.enrollCred(t, FactorPIV))
	require.NoError(t, err)
	require.NoError(t, mgr.LockUser("tenant-a", "alice"))
	cred, err := h.unlockCred(t, res.Factor)
	require.NoError(t, err)
	require.NoError(t, mgr.UnlockUser(ctx, "tenant-a", "alice", cred))
}

// TestPasskey_RelyingParty proves passkeys are scoped to the server's
// relying party: status advertises it, a factor records it, another one is
// refused, and a deployment without one offers no passkeys.
func TestPasskey_RelyingParty(t *testing.T) {
	mgr, _, _ := vaultFixture(t)
	ctx := context.Background()

	status, err := mgr.VaultStatus(ctx, "tenant-a", "alice")
	require.NoError(t, err)
	assert.Equal(t, testRelyingParty, status.PasskeyRelyingParty)

	res, err := mgr.EnrollFactor(ctx, "tenant-a", "alice", passkey("k1", 0x11))
	require.NoError(t, err)
	assert.Equal(t, testRelyingParty, res.Factor.RelyingParty)

	other := passkey("k2", 0x22)
	other.RelyingParty = "xkms-password-vault"
	_, err = mgr.EnrollFactor(ctx, "tenant-a", "alice", other)
	assert.ErrorIs(t, err, ErrVaultRelyingPartyMismatch)

	reg := newTestRegistry(t)
	registerAndInitTenant(t, reg, "tenant-a")
	bare, err := NewTenantPasswordStoreManager(reg, NewStore(storage.New()))
	require.NoError(t, err)
	_, err = bare.EnrollFactor(ctx, "tenant-a", "bob", passkey("k3", 0x33))
	assert.ErrorIs(t, err, ErrVaultPasskeyUnavailable)
	bareStatus, err := bare.VaultStatus(ctx, "tenant-a", "bob")
	require.NoError(t, err)
	assert.Empty(t, bareStatus.PasskeyRelyingParty)
	// Passphrases are unaffected.
	_, err = bare.EnrollFactor(ctx, "tenant-a", "bob", pass("bob"))
	require.NoError(t, err)
}
