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

package xkms

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/keyversion"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/testing/fipstest"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// The key-version tests run on the real software backend (setupDeriveService,
// which wires an in-memory version store), so every version is a real
// backend key and every signature and ciphertext is real.

// genKey generates keyID with algorithm in tenant through the service.
func genKey(t *testing.T, svc *XKMSService, tenant, keyID, algorithm string, size int) {
	t.Helper()
	_, err := svc.GenerateKey(ctxFor(tenant), &transport.GenerateKeyRequest{
		Backend: "software", KeyID: keyID, KeyType: "signing", Algorithm: algorithm, KeySize: size, TenantID: tenant,
	})
	require.NoError(t, err)
}

// ctxFor returns a context carrying tenant's identity, or none (the platform
// scope) for the system tenant.
func ctxFor(tenant string) context.Context {
	if tenant == "" {
		return context.Background()
	}
	return identityCtx(tenant)
}

// rotate rotates keyID in tenant and returns the new version.
func rotate(t *testing.T, svc *XKMSService, tenant, keyID string) uint32 {
	t.Helper()
	resp, err := svc.RotateKey(ctxFor(tenant), &transport.RotateKeyRequest{Backend: "software", KeyID: keyID, TenantID: tenant})
	require.NoError(t, err)
	return resp.KeyVersion
}

// sign signs data with keyID's current version.
func sign(t *testing.T, svc *XKMSService, keyID string, data []byte) *transport.SignResponse {
	t.Helper()
	resp, err := svc.Sign(context.Background(), &transport.SignRequest{Backend: "software", KeyID: keyID, Data: data})
	require.NoError(t, err)
	return resp
}

// verify verifies sig over data with keyID, at version (0: any enabled).
func verify(svc *XKMSService, keyID string, data, sig []byte, version uint32) (*transport.VerifyResponse, error) {
	return svc.Verify(context.Background(), &transport.VerifyRequest{
		Backend: "software", KeyID: keyID, Data: data, Signature: sig, KeyVersion: version,
	})
}

// publicRSAOf returns the RSA public key a PEM block holds.
func publicRSAOf(t *testing.T, pemStr string) *rsa.PublicKey {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	require.NotNil(t, block)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	rsaPub, ok := pub.(*rsa.PublicKey)
	require.True(t, ok)
	return rsaPub
}

// TestRotateKey_SignVerifyAcrossVersions proves a rotation makes the new
// version current, that sign reports it, and that a signature from the old
// version still verifies: newest-first without key_version, and under an
// explicit key_version.
func TestRotateKey_SignVerifyAcrossVersions(t *testing.T) {
	svc := setupDeriveService(t)
	genKey(t, svc, "", "signer", "ecdsa", 0)
	data := []byte("payload")

	v1 := sign(t, svc, "signer", data)
	assert.Equal(t, uint32(1), v1.KeyVersion)

	assert.Equal(t, uint32(2), rotate(t, svc, "", "signer"))
	v2 := sign(t, svc, "signer", data)
	assert.Equal(t, uint32(2), v2.KeyVersion)

	resp, err := verify(svc, "signer", data, v1.Signature, 0)
	require.NoError(t, err)
	assert.True(t, resp.Valid, "an old signature verifies without key_version")
	assert.Equal(t, uint32(1), resp.KeyVersion)

	resp, err = verify(svc, "signer", data, v2.Signature, 0)
	require.NoError(t, err)
	assert.True(t, resp.Valid)
	assert.Equal(t, uint32(2), resp.KeyVersion)

	resp, err = verify(svc, "signer", data, v1.Signature, 1)
	require.NoError(t, err)
	assert.True(t, resp.Valid)

	resp, err = verify(svc, "signer", data, v1.Signature, 2)
	require.NoError(t, err)
	assert.False(t, resp.Valid, "the v1 signature is not v2's")
	assert.Zero(t, resp.KeyVersion)

	_, err = verify(svc, "signer", data, v1.Signature, 7)
	assert.ErrorAs(t, err, new(*keyversion.VersionNotFoundError))
}

// TestRotateKey_KeepsAlgorithmAndSize proves the new version is generated
// with the current version's algorithm and size, read from its key.
func TestRotateKey_KeepsAlgorithmAndSize(t *testing.T) {
	svc := setupDeriveService(t)
	genKey(t, svc, "", "rsa3k", "rsa", 3072)
	rotate(t, svc, "", "rsa3k")

	got, err := svc.GetKey(context.Background(), "software", "rsa3k")
	require.NoError(t, err)
	assert.Equal(t, uint32(2), got.KeyVersion)
	assert.Equal(t, "rsa3k", got.KeyID)
	assert.Equal(t, 3072, publicRSAOf(t, got.PublicKeyPEM).N.BitLen())
}

// TestRotateKey_Errors covers rotation's refusals: a missing key, and no
// version store.
func TestRotateKey_Errors(t *testing.T) {
	svc := setupDeriveService(t)
	_, err := svc.RotateKey(context.Background(), &transport.RotateKeyRequest{Backend: "software", KeyID: "ghost"})
	assert.ErrorIs(t, err, ErrKeyNotFound)

	genKey(t, svc, "", "k", "ed25519", 0)
	svc.keyVersions = subsystem[*keyversion.Store]{}
	_, err = svc.RotateKey(context.Background(), &transport.RotateKeyRequest{Backend: "software", KeyID: "k"})
	assert.ErrorIs(t, err, ErrKeyVersionsNotConfigured)
}

// TestDecrypt_AEADAcrossVersions proves AES-GCM ciphertext from an old
// version decrypts without key_version.
func TestDecrypt_AEADAcrossVersions(t *testing.T) {
	svc := setupDeriveService(t)
	genKey(t, svc, "", "aead", "aes-256-gcm", 0)
	enc, err := svc.Encrypt(context.Background(), &transport.EncryptRequest{Backend: "software", KeyID: "aead", Plaintext: []byte("secret")})
	require.NoError(t, err)
	assert.Equal(t, uint32(1), enc.KeyVersion)

	rotate(t, svc, "", "aead")
	dec, err := svc.Decrypt(context.Background(), &transport.DecryptRequest{
		Backend: "software", KeyID: "aead", Ciphertext: enc.Ciphertext, Nonce: enc.Nonce, Tag: enc.Tag, GCMNonceMode: enc.GCMNonceMode,
	})
	require.NoError(t, err)
	assert.Equal(t, []byte("secret"), dec.Plaintext)
	assert.Equal(t, uint32(1), dec.KeyVersion)

	enc2, err := svc.Encrypt(context.Background(), &transport.EncryptRequest{Backend: "software", KeyID: "aead", Plaintext: []byte("newer")})
	require.NoError(t, err)
	assert.Equal(t, uint32(2), enc2.KeyVersion)
}

// TestDecrypt_CBCRequiresKeyVersion proves AES-CBC ciphertext is never tried
// against several versions: with two enabled versions and no key_version
// the decrypt is refused, and with the encrypt response's key_version it
// succeeds.
func TestDecrypt_CBCRequiresKeyVersion(t *testing.T) {
	svc := setupDeriveService(t)
	genKey(t, svc, "", "cbc", "aes-256-gcm", 0)
	enc, err := svc.Encrypt(context.Background(), &transport.EncryptRequest{
		Backend: "software", KeyID: "cbc", Plaintext: []byte("block cipher text"), Mode: "cbc-pad",
	})
	require.NoError(t, err)

	req := &transport.DecryptRequest{Backend: "software", KeyID: "cbc", Ciphertext: enc.Ciphertext, IV: enc.IV, Mode: "cbc-pad"}
	dec, err := svc.Decrypt(context.Background(), req)
	require.NoError(t, err, "with one enabled version the version is unambiguous")
	assert.Equal(t, uint32(1), dec.KeyVersion)

	rotate(t, svc, "", "cbc")
	_, err = svc.Decrypt(context.Background(), req)
	var required *keyversion.KeyVersionRequiredError
	require.ErrorAs(t, err, &required)
	assert.Equal(t, []uint32{2, 1}, required.Enabled)

	req.KeyVersion = enc.KeyVersion
	dec, err = svc.Decrypt(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, []byte("block cipher text"), dec.Plaintext)
}

// TestDecrypt_ExternalOAEPAcrossVersions proves RSA-OAEP ciphertext made
// outside xkms, under the v1 public key, decrypts after a rotation without
// key_version.
func TestDecrypt_ExternalOAEPAcrossVersions(t *testing.T) {
	svc := setupDeriveService(t)
	genKey(t, svc, "", "oaep", "rsa", 2048)
	got, err := svc.GetKey(context.Background(), "software", "oaep")
	require.NoError(t, err)
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicRSAOf(t, got.PublicKeyPEM), []byte("external"), nil)
	require.NoError(t, err)

	rotate(t, svc, "", "oaep")
	dec, err := svc.Decrypt(context.Background(), &transport.DecryptRequest{
		Backend: "software", KeyID: "oaep", Ciphertext: ciphertext, Padding: "oaep", Hash: "SHA-256",
	})
	require.NoError(t, err)
	assert.Equal(t, []byte("external"), dec.Plaintext)
	assert.Equal(t, uint32(1), dec.KeyVersion)
}

// TestDecrypt_PKCS1v15RequiresKeyVersion proves RSA PKCS#1 v1.5 ciphertext
// is treated like AES-CBC: never tried against several versions.
func TestDecrypt_PKCS1v15RequiresKeyVersion(t *testing.T) {
	// PKCS#1 v1.5 encryption (RFC 8017 section 7.2) is outside the FIPS
	// 140-3 module, which ignores allow_legacy_key_wrap.
	if !fipstest.OutsideFIPS(t) {
		return
	}
	types.SetAllowLegacyKeyWrap(true)
	t.Cleanup(func() { types.SetAllowLegacyKeyWrap(false) })

	svc := setupDeriveService(t)
	genKey(t, svc, "", "pkcs1", "rsa", 2048)
	got, err := svc.GetKey(context.Background(), "software", "pkcs1")
	require.NoError(t, err)
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, publicRSAOf(t, got.PublicKeyPEM), []byte("legacy")) //nolint:staticcheck // SA1019: the legacy construction under test
	require.NoError(t, err)

	rotate(t, svc, "", "pkcs1")
	req := &transport.DecryptRequest{Backend: "software", KeyID: "pkcs1", Ciphertext: ciphertext, Padding: "pkcs1v15"}
	_, err = svc.Decrypt(context.Background(), req)
	assert.ErrorAs(t, err, new(*keyversion.KeyVersionRequiredError))

	req.KeyVersion = 1
	dec, err := svc.Decrypt(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, []byte("legacy"), dec.Plaintext)
}

// TestKeyVersion_DisableEnable proves a disabled version cannot be used and
// comes back when enabled, and that the current version cannot be disabled.
func TestKeyVersion_DisableEnable(t *testing.T) {
	svc := setupDeriveService(t)
	genKey(t, svc, "", "k", "ed25519", 0)
	data := []byte("d")
	old := sign(t, svc, "k", data)
	rotate(t, svc, "", "k")

	ctx := context.Background()
	_, err := svc.DisableKeyVersion(ctx, &transport.KeyVersionRequest{Backend: "software", KeyID: "k", Version: 2})
	assert.ErrorAs(t, err, new(*keyversion.CurrentVersionError))

	resp, err := svc.DisableKeyVersion(ctx, &transport.KeyVersionRequest{Backend: "software", KeyID: "k", Version: 1})
	require.NoError(t, err)
	assert.True(t, resp.Changed)
	assert.Equal(t, transport.KeyVersionDisabled, resp.State)

	_, err = verify(svc, "k", data, old.Signature, 1)
	var unavailable *keyversion.VersionUnavailableError
	require.ErrorAs(t, err, &unavailable)
	assert.Equal(t, keyversion.StateDisabled, unavailable.State)
	result, err := verify(svc, "k", data, old.Signature, 0)
	require.NoError(t, err)
	assert.False(t, result.Valid, "a disabled version is not tried")

	resp, err = svc.EnableKeyVersion(ctx, &transport.KeyVersionRequest{Backend: "software", KeyID: "k", Version: 1})
	require.NoError(t, err)
	assert.True(t, resp.Changed)
	result, err = verify(svc, "k", data, old.Signature, 1)
	require.NoError(t, err)
	assert.True(t, result.Valid)

	resp, err = svc.EnableKeyVersion(ctx, &transport.KeyVersionRequest{Backend: "software", KeyID: "k", Version: 1})
	require.NoError(t, err)
	assert.False(t, resp.Changed, "enabling an enabled version changes nothing")
}

// TestKeyVersion_Retire proves retiring deletes the version's backend key
// for good, that the current version cannot be retired, and that the key
// keeps working through its current version after its version 1 is gone.
func TestKeyVersion_Retire(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()
	genKey(t, svc, "", "k", "ecdsa", 0)
	old := sign(t, svc, "k", []byte("d"))
	rotate(t, svc, "", "k")

	_, err := svc.RetireKeyVersion(ctx, &transport.KeyVersionRequest{Backend: "software", KeyID: "k", Version: 2})
	assert.ErrorAs(t, err, new(*keyversion.CurrentVersionError))

	resp, err := svc.RetireKeyVersion(ctx, &transport.KeyVersionRequest{Backend: "software", KeyID: "k", Version: 1})
	require.NoError(t, err)
	assert.Equal(t, transport.KeyVersionRetired, resp.State)

	b, err := svc.LookupBackend("software")
	require.NoError(t, err)
	_, err = findKeyAttrs(ctx, b, "k")
	assert.ErrorIs(t, err, ErrKeyNotFound, "version 1's backend key is deleted")

	_, err = svc.EnableKeyVersion(ctx, &transport.KeyVersionRequest{Backend: "software", KeyID: "k", Version: 1})
	assert.ErrorAs(t, err, new(*keyversion.RetiredVersionError))
	_, err = svc.RetireKeyVersion(ctx, &transport.KeyVersionRequest{Backend: "software", KeyID: "k", Version: 1})
	assert.ErrorAs(t, err, new(*keyversion.RetiredVersionError))
	_, err = verify(svc, "k", []byte("d"), old.Signature, 1)
	assert.ErrorAs(t, err, new(*keyversion.VersionUnavailableError))

	assert.Equal(t, uint32(2), sign(t, svc, "k", []byte("d")).KeyVersion)
	got, err := svc.GetKey(ctx, "software", "k")
	require.NoError(t, err)
	assert.Equal(t, uint32(2), got.KeyVersion)

	listed, err := svc.ListKeyVersions(ctx, &transport.ListKeyVersionsRequest{Backend: "software", KeyID: "k"})
	require.NoError(t, err)
	require.Len(t, listed.Versions, 2)
	assert.Equal(t, transport.KeyVersionRetired, listed.Versions[0].State)
	assert.Empty(t, listed.Versions[0].PublicKeyPEM)
	assert.True(t, listed.Versions[1].Current)
	assert.NotEmpty(t, listed.Versions[1].PublicKeyPEM)

	// The retired key's name cannot be taken over by a new key.
	_, err = svc.GenerateKey(ctx, &transport.GenerateKeyRequest{Backend: "software", KeyID: "k", Algorithm: "ecdsa"})
	assert.ErrorAs(t, err, new(*KeyExistsError))
	assert.ErrorIs(t, err, backend.ErrKeyAlreadyExists, "a get-or-generate caller must recognize the collision (go-xkms#1599)")
}

// TestKeyVersion_EnableAllDisableAll proves bulk changes never touch the
// current version.
func TestKeyVersion_EnableAllDisableAll(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()
	genKey(t, svc, "", "k", "ed25519", 0)
	rotate(t, svc, "", "k")
	rotate(t, svc, "", "k")

	resp, err := svc.DisableAllKeyVersions(ctx, &transport.AllKeyVersionsRequest{Backend: "software", KeyID: "k"})
	require.NoError(t, err)
	assert.Equal(t, []uint32{1, 2}, resp.Versions)
	assert.Equal(t, 2, resp.Count)

	resp, err = svc.EnableAllKeyVersions(ctx, &transport.AllKeyVersionsRequest{Backend: "software", KeyID: "k"})
	require.NoError(t, err)
	assert.Equal(t, []uint32{1, 2}, resp.Versions)

	resp, err = svc.EnableAllKeyVersions(ctx, &transport.AllKeyVersionsRequest{Backend: "software", KeyID: "k"})
	require.NoError(t, err)
	assert.Empty(t, resp.Versions)

	_, err = svc.EnableAllKeyVersions(ctx, &transport.AllKeyVersionsRequest{Backend: "software", KeyID: "ghost"})
	assert.ErrorIs(t, err, ErrKeyNotFound)
	_, err = svc.EnableAllKeyVersions(ctx, nil)
	assert.ErrorIs(t, err, ErrNilRequest)
}

// TestListKeyVersions_UnrotatedKey proves a key that was never rotated lists
// version 1 alone, current and enabled, with its public key.
func TestListKeyVersions_UnrotatedKey(t *testing.T) {
	svc := setupDeriveService(t)
	genKey(t, svc, "", "k", "ecdsa", 0)
	listed, err := svc.ListKeyVersions(context.Background(), &transport.ListKeyVersionsRequest{Backend: "software", KeyID: "k"})
	require.NoError(t, err)
	assert.Equal(t, uint32(1), listed.CurrentVersion)
	require.Len(t, listed.Versions, 1)
	assert.True(t, listed.Versions[0].Current)
	assert.Equal(t, transport.KeyVersionEnabled, listed.Versions[0].State)
	assert.Contains(t, listed.Versions[0].PublicKeyPEM, "BEGIN PUBLIC KEY")

	_, err = svc.ListKeyVersions(context.Background(), nil)
	assert.ErrorIs(t, err, ErrNilRequest)
	_, err = svc.ListKeyVersions(context.Background(), &transport.ListKeyVersionsRequest{Backend: "software", KeyID: "k--v2"})
	assert.ErrorAs(t, err, new(*keyversion.ReservedKeyIDError), "a version is reached through its key")
}

// TestDeleteKey_DeletesEveryVersion proves DeleteKey removes every version's
// backend key and the version record, so the ID is free again.
func TestDeleteKey_DeletesEveryVersion(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()
	genKey(t, svc, "", "k", "ecdsa", 0)
	rotate(t, svc, "", "k")
	rotate(t, svc, "", "k")

	require.NoError(t, svc.DeleteKey(ctx, "software", "k"))

	b, err := svc.LookupBackend("software")
	require.NoError(t, err)
	keys, err := b.ListKeys(ctx)
	require.NoError(t, err)
	for _, attrs := range keys {
		assert.NotEqual(t, "k", keyversion.BaseKeyID(attrs.CN), "no version of the deleted key remains: %s", attrs.CN)
	}
	_, found, err := svc.KeyVersionStore().Load(ctx, "", "software", "k")
	require.NoError(t, err)
	assert.False(t, found, "the version record is deleted")

	genKey(t, svc, "", "k", "ecdsa", 0)
	assert.Equal(t, uint32(1), sign(t, svc, "k", []byte("d")).KeyVersion)
}

// TestReservedVersionSuffixIsRefused proves no key can be created under a
// name a version would take, by generate, import or copy.
func TestReservedVersionSuffixIsRefused(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()
	var reserved *keyversion.ReservedKeyIDError

	_, err := svc.GenerateKey(ctx, &transport.GenerateKeyRequest{Backend: "software", KeyID: "k--v2", Algorithm: "ecdsa"})
	assert.ErrorAs(t, err, &reserved)
	_, err = svc.ImportKey(ctx, &transport.ImportKeyRequest{Backend: "software", KeyID: "k--v9", KeyType: "aes", WrappedKeyMaterial: []byte("x"), Algorithm: "RSAES_OAEP_SHA_256"})
	assert.ErrorAs(t, err, &reserved)

	genKey(t, svc, "", "src", "aes-256-gcm", 0)
	_, err = svc.CopyKey(ctx, &transport.CopyKeyRequest{SourceBackend: "software", SourceKeyID: "src", DestBackend: "software", DestKeyID: "dst--v1"})
	assert.ErrorAs(t, err, &reserved)

	_, err = svc.GenerateKey(ctx, &transport.GenerateKeyRequest{Backend: "software", KeyID: "k--version", Algorithm: "ecdsa"})
	assert.NoError(t, err, "only a digit suffix is reserved")
}

// TestListKeys_HidesVersionKeys proves a rotated key is listed once, under its
// own ID, with its current version and that version's public key.
func TestListKeys_HidesVersionKeys(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()
	genKey(t, svc, "", "a", "ecdsa", 0)
	genKey(t, svc, "", "b", "ecdsa", 0)
	rotate(t, svc, "", "a")
	rotate(t, svc, "", "a")

	listed, err := svc.ListKeys(ctx, "software")
	require.NoError(t, err)
	byID := map[string]transport.KeyInfo{}
	for _, info := range listed.Keys {
		_, dup := byID[info.KeyID]
		assert.False(t, dup, "key %s listed twice", info.KeyID)
		byID[info.KeyID] = info
	}
	require.Len(t, byID, 2)
	assert.Equal(t, uint32(3), byID["a"].KeyVersion)
	assert.Equal(t, uint32(1), byID["b"].KeyVersion)

	got, err := svc.GetKey(ctx, "software", "a")
	require.NoError(t, err)
	assert.Equal(t, got.PublicKeyPEM, byID["a"].PublicKeyPEM, "the listing shows the current version's public key")
}

// TestRotateScopeKeys_RotatesOnlyTheTargetTenant proves a scope rotation
// reaches every key of its tenant and no other tenant's.
func TestRotateScopeKeys_RotatesOnlyTheTargetTenant(t *testing.T) {
	svc := setupDeriveService(t)
	genKey(t, svc, "acme", "one", "ecdsa", 0)
	genKey(t, svc, "acme", "two", "aes-256-gcm", 0)
	genKey(t, svc, "globex", "one", "ecdsa", 0)
	rotate(t, svc, "acme", "one")

	resp, err := svc.RotateScopeKeys(identityCtx("acme"), &transport.RotateScopeKeysRequest{})
	require.NoError(t, err)
	assert.Equal(t, "acme", resp.TenantID)
	assert.Equal(t, 2, resp.Rotated)
	assert.Zero(t, resp.Failed)
	assert.Zero(t, resp.Skipped)
	versions := map[string]uint32{}
	for _, r := range resp.Results {
		versions[r.KeyID] = r.KeyVersion
	}
	assert.Equal(t, map[string]uint32{"one": 3, "two": 2}, versions)

	globex, err := svc.GetKey(identityCtx("globex"), "software", "one")
	require.NoError(t, err)
	assert.Equal(t, uint32(1), globex.KeyVersion, "another tenant's key is untouched")

	_, err = svc.RotateScopeKeys(identityCtx("acme"), &transport.RotateScopeKeysRequest{TenantID: "globex"})
	var binding *TenantBindingError
	assert.ErrorAs(t, err, &binding, "a tenant cannot rotate another tenant")

	_, err = svc.RotateScopeKeys(systemCtx(), &transport.RotateScopeKeysRequest{TenantID: "globex"})
	assert.ErrorAs(t, err, &binding, "the system tenant cannot rotate another tenant")

	resp, err = svc.RotateScopeKeys(identityCtx("globex"), &transport.RotateScopeKeysRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)
	assert.Equal(t, uint32(2), resp.Results[0].KeyVersion)

	_, err = svc.RotateScopeKeys(context.Background(), nil)
	assert.ErrorIs(t, err, ErrNilRequest)
}

// saveCert stores a self-signed certificate for the software backend's key
// under certID, the reference a caller saved it with.
func saveCert(t *testing.T, svc *XKMSService, certID string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	b, err := svc.LookupBackend("software")
	require.NoError(t, err)
	require.NoError(t, b.SaveCert(context.Background(), certID, selfSignedCertForKey(t, key, certID, 1)))
}

// TestRotateScopeKeys_SkipsPinnedAndCertifiedKeys proves a scope rotation
// rotates ordinary keys, and skips -- with the reason, not as a failure --
// the barrier's seal wrapping key, which the barrier names exactly, and keys
// with a certificate, whether it was saved under the bare name or a full key
// ID.
func TestRotateScopeKeys_SkipsPinnedAndCertifiedKeys(t *testing.T) {
	svc := setupDeriveService(t)
	genKey(t, svc, "", "plain", "ecdsa", 0)
	genKey(t, svc, "", seal.SealKeyCN, "ecdsa", 0)
	genKey(t, svc, "", "tls", "ecdsa", 0)
	genKey(t, svc, "", "web", "ecdsa", 0)
	saveCert(t, svc, "tls")
	saveCert(t, svc, "software:signing:ecdsa:web")

	resp, err := svc.RotateScopeKeys(context.Background(), &transport.RotateScopeKeysRequest{})
	require.NoError(t, err)
	assert.Equal(t, 1, resp.Rotated)
	assert.Equal(t, 3, resp.Skipped)
	assert.Zero(t, resp.Failed)
	byKey := map[string]transport.KeyRotationResult{}
	for _, r := range resp.Results {
		byKey[r.KeyID] = r
	}
	assert.Equal(t, transport.KeyRotationResult{Backend: "software", KeyID: "plain", State: transport.KeyRotationRotated, KeyVersion: 2}, byKey["plain"])
	assert.Equal(t, transport.KeyRotationResult{Backend: "software", KeyID: seal.SealKeyCN, State: transport.KeyRotationSkipped, Reason: SkipReasonBarrierSealKey}, byKey[seal.SealKeyCN])
	assert.Equal(t, SkipReasonCertificate, byKey["tls"].Reason)
	assert.Equal(t, SkipReasonCertificate, byKey["web"].Reason)

	got, err := svc.GetKey(context.Background(), "software", "tls")
	require.NoError(t, err)
	assert.Equal(t, uint32(1), got.KeyVersion, "a skipped key keeps its version")
}

// TestRotateScopeKeys_CertificateListingFails proves a backend whose
// certificates cannot be listed is reported as failed and none of its keys
// is rotated, since a certified key could not be told apart.
func TestRotateScopeKeys_CertificateListingFails(t *testing.T) {
	store := newMockKeyStore("mock")
	store.listCertsErr = errors.New("certificate store offline")
	_, err := store.GenerateECDSA(context.Background(), &types.KeyAttributes{CN: "k"})
	require.NoError(t, err)
	svc := setupDeriveService(t)
	svc.backends["mock"] = store

	resp, err := svc.RotateScopeKeys(context.Background(), &transport.RotateScopeKeysRequest{})
	require.NoError(t, err)
	var failed []transport.KeyRotationResult
	for _, r := range resp.Results {
		if r.Backend == "mock" {
			failed = append(failed, r)
		}
	}
	require.Len(t, failed, 1)
	assert.Equal(t, transport.KeyRotationFailed, failed[0].State)
	assert.Contains(t, failed[0].Error, "certificate store offline")
	assert.Equal(t, 1, resp.Failed)
}

// TestPinnedKeyReason proves the exact-name rules: PIV slot keys and the
// TPM2 sealed objects Seal names are pinned on a TPM2 backend only, the
// barrier's seal wrapping key on any backend, and every other key is not.
func TestPinnedKeyReason(t *testing.T) {
	tpm := newMockKeyStoreWithSealer("tpm2", types.BackendTypeTPM2)
	software := newMockKeyStoreWithSealer("software", types.BackendTypeSoftware)
	sealed, err := newTPMSealedObjectName()
	require.NoError(t, err)

	tests := []struct {
		name   string
		b      Backend
		keyID  string
		reason string
	}{
		{"PIV slot on TPM2", tpm, PivSlotCN("9a"), SkipReasonPIVSlot},
		{"retired PIV slot on TPM2", tpm, "piv-95", SkipReasonPIVSlot},
		{"TPM2 sealed object", tpm, sealed, SkipReasonTPMSealedObject},
		{"barrier seal key on TPM2", tpm, seal.SealKeyCN, SkipReasonBarrierSealKey},
		{"barrier seal key on software", software, seal.SealKeyCN, SkipReasonBarrierSealKey},
		{"PIV name off TPM2", software, "piv-9a", ""},
		{"not a slot", tpm, "piv-xyz", ""},
		{"ordinary key", tpm, "signer", ""},
		{"key-based default sealing key", software, "xkms-sealing-key-software", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, pinned := pinnedKeyReason(tt.b, tt.keyID)
			assert.Equal(t, tt.reason != "", pinned)
			assert.Equal(t, tt.reason, reason)
		})
	}
}

// TestRotateKey_ReportsCertificateReissue proves rotating a key with a
// certificate succeeds and says the certificate must be re-issued, a key
// without one does not, and a failure to list certificates leaves the key
// unrotated.
func TestRotateKey_ReportsCertificateReissue(t *testing.T) {
	svc := setupDeriveService(t)
	genKey(t, svc, "", "tls", "ecdsa", 0)
	genKey(t, svc, "", "plain", "ecdsa", 0)
	saveCert(t, svc, "tls")

	resp, err := svc.RotateKey(context.Background(), &transport.RotateKeyRequest{Backend: "software", KeyID: "tls"})
	require.NoError(t, err)
	assert.Equal(t, uint32(2), resp.KeyVersion)
	assert.True(t, resp.CertificateReissueRequired)

	resp, err = svc.RotateKey(context.Background(), &transport.RotateKeyRequest{Backend: "software", KeyID: "plain"})
	require.NoError(t, err)
	assert.False(t, resp.CertificateReissueRequired)

	store := newMockKeyStore("mock")
	store.listCertsErr = errors.New("certificate store offline")
	svc.backends["mock"] = store
	_, err = svc.RotateKey(context.Background(), &transport.RotateKeyRequest{Backend: "mock", KeyID: "k"})
	assert.ErrorContains(t, err, "certificate store offline")
}

// TestSeal_RecordsAndUsesTheSealingKeyVersion proves a seal under a named key
// records its version beside the ciphertext and unseals after a rotation,
// with and without the recorded version.
func TestSeal_RecordsAndUsesTheSealingKeyVersion(t *testing.T) {
	svc := setupDeriveService(t)
	storeTenantECDSAKey(t, svc, "", "sealer")
	blob := sealAs(t, svc, "", "sealer", []byte("sealed"))
	assert.Equal(t, uint32(1), blob.KeyVersion)

	rotate(t, svc, "", "sealer")
	newer := sealAs(t, svc, "", "sealer", []byte("newer"))
	assert.Equal(t, uint32(2), newer.KeyVersion)

	opened, err := svc.Unseal(context.Background(), &transport.UnsealRequest{
		Backend: "software", KeyID: "sealer", Ciphertext: blob.Ciphertext, Nonce: blob.Nonce, Tag: blob.Tag, KeyVersion: blob.KeyVersion,
	})
	require.NoError(t, err)
	assert.Equal(t, []byte("sealed"), opened.Plaintext)

	plaintext, err := unsealAs(svc, "", "sealer", blob)
	require.NoError(t, err, "without the recorded version every enabled version is tried")
	assert.Equal(t, []byte("sealed"), plaintext)
}

// TestDeriveKey_ReproducibleUnderItsVersion proves a derivation names the
// base key version it used and reproduces under it after a rotation.
func TestDeriveKey_ReproducibleUnderItsVersion(t *testing.T) {
	svc := setupDeriveService(t)
	keyID := storeSymmetricKey(t, svc, "kdf-base")
	req := &transport.DeriveKeyRequest{Backend: "software", KeyID: keyID, Algorithm: "hkdf", Hash: "SHA-256", KeyLength: 32, Info: []byte("ctx")}

	first, err := svc.DeriveKey(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, uint32(1), first.KeyVersion)

	rotate(t, svc, "", keyID)
	current, err := svc.DeriveKey(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), current.KeyVersion)
	assert.False(t, bytes.Equal(first.DerivedKey, current.DerivedKey))

	req.KeyVersion = 1
	again, err := svc.DeriveKey(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, first.DerivedKey, again.DerivedKey)
}

// TestUnwrapKeyByID_AcrossVersions proves a key wrapped under an old version
// of the wrapping key unwraps after a rotation: AES-KW is authenticated, so
// each enabled version is tried.
func TestUnwrapKeyByID_AcrossVersions(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()
	kek := storeSymmetricKey(t, svc, "kek")
	target := storeSymmetricKey(t, svc, "target")

	wrapped, err := svc.WrapKeyByID(ctx, &transport.WrapKeyByIDRequest{
		WrappingKeyID: kek, WrappingKeyBackend: "software", TargetKeyID: target, TargetKeyBackend: "software", Algorithm: string(types.WrapAESKW),
	})
	require.NoError(t, err)
	assert.Equal(t, uint32(1), wrapped.WrappingKeyVersion)

	rotate(t, svc, "", kek)
	resp, err := svc.UnwrapKeyByID(ctx, &transport.UnwrapKeyByIDRequest{
		WrappedKey: wrapped.WrappedKey, UnwrappingKeyID: kek, UnwrappingKeyBackend: "software", Algorithm: string(types.WrapAESKW),
		TargetKeyID: "unwrapped", TargetKeyBackend: "software", TargetKeyType: "aes", TargetKeySize: 256,
	})
	require.NoError(t, err)
	assert.True(t, resp.Success)

	_, err = svc.UnwrapKeyByID(ctx, &transport.UnwrapKeyByIDRequest{
		WrappedKey: wrapped.WrappedKey, UnwrappingKeyID: kek, UnwrappingKeyBackend: "software", Algorithm: string(types.WrapAESKW),
		TargetKeyID: "again--v2", TargetKeyBackend: "software", TargetKeyType: "aes", TargetKeySize: 256,
	})
	assert.ErrorAs(t, err, new(*keyversion.ReservedKeyIDError))
}

// TestRotateKey_RemovesAnInterruptedRotation proves a backend key left under
// the next version's name by a rotation that never recorded it is replaced,
// not collided with.
func TestRotateKey_RemovesAnInterruptedRotation(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()
	genKey(t, svc, "", "k", "ed25519", 0)
	b, err := svc.LookupBackend("software")
	require.NoError(t, err)
	orphan, err := b.GenerateEd25519(ctx, &types.KeyAttributes{CN: "k--v2", KeyType: types.KeyTypeSigning, StoreType: types.StoreSoftware})
	require.NoError(t, err)

	assert.Equal(t, uint32(2), rotate(t, svc, "", "k"))
	got, err := svc.GetKey(ctx, "software", "k")
	require.NoError(t, err)
	orphanPEM, err := pubKeyPEM(orphan)
	require.NoError(t, err)
	assert.NotEqual(t, orphanPEM, got.PublicKeyPEM, "version 2 is a new key, not the orphan")
}

// TestFindKeyAttributes proves a key is found through any of its versions
// and a version's own name is refused.
func TestFindKeyAttributes(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()
	genKey(t, svc, "", "k", "ecdsa", 0)
	rotate(t, svc, "", "k")
	_, err := svc.RetireKeyVersion(ctx, &transport.KeyVersionRequest{Backend: "software", KeyID: "k", Version: 1})
	require.NoError(t, err)

	b, err := svc.LookupBackend("software")
	require.NoError(t, err)
	attrs, err := FindKeyAttributes(ctx, b, "k")
	require.NoError(t, err)
	assert.Equal(t, "k--v2", attrs.CN)

	_, err = FindKeyAttributes(ctx, b, "ghost")
	assert.ErrorIs(t, err, ErrKeyNotFound)
	_, err = FindKeyAttributes(ctx, b, "k--v2")
	assert.ErrorAs(t, err, new(*keyversion.ReservedKeyIDError))
}

// TestSetKeyVersionState_Errors covers the version-state changes' refusals:
// a nil request, a missing key, version 0, and no store.
func TestSetKeyVersionState_Errors(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()
	genKey(t, svc, "", "k", "ecdsa", 0)

	_, err := svc.EnableKeyVersion(ctx, nil)
	assert.ErrorIs(t, err, ErrNilRequest)
	_, err = svc.RetireKeyVersion(ctx, nil)
	assert.ErrorIs(t, err, ErrNilRequest)
	_, err = svc.DisableKeyVersion(ctx, &transport.KeyVersionRequest{Backend: "software", KeyID: "ghost", Version: 1})
	assert.ErrorIs(t, err, ErrKeyNotFound)
	_, err = svc.DisableKeyVersion(ctx, &transport.KeyVersionRequest{Backend: "software", KeyID: "k", Version: 0})
	assert.ErrorAs(t, err, new(*keyversion.InvalidVersionError))

	svc.keyVersions = subsystem[*keyversion.Store]{}
	_, err = svc.EnableKeyVersion(ctx, &transport.KeyVersionRequest{Backend: "software", KeyID: "k", Version: 1})
	assert.ErrorIs(t, err, ErrKeyVersionsNotConfigured)
	_, err = svc.RotateScopeKeys(ctx, &transport.RotateScopeKeysRequest{})
	assert.ErrorIs(t, err, ErrKeyVersionsNotConfigured)
}

// TestRotateKey_TenantScoped proves a tenant's rotation creates the version
// in the tenant and records it under the tenant.
func TestRotateKey_TenantScoped(t *testing.T) {
	svc := setupDeriveService(t)
	genKey(t, svc, "acme", "k", "ecdsa", 0)
	assert.Equal(t, uint32(2), rotate(t, svc, "acme", "k"))

	_, found, err := svc.KeyVersionStore().Load(context.Background(), "acme", "software", "k")
	require.NoError(t, err)
	assert.True(t, found)

	_, err = svc.RotateKey(identityCtx("globex"), &transport.RotateKeyRequest{Backend: "software", KeyID: "k", TenantID: "globex"})
	assert.ErrorIs(t, err, ErrKeyNotFound, "another tenant's key is not found")

	sig, err := svc.Sign(identityCtx("acme"), &transport.SignRequest{Backend: "software", KeyID: "k", Data: []byte("d"), TenantID: "acme"})
	require.NoError(t, err)
	assert.Equal(t, uint32(2), sig.KeyVersion)
}

// TestGenerateKey_TenantSymmetricKeyStaysInTenant proves a tenant's
// symmetric key is created in the tenant -- visible to it and to no other
// tenant -- so it can be listed, used and rotated there.
func TestGenerateKey_TenantSymmetricKeyStaysInTenant(t *testing.T) {
	svc := setupDeriveService(t)
	genKey(t, svc, "acme", "aes", "aes-256-gcm", 0)

	acme, err := svc.ListKeys(identityCtx("acme"), "software")
	require.NoError(t, err)
	require.Len(t, acme.Keys, 1)
	assert.Equal(t, "aes", acme.Keys[0].KeyID)

	globex, err := svc.ListKeys(identityCtx("globex"), "software")
	require.NoError(t, err)
	assert.Empty(t, globex.Keys)

	_, err = svc.Encrypt(identityCtx("globex"), &transport.EncryptRequest{Backend: "software", KeyID: "aes", Plaintext: []byte("x"), TenantID: "globex"})
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

// TestRotateKey_ConcurrentRotationsTakeDistinctVersions proves concurrent
// rotations of one key are serialized: each creates its own version, and the
// record ends at the highest.
func TestRotateKey_ConcurrentRotationsTakeDistinctVersions(t *testing.T) {
	svc := setupDeriveService(t)
	genKey(t, svc, "", "k", "ed25519", 0)

	const rotations = 5
	versions := make(chan uint32, rotations)
	errs := make(chan error, rotations)
	var wg sync.WaitGroup
	for range rotations {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := svc.RotateKey(context.Background(), &transport.RotateKeyRequest{Backend: "software", KeyID: "k"})
			if err != nil {
				errs <- err
				return
			}
			versions <- resp.KeyVersion
		}()
	}
	wg.Wait()
	close(versions)
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	seen := map[uint32]bool{}
	for v := range versions {
		assert.False(t, seen[v], "version %d created twice", v)
		seen[v] = true
	}
	assert.Len(t, seen, rotations)

	listed, err := svc.ListKeyVersions(context.Background(), &transport.ListKeyVersionsRequest{Backend: "software", KeyID: "k"})
	require.NoError(t, err)
	assert.Equal(t, uint32(rotations+1), listed.CurrentVersion)
	assert.Len(t, listed.Versions, rotations+1)
}
