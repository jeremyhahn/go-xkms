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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// These tests pin the tenant scoping of the certificate store and of Seal
// and Unseal at the service (go-xkms#1228). Every transport is a thin
// adapter over these methods, so the scoping is only real if it holds here.

// tenantCertPEM returns a fresh self-signed certificate as PEM.
func tenantCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tenant-cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// saveTenantCert saves a certificate and a one-element chain under keyID as
// tenantID, through the service.
func saveTenantCert(t *testing.T, svc *XKMSService, tenantID, keyID string) string {
	t.Helper()
	certPEM := tenantCertPEM(t)
	require.NoError(t, svc.SaveCertificate(identityCtx(tenantID), &transport.SaveCertificateRequest{
		Backend: "software", KeyID: keyID, CertificatePEM: certPEM, TenantID: tenantID,
	}))
	require.NoError(t, svc.SaveCertificateChain(identityCtx(tenantID), &transport.SaveCertificateChainRequest{
		Backend: "software", KeyID: keyID, ChainPEM: []string{certPEM}, TenantID: tenantID,
	}))
	return certPEM
}

// certErrorsFor runs every by-ID certificate read as tenantID naming keyID
// and returns each one's error text, so two deployments can be compared.
func certErrorsFor(t *testing.T, svc *XKMSService, tenantID, keyID string) []string {
	t.Helper()
	ctx := identityCtx(tenantID)
	errText := func(err error) string {
		if err == nil {
			return "<nil>"
		}
		return err.Error()
	}
	_, getErr := svc.GetCertificate(ctx, "software", keyID)
	_, chainErr := svc.GetCertificateChain(ctx, "software", keyID)
	_, tlsErr := svc.GetTLSCertificate(ctx, "software", keyID)
	exists, existsErr := svc.CertificateExists(ctx, "software", keyID)
	deleteErr := svc.DeleteCertificate(ctx, "software", keyID)
	return []string{
		errText(getErr), errText(chainErr), errText(tlsErr),
		errText(existsErr), map[bool]string{true: "exists", false: "absent"}[exists],
		errText(deleteErr),
	}
}

func TestCertificateMethods_ConfinedToTheCallersTenant(t *testing.T) {
	for _, keyID := range []string{"web", "acme/web"} {
		t.Run(keyID, func(t *testing.T) {
			svc := setupDeriveService(t)
			missing := certErrorsFor(t, svc, "globex", keyID)

			svc = setupDeriveService(t)
			acmePEM := saveTenantCert(t, svc, "acme", "web")
			cross := certErrorsFor(t, svc, "globex", keyID)
			assert.Equal(t, missing, cross,
				"another tenant's certificate must read exactly like one nobody stored")

			got, err := svc.GetCertificate(identityCtx("acme"), "software", "web")
			require.NoError(t, err, "acme's certificate must survive globex's attempts")
			assert.Equal(t, acmePEM, got.CertificatePEM)
		})
	}
}

func TestCertificateMethods_PlatformCertIsNotATenantCert(t *testing.T) {
	svc := setupDeriveService(t)
	platformPEM := saveTenantCert(t, svc, "", "sys")

	_, err := svc.GetCertificate(identityCtx("acme"), "software", "sys")
	require.Error(t, err, "a tenant must not read the platform's certificate")

	// A tenant saving under the platform certificate's ID writes its own.
	acmePEM := saveTenantCert(t, svc, "acme", "sys")
	own, err := svc.GetCertificate(identityCtx("acme"), "software", "sys")
	require.NoError(t, err)
	assert.Equal(t, acmePEM, own.CertificatePEM)
	platform, err := svc.GetCertificate(context.Background(), "software", "sys")
	require.NoError(t, err)
	assert.Equal(t, platformPEM, platform.CertificatePEM, "the platform's certificate must not be overwritten")
}

func TestCertificateMethods_RejectTenantNamespaceInKeyID(t *testing.T) {
	svc := setupDeriveService(t)
	err := svc.SaveCertificate(identityCtx("globex"), &transport.SaveCertificateRequest{
		Backend: "software", KeyID: "acme/web", CertificatePEM: tenantCertPEM(t), TenantID: "globex",
	})
	var parseErr *ErrKeyIDParse
	require.ErrorAs(t, err, &parseErr)
	err = svc.SaveCertificateChain(identityCtx("globex"), &transport.SaveCertificateChainRequest{
		Backend: "software", KeyID: "acme/web", ChainPEM: []string{tenantCertPEM(t)}, TenantID: "globex",
	})
	require.ErrorAs(t, err, &parseErr)
}

func TestListCertificates_ConfinedToTheCallersTenant(t *testing.T) {
	svc := setupDeriveService(t)
	saveTenantCert(t, svc, "acme", "web")
	saveTenantCert(t, svc, "globex", "api")
	saveTenantCert(t, svc, "", "sys")

	for tenant, want := range map[string]string{"acme": "web", "globex": "api"} {
		resp, err := svc.ListCertificates(identityCtx(tenant), "software")
		require.NoError(t, err)
		require.Len(t, resp.Certificates, 1, "%s must see only its own certificate", tenant)
		assert.Equal(t, want, resp.Certificates[0].KeyID)
		assert.NotEmpty(t, resp.Certificates[0].CertificatePEM)
	}

	platform, err := svc.ListCertificates(context.Background(), "software")
	require.NoError(t, err)
	ids := make([]string, 0, len(platform.Certificates))
	for _, c := range platform.Certificates {
		ids = append(ids, c.KeyID)
	}
	assert.ElementsMatch(t, []string{"acme/web", "globex/api", "sys"}, ids,
		"a platform-scoped caller sees the whole store")
}

func TestCertificateMethods_InvalidCertificateIsARequestFault(t *testing.T) {
	svc := setupDeriveService(t)
	bad := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not DER")}))
	err := svc.SaveCertificate(identityCtx("acme"), &transport.SaveCertificateRequest{
		Backend: "software", KeyID: "web", CertificatePEM: bad, TenantID: "acme",
	})
	require.ErrorIs(t, err, ErrInvalidCertificate)
	var parseErr *ErrCertificateParse
	require.ErrorAs(t, err, &parseErr)

	err = svc.SaveCertificateChain(identityCtx("acme"), &transport.SaveCertificateChainRequest{
		Backend: "software", KeyID: "web", ChainPEM: []string{tenantCertPEM(t), bad}, TenantID: "acme",
	})
	require.ErrorIs(t, err, ErrInvalidCertificate)
	var indexErr *ErrCertParseIndex
	require.ErrorAs(t, err, &indexErr)
	assert.Equal(t, 1, indexErr.Index)
}

// sealAs seals data as tenantID through the service, under keyID or the
// default sealing key when keyID is empty.
func sealAs(t *testing.T, svc *XKMSService, tenantID, keyID string, data []byte) *transport.SealResponse {
	t.Helper()
	resp, err := svc.Seal(identityCtx(tenantID), &transport.SealRequest{
		Backend: "software", KeyID: keyID, Data: data, TenantID: tenantID,
	})
	require.NoError(t, err)
	return resp
}

// unsealAs unseals blob as tenantID through the service.
func unsealAs(svc *XKMSService, tenantID, keyID string, blob *transport.SealResponse) ([]byte, error) {
	resp, err := svc.Unseal(identityCtx(tenantID), &transport.UnsealRequest{
		Backend: "software", KeyID: keyID, TenantID: tenantID,
		Ciphertext: blob.Ciphertext, Nonce: blob.Nonce, Tag: blob.Tag,
	})
	if err != nil {
		return nil, err
	}
	return resp.Plaintext, nil
}

// storeTenantECDSAKey generates an ECDSA encryption key cn in tenantID.
func storeTenantECDSAKey(t *testing.T, svc *XKMSService, tenantID, cn string) {
	t.Helper()
	b, err := svc.resolveTenantBackend("software", tenantID)
	require.NoError(t, err)
	_, err = b.GenerateECDSA(context.Background(), &types.KeyAttributes{
		CN:            cn,
		KeyType:       types.KeyTypeEncryption,
		StoreType:     types.StoreSoftware,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	})
	require.NoError(t, err)
}

func TestSeal_DefaultSealingKeyIsPerTenant(t *testing.T) {
	svc := setupDeriveService(t)
	secret := []byte("acme's secret")
	blob := sealAs(t, svc, "acme", "", secret)

	defaultCN := defaultSealingKeyAttributes(types.BackendTypeSoftware).CN
	assert.True(t, tenantSeesKey(t, svc, "acme", defaultCN), "acme's default sealing key lives in acme")
	assert.False(t, tenantSeesKey(t, svc, "globex", defaultCN), "globex has no default sealing key yet")

	opened, err := unsealAs(svc, "acme", "", blob)
	require.NoError(t, err)
	assert.Equal(t, secret, opened)

	_, err = unsealAs(svc, "globex", "", blob)
	require.Error(t, err, "another tenant must not unseal acme's default-key blob")
	_, err = unsealAs(svc, "", "", blob)
	require.Error(t, err, "the platform's default sealing key is not acme's")

	// Once globex has a default key of its own, acme's blob still does not
	// open under it.
	sealAs(t, svc, "globex", "", []byte("globex's secret"))
	require.True(t, tenantSeesKey(t, svc, "globex", defaultCN))
	_, err = unsealAs(svc, "globex", "", blob)
	require.Error(t, err)
}

func TestSeal_NamedKeyResolvesWithinTheCallersTenant(t *testing.T) {
	svc := setupDeriveService(t)
	storeTenantECDSAKey(t, svc, "acme", "vault-key")
	blob := sealAs(t, svc, "acme", "vault-key", []byte("acme's secret"))

	_, sealErr := svc.Seal(identityCtx("globex"), &transport.SealRequest{
		Backend: "software", KeyID: "vault-key", Data: []byte("x"), TenantID: "globex",
	})
	assert.ErrorIs(t, sealErr, ErrKeyNotFound, "globex must not seal under acme's key")

	_, unsealErr := unsealAs(svc, "globex", "vault-key", blob)
	assert.ErrorIs(t, unsealErr, ErrKeyNotFound, "globex must not unseal with acme's key")
	_, missErr := unsealAs(svc, "globex", "no-such-key", blob)
	require.Error(t, missErr)
	assert.Equal(t, errors.Is(missErr, ErrKeyNotFound), errors.Is(unsealErr, ErrKeyNotFound))
	assert.Equal(t, missErr.Error(), unsealErr.Error(),
		"a cross-tenant refusal must read exactly like a genuine miss")

	_, err := unsealAs(svc, "globex", "acme/vault-key", blob)
	var parseErr *ErrKeyIDParse
	assert.ErrorAs(t, err, &parseErr, "a tenant namespace in a key ID is refused")

	opened, err := unsealAs(svc, "acme", "vault-key", blob)
	require.NoError(t, err)
	assert.Equal(t, []byte("acme's secret"), opened)
}

func TestSeal_TenantCallerRefusedOnUnboundTPM2Sealing(t *testing.T) {
	sealer := setupSealableServiceWithBackendType(t, "tpm2", types.BackendTypeTPM2)
	sealableStore(t, "tpm2").storeType = types.StoreTPM2
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Seal(identityCtx("acme"), &transport.SealRequest{
		Backend: "tpm2", Data: []byte("secret"), TenantID: "acme",
	})
	require.ErrorIs(t, err, ErrSealNotTenantBound)
	require.ErrorIs(t, err, ErrSealingNotSupported)
	assert.Nil(t, sealer.lastSealOpts, "the TPM must not be reached for a tenant caller")

	_, err = svc.Unseal(identityCtx("acme"), &transport.UnsealRequest{
		Backend: "tpm2", KeyID: "vault", TPMPublic: []byte("pub"), TPMPrivate: []byte("priv"), TenantID: "acme",
	})
	require.ErrorIs(t, err, ErrSealNotTenantBound)
	assert.Nil(t, sealer.lastUnsealOpts)

	// The platform still seals on TPM 2.0.
	_, err = svc.Seal(context.Background(), &transport.SealRequest{Backend: "tpm2", Data: []byte("secret")})
	require.NoError(t, err)
}
