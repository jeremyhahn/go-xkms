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

package xkms_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	gotpm "github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// setupServiceWithRealCA builds a service over a software backend and wires
// an initialized *ca.CA into it, so a test drives the service method and the
// CA's ownership recording together.
func setupServiceWithRealCA(t *testing.T) (*xkms.XKMSService, *ca.CA) {
	t.Helper()

	swBackend, err := software.NewBackend(&software.Config{KeyStorage: storage.NewMemory()})
	require.NoError(t, err)
	backend, err := xkms.New(&xkms.BackendConfig{
		Backend:     swBackend,
		CertStorage: storage.NewMemory(),
	})
	require.NoError(t, err)
	cs, err := certstore.New(&certstore.Config{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)

	config := ca.DefaultMultiIdentityCAConfig()
	config.Identity[0].Subject.CommonName = "Test Root CA"
	config.Identity[0].Subject.Organization = "Test Organization"
	config.Identity[0].Keys[0].KeyType = "CA"

	caIface, err := ca.NewFromMultiIdentityConfig(&ca.MultiIdentityParams{
		Config:   config,
		KeyStore: backend,
		BackendForStore: func(string, types.StoreType) (xkms.Backend, error) {
			return backend, nil
		},
		RevocationStore: storage.NewMemory(),
		CertStore:       cs,
	})
	require.NoError(t, err)
	require.NoError(t, caIface.Init(context.Background()))
	concreteCA, ok := caIface.(*ca.CA)
	require.True(t, ok, "expected *ca.CA, got %T", caIface)

	svc, err := xkms.NewService(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": backend},
		DefaultBackend: "software",
	})
	require.NoError(t, err)
	svc.SetCA(concreteCA)
	return svc, concreteCA
}

// lakPublicArea marshals a TPMT_PUBLIC for a restricted ECDSA P-256 signing
// key, the shape of a Local Attestation Key.
func lakPublicArea(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	uncompressed, err := pub.Bytes()
	require.NoError(t, err)
	coordLen := (len(uncompressed) - 1) / 2
	return gotpm.Marshal(gotpm.TPMTPublic{
		Type:    gotpm.TPMAlgECC,
		NameAlg: gotpm.TPMAlgSHA256,
		ObjectAttributes: gotpm.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
			Restricted:          true,
		},
		Parameters: gotpm.NewTPMUPublicParms(gotpm.TPMAlgECC, &gotpm.TPMSECCParms{
			CurveID: gotpm.TPMECCNistP256,
			Scheme: gotpm.TPMTECCScheme{
				Scheme: gotpm.TPMAlgECDSA,
				Details: gotpm.NewTPMUAsymScheme(gotpm.TPMAlgECDSA,
					&gotpm.TPMSSigSchemeECDSA{HashAlg: gotpm.TPMAlgSHA256}),
			},
		}),
		Unique: gotpm.NewTPMUPublicID(gotpm.TPMAlgECC, &gotpm.TPMSECCPoint{
			X: gotpm.TPM2BECCParameter{Buffer: uncompressed[1 : 1+coordLen]},
			Y: gotpm.TPM2BECCParameter{Buffer: uncompressed[1+coordLen:]},
		}),
	})
}

// lakCertifyEvidence builds the TPM2_Certify evidence an IAK produces over
// the LAK public area: the marshalled TPMS_ATTEST and the IAK's signature.
func lakCertifyEvidence(t *testing.T, iakKey *ecdsa.PrivateKey, lakPubArea, nonce []byte) (certifyInfo, signature []byte) {
	t.Helper()
	subject, err := gotpm.Unmarshal[gotpm.TPMTPublic](lakPubArea)
	require.NoError(t, err)
	name, err := gotpm.ObjectName(subject)
	require.NoError(t, err)
	certifyInfo = gotpm.Marshal(gotpm.TPMSAttest{
		Magic:     gotpm.TPMGeneratedValue,
		Type:      gotpm.TPMSTAttestCertify,
		ExtraData: gotpm.TPM2BData{Buffer: nonce},
		Attested: gotpm.NewTPMUAttest(gotpm.TPMSTAttestCertify, &gotpm.TPMSCertifyInfo{
			Name:          *name,
			QualifiedName: *name,
		}),
	})
	digest := sha256.Sum256(certifyInfo)
	signature, err = ecdsa.SignASN1(rand.Reader, iakKey, digest[:])
	require.NoError(t, err)
	return certifyInfo, signature
}

// TestIssueLAKCertificate_RecordsCallerTenant issues a LAK certificate through
// the service as a named tenant and requires the CA to record that tenant as
// its owner, so the same tenant's revocation request is accepted (#1764).
func TestIssueLAKCertificate_RecordsCallerTenant(t *testing.T) {
	const tenant = "tenant-a"
	svc, concreteCA := setupServiceWithRealCA(t)
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject:  "user@" + tenant,
		TenantID: tenant,
		Roles:    []string{"admin"},
	})

	iakKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	iakCert, err := concreteCA.IssueAKCertificate(ctx, &ca.CertificateRequest{
		TenantID: tenant,
		Subject:  ca.Subject{CommonName: "iak-lak-tenant-fixture"},
	}, iakKey.Public())
	require.NoError(t, err)

	lakKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	lakPubArea := lakPublicArea(t, &lakKey.PublicKey)
	nonce := []byte("nonce-TestIssueLAKCertificate_RecordsCallerTenant")
	certifyInfo, sig := lakCertifyEvidence(t, iakKey, lakPubArea, nonce)

	resp, err := svc.IssueLAKCertificate(ctx, &transport.IssueLAKCertificateRequest{
		TPMManufacturer:    "id:49465800",
		TPMModel:           "NPCT6xx",
		TPMFirmwareVersion: "7.2.3.1",
		IAKCertificateDER:  iakCert.Raw,
		CertifyInfo:        certifyInfo,
		Signature:          sig,
		SignatureAlgorithm: int(x509.ECDSAWithSHA256),
		LAKPublicArea:      lakPubArea,
		Nonce:              nonce,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	lakCert, err := x509.ParseCertificate(resp.CertificateDER)
	require.NoError(t, err)

	owner, err := concreteCA.CertificateTenant(ctx, lakCert.SerialNumber)
	require.NoError(t, err)
	assert.Equal(t, tenant, owner, "the LAK certificate must be recorded under the caller's tenant")

	revoked, err := svc.RevokeCertificate(ctx, &transport.RevokeCertificateRequest{
		SerialNumber: resp.SerialNumber,
		Reason:       1,
	})
	require.NoError(t, err, "the issuing tenant must be able to revoke its own LAK certificate")
	require.NotNil(t, revoked)
	assert.True(t, revoked.Success)
}
