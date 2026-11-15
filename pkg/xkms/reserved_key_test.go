package xkms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// The tenant login CA key signs the certificates go-qrdb trusts for a
// tenant's logins. keys:sign is granted to User and Operator, so any
// user-addressable operation that reaches this key by its CN would let
// them mint login certificates, swap the CA certificate, or rotate or
// delete the key. Every such operation is refused for every role.
func TestLoginCAKey_RefusedToUserAddressableOperations(t *testing.T) {
	const tenant = "acme"
	const loginCA = "qrdb-login-ca"
	svc := setupDeriveService(t)

	b, err := svc.resolveTenantBackend("software", tenant)
	require.NoError(t, err)
	_, err = b.GenerateECDSA(context.Background(), &types.KeyAttributes{
		CN:            loginCA,
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreSoftware,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
		TenantID:      tenant,
	})
	require.NoError(t, err)

	certPEM := selfSignedPEM(t)

	for _, role := range []string{"user", "operator"} {
		t.Run(role, func(t *testing.T) {
			ctx := identityCtx(tenant, role)

			_, err := svc.Sign(ctx, &transport.SignRequest{Backend: "software", KeyID: loginCA, Data: []byte("tbs"), TenantID: tenant})
			assert.ErrorContains(t, err, "reserved for internal use", "sign")

			err = svc.SaveCertificate(ctx, &transport.SaveCertificateRequest{Backend: "software", KeyID: loginCA, CertificatePEM: certPEM, TenantID: tenant})
			assert.ErrorContains(t, err, "reserved for internal use", "certificate replacement")

			_, err = svc.RotateKey(ctx, &transport.RotateKeyRequest{Backend: "software", KeyID: loginCA, TenantID: tenant})
			assert.ErrorContains(t, err, "reserved for internal use", "rotate")

			err = svc.DeleteKey(ctx, "software", loginCA)
			assert.ErrorContains(t, err, "reserved for internal use", "delete")

			_, err = svc.GenerateKey(identityCtx("globex", role), &transport.GenerateKeyRequest{
				Backend: "software", KeyID: loginCA, KeyType: "signing", Algorithm: "ecdsa", TenantID: "globex",
			})
			assert.ErrorContains(t, err, "reserved for internal use", "a caller may not create the name ahead of provisioning")
		})
	}

	// The key is still there, one version, for the provisioning path.
	keys, err := b.ListKeys(context.Background())
	require.NoError(t, err)
	n := 0
	for _, k := range keys {
		if k.CN == loginCA {
			n++
		}
	}
	assert.Equal(t, 1, n)
}

func selfSignedPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "forged login CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
