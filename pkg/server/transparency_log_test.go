package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// TestHeadSignerProviderOptions_WiresCAProvider proves the embedded node is
// given the CA-backed head-signer provider, so verifiable-log checkpoints are
// signed with the CA key rather than go-qrdb's software key.
func TestHeadSignerProviderOptions_WiresCAProvider(t *testing.T) {
	s := &Server{}
	opts := s.headSignerProviderOptions()
	require.Len(t, opts, 1)
	require.NotNil(t, s.headSignerProvider, "the provider is kept for binding once the CA is built")
}

// twoIdentityCA is a TrustedCA with a selected CA and a separate cluster
// CA identity reachable only through IssuerForIdentity.
type twoIdentityCA struct {
	selectedKey  *ecdsa.PrivateKey
	selectedCert *x509.Certificate
	clusterCN    string
	clusterKey   *ecdsa.PrivateKey
	clusterCert  *x509.Certificate
}

func (c *twoIdentityCA) Signer(context.Context) (crypto.Signer, error) { return c.selectedKey, nil }

func (c *twoIdentityCA) CACertificate() (*x509.Certificate, error) { return c.selectedCert, nil }

func (c *twoIdentityCA) IssuerForIdentity(_ context.Context, cn string) (crypto.Signer, *x509.Certificate, error) {
	if cn != c.clusterCN {
		return nil, nil, errors.New("unknown identity " + cn)
	}
	return c.clusterKey, c.clusterCert, nil
}

func selfSignedCA(t *testing.T, cn string) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return key, cert
}

func TestBindCAProviders_HeadSignerUsesClusterCAIdentity(t *testing.T) {
	ctx := context.Background()
	trusted := &twoIdentityCA{clusterCN: "cluster-ca"}
	trusted.selectedKey, trusted.selectedCert = selfSignedCA(t, "selected-ca")
	trusted.clusterKey, trusted.clusterCert = selfSignedCA(t, "cluster-ca")

	cfg := &config.Config{CA: ca.DefaultMultiIdentityCAConfigWithIntermediate()}
	cfg.Cluster.RaftEnrollment.ClusterCACN = "cluster-ca"
	s := &Server{config: cfg}
	require.Len(t, s.clusterCAKeyProviderOptions(), 1)
	require.Len(t, s.headSignerProviderOptions(), 1)

	require.NoError(t, s.bindCAProviders(trusted))

	clusterSigner, err := s.clusterCAKeyProvider.Signer(ctx)
	require.NoError(t, err)

	created, err := s.headSignerProvider.CreateKey(ctx, qrdbsdk.HeadSignerCreateKeyRequest{
		TenantID: "t1", Database: "system", Log: "issuance",
		Type: qrdbsdk.HeadSignatureECDSAP256SHA256, Version: 1,
	})
	require.NoError(t, err)
	hs, err := s.headSignerProvider.HeadSigner(ctx, qrdbsdk.HeadSignerRequest{
		TenantID: "t1", Database: "system", Log: "issuance", KeyRef: created.Ref, KeyVersion: 1,
	})
	require.NoError(t, err)

	require.True(t, trusted.clusterKey.PublicKey.Equal(clusterSigner.Public()))
	require.True(t, trusted.clusterKey.PublicKey.Equal(hs.Public()),
		"checkpoints must be signed with the cluster CA identity, not the selected CA")
}
