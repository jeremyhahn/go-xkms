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

	"github.com/jeremyhahn/go-qrdb/pkg/vlog"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-qrdb/sdk/go/transport/vlogwire"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/ca/tlog"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
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

// TestEmbeddedNode_LogCheckpointSignedWithCAKey starts the embedded node
// through initEmbeddedQRDBNode, binds a TrustedCA, and signs a verifiable-log
// checkpoint through the node: the checkpoint verifies under the cluster CA key
// and not under the selected CA key, so the node applied the head-signer option.
func TestEmbeddedNode_LogCheckpointSignedWithCAKey(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()
	ctx := context.Background()

	cfg := qrdbBarrierConfig(t)
	cfg.Barrier = config.BarrierConfig{Enabled: true, Strategy: "none"}
	// The cluster CA identity carries the server's own root CN: first-boot
	// issuance appends to the issuance log, whose head signer must resolve
	// it in the server's CA before the test rebinds a two-identity CA.
	clusterCN := cfg.CA.Identity[0].Subject.CommonName
	cfg.Cluster.RaftEnrollment.ClusterCACN = clusterCN
	s, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = s.Shutdown() }()

	trusted := &twoIdentityCA{clusterCN: clusterCN}
	trusted.selectedKey, trusted.selectedCert = selfSignedCA(t, "selected-ca")
	trusted.clusterKey, trusted.clusterCert = selfSignedCA(t, clusterCN)
	require.NoError(t, s.bindCAProviders(trusted))

	// The node's log service authorizes every call: act as the first-boot
	// owner of the system tenant.
	svcs := s.qrdbNode.Services()
	require.NotNil(t, svcs)
	if svcs.Log == nil {
		if vlogBuiltIn {
			t.Fatalf("built with qrdb_vlog, but the embedded node exposes no verifiable-log service (Services().Log is nil)")
		}
		t.Skip("the node's verifiable-log service is compiled in only with the qrdb_vlog build tag")
	}
	owner, err := svcs.Role.GetRoleByName(qrdbsdk.ContextWithTenant(ctx, qrdbsdk.SystemTenantID),
		qrdbsdk.SystemTenantID, "owner")
	require.NoError(t, err)
	caller := &qrdbsdk.Identity{Subject: "owner", TenantID: qrdbsdk.SystemTenantID, Roles: []string{owner.ID}}
	ctx = qrdbsdk.ContextWithTenant(qrdbsdk.WithIdentity(ctx, caller), qrdbsdk.SystemTenantID)

	// A log of the test's own: the server's first-boot issuance already
	// created the issuance log under the server's CA key.
	const origin = "xkms.test/checkpoint"
	vl := s.qrdbClient.Vlog()
	_, err = vl.VlogCreate(ctx, &vlogwire.CreateRequest{
		Log: "checkpoint", Origin: origin,
		SigningKeyType: qrdbsdk.HeadSignatureECDSAP256SHA256,
	})
	require.NoError(t, err)
	_, err = vl.VlogAppend(ctx, &vlogwire.AppendRequest{Log: "checkpoint", Entries: [][]byte{[]byte("cert-1")}})
	require.NoError(t, err)
	signed, err := vl.VlogSignHead(ctx, &vlogwire.LogRequest{Log: "checkpoint"})
	require.NoError(t, err)
	require.Equal(t, uint64(1), signed.Head.Size)

	require.NoError(t, vlog.VerifyHead(&trusted.clusterKey.PublicKey, origin, signed.Head),
		"the checkpoint must verify under the cluster CA key")
	require.Error(t, vlog.VerifyHead(&trusted.selectedKey.PublicKey, origin, signed.Head),
		"the checkpoint must not verify under the selected CA key")
}

// TestEmbeddedNode_TransparencyLogAppendsToNodeLog proves the appender the
// server hands the CA (compose.CAParams.TransparencyLog) writes to the
// node's own issuance log: created on first use, signed by the cluster CA
// key, and authorized without a caller identity of its own.
func TestEmbeddedNode_TransparencyLogAppendsToNodeLog(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()
	ctx := context.Background()

	cfg := qrdbBarrierConfig(t)
	cfg.Barrier = config.BarrierConfig{Enabled: true, Strategy: "none"}
	s, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = s.Shutdown() }()

	appender := s.transparencyLog()
	if s.qrdbNode.Services().Log == nil {
		if vlogBuiltIn {
			t.Fatalf("built with qrdb_vlog, but the embedded node exposes no verifiable-log service")
		}
		require.Nil(t, appender, "without a log service the CA gets no appender")
		t.Skip("the node's verifiable-log service is compiled in only with the qrdb_vlog build tag")
	}
	require.NotNil(t, appender, "a server with a qrdb client hands the CA an appender")

	owner := &qrdbsdk.Identity{Subject: "owner", TenantID: qrdbsdk.SystemTenantID,
		Roles: []string{qrdbsdk.SystemRoleID(qrdbsdk.SystemTenantID, "owner")}}
	octx := qrdbsdk.ContextWithTenant(qrdbsdk.WithIdentity(ctx, owner), qrdbsdk.SystemTenantID)
	vl := s.qrdbClient.Vlog()

	// The server's first-boot issuance already created the log and
	// appended its certificates.
	before, err := vl.VlogHead(octx, &vlogwire.LogRequest{Log: tlog.LogIssuance})
	require.NoError(t, err)
	require.NotZero(t, before.Size, "first-boot issuance appends cert-issued entries")

	require.NoError(t, tlog.AppendEntry(ctx, appender, tlog.CertIssued{SHA256: "00", Serial: "1"}))
	require.NoError(t, tlog.AppendEntry(ctx, appender, tlog.CertIssued{SHA256: "01", Serial: "2"}))

	signed, err := vl.VlogSignHead(octx, &vlogwire.LogRequest{Log: tlog.LogIssuance})
	require.NoError(t, err)
	require.Equal(t, before.Size+2, signed.Head.Size)
	hs, err := s.headSignerProvider.HeadSigner(ctx, qrdbsdk.HeadSignerRequest{KeyRef: tlog.KeyRef})
	require.NoError(t, err)
	require.NoError(t, vlog.VerifyHead(hs.Public(), qrdbsdk.SystemTenantID+"/"+tlog.LogIssuance, signed.Head),
		"the issuance checkpoint verifies under the server's CA key")
}
