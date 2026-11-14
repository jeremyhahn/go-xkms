//go:build integration && tpm_simulator

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

// Package clusterca_test drives a real cluster join end to end: a first node
// provisions its identity from an in-process cluster CA and advertises the
// trust anchor over Noise NK, and a joiner fetches that anchor, enrolls its
// simulated TPM over ACME enroll-01 against the CA's ACME server, and checks
// the issued IDevID names it as a cluster member.
//
// The joiner answers enroll-01 on 127.0.0.1:8080, the fixed port the ACME
// server dials, so the tests run sequentially and need that port free. The
// TPM is the in-process simulator, a process-wide singleton, which is a
// second reason nothing here runs in parallel.
package clusterca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/mux"
	clusterenroll "github.com/jeremyhahn/go-qrdb/sdk/go/clusterenroll"
	qrdbstorage "github.com/jeremyhahn/go-qrdb/sdk/go/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	acmeserver "github.com/jeremyhahn/go-xkms/pkg/acme/server"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"
	acmeobjstore "github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	xkmsstorage "github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmblobtest"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/trust/clusterca"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	acmesdk "github.com/jeremyhahn/go-xkms/sdk/go/acme"
	"github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

const (
	trustDomain = "join.cluster.test"

	// challengePort is the port the ACME server dials for enroll-01.
	challengePort = "8080"

	// iakCertHandle is the NV index the joiner's IAK certificate is
	// installed at once enroll-01 issues it.
	iakCertHandle = 0x01C90010
)

// cluster is a running first node: the membership it serves, the directory
// of the ACME server in front of its CA, the Noise NK advertiser joiners
// fetch the trust anchor from, and the EK root that CA trusts.
type cluster struct {
	members      map[uint64]string
	directoryURL string
	advertiser   *clusterenroll.Advertiser
	ekRoot       *testIssuer
}

// testIssuer is a self-signed CA key and certificate.
type testIssuer struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

// TestClusterJoin_MemberIsStampedWithNodeURI is the join the cluster CA
// exists for: a configured member that proves its TPM over enroll-01 comes
// back with spiffe://<td>/node/<raftAddr>, and its provisioner accepts the
// leaf as its cluster identity.
func TestClusterJoin_MemberIsStampedWithNodeURI(t *testing.T) {
	c := startCluster(t)

	joinerAddr := c.members[2]
	res, err := provisionJoiner(t, c, 2, joinerAddr)
	require.NoError(t, err, "a configured member that passes enroll-01 must join")
	require.NotNil(t, res.MTLS)
	require.NotEmpty(t, res.MTLS.Certificate.Certificate, "the joiner must hold a transport certificate")

	leaf, err := x509.ParseCertificate(res.MTLS.Certificate.Certificate[0])
	require.NoError(t, err)
	require.Len(t, leaf.URIs, 1)
	assert.Equal(t, fmt.Sprintf("spiffe://%s/node/%s", trustDomain, joinerAddr), leaf.URIs[0].String(),
		"the node URI must carry the whole Raft address the joiner presented")
	assert.Nil(t, res.Advertiser, "only the first node advertises the anchor")
}

// TestClusterJoin_NonMemberIsRefused verifies a TPM that passes enroll-01 is
// still not a cluster member unless the serving node's membership lists its
// Raft address: the CA issues the IDevID without a node URI, and the joiner
// refuses it rather than running with an identity peers would not accept.
func TestClusterJoin_NonMemberIsRefused(t *testing.T) {
	c := startCluster(t)

	res, err := provisionJoiner(t, c, 3, fmt.Sprintf("127.0.0.1:%d", freePort(t)))
	require.Error(t, err, "an address outside the membership must not yield a cluster identity")
	assert.Nil(t, res)

	var mismatch *clusterca.ErrSPIFFEMismatch
	require.ErrorAs(t, err, &mismatch)
	assert.Empty(t, mismatch.Got, "the CA must not stamp any node URI for a non-member")
}

// startCluster provisions a first node over an in-process cluster CA and
// serves that CA's ACME endpoint, with the cluster node URI hook registered
// exactly as a composition root registers it.
func startCluster(t *testing.T) *cluster {
	t.Helper()

	members := map[uint64]string{
		1: fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		2: fmt.Sprintf("127.0.0.1:%d", freePort(t)),
	}
	ekRoot := newTestIssuer(t, "Cluster Join Test EK Root")
	tcgCA := newTestCA(t, ekRoot)
	issuer, ok := tcgCA.(clusterca.CAIssuer)
	require.True(t, ok, "the TCG CA must be able to issue cluster transport certificates")
	directoryURL := serveACME(t, tcgCA, members)

	p, err := clusterca.New(&clusterca.Options{
		RaftAddress:     members[1],
		NodeID:          1,
		TrustDomain:     trustDomain,
		Members:         members,
		DataDir:         nodeDataDir(t),
		ACME:            &clusterca.ACMEOptions{},
		Backends:        nodeBackends(t, nil),
		NodeKeyBackends: nodeKeyBackends(t, nil),
		Advertise: clusterenroll.AdvertiseOptions{
			NoiseHost: "127.0.0.1",
			NoisePort: freePort(t),
		},
		CA: issuer,
	}, testLogger())
	require.NoError(t, err)

	res, err := p.Provision(t.Context())
	require.NoError(t, err, "the first node must provision from the in-process CA")
	require.NotNil(t, res.Advertiser, "a multi-node first node must advertise the anchor")
	t.Cleanup(res.Advertiser.Stop)

	return &cluster{members: members, directoryURL: directoryURL, advertiser: res.Advertiser, ekRoot: ekRoot}
}

// provisionJoiner runs a joining node's Provision against c with a freshly
// provisioned simulator TPM, through the same node-local backends a
// composition root builds.
func provisionJoiner(t *testing.T, c *cluster, nodeID uint64, raftAddr string) (*clusterca.Result, error) {
	t.Helper()

	joinerTPM := newJoinerTPM(t, c.ekRoot)
	p, err := clusterca.New(&clusterca.Options{
		RaftAddress: raftAddr,
		NodeID:      nodeID,
		TrustDomain: trustDomain,
		Members:     c.members,
		DataDir:     nodeDataDir(t),
		ACME: &clusterca.ACMEOptions{
			DirectoryURL:  c.directoryURL,
			ChallengePort: challengePort,
			ChallengeHost: "127.0.0.1",
		},
		KeyBackend:      "tpm2",
		Backends:        nodeBackends(t, joinerTPM),
		NodeKeyBackends: nodeKeyBackends(t, joinerTPM),
		Bootstrap: clusterenroll.BootstrapOptions{
			NoiseKey:  hex.EncodeToString(c.advertiser.NoisePublicKey()),
			NoiseAddr: c.advertiser.Addr(),
		},
	}, testLogger())
	require.NoError(t, err)

	return p.Provision(t.Context())
}

// serveACME starts the cluster CA's ACME server over TLS and returns its
// directory URL. Its certificate is issued by the cluster CA, so a joiner
// reaches it trusting nothing but the advertised anchor.
func serveACME(t *testing.T, tcgCA ca.TCGCA, members map[uint64]string) string {
	t.Helper()

	srv := httptest.NewUnstartedServer(nil)
	baseURL := "https://" + srv.Listener.Addr().String()

	kv, err := kvadapter.New(xkmsstorage.NewMemory())
	require.NoError(t, err)
	storageFactory, err := acmeobjstore.NewFactoryFromKVStore(kv)
	require.NoError(t, err)

	hooks := handlers.NewOrderPreSignHookRegistry()
	hooks.Register(acmesdk.NewACMEClusterNodeURISANHook(trustDomain, members))

	challengeClient := acmesdk.NewACMEChallengeClient(acmesdk.ACMEChallengeClientConfig{
		AllowPrivateTargets: true,
	})

	svc, err := handlers.NewRestService(&handlers.Params{
		// Every node in this test is on loopback: the server dials the
		// joiner's challenge listener at the address the request came from.
		AllowLoopbackIdentifier: true,
		AttestingVerifiers:      acmesdk.ACMEAttestingVerifiers(challengeClient, true, false, nil),
		BaseRESTURI:             baseURL,
		CA:                      tcgCA,
		ChallengeMap:            map[string]acmesdk.ACMEChallengeVerifierFunc{},
		Logger:                  testLogger(),
		OrderPreSignHooks:       hooks,
		StorageFactory:          storageFactory,
	})
	require.NoError(t, err)

	srv.Config.Handler = acmeRouter(svc)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCertificate(t, tcgCA)},
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return baseURL + "/acme/directory"
}

// acmeRouter mounts the ACME routes an enrolling client uses, the way the
// xkmsd composition root mounts them.
func acmeRouter(svc handlers.RestServicer) http.Handler {
	r := mux.NewRouter()
	r.Use(acmeserver.RequestBodyMiddleware)
	r.Use(svc.TenantAuthMiddleware)

	const prefix = "/acme"
	r.HandleFunc(prefix+"/directory", svc.DirectoryHandler).Methods(http.MethodGet, http.MethodHead)
	r.HandleFunc(prefix+"/new-nonce", svc.NewNonceHandler).Methods(http.MethodGet, http.MethodHead)
	r.HandleFunc(prefix+"/new-account", svc.NewAccountHandler).Methods(http.MethodPost)
	r.HandleFunc(prefix+"/account/{id:[0-9]+}", svc.AccountHandler).Methods(http.MethodPost)
	r.HandleFunc(prefix+"/new-order", svc.NewOrderHandler).Methods(http.MethodPost)
	r.HandleFunc(prefix+"/order/{id:[0-9]+}", svc.OrderHandler).Methods(http.MethodPost)
	r.HandleFunc(prefix+"/order/{id:[0-9]+}/finalize", svc.OrderFinalizeHandler).Methods(http.MethodPost)
	r.HandleFunc(prefix+"/authz/{id:[0-9]+}", svc.AuthorizationHandler).Methods(http.MethodPost)
	r.HandleFunc(prefix+"/challenge/{id:[0-9]+}", svc.ChallengeHandler).Methods(http.MethodPost)
	// The certificate ID is the issued certificate's hex serial.
	r.HandleFunc(prefix+"/cert/{id:[0-9a-fA-F]+}", svc.CertificateHandler).Methods(http.MethodPost)
	return r
}

// serverCertificate issues the ACME server's TLS certificate for 127.0.0.1
// from the cluster CA.
func serverCertificate(t *testing.T, tcgCA ca.TCGCA) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "acme.join.cluster.test"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}, key)
	require.NoError(t, err)

	cert, err := tcgCA.SignCSR(t.Context(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
		&ca.SignOptions{
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
	require.NoError(t, err)
	caCert, err := tcgCA.CACertificate()
	require.NoError(t, err)

	return tls.Certificate{Certificate: [][]byte{cert.Raw, caCert.Raw}, PrivateKey: key}
}

// newTestCA builds the cluster CA: an in-memory root and intermediate, the
// intermediate issuing, trusting ekRoot for endorsement key certificates.
func newTestCA(t *testing.T, ekRoot *testIssuer) ca.TCGCA {
	t.Helper()

	xkmssdk.ServiceReset()

	keyStorage, err := xkmssdk.NewMemoryBackend()
	require.NoError(t, err)
	certStorage, err := xkmssdk.NewMemoryBackend()
	require.NoError(t, err)
	// AllowPlaintextKeys is the documented fixture escape hatch for
	// throwaway in-memory CA keys with no per-key password.
	pkcs8Backend, err := xkmssdk.NewPKCS8Backend(&xkmssdk.PKCS8BackendConfig{
		KeyStorage:         keyStorage,
		AllowPlaintextKeys: true,
	})
	require.NoError(t, err)
	keyStore, err := xkmssdk.NewServiceBackend(&xkmssdk.ServiceBackendConfig{
		Backend:     pkcs8Backend,
		CertStorage: certStorage,
	})
	require.NoError(t, err)
	require.NoError(t, xkmssdk.ServiceInitialize(&xkmssdk.ServiceConfig{
		Backends:       map[string]xkmssdk.ServiceBackend{"software": keyStore},
		DefaultBackend: "software",
	}))
	t.Cleanup(func() { assert.NoError(t, xkmssdk.ServiceClose()) })

	certStore, err := xkmssdk.NewCertStore(&xkmssdk.CertStoreConfig{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)

	ecdsaKey := &types.KeyConfig{
		KeyAlgorithm:       types.AlgorithmECDSA,
		Hash:               types.HashSHA256,
		SignatureAlgorithm: types.SigECDSAWithSHA256,
		StoreType:          types.StoreSoftware,
		ECCConfig:          &types.ECCConfig{Curve: types.CurveP256},
		KeyType:            "CA",
	}
	_, intermediate, err := ca.NewCA(t.Context(), &ca.Params{
		Identity: []ca.Identity{
			{
				Subject:       ca.Subject{CommonName: "Cluster Join Test Root CA", Organization: "Test", Country: "US"},
				Valid:         ca.DefaultRootValidityYears,
				Keys:          []*types.KeyConfig{ecdsaKey},
				IsRoot:        true,
				MaxPathLength: 1,
			},
			{
				Subject:  ca.Subject{CommonName: "Cluster Join Test Intermediate CA", Organization: "Test", Country: "US"},
				Valid:    ca.DefaultIntermediateValidityYears,
				Keys:     []*types.KeyConfig{ecdsaKey},
				ParentCA: "Cluster Join Test Root CA",
			},
		},
		Config: &ca.CAConfig{
			DefaultCertValidityDays: ca.DefaultCertValidityDays,
			// enroll-01 refuses an EK certificate that does not chain to a
			// configured trust anchor.
			TCGConfig: &ca.TCGConfig{
				TrustAnchors: &truststore.Config{ExternalRootPaths: []string{writeCertPEM(t, ekRoot.cert)}},
			},
		},
		KeyStore:  keyStore,
		CertStore: certStore,
		BackendForStore: func(string, types.StoreType) (xkms.Backend, error) {
			return keyStore, nil
		},
		RevocationStore: xkmsstorage.NewMemory(),
		ObjectStore:     qrdbstorage.NewMemoryStorage(),
	})
	require.NoError(t, err)

	tcgCA, ok := intermediate.(ca.TCGCA)
	require.True(t, ok, "the intermediate CA must implement ca.TCGCA")
	return tcgCA
}

// newJoinerTPM opens the simulator TPM through the tpm2 key backend and gives
// it what a manufactured TPM carries: an IAK, and an EK certificate issued by
// ekRoot.
func newJoinerTPM(t *testing.T, ekRoot *testIssuer) *tpm2backend.Backend {
	t.Helper()

	// pkgtpm2.DefaultConfig shares its section pointers with every other
	// user, so the IAK section is copied before it is changed.
	cfg := pkgtpm2.DefaultConfig
	cfg.UseSimulator = true
	iak := *cfg.IAK
	iak.CN = "clusterca-joiner-iak"
	iak.CertHandle = iakCertHandle
	cfg.IAK = &iak

	backend, err := tpm2backend.NewBackend(&tpm2backend.Config{
		UseSimulator: true,
		Keys:         tpmblobtest.New(t),
		CN:           "clusterca-joiner",
		TPMConfig:    &cfg,
	})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, backend.Close()) })

	tpm := backend.TPM()
	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)
	// A freshly provisioned simulator's endorsement hierarchy has empty auth.
	ekAttrs.TPMAttributes.HierarchyAuth = nil
	_, err = tpm.CreateIAK(ekAttrs, nil)
	require.NoError(t, err)

	require.NoError(t, tpm.ProvisionEKCert(nil, ekCertificate(t, tpm, ekAttrs, ekRoot)))
	return backend
}

// ekCertificate issues an EK certificate for the simulator's endorsement key
// in the TCG EK Credential Profile shape enroll-01 verifies.
func ekCertificate(t *testing.T, tpm pkgtpm2.TrustedPlatformModule, ekAttrs *types.KeyAttributes, ekRoot *testIssuer) []byte {
	t.Helper()

	ekPublic, err := x509.ParsePKIXPublicKey(ekAttrs.TPMAttributes.PublicKeyBytes)
	require.NoError(t, err)
	props, err := tpm.FixedProperties()
	require.NoError(t, err)

	subject := pkix.Name{CommonName: "clusterca-joiner-ek"}
	san, err := ca.BuildSubjectAltName(subject, nil, nil, nil, nil, nil, []pkix.Name{{
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: ca.OIDTCGAttributeTPMManufacturer, Value: props.ManufacturerCode},
			{Type: ca.OIDTCGAttributeTPMModel, Value: props.Model},
			{Type: ca.OIDTCGAttributeTPMVersion, Value: fmt.Sprintf("id:%04X%04X", props.FwMajor, props.FwMinor)},
		},
	}})
	require.NoError(t, err)

	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{ca.OIDTCGKpEKCertificate},
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{san},
	}, ekRoot.cert, ekPublic, ekRoot.key)
	require.NoError(t, err)
	return der
}

// newTestIssuer creates a self-signed ECDSA P-256 CA.
func newTestIssuer(t *testing.T, cn string) *testIssuer {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &testIssuer{key: key, cert: cert}
}

// nodeBackends builds a node's key-backend resolver the way a composition
// root does. hardware, when non-nil, is the TPM the "tpm2" backend reuses.
func nodeBackends(t *testing.T, hardware types.Sealer) func(string) (xkms.Backend, error) {
	t.Helper()

	passphrase, err := secure.NewSecret(t.Context(), []byte("cluster-join-test"))
	require.NoError(t, err)
	resolve, err := clusterca.NewNodeLocalBackends(t.Context(), &clusterca.NodeLocalBackendsParams{
		DataDir:     nodeDataDir(t),
		Protection:  clusterca.KeyProtection{Mode: clusterca.KeyProtectPassphrase, Passphrase: passphrase},
		HardwareTPM: hardware,
		Logger:      testLogger(),
	})
	require.NoError(t, err)
	return resolve
}

// nodeKeyBackends builds a node's transport-key resolver the way a
// composition root does. hardware, when non-nil, is the TPM "tpm2" resolves to.
func nodeKeyBackends(t *testing.T, hardware types.Sealer) func(string) (xkms.Backend, error) {
	t.Helper()

	resolve, err := clusterca.NewNodeKeyBackends(&clusterca.NodeKeyBackendsParams{
		DataDir:     nodeDataDir(t),
		HardwareTPM: hardware,
	})
	require.NoError(t, err)
	return resolve
}

// nodeDataDir returns a node-local data directory removed once the node's
// asynchronous storage writes have drained. Closing file storage does not
// wait for writes already issued, so a bare t.TempDir can fail its own
// cleanup with "directory not empty".
func nodeDataDir(t *testing.T) string {
	t.Helper()

	dir := filepath.Join(t.TempDir(), "cluster-ca")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	t.Cleanup(func() { removeWhenQuiescent(t, dir) })
	return dir
}

// removeWhenQuiescent deletes dir and confirms it stays deleted, retrying
// until late writes stop recreating it.
func removeWhenQuiescent(t *testing.T, dir string) {
	t.Helper()

	const (
		settle  = 10 * time.Millisecond
		timeout = 15 * time.Second
	)
	deadline := time.Now().Add(timeout)
	for {
		removeErr := os.RemoveAll(dir)
		if removeErr == nil {
			time.Sleep(settle)
			if _, statErr := os.Stat(dir); errors.Is(statErr, fs.ErrNotExist) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("node data dir %s never quiesced after %s (last remove error: %v)", dir, timeout, removeErr)
		}
		time.Sleep(settle)
	}
}

// writeCertPEM writes cert to a PEM file and returns its path.
func writeCertPEM(t *testing.T, cert *x509.Certificate) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "ek-root.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600))
	return path
}

func randomSerial(t *testing.T) *big.Int {
	t.Helper()

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	return serial
}

// freePort returns a loopback TCP port that was free when asked.
func freePort(t *testing.T) int {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
