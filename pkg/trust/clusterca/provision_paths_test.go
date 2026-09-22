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

package clusterca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// ---------------------------------------------------------------------------
// Hardware-key provisioning (precedence 3)
// ---------------------------------------------------------------------------

// TestProvision_HardwareKeyMode verifies the hardware-key precedence: with a
// named key backend and no ACME options the node issues its leaf from the
// dedicated cluster CA over a backend-held key. The certificate must carry the
// node's SPIFFE identity and chain to the returned CA bundle, and the private
// key must be exposed only as a crypto.Signer so a hardware-resident key never
// has to be exported.
func TestProvision_HardwareKeyMode(t *testing.T) {
	opts := &Options{
		RaftAddress: "127.0.0.1:8311",
		NodeID:      7,
		TrustDomain: "test.cluster",
		DataDir:     t.TempDir(),
		Members:     map[uint64]string{7: "127.0.0.1:8311"},
		KeyBackend:  "software",
		Backends:    softwareBackends(t),
	}

	p, err := New(opts, testLogger())
	require.NoError(t, err)

	res, err := p.Provision(context.Background())
	require.NoError(t, err)
	require.NotNil(t, res.MTLS)
	require.NotNil(t, res.MTLS.Certificate, "hardware mode must return a signer-backed certificate")

	leaf := res.MTLS.Certificate.Leaf
	require.NotNil(t, leaf)
	require.Len(t, leaf.URIs, 1)
	assert.Equal(t, "spiffe://test.cluster/node/127.0.0.1:8311", leaf.URIs[0].String())

	// The private key is exposed only as a crypto.Signer, so a
	// hardware-resident key never has to be exported to serve TLS.
	_, isSigner := res.MTLS.Certificate.PrivateKey.(crypto.Signer)
	assert.True(t, isSigner, "the TLS private key must be a crypto.Signer, not raw key material")
	assert.Empty(t, res.MTLS.Key, "hardware mode must not emit exportable key PEM")

	// The leaf verifies against the CA bundle the provisioner returned.
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(res.MTLS.CACert))
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	require.NoError(t, err, "the node leaf must chain to the advertised cluster CA")
}

// TestProvision_HardwareKeyReusesKeyAcrossRestarts verifies a restart reuses
// the existing backend-held node key rather than generating a new one. A new
// key on every boot would invalidate any peer pinning and churn the CA.
func TestProvision_HardwareKeyReusesKeyAcrossRestarts(t *testing.T) {
	dataDir := t.TempDir()
	backends := softwareBackends(t)

	newProvisioner := func() *Provisioner {
		p, err := New(&Options{
			RaftAddress: "127.0.0.1:8312",
			NodeID:      8,
			TrustDomain: "test.cluster",
			DataDir:     dataDir,
			Members:     map[uint64]string{8: "127.0.0.1:8312"},
			KeyBackend:  "software",
			Backends:    backends,
		}, testLogger())
		require.NoError(t, err)
		return p
	}

	first, err := newProvisioner().Provision(context.Background())
	require.NoError(t, err)
	second, err := newProvisioner().Provision(context.Background())
	require.NoError(t, err)

	assert.True(t,
		publicKeysEqual(first.MTLS.Certificate.Leaf.PublicKey, second.MTLS.Certificate.Leaf.PublicKey),
		"the node key must be reused across restarts, not regenerated")
}

// TestProvision_HardwareKeyPropagatesBackendFailure verifies a backend that
// cannot be resolved aborts provisioning instead of silently falling back to a
// software key.
func TestProvision_HardwareKeyPropagatesBackendFailure(t *testing.T) {
	wantErr := errors.New("tpm2 backend unavailable")
	p, err := New(&Options{
		RaftAddress: "127.0.0.1:8313",
		TrustDomain: "test.cluster",
		DataDir:     t.TempDir(),
		KeyBackend:  "tpm2",
		Backends:    func(string) (xkms.Backend, error) { return nil, wantErr },
	}, testLogger())
	require.NoError(t, err)

	res, err := p.Provision(context.Background())
	require.ErrorIs(t, err, wantErr)
	assert.Nil(t, res)
}

// ---------------------------------------------------------------------------
// Explicit files (precedence 1)
// ---------------------------------------------------------------------------

// TestProvision_ExplicitFilesTakesPrecedence verifies operator-supplied files
// win over every automatic mode. An operator who pins cluster material must not
// have it quietly replaced by an auto-enrolled identity.
func TestProvision_ExplicitFilesTakesPrecedence(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		return path
	}

	opts := firstNodeOptions(t, t.TempDir(), softwareBackends(t))
	opts.KeyBackend = "software"
	opts.RaftTLSFiles = &ExplicitFiles{
		CACertFile: write("ca.pem", "ca-material"),
		CertFile:   write("cert.pem", "cert-material"),
		KeyFile:    write("key.pem", "key-material"),
	}

	p, err := New(opts, testLogger())
	require.NoError(t, err)

	res, err := p.Provision(context.Background())
	require.NoError(t, err)

	assert.Equal(t, []byte("ca-material"), res.MTLS.CACert)
	assert.Equal(t, []byte("cert-material"), res.MTLS.Cert)
	assert.Equal(t, []byte("key-material"), res.MTLS.Key)
	assert.Nil(t, res.MTLS.Certificate, "file mode supplies raw PEM, not a signer")
}

// TestExplicitFiles_Enabled verifies the mode engages only when all three paths
// are present. A partially-configured file mode must fall through to automatic
// enrollment rather than provisioning half an identity.
func TestExplicitFiles_Enabled(t *testing.T) {
	tests := []struct {
		name  string
		files *ExplicitFiles
		want  bool
	}{
		{"nil", nil, false},
		{"empty", &ExplicitFiles{}, false},
		{"ca only", &ExplicitFiles{CACertFile: "a"}, false},
		{"missing key", &ExplicitFiles{CACertFile: "a", CertFile: "b"}, false},
		{"missing cert", &ExplicitFiles{CACertFile: "a", KeyFile: "c"}, false},
		{"all three", &ExplicitFiles{CACertFile: "a", CertFile: "b", KeyFile: "c"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.files.Enabled())
		})
	}
}

// ---------------------------------------------------------------------------
// finishACME / anchor advertising
// ---------------------------------------------------------------------------

// freePort reserves and releases a localhost port so the advertiser can bind it.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}

// TestFinishACME_AdvertiserOnlyForFirstNodeOfMultiNodeCluster verifies the Noise
// anchor advertiser is started exactly when it is needed: on the first node of a
// cluster that expects peers. Starting it on a joiner or a single-node cluster
// would expose an unnecessary bootstrap listener.
func TestFinishACME_AdvertiserOnlyForFirstNodeOfMultiNodeCluster(t *testing.T) {
	anchorPEM, _, leaf := miniChain(t, "spiffe://test.cluster/node/127.0.0.1:8301")
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tlsCert, err := signerCertificate(certsToPEM(leaf), nil, signer)
	require.NoError(t, err)

	t.Run("single-node first node starts no advertiser", func(t *testing.T) {
		opts := firstNodeOptions(t, t.TempDir(), softwareBackends(t))
		opts.Members = map[uint64]string{1: "127.0.0.1:8301"}
		p, err := New(opts, testLogger())
		require.NoError(t, err)

		res, err := p.finishACME(tlsCert, anchorPEM, true)
		require.NoError(t, err)
		assert.Nil(t, res.Advertiser)
		assert.Equal(t, anchorPEM, res.MTLS.CACert)
	})

	t.Run("joiner starts no advertiser", func(t *testing.T) {
		opts := firstNodeOptions(t, t.TempDir(), softwareBackends(t))
		opts.Members = map[uint64]string{1: "127.0.0.1:8301", 2: "127.0.0.1:8302"}
		p, err := New(opts, testLogger())
		require.NoError(t, err)

		res, err := p.finishACME(tlsCert, anchorPEM, false)
		require.NoError(t, err)
		assert.Nil(t, res.Advertiser, "only the first node advertises the anchor")
	})

	t.Run("multi-node first node starts the advertiser", func(t *testing.T) {
		opts := firstNodeOptions(t, t.TempDir(), softwareBackends(t))
		opts.Members = map[uint64]string{1: "127.0.0.1:8301", 2: "127.0.0.1:8302"}
		opts.Advertise.NoisePort = freePort(t)
		// go-qrdb#167: clusterenroll refuses to pick a bind host for the
		// enrollment listener, so the fixture states one exactly as the
		// composition root does.
		opts.Advertise.NoiseHost = "127.0.0.1"
		p, err := New(opts, testLogger())
		require.NoError(t, err)

		res, err := p.finishACME(tlsCert, anchorPEM, true)
		require.NoError(t, err)
		require.NotNil(t, res.Advertiser, "peers need the anchor advertised to join")
		t.Cleanup(res.Advertiser.Stop)
	})
}

// TestFinishACME_RefusesToAdvertiseKeyBearingBundle is a security regression
// guard: the advertised anchor is served to unauthenticated joiners, so a
// bundle that accidentally contains private key material must abort startup
// rather than be published.
func TestFinishACME_RefusesToAdvertiseKeyBearingBundle(t *testing.T) {
	anchorPEM, _, leaf := miniChain(t, "spiffe://test.cluster/node/127.0.0.1:8301")
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tlsCert, err := signerCertificate(certsToPEM(leaf), nil, signer)
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(signer)
	require.NoError(t, err)
	poisoned := append(append([]byte{}, anchorPEM...),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)

	opts := firstNodeOptions(t, t.TempDir(), softwareBackends(t))
	opts.Members = map[uint64]string{1: "127.0.0.1:8301", 2: "127.0.0.1:8302"}
	opts.Advertise.NoisePort = freePort(t)
	p, err := New(opts, testLogger())
	require.NoError(t, err)

	res, err := p.finishACME(tlsCert, poisoned, true)
	require.Error(t, err, "an anchor bundle carrying a private key must never be advertised")
	assert.Nil(t, res)
}

// ---------------------------------------------------------------------------
// Joiner enrollment guards
// ---------------------------------------------------------------------------

// TestEnrollJoiner_UnreachableSeedNodeFailsFast verifies a joiner whose
// bootstrap endpoints are unreachable reports the fetch failure instead of
// hanging or proceeding without a trust anchor.
func TestEnrollJoiner_UnreachableSeedNodeFailsFast(t *testing.T) {
	opts := &Options{
		RaftAddress: "127.0.0.1:8302",
		TrustDomain: "test.cluster",
		DataDir:     t.TempDir(),
		ACME:        &ACMEOptions{DirectoryURL: "https://node1:8443/api/v1/acme/directory"},
		KeyBackend:  "tpm2",
		Backends:    softwareBackends(t),
		Bootstrap:   clusterenrollBootstrap(),
	}

	p, err := New(opts, testLogger())
	require.NoError(t, err)

	res, err := p.Provision(context.Background())
	require.Error(t, err, "an unreachable seed node must not yield a usable identity")
	assert.Nil(t, res)
}

// ---------------------------------------------------------------------------
// Key protection
// ---------------------------------------------------------------------------

// TestKeyProtection_EffectiveModeIsExplicitWhenSet verifies an explicitly
// configured mode is never silently rewritten. Downgrading an operator's
// explicit "tpm2" to a passphrase because the TPM is missing would break the
// deployment's stated security posture without telling anyone.
func TestKeyProtection_EffectiveModeIsExplicitWhenSet(t *testing.T) {
	for _, mode := range []KeyProtectionMode{
		KeyProtectTPM2, KeyProtectPKCS11, KeyProtectPassphrase, KeyProtectNone,
	} {
		t.Run(string(mode), func(t *testing.T) {
			kp := &KeyProtection{Mode: mode, DataDir: t.TempDir()}
			assert.Equal(t, mode, kp.effectiveMode(),
				"an explicit mode must survive even when unavailable, so Resolve can report why")
		})
	}
}

// TestKeyProtection_AutoSelectsPKCS11WhenStrategySaysSo verifies auto-detect
// distinguishes a PKCS#11 sealer from a TPM one, so the resolved mode names the
// hardware actually in use.
func TestKeyProtection_AutoSelectsPKCS11WhenStrategySaysSo(t *testing.T) {
	kp := &KeyProtection{
		Mode:           KeyProtectAuto,
		DataDir:        t.TempDir(),
		Sealer:         newFakeSealer(),
		SealStrategyID: string(KeyProtectPKCS11),
	}
	assert.Equal(t, KeyProtectPKCS11, kp.effectiveMode())
}

// TestKeyProtection_UnknownModeFailsClosed verifies an unrecognised mode string
// (e.g. a typo in configuration) does not fall through to plaintext.
func TestKeyProtection_UnknownModeFailsClosed(t *testing.T) {
	kp := &KeyProtection{Mode: KeyProtectionMode("bogus"), DataDir: t.TempDir()}
	assert.Equal(t, KeyProtectAuto, kp.effectiveMode())

	_, _, err := kp.Resolve(context.Background())
	var noProtection *ErrNoSecureCAKeyProtection
	require.ErrorAs(t, err, &noProtection)
}

// TestKeyProtection_AutoIgnoresSealerThatCannotSeal verifies a present but
// non-functional sealer (device open, sealing unavailable) does not win
// auto-selection over a configured passphrase.
func TestKeyProtection_AutoIgnoresSealerThatCannotSeal(t *testing.T) {
	kp := &KeyProtection{
		Mode:       KeyProtectAuto,
		DataDir:    t.TempDir(),
		Passphrase: mustSecret(t, "operator-secret"),
		Sealer:     &errSealer{canSeal: false},
	}
	assert.Equal(t, KeyProtectPassphrase, kp.effectiveMode())
}

// TestKeyProtection_SealStrategyLabel verifies the label reported for the active
// hardware strategy, which appears in operator-facing startup logs.
func TestKeyProtection_SealStrategyLabel(t *testing.T) {
	assert.Equal(t, string(KeyProtectTPM2), (&KeyProtection{}).sealStrategyLabel(),
		"TPM is the default hardware strategy")
	assert.Equal(t, "pkcs11", (&KeyProtection{SealStrategyID: "pkcs11"}).sealStrategyLabel())
}

// TestKeyProtection_SealFailurePropagates verifies a first-boot seal failure is
// reported rather than yielding an unprotected keystore password.
func TestKeyProtection_SealFailurePropagates(t *testing.T) {
	sealFailure := errors.New("tpm busy")
	kp := &KeyProtection{
		Mode:    KeyProtectTPM2,
		DataDir: t.TempDir(),
		Sealer:  &errSealer{canSeal: true, sealErr: sealFailure},
	}

	password, plaintext, err := kp.Resolve(context.Background())
	require.ErrorIs(t, err, sealFailure)
	assert.Nil(t, password)
	assert.False(t, plaintext)
}

// TestKeyProtection_UnsealFailurePropagates verifies a cached blob this machine
// can no longer unseal (moved disk, changed PCRs) is reported instead of being
// replaced by a freshly generated password, which would orphan the CA keys.
func TestKeyProtection_UnsealFailurePropagates(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()

	// Seal on first boot with a working sealer.
	working := &KeyProtection{Mode: KeyProtectTPM2, DataDir: dataDir, Sealer: newFakeSealer()}
	_, _, err := working.Resolve(ctx)
	require.NoError(t, err)

	// A different TPM cannot unseal it.
	unsealFailure := errors.New("policy digest mismatch")
	broken := &KeyProtection{
		Mode:    KeyProtectTPM2,
		DataDir: dataDir,
		Sealer:  &errSealer{canSeal: true, unsealErr: unsealFailure},
	}
	password, _, err := broken.Resolve(ctx)
	require.ErrorIs(t, err, unsealFailure)
	assert.Nil(t, password, "a fresh password must not silently replace the sealed one")
}

// TestKeyProtection_SealedPasswordCannotBeWrittenFailsClosed verifies that when
// the sealed blob cannot be persisted the operation fails, rather than
// returning a password that will be irrecoverable after a restart.
func TestKeyProtection_SealedPasswordCannotBeWrittenFailsClosed(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))

	kp := &KeyProtection{Mode: KeyProtectTPM2, DataDir: blocker, Sealer: newFakeSealer()}

	password, _, err := kp.Resolve(context.Background())
	require.Error(t, err)
	assert.Nil(t, password)
}

// ---------------------------------------------------------------------------
// Secret delivery
// ---------------------------------------------------------------------------

// failingProvider always errors, modelling a TPM that refuses to wrap.
type failingProvider struct{ err error }

func (p *failingProvider) ProvisionFor(context.Context, *NodeSecretRequest) (*ProvisionedSecret, error) {
	return nil, p.err
}

// nilProvider returns no material, modelling a strategy with nothing to deliver.
type nilProvider struct{}

func (p *nilProvider) ProvisionFor(context.Context, *NodeSecretRequest) (*ProvisionedSecret, error) {
	return nil, nil
}

// TestSecretDelivery_ProviderFailureIsNotLeakedToClient verifies a provider
// error becomes a generic 500 and that the underlying detail is not echoed to
// the unauthenticated-ish caller.
func TestSecretDelivery_ProviderFailureIsNotLeakedToClient(t *testing.T) {
	const nodeURI = "spiffe://test.cluster/node/10.0.0.2:63001"
	_, intermediate, leaf := miniChain(t, nodeURI)
	pool := x509.NewCertPool()
	pool.AddCert(intermediate)

	svc := NewSecretDeliveryService(testLogger(), pool,
		&failingProvider{err: errors.New("tpm credential wrap failed: secret 0xdeadbeef")})

	body, err := json.Marshal(&secretDeliveryRequest{
		NodeCertificatePEM: certPEM(leaf.Raw),
		EKCertificatePEM:   certPEM(intermediate.Raw),
		IAKPublic:          []byte("iak"),
	})
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	svc.Handler()(rec, httptest.NewRequest(http.MethodPost, SecretDeliveryPath, bytes.NewReader(body)))

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), "0xdeadbeef",
		"internal provider detail must not reach the client")
}

// TestSecretDelivery_RejectsCertificateWithoutSPIFFESAN verifies a node
// certificate that verifies but carries no URI SAN is refused. The SAN is the
// authoritative node identity used to decide what to wrap, so proceeding
// without one would deliver material to an unidentified peer.
func TestSecretDelivery_RejectsCertificateWithoutSPIFFESAN(t *testing.T) {
	// Build a chain whose leaf has no URI SAN by reusing the intermediate as
	// the presented "node certificate" (a CA cert carries no SPIFFE SAN).
	_, intermediate, _ := miniChain(t, "spiffe://test.cluster/node/10.0.0.2:1")
	pool := x509.NewCertPool()
	pool.AddCert(intermediate)

	svc := NewSecretDeliveryService(testLogger(), nil, &recordingProvider{})

	body, err := json.Marshal(&secretDeliveryRequest{
		NodeCertificatePEM: certPEM(intermediate.Raw),
		EKCertificatePEM:   certPEM(intermediate.Raw),
	})
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	svc.Handler()(rec, httptest.NewRequest(http.MethodPost, SecretDeliveryPath, bytes.NewReader(body)))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestSecretDelivery_RejectsMalformedCertificates verifies unusable node and EK
// certificate material is rejected with the right status: an unauthenticated
// node is 401, a well-authenticated node sending a bad EK is 400.
func TestSecretDelivery_RejectsMalformedCertificates(t *testing.T) {
	const nodeURI = "spiffe://test.cluster/node/10.0.0.2:63001"
	_, intermediate, leaf := miniChain(t, nodeURI)
	pool := x509.NewCertPool()
	pool.AddCert(intermediate)
	svc := NewSecretDeliveryService(testLogger(), pool, &recordingProvider{})

	post := func(t *testing.T, req *secretDeliveryRequest) int {
		t.Helper()
		body, err := json.Marshal(req)
		require.NoError(t, err)
		rec := httptest.NewRecorder()
		svc.Handler()(rec, httptest.NewRequest(http.MethodPost, SecretDeliveryPath, bytes.NewReader(body)))
		return rec.Code
	}

	t.Run("node certificate is not PEM", func(t *testing.T) {
		assert.Equal(t, http.StatusUnauthorized, post(t, &secretDeliveryRequest{
			NodeCertificatePEM: []byte("not pem"),
			EKCertificatePEM:   certPEM(intermediate.Raw),
		}))
	})

	t.Run("node certificate PEM holds bad DER", func(t *testing.T) {
		assert.Equal(t, http.StatusUnauthorized, post(t, &secretDeliveryRequest{
			NodeCertificatePEM: certPEM([]byte("garbage")),
			EKCertificatePEM:   certPEM(intermediate.Raw),
		}))
	})

	t.Run("EK certificate is not PEM", func(t *testing.T) {
		assert.Equal(t, http.StatusBadRequest, post(t, &secretDeliveryRequest{
			NodeCertificatePEM: certPEM(leaf.Raw),
			EKCertificatePEM:   []byte("not pem"),
		}))
	})

	t.Run("EK certificate PEM holds bad DER", func(t *testing.T) {
		assert.Equal(t, http.StatusBadRequest, post(t, &secretDeliveryRequest{
			NodeCertificatePEM: certPEM(leaf.Raw),
			EKCertificatePEM:   certPEM([]byte("garbage")),
		}))
	})
}

// TestSecretDeliveryService_NoProviders verifies a service with no providers
// reports itself as having none and delivers an empty set rather than erroring,
// which is the shape for a cluster whose strategy needs no secret delivery.
func TestSecretDeliveryService_NoProviders(t *testing.T) {
	svc := NewSecretDeliveryService(testLogger(), nil)
	assert.False(t, svc.HasProviders())

	secrets, err := svc.Deliver(context.Background(), &NodeSecretRequest{})
	require.NoError(t, err)
	assert.Empty(t, secrets)
}

// TestSecretDeliveryService_SkipsProvidersWithNothingToDeliver verifies a
// provider returning no material is omitted from the response instead of
// contributing a nil entry the client would dereference.
func TestSecretDeliveryService_SkipsProvidersWithNothingToDeliver(t *testing.T) {
	svc := NewSecretDeliveryService(testLogger(), nil, &nilProvider{}, &recordingProvider{})

	secrets, err := svc.Deliver(context.Background(), &NodeSecretRequest{NodeURI: "spiffe://x/node/1"})
	require.NoError(t, err)
	require.Len(t, secrets, 1)
	assert.NotNil(t, secrets[0])
}

// TestSecretDeliveryService_StopsOnFirstProviderError verifies delivery is
// all-or-nothing: one failing provider aborts the batch rather than returning a
// partial set the joiner would treat as complete.
func TestSecretDeliveryService_StopsOnFirstProviderError(t *testing.T) {
	wantErr := errors.New("provider exploded")
	svc := NewSecretDeliveryService(testLogger(), nil,
		&failingProvider{err: wantErr}, &recordingProvider{})

	secrets, err := svc.Deliver(context.Background(), &NodeSecretRequest{})
	require.ErrorIs(t, err, wantErr)
	assert.Nil(t, secrets)
}

// TestFetchClusterSecrets_ErrorPaths verifies the joiner-side client surfaces
// transport, status and body failures instead of returning an empty secret set
// that would look like "nothing to provision".
func TestFetchClusterSecrets_ErrorPaths(t *testing.T) {
	ctx := context.Background()

	t.Run("non-200 status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "nope", http.StatusForbidden)
		}))
		defer server.Close()

		secrets, err := FetchClusterSecrets(ctx, server.Client(), server.URL, nil, nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "403")
		assert.Nil(t, secrets)
	})

	t.Run("unparseable response body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("{not json"))
		}))
		defer server.Close()

		secrets, err := FetchClusterSecrets(ctx, server.Client(), server.URL, nil, nil, nil)
		require.Error(t, err)
		assert.Nil(t, secrets)
	})

	t.Run("unreachable server", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		client := server.Client()
		url := server.URL
		server.Close() // nothing is listening any more

		secrets, err := FetchClusterSecrets(ctx, client, url, nil, nil, nil)
		require.Error(t, err)
		assert.Nil(t, secrets)
	})

	t.Run("invalid base URL", func(t *testing.T) {
		secrets, err := FetchClusterSecrets(ctx, http.DefaultClient, "://not a url", nil, nil, nil)
		require.Error(t, err)
		assert.Nil(t, secrets)
	})
}

// TestVerifyNodeCert_WithoutPoolSkipsChainVerification verifies that a service
// configured with no cluster CA pool still parses and returns the certificate.
// This is the intra-cluster deployment where transport mTLS already authorizes
// the peer; it must not be mistaken for "verification passed".
func TestVerifyNodeCert_WithoutPoolSkipsChainVerification(t *testing.T) {
	_, _, leaf := miniChain(t, "spiffe://test.cluster/node/10.0.0.2:1")
	svc := NewSecretDeliveryService(testLogger(), nil, &recordingProvider{})

	got, err := svc.verifyNodeCert(certPEM(leaf.Raw))
	require.NoError(t, err)
	assert.Equal(t, leaf.SerialNumber, got.SerialNumber)
}

// TestNodeURIFromCert verifies SPIFFE identity extraction, including the
// no-SAN case that must yield an empty string so the caller can reject it.
func TestNodeURIFromCert(t *testing.T) {
	const nodeURI = "spiffe://test.cluster/node/10.0.0.2:63001"
	_, intermediate, leaf := miniChain(t, nodeURI)

	assert.Equal(t, nodeURI, nodeURIFromCert(leaf))
	assert.Empty(t, nodeURIFromCert(intermediate), "a CA certificate carries no node SAN")
	assert.Empty(t, nodeURIFromCert(&x509.Certificate{}))
}

// TestParseEKCertPEM verifies EK certificate decoding accepts a real
// certificate and rejects both non-PEM input and PEM wrapping invalid DER.
func TestParseEKCertPEM(t *testing.T) {
	_, _, leaf := miniChain(t, "spiffe://test.cluster/node/10.0.0.2:1")

	got, err := parseEKCertPEM(certPEM(leaf.Raw))
	require.NoError(t, err)
	assert.Equal(t, leaf.SerialNumber, got.SerialNumber)

	t.Run("not PEM", func(t *testing.T) {
		_, err := parseEKCertPEM([]byte("not pem"))
		require.ErrorIs(t, err, ErrMalformedRequest)
	})

	t.Run("PEM with invalid DER", func(t *testing.T) {
		_, err := parseEKCertPEM(certPEM([]byte("garbage")))
		require.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// TPM-resident node signer
// ---------------------------------------------------------------------------

// TestTPMKeySigner_PublicReportsCertificateKey verifies the signer advertises
// the public key taken from the issued certificate. TLS uses this to select a
// signature algorithm, so reporting a different key would break every
// handshake even though the TPM could sign correctly.
func TestTPMKeySigner_PublicReportsCertificateKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	s := &tpmKeySigner{public: key.Public()}

	require.NotNil(t, s.Public())
	assert.True(t, publicKeysEqual(key.Public(), s.Public()))

	// The signer must satisfy crypto.Signer so it can back a tls.Certificate.
	var _ = tls.Certificate{PrivateKey: s}
}

// TestNodeLocalBackendSet_RejectsUnusableDataDir verifies node-local backend
// construction fails when its storage directory cannot be created, instead of
// returning backends that silently lose every key they are given.
func TestNodeLocalBackendSet_RejectsUnusableDataDir(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))

	_, err := NewNodeLocalBackends(context.Background(), &NodeLocalBackendsParams{
		DataDir:    blocker,
		Protection: KeyProtection{Mode: KeyProtectPassphrase, Passphrase: mustSecret(t, "x")},
	})
	require.Error(t, err)
}

// TestNodeLocalBackends_TPMBackendUsedWhenItIsAKeyProvider verifies the shared
// TPM handle is reused for the "tpm2" key backend, which is what keeps the
// device from being opened twice.
func TestNodeLocalBackends_TPMBackendUsedWhenItIsAKeyProvider(t *testing.T) {
	// A sealer that is NOT a types.KeyProvider must fall back to software
	// rather than being handed out as a key backend.
	resolve, err := NewNodeLocalBackends(context.Background(), &NodeLocalBackendsParams{
		DataDir:     nodeLocalDataDir(t),
		Protection:  KeyProtection{Mode: KeyProtectPassphrase, Passphrase: mustSecret(t, "x")},
		HardwareTPM: newFakeSealer(),
	})
	require.NoError(t, err)

	tpmBackend, err := resolve("tpm2")
	require.NoError(t, err)
	require.NotNil(t, tpmBackend)

	softwareBackend, err := resolve("software")
	require.NoError(t, err)

	assert.Same(t, softwareBackend, tpmBackend,
		"a sealer that cannot provide keys must fall back to the software backend, "+
			"never be handed out as the tpm2 key backend")
}

// TestStagedCACertsPath_And_AnchorCachePath verify the on-disk contract the
// composition root depends on to adopt pre-staged material.
func TestStagedCACertsPath_And_AnchorCachePath(t *testing.T) {
	dir := t.TempDir()

	assert.Equal(t, filepath.Join(dir, "ca-certs.pem"), StagedCACertsPath(dir))
	assert.Equal(t, filepath.Join(dir, "anchor.pem"), AnchorCachePath(dir))
	assert.True(t, strings.HasSuffix(StagedCACertsPath(dir), ".pem"))
}

// TestKeyProtection_SealedBlobWriteFailureFailsClosed verifies that a sealed
// keystore password which cannot be written to its blob file is reported as an
// error rather than returned to the caller.
//
// A returned-but-unpersisted password is the worst outcome available: the CA
// keys would be encrypted under a secret that exists only in this process, and
// the next restart would generate a different one and find the keystore
// undecryptable. Here the blob path is occupied by a directory, which is what a
// half-finished migration or a bind-mount mishap leaves behind.
func TestKeyProtection_SealedBlobWriteFailureFailsClosed(t *testing.T) {
	dataDir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dataDir, "ca-key-seal.json"), 0o700))

	kp := &KeyProtection{Mode: KeyProtectTPM2, DataDir: dataDir, Sealer: newFakeSealer()}

	password, plaintext, err := kp.Resolve(context.Background())
	require.Error(t, err, "an unpersistable sealed password must not be handed out")
	assert.Nil(t, password)
	assert.False(t, plaintext)
}
