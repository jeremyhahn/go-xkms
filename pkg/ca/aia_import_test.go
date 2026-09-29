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

package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// aiaRepo is an httptest server publishing certificates by path, standing
// in for the AIA caIssuers endpoints of a real PKI.
type aiaRepo struct {
	srv   *httptest.Server
	mu    sync.Mutex
	certs map[string][]byte
	hits  int
}

func newAIARepo(t *testing.T) *aiaRepo {
	t.Helper()
	repo := &aiaRepo{certs: make(map[string][]byte)}
	repo.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		repo.mu.Lock()
		repo.hits++
		der, ok := repo.certs[r.URL.Path]
		repo.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/pkix-cert")
		_, _ = w.Write(der)
	}))
	t.Cleanup(repo.srv.Close)
	return repo
}

// url returns the AIA URL at which publish serves name.
func (r *aiaRepo) url(name string) string { return r.srv.URL + "/" + name + ".crt" }

func (r *aiaRepo) publish(name string, cert *x509.Certificate) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.certs["/"+name+".crt"] = cert.Raw
}

func (r *aiaRepo) requests() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hits
}

// aiaCert issues a certificate named cn. A nil parent makes it self-signed.
// aiaURL, when set, becomes its IssuingCertificateURL.
func aiaCert(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, aiaURL string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	if aiaURL != "" {
		tmpl.IssuingCertificateURL = []string{aiaURL}
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

// aiaChain publishes a self-signed root and n intermediates beneath it, each
// pointing at its issuer by AIA, and returns a leaf under the lowest one.
func aiaChain(t *testing.T, repo *aiaRepo, prefix string, n int) *x509.Certificate {
	t.Helper()
	issuerName := prefix + "-root"
	issuer, issuerKey := aiaCert(t, issuerName, nil, nil, "")
	repo.publish(issuerName, issuer)
	for i := 1; i <= n; i++ {
		name := fmt.Sprintf("%s-int%d", prefix, i)
		cert, key := aiaCert(t, name, issuer, issuerKey, repo.url(issuerName))
		repo.publish(name, cert)
		issuer, issuerKey, issuerName = cert, key, name
	}
	leaf, _ := aiaCert(t, prefix+"-leaf", issuer, issuerKey, repo.url(issuerName))
	return leaf
}

func assertStored(t *testing.T, ca *CA, cn string) {
	t.Helper()
	cert, err := ca.certStore.GetCertificate(cn)
	require.NoError(t, err, cn)
	assert.Equal(t, cn, cert.Subject.CommonName)
}

func assertNotStored(t *testing.T, ca *CA, cn string) {
	t.Helper()
	_, err := ca.certStore.GetCertificate(cn)
	assert.Error(t, err, "%s must not be imported", cn)
}

func TestImportIssuingCAs_ImportsFullChain(t *testing.T) {
	t.Parallel()
	repo := newAIARepo(t)
	// maxAIADepth issuers above the leaf: maxAIADepth-1 intermediates plus the root.
	leaf := aiaChain(t, repo, "full", maxAIADepth-1)
	ca := setupTestCA(t)
	allowLoopbackFetch(ca)

	require.NoError(t, ca.ImportIssuingCAs(context.Background(), leaf))

	assertStored(t, ca, "full-root")
	for i := 1; i < maxAIADepth; i++ {
		assertStored(t, ca, fmt.Sprintf("full-int%d", i))
	}
}

func TestImportIssuingCAs_AlreadyStoredIssuerIsWalkedThrough(t *testing.T) {
	t.Parallel()
	repo := newAIARepo(t)
	leaf := aiaChain(t, repo, "again", 1)
	ca := setupTestCA(t)
	allowLoopbackFetch(ca)

	require.NoError(t, ca.ImportIssuingCAs(context.Background(), leaf))
	require.NoError(t, ca.ImportIssuingCAs(context.Background(), leaf))
	assertStored(t, ca, "again-int1")
	assertStored(t, ca, "again-root")
}

func TestImportIssuingCAs_DepthLimit(t *testing.T) {
	t.Parallel()
	repo := newAIARepo(t)
	leaf := aiaChain(t, repo, "deep", maxAIADepth+1)
	ca := setupTestCA(t)
	allowLoopbackFetch(ca)

	err := ca.ImportIssuingCAs(context.Background(), leaf)
	assert.ErrorIs(t, err, ErrAIADepthExceeded)
	assert.Equal(t, maxAIADepth, repo.requests(), "the walk must stop at the depth limit")
	assertNotStored(t, ca, "deep-root")
}

func TestImportIssuingCAs_SelfReferencingAIALoopRefused(t *testing.T) {
	t.Parallel()
	repo := newAIARepo(t)
	root, rootKey := aiaCert(t, "loop-root", nil, nil, "")
	// The intermediate's AIA names the intermediate itself.
	intermediate, intermediateKey := aiaCert(t, "loop-int", root, rootKey, repo.url("loop-int"))
	repo.publish("loop-int", intermediate)
	leaf, _ := aiaCert(t, "loop-leaf", intermediate, intermediateKey, repo.url("loop-int"))
	ca := setupTestCA(t)
	allowLoopbackFetch(ca)

	err := ca.ImportIssuingCAs(context.Background(), leaf)
	assert.ErrorIs(t, err, ErrAIALoop)
	assert.Equal(t, 2, repo.requests(), "the loop must be detected on its first repetition")
}

func TestImportIssuingCAs_UnrelatedIssuerRefused(t *testing.T) {
	t.Parallel()
	repo := newAIARepo(t)
	realIssuer, realKey := aiaCert(t, "sig-real", nil, nil, "")
	impostor, _ := aiaCert(t, "sig-impostor", nil, nil, "")
	repo.publish("sig-real", impostor) // the AIA URL serves a certificate that did not sign the leaf
	leaf, _ := aiaCert(t, "sig-leaf", realIssuer, realKey, repo.url("sig-real"))
	ca := setupTestCA(t)
	allowLoopbackFetch(ca)

	err := ca.ImportIssuingCAs(context.Background(), leaf)
	assert.ErrorIs(t, err, ErrAIAIssuerSignatureInvalid)
	assertNotStored(t, ca, "sig-impostor")
}

func TestImportIssuingCAs_PrivateAddressRefused(t *testing.T) {
	t.Parallel()
	repo := newAIARepo(t)
	leaf := aiaChain(t, repo, "private", 1)
	ca := setupTestCA(t) // production client: loopback is not public

	err := ca.ImportIssuingCAs(context.Background(), leaf)
	assert.ErrorIs(t, err, ErrPKIFetchRefused)
	assert.Zero(t, repo.requests())
}

func TestImportIssuingCAs_OversizedResponseRefused(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, maxAIACertificateBytes+1))
	}))
	t.Cleanup(srv.Close)
	issuer, issuerKey := aiaCert(t, "big-root", nil, nil, "")
	leaf, _ := aiaCert(t, "big-leaf", issuer, issuerKey, srv.URL+"/big.crt")
	ca := setupTestCA(t)
	allowLoopbackFetch(ca)

	err := ca.ImportIssuingCAs(context.Background(), leaf)
	assert.ErrorIs(t, err, ErrPKIFetchTooLarge)
}

func TestImportIssuingCAs_UnparseableResponse(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("this is not a certificate"))
	}))
	t.Cleanup(srv.Close)
	issuer, issuerKey := aiaCert(t, "junk-root", nil, nil, "")
	leaf, _ := aiaCert(t, "junk-leaf", issuer, issuerKey, srv.URL+"/junk.crt")
	ca := setupTestCA(t)
	allowLoopbackFetch(ca)

	err := ca.ImportIssuingCAs(context.Background(), leaf)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestImportIssuingCAs_SelfSignedStartIsNotFetched(t *testing.T) {
	t.Parallel()
	repo := newAIARepo(t)
	root, _ := aiaCert(t, "selfsigned-root", nil, nil, repo.url("anything"))
	ca := setupTestCA(t)
	allowLoopbackFetch(ca)

	require.NoError(t, ca.ImportIssuingCAs(context.Background(), root))
	assert.Zero(t, repo.requests())
}
