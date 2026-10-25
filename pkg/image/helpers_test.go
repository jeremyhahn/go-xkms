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

package image

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// testPurpose is the trust-roots purpose the tests verify images under.
const testPurpose purpose = "image-signer"

// purpose stands in for a trust-roots store's purpose type.
type purpose string

// errTestSigner is the error failingSigner signs with.
var errTestSigner = errors.New("test: signer refused")

// testTSAPolicy is the policy the test TSA stamps under.
var testTSAPolicy = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}

// testRSAKey is generated once: RSA key generation is slow under -race.
var testRSAKey = sync.OnceValues(func() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
})

func newECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := testRSAKey()
	require.NoError(t, err)
	return key
}

func newEd25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return key
}

// signerKeys returns one signer of every supported key type.
func signerKeys(t *testing.T) map[string]crypto.Signer {
	t.Helper()
	return map[string]crypto.Signer{
		"ecdsa":   newECDSAKey(t),
		"rsa":     newRSAKey(t),
		"ed25519": newEd25519Key(t),
	}
}

// failingSigner is a crypto.Signer whose key refuses to sign.
type failingSigner struct {
	public crypto.PublicKey
}

func (s failingSigner) Public() crypto.PublicKey { return s.public }

func (s failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errTestSigner
}

// testPKI is a root CA issuing the tests' code-signing and TSA
// certificates.
type testPKI struct {
	key         crypto.Signer
	certificate *x509.Certificate
	pool        *x509.CertPool
	serial      atomic.Int64
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	key := newECDSAKey(t)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "image test root"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	pki := &testPKI{key: key, certificate: certificate, pool: x509.NewCertPool()}
	pki.pool.AddCert(certificate)
	pki.serial.Store(1)
	return pki
}

// issue certifies key under template, valid for an hour either side of now
// unless the template sets a validity.
func (p *testPKI) issue(t *testing.T, key crypto.PublicKey, template *x509.Certificate) *x509.Certificate {
	t.Helper()
	template.SerialNumber = big.NewInt(p.serial.Add(1))
	if template.NotBefore.IsZero() {
		template.NotBefore = time.Now().Add(-time.Hour)
	}
	if template.NotAfter.IsZero() {
		template.NotAfter = time.Now().Add(time.Hour)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, p.certificate, key, p.key)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return certificate
}

// codeSigning issues a code-signing certificate for key.
func (p *testPKI) codeSigning(t *testing.T, key crypto.PublicKey) *x509.Certificate {
	t.Helper()
	return p.issue(t, key, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "image signer"},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	})
}

// timestamping issues a time-stamping certificate for key, with the one
// critical id-kp-timeStamping extended key usage RFC 3161 section 2.3 requires.
func (p *testPKI) timestamping(t *testing.T, key crypto.PublicKey) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "image tsa"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		SubjectKeyId: []byte("image tsa key"),
		// The usages TrustedCA's timestamping profile sets.
		KeyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		ExtraExtensions: []pkix.Extension{extKeyUsageExtension(t, true, oidKPTimeStamping)},
	}
	return p.issue(t, key, template)
}

// extKeyUsageExtension encodes an extended key usage extension listing
// usages. x509.CreateCertificate always marks the one it builds from
// ExtKeyUsage non-critical; this one overrides it.
func extKeyUsageExtension(t *testing.T, critical bool, usages ...asn1.ObjectIdentifier) pkix.Extension {
	t.Helper()
	value, err := asn1.Marshal(usages)
	require.NoError(t, err)
	return pkix.Extension{Id: oidExtKeyUsage, Critical: critical, Value: value}
}

// roots returns a trust-roots store holding the PKI's root for
// testPurpose.
func (p *testPKI) roots() *testRoots {
	return &testRoots{byPurpose: map[purpose][]*x509.Certificate{testPurpose: {p.certificate}}}
}

// testRoots is a trust-roots store.
type testRoots struct {
	byPurpose map[purpose][]*x509.Certificate
	err       error
}

func (r *testRoots) CertificatesByPurpose(p purpose) ([]*x509.Certificate, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.byPurpose[p], nil
}

// testIssuer issues from a test PKI under TrustedCA's code-signing
// profile, as TrustedCA's issuer does.
type testIssuer struct {
	t       *testing.T
	pki     *testPKI
	profile string
	tenant  string
	edit    func(template *x509.Certificate)
	err     error
}

func (i *testIssuer) SignCSRRaw(_ context.Context, csrPEM []byte, profile string, _ int, tenantID string) (*x509.Certificate, error) {
	if i.err != nil {
		return nil, i.err
	}
	block, rest := pem.Decode(csrPEM)
	require.NotNil(i.t, block)
	require.Empty(i.t, rest)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(i.t, err)
	require.NoError(i.t, csr.CheckSignature())

	// TrustedCA's code-signing profile accepts a subject of one common name.
	require.NotEmpty(i.t, csr.Subject.CommonName)
	require.Equal(i.t, "CN="+csr.Subject.CommonName, csr.Subject.String())
	i.profile = profile
	i.tenant = tenantID

	// The usages TrustedCA's code-signing profile sets.
	template := &x509.Certificate{
		Subject:               csr.Subject,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}
	if i.edit != nil {
		i.edit(template)
	}
	return i.pki.issue(i.t, csr.PublicKey, template), nil
}

// registryConfig shapes a testRegistry.
type registryConfig struct {
	// referrers serves the OCI 1.1 referrers API; without it the registry
	// answers 404, as registries before OCI 1.1 do.
	referrers bool

	// referrersPage, when set, serves the referrers index in pages of that
	// many descriptors, each linking to the next with a relative Link header.
	referrersPage int

	// referrersLink, when set, is the Link header of every referrers page.
	// It is read under the registry's mu, so a test may set it once the
	// registry runs.
	referrersLink string

	// token, when set, is the bearer token every request must carry.
	token string

	// challenge answers a request without the token with a Bearer challenge
	// whose realm is the registry's /token endpoint, as an OCI distribution
	// token flow does. The endpoint issues token to a request carrying
	// service and scope, and the basic credentials username and password
	// when username is set.
	challenge          bool
	username, password string

	// uploadLocation, when set, is the Location of every blob upload.
	uploadLocation string
}

// storedManifest is a manifest the test registry holds.
type storedManifest struct {
	mediaType string
	body      []byte
}

// testRegistry is an in-memory OCI distribution registry served over TLS.
type testRegistry struct {
	t      *testing.T
	config registryConfig
	server *httptest.Server

	// unavailable counts the requests still to be answered 503.
	unavailable atomic.Int32

	mu        sync.Mutex
	manifests map[string]storedManifest // repository + "/" + tag or digest
	blobs     map[string][]byte         // repository + "@" + digest
	referring map[string][]Descriptor   // repository + "@" + subject digest
	uploads   int

	// tokensIssued counts the tokens the /token endpoint issued.
	tokensIssued atomic.Int32
}

// Bearer challenge parameters of the test registry's token flow.
const (
	testTokenService = "test-registry"
	testTokenScope   = "repository:team/app:pull,push"
)

// registryRoute serves the requests under one path marker of the
// distribution API.
type registryRoute struct {
	marker string
	serve  func(r *testRegistry, w http.ResponseWriter, req *http.Request, repository, rest string)
}

// registryRoutes are in match order: uploads before blobs.
var registryRoutes = []registryRoute{
	{marker: "/manifests/", serve: (*testRegistry).serveManifest},
	{marker: "/blobs/uploads/", serve: (*testRegistry).serveUpload},
	{marker: "/blobs/", serve: (*testRegistry).serveBlob},
	{marker: "/referrers/", serve: (*testRegistry).serveReferrers},
}

func newTestRegistry(t *testing.T, config registryConfig) *testRegistry {
	t.Helper()
	r := &testRegistry{
		t:         t,
		config:    config,
		manifests: map[string]storedManifest{},
		blobs:     map[string][]byte{},
		referring: map[string][]Descriptor{},
	}
	r.server = httptest.NewUnstartedServer(r)
	r.server.StartTLS()
	t.Cleanup(r.server.Close)
	return r
}

// host returns the registry's host:port.
func (r *testRegistry) host() string {
	return strings.TrimPrefix(r.server.URL, "https://")
}

// client returns a RegistryClient trusting the registry's certificate.
func (r *testRegistry) client(t *testing.T, opts *RegistryOptions) RegistryClient {
	t.Helper()
	if opts == nil {
		opts = &RegistryOptions{}
	}
	opts.RootCAs = x509.NewCertPool()
	opts.RootCAs.AddCert(r.server.Certificate())
	if opts.RetryDelay == 0 {
		opts.RetryDelay = time.Millisecond
	}
	client, err := NewRegistryClient(opts)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	return client
}

// seedImage stores a one-layer OCI image as repository:tag and returns its
// reference and manifest digest.
func (r *testRegistry) seedImage(t *testing.T, repository, tag string) (string, string) {
	t.Helper()
	config := []byte(`{"architecture":"amd64","os":"linux"}`)
	layer := []byte("layer of " + repository + ":" + tag)
	r.mu.Lock()
	r.blobs[repository+"@"+sha256Digest(config)] = config
	r.blobs[repository+"@"+sha256Digest(layer)] = layer
	r.mu.Unlock()

	body, err := json.Marshal(Manifest{
		SchemaVersion: 2,
		MediaType:     MediaTypeOCIManifest,
		Config:        Descriptor{MediaType: MediaTypeOCIConfig, Digest: sha256Digest(config), Size: int64(len(config))},
		Layers: []Descriptor{{
			MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
			Digest:    sha256Digest(layer),
			Size:      int64(len(layer)),
		}},
	})
	require.NoError(t, err)
	digest, _, err := r.putManifest(repository, tag, MediaTypeOCIManifest, body)
	require.NoError(t, err)
	return r.host() + "/" + repository + ":" + tag, digest
}

// manifest returns the manifest stored under repository and reference.
func (r *testRegistry) manifest(repository, reference string) (storedManifest, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	manifest, ok := r.manifests[repository+"/"+reference]
	return manifest, ok
}

// storeRaw stores body under repository and reference without checks.
func (r *testRegistry) storeRaw(repository, reference, mediaType string, body []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.manifests[repository+"/"+reference] = storedManifest{mediaType: mediaType, body: body}
}

// putManifest stores body under reference, a tag or the body's digest, and
// indexes it as a referrer of its subject when the registry serves
// referrers. It returns the body's digest and whether it was indexed.
func (r *testRegistry) putManifest(repository, reference, mediaType string, body []byte) (string, bool, error) {
	digest := sha256Digest(body)
	if validDigest(reference) && reference != digest {
		return "", false, ErrDigestMismatch
	}
	var manifest Manifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return "", false, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	stored := storedManifest{mediaType: mediaType, body: body}
	r.manifests[repository+"/"+digest] = stored
	r.manifests[repository+"/"+reference] = stored
	if manifest.Subject == nil || !r.config.referrers {
		return digest, false, nil
	}
	key := repository + "@" + manifest.Subject.Digest
	if !slices.ContainsFunc(r.referring[key], func(d Descriptor) bool { return d.Digest == digest }) {
		r.referring[key] = append(r.referring[key], Descriptor{
			MediaType:    mediaType,
			Digest:       digest,
			Size:         int64(len(body)),
			ArtifactType: manifest.ArtifactType,
		})
	}
	return digest, true, nil
}

// addReferrer indexes descriptor as a referrer of subject.
func (r *testRegistry) addReferrer(repository, subject string, descriptor Descriptor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := repository + "@" + subject
	r.referring[key] = append(r.referring[key], descriptor)
}

func (r *testRegistry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	for n := r.unavailable.Load(); n > 0; n = r.unavailable.Load() {
		if r.unavailable.CompareAndSwap(n, n-1) {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	if r.config.challenge && req.URL.Path == "/token" {
		r.serveToken(w, req)
		return
	}
	if r.config.token != "" && req.Header.Get("Authorization") != "Bearer "+r.config.token {
		if r.config.challenge {
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+r.server.URL+`/token",service="`+
				testTokenService+`",scope="`+testTokenScope+`"`)
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	path, ok := strings.CutPrefix(req.URL.Path, "/v2/")
	if !ok {
		http.NotFound(w, req)
		return
	}
	for _, route := range registryRoutes {
		if repository, rest, found := strings.Cut(path, route.marker); found {
			route.serve(r, w, req, repository, rest)
			return
		}
	}
	http.NotFound(w, req)
}

// serveToken is the registry's token endpoint: it issues the registry's
// token to a request for its service and scope with the right credentials.
func (r *testRegistry) serveToken(w http.ResponseWriter, req *http.Request) {
	query := req.URL.Query()
	if query.Get("service") != testTokenService || query.Get("scope") != testTokenScope {
		http.Error(w, "unknown service or scope", http.StatusBadRequest)
		return
	}
	username, password, _ := req.BasicAuth()
	if r.config.username != "" && (username != r.config.username || password != r.config.password) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	r.tokensIssued.Add(1)
	body, err := json.Marshal(map[string]string{"token": r.config.token})
	if err != nil {
		r.t.Errorf("token response: %v", err)
	}
	w.Header().Set("Content-Type", "application/json")
	r.reply(w, req, http.StatusOK, body)
}

func (r *testRegistry) serveManifest(w http.ResponseWriter, req *http.Request, repository, reference string) {
	switch req.Method {
	case http.MethodGet, http.MethodHead:
		manifest, ok := r.manifest(repository, reference)
		if !ok {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", manifest.mediaType)
		r.reply(w, req, http.StatusOK, manifest.body)
	case http.MethodPut:
		digest, indexed, err := r.putManifest(repository, reference, req.Header.Get("Content-Type"), r.read(req))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if indexed {
			var manifest Manifest
			if err := json.Unmarshal(r.mustManifest(repository, digest).body, &manifest); err != nil {
				r.t.Errorf("stored manifest: %v", err)
			}
			w.Header().Set(headerOCISubject, manifest.Subject.Digest)
		}
		w.Header().Set("Docker-Content-Digest", digest)
		w.WriteHeader(http.StatusCreated)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// mustManifest returns a manifest the registry holds.
func (r *testRegistry) mustManifest(repository, reference string) storedManifest {
	manifest, ok := r.manifest(repository, reference)
	if !ok {
		r.t.Errorf("no manifest %s/%s", repository, reference)
	}
	return manifest
}

func (r *testRegistry) serveUpload(w http.ResponseWriter, req *http.Request, repository, session string) {
	switch {
	case req.Method == http.MethodPost && session == "":
		r.mu.Lock()
		r.uploads++
		location := "/v2/" + repository + "/blobs/uploads/session-" + strconv.Itoa(r.uploads) + "?state=open"
		r.mu.Unlock()
		if r.config.uploadLocation != "" {
			location = r.config.uploadLocation
		}
		w.Header().Set("Location", location)
		w.WriteHeader(http.StatusAccepted)
	case req.Method == http.MethodPut && session != "":
		body := r.read(req)
		query := req.URL.Query()
		if query.Get("state") != "open" || query.Get("digest") != sha256Digest(body) {
			http.Error(w, "bad upload", http.StatusBadRequest)
			return
		}
		r.mu.Lock()
		r.blobs[repository+"@"+sha256Digest(body)] = body
		r.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (r *testRegistry) serveBlob(w http.ResponseWriter, req *http.Request, repository, digest string) {
	r.mu.Lock()
	blob, ok := r.blobs[repository+"@"+digest]
	r.mu.Unlock()
	if !ok {
		http.NotFound(w, req)
		return
	}
	r.reply(w, req, http.StatusOK, blob)
}

func (r *testRegistry) serveReferrers(w http.ResponseWriter, req *http.Request, repository, digest string) {
	if !r.config.referrers {
		http.NotFound(w, req)
		return
	}
	r.mu.Lock()
	manifests := slices.Clone(r.referring[repository+"@"+digest])
	link := r.config.referrersLink
	r.mu.Unlock()
	if manifests == nil {
		manifests = []Descriptor{}
	}
	if size := r.config.referrersPage; size > 0 {
		offset := 0
		if page := req.URL.Query().Get("page"); page != "" {
			var err error
			if offset, err = strconv.Atoi(page); err != nil {
				r.t.Errorf("referrers page: %v", err)
			}
		}
		end := min(offset+size, len(manifests))
		if end < len(manifests) {
			next := *req.URL
			query := next.Query()
			query.Set("page", strconv.Itoa(end))
			next.RawQuery = query.Encode()
			w.Header().Set("Link", "<"+next.RequestURI()+`>; rel="next"`)
		}
		manifests = manifests[offset:end]
	}
	if link != "" {
		w.Header().Set("Link", link)
	}
	body, err := json.Marshal(index{SchemaVersion: 2, MediaType: MediaTypeOCIIndex, Manifests: manifests})
	if err != nil {
		r.t.Errorf("referrers index: %v", err)
	}
	w.Header().Set("Content-Type", MediaTypeOCIIndex)
	r.reply(w, req, http.StatusOK, body)
}

// read returns the request body.
func (r *testRegistry) read(req *http.Request) []byte {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		r.t.Errorf("read request: %v", err)
	}
	return body
}

// reply answers status with body; HEAD answers carry no body.
func (r *testRegistry) reply(w http.ResponseWriter, req *http.Request, status int, body []byte) {
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	if req.Method == http.MethodHead {
		return
	}
	if _, err := w.Write(body); err != nil {
		r.t.Errorf("write response: %v", err)
	}
}

// tsaConfig shapes a testTSA.
type tsaConfig struct {
	// status is the PKIStatus answered; zero grants.
	status int

	// tamper edits every TSTInfo before it is signed.
	tamper func(info *tstInfo)
}

// testTSA is an RFC 3161 time-stamping authority served over HTTP.
type testTSA struct {
	t           *testing.T
	config      tsaConfig
	key         crypto.Signer
	certificate *x509.Certificate
	server      *httptest.Server
	serial      atomic.Int64
}

func newTestTSA(t *testing.T, pki *testPKI, config tsaConfig) *testTSA {
	t.Helper()
	key := newECDSAKey(t)
	tsa := &testTSA{t: t, config: config, key: key, certificate: pki.timestamping(t, key.Public())}
	tsa.server = httptest.NewUnstartedServer(tsa)
	tsa.server.Start()
	t.Cleanup(tsa.server.Close)
	return tsa
}

// client returns an RFC3161Client of the TSA.
func (a *testTSA) client(t *testing.T) *RFC3161Client {
	t.Helper()
	client, err := NewRFC3161Client(a.server.URL, a.server.Client())
	require.NoError(t, err)
	return client
}

func (a *testTSA) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(req.Body)
	if err != nil || req.Header.Get("Content-Type") != "application/timestamp-query" {
		http.Error(w, "bad query", http.StatusBadRequest)
		return
	}
	var query timeStampReq
	if err := unmarshalDER(body, &query, "TimeStampReq"); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	response, err := a.respond(&query)
	if err != nil {
		a.t.Errorf("timestamp response: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/timestamp-reply")
	if _, err := w.Write(response); err != nil {
		a.t.Errorf("write response: %v", err)
	}
}

// respond answers query.
func (a *testTSA) respond(query *timeStampReq) ([]byte, error) {
	if a.config.status != pkiStatusGranted {
		return asn1.Marshal(timeStampResp{Status: pkiStatusInfo{Status: a.config.status, StatusString: []string{"refused"}}})
	}
	info := tstInfo{
		Version:        1,
		Policy:         testTSAPolicy,
		MessageImprint: query.MessageImprint,
		SerialNumber:   big.NewInt(a.serial.Add(1)),
		GenTime:        time.Now().UTC().Truncate(time.Second),
		Nonce:          query.Nonce,
	}
	if a.config.tamper != nil {
		a.config.tamper(&info)
	}
	return timestampResponse(a.key, a.certificate, &info, &tokenOptions{})
}

// newTSTInfo returns a TSTInfo over data stamped at genTime.
func newTSTInfo(data []byte, genTime time.Time) *tstInfo {
	return &tstInfo{
		Version: 1,
		Policy:  testTSAPolicy,
		MessageImprint: messageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256},
			HashedMessage: sha256Sum(data),
		},
		SerialNumber: big.NewInt(7),
		GenTime:      genTime.UTC().Truncate(time.Second),
	}
}

// tokenOptions bend a timestamp token out of shape; the zero value builds
// a valid token.
type tokenOptions struct {
	// digestAlgorithm is the signer's digest algorithm; SHA-256 when nil.
	digestAlgorithm asn1.ObjectIdentifier

	// signatureAlgorithm is the signer's signature algorithm; the key's
	// with SHA-256 when nil.
	signatureAlgorithm asn1.ObjectIdentifier

	// contentType is the content-type attribute; TSTInfo when nil.
	contentType asn1.ObjectIdentifier

	// messageDigest is the message-digest attribute; the content's when nil.
	messageDigest []byte

	// keyIdentifier names the signer by subject key identifier rather than
	// issuer and serial number.
	keyIdentifier bool

	// noSignedAttributes leaves the signed attributes out.
	noSignedAttributes bool

	// signers is the number of signer infos; one when zero.
	signers int

	// certificates are the token's certificates; the signer's when nil.
	certificates []*x509.Certificate

	// status is the response's PKIStatus.
	status int
}

// timestampResponse returns a DER TimeStampResp holding info signed by
// signer, whose certificate is certificate.
func timestampResponse(signer crypto.Signer, certificate *x509.Certificate, info *tstInfo, opts *tokenOptions) ([]byte, error) {
	content, err := asn1.Marshal(*info)
	if err != nil {
		return nil, err
	}
	digestAlgorithm := opts.digestAlgorithm
	if digestAlgorithm == nil {
		digestAlgorithm = oidSHA256
	}
	digest, ok := hashAlgorithms[digestAlgorithm.String()]
	if !ok {
		digest = hashAlgorithms[oidSHA256.String()]
	}

	attributes, err := signedAttributes(opts, digest.sum(content))
	if err != nil {
		return nil, err
	}
	signed, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: attributes})
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign(rand.Reader, digest.sum(signed), digest.hash)
	if err != nil {
		return nil, err
	}
	sid, err := signerIdentifier(certificate, opts.keyIdentifier)
	if err != nil {
		return nil, err
	}

	signatureAlgorithm := opts.signatureAlgorithm
	if signatureAlgorithm == nil {
		signatureAlgorithm = oidECDSAWithSHA256
		if _, isRSA := signer.Public().(*rsa.PublicKey); isRSA {
			signatureAlgorithm = oidSHA256WithRSA
		}
	}
	info0 := signerInfo{
		Version:            1,
		SID:                sid,
		DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: digestAlgorithm},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: signatureAlgorithm},
		Signature:          signature,
	}
	if !opts.noSignedAttributes {
		info0.SignedAttrs = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: attributes}
	}
	signers := make([]signerInfo, max(opts.signers, 1))
	for i := range signers {
		signers[i] = info0
	}

	certificates := opts.certificates
	if certificates == nil {
		certificates = []*x509.Certificate{certificate}
	}
	var raw []byte
	for _, c := range certificates {
		raw = append(raw, c.Raw...)
	}

	signedContent, err := asn1.Marshal(signedData{
		Version:          3,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: digestAlgorithm}},
		EncapContentInfo: encapsulatedContentInfo{EContentType: oidTSTInfo, EContent: content},
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: raw},
		SignerInfos:      signers,
	})
	if err != nil {
		return nil, err
	}
	token, err := asn1.Marshal(contentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: signedContent},
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(timeStampResp{Status: pkiStatusInfo{Status: opts.status}, TimeStampToken: asn1.RawValue{FullBytes: token}})
}

// signedAttributes returns the DER content-type and message-digest
// attributes, concatenated.
func signedAttributes(opts *tokenOptions, contentDigest []byte) ([]byte, error) {
	contentType := opts.contentType
	if contentType == nil {
		contentType = oidTSTInfo
	}
	messageDigest := opts.messageDigest
	if messageDigest == nil {
		messageDigest = contentDigest
	}
	contentTypeValue, err := asn1.Marshal(contentType)
	if err != nil {
		return nil, err
	}
	messageDigestValue, err := asn1.Marshal(messageDigest)
	if err != nil {
		return nil, err
	}

	var attributes []byte
	for _, attr := range []attribute{
		{Type: oidAttContentType, Values: []asn1.RawValue{{FullBytes: contentTypeValue}}},
		{Type: oidAttMessageDigest, Values: []asn1.RawValue{{FullBytes: messageDigestValue}}},
	} {
		der, err := asn1.Marshal(attr)
		if err != nil {
			return nil, err
		}
		attributes = append(attributes, der...)
	}
	return attributes, nil
}

// signerIdentifier returns the CMS SignerIdentifier of certificate.
func signerIdentifier(certificate *x509.Certificate, keyIdentifier bool) (asn1.RawValue, error) {
	if keyIdentifier {
		return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: certificate.SubjectKeyId}, nil
	}
	der, err := asn1.Marshal(issuerAndSerialNumber{
		Issuer:       asn1.RawValue{FullBytes: certificate.RawIssuer},
		SerialNumber: certificate.SerialNumber,
	})
	if err != nil {
		return asn1.RawValue{}, err
	}
	return asn1.RawValue{FullBytes: der}, nil
}
