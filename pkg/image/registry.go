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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

const (
	// DefaultRegistryTimeout bounds one registry request.
	DefaultRegistryTimeout = 30 * time.Second

	// DefaultRegistryRetries is how often a registry 5xx or transport error
	// is retried.
	DefaultRegistryRetries = 3

	// DefaultRegistryRetryDelay is the delay between registry retries.
	DefaultRegistryRetryDelay = time.Second

	// DefaultUserAgent is the User-Agent of registry and TSA requests.
	DefaultUserAgent = "go-xkms-image"

	// dockerHubEndpoint is the API host of DefaultRegistry.
	dockerHubEndpoint = "registry-1.docker.io"

	// maxManifestSize bounds a manifest or referrers index read; the OCI
	// distribution specification lets registries refuse larger manifests.
	maxManifestSize = 4 << 20

	// maxReferrerPages bounds the pages of a referrers index followed
	// through Link headers, so a registry cannot keep a reader paging.
	maxReferrerPages = 64

	// maxBlobSize bounds an attestation envelope read.
	maxBlobSize = 32 << 20

	// maxStatusBody bounds the body of a response read only for its status.
	maxStatusBody = 64 << 10

	// headerOCISubject is the header a registry answers a manifest push with
	// when it indexed the manifest's subject for the referrers API.
	headerOCISubject = "OCI-Subject"

	// retryJitter spreads concurrent retries apart.
	retryJitter = 0.1

	// maxRedirects is the number of redirects one request follows, the
	// net/http default.
	maxRedirects = 10
)

// RegistryClient reads and writes image manifests and attestations in an
// OCI distribution registry.
type RegistryClient interface {
	// Resolve returns the descriptor of the manifest ref names.
	Resolve(ctx context.Context, ref *Reference) (*Descriptor, error)

	// PushAttestation stores att for the image ref, which names subject's
	// digest, both as an OCI 1.1 referrer and in cosign's ".att" tag.
	PushAttestation(ctx context.Context, ref *Reference, subject *Descriptor, att *Attestation) (*PushResult, error)

	// Attestations returns the attestations of the image ref, which must
	// name a digest: the referrers API's when it has any, otherwise the
	// ".att" tag's.
	Attestations(ctx context.Context, ref *Reference) ([]*Attestation, error)

	// Close releases idle connections.
	Close() error
}

// RegistryAuth holds registry credentials: a bearer token, or a username
// and password for basic authentication. Without a bearer token the client
// follows a registry's Bearer challenge, fetching a token from its auth
// realm with the username and password, or anonymously without them.
//
// The caller owns Password: the client opens it only for the length of each
// request it signs, wipes the plaintext copy, and never destroys the Secret.
// A nil Password sends the username with an empty password.
type RegistryAuth struct {
	Username string
	Password *secure.Secret
	Token    string
}

// RegistryOptions configures a registry client. Zero values take the
// defaults.
type RegistryOptions struct {
	// Auth holds the registry credentials; nil sends none.
	Auth *RegistryAuth

	// Timeout bounds one request; DefaultRegistryTimeout when zero.
	Timeout time.Duration

	// MaxRetries is how often a 5xx or transport error is retried;
	// DefaultRegistryRetries when zero.
	MaxRetries int

	// RetryDelay is the delay between retries; DefaultRegistryRetryDelay
	// when zero.
	RetryDelay time.Duration

	// UserAgent is the request User-Agent; DefaultUserAgent when empty.
	UserAgent string

	// RootCAs verifies the registry's TLS certificate; the system pool when
	// nil.
	RootCAs *x509.CertPool
}

// PushResult describes a pushed attestation.
type PushResult struct {
	// Referrer is the descriptor of the OCI 1.1 referrer manifest.
	Referrer Descriptor

	// ReferrerIndexed reports whether the registry indexed the referrer for
	// its referrers API, which it signals with the OCI-Subject header.
	ReferrerIndexed bool

	// AttestationTag is the cosign ".att" tag the attestation was added to.
	AttestationTag string
}

// registryClient is the OCI distribution API client behind RegistryClient.
type registryClient struct {
	http      *http.Client
	auth      *RegistryAuth
	userAgent string
	retry     *qrdbsdk.RetryConfig

	// tokens holds, per registry host, the bearer token its auth realm
	// last issued (string), sent until a new challenge replaces it.
	tokens sync.Map
}

// request is one registry API request; body is resent on each retry.
type request struct {
	method      string
	url         *url.URL
	accept      []string
	contentType string
	body        []byte

	// credentials sends the client's credentials; false for an upload
	// location on another host.
	credentials bool

	// realm marks a token request to a registry's auth realm: it carries
	// the basic credentials only, never a bearer token.
	realm bool
}

// response is a registry answer below a 5xx status.
type response struct {
	method string
	status int
	header http.Header
	body   []byte
}

// NewRegistryClient returns a registry client configured by opts, which
// may be nil.
func NewRegistryClient(opts *RegistryOptions) (RegistryClient, error) {
	if opts == nil {
		opts = &RegistryOptions{}
	}
	if opts.Timeout < 0 || opts.MaxRetries < 0 || opts.RetryDelay < 0 {
		return nil, &errs.Detail{Err: ErrInvalidRegistryOptions, Detail: "negative timeout, retries or delay"}
	}

	transport := &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: opts.RootCAs},
		ForceAttemptHTTP2: true,
	}
	return &registryClient{
		http: &http.Client{
			Transport:     transport,
			CheckRedirect: checkRedirect,
			Timeout:       valueOr(opts.Timeout, DefaultRegistryTimeout),
		},
		auth:      opts.Auth,
		userAgent: valueOr(opts.UserAgent, DefaultUserAgent),
		retry: &qrdbsdk.RetryConfig{
			MaxAttempts: valueOr(opts.MaxRetries, DefaultRegistryRetries) + 1,
			Backoff: &qrdbsdk.ConstantBackoff{
				Delay:  valueOr(opts.RetryDelay, DefaultRegistryRetryDelay),
				Jitter: retryJitter,
			},
			RetryableFunc: retryable,
		},
	}, nil
}

// valueOr returns value, or fallback when value is the zero value.
func valueOr[T comparable](value, fallback T) T {
	var zero T
	if value == zero {
		return fallback
	}
	return value
}

// retryable reports whether a registry request failed with an error worth
// retrying: a 5xx answer or a transport error, never a canceled context.
func retryable(err error) bool {
	return errors.Is(err, ErrRegistryUnavailable) &&
		!errors.Is(err, context.Canceled) &&
		!errors.Is(err, context.DeadlineExceeded)
}

// checkRedirect is the registry client's redirect policy. It refuses a
// redirect to any destination other than HTTPS, so credentials never travel
// in plaintext, and drops the Authorization header of a redirect to a host
// other than the one first asked, so they never reach a host they were not
// meant for.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return &errs.Detail{Err: ErrRedirectRefused, Detail: "stopped after " + strconv.Itoa(maxRedirects) + " redirects"}
	}
	if req.URL.Scheme != "https" {
		return &errs.Detail{Err: ErrRedirectRefused, Detail: "scheme " + strconv.Quote(req.URL.Scheme)}
	}
	if !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
		req.Header.Del("Authorization")
	}
	return nil
}

// Resolve returns the descriptor of the manifest ref names. The digest is
// computed from the manifest bytes and, when ref names a digest, checked
// against it.
func (c *registryClient) Resolve(ctx context.Context, ref *Reference) (*Descriptor, error) {
	if err := validReference(ref); err != nil {
		return nil, err
	}
	resp, err := c.do(ctx, &request{
		method:      http.MethodGet,
		url:         endpoint(ref, "manifests", ref.manifestReference()),
		accept:      manifestAccept,
		credentials: true,
	}, maxManifestSize)
	if err != nil {
		return nil, err
	}
	if resp.status == http.StatusNotFound {
		return nil, &errs.Detail{Err: ErrManifestNotFound, Detail: ref.String()}
	}
	if err := expectStatus(resp, http.StatusOK); err != nil {
		return nil, err
	}

	digest := sha256Digest(resp.body)
	if ref.Digest != "" {
		if !matchesDigest(ref.Digest, resp.body) {
			return nil, &errs.Detail{Err: ErrDigestMismatch, Detail: ref.String()}
		}
		digest = ref.Digest
	}
	mediaType, err := manifestMediaType(resp)
	if err != nil {
		return nil, err
	}
	return &Descriptor{MediaType: mediaType, Digest: digest, Size: int64(len(resp.body))}, nil
}

// manifestMediaType returns the media type a manifest declares, or the
// response's Content-Type when the manifest declares none.
func manifestMediaType(resp *response) (string, error) {
	var manifest struct {
		MediaType string `json:"mediaType"`
	}
	if err := json.Unmarshal(resp.body, &manifest); err != nil {
		return "", &errs.Joined{Lead: ErrInvalidManifest, Cause: err}
	}
	if manifest.MediaType != "" {
		return manifest.MediaType, nil
	}
	if mediaType, _, err := mime.ParseMediaType(resp.header.Get("Content-Type")); err == nil {
		return mediaType, nil
	}
	return "", &errs.Detail{Err: ErrInvalidManifest, Detail: "no media type"}
}

// PushAttestation pushes att's envelope and an OCI 1.1 referrer manifest
// whose subject is the image, then adds the envelope to the image's cosign
// ".att" manifest. Both are always written: cosign reads either, and a
// registry without the referrers API serves only the tag.
func (c *registryClient) PushAttestation(ctx context.Context, ref *Reference, subject *Descriptor, att *Attestation) (*PushResult, error) {
	if err := validReference(ref); err != nil {
		return nil, err
	}
	tag, err := ref.AttestationTag()
	if err != nil {
		return nil, err
	}
	if subject == nil {
		return nil, ErrSubjectRequired
	}
	if subject.Digest != ref.Digest {
		return nil, &errs.Detail{Err: ErrDigestMismatch, Detail: "subject " + subject.Digest + " is not " + ref.Digest}
	}
	if att == nil || len(att.Envelope) == 0 {
		return nil, &errs.Detail{Err: ErrInvalidAttestation, Detail: "no envelope"}
	}
	layer, err := att.layer()
	if err != nil {
		return nil, err
	}

	if err := c.pushBlob(ctx, ref, att.Envelope); err != nil {
		return nil, err
	}
	if err := c.pushBlob(ctx, ref, emptyJSON); err != nil {
		return nil, err
	}
	referrer, header, err := c.pushManifest(ctx, ref, "", referrerManifest(subject, layer))
	if err != nil {
		return nil, err
	}

	existing, err := c.manifest(ctx, ref, tag)
	if err != nil && !errors.Is(err, ErrManifestNotFound) {
		return nil, err
	}
	manifest, config, err := appendAttestationLayer(existing, layer)
	if err != nil {
		return nil, err
	}
	if err := c.pushBlob(ctx, ref, config); err != nil {
		return nil, err
	}
	if _, _, err := c.pushManifest(ctx, ref, tag, manifest); err != nil {
		return nil, err
	}

	return &PushResult{
		Referrer:        referrer,
		ReferrerIndexed: header.Get(headerOCISubject) == subject.Digest,
		AttestationTag:  tag,
	}, nil
}

// Attestations returns the image's attestations from its OCI 1.1
// referrers, falling back to its cosign ".att" tag when the registry has
// no referrers API or no attestation referrer.
func (c *registryClient) Attestations(ctx context.Context, ref *Reference) ([]*Attestation, error) {
	if err := validReference(ref); err != nil {
		return nil, err
	}
	tag, err := ref.AttestationTag()
	if err != nil {
		return nil, err
	}

	referrers, err := c.referrers(ctx, ref)
	if err != nil {
		return nil, err
	}
	var attestations []*Attestation
	for _, referrer := range referrers {
		manifest, err := c.manifest(ctx, ref, referrer.Digest)
		if err != nil {
			return nil, err
		}
		found, err := c.attestationsOf(ctx, ref, manifest)
		if err != nil {
			return nil, err
		}
		attestations = append(attestations, found...)
	}
	if len(attestations) > 0 {
		return attestations, nil
	}

	manifest, err := c.manifest(ctx, ref, tag)
	if errors.Is(err, ErrManifestNotFound) {
		return nil, &errs.Detail{Err: ErrNoAttestation, Detail: ref.String()}
	}
	if err != nil {
		return nil, err
	}
	attestations, err = c.attestationsOf(ctx, ref, manifest)
	if err != nil {
		return nil, err
	}
	if len(attestations) == 0 {
		return nil, &errs.Detail{Err: ErrNoAttestation, Detail: ref.String()}
	}
	return attestations, nil
}

// Close releases the client's idle connections.
func (c *registryClient) Close() error {
	c.http.CloseIdleConnections()
	return nil
}

// referrers returns the image's attestation referrers, none when the
// registry has no referrers API. The artifactType filter is applied here
// too, since registries may ignore it.
func (c *registryClient) referrers(ctx context.Context, ref *Reference) ([]Descriptor, error) {
	target := endpoint(ref, "referrers", ref.Digest)
	target.RawQuery = url.Values{"artifactType": {ArtifactTypeAttestation}}.Encode()
	var matching []Descriptor
	for page := 0; target != nil; page++ {
		if page == maxReferrerPages {
			return nil, &errs.Detail{Err: ErrInvalidManifest, Detail: "referrers index has too many pages"}
		}
		resp, err := c.do(ctx, &request{
			method:      http.MethodGet,
			url:         target,
			accept:      []string{MediaTypeOCIIndex},
			credentials: true,
		}, maxManifestSize)
		if err != nil {
			return nil, err
		}
		if page == 0 && resp.status == http.StatusNotFound {
			return nil, nil
		}
		if err := expectStatus(resp, http.StatusOK); err != nil {
			return nil, err
		}

		var referrers index
		if err := json.Unmarshal(resp.body, &referrers); err != nil {
			return nil, &errs.Joined{Lead: ErrInvalidManifest, Detail: "referrers index", Cause: err}
		}
		for _, descriptor := range referrers.Manifests {
			if descriptor.ArtifactType == ArtifactTypeAttestation {
				matching = append(matching, descriptor)
			}
		}
		if target, err = nextPage(target, resp.header); err != nil {
			return nil, err
		}
	}
	return matching, nil
}

// nextPage returns the next page of a paged response to target, from the
// rel="next" link of its Link header (RFC 8288), or nil on the last page.
// The next page must be an https URL on target's host: the client sends it
// the registry's credentials.
func nextPage(target *url.URL, header http.Header) (*url.URL, error) {
	link, err := nextLink(header)
	if err != nil || link == "" {
		return nil, err
	}
	next, err := target.Parse(link)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrInvalidManifest, Detail: "referrers next link", Cause: err}
	}
	if next.Scheme != "https" || next.Host != target.Host {
		return nil, &errs.Detail{Err: ErrInvalidManifest, Detail: "referrers next link leaves the registry: " + next.Redacted()}
	}
	return next, nil
}

// nextLink returns the target of the rel="next" link among header's Link
// values, "<target>; param; ...", or "" when there is none.
func nextLink(header http.Header) (string, error) {
	for _, s := range header.Values("Link") {
		for {
			s = strings.TrimLeft(s, " \t,")
			if s == "" {
				break
			}
			end := strings.IndexByte(s, '>')
			if s[0] != '<' || end < 0 {
				return "", &errs.Detail{Err: ErrInvalidManifest, Detail: "malformed Link header"}
			}
			target := s[1:end]
			s = s[end+1:]
			params := strings.IndexByte(s, '<')
			if params < 0 {
				params = len(s)
			}
			if isNextRelation(s[:params]) {
				return target, nil
			}
			s = s[params:]
		}
	}
	return "", nil
}

// isNextRelation reports whether a link's parameters carry rel="next"; rel
// may list several space-separated relation types.
func isNextRelation(params string) bool {
	for _, param := range strings.Split(params, ";") {
		name, value, _ := strings.Cut(param, "=")
		if !strings.EqualFold(strings.TrimSpace(name), "rel") {
			continue
		}
		for _, relation := range strings.Fields(strings.Trim(strings.TrimSpace(value), `",`)) {
			if strings.EqualFold(relation, "next") {
				return true
			}
		}
	}
	return false
}

// attestationsOf fetches the envelope of every DSSE layer of manifest.
func (c *registryClient) attestationsOf(ctx context.Context, ref *Reference, manifest *Manifest) ([]*Attestation, error) {
	layers := attestationLayers(manifest)
	attestations := make([]*Attestation, 0, len(layers))
	for _, layer := range layers {
		envelope, err := c.blob(ctx, ref, layer.Digest)
		if err != nil {
			return nil, err
		}
		attestations = append(attestations, attestationFromLayer(layer, envelope))
	}
	return attestations, nil
}

// manifest fetches and decodes the OCI manifest reference names in ref's
// repository; a digest reference is checked against the bytes.
func (c *registryClient) manifest(ctx context.Context, ref *Reference, reference string) (*Manifest, error) {
	resp, err := c.do(ctx, &request{
		method:      http.MethodGet,
		url:         endpoint(ref, "manifests", reference),
		accept:      []string{MediaTypeOCIManifest},
		credentials: true,
	}, maxManifestSize)
	if err != nil {
		return nil, err
	}
	if resp.status == http.StatusNotFound {
		return nil, &errs.Detail{Err: ErrManifestNotFound, Detail: ref.Name() + ":" + reference}
	}
	if err := expectStatus(resp, http.StatusOK); err != nil {
		return nil, err
	}
	if validDigest(reference) && !matchesDigest(reference, resp.body) {
		return nil, &errs.Detail{Err: ErrDigestMismatch, Detail: ref.Name() + "@" + reference}
	}
	return parseManifest(resp.body)
}

// blob fetches the blob digest names in ref's repository and checks its
// digest.
func (c *registryClient) blob(ctx context.Context, ref *Reference, digest string) ([]byte, error) {
	resp, err := c.do(ctx, &request{
		method:      http.MethodGet,
		url:         endpoint(ref, "blobs", digest),
		credentials: true,
	}, maxBlobSize)
	if err != nil {
		return nil, err
	}
	if err := expectStatus(resp, http.StatusOK); err != nil {
		return nil, err
	}
	if !matchesDigest(digest, resp.body) {
		return nil, &errs.Detail{Err: ErrDigestMismatch, Detail: ref.Name() + "@" + digest}
	}
	return resp.body, nil
}

// pushBlob uploads data to ref's repository unless the registry holds it
// already, as a monolithic POST-then-PUT upload.
func (c *registryClient) pushBlob(ctx context.Context, ref *Reference, data []byte) error {
	digest := sha256Digest(data)
	head, err := c.do(ctx, &request{
		method:      http.MethodHead,
		url:         endpoint(ref, "blobs", digest),
		credentials: true,
	}, maxStatusBody)
	if err != nil {
		return err
	}
	switch head.status {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
	default:
		return statusError(head)
	}

	uploads := endpoint(ref, "blobs", "uploads", "")
	start, err := c.do(ctx, &request{method: http.MethodPost, url: uploads, credentials: true}, maxStatusBody)
	if err != nil {
		return err
	}
	if err := expectStatus(start, http.StatusAccepted); err != nil {
		return err
	}
	location, err := uploadLocation(uploads, start.header.Get("Location"), digest)
	if err != nil {
		return err
	}
	put, err := c.do(ctx, &request{
		method:      http.MethodPut,
		url:         location,
		contentType: "application/octet-stream",
		body:        data,
		credentials: location.Host == uploads.Host,
	}, maxStatusBody)
	if err != nil {
		return err
	}
	return expectStatus(put, http.StatusCreated)
}

// uploadLocation resolves a blob upload's Location header against the
// uploads endpoint and adds the digest that completes the upload. The
// location must stay on https.
func uploadLocation(uploads *url.URL, location, digest string) (*url.URL, error) {
	if location == "" {
		return nil, &errs.Detail{Err: ErrInvalidUploadLocation, Detail: "no Location header"}
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrInvalidUploadLocation, Cause: err}
	}
	resolved := uploads.ResolveReference(parsed)
	if resolved.Scheme != "https" {
		return nil, &errs.Detail{Err: ErrInvalidUploadLocation, Detail: "scheme " + strconv.Quote(resolved.Scheme)}
	}
	query := resolved.Query()
	query.Set("digest", digest)
	resolved.RawQuery = query.Encode()
	return resolved, nil
}

// pushManifest puts manifest under reference, its digest when reference is
// empty, and returns its descriptor and the response header.
func (c *registryClient) pushManifest(ctx context.Context, ref *Reference, reference string, manifest *Manifest) (Descriptor, http.Header, error) {
	data, err := json.Marshal(manifest)
	if err != nil {
		return Descriptor{}, nil, &errs.Joined{Lead: ErrEncodingFailed, Cause: err}
	}
	descriptor := Descriptor{
		MediaType:    manifest.MediaType,
		Digest:       sha256Digest(data),
		Size:         int64(len(data)),
		ArtifactType: manifest.ArtifactType,
	}
	if reference == "" {
		reference = descriptor.Digest
	}
	resp, err := c.do(ctx, &request{
		method:      http.MethodPut,
		url:         endpoint(ref, "manifests", reference),
		contentType: manifest.MediaType,
		body:        data,
		credentials: true,
	}, maxStatusBody)
	if err != nil {
		return Descriptor{}, nil, err
	}
	if err := expectStatus(resp, http.StatusCreated); err != nil {
		return Descriptor{}, nil, err
	}
	return descriptor, resp.header, nil
}

// do sends req as send does. When the registry answers 401 with a Bearer
// challenge, it fetches a token from the challenge's realm (the OCI
// distribution token flow) and sends req once more with it; the token is
// kept for the registry's later requests. A client given a bearer token
// sends that one only.
func (c *registryClient) do(ctx context.Context, req *request, limit int64) (*response, error) {
	resp, err := c.send(ctx, req, limit)
	if err != nil || resp.status != http.StatusUnauthorized || !req.credentials || c.staticToken() {
		return resp, err
	}
	ch, err := bearerChallenge(resp.header)
	if err != nil || ch == nil {
		return resp, err
	}
	token, err := c.fetchToken(ctx, ch)
	if err != nil {
		return nil, err
	}
	c.tokens.Store(req.url.Host, token)
	return c.send(ctx, req, limit)
}

// staticToken reports whether the client was given a bearer token.
func (c *registryClient) staticToken() bool {
	return c.auth != nil && c.auth.Token != ""
}

// send sends req, retrying 5xx answers and transport errors, and reads at
// most limit bytes of the answer.
func (c *registryClient) send(ctx context.Context, req *request, limit int64) (*response, error) {
	var resp *response
	err := qrdbsdk.RetryDo(ctx, c.retry, func(ctx context.Context) error {
		attempt, err := c.attempt(ctx, req, limit)
		if err != nil {
			return err
		}
		resp = attempt
		return nil
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// attempt sends req once.
func (c *registryClient) attempt(ctx context.Context, req *request, limit int64) (*response, error) {
	httpReq, err := http.NewRequestWithContext(ctx, req.method, req.url.String(), bytes.NewReader(req.body))
	if err != nil {
		return nil, &errs.Joined{Lead: ErrRegistryRequest, Cause: err}
	}
	httpReq.Header.Set("User-Agent", c.userAgent)
	if len(req.accept) > 0 {
		httpReq.Header.Set("Accept", strings.Join(req.accept, ", "))
	}
	if req.contentType != "" {
		httpReq.Header.Set("Content-Type", req.contentType)
	}
	switch {
	case req.realm:
		err = c.authorizeRealm(httpReq)
	case req.credentials:
		err = c.authorize(httpReq)
	}
	if err != nil {
		return nil, err
	}

	httpResp, err := c.http.Do(httpReq)
	if errors.Is(err, ErrRedirectRefused) {
		return nil, err
	}
	if err != nil {
		return nil, &errs.Joined{Lead: ErrRegistryUnavailable, Cause: err}
	}
	body, err := readBody(httpResp, limit)
	if err != nil {
		return nil, err
	}
	if httpResp.StatusCode >= http.StatusInternalServerError {
		return nil, &errs.Detail{Err: ErrRegistryUnavailable, Detail: req.method + " " + httpResp.Status}
	}
	return &response{method: req.method, status: httpResp.StatusCode, header: httpResp.Header, body: body}, nil
}

// authorize adds the client's credentials to req.
func (c *registryClient) authorize(req *http.Request) error {
	if c.staticToken() {
		req.Header.Set("Authorization", "Bearer "+c.auth.Token)
		return nil
	}
	if cached, ok := c.tokens.Load(req.URL.Host); ok {
		if token, ok := cached.(string); ok {
			req.Header.Set("Authorization", "Bearer "+token)
			return nil
		}
	}
	return c.authorizeRealm(req)
}

// authorizeRealm adds the client's basic credentials, if any, to req.
func (c *registryClient) authorizeRealm(req *http.Request) error {
	if c.auth == nil || c.auth.Username == "" {
		return nil
	}
	header, err := basicAuthorization(req.Context(), c.auth.Username, c.auth.Password)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", header)
	return nil
}

// basicAuthorization returns the Basic Authorization header value for
// username and password (RFC 7617). The password is opened only for the
// encoding, and the plaintext "username:password" copy is wiped before the
// function returns.
func basicAuthorization(ctx context.Context, username string, password *secure.Secret) (string, error) {
	if password == nil {
		return basicHeader([]byte(username + ":")), nil
	}
	plaintext, err := password.Open(ctx)
	if err != nil {
		return "", &errs.Joined{Lead: ErrRegistryCredentials, Cause: err}
	}
	defer plaintext.Destroy()

	var header string
	err = plaintext.WithBytes(func(secret []byte) error {
		credentials := make([]byte, 0, len(username)+1+len(secret))
		credentials = append(credentials, username...)
		credentials = append(credentials, ':')
		credentials = append(credentials, secret...)
		header = basicHeader(credentials)
		secure.Wipe(credentials)
		return nil
	})
	if err != nil {
		return "", &errs.Joined{Lead: ErrRegistryCredentials, Cause: err}
	}
	return header, nil
}

// basicHeader encodes credentials as a Basic Authorization header value.
func basicHeader(credentials []byte) string {
	return "Basic " + base64.StdEncoding.EncodeToString(credentials)
}

// readBody reads at most limit bytes of resp's body and closes it.
func readBody(resp *http.Response, limit int64) ([]byte, error) {
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	closeErr := resp.Body.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, &errs.Joined{Lead: ErrResponseRead, Cause: err}
	}
	if int64(len(body)) > limit {
		return nil, &errs.Detail{Err: ErrResponseTooLarge, Detail: "over " + strconv.FormatInt(limit, 10) + " bytes"}
	}
	return body, nil
}

// expectStatus returns statusError(resp) unless resp has status want.
func expectStatus(resp *response, want int) error {
	if resp.status == want {
		return nil
	}
	return statusError(resp)
}

// statusError returns the ErrRegistryRequest of an unexpected answer.
func statusError(resp *response) error {
	return &errs.Detail{
		Err:    ErrRegistryRequest,
		Detail: resp.method + " answered " + strconv.Itoa(resp.status) + " " + http.StatusText(resp.status),
	}
}

// endpoint returns the URL of a registry API path below ref's repository.
func endpoint(ref *Reference, parts ...string) *url.URL {
	host := ref.Registry
	if host == DefaultRegistry {
		host = dockerHubEndpoint
	}
	return &url.URL{
		Scheme: "https",
		Host:   host,
		Path:   "/v2/" + ref.Repository + "/" + strings.Join(parts, "/"),
	}
}

// validReference returns an error unless ref is a well-formed reference.
func validReference(ref *Reference) error {
	if ref == nil {
		return &errs.Detail{Err: ErrInvalidReference, Detail: "nil reference"}
	}
	return ref.Validate()
}
