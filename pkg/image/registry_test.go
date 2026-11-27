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
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// pinned resolves ref and returns it pinned to its digest, with the
// image's descriptor.
func pinned(t *testing.T, client RegistryClient, ref string) (*Reference, *Descriptor) {
	t.Helper()
	reference, err := ParseReference(ref)
	require.NoError(t, err)
	subject, err := client.Resolve(context.Background(), reference)
	require.NoError(t, err)
	pinnedRef, err := reference.WithDigest(subject.Digest)
	require.NoError(t, err)
	return pinnedRef, subject
}

// push pushes an attestation with envelope to ref's image.
func push(t *testing.T, client RegistryClient, ref, envelope string) *PushResult {
	t.Helper()
	reference, subject := pinned(t, client, ref)
	result, err := client.PushAttestation(context.Background(), reference, subject, testAttestation(envelope))
	require.NoError(t, err)
	return result
}

func TestNewRegistryClient(t *testing.T) {
	client, err := NewRegistryClient(nil)
	require.NoError(t, err)
	require.NoError(t, client.Close())

	concrete, ok := client.(*registryClient)
	require.True(t, ok)
	assert.Equal(t, DefaultRegistryTimeout, concrete.http.Timeout)
	assert.Equal(t, DefaultUserAgent, concrete.userAgent)
	assert.Equal(t, DefaultRegistryRetries+1, concrete.retry.MaxAttempts)
}

func TestNewRegistryClient_InvalidOptions(t *testing.T) {
	for name, opts := range map[string]*RegistryOptions{
		"negative timeout": {Timeout: -time.Second},
		"negative retries": {MaxRetries: -1},
		"negative delay":   {RetryDelay: -time.Millisecond},
	} {
		t.Run(name, func(t *testing.T) {
			client, err := NewRegistryClient(opts)
			require.ErrorIs(t, err, ErrInvalidRegistryOptions)
			assert.Nil(t, client)
		})
	}
}

func TestRegistryClient_Resolve(t *testing.T) {
	registry := newTestRegistry(t, registryConfig{})
	client := registry.client(t, nil)
	ref, digest := registry.seedImage(t, "team/app", "v1")

	reference, err := ParseReference(ref)
	require.NoError(t, err)
	byTag, err := client.Resolve(context.Background(), reference)
	require.NoError(t, err)
	assert.Equal(t, digest, byTag.Digest)
	assert.Equal(t, MediaTypeOCIManifest, byTag.MediaType)
	assert.Equal(t, int64(len(registry.mustManifest("team/app", "v1").body)), byTag.Size)

	byDigest, err := client.Resolve(context.Background(), &Reference{Registry: registry.host(), Repository: "team/app", Digest: digest})
	require.NoError(t, err)
	assert.Equal(t, byTag, byDigest)
}

func TestRegistryClient_ResolveMediaTypeFromHeader(t *testing.T) {
	registry := newTestRegistry(t, registryConfig{})
	client := registry.client(t, nil)
	registry.storeRaw("team/app", "v1", mediaTypeDockerManifest+"; charset=utf-8", []byte(`{"schemaVersion":2}`))

	subject, err := client.Resolve(context.Background(), &Reference{Registry: registry.host(), Repository: "team/app", Tag: "v1"})
	require.NoError(t, err)
	assert.Equal(t, mediaTypeDockerManifest, subject.MediaType)
}

func TestRegistryClient_ResolveErrors(t *testing.T) {
	registry := newTestRegistry(t, registryConfig{})
	client := registry.client(t, &RegistryOptions{MaxRetries: 1})
	host := registry.host()
	registry.storeRaw("team/swapped", testSHA256, MediaTypeOCIManifest, []byte(`{"schemaVersion":2}`))
	registry.storeRaw("team/untyped", "v1", "", []byte(`{"schemaVersion":2}`))
	registry.storeRaw("team/garbage", "v1", MediaTypeOCIManifest, []byte(`not json`))
	registry.storeRaw("team/huge", "v1", MediaTypeOCIManifest, bytes.Repeat([]byte(" "), maxManifestSize+1))

	tests := []struct {
		name      string
		reference *Reference
		err       error
	}{
		{name: "nil reference", reference: nil, err: ErrInvalidReference},
		{name: "invalid reference", reference: &Reference{Registry: host, Repository: "UPPER", Tag: "v1"}, err: ErrInvalidReference},
		{name: "not found", reference: &Reference{Registry: host, Repository: "team/missing", Tag: "v1"}, err: ErrManifestNotFound},
		{name: "digest mismatch", reference: &Reference{Registry: host, Repository: "team/swapped", Digest: testSHA256}, err: ErrDigestMismatch},
		{name: "no media type", reference: &Reference{Registry: host, Repository: "team/untyped", Tag: "v1"}, err: ErrInvalidManifest},
		{name: "not json", reference: &Reference{Registry: host, Repository: "team/garbage", Tag: "v1"}, err: ErrInvalidManifest},
		{name: "too large", reference: &Reference{Registry: host, Repository: "team/huge", Tag: "v1"}, err: ErrResponseTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subject, err := client.Resolve(context.Background(), tt.reference)
			require.ErrorIs(t, err, tt.err)
			assert.Nil(t, subject)
		})
	}
}

func TestRegistryClient_Retries(t *testing.T) {
	registry := newTestRegistry(t, registryConfig{})
	client := registry.client(t, &RegistryOptions{MaxRetries: 2})
	ref, digest := registry.seedImage(t, "team/app", "v1")
	reference, err := ParseReference(ref)
	require.NoError(t, err)

	registry.unavailable.Store(2)
	subject, err := client.Resolve(context.Background(), reference)
	require.NoError(t, err, "two failures are retried")
	assert.Equal(t, digest, subject.Digest)

	registry.unavailable.Store(3)
	subject, err = client.Resolve(context.Background(), reference)
	require.ErrorIs(t, err, ErrRegistryUnavailable, "the retries are exhausted")
	assert.Nil(t, subject)
	assert.Zero(t, registry.unavailable.Load())
}

func TestRegistryClient_Unreachable(t *testing.T) {
	registry := newTestRegistry(t, registryConfig{})
	client := registry.client(t, &RegistryOptions{MaxRetries: 1})
	host := registry.host()
	registry.server.Close()

	subject, err := client.Resolve(context.Background(), &Reference{Registry: host, Repository: "team/app", Tag: "v1"})
	require.ErrorIs(t, err, ErrRegistryUnavailable)
	assert.Nil(t, subject)
}

func TestRegistryClient_CanceledContext(t *testing.T) {
	registry := newTestRegistry(t, registryConfig{})
	client := registry.client(t, &RegistryOptions{RetryDelay: time.Hour})
	ref, _ := registry.seedImage(t, "team/app", "v1")
	reference, err := ParseReference(ref)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	subject, err := client.Resolve(ctx, reference)
	require.ErrorIs(t, err, context.Canceled, "a canceled request is not retried for an hour")
	assert.Nil(t, subject)
}

func TestRegistryClient_BearerToken(t *testing.T) {
	registry := newTestRegistry(t, registryConfig{token: "secret"})
	ref, _ := registry.seedImage(t, "team/app", "v1")

	authorized := registry.client(t, &RegistryOptions{Auth: &RegistryAuth{Token: "secret"}})
	result := push(t, authorized, ref, "{}")
	assert.NotEmpty(t, result.AttestationTag)

	reference, err := ParseReference(ref)
	require.NoError(t, err)
	for name, auth := range map[string]*RegistryAuth{
		"anonymous":   nil,
		"wrong token": {Token: "guess"},
	} {
		t.Run(name, func(t *testing.T) {
			client := registry.client(t, &RegistryOptions{Auth: auth})
			subject, err := client.Resolve(context.Background(), reference)
			require.ErrorIs(t, err, ErrRegistryRequest)
			assert.Nil(t, subject)
		})
	}
}

func TestRegistryClient_TokenFlow(t *testing.T) {
	tests := map[string]struct {
		config registryConfig
		auth   *RegistryAuth
	}{
		"anonymous":         {config: registryConfig{token: "issued", challenge: true}},
		"basic credentials": {config: registryConfig{token: "issued", challenge: true, username: "u", password: "p"}, auth: &RegistryAuth{Username: "u", Password: registryPassword(t, "p")}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			registry := newTestRegistry(t, tt.config)
			ref, _ := registry.seedImage(t, "team/app", "v1")
			client := registry.client(t, &RegistryOptions{Auth: tt.auth})

			result := push(t, client, ref, "{}")
			assert.NotEmpty(t, result.AttestationTag)
			reference, _ := pinned(t, client, ref)
			attestations, err := client.Attestations(context.Background(), reference)
			require.NoError(t, err)
			assert.Len(t, attestations, 1)
			assert.Equal(t, int32(1), registry.tokensIssued.Load(), "the issued token is reused")
		})
	}
}

func TestRegistryClient_TokenFlowRefused(t *testing.T) {
	registry := newTestRegistry(t, registryConfig{token: "issued", challenge: true, username: "u", password: "p"})
	ref, _ := registry.seedImage(t, "team/app", "v1")
	reference, err := ParseReference(ref)
	require.NoError(t, err)

	for name, auth := range map[string]*RegistryAuth{
		"anonymous":      nil,
		"wrong password": {Username: "u", Password: registryPassword(t, "guess")},
	} {
		t.Run(name, func(t *testing.T) {
			client := registry.client(t, &RegistryOptions{Auth: auth})
			subject, err := client.Resolve(context.Background(), reference)
			require.ErrorIs(t, err, ErrRegistryAuth)
			assert.Nil(t, subject)
		})
	}
	assert.Zero(t, registry.tokensIssued.Load())
}

func TestRegistryClient_Authorize(t *testing.T) {
	tests := []struct {
		name     string
		auth     *RegistryAuth
		expected string
	}{
		{name: "anonymous", auth: nil, expected: ""},
		{name: "empty", auth: &RegistryAuth{}, expected: ""},
		{name: "token", auth: &RegistryAuth{Token: "t", Username: "u", Password: registryPassword(t, "p")}, expected: "Bearer t"},
		{name: "basic", auth: &RegistryAuth{Username: "u", Password: registryPassword(t, "p")}, expected: "Basic dTpw"},
		{name: "username only", auth: &RegistryAuth{Username: "u"}, expected: "Basic dTo="},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewRegistryClient(&RegistryOptions{Auth: tt.auth})
			require.NoError(t, err)
			concrete, ok := client.(*registryClient)
			require.True(t, ok)

			req := httptest.NewRequest(http.MethodGet, "https://registry.example/v2/", nil)
			require.NoError(t, concrete.authorize(req))
			assert.Equal(t, tt.expected, req.Header.Get("Authorization"))
		})
	}
}

func TestRegistryClient_DestroyedPasswordStopsTheRequest(t *testing.T) {
	registry := newTestRegistry(t, registryConfig{token: "issued", challenge: true, username: "u", password: "p"})
	ref, _ := registry.seedImage(t, "team/app", "v1")
	reference, err := ParseReference(ref)
	require.NoError(t, err)

	password := registryPassword(t, "p")
	password.Destroy()
	client := registry.client(t, &RegistryOptions{Auth: &RegistryAuth{Username: "u", Password: password}})
	subject, err := client.Resolve(context.Background(), reference)
	require.ErrorIs(t, err, ErrRegistryCredentials)
	assert.Nil(t, subject)
	assert.Zero(t, registry.tokensIssued.Load())
}

// registryPassword seals password into a Secret destroyed when t ends.
func registryPassword(t *testing.T, password string) *secure.Secret {
	t.Helper()
	secret, err := secure.NewSecret(t.Context(), []byte(password))
	require.NoError(t, err)
	t.Cleanup(secret.Destroy)
	return secret
}

func TestRegistryClient_PushAttestation(t *testing.T) {
	registry := newTestRegistry(t, registryConfig{referrers: true})
	client := registry.client(t, nil)
	ref, digest := registry.seedImage(t, "team/app", "v1")

	result := push(t, client, ref, `{"n":1}`)
	assert.True(t, result.ReferrerIndexed)
	assert.Equal(t, ArtifactTypeAttestation, result.Referrer.ArtifactType)
	assert.Equal(t, MediaTypeOCIManifest, result.Referrer.MediaType)
	reference, err := ParseReference(ref)
	require.NoError(t, err)
	pinnedRef, err := reference.WithDigest(digest)
	require.NoError(t, err)
	tag, err := pinnedRef.AttestationTag()
	require.NoError(t, err)
	assert.Equal(t, tag, result.AttestationTag)

	var referrer Manifest
	require.NoError(t, json.Unmarshal(registry.mustManifest("team/app", result.Referrer.Digest).body, &referrer))
	require.NotNil(t, referrer.Subject)
	assert.Equal(t, digest, referrer.Subject.Digest)
	assert.Equal(t, ArtifactTypeAttestation, referrer.ArtifactType)

	var attestations Manifest
	require.NoError(t, json.Unmarshal(registry.mustManifest("team/app", tag).body, &attestations))
	require.Len(t, attestations.Layers, 1)
	assert.Equal(t, sha256Digest([]byte(`{"n":1}`)), attestations.Layers[0].Digest)
	assert.Nil(t, attestations.Subject, "the .att tag manifest has no subject")

	registry.mu.Lock()
	envelope := registry.blobs["team/app@"+attestations.Layers[0].Digest]
	_, hasEmpty := registry.blobs["team/app@"+sha256Digest(emptyJSON)]
	_, hasConfig := registry.blobs["team/app@"+attestations.Config.Digest]
	registry.mu.Unlock()
	assert.Equal(t, []byte(`{"n":1}`), envelope)
	assert.True(t, hasEmpty)
	assert.True(t, hasConfig)

	second := push(t, client, ref, `{"n":2}`)
	require.NoError(t, json.Unmarshal(registry.mustManifest("team/app", tag).body, &attestations))
	assert.Len(t, attestations.Layers, 2, "the .att tag accumulates attestations")
	assert.NotEqual(t, result.Referrer.Digest, second.Referrer.Digest)
}

func TestRegistryClient_PushAttestationWithoutReferrers(t *testing.T) {
	registry := newTestRegistry(t, registryConfig{})
	client := registry.client(t, nil)
	ref, _ := registry.seedImage(t, "team/app", "v1")

	result := push(t, client, ref, "{}")
	assert.False(t, result.ReferrerIndexed)
	_, stored := registry.manifest("team/app", result.Referrer.Digest)
	assert.True(t, stored, "the referrer manifest is pushed even when the registry does not index it")
}

func TestRegistryClient_PushAttestationReusesBlobs(t *testing.T) {
	registry := newTestRegistry(t, registryConfig{})
	client := registry.client(t, nil)
	ref, _ := registry.seedImage(t, "team/app", "v1")

	first := push(t, client, ref, `{"n":1}`)
	registry.mu.Lock()
	uploads := registry.uploads
	registry.mu.Unlock()
	assert.Equal(t, 3, uploads, "envelope, empty config and .att config")

	second := push(t, client, ref, `{"n":1}`)
	registry.mu.Lock()
	assert.Equal(t, uploads, registry.uploads, "blobs the registry has are not uploaded again")
	registry.mu.Unlock()
	assert.Equal(t, first, second)
}

func TestRegistryClient_PushAttestationErrors(t *testing.T) {
	registry := newTestRegistry(t, registryConfig{})
	client := registry.client(t, nil)
	ref, _ := registry.seedImage(t, "team/app", "v1")
	reference, subject := pinned(t, client, ref)
	unpinned := &Reference{Registry: reference.Registry, Repository: reference.Repository, Tag: "v1"}
	other := &Descriptor{MediaType: MediaTypeOCIManifest, Digest: testSHA256}

	tests := []struct {
		name        string
		reference   *Reference
		subject     *Descriptor
		attestation *Attestation
		err         error
	}{
		{name: "nil reference", reference: nil, subject: subject, attestation: testAttestation("{}"), err: ErrInvalidReference},
		{name: "no digest", reference: unpinned, subject: subject, attestation: testAttestation("{}"), err: ErrDigestRequired},
		{name: "nil subject", reference: reference, subject: nil, attestation: testAttestation("{}"), err: ErrSubjectRequired},
		{name: "other subject", reference: reference, subject: other, attestation: testAttestation("{}"), err: ErrDigestMismatch},
		{name: "nil attestation", reference: reference, subject: subject, attestation: nil, err: ErrInvalidAttestation},
		{name: "no envelope", reference: reference, subject: subject, attestation: testAttestation(""), err: ErrInvalidAttestation},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := client.PushAttestation(context.Background(), tt.reference, tt.subject, tt.attestation)
			require.ErrorIs(t, err, tt.err)
			assert.Nil(t, result)
		})
	}
}

func TestRegistryClient_PushAttestationRefused(t *testing.T) {
	registry := newTestRegistry(t, registryConfig{token: "secret"})
	ref, _ := registry.seedImage(t, "team/app", "v1")
	reference, subject := pinned(t, registry.client(t, &RegistryOptions{Auth: &RegistryAuth{Token: "secret"}}), ref)

	result, err := registry.client(t, nil).PushAttestation(context.Background(), reference, subject, testAttestation("{}"))
	require.ErrorIs(t, err, ErrRegistryRequest)
	assert.Nil(t, result)
}

func TestRegistryClient_PushAttestationInsecureUploadLocation(t *testing.T) {
	registry := newTestRegistry(t, registryConfig{uploadLocation: "http://127.0.0.1:1/upload"})
	client := registry.client(t, nil)
	ref, _ := registry.seedImage(t, "team/app", "v1")
	reference, subject := pinned(t, client, ref)

	result, err := client.PushAttestation(context.Background(), reference, subject, testAttestation("{}"))
	require.ErrorIs(t, err, ErrInvalidUploadLocation)
	assert.Nil(t, result)
}

func TestRegistryClient_UploadElsewhereWithoutCredentials(t *testing.T) {
	var uploads, credentialed atomic.Int32
	storage := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		uploads.Add(1)
		if req.Header.Get("Authorization") != "" {
			credentialed.Add(1)
		}
		if _, err := io.Copy(io.Discard, req.Body); err != nil {
			t.Errorf("read upload: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	storage.StartTLS()
	t.Cleanup(storage.Close)

	registry := newTestRegistry(t, registryConfig{token: "secret", uploadLocation: storage.URL + "/upload?state=open"})
	client := registry.client(t, &RegistryOptions{Auth: &RegistryAuth{Token: "secret"}})
	ref, _ := registry.seedImage(t, "team/app", "v1")

	push(t, client, ref, `{"n":1}`)
	assert.Equal(t, int32(3), uploads.Load())
	assert.Zero(t, credentialed.Load(), "registry credentials never reach another host")
}

// redirectFixture is a TLS registry that redirects every request outside
// /moved/ to target and serves /moved/ with moved, and the client of it
// holding a bearer token.
type redirectFixture struct {
	client    RegistryClient
	reference *Reference
	requests  atomic.Int32
}

func newRedirectFixture(t *testing.T, target func(req *http.Request) string, moved http.HandlerFunc) *redirectFixture {
	t.Helper()
	f := &redirectFixture{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.HasPrefix(req.URL.Path, "/moved/") {
			moved(w, req)
			return
		}
		f.requests.Add(1)
		http.Redirect(w, req, target(req), http.StatusTemporaryRedirect)
	}))
	t.Cleanup(server.Close)

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client, err := NewRegistryClient(&RegistryOptions{RootCAs: roots, Auth: &RegistryAuth{Token: "secret"}, RetryDelay: time.Millisecond})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	f.client = client

	f.reference, err = ParseReference(strings.TrimPrefix(server.URL, "https://") + "/team/app:v1")
	require.NoError(t, err)
	return f
}

// manifestHandler serves a manifest, counting the requests it answers and
// those that carried the fixture's token.
func manifestHandler(served, credentialed *atomic.Int32) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		served.Add(1)
		if req.Header.Get("Authorization") == "Bearer secret" {
			credentialed.Add(1)
		}
		w.Header().Set("Content-Type", MediaTypeOCIManifest)
		if _, err := io.WriteString(w, `{"schemaVersion":2,"mediaType":"`+MediaTypeOCIManifest+`"}`); err != nil {
			panic(err)
		}
	}
}

func TestRegistryClient_RedirectToHTTPRefused(t *testing.T) {
	var served, credentialed atomic.Int32
	plain := httptest.NewServer(manifestHandler(&served, &credentialed))
	t.Cleanup(plain.Close)
	f := newRedirectFixture(t, func(req *http.Request) string { return plain.URL + req.URL.Path }, nil)

	subject, err := f.client.Resolve(context.Background(), f.reference)
	require.ErrorIs(t, err, ErrRedirectRefused)
	assert.Nil(t, subject)
	assert.Zero(t, served.Load(), "the plaintext destination is never asked")
	assert.Zero(t, credentialed.Load(), "no credential leaves in plaintext")
	assert.Equal(t, int32(1), f.requests.Load(), "a refused redirect is not retried")
}

func TestRegistryClient_RedirectSameHost(t *testing.T) {
	var served, credentialed atomic.Int32
	f := newRedirectFixture(t, func(req *http.Request) string { return "/moved" + req.URL.Path }, manifestHandler(&served, &credentialed))

	subject, err := f.client.Resolve(context.Background(), f.reference)
	require.NoError(t, err)
	assert.Equal(t, MediaTypeOCIManifest, subject.MediaType)
	assert.Equal(t, int32(1), served.Load())
	assert.Equal(t, int32(1), credentialed.Load(), "the same host keeps the credentials")
}

func TestRegistryClient_RedirectElsewhereWithoutCredentials(t *testing.T) {
	var served, credentialed atomic.Int32
	// httptest's TLS servers share one certificate, so the client trusts
	// storage as it trusts the registry.
	storage := httptest.NewTLSServer(manifestHandler(&served, &credentialed))
	t.Cleanup(storage.Close)
	f := newRedirectFixture(t, func(req *http.Request) string { return storage.URL + req.URL.Path }, nil)

	subject, err := f.client.Resolve(context.Background(), f.reference)
	require.NoError(t, err)
	assert.NotNil(t, subject)
	assert.Equal(t, int32(1), served.Load())
	assert.Zero(t, credentialed.Load(), "registry credentials never reach another host")
}

func TestUploadLocation(t *testing.T) {
	uploads := &url.URL{Scheme: "https", Host: "registry.example", Path: "/v2/team/app/blobs/uploads/"}
	digest := sha256Digest([]byte("blob"))

	relative, err := uploadLocation(uploads, "/v2/team/app/blobs/uploads/s1?state=abc", digest)
	require.NoError(t, err)
	assert.Equal(t, "registry.example", relative.Host)
	assert.Equal(t, "/v2/team/app/blobs/uploads/s1", relative.Path)
	assert.Equal(t, url.Values{"state": {"abc"}, "digest": {digest}}, relative.Query())

	absolute, err := uploadLocation(uploads, "https://storage.example/u?sig=x", digest)
	require.NoError(t, err)
	assert.Equal(t, "storage.example", absolute.Host)
	assert.Equal(t, url.Values{"sig": {"x"}, "digest": {digest}}, absolute.Query())
}

func TestUploadLocation_Invalid(t *testing.T) {
	uploads := &url.URL{Scheme: "https", Host: "registry.example", Path: "/v2/team/app/blobs/uploads/"}
	for name, location := range map[string]string{
		"missing":   "",
		"malformed": "https://registry.example/%zz",
		"plaintext": "http://registry.example/upload",
		"file":      "file:///etc/passwd",
	} {
		t.Run(name, func(t *testing.T) {
			resolved, err := uploadLocation(uploads, location, testSHA256)
			require.ErrorIs(t, err, ErrInvalidUploadLocation)
			assert.Nil(t, resolved)
		})
	}
}

func TestRegistryClient_Attestations(t *testing.T) {
	for name, referrers := range map[string]bool{"referrers": true, "attestation tag": false} {
		t.Run(name, func(t *testing.T) {
			registry := newTestRegistry(t, registryConfig{referrers: referrers})
			client := registry.client(t, nil)
			ref, _ := registry.seedImage(t, "team/app", "v1")
			push(t, client, ref, `{"n":1}`)
			push(t, client, ref, `{"n":2}`)

			reference, _ := pinned(t, client, ref)
			attestations, err := client.Attestations(context.Background(), reference)
			require.NoError(t, err)
			require.Len(t, attestations, 2)
			assert.Equal(t, testAttestation(`{"n":1}`), attestations[0])
			assert.Equal(t, testAttestation(`{"n":2}`), attestations[1])
		})
	}
}

func TestRegistryClient_AttestationsFallBackToTag(t *testing.T) {
	registry := newTestRegistry(t, registryConfig{referrers: true})
	client := registry.client(t, nil)
	ref, _ := registry.seedImage(t, "team/app", "v1")
	push(t, client, ref, "{}")

	// A registry that lost its referrers index, or an attestation pushed by
	// a cosign release that writes only the .att tag.
	registry.mu.Lock()
	clear(registry.referring)
	registry.mu.Unlock()

	reference, _ := pinned(t, client, ref)
	attestations, err := client.Attestations(context.Background(), reference)
	require.NoError(t, err)
	assert.Equal(t, []*Attestation{testAttestation("{}")}, attestations)
}

func TestRegistryClient_AttestationsFilterReferrers(t *testing.T) {
	registry := newTestRegistry(t, registryConfig{referrers: true})
	client := registry.client(t, nil)
	ref, digest := registry.seedImage(t, "team/app", "v1")
	registry.addReferrer("team/app", digest, Descriptor{
		MediaType:    MediaTypeOCIManifest,
		Digest:       testSHA256,
		ArtifactType: "application/spdx+json",
	})
	push(t, client, ref, "{}")

	reference, _ := pinned(t, client, ref)
	attestations, err := client.Attestations(context.Background(), reference)
	require.NoError(t, err, "a referrer of another artifact type is never fetched")
	assert.Len(t, attestations, 1)
}

func TestRegistryClient_AttestationsPagedReferrers(t *testing.T) {
	registry := newTestRegistry(t, registryConfig{referrers: true, referrersPage: 1})
	client := registry.client(t, nil)
	ref, _ := registry.seedImage(t, "team/app", "v1")
	push(t, client, ref, `{"n":1}`)
	push(t, client, ref, `{"n":2}`)
	push(t, client, ref, `{"n":3}`)

	reference, _ := pinned(t, client, ref)
	attestations, err := client.Attestations(context.Background(), reference)
	require.NoError(t, err)
	assert.Equal(t, []*Attestation{
		testAttestation(`{"n":1}`), testAttestation(`{"n":2}`), testAttestation(`{"n":3}`),
	}, attestations, "every page of the referrers index is read")
}

func TestRegistryClient_AttestationsReferrersBadLink(t *testing.T) {
	for name, link := range map[string]func(host, digest string) string{
		"no angle brackets": func(string, string) string { return `/v2/team/app/referrers; rel="next"` },
		"unterminated":      func(string, string) string { return `</v2/team/app/referrers; rel="next"` },
		"another host": func(string, string) string {
			return `<https://elsewhere.example/v2/team/app/referrers>; rel="next"`
		},
		"plain http": func(host, digest string) string {
			return `<http://` + host + `/v2/team/app/referrers/` + digest + `>; rel="next"`
		},
		"endless next pages": func(_, digest string) string {
			return `</v2/team/app/referrers/` + digest + `>; rel="next"`
		},
	} {
		t.Run(name, func(t *testing.T) {
			registry := newTestRegistry(t, registryConfig{referrers: true})
			client := registry.client(t, nil)
			ref, digest := registry.seedImage(t, "team/app", "v1")
			push(t, client, ref, "{}")
			registry.mu.Lock()
			registry.config.referrersLink = link(strings.TrimPrefix(registry.server.URL, "https://"), digest)
			registry.mu.Unlock()

			reference, _ := pinned(t, client, ref)
			attestations, err := client.Attestations(context.Background(), reference)
			require.ErrorIs(t, err, ErrInvalidManifest)
			assert.Nil(t, attestations)
		})
	}
}

func TestNextPage(t *testing.T) {
	target := mustURL(t, "https://registry.example/v2/team/app/referrers/sha256:a?artifactType=x")
	tests := map[string]struct {
		values []string
		want   string
	}{
		"relative":       {values: []string{`</v2/team/app/referrers/sha256:a?last=b>; rel="next"`}, want: "https://registry.example/v2/team/app/referrers/sha256:a?last=b"},
		"absolute":       {values: []string{`<https://registry.example/next>; rel=next`}, want: "https://registry.example/next"},
		"relation list":  {values: []string{`</next>; rel="prev next"`}, want: "https://registry.example/next"},
		"second link":    {values: []string{`</prev>; rel="prev"; title="a, <b>", </next>; REL="next"`}, want: "https://registry.example/next"},
		"second value":   {values: []string{`</prev>; rel="prev"`, `</next>; rel="next"`}, want: "https://registry.example/next"},
		"no next link":   {values: []string{`</prev>; rel="prev"`}},
		"no Link header": {},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			header := http.Header{}
			for _, value := range tt.values {
				header.Add("Link", value)
			}
			next, err := nextPage(target, header)
			require.NoError(t, err)
			if tt.want == "" {
				assert.Nil(t, next)
				return
			}
			assert.Equal(t, tt.want, next.String())
		})
	}
}

func TestNextPage_Invalid(t *testing.T) {
	target := mustURL(t, "https://registry.example/v2/team/app/referrers/sha256:a")
	for name, value := range map[string]string{
		"no angle brackets": `/next; rel="next"`,
		"unterminated":      `</next; rel="next"`,
		"unparseable":       `<%zz>; rel="next"`,
		"another host":      `<https://elsewhere.example/next>; rel="next"`,
		"another port":      `<https://registry.example:8443/next>; rel="next"`,
		"plain http":        `<http://registry.example/next>; rel="next"`,
	} {
		t.Run(name, func(t *testing.T) {
			next, err := nextPage(target, http.Header{"Link": {value}})
			require.ErrorIs(t, err, ErrInvalidManifest)
			assert.Nil(t, next)
		})
	}
}

func TestRegistryClient_AttestationsErrors(t *testing.T) {
	registry := newTestRegistry(t, registryConfig{})
	client := registry.client(t, nil)
	ref, digest := registry.seedImage(t, "team/app", "v1")
	reference, _ := pinned(t, client, ref)

	attestations, err := client.Attestations(context.Background(), reference)
	require.ErrorIs(t, err, ErrNoAttestation, "an unsigned image")
	assert.Nil(t, attestations)

	attestations, err = client.Attestations(context.Background(), nil)
	require.ErrorIs(t, err, ErrInvalidReference)
	assert.Nil(t, attestations)

	attestations, err = client.Attestations(context.Background(), &Reference{Registry: reference.Registry, Repository: "team/app", Tag: "v1"})
	require.ErrorIs(t, err, ErrDigestRequired)
	assert.Nil(t, attestations)

	tag, err := reference.AttestationTag()
	require.NoError(t, err)
	unrelated, err := json.Marshal(Manifest{SchemaVersion: 2, MediaType: MediaTypeOCIManifest, Layers: []Descriptor{
		{MediaType: "application/vnd.dev.cosign.simplesigning.v1+json", Digest: digest},
	}})
	require.NoError(t, err)
	registry.storeRaw("team/app", tag, MediaTypeOCIManifest, unrelated)
	attestations, err = client.Attestations(context.Background(), reference)
	require.ErrorIs(t, err, ErrNoAttestation, "an .att tag without DSSE layers")
	assert.Nil(t, attestations)
}

func TestRegistryClient_AttestationsTamperedBlob(t *testing.T) {
	registry := newTestRegistry(t, registryConfig{})
	client := registry.client(t, nil)
	ref, _ := registry.seedImage(t, "team/app", "v1")
	push(t, client, ref, `{"n":1}`)

	registry.mu.Lock()
	registry.blobs["team/app@"+sha256Digest([]byte(`{"n":1}`))] = []byte(`{"n":2}`)
	registry.mu.Unlock()

	reference, _ := pinned(t, client, ref)
	attestations, err := client.Attestations(context.Background(), reference)
	require.ErrorIs(t, err, ErrDigestMismatch)
	assert.Nil(t, attestations)
}

func TestRetryable(t *testing.T) {
	assert.True(t, retryable(&errs.Detail{Err: ErrRegistryUnavailable, Detail: "GET 503"}))
	assert.False(t, retryable(&errs.Joined{Lead: ErrRegistryUnavailable, Cause: context.Canceled}))
	assert.False(t, retryable(&errs.Joined{Lead: ErrRegistryUnavailable, Cause: context.DeadlineExceeded}))
	assert.False(t, retryable(&errs.Detail{Err: ErrRegistryRequest, Detail: "GET answered 404"}))
}

func TestEndpoint(t *testing.T) {
	hub := endpoint(&Reference{Registry: DefaultRegistry, Repository: "library/nginx"}, "manifests", "latest")
	assert.Equal(t, "https://registry-1.docker.io/v2/library/nginx/manifests/latest", hub.String())

	private := endpoint(&Reference{Registry: "localhost:5000", Repository: "team/app"}, "blobs", "uploads", "")
	assert.Equal(t, "https://localhost:5000/v2/team/app/blobs/uploads/", private.String())
}
