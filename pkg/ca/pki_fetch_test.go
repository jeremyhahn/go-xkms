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
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/netguard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// allowLoopbackFetch lets ca's PKI fetches reach an httptest server. Every
// other limit of the production client still applies.
func allowLoopbackFetch(ca *CA) {
	ca.fetchClient = newPKIFetchClient(netguard.AllowAll)
}

// countingServer serves body with status and counts the requests it gets.
func countingServer(t *testing.T, status int, body []byte) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestCheckFetchURL(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{"http://pki.example.com/ca.crt", "https://pki.example.com/ca.crl"} {
		u, err := url.Parse(ok)
		require.NoError(t, err)
		assert.NoError(t, checkFetchURL(u), ok)
	}
	for _, bad := range []string{
		"ldap://ldap.example.com/cn=CA?cACertificate",
		"file:///etc/passwd",
		"ftp://pki.example.com/ca.crt",
		"http:///no-host",
		"http://user:pass@pki.example.com/ca.crt",
	} {
		u, err := url.Parse(bad)
		require.NoError(t, err)
		assert.ErrorIs(t, checkFetchURL(u), ErrPKIFetchRefused, bad)
	}
}

func TestFetchPKIObject_WithinLimit(t *testing.T) {
	t.Parallel()
	srv, _ := countingServer(t, http.StatusOK, []byte("0123456789"))
	ca := &CA{}
	allowLoopbackFetch(ca)

	body, err := ca.fetchPKIObject(context.Background(), srv.URL, 10)
	require.NoError(t, err)
	assert.Equal(t, []byte("0123456789"), body)
}

func TestFetchPKIObject_OversizedBodyRefused(t *testing.T) {
	t.Parallel()
	srv, _ := countingServer(t, http.StatusOK, []byte("0123456789A"))
	ca := &CA{}
	allowLoopbackFetch(ca)

	_, err := ca.fetchPKIObject(context.Background(), srv.URL, 10)
	assert.ErrorIs(t, err, ErrPKIFetchTooLarge)
}

func TestFetchPKIObject_LoopbackRefusedByDefault(t *testing.T) {
	t.Parallel()
	srv, hits := countingServer(t, http.StatusOK, []byte("x"))

	_, err := (&CA{}).fetchPKIObject(context.Background(), srv.URL, 10)
	assert.ErrorIs(t, err, ErrPKIFetchRefused)
	assert.Zero(t, hits.Load(), "a refused destination must never receive a request")
}

func TestFetchPKIObject_HostnameResolvingToLoopbackRefused(t *testing.T) {
	t.Parallel()
	srv, hits := countingServer(t, http.StatusOK, []byte("x"))
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	u.Host = "localhost:" + u.Port()

	_, err = (&CA{}).fetchPKIObject(context.Background(), u.String(), 10)
	assert.ErrorIs(t, err, ErrPKIFetchRefused)
	assert.Zero(t, hits.Load())
}

func TestFetchPKIObject_MetadataAddressRefused(t *testing.T) {
	t.Parallel()
	_, err := (&CA{}).fetchPKIObject(context.Background(), "http://169.254.169.254/latest/meta-data/", 10)
	assert.ErrorIs(t, err, ErrPKIFetchRefused)
}

func TestFetchPKIObject_NonHTTPSchemeRefused(t *testing.T) {
	t.Parallel()
	_, err := (&CA{}).fetchPKIObject(context.Background(), "file:///etc/passwd", 10)
	assert.ErrorIs(t, err, ErrPKIFetchRefused)

	_, err = (&CA{}).fetchPKIObject(context.Background(), "://bad", 10)
	assert.ErrorIs(t, err, ErrPKIFetchRefused)
}

func TestFetchPKIObject_RedirectLoopRefused(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, r.URL.Path, http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	ca := &CA{}
	allowLoopbackFetch(ca)

	_, err := ca.fetchPKIObject(context.Background(), srv.URL+"/loop", 10)
	assert.ErrorIs(t, err, ErrPKIFetchRefused)
	assert.EqualValues(t, maxPKIFetchRedirects, hits.Load())
}

func TestFetchPKIObject_RedirectToNonHTTPSchemeRefused(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "file:///etc/passwd", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	ca := &CA{}
	allowLoopbackFetch(ca)

	_, err := ca.fetchPKIObject(context.Background(), srv.URL, 10)
	assert.ErrorIs(t, err, ErrPKIFetchRefused)
}

func TestFetchPKIObject_Non200IsStorageError(t *testing.T) {
	t.Parallel()
	srv, _ := countingServer(t, http.StatusNotFound, nil)
	ca := &CA{}
	allowLoopbackFetch(ca)

	_, err := ca.fetchPKIObject(context.Background(), srv.URL, 10)
	assert.ErrorIs(t, err, ErrStorageError)
}

func TestImportDistributionCRLs_PrivateAddressRefused(t *testing.T) {
	t.Parallel()
	srv, hits := countingServer(t, http.StatusOK, []byte("crl"))
	ca := setupTestCAWithObjectStore(t)

	err := ca.ImportDistributionCRLs(&x509.Certificate{CRLDistributionPoints: []string{srv.URL + "/ca.crl"}})
	assert.ErrorIs(t, err, ErrPKIFetchRefused)
	assert.Zero(t, hits.Load())
}

func TestImportDistributionCRLs_OversizedCRLRefused(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.Copy(w, io.LimitReader(zeroReader{}, maxCRLBytes+1))
	}))
	t.Cleanup(srv.Close)
	ca := setupTestCAWithObjectStore(t)
	allowLoopbackFetch(ca)

	err := ca.ImportDistributionCRLs(&x509.Certificate{CRLDistributionPoints: []string{srv.URL + "/huge.crl"}})
	assert.ErrorIs(t, err, ErrPKIFetchTooLarge)
}

func TestImportDistributionCRLs_LDAPURLRefused(t *testing.T) {
	t.Parallel()
	ca := setupTestCAWithObjectStore(t)

	err := ca.ImportDistributionCRLs(&x509.Certificate{CRLDistributionPoints: []string{"ldap://ldap.example.com/cn=CA?certificateRevocationList"}})
	assert.ErrorIs(t, err, ErrPKIFetchRefused)
	assert.True(t, strings.Contains(err.Error(), "ldap"), "the refusal names the scheme")
}

// zeroReader yields an endless stream of zero bytes.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
