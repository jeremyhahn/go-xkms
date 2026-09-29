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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/netguard"
)

// Limits on fetching the PKI objects certificate extensions point at. The
// URLs come from certificates this CA did not issue, so each fetch is
// attacker-directed: the destination is filtered and the response bounded.
const (
	// maxAIACertificateBytes bounds an AIA caIssuers response. It holds one
	// certificate; even a hybrid post-quantum certificate in PEM is a small
	// fraction of this.
	maxAIACertificateBytes = 64 << 10

	// maxCRLBytes bounds a CRL distribution point response. Large public
	// CAs publish CRLs of several megabytes.
	maxCRLBytes = 32 << 20

	// maxAIADepth bounds how many issuers an AIA walk fetches above the
	// starting certificate before it must reach a self-signed root.
	maxAIADepth = 5

	// maxPKIFetchRedirects bounds the redirects a single fetch follows.
	maxPKIFetchRedirects = 3

	// pkiFetchTimeout bounds a whole fetch, body included.
	pkiFetchTimeout = 30 * time.Second
)

// pkiFetchClient is the client every AIA and CRL distribution point fetch
// uses unless a test injects CA.fetchClient. It dials only addresses
// netguard.DenyReserved accepts: the check runs in the dialer's Control
// hook, after DNS resolution and on every connection, so neither a
// hostname that resolves to a reserved address, a DNS rebind, nor a
// redirect reaches an internal service.
var pkiFetchClient = newPKIFetchClient(nil)

// newPKIFetchClient returns an HTTP client for PKI object fetches whose
// dialer accepts only addresses allow permits. A nil allow defaults to
// netguard.DenyReserved.
func newPKIFetchClient(allow netguard.AllowFunc) *http.Client {
	return &http.Client{
		Timeout: pkiFetchTimeout,
		Transport: netguard.GuardedTransport(netguard.TransportConfig{
			Allow:                  allow,
			DialTimeout:            10 * time.Second,
			TLSHandshakeTimeout:    10 * time.Second,
			ResponseHeaderTimeout:  15 * time.Second,
			MaxResponseHeaderBytes: 64 << 10,
			ForceAttemptHTTP2:      true,
		}),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxPKIFetchRedirects {
				return &errs.Detail{Err: ErrPKIFetchRefused, Detail: fmt.Sprintf("more than %d redirects", maxPKIFetchRedirects)}
			}
			return checkFetchURL(req.URL)
		},
	}
}

// checkFetchURL refuses a URL that is not an absolute http or https URL
// with a host. AIA and CRL distribution point URLs may name ldap, ftp or
// file resources; none of them is fetched.
func checkFetchURL(u *url.URL) error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return &errs.Detail{Err: ErrPKIFetchRefused, Detail: fmt.Sprintf("unsupported scheme %q", u.Scheme)}
	}
	if u.Hostname() == "" {
		return &errs.Detail{Err: ErrPKIFetchRefused, Detail: "url has no host"}
	}
	if u.User != nil {
		return &errs.Detail{Err: ErrPKIFetchRefused, Detail: "url carries credentials"}
	}
	return nil
}

// httpFetchClient returns the client PKI object fetches use.
func (ca *CA) httpFetchClient() *http.Client {
	if ca.fetchClient != nil {
		return ca.fetchClient
	}
	return pkiFetchClient
}

// fetchPKIObject downloads rawURL and returns its body, refusing a URL
// checkFetchURL rejects, a destination the client will not dial, a non-200
// status, and a body longer than limit bytes. A refusal wraps
// ErrPKIFetchRefused, an oversized body ErrPKIFetchTooLarge, and any other
// failure ErrStorageError.
func (ca *CA) fetchPKIObject(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, &errs.Detail{Err: ErrPKIFetchRefused, Detail: fmt.Sprintf("unparseable url %q: %v", rawURL, err)}
	}
	if err := checkFetchURL(u); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("failed to build request %s: %v", rawURL, err)}
	}
	resp, err := ca.httpFetchClient().Do(req)
	if err != nil {
		var refused *netguard.AddressNotPermittedError
		if errors.As(err, &refused) || errors.Is(err, ErrPKIFetchRefused) {
			return nil, &errs.Detail{Err: ErrPKIFetchRefused, Detail: fmt.Sprintf("%s: %v", rawURL, err)}
		}
		return nil, &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("failed to download %s: %v", rawURL, err)}
	}

	// netguard.ReadLimited reads one byte past limit so an exactly-full
	// body is accepted and anything longer is detected without buffering
	// the rest.
	body, readErr := netguard.ReadLimited(resp.Body, limit)
	closeErr := resp.Body.Close()

	var fetchErr error
	switch {
	case readErr != nil:
		var tooLarge *netguard.ResponseTooLargeError
		if errors.As(readErr, &tooLarge) {
			fetchErr = &errs.Detail{Err: ErrPKIFetchTooLarge, Detail: fmt.Sprintf("%s exceeds %d bytes", rawURL, limit)}
		} else {
			fetchErr = &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("failed to read %s: %v", rawURL, readErr)}
		}
	case resp.StatusCode != http.StatusOK:
		fetchErr = &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("download %s returned status %d", rawURL, resp.StatusCode)}
	}
	if fetchErr != nil {
		return nil, errors.Join(fetchErr, closeErr)
	}
	if closeErr != nil {
		return nil, &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("failed to close response body for %s: %v", rawURL, closeErr)}
	}
	return body, nil
}
