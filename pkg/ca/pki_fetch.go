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
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
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
// uses unless a test injects CA.fetchClient. It dials only public unicast
// addresses: the check runs in the dialer's Control hook, after DNS
// resolution and on every connection, so neither a hostname that resolves
// to a private address, a DNS rebind, nor a redirect reaches an internal
// service.
//
// TODO(#1172): the ACME http-01/enroll-01 validators need the same dialer;
// consolidate into one shared package when that lands.
var pkiFetchClient = newPKIFetchClient(isPublicAddress)

// newPKIFetchClient returns an HTTP client for PKI object fetches that dials
// only addresses allowed accepts. It never uses a proxy: a proxy would dial
// on the client's behalf and bypass the address check.
func newPKIFetchClient(allowed func(netip.Addr) bool) *http.Client {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			return checkDialAddress(address, allowed)
		},
	}
	return &http.Client{
		Timeout: pkiFetchTimeout,
		Transport: &http.Transport{
			Proxy:                  nil,
			DialContext:            dialer.DialContext,
			TLSHandshakeTimeout:    10 * time.Second,
			ResponseHeaderTimeout:  15 * time.Second,
			MaxResponseHeaderBytes: 64 << 10,
			ForceAttemptHTTP2:      true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxPKIFetchRedirects {
				return &errs.Detail{Err: ErrPKIFetchRefused, Detail: fmt.Sprintf("more than %d redirects", maxPKIFetchRedirects)}
			}
			return checkFetchURL(req.URL)
		},
	}
}

// checkDialAddress refuses a dial to an address allowed rejects. address is
// the resolved "ip:port" the dialer is about to connect to.
func checkDialAddress(address string, allowed func(netip.Addr) bool) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return &errs.Detail{Err: ErrPKIFetchRefused, Detail: fmt.Sprintf("unparseable dial address %q", address)}
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return &errs.Detail{Err: ErrPKIFetchRefused, Detail: fmt.Sprintf("unparseable dial address %q", address)}
	}
	if !allowed(addr.Unmap()) {
		return &errs.Detail{Err: ErrPKIFetchRefused, Detail: fmt.Sprintf("address %s is not publicly routable", addr)}
	}
	return nil
}

// cgnatPrefix is the RFC 6598 shared address space, which netip does not
// classify as private but which is never a public PKI endpoint.
var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// isPublicAddress reports whether addr is a public unicast address. It
// rejects loopback, RFC 1918 and ULA private ranges, link-local (including
// the 169.254.169.254 cloud metadata endpoint), multicast, unspecified and
// shared (CGNAT) addresses.
func isPublicAddress(addr netip.Addr) bool {
	return addr.IsGlobalUnicast() && !addr.IsPrivate() && !cgnatPrefix.Contains(addr)
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
		if errors.Is(err, ErrPKIFetchRefused) {
			return nil, &errs.Detail{Err: ErrPKIFetchRefused, Detail: fmt.Sprintf("%s: %v", rawURL, err)}
		}
		return nil, &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("failed to download %s: %v", rawURL, err)}
	}

	// Read one byte past the limit so an exactly-full body is accepted and
	// anything longer is detected without buffering the rest.
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	closeErr := resp.Body.Close()

	var fetchErr error
	switch {
	case readErr != nil:
		fetchErr = &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("failed to read %s: %v", rawURL, readErr)}
	case resp.StatusCode != http.StatusOK:
		fetchErr = &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("download %s returned status %d", rawURL, resp.StatusCode)}
	case int64(len(body)) > limit:
		fetchErr = &errs.Detail{Err: ErrPKIFetchTooLarge, Detail: fmt.Sprintf("%s exceeds %d bytes", rawURL, limit)}
	}
	if fetchErr != nil {
		return nil, errors.Join(fetchErr, closeErr)
	}
	if closeErr != nil {
		return nil, &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("failed to close response body for %s: %v", rawURL, closeErr)}
	}
	return body, nil
}
