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

// Package validation is the HTTP client every ACME challenge verifier uses
// to contact a target the ACME client named: http-01 fetches the key
// authorization from it, enroll-01 fetches a TCG-CSR-IDEVID and posts the
// credential challenge back, device-attest-01 fetches the attestation.
//
// The target is attacker-chosen, so the client is built to be safe to point
// at anything:
//
//   - the host must be a bare hostname or IP literal
//     (policy.ValidateNetworkTarget) and the URL is assembled with url.URL
//     and net.JoinHostPort, never by string formatting, so a target cannot
//     add a path, query, fragment, userinfo or port;
//   - the dialer's Control hook refuses every reserved address
//     (policy.IsReservedIP: loopback, private, link-local and cloud
//     metadata, multicast, unspecified, special-purpose). It runs on the
//     address actually being connected to, after DNS resolution, so a name
//     that resolves -- or re-resolves -- to an internal address is refused,
//     and it runs again for every redirect hop;
//   - no proxy is consulted, so the address checked is the address dialed;
//   - redirects are refused unless the request opts in (http-01, RFC 8555
//     section 8.3), and are then limited to MaxRedirects http/https hops;
//   - the response body is read through io.LimitReader and a body larger
//     than the request's limit is refused rather than truncated.
//
// Reserved targets are only reachable when Config.AllowPrivateTargets is
// set, which xkmsd exposes as acme.challenges.allow_private_targets for test
// and lab deployments whose devices live on a private network.
package validation

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"syscall"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/policy"
)

const (
	// DefaultMaxResponseBytes caps a challenge response body when the
	// request does not set its own limit. A key authorization, an
	// activation secret and a device attestation all fit comfortably.
	DefaultMaxResponseBytes int64 = 64 << 10

	// MaxRedirects is the number of redirects a request that opts in to
	// redirects will follow, the same bound Go's default client uses.
	MaxRedirects = 10

	dialTimeout           = 5 * time.Second
	requestTimeout        = 10 * time.Second
	responseHeaderTimeout = 5 * time.Second
	tlsHandshakeTimeout   = 5 * time.Second
)

// Config configures a Client.
type Config struct {
	// AllowPrivateTargets permits connections to reserved addresses
	// (policy.IsReservedIP): loopback, private, link-local, metadata and the
	// other special-purpose ranges. It exists for tests and lab deployments
	// whose devices are on a private network; production leaves it false.
	AllowPrivateTargets bool

	// Resolver resolves target host names. Nil uses net.DefaultResolver.
	// The resolved address is what the dial-time check inspects, so a
	// resolver cannot be used to smuggle a reserved address past it.
	Resolver *net.Resolver
}

// Client performs challenge-validation HTTP requests against client-named
// targets. It is safe for concurrent use, and one Client is meant to be
// shared by every verifier of an ACME server.
type Client struct {
	transport *http.Transport
}

// NewClient returns a Client configured by cfg.
func NewClient(cfg Config) *Client {
	var control dialControl
	if !cfg.AllowPrivateTargets {
		control = refuseReservedAddress
	}
	return newClient(cfg.Resolver, control)
}

// dialControl is a net.Dialer Control hook: it sees the resolved address of
// every connection the client opens, before the connection is made.
type dialControl func(network, address string, c syscall.RawConn) error

func newClient(resolver *net.Resolver, control dialControl) *Client {
	dialer := &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: dialTimeout,
		Resolver:  resolver,
		Control:   control,
	}
	return &Client{
		transport: &http.Transport{
			// Proxy is deliberately nil: a proxy would make the dialed
			// address the proxy's, and the target check meaningless.
			Proxy:                 nil,
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   tlsHandshakeTimeout,
			ResponseHeaderTimeout: responseHeaderTimeout,
			ExpectContinueTimeout: time.Second,
			MaxIdleConns:          16,
			IdleConnTimeout:       30 * time.Second,
		},
	}
}

// Target names the resource a challenge request is sent to.
type Target struct {
	// Host is the client-named host: a bare hostname or IP literal.
	Host string

	// Port is the decimal TCP port.
	Port string

	// Path is the request path, for example
	// "/.well-known/acme-challenge/<token>".
	Path string

	// MaxResponseBytes caps the response body. Zero means
	// DefaultMaxResponseBytes.
	MaxResponseBytes int64

	// FollowRedirects permits up to MaxRedirects http/https redirects.
	FollowRedirects bool
}

// URL returns the target's URL, or an *Error of KindInvalidTarget when the
// host is not a bare hostname or IP literal or the port is not a TCP port.
func (t Target) URL() (*url.URL, error) {
	if err := policy.ValidateNetworkTarget(t.Host); err != nil {
		return nil, &Error{Kind: KindInvalidTarget, Err: err}
	}
	port, err := strconv.ParseUint(t.Port, 10, 16)
	if err != nil || port == 0 {
		return nil, &Error{Kind: KindInvalidTarget, Err: &InvalidPortError{Port: t.Port}}
	}
	return &url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(t.Host, t.Port),
		Path:   t.Path,
	}, nil
}

// Get fetches target and returns its body. A status other than 200 OK is an
// *Error of KindStatus.
func (c *Client) Get(ctx context.Context, target Target) ([]byte, error) {
	return c.do(ctx, http.MethodGet, target, "", nil)
}

// Post sends body to target with the given content type and returns the
// response body. A status other than 200 OK is an *Error of KindStatus.
func (c *Client) Post(ctx context.Context, target Target, contentType string, body []byte) ([]byte, error) {
	return c.do(ctx, http.MethodPost, target, contentType, body)
}

func (c *Client) do(ctx context.Context, method string, target Target, contentType string, body []byte) ([]byte, error) {
	if c == nil || c.transport == nil {
		return nil, ErrNilClient
	}
	u, err := target.URL()
	if err != nil {
		return nil, err
	}

	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reqBody)
	if err != nil {
		return nil, &Error{Kind: KindInvalidTarget, Err: err}
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	httpClient := &http.Client{
		Transport:     c.transport,
		Timeout:       requestTimeout,
		CheckRedirect: redirectPolicy(target.FollowRedirects),
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, classifyTransportError(err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			slog.Debug("challenge validation: failed to close response body", slog.String("error", closeErr.Error()))
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, &Error{Kind: KindStatus, Err: &StatusError{StatusCode: resp.StatusCode}}
	}
	return readLimited(resp.Body, target.MaxResponseBytes)
}

// readLimited reads at most limit bytes of r, refusing a body larger than
// limit rather than silently truncating it.
func readLimited(r io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		limit = DefaultMaxResponseBytes
	}
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, &Error{Kind: KindConnection, Err: err}
	}
	if int64(len(body)) > limit {
		return nil, &Error{Kind: KindResponseTooLarge, Err: &ResponseTooLargeError{Limit: limit}}
	}
	return body, nil
}

// redirectPolicy returns the CheckRedirect function for a request. Every
// hop is dialed through the same transport, so the reserved-address check
// applies to each redirect target as it does to the first.
func redirectPolicy(follow bool) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if !follow {
			return &RedirectError{Reason: "redirects are not permitted for this challenge"}
		}
		if len(via) >= MaxRedirects {
			return &RedirectError{Reason: "too many redirects"}
		}
		if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
			return &RedirectError{Reason: "redirect to unsupported scheme " + strconv.Quote(req.URL.Scheme)}
		}
		if err := policy.ValidateNetworkTarget(req.URL.Hostname()); err != nil {
			return &RedirectError{Reason: "redirect to invalid host"}
		}
		return nil
	}
}

// refuseReservedAddress is the dialer Control hook. address is the
// resolved ip:port being connected to.
func refuseReservedAddress(network, address string, _ syscall.RawConn) error {
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return &AddressNotPermittedError{Address: address}
	}
	if policy.IsReservedIP(addrPort.Addr()) {
		return &AddressNotPermittedError{Address: address}
	}
	return nil
}

// classifyTransportError maps an error from http.Client.Do onto an *Error.
func classifyTransportError(err error) error {
	var refused *AddressNotPermittedError
	if errors.As(err, &refused) {
		return &Error{Kind: KindTargetRefused, Err: err}
	}
	var redirect *RedirectError
	if errors.As(err, &redirect) {
		return &Error{Kind: KindRedirect, Err: err}
	}
	return &Error{Kind: KindConnection, Err: err}
}
