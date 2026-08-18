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

// Package fetcher implements an HTTPS client that retrieves a CA bundle from
// a go-trusted-platform node. The server's identity is verified against a
// mandatory pre-shared SPKI SHA-256 hash supplied by the operator out-of-
// band; there is no trust-on-first-use path and no unauthenticated TLS path.
//
// Reusable infrastructure for the xkey trust bootstrap CLI commands. Logic
// here MUST NOT depend on cobra, viper, or any other CLI framework so that
// it can be reused by SDK consumers and integration tests.
package fetcher

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// DefaultTimeout is the HTTP timeout applied when Options.Timeout is zero.
const DefaultTimeout = 30 * time.Second

// DefaultBundlePath is the canonical UNAUTHENTICATED trust-bootstrap
// endpoint (raw PEM), shared with go-truststrap's default. First-contact
// clients have no credentials by definition, so the default must never
// point at an authenticated route: the previous /api/v1/ca/bundle default
// only worked while adaptive authentication served it anonymously, and the
// canonical first-boot closes that window by creating the administrator at
// startup. Callers fetching the richer authenticated bundle set BundlePath
// explicitly.
const DefaultBundlePath = "/v1/ca/bootstrap"

// pemMediaType is the IANA media type for PEM-encoded certificate data.
const pemMediaType = "application/x-pem-file"

// jsonBundleResponse mirrors the platform REST CABundleResponse type. The
// platform wraps responses in a {code,error,success,payload} envelope, so we
// support both the envelope-wrapped form and the bare CABundleResponse. We
// only depend on the bundle bytes; remaining fields are decoded for forward
// compatibility but ignored.
type jsonBundleResponse struct {
	Bundle  []byte             `json:"bundle"`
	Payload *jsonBundlePayload `json:"payload,omitempty"`
}

// jsonBundlePayload mirrors the inner payload of the platform envelope.
type jsonBundlePayload struct {
	Bundle []byte `json:"bundle"`
}

// bundleBytes returns the bundle bytes regardless of envelope nesting.
func (r jsonBundleResponse) bundleBytes() []byte {
	if len(r.Bundle) > 0 {
		return r.Bundle
	}
	if r.Payload != nil {
		return r.Payload.Bundle
	}
	return nil
}

// Options configures a single Fetch call.
type Options struct {
	// SPKIPin is a 64-char hex SHA-256 hash of the leaf SubjectPublicKeyInfo.
	// It is mandatory; an empty pin returns ErrPinRequired. The pin must be
	// obtained out-of-band via a secure channel (e.g., HSM-attested deploy
	// manifest, signed deployment log, or manual transcription from the
	// server console). Direct fetches without a pin are not supported.
	SPKIPin string

	// Timeout caps the entire HTTP transaction. Zero defaults to
	// DefaultTimeout.
	Timeout time.Duration

	// HTTPClient lets tests inject a fully constructed client (e.g., one
	// pointed at httptest.Server.Client()). When nil, Fetch builds a client
	// from the SPKI pin.
	HTTPClient *http.Client

	// ExtraHeaders are merged into the request after Accept is set. Useful
	// for callers that need to include auth tokens or trace IDs.
	ExtraHeaders http.Header
}

// Bundle is the result of a successful fetch.
type Bundle struct {
	// PEM is the raw PEM-encoded CA bundle suitable for direct insertion
	// into a truststore.
	PEM []byte

	// Certificates is the parsed bundle in declaration order.
	Certificates []*x509.Certificate

	// Source is a short human-readable label for provenance (e.g., the
	// host:port of the upstream platform node). Useful when recording the
	// bundle into a metadata-aware truststore.
	Source string

	// LeafSPKI is the lowercase hex SHA-256 of the TLS leaf certificate's
	// SubjectPublicKeyInfo. Always equals the supplied SPKIPin on success;
	// recorded so callers can audit/log what was matched.
	LeafSPKI string
}

// Fetch retrieves and parses a CA bundle from rawURL. The supplied SPKIPin
// is verified against the TLS leaf certificate. It returns ErrInvalidURL for
// parse errors, ErrPinRequired / ErrInvalidPin for pin problems,
// ErrPinMismatch for handshake verification failures, ErrHTTPStatus for
// non-2xx responses, and ErrEmptyBundle / ErrInvalidPEM / ErrInvalidJSON for
// response decoding errors.
func Fetch(ctx context.Context, rawURL string, opts Options) (*Bundle, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, &errs.Detail{Err: ErrInvalidURL, Detail: fmt.Sprintf("%v", err)}
	}
	if parsed.Scheme != "https" {
		return nil, &errs.Detail{Err: ErrInvalidURL, Detail: fmt.Sprintf("scheme must be https, got %q", parsed.Scheme)}
	}
	if parsed.Host == "" {
		return nil, &errs.Detail{Err: ErrInvalidURL, Detail: "missing host"}
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	client := opts.HTTPClient
	var leafCapture *leafObserver
	if client == nil {
		client, leafCapture, err = newClient(opts, timeout)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, &errs.Detail{Err: ErrInvalidURL, Detail: fmt.Sprintf("%v", err)}
	}
	req.Header.Set("Accept", pemMediaType+", application/json;q=0.5")
	req.Header.Set("User-Agent", "xkey-trust-fetcher/1.0")
	for k, vs := range opts.ExtraHeaders {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, &errs.Detail{Err: ErrHTTPStatus, Detail: fmt.Sprintf("%d %s: %s", resp.StatusCode, resp.Status, string(body))}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &errs.Detail{Err: ErrHTTPStatus, Detail: fmt.Sprintf("%v", err)}
	}

	bundlePEM, certs, err := decodeBundle(resp.Header.Get("Content-Type"), body)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, ErrEmptyBundle
	}

	bundle := &Bundle{
		PEM:          bundlePEM,
		Certificates: certs,
		Source:       "platform:" + parsed.Host,
	}
	if leafCapture != nil {
		bundle.LeafSPKI = leafCapture.SPKI()
	}
	return bundle, nil
}

// newClient builds a TLS-pinned HTTP client according to opts. It also
// returns a leafObserver that records the SPKI of the leaf cert presented
// during the handshake so callers can audit/log the matched value.
func newClient(opts Options, timeout time.Duration) (*http.Client, *leafObserver, error) {
	tlsConfig, err := BuildTLSConfig(opts.SPKIPin)
	if err != nil {
		return nil, nil, err
	}

	observer := newLeafObserver()
	wrapped := observer.wrap(tlsConfig.VerifyPeerCertificate)
	// #nosec G123 -- resumption disabled via SessionTicketsDisabled in BuildTLSConfig, so VerifyPeerCertificate is never bypassed on a resumed session.
	tlsConfig.VerifyPeerCertificate = wrapped //nolint:gosec // G123 handled by SessionTicketsDisabled in BuildTLSConfig

	transport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          2,
		IdleConnTimeout:       timeout,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}, observer, nil
}

// decodeBundle parses the response body. It first attempts PEM decoding
// (the preferred format when the server honors our Accept header). If that
// fails and the content type indicates JSON, it falls back to the platform
// REST CABundleResponse shape.
func decodeBundle(contentType string, body []byte) ([]byte, []*x509.Certificate, error) {
	pemCerts, ok := tryParsePEM(body)
	if ok {
		return body, pemCerts, nil
	}

	if contentType != "" && (contentTypeMatches(contentType, "application/json") ||
		contentTypeMatches(contentType, "text/json")) {
		var resp jsonBundleResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, nil, &errs.Detail{Err: ErrInvalidJSON, Detail: fmt.Sprintf("%v", err)}
		}
		bundleBytes := resp.bundleBytes()
		jsonCerts, ok := tryParsePEM(bundleBytes)
		if !ok {
			return nil, nil, ErrInvalidPEM
		}
		return bundleBytes, jsonCerts, nil
	}

	return nil, nil, ErrInvalidPEM
}

// contentTypeMatches reports whether ct begins with prefix (case-insensitive,
// ignoring parameters like "; charset=utf-8").
func contentTypeMatches(ct, prefix string) bool {
	if len(ct) < len(prefix) {
		return false
	}
	return equalFold(ct[:len(prefix)], prefix)
}

// equalFold compares two ASCII strings case-insensitively without allocating.
func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// tryParsePEM attempts to decode body as one or more concatenated PEM
// CERTIFICATE blocks. It returns the parsed certs and true on success;
// false if no CERTIFICATE blocks were found.
func tryParsePEM(body []byte) ([]*x509.Certificate, bool) {
	var certs []*x509.Certificate
	rest := body
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, false
		}
		certs = append(certs, cert)
	}
	return certs, len(certs) > 0
}

// leafObserver records the SPKI hash of the first leaf certificate seen
// during a TLS handshake. It composes with an inner VerifyPeerCertificate
// callback so we can both pin and capture.
type leafObserver struct {
	hash string
}

func newLeafObserver() *leafObserver { return &leafObserver{} }

func (l *leafObserver) SPKI() string { return l.hash }

func (l *leafObserver) wrap(inner func([][]byte, [][]*x509.Certificate) error) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
		if len(rawCerts) > 0 && l.hash == "" {
			if cert, err := x509.ParseCertificate(rawCerts[0]); err == nil {
				l.hash = SPKIHash(cert)
			}
		}
		if inner == nil {
			return nil
		}
		return inner(rawCerts, chains)
	}
}

// CompileTimeChecks ensures the package compiles against the expected types.
var _ = (*tls.Config)(nil)
