// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package ssh

import (
	"crypto/tls"
	"net/http"

	"github.com/quic-go/quic-go/http3"
)

// QUICOptions configures the QUIC/HTTP3 transport Client. The wire
// format is identical to the REST transport (JSON over HTTP); only the
// underlying connection uses QUIC instead of TCP.
type QUICOptions struct {
	// BaseURL is the xkmsd base URL, e.g. "https://xkms.example.com:8444".
	// Required. Trailing slashes are tolerated.
	BaseURL string

	// TLSConfig is the TLS configuration used by the HTTP/3 transport.
	// nil selects a minimal TLS 1.3 configuration. Callers that need
	// custom CA pools, client certificates, or SPKI pin verification
	// should construct and pass a fully configured *tls.Config.
	TLSConfig *tls.Config

	// AuthToken is an optional bearer token forwarded in the
	// Authorization header on every request.
	AuthToken string
}

// NewQUIC constructs a Client that communicates over HTTP/3 (QUIC) with
// the same JSON wire format as the REST transport. It reuses the REST
// client implementation by installing an HTTP/3 RoundTripper on the
// underlying *http.Client — no method bodies are duplicated.
//
// Returns *NilInputError when BaseURL is empty.
func NewQUIC(opts QUICOptions) (Client, error) {
	tlsCfg := opts.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
	}
	h3Transport := &http3.Transport{
		TLSClientConfig: tlsCfg,
	}
	hc := &http.Client{Transport: h3Transport}
	return NewREST(RESTOptions{
		BaseURL:    opts.BaseURL,
		HTTPClient: hc,
		AuthToken:  opts.AuthToken,
	})
}
