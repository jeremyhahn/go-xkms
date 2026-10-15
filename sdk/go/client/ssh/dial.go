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
	"net/url"
)

// ServerOptions is the connection material for NewClientForServerWith.
type ServerOptions struct {
	// TLSConfig verifies the server on the TLS transports and may carry an
	// mTLS client certificate or an SPKI pin. nil selects a TLS 1.3
	// configuration over the system roots.
	TLSConfig *tls.Config

	// Token is the bearer token presented on every call, on every
	// transport. Empty presents none.
	Token string
}

// NewClientForServer constructs an SSH Client for a server URL; see
// NewClientForServerWith for the scheme dispatch. tlsCA, when set, is the
// PEM CA bundle used to verify the server on the TLS transports; token is
// the bearer token. Callers own Close() on the returned client.
func NewClientForServer(server, tlsCA, token string) (Client, error) {
	tlsCfg, err := tlsConfigFromCA(tlsCA)
	if err != nil {
		return nil, err
	}
	return NewClientForServerWith(server, ServerOptions{TLSConfig: tlsCfg, Token: token})
}

// NewClientForServerWith constructs an SSH Client for a server URL,
// dispatching on the scheme so a single call site works across every
// protocol:
//
//   - http://, https://      → REST
//   - grpc://, grpcs://       → gRPC (grpcs enables TLS)
//   - unix://<path>           → gRPC over TLS on a Unix domain socket
//   - quic://<host:port>      → HTTP/3
//   - mcp://, mcps://         → MCP JSON-RPC (mcps enables TLS)
//
// opts.TLSConfig is used on every TLS transport and opts.Token rides every
// transport. Callers own Close() on the returned client.
func NewClientForServerWith(server string, opts ServerOptions) (Client, error) {
	if server == "" {
		return nil, &NilInputError{Field: "server"}
	}
	u, err := url.Parse(server)
	if err != nil {
		return nil, &ProtocolError{Message: "parse server url", Err: err}
	}
	tlsCfg := opts.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS13}
	}
	switch u.Scheme {
	case "http", "https":
		restOpts := RESTOptions{BaseURL: server, AuthToken: opts.Token}
		if u.Scheme == "https" {
			restOpts.HTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}
		}
		return NewREST(restOpts)
	case "grpc", "grpcs":
		grpcOpts := GRPCOptions{Endpoint: u.Host, TLSEnabled: u.Scheme == "grpcs", AuthToken: opts.Token}
		if grpcOpts.TLSEnabled {
			grpcOpts.TLSConfig = tlsCfg
		}
		return NewGRPC(grpcOpts)
	case "unix":
		// xkmsd's socket is the qrdb node's TLS listener, so the socket
		// takes TLS like grpcs; opts.TLSConfig verifies the node and may
		// carry the client certificate.
		return NewGRPC(GRPCOptions{Endpoint: server, TLSEnabled: true, TLSConfig: tlsCfg, AuthToken: opts.Token})
	case "quic":
		return NewQUIC(QUICOptions{BaseURL: "https://" + u.Host, TLSConfig: tlsCfg, AuthToken: opts.Token})
	case "mcp", "mcps":
		mcpOpts := MCPOptions{Addr: u.Host, AuthToken: opts.Token}
		if u.Scheme == "mcps" {
			mcpOpts.TLSConfig = tlsCfg
		}
		return NewMCP(mcpOpts)
	default:
		return nil, &ProtocolError{Message: "unsupported server scheme: " + u.Scheme}
	}
}
