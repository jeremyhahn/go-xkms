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

// NewClientForServer constructs an SSH Client for a server URL, dispatching on
// the scheme so a single call site works across every protocol:
//
//   - http://, https://      → REST
//   - grpc://, grpcs://       → gRPC (grpcs enables TLS)
//   - unix://<path>           → gRPC over a Unix domain socket (plaintext)
//   - quic://<host:port>      → HTTP/3
//   - mcp://, mcps://         → MCP JSON-RPC (mcps enables TLS)
//
// tlsCA, when set, is the PEM CA bundle used to verify the server for the TLS
// transports. token is forwarded as a bearer token where the transport
// supports it (REST/QUIC). Callers own Close() on the returned client.
func NewClientForServer(server, tlsCA, token string) (Client, error) {
	if server == "" {
		return nil, &NilInputError{Field: "server"}
	}
	u, err := url.Parse(server)
	if err != nil {
		return nil, &ProtocolError{Message: "parse server url", Err: err}
	}
	switch u.Scheme {
	case "http", "https":
		opts := RESTOptions{BaseURL: server, AuthToken: token}
		if u.Scheme == "https" {
			// Thread tlsCA exactly like the other TLS schemes (grpcs/quic/
			// mcps); without this an https server signed by a private CA
			// fails verification even when --tls-ca is supplied.
			tlsCfg, terr := tlsConfigFromCA(tlsCA)
			if terr != nil {
				return nil, terr
			}
			opts.HTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}
		}
		return NewREST(opts)
	case "grpc", "grpcs":
		return NewGRPC(GRPCOptions{Endpoint: u.Host, TLSEnabled: u.Scheme == "grpcs", TLSCAFile: tlsCA})
	case "unix":
		// gRPC dials the unix socket target directly; the local socket is
		// plaintext, so TLS is disabled.
		return NewGRPC(GRPCOptions{Endpoint: server, TLSEnabled: false})
	case "quic":
		tlsCfg, terr := tlsConfigFromCA(tlsCA)
		if terr != nil {
			return nil, terr
		}
		return NewQUIC(QUICOptions{BaseURL: "https://" + u.Host, TLSConfig: tlsCfg, AuthToken: token})
	case "mcp", "mcps":
		var tlsCfg *tls.Config
		if u.Scheme == "mcps" {
			cfg, terr := tlsConfigFromCA(tlsCA)
			if terr != nil {
				return nil, terr
			}
			tlsCfg = cfg
		}
		return NewMCP(MCPOptions{Addr: u.Host, TLSConfig: tlsCfg})
	default:
		return nil, &ProtocolError{Message: "unsupported server scheme: " + u.Scheme}
	}
}
