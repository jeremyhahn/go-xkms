// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// Shared plumbing used by every remote transport leg (rest/grpc/quic/mcp).
// TLS construction is delegated to the SDK-wide transport.BuildTLSConfig
// helper so no per-transport TLS fork can drift.

package ssh

import (
	"crypto/tls"
	"errors"
	"net"

	gossh "golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// buildTLSConfig delegates to the shared transport.BuildTLSConfig helper and
// maps its typed errors onto this package's *ProtocolError so every TLS
// scheme (https/grpcs/quic/mcps) reports failures identically.
func buildTLSConfig(opts transport.TLSOptions) (*tls.Config, error) {
	cfg, err := transport.BuildTLSConfig(opts)
	if err == nil {
		return cfg, nil
	}
	var (
		readErr  *transport.CAFileReadError
		parseErr *transport.CAFileParseError
		certErr  *transport.ClientCertLoadError
	)
	switch {
	case errors.As(err, &readErr):
		return nil, &ProtocolError{Message: "read tls ca", Err: readErr.Err}
	case errors.As(err, &parseErr):
		return nil, &ProtocolError{Message: "parse tls ca: no certificates found"}
	case errors.As(err, &certErr):
		return nil, &ProtocolError{Message: "load client certificate", Err: certErr.Err}
	default:
		return nil, &ProtocolError{Message: "build tls config", Err: err}
	}
}

// tlsConfigFromCA builds a TLS 1.3 config trusting caFile (system roots when
// caFile is empty).
func tlsConfigFromCA(caFile string) (*tls.Config, error) {
	return buildTLSConfig(transport.TLSOptions{CAFile: caFile})
}

// parseExportedPublicKey parses the authorized_keys line returned by
// ExportPublic into a gossh.PublicKey for the remote-signer proxies.
func parseExportedPublicKey(line string) (gossh.PublicKey, error) {
	pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, &ProtocolError{Message: "parse exported public key", Err: err}
	}
	return pub, nil
}

// stripCallbackPort removes the trailing ":port" from the hostname
// x/crypto/ssh passes to a HostKeyCallback so pins persist per-host.
// Identical semantics to pkg/ssh/known_hosts.stripPort; duplicated here
// to avoid depending on that unexported symbol.
func stripCallbackPort(hostname string) string {
	host, _, err := net.SplitHostPort(hostname)
	if err != nil {
		return hostname
	}
	return host
}
