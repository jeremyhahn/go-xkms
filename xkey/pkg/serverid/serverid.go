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

// Package serverid identifies an xkms server by its TLS identity: qrdb's
// SPKI SHA-256 thumbprint of the leaf certificate it presents. The unified
// server presents one certificate on REST, gRPC, QUIC and MCP, so the
// identity is the same on every transport, whatever the scheme or port,
// and two servers with different certificates never share one, even on
// one host. xkey keys stored logins by it.
package serverid

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/quic-go/quic-go"
)

// ErrNoTLS is returned for a URL whose transport carries no TLS (http://,
// grpc://, mcp://), where no certificate identifies the server, and for
// unix://, whose server is named by configuration rather than probed.
var ErrNoTLS = errors.New("serverid: the transport has no TLS identity")

// ProbeError is returned when the server's identity cannot be read.
type ProbeError struct {
	URL string
	Err error
}

// Error implements the error interface.
func (e *ProbeError) Error() string {
	return fmt.Sprintf("serverid: identify %s: %v", e.URL, e.Err)
}

// Unwrap returns the cause.
func (e *ProbeError) Unwrap() error { return e.Err }

// Of returns the identity of a server certificate.
func Of(cert *x509.Certificate) string {
	return qrdbsdk.ComputeSPKIThumbprint(cert)
}

// tlsDefaultPorts lists the TLS schemes and the port each defaults to.
var tlsDefaultPorts = map[string]string{
	"https": "443",
	"grpcs": "443",
	"mcps":  "443",
	"quic":  "443",
}

// Probe performs a TLS handshake with the server rawURL names, verified by
// cfg exactly as the call it precedes would be, and returns the identity
// of the certificate it presents: over QUIC for quic://, over TCP for the
// other TLS schemes. A scheme without TLS returns ErrNoTLS.
func Probe(ctx context.Context, rawURL string, cfg *tls.Config) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", &ProbeError{URL: rawURL, Err: err}
	}
	scheme := strings.ToLower(u.Scheme)
	defaultPort, ok := tlsDefaultPorts[scheme]
	if !ok {
		return "", ErrNoTLS
	}
	if u.Hostname() == "" {
		return "", &ProbeError{URL: rawURL, Err: errors.New("no host")}
	}
	port := u.Port()
	if port == "" {
		port = defaultPort
	}
	addr := net.JoinHostPort(u.Hostname(), port)

	conf := &tls.Config{MinVersion: tls.VersionTLS13}
	if cfg != nil {
		conf = cfg.Clone()
	}
	if conf.ServerName == "" {
		conf.ServerName = u.Hostname()
	}

	var peers []*x509.Certificate
	if scheme == "quic" {
		peers, err = probeQUIC(ctx, addr, conf)
	} else {
		peers, err = probeTCP(ctx, addr, conf)
	}
	if err != nil {
		return "", &ProbeError{URL: rawURL, Err: err}
	}
	if len(peers) == 0 {
		return "", &ProbeError{URL: rawURL, Err: errors.New("the server presented no certificate")}
	}
	return Of(peers[0]), nil
}

// probeTCP handshakes TLS over TCP and returns the peer certificates.
func probeTCP(ctx context.Context, addr string, conf *tls.Config) ([]*x509.Certificate, error) {
	conn, err := (&tls.Dialer{Config: conf}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	peers := conn.(*tls.Conn).ConnectionState().PeerCertificates
	return peers, conn.Close()
}

// probeQUIC handshakes QUIC (HTTP/3's ALPN) and returns the peer
// certificates.
func probeQUIC(ctx context.Context, addr string, conf *tls.Config) ([]*x509.Certificate, error) {
	if len(conf.NextProtos) == 0 {
		conf.NextProtos = []string{"h3"}
	}
	conn, err := quic.DialAddr(ctx, addr, conf, nil)
	if err != nil {
		return nil, err
	}
	peers := conn.ConnectionState().TLS.PeerCertificates
	return peers, conn.CloseWithError(0, "")
}
