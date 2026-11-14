// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package testutil

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/url"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// mutualTLSHandshakeTimeout bounds the in-memory handshake so a broken
// configuration fails the test instead of hanging it.
const mutualTLSHandshakeTimeout = 10 * time.Second

// MutualTLSState completes a TLS 1.3 handshake requiring a verified client
// certificate over an in-memory pipe and returns the server's view of the
// connection: what a transport hands the service for an mTLS caller, with
// the client's verified chain and a working keying-material exporter.
func MutualTLSState() (state *tls.ConnectionState, err error) {
	ca, err := GenerateTestCA()
	if err != nil {
		return nil, err
	}
	serverCert, err := GenerateTestServerCert(ca, "localhost")
	if err != nil {
		return nil, err
	}
	clientCert, err := GenerateTestClientCert(ca, "peer")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)

	serverEnd, clientEnd := net.Pipe()
	defer func() {
		if closeErr := errors.Join(serverEnd.Close(), clientEnd.Close()); closeErr != nil && err == nil {
			state, err = nil, &errs.Wrapped{Msg: "failed to close the TLS pipe", Err: closeErr}
		}
	}()
	server := tls.Server(serverEnd, &tls.Config{
		Certificates: []tls.Certificate{serverCert.TLSCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	})
	client := tls.Client(clientEnd, &tls.Config{
		Certificates: []tls.Certificate{clientCert.TLSCert},
		RootCAs:      pool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	})

	ctx, cancel := context.WithTimeout(context.Background(), mutualTLSHandshakeTimeout)
	defer cancel()
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.HandshakeContext(ctx) }()
	if err := client.HandshakeContext(ctx); err != nil {
		return nil, &errs.Wrapped{Msg: "client handshake failed", Err: err}
	}
	if err := <-serverErr; err != nil {
		return nil, &errs.Wrapped{Msg: "server handshake failed", Err: err}
	}

	serverState := server.ConnectionState()
	return &serverState, nil
}

// VerifiedClientState returns the TLS state of a server connection whose
// client presented a certificate, issued by a fresh test CA, carrying uris
// as its URI SANs, and verified it: the shape a mutual TLS handshake leaves
// for a caller identified by a SPIFFE ID.
func VerifiedClientState(uris ...string) (*tls.ConnectionState, error) {
	ca, err := GenerateTestCA()
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate key", Err: err}
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "caller"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	for _, s := range uris {
		u, err := url.Parse(s)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to parse URI SAN", Err: err}
		}
		template.URIs = append(template.URIs, u)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create certificate", Err: err}
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse certificate", Err: err}
	}
	return &tls.ConnectionState{
		HandshakeComplete: true,
		PeerCertificates:  []*x509.Certificate{leaf},
		VerifiedChains:    [][]*x509.Certificate{{leaf, ca.Cert}},
	}, nil
}
