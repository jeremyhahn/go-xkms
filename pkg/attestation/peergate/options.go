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

package peergate

import (
	"crypto/tls"
	"crypto/x509"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// Option configures a Collector or a Verifier.
type Option func(*settings)

// settings is what an Option can change.
type settings struct {
	now func() time.Time
}

// WithClock replaces the wall clock: the collector's receipt time and
// challenge expiry, and the verifier's certificate validity and freshness
// judgments. Tests pin it; production leaves it alone. A nil clock is ignored.
func WithClock(now func() time.Time) Option {
	return func(s *settings) {
		if now != nil {
			s.now = now
		}
	}
}

func newSettings(opts []Option) settings {
	s := settings{now: func() time.Time { return time.Now().UTC() }}
	for _, opt := range opts {
		opt(&s)
	}
	return s
}

// verifiedPeer returns the verified client certificate of a TLS connection
// and its canonical SPKI thumbprint. It applies go-qrdb's rule exactly: only
// a certificate the handshake verified counts, so an unverified certificate a
// client merely presented (tls.RequestClientCert) is no peer at all.
func verifiedPeer(state *tls.ConnectionState) (*x509.Certificate, string, error) {
	if state == nil {
		return nil, "", &PeerCertificateError{Reason: "no TLS connection state"}
	}
	if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return nil, "", &PeerCertificateError{Reason: "the connection carries no verified client certificate"}
	}
	cert := state.VerifiedChains[0][0]
	return cert, qrdbsdk.ComputeSPKIThumbprint(cert), nil
}
