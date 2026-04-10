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

package server

import (
	"crypto/x509"
	"encoding/pem"
	"os"
)

// tlsCABundler provides the CA certificate bundle from the server's TLS
// configuration. It implements the CABundler interfaces expected by
// REST, gRPC, and Noise bootstrap subsystems.
type tlsCABundler struct {
	certPEM []byte
	cert    *x509.Certificate
}

// newTLSCABundler creates a CA bundler from a PEM-encoded CA certificate file.
func newTLSCABundler(caFile string) (*tlsCABundler, error) {
	// #nosec G304 - CA certificate path from trusted config file
	pemData, err := os.ReadFile(caFile)
	if err != nil {
		return nil, ErrCAFileReadFailed
	}

	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, ErrCAParseFailed
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, ErrCAParseFailed
	}

	return &tlsCABundler{
		certPEM: pemData,
		cert:    cert,
	}, nil
}

// CABundle returns the CA certificate chain in PEM format.
func (b *tlsCABundler) CABundle() ([]byte, error) {
	return b.certPEM, nil
}

// CACertificate returns the parsed CA certificate.
func (b *tlsCABundler) CACertificate() (*x509.Certificate, error) {
	return b.cert, nil
}

// caInstanceProvider is the subset of ca.XKMSCA needed to create a bundler.
type caInstanceProvider interface {
	CABundle() ([]byte, error)
	CACertificate() (*x509.Certificate, error)
}

// newCAInstanceBundler creates a CA bundler from an initialized CA instance.
func newCAInstanceBundler(caInstance caInstanceProvider) (*tlsCABundler, error) {
	certPEM, err := caInstance.CABundle()
	if err != nil {
		return nil, &ErrCABundleGet{Operation: "CA bundle", Err: err}
	}

	cert, err := caInstance.CACertificate()
	if err != nil {
		return nil, &ErrCABundleGet{Operation: "CA certificate", Err: err}
	}

	return &tlsCABundler{
		certPEM: certPEM,
		cert:    cert,
	}, nil
}
