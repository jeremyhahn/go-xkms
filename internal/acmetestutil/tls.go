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

// Package testutil provides shared test helpers for the go-xkms project.
package testutil

import (
	"crypto/tls"
	"crypto/x509"
	"net/http/httptest"
)

// TLSConfigFromServer creates a tls.Config that trusts the given test server's certificate.
// This replaces InsecureSkipVerify: true in tests.
func TLSConfigFromServer(server *httptest.Server) *tls.Config {
	certPool := x509.NewCertPool()
	if server.TLS != nil {
		for _, cert := range server.TLS.Certificates {
			for _, certDER := range cert.Certificate {
				x509Cert, err := x509.ParseCertificate(certDER)
				if err == nil {
					certPool.AddCert(x509Cert)
				}
			}
		}
	}
	return &tls.Config{
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS13,
	}
}

// CertPoolFromServer extracts a cert pool that trusts the given test server's certificate.
func CertPoolFromServer(server *httptest.Server) *x509.CertPool {
	certPool := x509.NewCertPool()
	if server.TLS != nil {
		for _, cert := range server.TLS.Certificates {
			for _, certDER := range cert.Certificate {
				x509Cert, err := x509.ParseCertificate(certDER)
				if err == nil {
					certPool.AddCert(x509Cert)
				}
			}
		}
	}
	return certPool
}
