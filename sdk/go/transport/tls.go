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

package transport

import (
	"crypto/tls"
	"crypto/x509"
	"os"
)

// TLSOptions configures BuildTLSConfig. All fields are optional; the zero
// value yields a minimal TLS 1.3 client configuration that verifies servers
// against the system root pool.
type TLSOptions struct {
	// CAFile is the path to a PEM CA bundle used to verify the server.
	// Empty selects the system root pool.
	CAFile string

	// CertFile and KeyFile enable mTLS client authentication. Both must be
	// set for a client certificate to be loaded.
	CertFile string
	KeyFile  string

	// ServerName overrides the TLS SNI / verification name.
	ServerName string
}

// CAFileReadError is returned when a configured CA bundle cannot be read.
type CAFileReadError struct {
	Path string
	Err  error
}

// Error implements the error interface.
func (e *CAFileReadError) Error() string {
	return "transport: read CA file " + e.Path + ": " + e.Err.Error()
}

// Unwrap returns the underlying read error.
func (e *CAFileReadError) Unwrap() error { return e.Err }

// CAFileParseError is returned when a configured CA bundle contains no
// parseable PEM certificates.
type CAFileParseError struct {
	Path string
}

// Error implements the error interface.
func (e *CAFileParseError) Error() string {
	return "transport: parse CA file " + e.Path + ": no certificates found"
}

// ClientCertLoadError is returned when an mTLS client keypair cannot be
// loaded.
type ClientCertLoadError struct {
	CertFile string
	KeyFile  string
	Err      error
}

// Error implements the error interface.
func (e *ClientCertLoadError) Error() string {
	return "transport: load client certificate " + e.CertFile + ": " + e.Err.Error()
}

// Unwrap returns the underlying load error.
func (e *ClientCertLoadError) Unwrap() error { return e.Err }

// LoadCertPool reads caFile and parses it into an *x509.CertPool. It returns
// *CAFileReadError when the file cannot be read and *CAFileParseError when
// the file contains no PEM certificates.
func LoadCertPool(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, &CAFileReadError{Path: caFile, Err: err}
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, &CAFileParseError{Path: caFile}
	}
	return pool, nil
}

// BuildTLSConfig builds a TLS 1.3 client configuration from opts. It is the
// single shared TLS builder for every SDK client transport (https, grpcs,
// quic, mcps); per-transport forks of this logic are forbidden.
//
// CA errors take precedence over client-certificate errors, preserving the
// historical per-transport evaluation order.
func BuildTLSConfig(opts TLSOptions) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if opts.ServerName != "" {
		cfg.ServerName = opts.ServerName
	}
	if opts.CAFile != "" {
		pool, err := LoadCertPool(opts.CAFile)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}
	if opts.CertFile != "" && opts.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
		if err != nil {
			return nil, &ClientCertLoadError{CertFile: opts.CertFile, KeyFile: opts.KeyFile, Err: err}
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}
