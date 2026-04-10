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

package xkeysigner

import (
	"crypto/tls"
	"crypto/x509"
)

// TLSConfig configures TLS client authentication via xkey IPC.
type TLSConfig struct {
	// SignerConfig configures the underlying IPC signer.
	SignerConfig *SignerConfig

	// CACertPEM contains optional CA certificate(s) in PEM format to add
	// to the trusted root certificate pool.
	CACertPEM []byte

	// ServerName is the optional expected server name for TLS verification.
	ServerName string
}

// TLSCertificate returns a tls.Certificate backed by the xkey IPC signer.
// The certificate chain is fetched from the PIV slot and the private key
// is the Signer itself (which implements crypto.Signer).
func TLSCertificate(config *SignerConfig) (*tls.Certificate, error) {
	if config == nil {
		return nil, ErrNilConfig
	}

	signer, err := NewSigner(config)
	if err != nil {
		return nil, err
	}

	cert, err := signer.Certificate()
	if err != nil {
		return nil, err
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  signer,
		Leaf:        cert,
	}

	return tlsCert, nil
}

// TLSClientConfig returns a *tls.Config suitable for mTLS client connections.
// It uses TLSCertificate for the client certificate and optionally adds CA
// certificates to the root pool.
func TLSClientConfig(config *TLSConfig) (*tls.Config, error) {
	if config == nil {
		return nil, ErrNilConfig
	}
	if config.SignerConfig == nil {
		return nil, ErrNilConfig
	}

	tlsCert, err := TLSCertificate(config.SignerConfig)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	if config.ServerName != "" {
		tlsConfig.ServerName = config.ServerName
	}

	if len(config.CACertPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(config.CACertPEM) {
			return nil, ErrInvalidCertFormat
		}
		tlsConfig.RootCAs = pool
	}

	return tlsConfig, nil
}
