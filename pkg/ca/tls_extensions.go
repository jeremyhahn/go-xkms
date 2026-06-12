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

// Package ca provides TLS helpers that build on the native TLSCertificate /
// TLSConfig primitives to support cross-signed chains and PEM bundle export.
package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TLSBundle returns a PEM-encoded bundle containing the certificate chain
// and the private key for the identity described by attrs. This matches the
// wrapper semantics used by ACME clients that need a single artefact to feed
// into external TLS stacks.
//
// Private-key export is only supported for software-backed keys (PKCS#8).
// Hardware-backed keys (TPM2, HSM) return an error here because they cannot
// be extracted by design; use TLSCertificate() or TLSConfig() for those
// backends and pass the resulting crypto.Signer to the TLS stack directly.
//
// Thread-safe: Yes
func (ca *CA) TLSBundle(ctx context.Context, attrs *types.KeyAttributes) ([]byte, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}
	if attrs == nil {
		return nil, fmt.Errorf("%w: key attributes required", ErrInvalidTLSOptions)
	}

	var bundle bytes.Buffer

	// Prefer the keystore's chain when available so that intermediates are
	// included in the bundle.
	chain, err := ca.keyStore.GetCertChain(ctx, attrs.CN)
	if err != nil || len(chain) == 0 {
		cert, certErr := ca.Certificate(ctx, attrs)
		if certErr != nil {
			return nil, certErr
		}
		chain = []*x509.Certificate{cert}
	}

	for _, cert := range chain {
		if err := pem.Encode(&bundle, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}); err != nil {
			return nil, fmt.Errorf("%w: failed to encode certificate: %v", ErrTLSConfigFailed, err)
		}
	}

	key, err := ca.keyStore.GetKey(ctx, attrs)
	if err != nil {
		return nil, fmt.Errorf("%w: private key export unsupported by backend: %v",
			ErrTLSConfigFailed, err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to marshal private key: %v", ErrTLSConfigFailed, err)
	}
	if err := pem.Encode(&bundle, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}); err != nil {
		return nil, fmt.Errorf("%w: failed to encode private key: %v", ErrTLSConfigFailed, err)
	}
	return bundle.Bytes(), nil
}

// TLSBundleWithCrossSigner extends TLSBundle by prepending cross-signed
// chain certificates issued by the supplied xsigner. The xsigner's public
// key is resolved via an issuer-CN lookup in the object store so the call
// site does not need to supply the issuerCN separately.
//
// When xsigner is nil the result is identical to TLSBundle.
//
// Thread-safe: Yes
func (ca *CA) TLSBundleWithCrossSigner(ctx context.Context, attrs *types.KeyAttributes, xsigner crypto.Signer) ([]byte, error) {
	base, err := ca.TLSBundle(ctx, attrs)
	if err != nil {
		return nil, err
	}
	if xsigner == nil {
		return base, nil
	}

	xsignedCerts, err := ca.getXSignedCertificates(attrs.CN)
	if err != nil || len(xsignedCerts) == 0 {
		return base, nil
	}

	var bundle bytes.Buffer
	for _, cert := range xsignedCerts {
		if err := pem.Encode(&bundle, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}); err != nil {
			return nil, fmt.Errorf("%w: failed to encode cross-signed certificate: %v",
				ErrTLSConfigFailed, err)
		}
	}
	bundle.Write(base)
	return bundle.Bytes(), nil
}

// TLSConfigWithXSigner builds a TLS config whose RootCAs pool is augmented
// with any cross-signed certificates discovered for the CA's root CN when
// xsigner is non-nil. When xsigner is nil it produces the same result as
// TLSConfig.
//
// Thread-safe: Yes
func (ca *CA) TLSConfigWithXSigner(ctx context.Context, attrs *types.KeyAttributes, xsigner crypto.Signer) (*tls.Config, error) {
	cfg, err := ca.TLSConfig(ctx, attrs)
	if err != nil {
		return nil, err
	}
	if xsigner == nil {
		return cfg, nil
	}

	ca.mu.RLock()
	root := ca.rootCert
	intermediate := ca.intermediateCert
	ca.mu.RUnlock()

	if root == nil {
		return cfg, nil
	}

	if xsignedRoots, err := ca.getXSignedCertificates(root.Subject.CommonName); err == nil {
		for _, c := range xsignedRoots {
			if cfg.RootCAs == nil {
				cfg.RootCAs = x509.NewCertPool()
			}
			cfg.RootCAs.AddCert(c)
			if cfg.ClientCAs != nil {
				cfg.ClientCAs.AddCert(c)
			}
		}
	}
	if intermediate != nil {
		if xsignedInt, err := ca.getXSignedCertificates(intermediate.Subject.CommonName); err == nil {
			for _, c := range xsignedInt {
				if cfg.RootCAs == nil {
					cfg.RootCAs = x509.NewCertPool()
				}
				cfg.RootCAs.AddCert(c)
			}
		}
	}
	return cfg, nil
}
