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

// Package ca provides trust chain helpers for building x509.CertPool instances
// from the CA's certificate hierarchy and the OS trust store.
package ca

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// TrustedRootCertPool returns a certificate pool containing the root CA
// certificate that anchors the given certificate's trust chain.
//
// The root is located by walking the CA's cached certificate hierarchy:
// if the leaf was issued by the intermediate, the root certificate is
// returned; otherwise, the root is returned directly.
//
// Thread-safe: Yes
func (ca *CA) TrustedRootCertPool(cert *x509.Certificate) (*x509.CertPool, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}

	ca.mu.RLock()
	rootCert := ca.rootCert
	ca.mu.RUnlock()

	if rootCert == nil {
		return nil, ErrRootNotFound
	}

	pool := x509.NewCertPool()
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rootCert.Raw,
	})
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("%w: failed to append root certificate to pool", ErrInvalidCertificateChain)
	}

	return pool, nil
}

// TrustedIntermediateCertPool returns a certificate pool containing the
// intermediate CA certificate for the given leaf certificate's chain.
// Returns an empty pool when the leaf is directly issued by the root CA.
//
// Thread-safe: Yes
func (ca *CA) TrustedIntermediateCertPool(cert *x509.Certificate) (*x509.CertPool, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}

	pool := x509.NewCertPool()

	ca.mu.RLock()
	rootCert := ca.rootCert
	intermediateCert := ca.intermediateCert
	ca.mu.RUnlock()

	// If the leaf is issued by the root, there are no intermediates to add.
	if rootCert != nil && cert.Issuer.CommonName == rootCert.Subject.CommonName {
		return pool, nil
	}

	if intermediateCert == nil {
		return pool, nil
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: intermediateCert.Raw,
	})
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("%w: failed to append intermediate certificate to pool", ErrInvalidCertificateChain)
	}

	return pool, nil
}

// CABundleCertPool returns a certificate pool populated from the CA bundle.
//
// The pool contains all CA certificates in the trust chain (root and
// intermediate). This is the standard pool for most TLS configurations.
//
// Thread-safe: Yes
func (ca *CA) CABundleCertPool() (*x509.CertPool, error) {
	bundlePEM, err := ca.CABundle()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCertificateChain, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bundlePEM) {
		return nil, fmt.Errorf("%w: no valid certificates in bundle", ErrInvalidCertificateChain)
	}

	return pool, nil
}

// OSTrustStore returns the operating system's trusted certificate pool.
//
// Loads the platform-specific trust store via Go's standard
// x509.SystemCertPool:
//   - Linux: /etc/ssl/certs, /etc/pki/tls/certs, etc.
//   - macOS: Keychain Access (System Roots)
//   - Windows: Certificate Store (Trusted Root Certification Authorities)
//
// Thread-safe: Yes
func (ca *CA) OSTrustStore() (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("%w: failed to load OS trust store: %v", ErrInvalidCertificateChain, err)
	}
	if pool == nil {
		return nil, fmt.Errorf("%w: OS trust store is not available on this platform", ErrInvalidCertificateChain)
	}
	return pool, nil
}
