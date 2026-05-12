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

// Package ca provides the extended trust-chain operations that complement
// the native TrustedRootCertPool/TrustedIntermediateCertPool helpers with
// variants that honour cross-signed chains, AIA auto-import, and bundle
// parsing.
package ca

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
)

// TrustedRoot returns the root CA certificate that anchors this CA's
// hierarchy. Returns ErrNotInitialized if Init/Load has not been called,
// and ErrRootNotFound when the root has not been materialised yet.
//
// Thread-safe: Yes
func (ca *CA) TrustedRoot() (*x509.Certificate, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}

	ca.mu.RLock()
	root := ca.rootCert
	ca.mu.RUnlock()

	if root == nil {
		return nil, ErrRootNotFound
	}
	return root, nil
}

// TrustedIntermediate returns the intermediate CA certificate, if any.
// Returns ErrIntermediateNotFound when the CA is configured as a pure root.
//
// Thread-safe: Yes
func (ca *CA) TrustedIntermediate() (*x509.Certificate, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}

	ca.mu.RLock()
	intermediate := ca.intermediateCert
	ca.mu.RUnlock()

	if intermediate == nil {
		return nil, ErrIntermediateNotFound
	}
	return intermediate, nil
}

// TrustedRootCertPoolWithXSigner builds on TrustedRootCertPool by also
// appending any cross-signed root certificates that match the resolved root's
// CN when xsigner is non-nil. xsigner itself is not consulted for the pool
// contents; its non-nil value is used as the caller's opt-in to cross-sign
// augmentation so downstream TLS configurations can verify chains signed by
// both the native root and any foreign issuers that cross-signed it.
//
// Thread-safe: Yes
func (ca *CA) TrustedRootCertPoolWithXSigner(cert *x509.Certificate, xsigner crypto.Signer) (*x509.CertPool, error) {
	pool, err := ca.TrustedRootCertPool(cert)
	if err != nil {
		return nil, err
	}
	if xsigner == nil {
		return pool, nil
	}

	root, err := ca.RootCertificate(cert)
	if err != nil {
		// Fall back to the native root we already added to the pool.
		return pool, nil
	}

	xsigned, err := ca.getXSignedCertificates(root.Subject.CommonName)
	if err != nil || len(xsigned) == 0 {
		return pool, nil
	}

	for _, c := range xsigned {
		pool.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		}))
	}
	return pool, nil
}

// TrustedIntermediateCertPoolWithXSigner is the cross-sign-aware counterpart
// to TrustedIntermediateCertPool. See TrustedRootCertPoolWithXSigner for the
// semantics of xsigner.
//
// Thread-safe: Yes
func (ca *CA) TrustedIntermediateCertPoolWithXSigner(cert *x509.Certificate, xsigner crypto.Signer) (*x509.CertPool, error) {
	pool, err := ca.TrustedIntermediateCertPool(cert)
	if err != nil {
		return nil, err
	}
	if xsigner == nil {
		return pool, nil
	}

	ca.mu.RLock()
	intermediate := ca.intermediateCert
	ca.mu.RUnlock()

	if intermediate == nil {
		return pool, nil
	}

	xsigned, err := ca.getXSignedCertificates(intermediate.Subject.CommonName)
	if err != nil || len(xsigned) == 0 {
		return pool, nil
	}

	for _, c := range xsigned {
		pool.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		}))
	}
	return pool, nil
}

// ParseBundle parses a PEM-encoded certificate bundle into individual
// certificates. Empty input or input that contains no CERTIFICATE blocks
// returns ErrInvalidPEM so callers can cleanly distinguish missing bundles
// from genuinely unreadable ones.
//
// Thread-safe: Yes (pure function of its inputs)
func (ca *CA) ParseBundle(bundle []byte) ([]*x509.Certificate, error) {
	if len(bundle) == 0 {
		return nil, fmt.Errorf("%w: empty bundle", ErrInvalidPEM)
	}

	certs := make([]*x509.Certificate, 0)
	remaining := bundle
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("%w: failed to parse certificate: %v", ErrInvalidCertificate, err)
			}
			certs = append(certs, cert)
		}
		remaining = rest
		if len(rest) == 0 {
			break
		}
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("%w: no certificates found", ErrInvalidPEM)
	}
	return certs, nil
}

// RootCertificate walks the issuer chain starting from childCert and returns
// the self-signed root certificate that anchors it. The walk consults both
// the certificate store (via ca.certStore) and the CA's own cached root and
// intermediate certificates. A maximum of 10 hops is permitted to prevent
// pathological chains.
//
// Thread-safe: Yes
func (ca *CA) RootCertificate(childCert *x509.Certificate) (*x509.Certificate, error) {
	if childCert == nil {
		return nil, ErrInvalidCertificate
	}

	if childCert.Issuer.CommonName == childCert.Subject.CommonName {
		if !childCert.IsCA {
			return nil, fmt.Errorf("%w: self-signed non-CA certificate", ErrInvalidCertificateChain)
		}
		return childCert, nil
	}

	ca.mu.RLock()
	rootCert := ca.rootCert
	intermediateCert := ca.intermediateCert
	ca.mu.RUnlock()

	visited := make(map[string]bool)
	current := childCert
	for hop := 0; hop < 10; hop++ {
		if visited[current.Subject.CommonName] {
			return nil, fmt.Errorf("%w: circular chain detected", ErrInvalidCertificateChain)
		}
		visited[current.Subject.CommonName] = true

		issuerCN := current.Issuer.CommonName

		// Try the certificate store first.
		var issuerCert *x509.Certificate
		if ca.certStore != nil {
			if c, err := ca.certStore.GetCertificate(issuerCN); err == nil {
				issuerCert = c
			}
		}

		if issuerCert == nil {
			switch {
			case intermediateCert != nil && intermediateCert.Subject.CommonName == issuerCN:
				issuerCert = intermediateCert
			case rootCert != nil && rootCert.Subject.CommonName == issuerCN:
				return rootCert, nil
			default:
				return nil, fmt.Errorf("%w: issuer %s not found", ErrRootNotFound, issuerCN)
			}
		}

		if issuerCert.Issuer.CommonName == issuerCert.Subject.CommonName {
			if !issuerCert.IsCA {
				return nil, fmt.Errorf("%w: self-signed non-CA certificate", ErrInvalidCertificateChain)
			}
			return issuerCert, nil
		}

		current = issuerCert
	}
	return nil, fmt.Errorf("%w: chain too long", ErrInvalidCertificateChain)
}

// ImportIssuingCAs recursively downloads every certificate listed in the
// provided certificate's AuthorityInformationAccess (IssuingCertificateURL)
// extension and imports it into the certificate store. The walk stops at
// self-signed certificates. Existing certificates are skipped.
//
// Returns nil when cert has no AIA extension (not an error).
//
// Thread-safe: Yes (stateless once initialised)
func (ca *CA) ImportIssuingCAs(cert *x509.Certificate) error {
	if cert == nil {
		return ErrInvalidCertificate
	}
	if len(cert.IssuingCertificateURL) == 0 {
		return nil
	}

	for _, issuerURL := range cert.IssuingCertificateURL {
		// #nosec G107 - URL is from X.509 certificate AIA extension (issuer-controlled)
		resp, err := http.Get(issuerURL)
		if err != nil {
			return fmt.Errorf("%w: failed to download %s: %v", ErrStorageError, issuerURL, err)
		}

		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("%w: failed to read %s: %v", ErrStorageError, issuerURL, readErr)
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%w: AIA download %s returned status %d",
				ErrStorageError, issuerURL, resp.StatusCode)
		}

		issuerCert, err := parseAIACertificate(body)
		if err != nil {
			return fmt.Errorf("%w: %s: %v", ErrInvalidCertificate, issuerURL, err)
		}

		// Skip if the certificate already exists in the store.
		if existing, err := ca.certStore.GetCertificate(issuerCert.Subject.CommonName); err == nil && existing != nil {
			// Still recurse in case the parent chain hasn't been populated.
			if err := ca.ImportIssuingCAs(issuerCert); err != nil {
				return err
			}
			continue
		}

		if err := ca.ImportCertificate(issuerCert); err != nil {
			return err
		}

		if len(issuerCert.IssuingCertificateURL) > 0 {
			if err := ca.ImportIssuingCAs(issuerCert); err != nil {
				return err
			}
		}
	}
	return nil
}

// parseAIACertificate parses a certificate downloaded from an AIA URL.
// Both DER and PEM payloads are accepted because the TLS form used by AIA
// responses varies between deployments.
func parseAIACertificate(body []byte) (*x509.Certificate, error) {
	if cert, err := x509.ParseCertificate(body); err == nil {
		return cert, nil
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, fmt.Errorf("payload is neither DER nor PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// appendPEM is a small helper used by the cross-sign-aware pool builders.
//
//nolint:unused // retained for future pool construction helpers
func appendPEM(pool *x509.CertPool, cert *x509.Certificate) {
	pool.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}))
}

// bufferBytes is a helper used by tests to materialise an io.Reader into a
// known byte slice in a single statement.
//
//nolint:unused // retained for consumers that reuse this helper
func bufferBytes(r io.Reader) []byte {
	buf := new(bytes.Buffer)
	_, _ = io.Copy(buf, r)
	return buf.Bytes()
}
