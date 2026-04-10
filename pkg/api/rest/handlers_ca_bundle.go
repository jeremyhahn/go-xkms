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

package rest

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
)

// ContentTypePEMCertChain is the MIME type for PEM-encoded certificate chains.
// This is the standard content type used by ACME and PKI systems.
const ContentTypePEMCertChain = "application/pem-certificate-chain"

// CABundler defines the interface for retrieving CA certificate bundles.
// This interface must be implemented by CA providers to supply their
// certificate chain for trust establishment.
type CABundler interface {
	// CABundle returns the CA certificate chain in PEM format.
	// The bundle contains all certificates in the trust chain from the
	// issuing CA to the root CA, ordered from intermediate to root.
	CABundle() ([]byte, error)

	// CACertificate returns the CA's certificate.
	CACertificate() (*x509.Certificate, error)
}

// Typed errors for CA bundle operations.
var (
	ErrCABundlerNotConfigured = errors.New("rest: CA bundler not configured")
	ErrCABundleEmpty          = errors.New("rest: CA bundle is empty")
)

// caBundler holds the configured CA bundler for the REST API.
// This is set via SetCABundler and used by GetCABundleHandler.
var caBundler CABundler

// SetCABundler configures the CA bundler for the REST API.
// This must be called before GetCABundleHandler can be used.
func SetCABundler(bundler CABundler) {
	caBundler = bundler
}

// GetCABundler returns the configured CA bundler, or nil if not set.
func GetCABundler() CABundler {
	return caBundler
}

// GetCABundleHandler handles GET /api/v1/ca/bundle requests.
// Returns the CA certificate bundle in PEM format.
//
// This endpoint is used by bootstrap clients (DANE, SPKI, Direct) to retrieve
// CA certificates for trust establishment.
//
// Response headers:
//   - Content-Type: application/pem-certificate-chain
//   - Cache-Control: no-store
//
// Response body: PEM-encoded certificate chain (intermediate + root)
//
// Query parameters (optional):
//   - store_type: Filter by store type ("root", "intermediate")
//   - algorithm: Filter by algorithm ("RSA", "ECDSA", "Ed25519")
func (h *HandlerContext) GetCABundleHandler(w http.ResponseWriter, r *http.Request) {
	// Validate CA bundler is configured
	if caBundler == nil {
		writeError(w, ErrCABundlerNotConfigured, http.StatusServiceUnavailable)
		return
	}

	// Get query parameters for optional filtering
	storeType := r.URL.Query().Get("store_type")
	algorithm := r.URL.Query().Get("algorithm")

	// Get the CA bundle
	bundlePEM, err := caBundler.CABundle()
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	// Validate bundle is not empty
	if len(bundlePEM) == 0 {
		writeError(w, ErrCABundleEmpty, http.StatusNotFound)
		return
	}

	// Apply filters if specified
	if storeType != "" || algorithm != "" {
		bundlePEM, err = filterCABundlePEM(bundlePEM, storeType, algorithm)
		if err != nil {
			writeError(w, err, http.StatusInternalServerError)
			return
		}
	}

	// Check if bundle is empty after filtering
	if len(bundlePEM) == 0 {
		writeError(w, ErrCABundleEmpty, http.StatusNotFound)
		return
	}

	// Set response headers per RFC 5280 and ACME conventions
	w.Header().Set("Content-Type", ContentTypePEMCertChain)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	// Write the PEM-encoded bundle
	_, _ = w.Write(bundlePEM)
}

// filterCABundlePEM parses a PEM bundle, filters certificates, and re-encodes.
func filterCABundlePEM(bundlePEM []byte, storeType, algorithm string) ([]byte, error) {
	// Parse certificates from PEM
	certs, err := parsePEMCertificates(bundlePEM)
	if err != nil {
		return nil, err
	}

	// Apply filters
	filtered := filterCACertificates(certs, storeType, algorithm)

	// Re-encode to PEM
	return encodeCertsToPEM(filtered), nil
}

// parsePEMCertificates parses all PEM-encoded certificates from the given data.
func parsePEMCertificates(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemData

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

// encodeCertsToPEM encodes certificates to PEM format.
func encodeCertsToPEM(certs []*x509.Certificate) []byte {
	var result []byte
	for _, cert := range certs {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		result = append(result, pem.EncodeToMemory(block)...)
	}
	return result
}

// filterCACertificates filters certificates based on store type and algorithm.
func filterCACertificates(certs []*x509.Certificate, storeType, algorithm string) []*x509.Certificate {
	var filtered []*x509.Certificate

	for _, cert := range certs {
		// Apply store type filter
		if storeType != "" && !matchesCertStoreType(cert, storeType) {
			continue
		}

		// Apply algorithm filter
		if algorithm != "" && !matchesCertAlgorithm(cert, algorithm) {
			continue
		}

		filtered = append(filtered, cert)
	}

	return filtered
}

// storeTypeCertMatcher defines a function type for matching store types
type storeTypeCertMatcher func(cert *x509.Certificate) bool

// storeTypeCertMatchers provides O(1) lookup for store type matching
var storeTypeCertMatchers = map[string]storeTypeCertMatcher{
	"root": func(cert *x509.Certificate) bool {
		// Root certificates are self-signed CA certificates
		return cert.IsCA && cert.CheckSignatureFrom(cert) == nil
	},
	"intermediate": func(cert *x509.Certificate) bool {
		// Intermediate certificates are CA certificates that are not self-signed
		return cert.IsCA && cert.CheckSignatureFrom(cert) != nil
	},
	"leaf": func(cert *x509.Certificate) bool {
		// Leaf/end-entity certificates are not CA certificates
		return !cert.IsCA
	},
	"end-entity": func(cert *x509.Certificate) bool {
		// Alias for leaf
		return !cert.IsCA
	},
}

// matchesCertStoreType checks if a certificate matches the specified store type.
func matchesCertStoreType(cert *x509.Certificate, storeType string) bool {
	matcher, ok := storeTypeCertMatchers[storeType]
	if !ok {
		return false
	}
	return matcher(cert)
}

// algorithmCertMatcher defines a function type for matching algorithms
type algorithmCertMatcher func(alg x509.PublicKeyAlgorithm) bool

// algorithmCertMatchers provides O(1) lookup for algorithm matching
var algorithmCertMatchers = map[string]algorithmCertMatcher{
	"RSA":     func(alg x509.PublicKeyAlgorithm) bool { return alg == x509.RSA },
	"ECDSA":   func(alg x509.PublicKeyAlgorithm) bool { return alg == x509.ECDSA },
	"Ed25519": func(alg x509.PublicKeyAlgorithm) bool { return alg == x509.Ed25519 },
	"DSA":     func(alg x509.PublicKeyAlgorithm) bool { return alg == x509.DSA },
}

// matchesCertAlgorithm checks if a certificate's public key matches the specified algorithm.
func matchesCertAlgorithm(cert *x509.Certificate, algorithm string) bool {
	matcher, ok := algorithmCertMatchers[algorithm]
	if !ok {
		return false
	}
	return matcher(cert.PublicKeyAlgorithm)
}
