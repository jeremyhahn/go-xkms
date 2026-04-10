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

package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sort"
	"strings"
)

// Bundle errors indicate issues with CA bundle operations.
var (
	// ErrNoCACertificates indicates no CA certificates are available.
	ErrNoCACertificates = errors.New("ca: no ca certificates available")

	// ErrNoCertificatesMatch indicates no certificates match the filter criteria.
	ErrNoCertificatesMatch = errors.New("ca: no certificates match filter criteria")

	// ErrPEMEncodingFailed indicates PEM encoding failed.
	ErrPEMEncodingFailed = errors.New("ca: pem encoding failed")

	// ErrNilCertificate indicates a nil certificate was provided.
	ErrNilCertificate = errors.New("ca: nil certificate provided")
)

// StoreType constants for filtering certificates by key store type.
const (
	StoreTypeSoftware = "software"
	StoreTypeTPM2     = "tpm2"
	StoreTypePKCS11   = "pkcs11"
	StoreTypeAll      = "" // Empty string matches all store types
)

// Algorithm constants for filtering certificates by key algorithm.
const (
	AlgorithmRSA     = "RSA"
	AlgorithmECDSA   = "ECDSA"
	AlgorithmEd25519 = "Ed25519"
	AlgorithmAll     = "" // Empty string matches all algorithms
)

// CABundler provides CA certificate bundles for trust store population.
//
// CABundler allows retrieving CA certificates as PEM-encoded bundles or
// as individual x509.Certificate objects. Certificates can be filtered
// by store type (software, tpm2, pkcs11) and algorithm (RSA, ECDSA, Ed25519).
//
// The bundle ordering follows standard PKI conventions with intermediate
// certificates first and root certificates last.
//
// Thread-safe: Implementations must be thread-safe.
type CABundler interface {
	// CABundle returns the CA certificate bundle as PEM-encoded data.
	//
	// The storeType parameter filters certificates by their key store type:
	//   - "software": Software-backed keys (PKCS#8)
	//   - "tpm2": TPM 2.0 backed keys
	//   - "pkcs11": HSM-backed keys (PKCS#11)
	//   - "": All store types (no filtering)
	//
	// The algorithm parameter filters certificates by public key algorithm:
	//   - "RSA": RSA keys
	//   - "ECDSA": ECDSA keys
	//   - "Ed25519": Ed25519 keys
	//   - "": All algorithms (no filtering)
	//
	// The returned PEM data contains certificates ordered from intermediate
	// to root (leaf-most first, root last) for proper chain building.
	//
	// Returns ErrNoCACertificates if no certificates are available.
	// Returns ErrNoCertificatesMatch if no certificates match the filter.
	// Returns ErrPEMEncodingFailed if PEM encoding fails.
	//
	// Thread-safe: Yes
	CABundle(storeType, algorithm string) ([]byte, error)

	// CABundleCerts returns the CA certificates as individual x509.Certificate objects.
	//
	// The storeType and algorithm parameters work the same as CABundle.
	//
	// The returned certificates are ordered from intermediate to root
	// (leaf-most first, root last) for proper chain building.
	//
	// Returns ErrNoCACertificates if no certificates are available.
	// Returns ErrNoCertificatesMatch if no certificates match the filter.
	//
	// Thread-safe: Yes
	CABundleCerts(storeType, algorithm string) ([]*x509.Certificate, error)
}

// CertificateProvider provides certificate metadata for filtering.
//
// This interface allows the bundler to access metadata about certificates
// beyond what is available in the x509.Certificate structure, such as
// the store type where the certificate's key is held.
type CertificateProvider interface {
	// Certificate returns the x509.Certificate.
	Certificate() *x509.Certificate

	// StoreType returns the store type (software, tpm2, pkcs11).
	StoreType() string
}

// SimpleCertificate is a basic implementation of CertificateProvider.
//
// Use this when certificates are loaded without store type metadata.
// The store type defaults to empty string which matches all filters.
type SimpleCertificate struct {
	cert      *x509.Certificate
	storeType string
}

// NewSimpleCertificate creates a new SimpleCertificate.
func NewSimpleCertificate(cert *x509.Certificate, storeType string) *SimpleCertificate {
	return &SimpleCertificate{
		cert:      cert,
		storeType: storeType,
	}
}

// Certificate returns the x509.Certificate.
func (s *SimpleCertificate) Certificate() *x509.Certificate {
	return s.cert
}

// StoreType returns the store type.
func (s *SimpleCertificate) StoreType() string {
	return s.storeType
}

// DefaultCABundler is the default implementation of CABundler.
//
// DefaultCABundler holds a collection of CA certificates and provides
// filtering and bundle generation capabilities. Certificates can be
// provided either as raw x509.Certificate objects (via the simple
// constructor) or as CertificateProvider objects for full metadata support.
type DefaultCABundler struct {
	providers []CertificateProvider
}

// NewDefaultCABundler creates a new DefaultCABundler with the given certificates.
//
// This is a convenience constructor for cases where store type metadata
// is not needed. All certificates are treated as having an empty store type,
// which matches all store type filters.
//
// The certificates should include all CA certificates in the trust chain.
// Ordering in the input slice does not matter; the bundler will sort
// certificates appropriately when generating bundles.
func NewDefaultCABundler(certs []*x509.Certificate) *DefaultCABundler {
	providers := make([]CertificateProvider, 0, len(certs))
	for _, cert := range certs {
		if cert != nil {
			providers = append(providers, &SimpleCertificate{cert: cert, storeType: ""})
		}
	}
	return &DefaultCABundler{providers: providers}
}

// NewDefaultCABundlerWithProviders creates a new DefaultCABundler with certificate providers.
//
// This constructor allows full control over certificate metadata including
// store type information for filtering.
func NewDefaultCABundlerWithProviders(providers []CertificateProvider) *DefaultCABundler {
	validProviders := make([]CertificateProvider, 0, len(providers))
	for _, p := range providers {
		if p != nil && p.Certificate() != nil {
			validProviders = append(validProviders, p)
		}
	}
	return &DefaultCABundler{providers: validProviders}
}

// algorithmFilter is a function type for algorithm-based certificate filtering.
type algorithmFilter func(*x509.Certificate) bool

// algorithmFilters maps algorithm names to their filter functions.
var algorithmFilters = map[string]algorithmFilter{
	AlgorithmRSA:     isRSACertificate,
	AlgorithmECDSA:   isECDSACertificate,
	AlgorithmEd25519: isEd25519Certificate,
	AlgorithmAll:     matchAllAlgorithms,
}

// isRSACertificate returns true if the certificate uses an RSA public key.
func isRSACertificate(cert *x509.Certificate) bool {
	_, ok := cert.PublicKey.(*rsa.PublicKey)
	return ok
}

// isECDSACertificate returns true if the certificate uses an ECDSA public key.
func isECDSACertificate(cert *x509.Certificate) bool {
	_, ok := cert.PublicKey.(*ecdsa.PublicKey)
	return ok
}

// isEd25519Certificate returns true if the certificate uses an Ed25519 public key.
func isEd25519Certificate(cert *x509.Certificate) bool {
	_, ok := cert.PublicKey.(ed25519.PublicKey)
	return ok
}

// matchAllAlgorithms always returns true (no algorithm filtering).
func matchAllAlgorithms(_ *x509.Certificate) bool {
	return true
}

// CABundle returns the CA certificate bundle as PEM-encoded data.
func (b *DefaultCABundler) CABundle(storeType, algorithm string) ([]byte, error) {
	certs, err := b.CABundleCerts(storeType, algorithm)
	if err != nil {
		return nil, err
	}

	return encodeCertsToPEM(certs)
}

// CABundleCerts returns the CA certificates as individual x509.Certificate objects.
func (b *DefaultCABundler) CABundleCerts(storeType, algorithm string) ([]*x509.Certificate, error) {
	if len(b.providers) == 0 {
		return nil, ErrNoCACertificates
	}

	filtered := b.filterCertificates(storeType, algorithm)
	if len(filtered) == 0 {
		return nil, ErrNoCertificatesMatch
	}

	return sortCertificatesForBundle(filtered), nil
}

// filterCertificates applies store type and algorithm filters to the certificate collection.
func (b *DefaultCABundler) filterCertificates(storeType, algorithm string) []*x509.Certificate {
	// Normalize filter inputs
	normalizedStoreType := strings.ToLower(strings.TrimSpace(storeType))
	normalizedAlgorithm := strings.TrimSpace(algorithm)

	// Get algorithm filter function
	algFilter, ok := algorithmFilters[normalizedAlgorithm]
	if !ok {
		// Unknown algorithm - try case-insensitive match
		for key, filter := range algorithmFilters {
			if strings.EqualFold(key, normalizedAlgorithm) {
				algFilter = filter
				break
			}
		}
		if algFilter == nil {
			// No match found, no certificates will match
			return nil
		}
	}

	var filtered []*x509.Certificate
	for _, provider := range b.providers {
		cert := provider.Certificate()
		if cert == nil {
			continue
		}

		// Apply store type filter
		if normalizedStoreType != "" {
			providerStoreType := strings.ToLower(strings.TrimSpace(provider.StoreType()))
			if providerStoreType != "" && providerStoreType != normalizedStoreType {
				continue
			}
		}

		// Apply algorithm filter
		if !algFilter(cert) {
			continue
		}

		// Certificate passes all filters
		filtered = append(filtered, cert)
	}

	return filtered
}

// sortCertificatesForBundle sorts certificates for proper chain ordering.
//
// The ordering places intermediate certificates first and root certificates last.
// This follows the standard PKI convention where the chain is built from
// the issuing CA toward the trust anchor.
//
// Sorting criteria:
// 1. Non-self-signed (intermediate) certificates come before self-signed (root)
// 2. Within each group, sort by path length (higher path length first)
// 3. Within same path length, sort by subject for deterministic ordering
func sortCertificatesForBundle(certs []*x509.Certificate) []*x509.Certificate {
	if len(certs) <= 1 {
		return certs
	}

	// Create a copy to avoid modifying the input
	sorted := make([]*x509.Certificate, len(certs))
	copy(sorted, certs)

	sort.Slice(sorted, func(i, j int) bool {
		certI := sorted[i]
		certJ := sorted[j]

		// Self-signed certificates (roots) go last
		selfSignedI := isSelfSigned(certI)
		selfSignedJ := isSelfSigned(certJ)

		if selfSignedI != selfSignedJ {
			// Intermediate (non-self-signed) before root (self-signed)
			return !selfSignedI
		}

		// Both are same type (both intermediate or both root)
		// Sort by path length constraint (higher constraint = closer to leaf)
		pathLenI := getEffectivePathLen(certI)
		pathLenJ := getEffectivePathLen(certJ)

		if pathLenI != pathLenJ {
			return pathLenI > pathLenJ
		}

		// Same path length - sort by subject for deterministic ordering
		return certI.Subject.String() < certJ.Subject.String()
	})

	return sorted
}

// isSelfSigned returns true if the certificate is self-signed.
func isSelfSigned(cert *x509.Certificate) bool {
	return cert.Subject.String() == cert.Issuer.String()
}

// getEffectivePathLen returns the effective path length constraint.
// Returns -1 for certificates without a path length constraint (unlimited).
// Returns the actual MaxPathLen for certificates with a constraint.
func getEffectivePathLen(cert *x509.Certificate) int {
	if !cert.IsCA {
		return -2 // Non-CA certificates sort first among non-roots
	}

	if cert.MaxPathLenZero {
		return 0
	}

	if cert.MaxPathLen > 0 {
		return cert.MaxPathLen
	}

	// No path length constraint (unlimited)
	return -1
}

// encodeCertsToPEM encodes a slice of certificates to PEM format.
func encodeCertsToPEM(certs []*x509.Certificate) ([]byte, error) {
	var buf bytes.Buffer

	for _, cert := range certs {
		if cert == nil {
			continue
		}

		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}

		if err := pem.Encode(&buf, block); err != nil {
			return nil, ErrPEMEncodingFailed
		}
	}

	if buf.Len() == 0 {
		return nil, ErrNoCACertificates
	}

	return buf.Bytes(), nil
}

// AddCertificate adds a certificate to the bundler.
//
// Thread-safe: No. External synchronization required for concurrent access.
func (b *DefaultCABundler) AddCertificate(cert *x509.Certificate, storeType string) error {
	if cert == nil {
		return ErrNilCertificate
	}

	b.providers = append(b.providers, &SimpleCertificate{
		cert:      cert,
		storeType: storeType,
	})

	return nil
}

// AddProvider adds a certificate provider to the bundler.
//
// Thread-safe: No. External synchronization required for concurrent access.
func (b *DefaultCABundler) AddProvider(provider CertificateProvider) error {
	if provider == nil || provider.Certificate() == nil {
		return ErrNilCertificate
	}

	b.providers = append(b.providers, provider)
	return nil
}

// Count returns the number of certificates in the bundler.
func (b *DefaultCABundler) Count() int {
	return len(b.providers)
}

// Clear removes all certificates from the bundler.
//
// Thread-safe: No. External synchronization required for concurrent access.
func (b *DefaultCABundler) Clear() {
	b.providers = nil
}
