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

package grpc

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ContentTypePEMCertificateChain is the content type for PEM-encoded certificate chains.
const ContentTypePEMCertificateChain = "application/pem-certificate-chain"

// CABundler defines the interface for retrieving CA certificate bundles.
// This interface is implemented by CA providers that can return their
// certificate chain for trust establishment.
type CABundler interface {
	// CABundle returns the CA certificate chain in PEM format.
	// The bundle contains all certificates in the trust chain from the
	// issuing CA to the root CA, ordered from leaf to root.
	CABundle() ([]byte, error)

	// CACertificate returns the CA's certificate.
	CACertificate() (*x509.Certificate, error)
}

// CABundleFilter defines optional filters for CA bundle retrieval.
type CABundleFilter struct {
	// StoreType filters by certificate store type (e.g., "root", "intermediate").
	StoreType string

	// Algorithm filters by key algorithm (e.g., "RSA", "ECDSA", "Ed25519").
	Algorithm string
}

// Typed errors for CA bundle operations.
var (
	ErrCABundlerNotConfigured  = errors.New("grpc: CA bundler not configured")
	ErrCABundleEmpty           = errors.New("grpc: CA bundle is empty")
	ErrCertificateEncodeFailed = errors.New("grpc: failed to encode certificate")
)

// caBundler holds the configured CA bundler for the service.
// This is set via SetCABundler and used by GetCABundle.
var caBundler CABundler

// SetCABundler configures the CA bundler for the gRPC service.
// This must be called before GetCABundle can be used.
func SetCABundler(bundler CABundler) {
	caBundler = bundler
}

// GetCABundler returns the configured CA bundler, or nil if not set.
func GetCABundler() CABundler {
	return caBundler
}

// GetCABundle retrieves the CA certificate bundle.
//
// The handler returns PEM-encoded certificate chain and individual DER-encoded
// certificates. Optional filters can be applied via store_type and algorithm
// fields in the request.
//
// Response fields:
//   - bundle_pem: Complete certificate chain in PEM format
//   - certificates: Individual certificates in DER format
//   - content_type: "application/pem-certificate-chain"
func (s *Service) GetCABundle(ctx context.Context, req *pb.GetCABundleRequest) (*pb.GetCABundleResponse, error) {
	// Resolve the CA bundler: prefer explicit bundler (SetCABundler), fall back
	// to the CA instance (SetCA) which also implements CABundler via duck typing.
	bundler := caBundler
	if bundler == nil {
		ca := getCAInstance()
		if ca == nil {
			return nil, status.Error(codes.FailedPrecondition, ErrCABundlerNotConfigured.Error())
		}
		b, ok := ca.(CABundler)
		if !ok {
			return nil, status.Error(codes.FailedPrecondition, ErrCABundlerNotConfigured.Error())
		}
		bundler = b
	}

	if err := s.authorize(ctx, "certs", "read", ""); err != nil {
		return nil, err
	}
	// Build filter from request
	filter := &CABundleFilter{
		StoreType: req.GetStoreType(),
		Algorithm: req.GetAlgorithm(),
	}

	// Get the CA bundle
	bundlePEM, certs, err := getFilteredCABundle(bundler, filter)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get CA bundle: %v", err)
	}

	// Validate bundle is not empty
	if len(bundlePEM) == 0 {
		return nil, status.Error(codes.NotFound, ErrCABundleEmpty.Error())
	}

	// Convert certificates to DER format
	derCerts := make([][]byte, 0, len(certs))
	for _, cert := range certs {
		derCerts = append(derCerts, cert.Raw)
	}

	return &pb.GetCABundleResponse{
		BundlePem:    bundlePEM,
		Certificates: derCerts,
		ContentType:  ContentTypePEMCertificateChain,
	}, nil
}

// getFilteredCABundle retrieves the CA bundle with optional filtering.
// Returns the PEM-encoded bundle and the parsed certificates.
func getFilteredCABundle(bundler CABundler, filter *CABundleFilter) ([]byte, []*x509.Certificate, error) {
	// Get the raw PEM bundle
	bundlePEM, err := bundler.CABundle()
	if err != nil {
		return nil, nil, err
	}

	// Parse the certificates from PEM
	certs, err := parsePEMCertificatesFromBundle(bundlePEM)
	if err != nil {
		return nil, nil, err
	}

	// Apply filters if specified
	if filter.StoreType != "" || filter.Algorithm != "" {
		certs = filterCertificates(certs, filter)
	}

	// If filters were applied, rebuild the PEM bundle
	if filter.StoreType != "" || filter.Algorithm != "" {
		bundlePEM, err = encodeCertificatesToPEM(certs)
		if err != nil {
			return nil, nil, err
		}
	}

	return bundlePEM, certs, nil
}

// parsePEMCertificatesFromBundle parses all PEM-encoded certificates from the given data.
// This is named differently from the truststore version to avoid conflicts.
func parsePEMCertificatesFromBundle(pemData []byte) ([]*x509.Certificate, error) {
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

// encodeCertificatesToPEM encodes certificates to PEM format.
func encodeCertificatesToPEM(certs []*x509.Certificate) ([]byte, error) {
	var result []byte
	for _, cert := range certs {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		result = append(result, pem.EncodeToMemory(block)...)
	}
	return result, nil
}

// filterCertificates filters certificates based on the provided filter criteria.
func filterCertificates(certs []*x509.Certificate, filter *CABundleFilter) []*x509.Certificate {
	if filter == nil {
		return certs
	}

	var filtered []*x509.Certificate
	for _, cert := range certs {
		// Apply store type filter
		if filter.StoreType != "" && !matchesStoreType(cert, filter.StoreType) {
			continue
		}

		// Apply algorithm filter
		if filter.Algorithm != "" && !matchesAlgorithm(cert, filter.Algorithm) {
			continue
		}

		filtered = append(filtered, cert)
	}

	return filtered
}

// storeTypeMatcher defines a function type for matching store types
type storeTypeMatcher func(cert *x509.Certificate) bool

// storeTypeMatchers provides O(1) lookup for store type matching
var storeTypeMatchers = map[string]storeTypeMatcher{
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

// matchesStoreType checks if a certificate matches the specified store type.
// Store types can be "root", "intermediate", or custom types based on
// certificate properties (e.g., BasicConstraints, IsCA).
func matchesStoreType(cert *x509.Certificate, storeType string) bool {
	matcher, ok := storeTypeMatchers[storeType]
	if !ok {
		// Unknown store type, no match
		return false
	}
	return matcher(cert)
}

// algorithmMatcher defines a function type for matching algorithms
type algorithmMatcher func(alg x509.PublicKeyAlgorithm) bool

// algorithmMatchers provides O(1) lookup for algorithm matching
var algorithmMatchers = map[string]algorithmMatcher{
	"RSA":     func(alg x509.PublicKeyAlgorithm) bool { return alg == x509.RSA },
	"ECDSA":   func(alg x509.PublicKeyAlgorithm) bool { return alg == x509.ECDSA },
	"Ed25519": func(alg x509.PublicKeyAlgorithm) bool { return alg == x509.Ed25519 },
	"DSA":     func(alg x509.PublicKeyAlgorithm) bool { return alg == x509.DSA },
}

// matchesAlgorithm checks if a certificate's public key matches the specified algorithm.
func matchesAlgorithm(cert *x509.Certificate, algorithm string) bool {
	matcher, ok := algorithmMatchers[algorithm]
	if !ok {
		return false
	}
	return matcher(cert.PublicKeyAlgorithm)
}

// algorithmNames provides O(1) lookup for algorithm names
var algorithmNames = map[x509.PublicKeyAlgorithm]string{
	x509.RSA:     "RSA",
	x509.ECDSA:   "ECDSA",
	x509.Ed25519: "Ed25519",
	x509.DSA:     "DSA",
}

// getPublicKeyAlgorithmName returns the algorithm name for a certificate's public key.
// This is named differently to avoid conflicts with other functions in the package.
func getPublicKeyAlgorithmName(cert *x509.Certificate) string {
	name, ok := algorithmNames[cert.PublicKeyAlgorithm]
	if !ok {
		return "Unknown"
	}
	return name
}
