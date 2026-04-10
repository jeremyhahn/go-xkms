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
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// ContentTypePEMCertificateChain is the MIME type for PEM-encoded certificate chains.
const ContentTypePEMCertificateChain = "application/pem-certificate-chain"

// Config holds configuration for the embedded CA service.
type Config struct {
	// HomeDir is the base directory for CA storage.
	HomeDir string `yaml:"home-dir" json:"home_dir" mapstructure:"home-dir"`

	// DefaultValidityDays is the default validity period for issued certificates.
	DefaultValidityDays int `yaml:"default-validity-days" json:"default_validity_days" mapstructure:"default-validity-days"`
}

// Service provides CA operations for the embedded transport by delegating
// to a go-xkms TCGCA instance. It implements the standard CA methods from
// the XKMSServicer interface plus TCG Trusted Computing operations for
// TPM device identity and attestation key certificate management.
//
// This service does not implement the full XKMSServicer interface. It
// provides only the CA methods that a composite service can mix in alongside
// other service implementations for key management, attestation, etc.
//
// Thread-safe: Yes, delegates to thread-safe TCGCA.
type Service struct {
	config *Config
	ca     ca.TCGCA
}

// NewService creates a new embedded CA service wrapping the given TCGCA.
//
// The config parameter provides service-level configuration. The tcgCA
// parameter must be an initialized TCGCA instance ready for operations.
//
// Returns ErrNilConfig if config is nil.
// Returns ErrNilCA if tcgCA is nil.
func NewService(config *Config, tcgCA ca.TCGCA) (*Service, error) {
	if config == nil {
		return nil, ErrNilConfig
	}
	if tcgCA == nil {
		return nil, ErrNilCA
	}
	return &Service{
		config: config,
		ca:     tcgCA,
	}, nil
}

// CA returns the underlying TCGCA instance.
func (s *Service) CA() ca.TCGCA {
	return s.ca
}

// IssueEKCertificate issues an Endorsement Key certificate per TCG EK
// Credential Profile. The request provides subject/SAN information, and
// ekPubKey is the EK public key extracted from the TPM.
func (s *Service) IssueEKCertificate(request *ca.CertificateRequest, ekPubKey crypto.PublicKey) (*x509.Certificate, error) {
	if request == nil {
		return nil, ErrNilRequest
	}
	cert, err := s.ca.IssueEKCertificate(request, ekPubKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTCGCertIssuance, err)
	}
	return cert, nil
}

// IssueAKCertificate issues an Attestation Key certificate per TCG spec.
// The request provides subject/SAN information, and pubKey is the AK
// public key extracted from the TPM.
func (s *Service) IssueAKCertificate(request *ca.CertificateRequest, pubKey crypto.PublicKey) (*x509.Certificate, error) {
	if request == nil {
		return nil, ErrNilRequest
	}
	cert, err := s.ca.IssueAKCertificate(request, pubKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTCGCertIssuance, err)
	}
	return cert, nil
}

// SignTCGCSRIDevID verifies and signs a TCG-CSR-IDEVID, issuing both IAK
// and IDevID certificates. Returns DER-encoded IAK and IDevID certificates.
func (s *Service) SignTCGCSRIDevID(tcgCSR *tpm2.TCG_CSR_IDEVID, request *ca.CertificateRequest) (iakDER, idevidDER []byte, err error) {
	if tcgCSR == nil {
		return nil, nil, ErrNilTCGCSR
	}
	if request == nil {
		return nil, nil, ErrNilRequest
	}
	iakDER, idevidDER, err = s.ca.SignTCGCSRIDevID(tcgCSR, request)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrTCGCSRSigning, err)
	}
	return iakDER, idevidDER, nil
}

// EnrollDevice performs complete TCG enrollment: verifies the packed CSR,
// generates a MakeCredential challenge, and prepares certificates. The
// caller must complete the ActivateCredential challenge/response before
// delivering the certificates to the device.
func (s *Service) EnrollDevice(packedCSR []byte, request *ca.CertificateRequest) (*ca.TCGEnrollmentResult, error) {
	if len(packedCSR) == 0 {
		return nil, ErrEmptyPackedCSR
	}
	if request == nil {
		return nil, ErrNilRequest
	}
	result, err := s.ca.EnrollDevice(packedCSR, request)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTCGEnrollment, err)
	}
	return result, nil
}

// SetTPM configures the TPM instance for enrollment operations requiring
// MakeCredentialWithExternalEK (server-side credential challenge).
func (s *Service) SetTPM(tpm tpm2.TrustedPlatformModule) {
	s.ca.SetTPM(tpm)
}

// GetCABundle retrieves the CA certificate bundle.
//
// The request may include optional StoreType and Algorithm filters. The
// response contains the PEM-encoded certificate chain, individual DER-encoded
// certificates, and the content type.
func (s *Service) GetCABundle(_ context.Context, req *transport.GetCABundleRequest) (*transport.GetCABundleResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	bundlePEM, err := s.ca.CABundle()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBundleGeneration, err)
	}

	// Parse individual certificates from the PEM bundle.
	derCerts := parsePEMCertificates(bundlePEM)

	// Apply optional algorithm filter.
	if req.Algorithm != "" {
		derCerts = filterByAlgorithm(derCerts, req.Algorithm)
		// Re-encode after filtering.
		bundlePEM = encodeDERCertsToPEM(derCerts)
	}

	// Build the DER certificate list for the response.
	certificates := make([][]byte, len(derCerts))
	copy(certificates, derCerts)

	return &transport.GetCABundleResponse{
		BundlePEM:    bundlePEM,
		Certificates: certificates,
		ContentType:  ContentTypePEMCertificateChain,
	}, nil
}

// GetCACertificate retrieves the CA certificate.
//
// The Identity field in the request is currently unused; the service always
// returns the certificate from the configured XKMSCA.
func (s *Service) GetCACertificate(_ context.Context, req *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	cert, err := s.ca.CACertificate()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCACertificateRetrieval, err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	if certPEM == nil {
		return nil, ErrPEMEncoding
	}

	return &transport.GetCACertificateResponse{
		CertificatePEM: certPEM,
		Subject:        cert.Subject.String(),
		Issuer:         cert.Issuer.String(),
		SerialNumber:   cert.SerialNumber.Text(10),
		NotBefore:      cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
		NotAfter:       cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		IsCA:           cert.IsCA,
	}, nil
}

// SignCSR signs a certificate signing request and returns the issued certificate.
//
// The CSRPEM field must contain a valid PEM-encoded PKCS#10 CSR. The optional
// Profile field selects a certificate profile, and ValidityDays overrides
// the default validity period.
func (s *Service) SignCSR(_ context.Context, req *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if len(req.CSRPEM) == 0 {
		return nil, ErrEmptyCSR
	}

	opts := &ca.SignOptions{
		Profile:      req.Profile,
		ValidityDays: req.ValidityDays,
	}

	cert, err := s.ca.SignCSR(req.CSRPEM, opts)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCSRSigning, err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	if certPEM == nil {
		return nil, ErrPEMEncoding
	}

	// Get the CA chain for the response.
	chainPEM, chainErr := s.ca.CABundle()
	if chainErr != nil {
		// Chain is optional; return the signed certificate without it.
		chainPEM = nil
	}

	return &transport.SignCSRResponse{
		CertificatePEM: certPEM,
		ChainPEM:       chainPEM,
		SerialNumber:   cert.SerialNumber.Text(10),
	}, nil
}

// IssueCertificate generates a new key pair and issues a certificate.
//
// The CommonName field is required. Optional fields include Organization,
// SANs, ValidityDays, Algorithm, and Profile.
func (s *Service) IssueCertificate(_ context.Context, req *transport.IssueCertificateRequest) (*transport.IssueCertificateResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.CommonName == "" {
		return nil, ErrEmptyCommonName
	}

	// Build the certificate request from the transport request.
	certReq := &ca.CertificateRequest{
		Subject: ca.Subject{
			CommonName:   req.CommonName,
			Organization: req.Organization,
		},
		Valid: req.ValidityDays,
	}

	// Parse SANs from the request.
	if len(req.SANs) > 0 {
		certReq.SANS = parseSANs(req.SANs)
	}

	var issued *ca.IssuedCertificate
	var err error

	if req.Profile != "" {
		issued, err = s.ca.IssueCertificateWithProfile(certReq, req.Profile)
	} else {
		issued, err = s.ca.IssueCertificate(certReq)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCertificateIssuance, err)
	}

	return &transport.IssueCertificateResponse{
		CertificatePEM: issued.CertificatePEM,
		ChainPEM:       issued.ChainPEM,
		PrivateKeyPEM:  issued.PrivateKeyPEM,
		SerialNumber:   issued.SerialNumber.Text(10),
	}, nil
}

// RevokeCertificate revokes a certificate by its serial number.
//
// The SerialNumber field must contain a decimal string representation of
// the certificate's serial number. The Reason field should be an RFC 5280
// CRLReason code.
func (s *Service) RevokeCertificate(_ context.Context, req *transport.RevokeCertificateRequest) (*transport.RevokeCertificateResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.SerialNumber == "" {
		return nil, ErrEmptySerialNumber
	}

	serial, ok := new(big.Int).SetString(req.SerialNumber, 10)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrInvalidSerialNumber, req.SerialNumber)
	}

	if err := s.ca.Revoke(serial, req.Reason); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCertificateRevocation, err)
	}

	return &transport.RevokeCertificateResponse{
		Success: true,
		Message: "certificate revoked",
	}, nil
}

// GenerateCRL generates a Certificate Revocation List.
//
// The request is currently empty; the CA uses its configured defaults
// for CRL generation parameters.
func (s *Service) GenerateCRL(_ context.Context, req *transport.GenerateCRLRequest) (*transport.GenerateCRLResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	crlDER, err := s.ca.GenerateCRL()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCRLGeneration, err)
	}

	crlPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlDER,
	})
	if crlPEM == nil {
		return nil, ErrPEMEncoding
	}

	return &transport.GenerateCRLResponse{
		CRLPEM: crlPEM,
	}, nil
}

// IsRevoked checks whether a certificate with the given serial number
// has been revoked.
//
// The SerialNumber field must contain a decimal string representation of
// the certificate's serial number.
func (s *Service) IsRevoked(_ context.Context, req *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.SerialNumber == "" {
		return nil, ErrEmptySerialNumber
	}

	serial, ok := new(big.Int).SetString(req.SerialNumber, 10)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrInvalidSerialNumber, req.SerialNumber)
	}

	revoked, err := s.ca.IsRevoked(serial)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRevocationCheck, err)
	}

	return &transport.IsRevokedResponse{
		Revoked: revoked,
	}, nil
}

// parseSANs converts a string slice of SANs into a SubjectAlternativeNames
// structure. Each entry is prefixed with its type: "DNS:", "IP:", "Email:".
// Entries without a recognized prefix are treated as DNS names.
func parseSANs(sans []string) *ca.SubjectAlternativeNames {
	result := &ca.SubjectAlternativeNames{}

	for _, san := range sans {
		switch {
		case strings.HasPrefix(san, "DNS:"):
			result.DNS = append(result.DNS, strings.TrimPrefix(san, "DNS:"))
		case strings.HasPrefix(san, "IP:"):
			result.IPs = append(result.IPs, strings.TrimPrefix(san, "IP:"))
		case strings.HasPrefix(san, "Email:"):
			result.Email = append(result.Email, strings.TrimPrefix(san, "Email:"))
		case strings.HasPrefix(san, "URI:"):
			result.URIs = append(result.URIs, strings.TrimPrefix(san, "URI:"))
		default:
			// Default to DNS name for untyped entries.
			result.DNS = append(result.DNS, san)
		}
	}

	return result
}

// parsePEMCertificates extracts DER-encoded certificate bytes from PEM data.
func parsePEMCertificates(pemData []byte) [][]byte {
	var certs [][]byte
	rest := pemData

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certs = append(certs, block.Bytes)
		}
	}

	return certs
}

// filterByAlgorithm filters DER-encoded certificates by public key algorithm name.
// An empty algorithm string matches all certificates.
func filterByAlgorithm(derCerts [][]byte, algorithm string) [][]byte {
	if algorithm == "" {
		return derCerts
	}

	normalizedAlg := strings.ToUpper(strings.TrimSpace(algorithm))
	filtered := make([][]byte, 0, len(derCerts))

	for _, der := range derCerts {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		if matchesAlgorithmName(cert.PublicKeyAlgorithm.String(), normalizedAlg) {
			filtered = append(filtered, der)
		}
	}

	return filtered
}

// matchesAlgorithmName performs a case-insensitive comparison between the
// certificate's algorithm name and the requested algorithm filter.
func matchesAlgorithmName(certAlg, requestedAlg string) bool {
	return strings.ToUpper(certAlg) == requestedAlg
}

// encodeDERCertsToPEM encodes DER certificate bytes back to PEM format.
func encodeDERCertsToPEM(derCerts [][]byte) []byte {
	var result []byte
	for _, der := range derCerts {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		}
		result = append(result, pem.EncodeToMemory(block)...)
	}
	return result
}
