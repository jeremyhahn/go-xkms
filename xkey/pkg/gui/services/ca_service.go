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

package services

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// CAService errors.
var (
	// ErrCAServiceNilClient indicates the CA service has no connected client.
	ErrCAServiceNilClient = errors.New("ca_service: nil client")

	// ErrCAServiceInvalidPEM indicates the PEM data could not be parsed.
	ErrCAServiceInvalidPEM = errors.New("ca_service: invalid PEM data")

	// ErrCAServiceInvalidCSR indicates the CSR PEM data is empty or invalid.
	ErrCAServiceInvalidCSR = errors.New("ca_service: invalid CSR PEM")

	// ErrCAServiceInvalidSerial indicates the serial number is empty.
	ErrCAServiceInvalidSerial = errors.New("ca_service: invalid serial number")

	// ErrCAServiceInvalidCommonName indicates the common name is empty.
	ErrCAServiceInvalidCommonName = errors.New("ca_service: common name is required")
)

// CACertInfo is a JSON-friendly CA certificate representation for the frontend.
type CACertInfo struct {
	Subject   string `json:"subject"`
	Issuer    string `json:"issuer"`
	Serial    string `json:"serial"`
	Algorithm string `json:"algorithm"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	IsCA      bool   `json:"is_ca"`
}

// IssuedCertInfo represents an issued certificate for the frontend.
type IssuedCertInfo struct {
	Serial         string `json:"serial"`
	Subject        string `json:"subject"`
	Issuer         string `json:"issuer"`
	Algorithm      string `json:"algorithm"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	CertificatePEM string `json:"certificate_pem"`
	ChainPEM       string `json:"chain_pem"`
	PrivateKeyPEM  string `json:"private_key_pem,omitempty"`
}

// CAService provides CA operations for the GUI frontend.
type CAService struct {
	client transport.Client
}

// NewCAService creates a new CAService.
func NewCAService(client transport.Client) *CAService {
	return &CAService{client: client}
}

// GetCAInfo retrieves the CA certificate and returns its parsed fields.
func (s *CAService) GetCAInfo() (*CACertInfo, error) {
	if s.client == nil {
		return nil, ErrCAServiceNilClient
	}

	resp, err := s.client.GetCACertificate(context.Background(), &transport.GetCACertificateRequest{})
	if err != nil {
		return nil, err
	}

	cert, parseErr := parsePEMCertificate(resp.CertificatePEM)
	if parseErr != nil {
		// Fall back to the response fields if PEM parsing fails.
		return &CACertInfo{
			Subject:   resp.Subject,
			Issuer:    resp.Issuer,
			Serial:    resp.SerialNumber,
			NotBefore: resp.NotBefore,
			NotAfter:  resp.NotAfter,
			IsCA:      resp.IsCA,
		}, nil
	}

	return &CACertInfo{
		Subject:   cert.Subject.String(),
		Issuer:    cert.Issuer.String(),
		Serial:    cert.SerialNumber.String(),
		Algorithm: cert.PublicKeyAlgorithm.String(),
		NotBefore: cert.NotBefore.Format(time.RFC3339),
		NotAfter:  cert.NotAfter.Format(time.RFC3339),
		IsCA:      cert.IsCA,
	}, nil
}

// IssueCertificate issues a new certificate with the specified parameters.
// The sans parameter is a comma-separated list of Subject Alternative Names.
func (s *CAService) IssueCertificate(profile, commonName, organization, sans string, validityDays int, algorithm string) (*IssuedCertInfo, error) {
	if s.client == nil {
		return nil, ErrCAServiceNilClient
	}
	if commonName == "" {
		return nil, ErrCAServiceInvalidCommonName
	}

	sanList := parseSANs(sans)

	resp, err := s.client.IssueCertificate(context.Background(), &transport.IssueCertificateRequest{
		Profile:      profile,
		CommonName:   commonName,
		Organization: organization,
		SANs:         sanList,
		ValidityDays: validityDays,
		Algorithm:    algorithm,
	})
	if err != nil {
		return nil, err
	}

	info := &IssuedCertInfo{
		Serial:         resp.SerialNumber,
		CertificatePEM: string(resp.CertificatePEM),
		ChainPEM:       string(resp.ChainPEM),
		PrivateKeyPEM:  string(resp.PrivateKeyPEM),
	}

	cert, parseErr := parsePEMCertificate(resp.CertificatePEM)
	if parseErr == nil {
		info.Subject = cert.Subject.String()
		info.Issuer = cert.Issuer.String()
		info.Algorithm = cert.PublicKeyAlgorithm.String()
		info.NotBefore = cert.NotBefore.Format(time.RFC3339)
		info.NotAfter = cert.NotAfter.Format(time.RFC3339)
	}

	return info, nil
}

// SignCSR signs a PEM-encoded certificate signing request.
func (s *CAService) SignCSR(csrPEM string, profile string) (*IssuedCertInfo, error) {
	if s.client == nil {
		return nil, ErrCAServiceNilClient
	}
	if strings.TrimSpace(csrPEM) == "" {
		return nil, ErrCAServiceInvalidCSR
	}

	resp, err := s.client.SignCSR(context.Background(), &transport.SignCSRRequest{
		CSRPEM:  []byte(csrPEM),
		Profile: profile,
	})
	if err != nil {
		return nil, err
	}

	info := &IssuedCertInfo{
		Serial:         resp.SerialNumber,
		CertificatePEM: string(resp.CertificatePEM),
		ChainPEM:       string(resp.ChainPEM),
	}

	cert, parseErr := parsePEMCertificate(resp.CertificatePEM)
	if parseErr == nil {
		info.Subject = cert.Subject.String()
		info.Issuer = cert.Issuer.String()
		info.Algorithm = cert.PublicKeyAlgorithm.String()
		info.NotBefore = cert.NotBefore.Format(time.RFC3339)
		info.NotAfter = cert.NotAfter.Format(time.RFC3339)
	}

	return info, nil
}

// RevokeCertificate revokes a certificate by serial number with the given RFC 5280 reason code.
func (s *CAService) RevokeCertificate(serial string, reason int) error {
	if s.client == nil {
		return ErrCAServiceNilClient
	}
	if serial == "" {
		return ErrCAServiceInvalidSerial
	}

	_, err := s.client.RevokeCertificate(context.Background(), &transport.RevokeCertificateRequest{
		SerialNumber: serial,
		Reason:       reason,
	})
	return err
}

// GenerateCRL generates a certificate revocation list and returns it as a PEM string.
func (s *CAService) GenerateCRL() (string, error) {
	if s.client == nil {
		return "", ErrCAServiceNilClient
	}

	resp, err := s.client.GenerateCRL(context.Background(), &transport.GenerateCRLRequest{})
	if err != nil {
		return "", err
	}

	return string(resp.CRLPEM), nil
}

// IsRevoked checks if a certificate with the given serial number has been revoked.
func (s *CAService) IsRevoked(serial string) (bool, error) {
	if s.client == nil {
		return false, ErrCAServiceNilClient
	}
	if serial == "" {
		return false, ErrCAServiceInvalidSerial
	}

	resp, err := s.client.IsRevoked(context.Background(), &transport.IsRevokedRequest{
		SerialNumber: serial,
	})
	if err != nil {
		return false, err
	}

	return resp.Revoked, nil
}

// GetCABundle retrieves the CA certificate bundle and returns it as a PEM string.
func (s *CAService) GetCABundle(storeType, algorithm string) (string, error) {
	if s.client == nil {
		return "", ErrCAServiceNilClient
	}

	resp, err := s.client.GetCABundle(context.Background(), &transport.GetCABundleRequest{
		StoreType: storeType,
		Algorithm: algorithm,
	})
	if err != nil {
		return "", err
	}

	return string(resp.BundlePEM), nil
}

// parsePEMCertificate decodes PEM data and parses the first certificate.
func parsePEMCertificate(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, ErrCAServiceInvalidPEM
	}
	return x509.ParseCertificate(block.Bytes)
}

// parseSANs splits a comma-separated SAN string into a slice, trimming whitespace
// and removing empty entries.
func parseSANs(sans string) []string {
	if sans == "" {
		return nil
	}
	raw := strings.Split(sans, ",")
	result := make([]string, 0, len(raw))
	for _, s := range raw {
		trimmed := strings.TrimSpace(s)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}
