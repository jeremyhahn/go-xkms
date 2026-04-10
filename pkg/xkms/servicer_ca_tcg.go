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

package xkms

import (
	"context"
	"crypto/x509"
	"encoding/pem"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/ca/provider"
)

// getTCGCA returns the CA as a TCGCA provider. Returns ErrNotConfigured if
// no CA is wired, or ErrNotSupported if the CA does not support TCG operations.
func (s *XKMSService) getTCGCA() (provider.TCGCA, error) {
	if s.ca == nil {
		return nil, ErrNotConfigured
	}
	tcg, ok := s.ca.(provider.TCGCA)
	if !ok {
		return nil, ErrNotSupported
	}
	return tcg, nil
}

// IssueEKCertificate issues a TCG Endorsement Key certificate.
func (s *XKMSService) IssueEKCertificate(ctx context.Context, req *transport.IssueEKCertificateRequest) (*transport.IssueEKCertificateResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.CommonName == "" {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "common name required"}
	}
	if len(req.EKPublicKey) == 0 {
		return nil, &ErrValidation{Sentinel: ErrNilData, Detail: "EK public key required"}
	}

	tcg, err := s.getTCGCA()
	if err != nil {
		return nil, err
	}

	certDER, err := tcg.IssueEKCertificateRaw(req.CommonName, req.Organization, req.EKPublicKey)
	if err != nil {
		return nil, &ErrCAOperation{Operation: "issue ek certificate", Err: err}
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return &transport.IssueEKCertificateResponse{
		CertificateDER: certDER,
		CertificatePEM: certPEM,
		SerialNumber:   serialFromDER(certDER),
	}, nil
}

// IssueAKCertificate issues a TCG Attestation Key certificate.
func (s *XKMSService) IssueAKCertificate(ctx context.Context, req *transport.IssueAKCertificateRequest) (*transport.IssueAKCertificateResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.CommonName == "" {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "common name required"}
	}
	if len(req.PublicKey) == 0 {
		return nil, &ErrValidation{Sentinel: ErrNilData, Detail: "public key required"}
	}

	tcg, err := s.getTCGCA()
	if err != nil {
		return nil, err
	}

	certDER, err := tcg.IssueAKCertificateRaw(req.CommonName, req.Organization, req.PublicKey)
	if err != nil {
		return nil, &ErrCAOperation{Operation: "issue ak certificate", Err: err}
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return &transport.IssueAKCertificateResponse{
		CertificateDER: certDER,
		CertificatePEM: certPEM,
		SerialNumber:   serialFromDER(certDER),
	}, nil
}

// SignTCGCSR signs a TCG-CSR-IDEVID for device identity enrollment.
func (s *XKMSService) SignTCGCSR(ctx context.Context, req *transport.SignTCGCSRRequest) (*transport.SignTCGCSRResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.CommonName == "" {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "common name required"}
	}
	if len(req.TCGCSR) == 0 {
		return nil, &ErrValidation{Sentinel: ErrNilData, Detail: "TCG CSR required"}
	}

	tcg, err := s.getTCGCA()
	if err != nil {
		return nil, err
	}

	iakDER, idevidDER, err := tcg.SignTCGCSRIDevIDRaw(req.CommonName, req.Organization, req.TCGCSR)
	if err != nil {
		return nil, &ErrCAOperation{Operation: "sign tcg csr", Err: err}
	}

	return &transport.SignTCGCSRResponse{
		IAKCertDER:    iakDER,
		IDevIDCertDER: idevidDER,
	}, nil
}

// EnrollDevice performs complete TCG device enrollment.
func (s *XKMSService) EnrollDevice(ctx context.Context, req *transport.EnrollDeviceRequest) (*transport.EnrollDeviceResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.CommonName == "" {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "common name required"}
	}
	if len(req.PackedCSR) == 0 {
		return nil, &ErrValidation{Sentinel: ErrNilData, Detail: "packed CSR required"}
	}

	tcg, err := s.getTCGCA()
	if err != nil {
		return nil, err
	}

	iakDER, idevidDER, credBlob, encSecret, plainSecret, err := tcg.EnrollDeviceRaw(
		req.CommonName, req.Organization, req.PackedCSR,
	)
	if err != nil {
		return nil, &ErrCAOperation{Operation: "enroll device", Err: err}
	}

	return &transport.EnrollDeviceResponse{
		IAKCertDER:      iakDER,
		IDevIDCertDER:   idevidDER,
		CredentialBlob:  credBlob,
		EncryptedSecret: encSecret,
		PlainSecret:     plainSecret,
	}, nil
}

// serialFromDER extracts the hex serial number from a DER-encoded certificate.
// Returns empty string if parsing fails.
func serialFromDER(der []byte) string {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return ""
	}
	return cert.SerialNumber.Text(16)
}
