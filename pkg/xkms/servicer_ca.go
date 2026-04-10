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
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/ca/provider"
)

// getCA returns the typed CA provider. Returns ErrNotConfigured if no CA is wired.
func (s *XKMSService) getCA() (provider.CA, error) {
	if s.ca == nil {
		return nil, ErrNotConfigured
	}
	return s.ca, nil
}

// GetCABundle retrieves the CA certificate bundle.
func (s *XKMSService) GetCABundle(ctx context.Context, req *transport.GetCABundleRequest) (*transport.GetCABundleResponse, error) {
	ca, err := s.getCA()
	if err != nil {
		return nil, err
	}

	bundlePEM, err := ca.CABundle()
	if err != nil {
		return nil, &ErrCAOperation{Operation: "get bundle", Err: err}
	}

	// Parse individual DER certificates from PEM bundle.
	var certs [][]byte
	rest := bundlePEM
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

	return &transport.GetCABundleResponse{
		BundlePEM:    bundlePEM,
		Certificates: certs,
		ContentType:  "application/x-pem-file",
	}, nil
}

// GetCACertificate retrieves the CA certificate.
func (s *XKMSService) GetCACertificate(ctx context.Context, req *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error) {
	ca, err := s.getCA()
	if err != nil {
		return nil, err
	}

	cert, err := ca.CACertificate()
	if err != nil {
		return nil, &ErrCAOperation{Operation: "get certificate", Err: err}
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	return &transport.GetCACertificateResponse{
		CertificatePEM: certPEM,
		Subject:        cert.Subject.String(),
		Issuer:         cert.Issuer.String(),
		SerialNumber:   cert.SerialNumber.Text(16),
		NotBefore:      cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
		NotAfter:       cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		IsCA:           cert.IsCA,
	}, nil
}

// SignCSR signs a certificate signing request using the CA.
func (s *XKMSService) SignCSR(ctx context.Context, req *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if len(req.CSRPEM) == 0 {
		return nil, ErrNilData
	}

	ca, err := s.getCA()
	if err != nil {
		return nil, err
	}

	cert, err := ca.SignCSRRaw(req.CSRPEM, req.Profile, req.ValidityDays)
	if err != nil {
		return nil, &ErrCAOperation{Operation: "sign csr", Err: err}
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	// Get CA certificate for chain.
	var chainPEM []byte
	if caCert, caErr := ca.CACertificate(); caErr == nil {
		chainPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caCert.Raw,
		})
	}

	return &transport.SignCSRResponse{
		CertificatePEM: certPEM,
		ChainPEM:       chainPEM,
		SerialNumber:   cert.SerialNumber.Text(16),
	}, nil
}

// IssueCertificate issues a new certificate from the CA.
func (s *XKMSService) IssueCertificate(ctx context.Context, req *transport.IssueCertificateRequest) (*transport.IssueCertificateResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.CommonName == "" {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "common name required"}
	}

	ca, err := s.getCA()
	if err != nil {
		return nil, err
	}

	certPEM, chainPEM, keyPEM, serialHex, err := ca.IssueCertificateRaw(
		req.CommonName,
		req.Organization,
		req.SANs,
		req.ValidityDays,
		req.Profile,
		req.Algorithm,
	)
	if err != nil {
		return nil, &ErrCAOperation{Operation: "issue certificate", Err: err}
	}

	return &transport.IssueCertificateResponse{
		CertificatePEM: certPEM,
		ChainPEM:       chainPEM,
		PrivateKeyPEM:  keyPEM,
		SerialNumber:   serialHex,
	}, nil
}

// RevokeCertificate revokes a certificate by serial number.
func (s *XKMSService) RevokeCertificate(ctx context.Context, req *transport.RevokeCertificateRequest) (*transport.RevokeCertificateResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.SerialNumber == "" {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "serial number required"}
	}

	ca, err := s.getCA()
	if err != nil {
		return nil, err
	}

	serial, err := parseSerialHex(req.SerialNumber)
	if err != nil {
		return nil, err
	}

	if err := ca.Revoke(serial, req.Reason); err != nil {
		return nil, &ErrCAOperation{Operation: "revoke", Err: err}
	}

	return &transport.RevokeCertificateResponse{
		Success: true,
		Message: fmt.Sprintf("certificate %s revoked", req.SerialNumber),
	}, nil
}

// GenerateCRL generates a certificate revocation list.
func (s *XKMSService) GenerateCRL(ctx context.Context, req *transport.GenerateCRLRequest) (*transport.GenerateCRLResponse, error) {
	ca, err := s.getCA()
	if err != nil {
		return nil, err
	}

	crlDER, err := ca.GenerateCRL()
	if err != nil {
		return nil, &ErrCAOperation{Operation: "generate crl", Err: err}
	}

	crlPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlDER,
	})

	return &transport.GenerateCRLResponse{
		CRLPEM: crlPEM,
	}, nil
}

// IsRevoked checks whether a certificate has been revoked.
func (s *XKMSService) IsRevoked(ctx context.Context, req *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.SerialNumber == "" {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "serial number required"}
	}

	ca, err := s.getCA()
	if err != nil {
		return nil, err
	}

	serial, err := parseSerialHex(req.SerialNumber)
	if err != nil {
		return nil, err
	}

	revoked, err := ca.IsRevoked(serial)
	if err != nil {
		return nil, &ErrCAOperation{Operation: "is revoked", Err: err}
	}

	resp := &transport.IsRevokedResponse{
		Revoked: revoked,
	}
	if revoked {
		resp.Message = "certificate is revoked"
	} else {
		resp.Message = "certificate is not revoked"
	}

	return resp, nil
}

// parseSerialHex parses a hex serial number string, stripping optional 0x/0X prefix.
func parseSerialHex(s string) (*big.Int, error) {
	serialStr := strings.TrimPrefix(s, "0x")
	serialStr = strings.TrimPrefix(serialStr, "0X")
	serial := new(big.Int)
	if _, ok := serial.SetString(serialStr, 16); !ok {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "invalid serial number format"}
	}
	return serial, nil
}
