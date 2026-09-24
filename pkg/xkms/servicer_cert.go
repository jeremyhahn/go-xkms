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
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/metrics"
	"github.com/jeremyhahn/go-xkms/pkg/validation"
)

// GetCertificate retrieves a certificate by key ID from the specified backend.
// If backendName is empty, the default backend is used.
// Implements the CertServicer interface.
func (s *XKMSService) GetCertificate(ctx context.Context, backendName, keyID string) (resp *transport.GetCertificateResponse, err error) {
	start := time.Now()
	metricsBackend := s.metricsBackendName(backendName)
	defer func() { recordServiceOp(metrics.OpGet, metricsBackend, start, err) }()

	b, err := s.resolveBackend(backendName)
	if err != nil {
		return nil, err
	}

	if err := validation.ValidateKeyReference(keyID); err != nil {
		return nil, &ErrKeyIDParse{Err: err}
	}

	cert, err := b.GetCert(ctx, keyID)
	if err != nil {
		return nil, &ErrCertOperation{Operation: "get certificate", Err: err}
	}

	return &transport.GetCertificateResponse{
		KeyID:          keyID,
		CertificatePEM: certToPEM(cert),
	}, nil
}

// SaveCertificate saves a PEM-encoded certificate to the specified backend.
// Implements the CertServicer interface.
func (s *XKMSService) SaveCertificate(ctx context.Context, req *transport.SaveCertificateRequest) (err error) {
	start := time.Now()
	metricsBackend := ""
	if req != nil {
		metricsBackend = s.metricsBackendName(req.Backend)
	}
	defer func() { recordServiceOp(metrics.OpStore, metricsBackend, start, err) }()

	if req == nil {
		return ErrNilRequest
	}

	b, err := s.resolveBackend(req.Backend)
	if err != nil {
		return err
	}

	if err = validation.ValidateKeyReference(req.KeyID); err != nil {
		return &ErrKeyIDParse{Err: err}
	}

	cert, err := certFromPEM(req.CertificatePEM)
	if err != nil {
		return &ErrCertOperation{Operation: "parse certificate PEM", Err: err}
	}

	if err = b.SaveCert(ctx, req.KeyID, cert); err != nil {
		return err
	}

	incrementCertsTotal(metricsBackend)
	return nil
}

// DeleteCertificate deletes a certificate by key ID from the specified backend.
// If backendName is empty, the default backend is used.
// Implements the CertServicer interface.
func (s *XKMSService) DeleteCertificate(ctx context.Context, backendName, keyID string) (err error) {
	start := time.Now()
	metricsBackend := s.metricsBackendName(backendName)
	defer func() { recordServiceOp(metrics.OpDelete, metricsBackend, start, err) }()

	b, err := s.resolveBackend(backendName)
	if err != nil {
		return err
	}

	if err = validation.ValidateKeyReference(keyID); err != nil {
		return &ErrKeyIDParse{Err: err}
	}

	if err = b.DeleteCert(ctx, keyID); err != nil {
		return err
	}

	decrementCertsTotal(metricsBackend)
	return nil
}

// CertificateExists checks if a certificate exists for the given key ID.
// If backendName is empty, the default backend is used.
// Implements the CertServicer interface.
func (s *XKMSService) CertificateExists(ctx context.Context, backendName, keyID string) (exists bool, err error) {
	start := time.Now()
	metricsBackend := s.metricsBackendName(backendName)
	defer func() { recordServiceOp(metrics.OpGet, metricsBackend, start, err) }()

	b, err := s.resolveBackend(backendName)
	if err != nil {
		return false, err
	}

	if err = validation.ValidateKeyReference(keyID); err != nil {
		return false, &ErrKeyIDParse{Err: err}
	}

	return b.CertExists(ctx, keyID)
}

// ListCertificates lists all certificates from the specified backend.
// If backendName is empty, the default backend is used.
// Implements the CertServicer interface.
func (s *XKMSService) ListCertificates(ctx context.Context, backendName string, opts ...transport.ListOption) (resp *transport.ListCertificatesResponse, err error) {
	start := time.Now()
	metricsBackend := s.metricsBackendName(backendName)
	defer func() { recordServiceOp(metrics.OpList, metricsBackend, start, err) }()

	b, err := s.resolveBackend(backendName)
	if err != nil {
		return nil, err
	}

	certIDs, err := b.ListCerts(ctx)
	if err != nil {
		return nil, &ErrCertOperation{Operation: "list certificates", Err: err}
	}

	certs := make([]transport.CertificateInfo, 0, len(certIDs))
	for _, id := range certIDs {
		info := transport.CertificateInfo{
			KeyID: id,
		}

		// Attempt to retrieve full certificate details for richer response.
		// If retrieval fails, include the entry with just the key ID.
		cert, certErr := b.GetCert(ctx, id)
		if certErr == nil && cert != nil {
			info.CertificatePEM = certToPEM(cert)
			info.Subject = cert.Subject.String()
			info.Issuer = cert.Issuer.String()
			info.NotBefore = cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z")
			info.NotAfter = cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z")
			info.SerialNumber = cert.SerialNumber.String()
		}

		certs = append(certs, info)
	}

	return &transport.ListCertificatesResponse{
		Certificates: certs,
	}, nil
}

// SaveCertificateChain saves a PEM-encoded certificate chain to the specified backend.
// Implements the CertServicer interface.
func (s *XKMSService) SaveCertificateChain(ctx context.Context, req *transport.SaveCertificateChainRequest) (err error) {
	start := time.Now()
	metricsBackend := ""
	if req != nil {
		metricsBackend = s.metricsBackendName(req.Backend)
	}
	defer func() { recordServiceOp(metrics.OpStore, metricsBackend, start, err) }()

	if req == nil {
		return ErrNilRequest
	}

	b, err := s.resolveBackend(req.Backend)
	if err != nil {
		return err
	}

	if err = validation.ValidateKeyReference(req.KeyID); err != nil {
		return &ErrKeyIDParse{Err: err}
	}

	if len(req.ChainPEM) == 0 {
		return ErrEmptyChain
	}

	chain := make([]*x509.Certificate, 0, len(req.ChainPEM))
	for i, pemStr := range req.ChainPEM {
		cert, certErr := certFromPEM(pemStr)
		if certErr != nil {
			return &ErrCertParseIndex{Index: i, Err: certErr}
		}
		chain = append(chain, cert)
	}

	// Deliberately no certs-total gauge update here: a chain is stored under
	// a distinct key (storage.CertChainPath) that ListCerts excludes from
	// the count that gauge tracks, so saving a chain does not change it --
	// see incrementCertsTotal's doc comment.
	return b.SaveCertChain(ctx, req.KeyID, chain)
}

// GetCertificateChain retrieves a certificate chain by key ID from the specified backend.
// If backendName is empty, the default backend is used.
// Implements the CertServicer interface.
func (s *XKMSService) GetCertificateChain(ctx context.Context, backendName, keyID string) (resp *transport.GetCertificateChainResponse, err error) {
	start := time.Now()
	metricsBackend := s.metricsBackendName(backendName)
	defer func() { recordServiceOp(metrics.OpGet, metricsBackend, start, err) }()

	b, err := s.resolveBackend(backendName)
	if err != nil {
		return nil, err
	}

	if err = validation.ValidateKeyReference(keyID); err != nil {
		return nil, &ErrKeyIDParse{Err: err}
	}

	chain, err := b.GetCertChain(ctx, keyID)
	if err != nil {
		return nil, &ErrCertOperation{Operation: "get certificate chain", Err: err}
	}

	chainPEM := make([]string, 0, len(chain))
	for _, cert := range chain {
		chainPEM = append(chainPEM, certToPEM(cert))
	}

	return &transport.GetCertificateChainResponse{
		KeyID:    keyID,
		ChainPEM: chainPEM,
	}, nil
}

// GetTLSCertificate retrieves a TLS certificate bundle (leaf + chain) by key ID.
// If backendName is empty, the default backend is used.
// Implements the CertServicer interface.
func (s *XKMSService) GetTLSCertificate(ctx context.Context, backendName, keyID string) (resp *transport.GetTLSCertificateResponse, err error) {
	start := time.Now()
	metricsBackend := s.metricsBackendName(backendName)
	defer func() { recordServiceOp(metrics.OpGet, metricsBackend, start, err) }()

	b, err := s.resolveBackend(backendName)
	if err != nil {
		return nil, err
	}

	if err = validation.ValidateKeyReference(keyID); err != nil {
		return nil, &ErrKeyIDParse{Err: err}
	}

	// Get the leaf certificate
	leafCert, err := b.GetCert(ctx, keyID)
	if err != nil {
		return nil, &ErrCertOperation{Operation: "get leaf certificate", Err: err}
	}

	resp = &transport.GetTLSCertificateResponse{
		KeyID:          keyID,
		CertificatePEM: certToPEM(leafCert),
	}

	// Attempt to get the chain; chain is optional for TLS bundles
	chain, chainErr := b.GetCertChain(ctx, keyID)
	if chainErr == nil && len(chain) > 0 {
		chainPEM := make([]string, 0, len(chain))
		for _, cert := range chain {
			chainPEM = append(chainPEM, certToPEM(cert))
		}
		resp.ChainPEM = chainPEM
	}

	return resp, nil
}

// certToPEM encodes an x509.Certificate to a PEM-encoded string.
func certToPEM(cert *x509.Certificate) string {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return string(pem.EncodeToMemory(block))
}

// certFromPEM decodes a PEM-encoded string into an x509.Certificate.
func certFromPEM(pemStr string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, ErrInvalidEncodingPEM
	}
	if block.Type != "CERTIFICATE" {
		return nil, &ErrPEMBlock{Expected: "CERTIFICATE", Got: block.Type}
	}
	return x509.ParseCertificate(block.Bytes)
}
