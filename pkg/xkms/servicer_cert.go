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
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"sort"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/metrics"
	"github.com/jeremyhahn/go-xkms/pkg/validation"
)

// Every certificate method resolves the backend through the caller's tenant,
// so a tenant reads, writes, lists and deletes only certificates stored in
// its own namespace ("{tenant}/{keyID}", see TenantScopedBackend). Methods
// with a request struct take the tenant from its TenantID, which each
// transport fills from the authenticated identity; the rest read it from the
// identity on ctx (scopedTenantIDFromContext). A platform-scoped caller
// operates on the unscoped store. A key ID is validated before use, and the
// validation refuses "/", so a tenant cannot name another tenant's namespace.
// Another tenant's certificate is therefore exactly as absent as one nobody
// stored. The transports used to call the unscoped backend directly, and any
// tenant could read, overwrite, list or delete every tenant's certificates
// and the platform's (go-xkms#1228).

// GetCertificate retrieves a certificate by key ID from the specified backend.
// If backendName is empty, the default backend is used.
// Implements the CertServicer interface.
func (s *XKMSService) GetCertificate(ctx context.Context, backendName, keyID string) (resp *transport.GetCertificateResponse, err error) {
	start := time.Now()
	metricsBackend := s.metricsBackendName(backendName)
	defer func() { recordServiceOp(metrics.OpGet, metricsBackend, start, err) }()

	b, err := s.resolveTenantBackend(backendName, scopedTenantIDFromContext(ctx))
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

	b, err := s.resolveTenantBackend(req.Backend, req.TenantID)
	if err != nil {
		return err
	}

	if err = validation.ValidateKeyReference(req.KeyID); err != nil {
		return &ErrKeyIDParse{Err: err}
	}

	cert, err := certFromPEM(req.CertificatePEM)
	if err != nil {
		return err
	}

	if saveErr := b.SaveCert(ctx, req.KeyID, cert); saveErr != nil {
		return saveErr
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

	b, err := s.resolveTenantBackend(backendName, scopedTenantIDFromContext(ctx))
	if err != nil {
		return err
	}

	if err = validation.ValidateKeyReference(keyID); err != nil {
		return &ErrKeyIDParse{Err: err}
	}

	if delErr := b.DeleteCert(ctx, keyID); delErr != nil {
		return delErr
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

	b, err := s.resolveTenantBackend(backendName, scopedTenantIDFromContext(ctx))
	if err != nil {
		return false, err
	}

	if err = validation.ValidateKeyReference(keyID); err != nil {
		return false, &ErrKeyIDParse{Err: err}
	}

	return b.CertExists(ctx, keyID)
}

// ListCertificates lists the caller's certificates in the specified backend.
// If backendName is empty, the default backend is used. The list options are
// honoured: the response carries the requested page and the pagination
// metadata describing it, and with no options the full list.
// Implements the CertServicer interface.
func (s *XKMSService) ListCertificates(ctx context.Context, backendName string, opts ...transport.ListOption) (resp *transport.ListCertificatesResponse, err error) {
	start := time.Now()
	metricsBackend := s.metricsBackendName(backendName)
	defer func() { recordServiceOp(metrics.OpList, metricsBackend, start, err) }()

	b, err := s.resolveTenantBackend(backendName, scopedTenantIDFromContext(ctx))
	if err != nil {
		return nil, err
	}

	certIDs, err := b.ListCerts(ctx)
	if err != nil {
		return nil, &ErrCertOperation{Operation: "list certificates", Err: err}
	}

	// The IDs are ordered before paging so a caller walking the pages sees
	// each certificate once, and only the requested page is read back.
	sort.Strings(certIDs)
	page, pagination := transport.ApplyPagination(certIDs, transport.BuildPageRequest(opts...))

	certs := make([]transport.CertificateInfo, 0, len(page))
	for _, id := range page {
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
		PageResponse: pagination,
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

	b, err := s.resolveTenantBackend(req.Backend, req.TenantID)
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

	b, err := s.resolveTenantBackend(backendName, scopedTenantIDFromContext(ctx))
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
// If backendName is empty, the default backend is used. The bundle carries no
// private key, so it needs none: the leaf and chain are read from the
// caller's certificate namespace like every other certificate read.
// Implements the CertServicer interface.
func (s *XKMSService) GetTLSCertificate(ctx context.Context, backendName, keyID string) (resp *transport.GetTLSCertificateResponse, err error) {
	start := time.Now()
	metricsBackend := s.metricsBackendName(backendName)
	defer func() { recordServiceOp(metrics.OpGet, metricsBackend, start, err) }()

	b, err := s.resolveTenantBackend(backendName, scopedTenantIDFromContext(ctx))
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

	// Attempt to get the chain; chain is optional for TLS bundles. A stored
	// chain runs leaf to root, so when it opens with the leaf that entry is
	// dropped: ChainPEM carries the certificates above the leaf, which
	// CertificatePEM already holds.
	chain, chainErr := b.GetCertChain(ctx, keyID)
	if chainErr == nil && len(chain) > 0 {
		if bytes.Equal(chain[0].Raw, leafCert.Raw) {
			chain = chain[1:]
		}
		chainPEM := make([]string, 0, len(chain))
		for _, cert := range chain {
			chainPEM = append(chainPEM, certToPEM(cert))
		}
		if len(chainPEM) > 0 {
			resp.ChainPEM = chainPEM
		}
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
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, &ErrCertificateParse{Err: err}
	}
	return cert, nil
}
