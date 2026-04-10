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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// RemoteCertificateInfo describes a certificate for the frontend.
type RemoteCertificateInfo struct {
	Backend     string `json:"backend"`
	KeyID       string `json:"key_id"`
	Subject     string `json:"subject"`
	Issuer      string `json:"issuer"`
	NotBefore   string `json:"not_before"`
	NotAfter    string `json:"not_after"`
	Algorithm   string `json:"algorithm"`
	IsCA        bool   `json:"is_ca"`
	IsExpired   bool   `json:"is_expired"`
	Fingerprint string `json:"fingerprint"`
	PEM         string `json:"pem"`
}

// CertificateService exposes certificate listing to the frontend.
// It is bound to the Wails runtime so every exported method is
// callable from the Svelte frontend.
type CertificateService struct {
	ctx    context.Context
	log    *slog.Logger
	client atomic.Pointer[transport.Client]
}

// NewCertificateService creates a new CertificateService.
func NewCertificateService() *CertificateService {
	return &CertificateService{
		log: slog.Default().With("component", "certificate_service"),
	}
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *CertificateService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetClient sets the transport client used to communicate with the server.
func (s *CertificateService) SetClient(c transport.Client) {
	s.client.Store(&c)
}

// getClient returns the current transport client or ErrCertServiceNoClient.
func (s *CertificateService) getClient() (transport.Client, error) {
	ptr := s.client.Load()
	if ptr == nil {
		return nil, ErrCertServiceNoClient
	}
	return *ptr, nil
}

// ListCertificates returns the certificates stored in a single named backend.
func (s *CertificateService) ListCertificates(backend string) (result []RemoteCertificateInfo, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ListCertificates", "recover", r)
			result = nil
			retErr = fmt.Errorf("certificate_service: panic in ListCertificates: %v", r)
		}
	}()

	client, err := s.getClient()
	if err != nil {
		return nil, err
	}

	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	certsResp, err := client.ListCertificates(ctx, backend)
	if err != nil {
		return nil, err
	}

	var result2 []RemoteCertificateInfo
	for _, ci := range certsResp.Certificates {
		result2 = append(result2, parseCertificateInfo(backend, &ci))
	}
	if result2 == nil {
		return []RemoteCertificateInfo{}, nil
	}
	return result2, nil
}

// ListAllCertificates aggregates certificates from all available backends.
func (s *CertificateService) ListAllCertificates() (result []RemoteCertificateInfo, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ListAllCertificates", "recover", r)
			result = nil
			retErr = fmt.Errorf("certificate_service: panic in ListAllCertificates: %v", r)
		}
	}()

	client, err := s.getClient()
	if err != nil {
		return nil, err
	}

	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	backendsResp, err := client.ListBackends(ctx)
	if err != nil {
		return nil, err
	}

	var all []RemoteCertificateInfo
	for _, b := range backendsResp.Backends {
		certsResp, err := client.ListCertificates(ctx, b.ID)
		if err != nil {
			s.log.Warn("failed to list certificates for backend",
				"backend", b.ID,
				"error", err)
			continue
		}
		for _, ci := range certsResp.Certificates {
			info := parseCertificateInfo(b.ID, &ci)
			all = append(all, info)
		}
	}

	if all == nil {
		return []RemoteCertificateInfo{}, nil
	}

	return all, nil
}

// parseCertificateInfo converts a transport.CertificateInfo into a
// RemoteCertificateInfo, parsing X.509 fields from the PEM data.
func parseCertificateInfo(backend string, ci *transport.CertificateInfo) RemoteCertificateInfo {
	info := RemoteCertificateInfo{
		Backend: backend,
		KeyID:   ci.KeyID,
		Subject: ci.Subject,
		Issuer:  ci.Issuer,
		PEM:     ci.CertificatePEM,
	}

	// Parse the PEM to extract additional X.509 fields.
	block, _ := pem.Decode([]byte(ci.CertificatePEM))
	if block == nil {
		return info
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return info
	}

	info.Subject = cert.Subject.String()
	info.Issuer = cert.Issuer.String()
	info.NotBefore = cert.NotBefore.Format(time.RFC3339)
	info.NotAfter = cert.NotAfter.Format(time.RFC3339)
	info.Algorithm = cert.SignatureAlgorithm.String()
	info.IsCA = cert.IsCA
	info.IsExpired = time.Now().After(cert.NotAfter)

	fingerprint := sha256.Sum256(cert.Raw)
	info.Fingerprint = hex.EncodeToString(fingerprint[:])

	return info
}
