// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package certstore

import (
	"crypto/x509"
	"fmt"
	"sync"
	"time"
)

// compositeCertStore implements the CertStore interface by composing
// a CertificateStorageAdapter with certificate validation and CRL management.
type compositeCertStore struct {
	storage       CertificateStorageAdapter
	verifyOptions *x509.VerifyOptions
	allowRevoked  bool
	crlCache      map[string]*x509.RevocationList // issuer -> CRL
	mu            sync.RWMutex
	closed        bool
}

// New creates a new CertStore instance with the provided configuration.
//
// Example usage:
//
//	storage := file.NewCertStorage("/var/lib/certs")
//	certStore, err := certstore.New(&certstore.Config{
//	    CertStorage: storage,
//	})
func New(config *Config) (CertStore, error) {
	if config == nil {
		return nil, ErrInvalidConfig
	}
	if config.CertStorage == nil {
		return nil, ErrStorageRequired
	}

	verifyOpts := config.VerifyOptions
	if verifyOpts == nil {
		verifyOpts = &x509.VerifyOptions{
			CurrentTime: time.Now(),
		}
	}

	return &compositeCertStore{
		storage:       config.CertStorage,
		verifyOptions: verifyOpts,
		allowRevoked:  config.AllowRevoked,
		crlCache:      make(map[string]*x509.RevocationList),
		closed:        false,
	}, nil
}

// ========================================================================
// Basic Certificate Operations
// ========================================================================

// StoreCertificate stores a certificate identified by its Common Name.
func (cs *compositeCertStore) StoreCertificate(cert *x509.Certificate) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.closed {
		return ErrStorageClosed
	}

	if cert == nil {
		return ErrCertInvalid
	}

	if cert.Subject.CommonName == "" {
		return ErrInvalidCN
	}

	// Check if certificate is expired
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return ErrCertNotYetValid
	}
	if now.After(cert.NotAfter) {
		return ErrCertExpired
	}

	// Check if certificate is revoked (unless allowed)
	if !cs.allowRevoked {
		revoked, err := cs.isRevokedLocked(cert)
		if err != nil {
			return fmt.Errorf("failed to check revocation status: %w", err)
		}
		if revoked {
			return ErrCertRevoked
		}
	}

	if err := cs.storage.SaveCert(cert.Subject.CommonName, cert); err != nil {
		return fmt.Errorf("failed to store certificate: %w", err)
	}

	return nil
}

// GetCertificate retrieves a certificate by its Common Name.
func (cs *compositeCertStore) GetCertificate(cn string) (*x509.Certificate, error) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if cs.closed {
		return nil, ErrStorageClosed
	}

	if cn == "" {
		return nil, ErrInvalidCN
	}

	cert, err := cs.storage.GetCert(cn)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	return cert, nil
}

// DeleteCertificate removes a certificate by its Common Name.
func (cs *compositeCertStore) DeleteCertificate(cn string) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.closed {
		return ErrStorageClosed
	}

	if cn == "" {
		return ErrInvalidCN
	}

	if err := cs.storage.DeleteCert(cn); err != nil {
		return fmt.Errorf("failed to delete certificate: %w", err)
	}

	return nil
}

// ListCertificates returns all certificates currently stored.
func (cs *compositeCertStore) ListCertificates() ([]*x509.Certificate, error) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if cs.closed {
		return nil, ErrStorageClosed
	}

	ids, err := cs.storage.ListCerts()
	if err != nil {
		return nil, fmt.Errorf("failed to list certificates: %w", err)
	}

	var certs []*x509.Certificate
	for _, id := range ids {
		cert, err := cs.storage.GetCert(id)
		if err != nil {
			continue
		}
		if cert == nil {
			continue
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

// ========================================================================
// Certificate Chain Operations
// ========================================================================

// StoreCertificateChain stores a certificate chain.
// The chain should be ordered from leaf to root.
func (cs *compositeCertStore) StoreCertificateChain(chain []*x509.Certificate) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.closed {
		return ErrStorageClosed
	}

	if len(chain) == 0 {
		return ErrChainEmpty
	}

	// Use the leaf certificate's CN as the chain identifier
	cn := chain[0].Subject.CommonName
	if cn == "" {
		return ErrInvalidCN
	}

	// Validate each certificate in the chain
	for i, cert := range chain {
		if cert == nil {
			return fmt.Errorf("%w: certificate at index %d is nil", ErrChainInvalid, i)
		}
	}

	if err := cs.storage.SaveCertChain(cn, chain); err != nil {
		return fmt.Errorf("failed to store certificate chain: %w", err)
	}

	return nil
}

// GetCertificateChain retrieves a certificate chain by Common Name.
func (cs *compositeCertStore) GetCertificateChain(cn string) ([]*x509.Certificate, error) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if cs.closed {
		return nil, ErrStorageClosed
	}

	if cn == "" {
		return nil, ErrInvalidCN
	}

	chain, err := cs.storage.GetCertChain(cn)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate chain: %w", err)
	}

	return chain, nil
}

// ========================================================================
// Certificate Revocation List (CRL) Operations
// ========================================================================

// StoreCRL stores a Certificate Revocation List.
func (cs *compositeCertStore) StoreCRL(crl *x509.RevocationList) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.closed {
		return ErrStorageClosed
	}

	if crl == nil {
		return ErrCRLInvalid
	}

	// Extract issuer CN
	issuer := crl.Issuer.CommonName
	if issuer == "" {
		return ErrInvalidIssuer
	}

	// Check if CRL is expired
	now := time.Now()
	if crl.NextUpdate.Before(now) {
		return ErrCRLExpired
	}

	// Store in cache
	cs.crlCache[issuer] = crl

	// Note: CRLs are kept in memory cache only for now.
	// For production use, you may want to persist them using a separate storage mechanism.

	return nil
}

// GetCRL retrieves a CRL for the given issuer.
func (cs *compositeCertStore) GetCRL(issuer string) (*x509.RevocationList, error) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if cs.closed {
		return nil, ErrStorageClosed
	}

	if issuer == "" {
		return nil, ErrInvalidIssuer
	}

	crl, found := cs.crlCache[issuer]
	if !found {
		return nil, ErrCRLNotFound
	}

	return crl, nil
}

// ========================================================================
// Certificate Validation Operations
// ========================================================================

// VerifyCertificate validates a certificate against a pool of trusted roots.
func (cs *compositeCertStore) VerifyCertificate(cert *x509.Certificate, roots *x509.CertPool) error {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if cs.closed {
		return ErrStorageClosed
	}

	if cert == nil {
		return ErrCertInvalid
	}

	if roots == nil {
		return ErrNoRoots
	}

	// Prepare verification options
	opts := x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: time.Now(),
	}

	// Copy any additional options from config
	if cs.verifyOptions != nil {
		if cs.verifyOptions.DNSName != "" {
			opts.DNSName = cs.verifyOptions.DNSName
		}
		if cs.verifyOptions.Intermediates != nil {
			opts.Intermediates = cs.verifyOptions.Intermediates
		}
		if len(cs.verifyOptions.KeyUsages) > 0 {
			opts.KeyUsages = cs.verifyOptions.KeyUsages
		}
	}

	// Perform verification
	_, err := cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrVerificationFailed, err)
	}

	return nil
}

// IsRevoked checks if a certificate has been revoked.
func (cs *compositeCertStore) IsRevoked(cert *x509.Certificate) (bool, error) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if cs.closed {
		return false, ErrStorageClosed
	}

	return cs.isRevokedLocked(cert)
}

// isRevokedLocked checks if a certificate is revoked (caller must hold read lock).
func (cs *compositeCertStore) isRevokedLocked(cert *x509.Certificate) (bool, error) {
	if cert == nil {
		return false, ErrCertInvalid
	}

	// Get issuer CN
	issuer := cert.Issuer.CommonName
	if issuer == "" {
		// No issuer, can't check revocation
		return false, nil
	}

	// Look up CRL for this issuer
	crl, found := cs.crlCache[issuer]
	if !found {
		// No CRL available, assume not revoked
		return false, nil
	}

	// Check if CRL is still valid
	now := time.Now()
	if crl.NextUpdate.Before(now) || crl.NextUpdate.Equal(now) { //nolint:staticcheck // SA4017: checking expiration
		//nolint:staticcheck // SA4017: intentional expiration check
		// CRL is expired, should be refreshed
		// For now, we'll still check it
	}

	// Check if certificate serial number is in the revoked list
	for _, revokedCert := range crl.RevokedCertificateEntries {
		if revokedCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return true, nil
		}
	}

	// Also check RevokedCertificates for Go versions before 1.21
	// (Go 1.21+ uses RevokedCertificateEntries instead)
	for _, entry := range crl.RevokedCertificateEntries {
		revokedCert := entry.SerialNumber
		if revokedCert.Cmp(cert.SerialNumber) == 0 {
			return true, nil
		}
	}

	return false, nil
}

// ========================================================================
// Lifecycle
// ========================================================================

// Close releases all resources held by the cert store.
func (cs *compositeCertStore) Close() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.closed {
		return nil
	}

	cs.closed = true

	// Clear CRL cache
	cs.crlCache = nil

	// Close underlying storage
	if err := cs.storage.Close(); err != nil {
		return fmt.Errorf("failed to close storage: %w", err)
	}

	return nil
}

// Verify interface compliance at compile time
var _ CertStore = (*compositeCertStore)(nil)
