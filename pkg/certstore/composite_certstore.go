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

package certstore

import (
	"context"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
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
			return &errs.Wrapped{Msg: "failed to check revocation status", Err: err}
		}
		if revoked {
			return ErrCertRevoked
		}
	}

	if err := cs.storage.SaveCert(context.Background(), cert.Subject.CommonName, cert); err != nil {
		return &errs.Wrapped{Msg: "failed to store certificate", Err: err}
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

	cert, err := cs.storage.GetCert(context.Background(), cn)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get certificate", Err: err}
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

	if err := cs.storage.DeleteCert(context.Background(), cn); err != nil {
		return &errs.Wrapped{Msg: "failed to delete certificate", Err: err}
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

	ids, err := cs.storage.ListCerts(context.Background())
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to list certificates", Err: err}
	}

	var certs []*x509.Certificate
	for _, id := range ids {
		cert, err := cs.storage.GetCert(context.Background(), id)
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
			return &errs.Detail{Err: ErrChainInvalid, Detail: fmt.Sprintf("certificate at index %d is nil", i)}
		}
	}

	if err := cs.storage.SaveCertChain(context.Background(), cn, chain); err != nil {
		return &errs.Wrapped{Msg: "failed to store certificate chain", Err: err}
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

	chain, err := cs.storage.GetCertChain(context.Background(), cn)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get certificate chain", Err: err}
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

	// Store in cache. This is intentionally an in-process, non-durable
	// cache only: pkg/ca persists the signed CRL DER as a replicated
	// artifact (see crl_persistence.go, go-xkms#275) and calls StoreCRL to
	// warm this cache after every (re)generation. GetCRL is the fast path
	// CA.CRL consults before falling through to the persisted artifact;
	// callers that need durability or cross-instance visibility must go
	// through CA.CRL, not this cache directly.
	cs.crlCache[issuer] = crl

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
		return &errs.Detail{Err: ErrVerificationFailed, Detail: fmt.Sprintf("%v", err)}
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

	// A stale CRL (NextUpdate in the past) should be refreshed, but a cache
	// refresh failure must not make revocation checking fail open: the
	// revoked-entries check below still runs against whatever CRL is
	// cached, stale or not.

	// Check if certificate serial number is in the revoked list
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
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
		return &errs.Wrapped{Msg: "failed to close storage", Err: err}
	}

	return nil
}

// Verify interface compliance at compile time
var _ CertStore = (*compositeCertStore)(nil)
