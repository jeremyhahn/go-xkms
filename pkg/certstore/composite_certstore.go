// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// listPageSize is the page size the store lists its certificates with.
const listPageSize = 500

// compositeCertStore implements the CertStore interface by composing
// certificate and chain DAOs in DatabaseName with certificate validation and
// CRL management. Every entity's ID derives from its natural key, the
// certificate's CertificateKey.
type compositeCertStore struct {
	certs         qrdbsdk.GenericDAO[*certificateEntity]
	chains        qrdbsdk.GenericDAO[*chainEntity]
	verifyOptions *x509.VerifyOptions
	allowRevoked  bool
	crlCache      map[string]*x509.RevocationList // issuer -> CRL
	mu            sync.RWMutex
	closed        bool
}

// New creates a new CertStore whose DAOs config.DAOs builds in
// DatabaseName. The factory must already serve that database; the errors
// are pkg/dao's.
//
// Example usage:
//
//	certStore, err := certstore.New(&certstore.Config{
//	    DAOs: dao.NewStoreFactory(qrdbsdk.NewMemoryKVStore()),
//	})
func New(config *Config) (CertStore, error) {
	if config == nil {
		return nil, ErrInvalidConfig
	}
	certs, err := newDAO(config.DAOs, certificateEntityType, func() *certificateEntity { return &certificateEntity{} })
	if err != nil {
		return nil, err
	}
	chains, err := newDAO(config.DAOs, chainEntityType, func() *chainEntity { return &chainEntity{} })
	if err != nil {
		return nil, err
	}

	verifyOpts := config.VerifyOptions
	if verifyOpts == nil {
		verifyOpts = &x509.VerifyOptions{
			CurrentTime: time.Now(),
		}
	}

	return &compositeCertStore{
		certs:         certs,
		chains:        chains,
		verifyOptions: verifyOpts,
		allowRevoked:  config.AllowRevoked,
		crlCache:      make(map[string]*x509.RevocationList),
	}, nil
}

// newDAO builds the DAO of one certificate store entity type, its IDs
// derived from the entity's natural key with a collision-resistant hash.
func newDAO[E qrdbsdk.Entity](daos *qrdbsdk.DAOFactory, entityType string, newEntity func() E) (qrdbsdk.GenericDAO[E], error) {
	return dao.New(daos, DatabaseName, entityType, newEntity,
		qrdbsdk.WithIDGenerator(qrdbsdk.NewCryptoFieldHashGenerator(naturalKeyField)))
}

// load returns the entity whose natural key is key, or a *NotFoundError
// matching notFound when there is none.
func load[E qrdbsdk.Entity](ctx context.Context, d qrdbsdk.GenericDAO[E], key string, notFound error) (E, error) {
	entity, err := d.GetByNaturalKey(ctx, key)
	if qrdbsdk.IsDAONotFound(err) {
		var zero E
		return zero, &NotFoundError{Sentinel: notFound, Key: key, Err: err}
	}
	if err != nil {
		var zero E
		return zero, &StoreError{Op: "get", Key: key, Err: err}
	}
	return entity, nil
}

// parseCertificate decodes the DER of the record stored under key.
func parseCertificate(key string, der []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, &StoreError{Op: "decode", Key: key, Err: err}
	}
	return cert, nil
}

// ========================================================================
// Basic Certificate Operations
// ========================================================================

// StoreCertificate stores a certificate under its CertificateKey, replacing
// any certificate stored there.
func (cs *compositeCertStore) StoreCertificate(cert *x509.Certificate) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.closed {
		return ErrStorageClosed
	}

	if cert == nil || len(cert.Raw) == 0 {
		return ErrCertInvalid
	}

	// A certificate with a non-empty Subject is keyed by its Common Name, as
	// always. One with an empty Subject -- the WebAuthn Level 2 §8.3.1
	// profile Local Attestation Key certificate go-xkms#715 introduced is the
	// first example -- is keyed by its SPKI SHA-256 thumbprint instead of
	// being refused outright: see CertificateKey.
	key := CertificateKey(cert)
	if key == "" {
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

	if err := cs.certs.Save(context.Background(), &certificateEntity{Key: key, DER: cert.Raw}); err != nil {
		return &StoreError{Op: "put", Key: key, Err: err}
	}
	return nil
}

// GetCertificate retrieves a certificate by its CertificateKey, or a
// *NotFoundError matching ErrCertNotFound.
func (cs *compositeCertStore) GetCertificate(cn string) (*x509.Certificate, error) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if cs.closed {
		return nil, ErrStorageClosed
	}

	if cn == "" {
		return nil, ErrInvalidCN
	}

	entity, err := load(context.Background(), cs.certs, cn, ErrCertNotFound)
	if err != nil {
		return nil, err
	}
	return parseCertificate(cn, entity.DER)
}

// DeleteCertificate removes a certificate by its CertificateKey, or returns
// a *NotFoundError matching ErrCertNotFound when none is stored there.
func (cs *compositeCertStore) DeleteCertificate(cn string) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.closed {
		return ErrStorageClosed
	}

	if cn == "" {
		return ErrInvalidCN
	}

	ctx := context.Background()
	entity, err := load(ctx, cs.certs, cn, ErrCertNotFound)
	if err != nil {
		return err
	}
	if err := cs.certs.Delete(ctx, entity); err != nil {
		return &StoreError{Op: "delete", Key: cn, Err: err}
	}
	return nil
}

// ListCertificates returns all certificates currently stored, in storage
// order.
func (cs *compositeCertStore) ListCertificates() ([]*x509.Certificate, error) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if cs.closed {
		return nil, ErrStorageClosed
	}

	var certs []*x509.Certificate
	query := qrdbsdk.PageQuery{Page: 1, PageSize: listPageSize}
	err := cs.certs.ForEachPage(context.Background(), query, func(page qrdbsdk.PageResult[*certificateEntity]) error {
		for _, entity := range page.Entities {
			cert, err := parseCertificate(entity.Key, entity.DER)
			if err != nil {
				return err
			}
			certs = append(certs, cert)
		}
		return nil
	})
	if err != nil {
		return nil, &StoreError{Op: "list", Key: certificateEntityType, Err: err}
	}
	return certs, nil
}

// ========================================================================
// Certificate Chain Operations
// ========================================================================

// StoreCertificateChain stores a certificate chain under its leaf's
// CertificateKey, replacing any chain stored there.
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

	// Use the leaf certificate's key, the same rule StoreCertificate applies
	// (see CertificateKey), as the chain identifier.
	key := CertificateKey(chain[0])
	if key == "" {
		return ErrInvalidCN
	}

	der := make([][]byte, 0, len(chain))
	for i, cert := range chain {
		if cert == nil || len(cert.Raw) == 0 {
			return &errs.Detail{Err: ErrChainInvalid, Detail: fmt.Sprintf("certificate at index %d is nil or not parsed from DER", i)}
		}
		der = append(der, cert.Raw)
	}

	if err := cs.chains.Save(context.Background(), &chainEntity{Key: key, DER: der}); err != nil {
		return &StoreError{Op: "put", Key: key, Err: err}
	}
	return nil
}

// GetCertificateChain retrieves a certificate chain by its leaf's
// CertificateKey, or a *NotFoundError matching ErrChainNotFound.
func (cs *compositeCertStore) GetCertificateChain(cn string) ([]*x509.Certificate, error) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if cs.closed {
		return nil, ErrStorageClosed
	}

	if cn == "" {
		return nil, ErrInvalidCN
	}

	entity, err := load(context.Background(), cs.chains, cn, ErrChainNotFound)
	if err != nil {
		return nil, err
	}
	chain := make([]*x509.Certificate, 0, len(entity.DER))
	for _, der := range entity.DER {
		cert, err := parseCertificate(cn, der)
		if err != nil {
			return nil, err
		}
		chain = append(chain, cert)
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

// Close marks the store closed and drops its CRL cache. The DAO factory
// belongs to the composition root, which closes the datastore behind it.
func (cs *compositeCertStore) Close() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cs.closed = true
	cs.crlCache = nil
	return nil
}

// Verify interface compliance at compile time
var _ CertStore = (*compositeCertStore)(nil)
