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

package truststore

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

const (
	certKeyPrefix     = "certificates/"
	metadataKeyPrefix = "metadata/"
	certKeySuffix     = ".pem"
	metadataKeySuffix = ".json"
)

// BackendStore implements TrustStore using a storage.Backend for persistence.
// Each certificate is stored as an individual PEM entry keyed by its SHA-256
// fingerprint, and each metadata entry is stored as an individual JSON entry.
// This enables transparent encryption when the backend is a barrier.
type BackendStore struct {
	mu      sync.RWMutex
	backend storage.Backend
	prefix  string
	certs   map[string]*x509.Certificate // fingerprint -> parsed cert (in-memory cache)
	meta    map[string]*CertMetadata     // fingerprint -> metadata (in-memory cache)
	pool    *x509.CertPool               // cached cert pool
	dirty   bool                         // true when pool needs rebuild
	closed  bool
}

// NewBackendStore creates a new BackendStore using the given storage backend.
// The prefix is prepended to all storage keys (e.g., "trust/" produces keys
// like "trust/certificates/{fingerprint}.pem"). Existing data in the backend
// is loaded into the in-memory cache on creation.
func NewBackendStore(backend storage.Backend, prefix string) (*BackendStore, error) {
	if backend == nil {
		return nil, fmt.Errorf("%w: storage backend is required", ErrInvalidCertificate)
	}

	bs := &BackendStore{
		backend: backend,
		prefix:  prefix,
		certs:   make(map[string]*x509.Certificate),
		meta:    make(map[string]*CertMetadata),
		dirty:   true,
	}

	if err := bs.loadFromBackend(); err != nil {
		return nil, err
	}

	return bs, nil
}

// certKey returns the storage key for a certificate PEM entry.
func (bs *BackendStore) certKey(fingerprint string) string {
	return bs.prefix + certKeyPrefix + fingerprint + certKeySuffix
}

// metaKey returns the storage key for a certificate metadata entry.
func (bs *BackendStore) metaKey(fingerprint string) string {
	return bs.prefix + metadataKeyPrefix + fingerprint + metadataKeySuffix
}

// AddCertificate adds a trusted certificate to the store. It persists the
// certificate as a PEM entry and creates an individual metadata entry.
func (bs *BackendStore) AddCertificate(cert *x509.Certificate) error {
	if cert == nil {
		return ErrInvalidCertificate
	}

	fp := Fingerprint(cert)

	bs.mu.Lock()
	defer bs.mu.Unlock()

	if bs.closed {
		return ErrStoreClosed
	}

	if _, exists := bs.certs[fp]; exists {
		return ErrCertificateExists
	}

	if err := bs.writeCert(fp, cert); err != nil {
		return err
	}

	meta := newCertMetadata(cert, fp)
	if err := bs.writeMeta(fp, meta); err != nil {
		// Roll back the certificate entry on metadata write failure.
		_ = bs.backend.Delete(context.Background(), bs.certKey(fp))
		return err
	}

	bs.certs[fp] = cert
	bs.meta[fp] = meta
	bs.dirty = true

	return nil
}

// AddCertificateWithOptions adds a trusted certificate with explicit metadata.
// If opts.Purpose is empty, the purpose is auto-classified from the certificate.
func (bs *BackendStore) AddCertificateWithOptions(cert *x509.Certificate, opts *AddCertificateOptions) error {
	if cert == nil {
		return ErrInvalidCertificate
	}
	if opts == nil {
		return bs.AddCertificate(cert)
	}

	fp := Fingerprint(cert)

	bs.mu.Lock()
	defer bs.mu.Unlock()

	if bs.closed {
		return ErrStoreClosed
	}

	if _, exists := bs.certs[fp]; exists {
		return ErrCertificateExists
	}

	if err := bs.writeCert(fp, cert); err != nil {
		return err
	}

	meta := newCertMetadata(cert, fp)
	if opts.Purpose != "" {
		meta.Purpose = opts.Purpose
	}
	if opts.Source != "" {
		meta.Source = opts.Source
	}
	if len(opts.Tags) > 0 {
		tags := make([]string, len(opts.Tags))
		copy(tags, opts.Tags)
		meta.Tags = tags
	}

	if err := bs.writeMeta(fp, meta); err != nil {
		_ = bs.backend.Delete(context.Background(), bs.certKey(fp))
		return err
	}

	bs.certs[fp] = cert
	bs.meta[fp] = meta
	bs.dirty = true

	return nil
}

// AddPEM parses and adds all certificates from PEM-encoded data. It returns
// the number of certificates successfully added. Certificates that already
// exist in the store are silently skipped.
func (bs *BackendStore) AddPEM(pemData []byte) (int, error) {
	if len(pemData) == 0 {
		return 0, ErrInvalidCertificate
	}

	certs, err := parsePEMCertificates(pemData)
	if err != nil {
		return 0, err
	}

	added := 0
	for _, cert := range certs {
		err := bs.AddCertificate(cert)
		if err == ErrCertificateExists {
			continue
		}
		if err != nil {
			return added, err
		}
		added++
	}

	return added, nil
}

// RemoveCertificate removes a certificate by its SHA-256 fingerprint.
func (bs *BackendStore) RemoveCertificate(fingerprint string) error {
	if err := validateFingerprint(fingerprint); err != nil {
		return err
	}

	bs.mu.Lock()
	defer bs.mu.Unlock()

	if bs.closed {
		return ErrStoreClosed
	}

	if _, exists := bs.certs[fingerprint]; !exists {
		return ErrCertificateNotFound
	}

	// Delete certificate PEM entry.
	if err := bs.backend.Delete(context.Background(), bs.certKey(fingerprint)); err != nil && !errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("%w: %v", ErrStorageWrite, err)
	}

	// Delete metadata entry.
	if err := bs.backend.Delete(context.Background(), bs.metaKey(fingerprint)); err != nil && !errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("%w: %v", ErrStorageWrite, err)
	}

	delete(bs.certs, fingerprint)
	delete(bs.meta, fingerprint)
	bs.dirty = true

	return nil
}

// Certificates returns a copy of all trusted certificates in the store.
func (bs *BackendStore) Certificates() ([]*x509.Certificate, error) {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	if bs.closed {
		return nil, ErrStoreClosed
	}

	result := make([]*x509.Certificate, 0, len(bs.certs))
	for _, cert := range bs.certs {
		result = append(result, cert)
	}

	return result, nil
}

// CertificatesByPurpose returns all certificates matching the given purpose.
func (bs *BackendStore) CertificatesByPurpose(purpose CertPurpose) ([]*x509.Certificate, error) {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	if bs.closed {
		return nil, ErrStoreClosed
	}

	var result []*x509.Certificate
	for fp, meta := range bs.meta {
		if meta.Purpose == purpose {
			if cert, ok := bs.certs[fp]; ok {
				result = append(result, cert)
			}
		}
	}

	return result, nil
}

// Metadata returns the metadata for a certificate by fingerprint.
func (bs *BackendStore) Metadata(fingerprint string) (*CertMetadata, error) {
	if err := validateFingerprint(fingerprint); err != nil {
		return nil, err
	}

	bs.mu.RLock()
	defer bs.mu.RUnlock()

	if bs.closed {
		return nil, ErrStoreClosed
	}

	meta, ok := bs.meta[fingerprint]
	if !ok {
		return nil, ErrCertificateNotFound
	}

	return meta, nil
}

// SetPurpose updates the purpose of a certificate by fingerprint.
func (bs *BackendStore) SetPurpose(fingerprint string, purpose CertPurpose) error {
	if err := validateFingerprint(fingerprint); err != nil {
		return err
	}

	bs.mu.Lock()
	defer bs.mu.Unlock()

	if bs.closed {
		return ErrStoreClosed
	}

	meta, ok := bs.meta[fingerprint]
	if !ok {
		return ErrCertificateNotFound
	}

	meta.Purpose = purpose

	return bs.writeMeta(fingerprint, meta)
}

// SetSource updates the source of a certificate by fingerprint.
func (bs *BackendStore) SetSource(fingerprint string, source string) error {
	if err := validateFingerprint(fingerprint); err != nil {
		return err
	}

	bs.mu.Lock()
	defer bs.mu.Unlock()

	if bs.closed {
		return ErrStoreClosed
	}

	meta, ok := bs.meta[fingerprint]
	if !ok {
		return ErrCertificateNotFound
	}

	meta.Source = source

	return bs.writeMeta(fingerprint, meta)
}

// SetSystemInstalled updates the system-installed flag for a certificate.
func (bs *BackendStore) SetSystemInstalled(fingerprint string, installed bool) error {
	if err := validateFingerprint(fingerprint); err != nil {
		return err
	}

	bs.mu.Lock()
	defer bs.mu.Unlock()

	if bs.closed {
		return ErrStoreClosed
	}

	meta, ok := bs.meta[fingerprint]
	if !ok {
		return ErrCertificateNotFound
	}

	meta.SystemInstalled = installed

	return bs.writeMeta(fingerprint, meta)
}

// SetTags updates the tags for a certificate by fingerprint.
func (bs *BackendStore) SetTags(fingerprint string, tags []string) error {
	if err := validateFingerprint(fingerprint); err != nil {
		return err
	}

	bs.mu.Lock()
	defer bs.mu.Unlock()

	if bs.closed {
		return ErrStoreClosed
	}

	meta, ok := bs.meta[fingerprint]
	if !ok {
		return ErrCertificateNotFound
	}

	if len(tags) > 0 {
		tagsCopy := make([]string, len(tags))
		copy(tagsCopy, tags)
		meta.Tags = tagsCopy
	} else {
		meta.Tags = nil
	}

	return bs.writeMeta(fingerprint, meta)
}

// CertPool returns an x509.CertPool containing all trusted certificates.
// The pool is cached and rebuilt only when the store has been mutated.
func (bs *BackendStore) CertPool() (*x509.CertPool, error) {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	if bs.closed {
		return nil, ErrStoreClosed
	}

	if !bs.dirty && bs.pool != nil {
		return bs.pool, nil
	}

	pool := x509.NewCertPool()
	for _, cert := range bs.certs {
		pool.AddCert(cert)
	}

	bs.pool = pool
	bs.dirty = false

	return bs.pool, nil
}

// Contains checks if a certificate with the given fingerprint is in the store.
func (bs *BackendStore) Contains(fingerprint string) (bool, error) {
	if err := validateFingerprint(fingerprint); err != nil {
		return false, err
	}

	bs.mu.RLock()
	defer bs.mu.RUnlock()

	if bs.closed {
		return false, ErrStoreClosed
	}

	_, exists := bs.certs[fingerprint]
	return exists, nil
}

// Count returns the number of trusted certificates in the store.
func (bs *BackendStore) Count() (int, error) {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	if bs.closed {
		return 0, ErrStoreClosed
	}

	return len(bs.certs), nil
}

// Close marks the store as closed. It does NOT close the backend since it
// may be shared with other components. Subsequent operations return ErrStoreClosed.
func (bs *BackendStore) Close() error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	if bs.closed {
		return ErrStoreClosed
	}

	bs.closed = true
	bs.pool = nil

	return nil
}

// loadFromBackend loads existing certificates and metadata from the storage
// backend into the in-memory cache.
func (bs *BackendStore) loadFromBackend() error {
	// Load metadata entries first.
	metaPrefix := bs.prefix + metadataKeyPrefix
	metaKeys, err := bs.backend.List(context.Background(), metaPrefix)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageRead, err)
	}

	for _, key := range metaKeys {
		data, getErr := bs.backend.Get(context.Background(), key)
		if getErr != nil {
			if errors.Is(getErr, storage.ErrNotFound) {
				continue
			}
			return fmt.Errorf("%w: %v", ErrStorageRead, getErr)
		}

		var meta CertMetadata
		if jsonErr := json.Unmarshal(data, &meta); jsonErr != nil {
			// Corrupt metadata entry; skip.
			continue
		}

		// Load the corresponding certificate PEM.
		certData, certErr := bs.backend.Get(context.Background(), bs.certKey(meta.Fingerprint))
		if certErr != nil {
			// Certificate missing; skip this entry.
			continue
		}

		cert, parseErr := parsePEMBytes(certData)
		if parseErr != nil {
			// Corrupt PEM; skip.
			continue
		}

		// Verify fingerprint matches.
		actualFP := Fingerprint(cert)
		if actualFP != meta.Fingerprint {
			continue
		}

		bs.certs[meta.Fingerprint] = cert
		bs.meta[meta.Fingerprint] = &meta
	}

	// If no metadata was loaded, try rebuilding from certificate PEM entries.
	if len(bs.meta) == 0 {
		if err := bs.rebuildFromCerts(); err != nil {
			return err
		}
	}

	return nil
}

// rebuildFromCerts scans certificate PEM entries in the backend and rebuilds
// metadata for any certificates that lack metadata entries.
func (bs *BackendStore) rebuildFromCerts() error {
	certPrefix := bs.prefix + certKeyPrefix
	certKeys, err := bs.backend.List(context.Background(), certPrefix)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageRead, err)
	}

	for _, key := range certKeys {
		// Extract fingerprint from key: {prefix}certificates/{fingerprint}.pem
		fp := extractFingerprint(key, certPrefix, certKeySuffix)
		if fp == "" {
			continue
		}

		data, getErr := bs.backend.Get(context.Background(), key)
		if getErr != nil {
			if errors.Is(getErr, storage.ErrNotFound) {
				continue
			}
			continue
		}

		cert, parseErr := parsePEMBytes(data)
		if parseErr != nil {
			continue
		}

		actualFP := Fingerprint(cert)
		if actualFP != fp {
			continue
		}

		meta := newCertMetadata(cert, fp)
		bs.certs[fp] = cert
		bs.meta[fp] = meta

		// Persist the rebuilt metadata.
		_ = bs.writeMeta(fp, meta)
	}

	return nil
}

// writeCert writes a certificate as PEM-encoded data to the backend.
func (bs *BackendStore) writeCert(fingerprint string, cert *x509.Certificate) error {
	block := &pem.Block{
		Type:  pemBlockType,
		Bytes: cert.Raw,
	}
	pemBytes := pem.EncodeToMemory(block)

	if err := bs.backend.Put(context.Background(), bs.certKey(fingerprint), pemBytes); err != nil {
		return fmt.Errorf("%w: %v", ErrStorageWrite, err)
	}

	return nil
}

// writeMeta writes certificate metadata as JSON to the backend.
func (bs *BackendStore) writeMeta(fingerprint string, meta *CertMetadata) error {
	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageWrite, err)
	}

	if err := bs.backend.Put(context.Background(), bs.metaKey(fingerprint), data); err != nil {
		return fmt.Errorf("%w: %v", ErrStorageWrite, err)
	}

	return nil
}

// parsePEMBytes parses a single PEM-encoded certificate from raw bytes.
func parsePEMBytes(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != pemBlockType {
		return nil, fmt.Errorf("%w: invalid PEM block", ErrInvalidCertificate)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
	}

	return cert, nil
}

// extractFingerprint extracts the fingerprint from a storage key by stripping
// the prefix and suffix. Returns empty string if the key format is invalid.
func extractFingerprint(key, prefix, suffix string) string {
	if !strings.HasPrefix(key, prefix) || !strings.HasSuffix(key, suffix) {
		return ""
	}
	fp := key[len(prefix) : len(key)-len(suffix)]
	if !fingerprintPattern.MatchString(fp) {
		return ""
	}
	return fp
}
