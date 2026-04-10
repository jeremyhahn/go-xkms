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
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

const (
	certsDirName   = "certificates"
	metadataFile   = "metadata.json"
	pemFileMode    = 0o600
	dirMode        = 0o700
	metadataMode   = 0o600
	pemFileExt     = ".pem"
	pemBlockType   = "CERTIFICATE"
	fingerprintLen = 64 // SHA-256 hex-encoded length
)

// fingerprintPattern matches a valid lowercase hex-encoded SHA-256 fingerprint.
var fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// CertMetadata holds metadata about a trusted certificate, stored in the
// metadata index for fast lookups without parsing PEM files.
type CertMetadata struct {
	Subject         string      `json:"subject"`
	Issuer          string      `json:"issuer"`
	Fingerprint     string      `json:"fingerprint"`
	NotBefore       time.Time   `json:"not_before"`
	NotAfter        time.Time   `json:"not_after"`
	Algorithm       string      `json:"algorithm"`
	AddedAt         time.Time   `json:"added_at"`
	Purpose         CertPurpose `json:"purpose"`
	Source          string      `json:"source,omitempty"`
	Tags            []string    `json:"tags,omitempty"`
	SystemInstalled bool        `json:"system_installed"`
}

// AddCertificateOptions configures optional metadata for certificate import.
type AddCertificateOptions struct {
	Purpose CertPurpose
	Source  string
	Tags    []string
}

// FileStoreConfig holds the configuration for a file-based trust store.
type FileStoreConfig struct {
	// BaseDir is the root directory for the trust store.
	// The store will create a "certificates" subdirectory and a
	// "metadata.json" file within this directory.
	BaseDir string
}

// FileStore implements TrustStore using the local filesystem. Certificates
// are stored as individual PEM files named by their SHA-256 fingerprint,
// and a JSON metadata index provides fast lookups without certificate parsing.
type FileStore struct {
	config    *FileStoreConfig
	mu        sync.RWMutex
	certs     map[string]*x509.Certificate // fingerprint -> cert
	metadata  map[string]*CertMetadata     // fingerprint -> metadata
	pool      *x509.CertPool               // cached cert pool
	poolDirty bool                         // true when pool needs rebuild
	closed    bool
}

// NewFileStore creates a new file-based trust store. It creates the necessary
// directories if they do not exist and loads any existing certificates from disk.
func NewFileStore(cfg *FileStoreConfig) (*FileStore, error) {
	if cfg == nil || cfg.BaseDir == "" {
		return nil, fmt.Errorf("%w: base directory is required", ErrInvalidCertificate)
	}

	certsDir := filepath.Join(cfg.BaseDir, certsDirName)
	if err := os.MkdirAll(certsDir, dirMode); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStorageWrite, err)
	}

	fs := &FileStore{
		config:    cfg,
		certs:     make(map[string]*x509.Certificate),
		metadata:  make(map[string]*CertMetadata),
		poolDirty: true,
	}

	if err := fs.loadFromDisk(); err != nil {
		return nil, err
	}

	return fs, nil
}

// AddCertificate adds a trusted certificate to the store. It persists the
// certificate as a PEM file and updates the metadata index.
func (fs *FileStore) AddCertificate(cert *x509.Certificate) error {
	if cert == nil {
		return ErrInvalidCertificate
	}

	fp := Fingerprint(cert)

	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.closed {
		return ErrStoreClosed
	}

	if _, exists := fs.certs[fp]; exists {
		return ErrCertificateExists
	}

	if err := fs.writeCertPEM(fp, cert); err != nil {
		return err
	}

	meta := newCertMetadata(cert, fp)
	fs.certs[fp] = cert
	fs.metadata[fp] = meta
	fs.poolDirty = true

	if err := fs.writeMetadata(); err != nil {
		// Roll back the in-memory state and PEM file on metadata write failure.
		delete(fs.certs, fp)
		delete(fs.metadata, fp)
		_ = os.Remove(fs.certPath(fp))
		return err
	}

	return nil
}

// AddCertificateWithOptions adds a trusted certificate with explicit metadata.
// If opts.Purpose is empty, the purpose is auto-classified from the certificate.
func (fs *FileStore) AddCertificateWithOptions(cert *x509.Certificate, opts *AddCertificateOptions) error {
	if cert == nil {
		return ErrInvalidCertificate
	}
	if opts == nil {
		return fs.AddCertificate(cert)
	}

	fp := Fingerprint(cert)

	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.closed {
		return ErrStoreClosed
	}

	if _, exists := fs.certs[fp]; exists {
		return ErrCertificateExists
	}

	if err := fs.writeCertPEM(fp, cert); err != nil {
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

	fs.certs[fp] = cert
	fs.metadata[fp] = meta
	fs.poolDirty = true

	if err := fs.writeMetadata(); err != nil {
		delete(fs.certs, fp)
		delete(fs.metadata, fp)
		_ = os.Remove(fs.certPath(fp))
		return err
	}

	return nil
}

// AddPEM parses and adds all certificates from PEM-encoded data. It returns
// the number of certificates successfully added. Certificates that already
// exist in the store are silently skipped.
func (fs *FileStore) AddPEM(pemData []byte) (int, error) {
	if len(pemData) == 0 {
		return 0, ErrInvalidCertificate
	}

	certs, err := parsePEMCertificates(pemData)
	if err != nil {
		return 0, err
	}

	added := 0
	for _, cert := range certs {
		err := fs.AddCertificate(cert)
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
func (fs *FileStore) RemoveCertificate(fingerprint string) error {
	if err := validateFingerprint(fingerprint); err != nil {
		return err
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.closed {
		return ErrStoreClosed
	}

	if _, exists := fs.certs[fingerprint]; !exists {
		return ErrCertificateNotFound
	}

	// Remove PEM file from disk.
	pemPath := fs.certPath(fingerprint)
	if err := os.Remove(pemPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("%w: %v", ErrStorageWrite, err)
	}

	// Remove from in-memory state.
	delete(fs.certs, fingerprint)
	delete(fs.metadata, fingerprint)
	fs.poolDirty = true

	if err := fs.writeMetadata(); err != nil {
		return err
	}

	return nil
}

// Certificates returns a copy of all trusted certificates in the store.
func (fs *FileStore) Certificates() ([]*x509.Certificate, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	if fs.closed {
		return nil, ErrStoreClosed
	}

	result := make([]*x509.Certificate, 0, len(fs.certs))
	for _, cert := range fs.certs {
		result = append(result, cert)
	}

	return result, nil
}

// CertificatesByPurpose returns all certificates matching the given purpose.
func (fs *FileStore) CertificatesByPurpose(purpose CertPurpose) ([]*x509.Certificate, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	if fs.closed {
		return nil, ErrStoreClosed
	}

	var result []*x509.Certificate
	for fp, meta := range fs.metadata {
		if meta.Purpose == purpose {
			if cert, ok := fs.certs[fp]; ok {
				result = append(result, cert)
			}
		}
	}

	return result, nil
}

// Metadata returns the metadata for a certificate by fingerprint.
func (fs *FileStore) Metadata(fingerprint string) (*CertMetadata, error) {
	if err := validateFingerprint(fingerprint); err != nil {
		return nil, err
	}

	fs.mu.RLock()
	defer fs.mu.RUnlock()

	if fs.closed {
		return nil, ErrStoreClosed
	}

	meta, ok := fs.metadata[fingerprint]
	if !ok {
		return nil, ErrCertificateNotFound
	}

	return meta, nil
}

// SetPurpose updates the purpose of a certificate by fingerprint.
func (fs *FileStore) SetPurpose(fingerprint string, purpose CertPurpose) error {
	if err := validateFingerprint(fingerprint); err != nil {
		return err
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.closed {
		return ErrStoreClosed
	}

	meta, ok := fs.metadata[fingerprint]
	if !ok {
		return ErrCertificateNotFound
	}

	meta.Purpose = purpose

	return fs.writeMetadata()
}

// SetSource updates the source of a certificate by fingerprint.
func (fs *FileStore) SetSource(fingerprint string, source string) error {
	if err := validateFingerprint(fingerprint); err != nil {
		return err
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.closed {
		return ErrStoreClosed
	}

	meta, ok := fs.metadata[fingerprint]
	if !ok {
		return ErrCertificateNotFound
	}

	meta.Source = source

	return fs.writeMetadata()
}

// SetSystemInstalled updates the system-installed flag for a certificate.
func (fs *FileStore) SetSystemInstalled(fingerprint string, installed bool) error {
	if err := validateFingerprint(fingerprint); err != nil {
		return err
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.closed {
		return ErrStoreClosed
	}

	meta, ok := fs.metadata[fingerprint]
	if !ok {
		return ErrCertificateNotFound
	}

	meta.SystemInstalled = installed

	return fs.writeMetadata()
}

// SetTags updates the tags for a certificate by fingerprint.
func (fs *FileStore) SetTags(fingerprint string, tags []string) error {
	if err := validateFingerprint(fingerprint); err != nil {
		return err
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.closed {
		return ErrStoreClosed
	}

	meta, ok := fs.metadata[fingerprint]
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

	return fs.writeMetadata()
}

// CertPool returns an x509.CertPool containing all trusted certificates.
// The pool is cached and rebuilt only when the store has been mutated.
func (fs *FileStore) CertPool() (*x509.CertPool, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.closed {
		return nil, ErrStoreClosed
	}

	if !fs.poolDirty && fs.pool != nil {
		return fs.pool, nil
	}

	pool := x509.NewCertPool()
	for _, cert := range fs.certs {
		pool.AddCert(cert)
	}

	fs.pool = pool
	fs.poolDirty = false

	return fs.pool, nil
}

// Contains checks if a certificate with the given fingerprint is in the store.
func (fs *FileStore) Contains(fingerprint string) (bool, error) {
	if err := validateFingerprint(fingerprint); err != nil {
		return false, err
	}

	fs.mu.RLock()
	defer fs.mu.RUnlock()

	if fs.closed {
		return false, ErrStoreClosed
	}

	_, exists := fs.certs[fingerprint]
	return exists, nil
}

// Count returns the number of trusted certificates in the store.
func (fs *FileStore) Count() (int, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	if fs.closed {
		return 0, ErrStoreClosed
	}

	return len(fs.certs), nil
}

// Close marks the store as closed. Subsequent operations return ErrStoreClosed.
func (fs *FileStore) Close() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.closed {
		return ErrStoreClosed
	}

	fs.closed = true
	fs.pool = nil

	return nil
}

// loadFromDisk loads existing certificates and metadata from the filesystem.
// It first attempts to load from the metadata index, then validates against
// PEM files on disk. If no metadata file exists, it rebuilds from PEM files.
func (fs *FileStore) loadFromDisk() error {
	metaPath := filepath.Join(fs.config.BaseDir, metadataFile)

	metaData, err := os.ReadFile(metaPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("%w: %v", ErrStorageRead, err)
	}

	// Load metadata index if it exists.
	if err == nil && len(metaData) > 0 {
		var entries []*CertMetadata
		if jsonErr := json.Unmarshal(metaData, &entries); jsonErr != nil {
			// Metadata is corrupt; fall through to rebuild from PEM files.
			entries = nil
		}

		if entries != nil {
			return fs.loadFromMetadata(entries)
		}
	}

	// No metadata or corrupt metadata: rebuild from PEM files.
	return fs.loadFromPEMFiles()
}

// loadFromMetadata loads certificates from disk using the metadata index
// for fast fingerprint-based lookups.
func (fs *FileStore) loadFromMetadata(entries []*CertMetadata) error {
	for _, meta := range entries {
		pemPath := fs.certPath(meta.Fingerprint)
		cert, err := readCertPEM(pemPath)
		if err != nil {
			// PEM file missing or corrupt; skip this entry.
			continue
		}

		// Verify the fingerprint matches.
		actualFP := Fingerprint(cert)
		if actualFP != meta.Fingerprint {
			continue
		}

		fs.certs[meta.Fingerprint] = cert
		fs.metadata[meta.Fingerprint] = meta
	}

	return nil
}

// loadFromPEMFiles scans the certificates directory and loads all PEM files,
// rebuilding the metadata index.
func (fs *FileStore) loadFromPEMFiles() error {
	certsDir := filepath.Join(fs.config.BaseDir, certsDirName)

	entries, err := os.ReadDir(certsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("%w: %v", ErrStorageRead, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) != pemFileExt {
			continue
		}

		pemPath := filepath.Join(certsDir, entry.Name())
		cert, err := readCertPEM(pemPath)
		if err != nil {
			continue
		}

		fp := Fingerprint(cert)
		meta := newCertMetadata(cert, fp)
		fs.certs[fp] = cert
		fs.metadata[fp] = meta
	}

	// Rebuild metadata file from loaded certificates.
	if len(fs.metadata) > 0 {
		if err := fs.writeMetadata(); err != nil {
			return err
		}
	}

	return nil
}

// writeCertPEM writes a certificate as a PEM file to the certificates directory.
func (fs *FileStore) writeCertPEM(fingerprint string, cert *x509.Certificate) error {
	pemPath := fs.certPath(fingerprint)

	block := &pem.Block{
		Type:  pemBlockType,
		Bytes: cert.Raw,
	}

	pemBytes := pem.EncodeToMemory(block)
	if err := os.WriteFile(pemPath, pemBytes, pemFileMode); err != nil {
		return fmt.Errorf("%w: %v", ErrStorageWrite, err)
	}

	return nil
}

// writeMetadata writes the current metadata index to disk as JSON.
func (fs *FileStore) writeMetadata() error {
	entries := make([]*CertMetadata, 0, len(fs.metadata))
	for _, meta := range fs.metadata {
		entries = append(entries, meta)
	}

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageWrite, err)
	}

	metaPath := filepath.Join(fs.config.BaseDir, metadataFile)

	// Write to a temp file first, then rename for atomicity.
	tmpPath := metaPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, metadataMode); err != nil {
		return fmt.Errorf("%w: %v", ErrStorageWrite, err)
	}

	if err := os.Rename(tmpPath, metaPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("%w: %v", ErrStorageWrite, err)
	}

	return nil
}

// certPath returns the filesystem path for a certificate PEM file.
func (fs *FileStore) certPath(fingerprint string) string {
	return filepath.Join(fs.config.BaseDir, certsDirName, fingerprint+pemFileExt)
}

// readCertPEM reads and parses a single PEM-encoded certificate from a file.
func readCertPEM(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStorageRead, err)
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != pemBlockType {
		return nil, fmt.Errorf("%w: invalid PEM block in %s", ErrInvalidCertificate, path)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
	}

	return cert, nil
}

// parsePEMCertificates parses all PEM-encoded certificates from the given data.
func parsePEMCertificates(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemData

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != pemBlockType {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, ErrInvalidCertificate
	}

	return certs, nil
}

// newCertMetadata creates a CertMetadata from a certificate and its fingerprint.
func newCertMetadata(cert *x509.Certificate, fingerprint string) *CertMetadata {
	return &CertMetadata{
		Subject:     cert.Subject.String(),
		Issuer:      cert.Issuer.String(),
		Fingerprint: fingerprint,
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		Algorithm:   algorithmName(cert.PublicKeyAlgorithm),
		AddedAt:     time.Now().UTC(),
		Purpose:     ClassifyCertificate(cert),
	}
}

// validateFingerprint checks that a fingerprint is a valid lowercase
// hex-encoded SHA-256 hash.
func validateFingerprint(fingerprint string) error {
	if !fingerprintPattern.MatchString(fingerprint) {
		return ErrInvalidFingerprint
	}
	return nil
}
