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

package backup

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	// BackupVersion is the current backup format version.
	BackupVersion = 1

	// BackupMagic identifies xkey backup files.
	BackupMagic = "XKBK"
)

// Item type constants for the backup manifest.
const (
	ItemTrustStore = "trust-store"
	ItemCAData     = "ca-data"
	ItemOATH       = "oath-credentials"
	ItemPasswords  = "static-passwords"
	ItemConfig     = "config"
)

// ---------------------------------------------------------------------------
// Data-source interfaces
// ---------------------------------------------------------------------------

// TrustStoreReader provides read access to trust store data for backup.
type TrustStoreReader interface {
	Certificates() ([]*x509.Certificate, error)
	Metadata(fingerprint string) (*CertMetadataInfo, error)
}

// CertMetadataInfo is a simplified metadata structure the backup service
// uses. This avoids importing the truststore package directly.
type CertMetadataInfo struct {
	Fingerprint string
	Purpose     string
	Source      string
	Tags        []string
}

// OATHReader provides read access to OATH credentials for backup.
type OATHReader interface {
	List() ([]*OATHCredentialInfo, error)
}

// OATHCredentialInfo is a simplified credential for backup purposes.
type OATHCredentialInfo struct {
	ID          string
	Name        string
	Issuer      string
	AccountName string
	Secret      string
	Type        string
	Algorithm   string
	Digits      int
	Period      int
	Counter     int64
}

// OATHWriter provides write access for restoring OATH credentials.
type OATHWriter interface {
	Add(cred *OATHCredentialInfo) error
}

// PasswordReader provides read access to static passwords for backup.
type PasswordReader interface {
	List() ([]*PasswordInfo, error)
}

// PasswordInfo is simplified password data for backup.
type PasswordInfo struct {
	ID         string
	Name       string
	Title      string
	Username   string
	Password   string
	URL        string
	Notes      string
	FolderPath string
}

// PasswordWriter provides write access for restoring static passwords.
type PasswordWriter interface {
	Add(pw *PasswordInfo) error
}

// CAReader provides read access to CA data for backup.
type CAReader interface {
	GetCACertificatePEM() ([]byte, error)
	GetCAChainPEM() ([]byte, error)
}

// TrustStoreWriter accepts PEM data for restoring certificates.
type TrustStoreWriter interface {
	AddPEM(pemData []byte) (int, error)
}

// ---------------------------------------------------------------------------
// Backup / archive types
// ---------------------------------------------------------------------------

// Manifest describes the contents of a backup.
type Manifest struct {
	Version    int            `json:"version"`
	Created    time.Time      `json:"created"`
	DeviceName string         `json:"device_name"`
	Contents   []ManifestItem `json:"contents"`
	Checksum   string         `json:"checksum"`
}

// ManifestItem describes a single data category in the backup.
type ManifestItem struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

// Archive is the full backup structure serialized to JSON then encrypted.
type Archive struct {
	Manifest   Manifest         `json:"manifest"`
	TrustStore *TrustStoreData  `json:"trust_store,omitempty"`
	CAData     *CABackupData    `json:"ca_data,omitempty"`
	OATHCreds  []OATHCredential `json:"oath_credentials,omitempty"`
	Passwords  []PasswordEntry  `json:"passwords,omitempty"`
	Config     []byte           `json:"config,omitempty"`
}

// TrustStoreData holds all certificates and their metadata.
type TrustStoreData struct {
	Certificates []TrustStoreCert `json:"certificates"`
}

// TrustStoreCert holds a single certificate and its metadata for backup.
type TrustStoreCert struct {
	PEM         string   `json:"pem"`
	Fingerprint string   `json:"fingerprint"`
	Purpose     string   `json:"purpose"`
	Source      string   `json:"source"`
	Tags        []string `json:"tags,omitempty"`
}

// CABackupData holds CA certificate and metadata.
type CABackupData struct {
	CACertPEM  string `json:"ca_cert_pem"`
	CAChainPEM string `json:"ca_chain_pem,omitempty"`
}

// OATHCredential represents a single OATH credential for backup.
type OATHCredential struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Issuer      string `json:"issuer"`
	AccountName string `json:"account_name"`
	Secret      string `json:"secret"`
	Type        string `json:"type"`
	Algorithm   string `json:"algorithm"`
	Digits      int    `json:"digits"`
	Period      int    `json:"period"`
	Counter     int64  `json:"counter"`
}

// PasswordEntry represents a single static password for backup.
type PasswordEntry struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Title      string `json:"title,omitempty"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password"`
	URL        string `json:"url,omitempty"`
	Notes      string `json:"notes,omitempty"`
	FolderPath string `json:"folder_path,omitempty"`
}

// EncryptedBackup is the on-wire / file format.
type EncryptedBackup struct {
	Magic      string `json:"magic"`
	Version    int    `json:"version"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// RestoreResult reports the outcome of a restore operation.
type RestoreResult struct {
	ItemType string
	Restored int
	Skipped  int
	Errors   []string
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

// Config holds the backup service configuration.
type Config struct {
	DeviceName string
}

// Service provides backup and restore operations for xkey data.
type Service struct {
	config         *Config
	trustStore     TrustStoreReader
	oathReader     OATHReader
	passwordReader PasswordReader
	caReader       CAReader
}

// Option is a functional option for configuring the backup service.
type Option func(*Service)

// WithTrustStore attaches a TrustStoreReader data source.
func WithTrustStore(ts TrustStoreReader) Option {
	return func(s *Service) { s.trustStore = ts }
}

// WithOATH attaches an OATHReader data source.
func WithOATH(r OATHReader) Option {
	return func(s *Service) { s.oathReader = r }
}

// WithPasswords attaches a PasswordReader data source.
func WithPasswords(r PasswordReader) Option {
	return func(s *Service) { s.passwordReader = r }
}

// WithCA attaches a CAReader data source.
func WithCA(r CAReader) Option {
	return func(s *Service) { s.caReader = r }
}

// NewService creates a new backup service. Config must be non-nil.
// Data sources are optional; only non-nil sources are included in backups.
func NewService(config *Config, opts ...Option) (*Service, error) {
	if config == nil {
		return nil, ErrNilConfig
	}
	svc := &Service{config: config}
	for _, opt := range opts {
		opt(svc)
	}
	return svc, nil
}

// ---------------------------------------------------------------------------
// Backup
// ---------------------------------------------------------------------------

// CreateBackup collects data from all non-nil sources, serializes the
// archive to JSON, and encrypts it with XChaCha20-Poly1305. The key must
// be exactly 32 bytes.
func (s *Service) CreateBackup(key []byte) (*EncryptedBackup, error) {
	archive, err := s.collectArchive()
	if err != nil {
		return nil, err
	}

	// Serialize without checksum to compute the hash.
	archive.Manifest.Checksum = ""
	payload, err := json.Marshal(archive)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCollectFailed, err)
	}

	hash := sha256.Sum256(payload)
	archive.Manifest.Checksum = hex.EncodeToString(hash[:])

	// Re-serialize with checksum set.
	plaintext, err := json.Marshal(archive)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCollectFailed, err)
	}

	ciphertext, nonce, err := encrypt(plaintext, key)
	if err != nil {
		return nil, err
	}

	return &EncryptedBackup{
		Magic:      BackupMagic,
		Version:    BackupVersion,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}, nil
}

// DecryptBackup validates and decrypts an EncryptedBackup, verifies the
// payload checksum, and returns the deserialized Archive.
func (s *Service) DecryptBackup(eb *EncryptedBackup, key []byte) (*Archive, error) {
	if err := validateEncryptedBackup(eb); err != nil {
		return nil, err
	}

	plaintext, err := decrypt(eb.Ciphertext, eb.Nonce, key)
	if err != nil {
		return nil, err
	}

	var archive Archive
	if err := json.Unmarshal(plaintext, &archive); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidBackup, err)
	}

	// Verify checksum: re-compute hash with checksum field cleared.
	savedChecksum := archive.Manifest.Checksum
	archive.Manifest.Checksum = ""
	raw, err := json.Marshal(&archive)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptedBackup, err)
	}

	hash := sha256.Sum256(raw)
	computed := hex.EncodeToString(hash[:])
	if computed != savedChecksum {
		return nil, ErrCorruptedBackup
	}

	archive.Manifest.Checksum = savedChecksum
	return &archive, nil
}

// GetManifest decrypts the backup and returns only its manifest.
func (s *Service) GetManifest(eb *EncryptedBackup, key []byte) (*Manifest, error) {
	archive, err := s.DecryptBackup(eb, key)
	if err != nil {
		return nil, err
	}
	return &archive.Manifest, nil
}

// ---------------------------------------------------------------------------
// Restore
// ---------------------------------------------------------------------------

// RestoreTrustStore restores trust store certificates from the archive.
func (s *Service) RestoreTrustStore(archive *Archive, writer TrustStoreWriter) (*RestoreResult, error) {
	if archive == nil {
		return nil, fmt.Errorf("%w: nil archive", ErrRestoreFailed)
	}
	result := &RestoreResult{ItemType: ItemTrustStore}

	if archive.TrustStore == nil || len(archive.TrustStore.Certificates) == 0 {
		return result, nil
	}

	for _, cert := range archive.TrustStore.Certificates {
		n, err := writer.AddPEM([]byte(cert.PEM))
		if err != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("cert %s: %v", cert.Fingerprint, err))
			result.Skipped++
			continue
		}
		result.Restored += n
	}
	return result, nil
}

// RestoreOATH restores OATH credentials from the archive.
func (s *Service) RestoreOATH(archive *Archive, writer OATHWriter) (*RestoreResult, error) {
	if archive == nil {
		return nil, fmt.Errorf("%w: nil archive", ErrRestoreFailed)
	}
	result := &RestoreResult{ItemType: ItemOATH}

	for _, c := range archive.OATHCreds {
		info := &OATHCredentialInfo{
			ID:          c.ID,
			Name:        c.Name,
			Issuer:      c.Issuer,
			AccountName: c.AccountName,
			Secret:      c.Secret,
			Type:        c.Type,
			Algorithm:   c.Algorithm,
			Digits:      c.Digits,
			Period:      c.Period,
			Counter:     c.Counter,
		}
		if err := writer.Add(info); err != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("oath %s: %v", c.ID, err))
			result.Skipped++
			continue
		}
		result.Restored++
	}
	return result, nil
}

// RestorePasswords restores static passwords from the archive.
func (s *Service) RestorePasswords(archive *Archive, writer PasswordWriter) (*RestoreResult, error) {
	if archive == nil {
		return nil, fmt.Errorf("%w: nil archive", ErrRestoreFailed)
	}
	result := &RestoreResult{ItemType: ItemPasswords}

	for _, p := range archive.Passwords {
		info := &PasswordInfo{
			ID:         p.ID,
			Name:       p.Name,
			Title:      p.Title,
			Username:   p.Username,
			Password:   p.Password,
			URL:        p.URL,
			Notes:      p.Notes,
			FolderPath: p.FolderPath,
		}
		if err := writer.Add(info); err != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("password %s: %v", p.ID, err))
			result.Skipped++
			continue
		}
		result.Restored++
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Internal: data collection
// ---------------------------------------------------------------------------

// collectArchive gathers data from all non-nil sources and builds an Archive.
func (s *Service) collectArchive() (*Archive, error) {
	archive := &Archive{
		Manifest: Manifest{
			Version:    BackupVersion,
			Created:    time.Now().UTC(),
			DeviceName: s.config.DeviceName,
		},
	}

	hasData := false

	// Dispatch map for optional collectors. Each returns true if data was
	// added to the archive, and appends ManifestItems as needed.
	type collector func(a *Archive) (bool, error)

	collectors := map[string]collector{
		ItemTrustStore: s.collectTrustStore,
		ItemCAData:     s.collectCA,
		ItemOATH:       s.collectOATH,
		ItemPasswords:  s.collectPasswords,
	}

	// Deterministic ordering for manifest.
	order := []string{ItemTrustStore, ItemCAData, ItemOATH, ItemPasswords}

	for _, key := range order {
		fn := collectors[key]
		collected, err := fn(archive)
		if err != nil {
			return nil, err
		}
		if collected {
			hasData = true
		}
	}

	if !hasData {
		return nil, ErrEmptyBackup
	}

	return archive, nil
}

func (s *Service) collectTrustStore(a *Archive) (bool, error) {
	if s.trustStore == nil {
		return false, nil
	}
	certs, err := s.trustStore.Certificates()
	if err != nil {
		return false, fmt.Errorf("%w: trust store: %v", ErrCollectFailed, err)
	}
	if len(certs) == 0 {
		return false, nil
	}

	tsData := &TrustStoreData{
		Certificates: make([]TrustStoreCert, 0, len(certs)),
	}

	for _, cert := range certs {
		fp := certFingerprint(cert)
		tsc := TrustStoreCert{
			PEM:         encodeCertPEM(cert),
			Fingerprint: fp,
		}
		meta, err := s.trustStore.Metadata(fp)
		if err == nil && meta != nil {
			tsc.Purpose = meta.Purpose
			tsc.Source = meta.Source
			tsc.Tags = meta.Tags
		}
		tsData.Certificates = append(tsData.Certificates, tsc)
	}

	a.TrustStore = tsData
	a.Manifest.Contents = append(a.Manifest.Contents, ManifestItem{
		Type:  ItemTrustStore,
		Count: len(tsData.Certificates),
	})
	return true, nil
}

func (s *Service) collectCA(a *Archive) (bool, error) {
	if s.caReader == nil {
		return false, nil
	}
	certPEM, err := s.caReader.GetCACertificatePEM()
	if err != nil {
		return false, fmt.Errorf("%w: ca cert: %v", ErrCollectFailed, err)
	}
	if len(certPEM) == 0 {
		return false, nil
	}

	caData := &CABackupData{
		CACertPEM: string(certPEM),
	}

	chainPEM, err := s.caReader.GetCAChainPEM()
	if err == nil && len(chainPEM) > 0 {
		caData.CAChainPEM = string(chainPEM)
	}

	a.CAData = caData
	a.Manifest.Contents = append(a.Manifest.Contents, ManifestItem{
		Type:  ItemCAData,
		Count: 1,
	})
	return true, nil
}

func (s *Service) collectOATH(a *Archive) (bool, error) {
	if s.oathReader == nil {
		return false, nil
	}
	creds, err := s.oathReader.List()
	if err != nil {
		return false, fmt.Errorf("%w: oath: %v", ErrCollectFailed, err)
	}
	if len(creds) == 0 {
		return false, nil
	}

	oathCreds := make([]OATHCredential, 0, len(creds))
	for _, c := range creds {
		oathCreds = append(oathCreds, OATHCredential{
			ID:          c.ID,
			Name:        c.Name,
			Issuer:      c.Issuer,
			AccountName: c.AccountName,
			Secret:      c.Secret,
			Type:        c.Type,
			Algorithm:   c.Algorithm,
			Digits:      c.Digits,
			Period:      c.Period,
			Counter:     c.Counter,
		})
	}

	a.OATHCreds = oathCreds
	a.Manifest.Contents = append(a.Manifest.Contents, ManifestItem{
		Type:  ItemOATH,
		Count: len(oathCreds),
	})
	return true, nil
}

func (s *Service) collectPasswords(a *Archive) (bool, error) {
	if s.passwordReader == nil {
		return false, nil
	}
	passwords, err := s.passwordReader.List()
	if err != nil {
		return false, fmt.Errorf("%w: passwords: %v", ErrCollectFailed, err)
	}
	if len(passwords) == 0 {
		return false, nil
	}

	entries := make([]PasswordEntry, 0, len(passwords))
	for _, p := range passwords {
		entries = append(entries, PasswordEntry{
			ID:         p.ID,
			Name:       p.Name,
			Title:      p.Title,
			Username:   p.Username,
			Password:   p.Password,
			URL:        p.URL,
			Notes:      p.Notes,
			FolderPath: p.FolderPath,
		})
	}

	a.Passwords = entries
	a.Manifest.Contents = append(a.Manifest.Contents, ManifestItem{
		Type:  ItemPasswords,
		Count: len(entries),
	})
	return true, nil
}

// ---------------------------------------------------------------------------
// Internal: encryption helpers
// ---------------------------------------------------------------------------

// encrypt uses XChaCha20-Poly1305 to encrypt plaintext with a 32-byte key.
func encrypt(plaintext, key []byte) (ciphertext, nonce []byte, err error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("%w: nonce generation: %v", ErrEncryptionFailed, err)
	}

	ciphertext = aead.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// decrypt uses XChaCha20-Poly1305 to decrypt ciphertext with a 32-byte key.
func decrypt(ciphertext, nonce, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return plaintext, nil
}

// validateEncryptedBackup checks magic bytes and version.
func validateEncryptedBackup(eb *EncryptedBackup) error {
	if eb == nil || eb.Magic != BackupMagic {
		return ErrInvalidBackup
	}
	if eb.Version != BackupVersion {
		return ErrVersionMismatch
	}
	return nil
}

// ---------------------------------------------------------------------------
// Internal: PEM / fingerprint helpers
// ---------------------------------------------------------------------------

// encodeCertPEM encodes an x509.Certificate to a PEM string.
func encodeCertPEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}))
}

// certFingerprint returns the hex-encoded SHA-256 fingerprint of the
// certificate's raw DER bytes.
func certFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}
