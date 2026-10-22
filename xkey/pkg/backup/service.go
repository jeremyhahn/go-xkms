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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"

	"github.com/jeremyhahn/go-xkms/sdk/go/truststore"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	// BackupVersion is the current backup format version: AES-256-GCM with
	// a random 96-bit nonce, a salted password KDF record, and the envelope
	// header authenticated as AEAD additional data. Version 2 files
	// (XChaCha20-Poly1305) are refused with ErrVersionMismatch.
	BackupVersion = 3

	// gcmNonceSize is the AES-GCM random nonce length in bytes.
	gcmNonceSize = 12

	// legacyUnsaltedVersion is the refused version 1 format, whose password
	// key was an unsalted SHA-256 of the password.
	legacyUnsaltedVersion = 1

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

// CertMetadataInfo is the per-certificate metadata the backup service
// records in an archive.
type CertMetadataInfo struct {
	Fingerprint string
	Purpose     string
	Source      string
	Tags        []string
}

// OATHReader provides read access to OATH credentials for backup. The records
// List returns are the caller's: each holds protected memory, which the caller
// releases with OATHCredentialInfo.Destroy once it has read them. List must
// therefore return records of its own on every call, not ones it retains.
type OATHReader interface {
	List() ([]*OATHCredentialInfo, error)
}

// OATHCredentialInfo is a simplified credential for backup purposes.
type OATHCredentialInfo struct {
	ID          string
	Name        string
	Issuer      string
	AccountName string

	// BackendID names the OATH backend partition holding the credential, so
	// a restore writes it back to the same backend. Empty selects the
	// restoring store's default backend.
	BackendID string

	// secret holds the Base32-encoded shared secret in mlocked,
	// guard-paged protected memory (go-xkms#587), matching the same
	// oath.Credential.secret field this value is routed into by an
	// OATHWriter (via oath.Credential.SetSecret). It is unexported so no
	// consumer can hold the key material as an unwipeable Go string; use
	// SetSecret to store it and Secret to export a copy at a serialization
	// boundary. The persisted JSON form keeps the historical "Secret" key
	// via MarshalJSON/UnmarshalJSON.
	secret *secure.Buffer

	Type      string
	Algorithm string
	Digits    int
	Period    int
	Counter   int64
}

// SetSecret copies the Base32-encoded shared secret into protected memory,
// replacing (and destroying) any previous value. The value is stored
// verbatim. An empty secret clears it. secret stays the caller's, who wipes it.
//
// Returns a wrapped ErrProtectedMemory if the protected allocation fails.
func (c *OATHCredentialInfo) SetSecret(secret []byte) error {
	return setProtected(&c.secret, secret)
}

// SetSecretText copies the secret held by text into protected memory, with the
// semantics of SetSecret. text stays its owner's.
func (c *OATHCredentialInfo) SetSecretText(text xkms.SecretText) error {
	plain, err := text.Copy()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrProtectedMemory, Cause: err}
	}
	defer secure.Wipe(plain)
	return c.SetSecret(plain)
}

// SecretText returns the shared secret as a SecretText of its own, ready to be
// placed in a wire record. The caller owns it and calls Destroy. The zero
// SecretText is returned when no secret is set.
func (c *OATHCredentialInfo) SecretText() (xkms.SecretText, error) {
	plain, err := c.Secret()
	if err != nil {
		return xkms.SecretText{}, err
	}
	defer secure.Wipe(plain)
	text, err := xkms.NewSecretText(plain)
	if err != nil {
		return xkms.SecretText{}, &SentinelCauseError{Sentinel: ErrProtectedMemory, Cause: err}
	}
	return text, nil
}

// Clone returns an independent record with its own protected copy of the
// secret, for a reader that must hand out a record per call while it keeps its
// own. Returns nil for a nil receiver. The caller destroys the clone.
func (c *OATHCredentialInfo) Clone() (*OATHCredentialInfo, error) {
	if c == nil {
		return nil, nil
	}
	clone := &OATHCredentialInfo{
		ID: c.ID, Name: c.Name, Issuer: c.Issuer, AccountName: c.AccountName, BackendID: c.BackendID,
		Type: c.Type, Algorithm: c.Algorithm, Digits: c.Digits, Period: c.Period, Counter: c.Counter,
	}
	secret, err := c.Secret()
	if err != nil {
		return nil, err
	}
	defer secure.Wipe(secret)
	if err := clone.SetSecret(secret); err != nil {
		return nil, err
	}
	return clone, nil
}

// Destroy wipes and releases the shared secret. Safe on a nil receiver and
// more than once; the record is empty afterwards.
func (c *OATHCredentialInfo) Destroy() {
	if c == nil {
		return
	}
	c.secret.Destroy()
	c.secret = nil
}

// HasSecret reports whether the credential holds a shared secret.
func (c *OATHCredentialInfo) HasSecret() bool {
	return c != nil && c.secret != nil
}

// Secret returns a caller-owned copy of the Base32-encoded shared secret, or
// nil when no secret is set. The caller MUST wipe it (secure.Wipe) as soon as
// it has been used. Returns a wrapped ErrProtectedMemory if the protected
// buffer can no longer be read.
func (c *OATHCredentialInfo) Secret() ([]byte, error) {
	if c == nil {
		return nil, nil
	}
	return copyProtected(c.secret)
}

// oathCredentialInfoJSON is the persisted JSON form of OATHCredentialInfo.
// It exists so the protected in-memory secret round-trips through the
// historical wire format unchanged: the "Secret" key carries the Base32
// string exactly as it did when Secret was an exported string field.
type oathCredentialInfoJSON struct {
	ID          string           `json:"ID"`
	Name        string           `json:"Name"`
	Issuer      string           `json:"Issuer"`
	AccountName string           `json:"AccountName"`
	BackendID   string           `json:"BackendID,omitempty"`
	Secret      xkms.SecretBytes `json:"Secret"`
	Type        string           `json:"Type"`
	Algorithm   string           `json:"Algorithm"`
	Digits      int              `json:"Digits"`
	Period      int              `json:"Period"`
	Counter     int64            `json:"Counter"`
}

// MarshalJSON implements json.Marshaler, exporting the protected secret
// into the historical "Secret" JSON key. Serialization necessarily
// materializes the secret on the heap; that residue belongs to the
// persistence boundary, not to this type.
func (c *OATHCredentialInfo) MarshalJSON() ([]byte, error) {
	secret, err := c.Secret()
	if err != nil {
		return nil, err
	}
	defer secure.Wipe(secret)
	wire := oathCredentialInfoJSON{
		ID:          c.ID,
		Name:        c.Name,
		Issuer:      c.Issuer,
		AccountName: c.AccountName,
		BackendID:   c.BackendID,
		Secret:      secret,
		Type:        c.Type,
		Algorithm:   c.Algorithm,
		Digits:      c.Digits,
		Period:      c.Period,
		Counter:     c.Counter,
	}
	return json.Marshal(wire)
}

// UnmarshalJSON implements json.Unmarshaler, adopting the "Secret" JSON
// key into protected memory.
func (c *OATHCredentialInfo) UnmarshalJSON(data []byte) error {
	var aux oathCredentialInfoJSON
	defer aux.Secret.Wipe()
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	c.ID = aux.ID
	c.Name = aux.Name
	c.Issuer = aux.Issuer
	c.AccountName = aux.AccountName
	c.BackendID = aux.BackendID
	c.Type = aux.Type
	c.Algorithm = aux.Algorithm
	c.Digits = aux.Digits
	c.Period = aux.Period
	c.Counter = aux.Counter
	return c.SetSecret(aux.Secret)
}

// OATHWriter provides write access for restoring OATH credentials. Add must
// copy what it keeps: the caller destroys cred as soon as Add returns.
type OATHWriter interface {
	Add(cred *OATHCredentialInfo) error
}

// PasswordReader provides read access to static passwords for backup. The
// records List returns are the caller's, who releases each with
// PasswordInfo.Destroy; List must return records of its own on every call.
type PasswordReader interface {
	List() ([]*PasswordInfo, error)
}

// PasswordInfo is simplified password data for backup.
type PasswordInfo struct {
	ID       string
	Name     string
	Title    string
	Username string

	// password holds the stored password in mlocked, guard-paged
	// protected memory (go-xkms#587). It is unexported so no consumer can
	// hold the value as an unwipeable Go string; use SetPassword to store
	// it and Password to export a copy at a serialization boundary.
	// The persisted JSON form keeps the historical "Password" key via
	// MarshalJSON/UnmarshalJSON.
	password *secure.Buffer

	URL        string
	Notes      string
	FolderPath string
}

// SetPassword copies the password into protected memory, replacing (and
// destroying) any previous value. The value is stored verbatim. An empty
// password clears it. password stays the caller's, who wipes it.
//
// Returns a wrapped ErrProtectedMemory if the protected allocation fails.
func (p *PasswordInfo) SetPassword(password []byte) error {
	return setProtected(&p.password, password)
}

// SetPasswordText copies the password held by text into protected memory, with
// the semantics of SetPassword. text stays its owner's.
func (p *PasswordInfo) SetPasswordText(text xkms.SecretText) error {
	plain, err := text.Copy()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrProtectedMemory, Cause: err}
	}
	defer secure.Wipe(plain)
	return p.SetPassword(plain)
}

// PasswordText returns the password as a SecretText of its own, ready to be
// placed in a wire record. The caller owns it and calls Destroy. The zero
// SecretText is returned when no password is set.
func (p *PasswordInfo) PasswordText() (xkms.SecretText, error) {
	plain, err := p.Password()
	if err != nil {
		return xkms.SecretText{}, err
	}
	defer secure.Wipe(plain)
	text, err := xkms.NewSecretText(plain)
	if err != nil {
		return xkms.SecretText{}, &SentinelCauseError{Sentinel: ErrProtectedMemory, Cause: err}
	}
	return text, nil
}

// Clone returns an independent record with its own protected copy of the
// password, for a reader that must hand out a record per call while it keeps
// its own. Returns nil for a nil receiver. The caller destroys the clone.
func (p *PasswordInfo) Clone() (*PasswordInfo, error) {
	if p == nil {
		return nil, nil
	}
	clone := &PasswordInfo{
		ID: p.ID, Name: p.Name, Title: p.Title, Username: p.Username,
		URL: p.URL, Notes: p.Notes, FolderPath: p.FolderPath,
	}
	password, err := p.Password()
	if err != nil {
		return nil, err
	}
	defer secure.Wipe(password)
	if err := clone.SetPassword(password); err != nil {
		return nil, err
	}
	return clone, nil
}

// Destroy wipes and releases the password. Safe on a nil receiver and more than
// once; the record is empty afterwards.
func (p *PasswordInfo) Destroy() {
	if p == nil {
		return
	}
	p.password.Destroy()
	p.password = nil
}

// HasPassword reports whether the entry holds a password.
func (p *PasswordInfo) HasPassword() bool {
	return p != nil && p.password != nil
}

// Password returns a caller-owned copy of the password, or nil when no
// password is set. The caller MUST wipe it (secure.Wipe) as soon as it has
// been used. Returns a wrapped ErrProtectedMemory if the protected buffer can
// no longer be read.
func (p *PasswordInfo) Password() ([]byte, error) {
	if p == nil {
		return nil, nil
	}
	return copyProtected(p.password)
}

// passwordInfoJSON is the persisted JSON form of PasswordInfo. It exists so
// the protected in-memory password round-trips through the historical wire
// format unchanged: the "Password" key carries the string exactly as it
// did when Password was an exported string field.
type passwordInfoJSON struct {
	ID         string           `json:"ID"`
	Name       string           `json:"Name"`
	Title      string           `json:"Title"`
	Username   string           `json:"Username"`
	Password   xkms.SecretBytes `json:"Password"`
	URL        string           `json:"URL"`
	Notes      string           `json:"Notes"`
	FolderPath string           `json:"FolderPath"`
}

// MarshalJSON implements json.Marshaler, exporting the protected password
// into the historical "Password" JSON key. Serialization necessarily
// materializes the password on the heap; that residue belongs to the
// persistence boundary, not to this type.
func (p *PasswordInfo) MarshalJSON() ([]byte, error) {
	password, err := p.Password()
	if err != nil {
		return nil, err
	}
	defer secure.Wipe(password)
	wire := passwordInfoJSON{
		ID:         p.ID,
		Name:       p.Name,
		Title:      p.Title,
		Username:   p.Username,
		Password:   password,
		URL:        p.URL,
		Notes:      p.Notes,
		FolderPath: p.FolderPath,
	}
	return json.Marshal(wire)
}

// UnmarshalJSON implements json.Unmarshaler, adopting the "Password" JSON
// key into protected memory.
func (p *PasswordInfo) UnmarshalJSON(data []byte) error {
	var aux passwordInfoJSON
	defer aux.Password.Wipe()
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	p.ID = aux.ID
	p.Name = aux.Name
	p.Title = aux.Title
	p.Username = aux.Username
	p.URL = aux.URL
	p.Notes = aux.Notes
	p.FolderPath = aux.FolderPath
	return p.SetPassword(aux.Password)
}

// setProtected copies src into protected memory at *dst, destroying whatever
// *dst held before. An empty src clears *dst. src stays the caller's.
func setProtected(dst **secure.Buffer, src []byte) error {
	if len(src) == 0 {
		(*dst).Destroy()
		*dst = nil
		return nil
	}
	buf, err := secure.NewBufferFromBytes(bytes.Clone(src))
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrProtectedMemory, Cause: err}
	}
	(*dst).Destroy()
	*dst = buf
	return nil
}

// copyProtected returns a caller-owned copy of buf's contents, or nil for a
// nil buf.
func copyProtected(buf *secure.Buffer) ([]byte, error) {
	if buf == nil {
		return nil, nil
	}
	out, err := secure.CopyOut(buf)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrProtectedMemory, Cause: err}
	}
	return out, nil
}

// PasswordWriter provides write access for restoring static passwords. Add
// must copy what it keeps: the caller destroys pw as soon as Add returns.
type PasswordWriter interface {
	Add(pw *PasswordInfo) error
}

// CAReader provides read access to CA data for backup.
type CAReader interface {
	GetCACertificatePEM() ([]byte, error)
	GetCAChainPEM() ([]byte, error)
}

// TrustStoreWriter accepts PEM data for restoring certificates, filing each
// under the metadata the caller chooses. Restore always passes the purpose
// recorded in the archive, never nil: a nil opts auto-classifies, and
// auto-classification discards the operator's classification (#1312).
type TrustStoreWriter interface {
	ImportPEM(pemData []byte, opts *truststore.AddCertificateOptions) (truststore.ImportResult, error)
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

// Destroy wipes and releases every secret the archive carries: the OATH shared
// secrets and the static passwords. A caller that obtains an Archive from
// DecryptBackup destroys it once the restore has run. Safe on a nil receiver.
func (a *Archive) Destroy() {
	if a == nil {
		return
	}
	for i := range a.OATHCreds {
		a.OATHCreds[i].Secret.Destroy()
	}
	for i := range a.Passwords {
		a.Passwords[i].Password.Destroy()
	}
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
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Issuer      string          `json:"issuer"`
	AccountName string          `json:"account_name"`
	BackendID   string          `json:"backend_id,omitempty"`
	Secret      xkms.SecretText `json:"secret"`
	Type        string          `json:"type"`
	Algorithm   string          `json:"algorithm"`
	Digits      int             `json:"digits"`
	Period      int             `json:"period"`
	Counter     int64           `json:"counter"`
}

// PasswordEntry represents a single static password for backup.
type PasswordEntry struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Title      string          `json:"title,omitempty"`
	Username   string          `json:"username,omitempty"`
	Password   xkms.SecretText `json:"password"`
	URL        string          `json:"url,omitempty"`
	Notes      string          `json:"notes,omitempty"`
	FolderPath string          `json:"folder_path,omitempty"`
}

// EncryptedBackup is the on-wire / file format. Magic, Version and KDF form
// the header, which is bound to the ciphertext as AEAD additional data: a
// header altered after sealing -- a changed salt, cost parameter or version
// -- fails authentication.
type EncryptedBackup struct {
	Magic   string `json:"magic"`
	Version int    `json:"version"`

	// KDF records the password key derivation (algorithm, costs, salt).
	// It is nil for an envelope sealed with a raw key.
	KDF *xkms.PasswordKeyParams `json:"kdf,omitempty"`

	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// encryptedBackupHeader is the authenticated part of an EncryptedBackup.
type encryptedBackupHeader struct {
	Magic   string                  `json:"magic"`
	Version int                     `json:"version"`
	KDF     *xkms.PasswordKeyParams `json:"kdf,omitempty"`
}

// headerAAD returns the canonical encoding of the envelope header used as
// AEAD additional data.
func (eb *EncryptedBackup) headerAAD() ([]byte, error) {
	return json.Marshal(encryptedBackupHeader{Magic: eb.Magic, Version: eb.Version, KDF: eb.KDF})
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
// archive to JSON, and encrypts it with AES-256-GCM under key. A
// password-derived key's KDF record is written into the header, which is
// authenticated with the ciphertext.
func (s *Service) CreateBackup(key *Key) (*EncryptedBackup, error) {
	if key == nil {
		return nil, ErrInvalidKey
	}
	archive, err := s.collectArchive()
	if err != nil {
		return nil, err
	}
	defer archive.Destroy()

	// Serialize without checksum to compute the hash.
	archive.Manifest.Checksum = ""
	payload, err := json.Marshal(archive)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrCollectFailed, Cause: err}
	}
	defer secure.Wipe(payload)

	hash := sha256.Sum256(payload)
	archive.Manifest.Checksum = hex.EncodeToString(hash[:])

	// Re-serialize with checksum set.
	plaintext, err := json.Marshal(archive)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrCollectFailed, Cause: err}
	}
	defer secure.Wipe(plaintext)

	eb := &EncryptedBackup{Magic: BackupMagic, Version: BackupVersion, KDF: key.kdf}
	aad, err := eb.headerAAD()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrEncryptionFailed, Cause: err}
	}

	eb.Ciphertext, eb.Nonce, err = encrypt(plaintext, key.material, aad)
	if err != nil {
		return nil, err
	}
	return eb, nil
}

// DecryptBackup validates and decrypts an EncryptedBackup, verifies the
// payload checksum, and returns the deserialized Archive. The caller owns the
// archive's secrets and must call Archive.Destroy once it has used them.
//
// A password key must come from DerivePasswordKey(eb.KDF, password). A
// version 1 envelope is refused with ErrLegacyBackupFormat.
func (s *Service) DecryptBackup(eb *EncryptedBackup, key *Key) (*Archive, error) {
	if err := validateEncryptedBackup(eb); err != nil {
		return nil, err
	}
	if key == nil {
		return nil, ErrInvalidKey
	}

	aad, err := eb.headerAAD()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrInvalidBackup, Cause: err}
	}

	plaintext, err := decrypt(eb.Ciphertext, eb.Nonce, key.material, aad)
	if err != nil {
		return nil, err
	}
	defer secure.Wipe(plaintext)

	var archive Archive
	if err := json.Unmarshal(plaintext, &archive); err != nil {
		archive.Destroy()
		return nil, &SentinelCauseError{Sentinel: ErrInvalidBackup, Cause: err}
	}

	// Verify checksum: re-compute hash with checksum field cleared.
	savedChecksum := archive.Manifest.Checksum
	archive.Manifest.Checksum = ""
	raw, err := json.Marshal(&archive)
	if err != nil {
		archive.Destroy()
		return nil, &SentinelCauseError{Sentinel: ErrCorruptedBackup, Cause: err}
	}
	defer secure.Wipe(raw)

	hash := sha256.Sum256(raw)
	computed := hex.EncodeToString(hash[:])
	if computed != savedChecksum {
		archive.Destroy()
		return nil, ErrCorruptedBackup
	}

	archive.Manifest.Checksum = savedChecksum
	return &archive, nil
}

// GetManifest decrypts the backup and returns only its manifest.
func (s *Service) GetManifest(eb *EncryptedBackup, key *Key) (*Manifest, error) {
	archive, err := s.DecryptBackup(eb, key)
	if err != nil {
		return nil, err
	}
	defer archive.Destroy()
	return &archive.Manifest, nil
}

// ---------------------------------------------------------------------------
// Restore
// ---------------------------------------------------------------------------

// RestoreTrustStore restores trust store certificates from the archive.
func (s *Service) RestoreTrustStore(archive *Archive, writer TrustStoreWriter) (*RestoreResult, error) {
	if archive == nil {
		return nil, &DetailError{Err: ErrRestoreFailed, Detail: ": nil archive"}
	}
	result := &RestoreResult{ItemType: ItemTrustStore}

	if archive.TrustStore == nil || len(archive.TrustStore.Certificates) == 0 {
		return result, nil
	}

	// Validate every recorded purpose before writing anything, so an
	// archive carrying one bad purpose restores no certificate at all
	// rather than a partial trust store.
	opts := make([]*truststore.AddCertificateOptions, len(archive.TrustStore.Certificates))
	for i, cert := range archive.TrustStore.Certificates {
		certOpts, err := recordedImportOptions(cert)
		if err != nil {
			return nil, err
		}
		opts[i] = certOpts
	}

	for i, cert := range archive.TrustStore.Certificates {
		imported, err := writer.ImportPEM([]byte(cert.PEM), opts[i])
		if err != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("cert %s: %v", cert.Fingerprint, err))
			result.Skipped++
			continue
		}
		result.Restored += imported.Added
	}
	return result, nil
}

// recordedImportOptions returns the metadata cert was recorded with, which
// restore files it under exactly. An absent or unrecognized purpose is
// refused, never auto-classified: auto-classification would discard the
// operator's classification and could promote a quarantined certificate to
// an anchor (#1312).
func recordedImportOptions(cert TrustStoreCert) (*truststore.AddCertificateOptions, error) {
	if cert.Purpose == "" {
		return nil, &RecordedPurposeError{Fingerprint: cert.Fingerprint, Err: ErrMissingRecordedPurpose}
	}
	purpose := truststore.CertPurpose(cert.Purpose)
	if !truststore.IsValidPurpose(purpose) {
		return nil, &RecordedPurposeError{Fingerprint: cert.Fingerprint, Purpose: cert.Purpose, Err: ErrInvalidRecordedPurpose}
	}
	return &truststore.AddCertificateOptions{
		Purpose: purpose,
		Source:  cert.Source,
		Tags:    cert.Tags,
	}, nil
}

// RestoreOATH restores OATH credentials from the archive.
func (s *Service) RestoreOATH(archive *Archive, writer OATHWriter) (*RestoreResult, error) {
	if archive == nil {
		return nil, &DetailError{Err: ErrRestoreFailed, Detail: ": nil archive"}
	}
	result := &RestoreResult{ItemType: ItemOATH}

	for _, c := range archive.OATHCreds {
		info := &OATHCredentialInfo{
			ID:          c.ID,
			Name:        c.Name,
			Issuer:      c.Issuer,
			AccountName: c.AccountName,
			BackendID:   c.BackendID,
			Type:        c.Type,
			Algorithm:   c.Algorithm,
			Digits:      c.Digits,
			Period:      c.Period,
			Counter:     c.Counter,
		}
		if err := info.SetSecretText(c.Secret); err != nil {
			info.Destroy()
			result.Errors = append(result.Errors,
				fmt.Sprintf("oath %s: %v", c.ID, err))
			result.Skipped++
			continue
		}
		addErr := writer.Add(info)
		info.Destroy()
		if addErr != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("oath %s: %v", c.ID, addErr))
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
		return nil, &DetailError{Err: ErrRestoreFailed, Detail: ": nil archive"}
	}
	result := &RestoreResult{ItemType: ItemPasswords}

	for _, p := range archive.Passwords {
		info := &PasswordInfo{
			ID:         p.ID,
			Name:       p.Name,
			Title:      p.Title,
			Username:   p.Username,
			URL:        p.URL,
			Notes:      p.Notes,
			FolderPath: p.FolderPath,
		}
		if err := info.SetPasswordText(p.Password); err != nil {
			info.Destroy()
			result.Errors = append(result.Errors,
				fmt.Sprintf("password %s: %v", p.ID, err))
			result.Skipped++
			continue
		}
		addErr := writer.Add(info)
		info.Destroy()
		if addErr != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("password %s: %v", p.ID, addErr))
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
			archive.Destroy()
			return nil, err
		}
		if collected {
			hasData = true
		}
	}

	if !hasData {
		archive.Destroy()
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
		return false, &DetailError{Err: ErrCollectFailed, Detail: fmt.Sprintf(": trust store: %v", err)}
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
		// Every certificate's purpose is recorded: restore refuses a
		// certificate without one rather than guessing it (#1312), so an
		// archive missing metadata would be unrestorable.
		meta, err := s.trustStore.Metadata(fp)
		if err != nil {
			return false, &DetailError{Err: ErrCollectFailed, Detail: fmt.Sprintf(": trust store metadata %s: %v", fp, err)}
		}
		if meta == nil {
			return false, &DetailError{Err: ErrCollectFailed, Detail: fmt.Sprintf(": trust store metadata %s: missing", fp)}
		}
		tsc.Purpose = meta.Purpose
		tsc.Source = meta.Source
		tsc.Tags = meta.Tags
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
		return false, &DetailError{Err: ErrCollectFailed, Detail: fmt.Sprintf(": ca cert: %v", err)}
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
		return false, &DetailError{Err: ErrCollectFailed, Detail: fmt.Sprintf(": oath: %v", err)}
	}
	// The records are the reader's gift to this call: whatever the outcome,
	// their protected memory is released once the archive holds its own copies.
	defer func() {
		for _, c := range creds {
			c.Destroy()
		}
	}()
	if len(creds) == 0 {
		return false, nil
	}

	oathCreds := make([]OATHCredential, 0, len(creds))
	for _, c := range creds {
		secret, err := c.SecretText()
		if err != nil {
			(&Archive{OATHCreds: oathCreds}).Destroy()
			return false, &DetailError{Err: ErrCollectFailed, Detail: fmt.Sprintf(": oath %s: %v", c.ID, err)}
		}
		oathCreds = append(oathCreds, OATHCredential{
			ID:          c.ID,
			Name:        c.Name,
			Issuer:      c.Issuer,
			AccountName: c.AccountName,
			BackendID:   c.BackendID,
			Secret:      secret,
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
		return false, &DetailError{Err: ErrCollectFailed, Detail: fmt.Sprintf(": passwords: %v", err)}
	}
	// The records are the reader's gift to this call: whatever the outcome,
	// their protected memory is released once the archive holds its own copies.
	defer func() {
		for _, p := range passwords {
			p.Destroy()
		}
	}()
	if len(passwords) == 0 {
		return false, nil
	}

	entries := make([]PasswordEntry, 0, len(passwords))
	for _, p := range passwords {
		password, err := p.PasswordText()
		if err != nil {
			(&Archive{Passwords: entries}).Destroy()
			return false, &DetailError{Err: ErrCollectFailed, Detail: fmt.Sprintf(": password %s: %v", p.ID, err)}
		}
		entries = append(entries, PasswordEntry{
			ID:         p.ID,
			Name:       p.Name,
			Title:      p.Title,
			Username:   p.Username,
			Password:   password,
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

// newAEAD returns AES-256-GCM with a random 96-bit nonce, the only GCM
// construction FIPS 140-only mode permits (NIST SP 800-38D §8.2.2).
func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, &DetailError{Err: ErrInvalidKey, Detail: fmt.Sprintf(": key is %d bytes, want %d", len(key), KeySize)}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

// encrypt seals plaintext with AES-256-GCM under a 32-byte key,
// authenticating aad alongside it. The random nonce is returned
// separately from the ciphertext and tag.
func encrypt(plaintext, key, aad []byte) (ciphertext, nonce []byte, err error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, nil, &SentinelCauseError{Sentinel: ErrEncryptionFailed, Cause: err}
	}

	// NewGCMWithRandomNonce draws the nonce itself and prefixes it to
	// the sealed output.
	sealed := aead.Seal(nil, nil, plaintext, aad)
	return sealed[gcmNonceSize:], sealed[:gcmNonceSize], nil
}

// decrypt opens AES-256-GCM ciphertext with a 32-byte key, verifying aad
// alongside it.
func decrypt(ciphertext, nonce, key, aad []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrDecryptionFailed, Cause: err}
	}

	// The nonce is read back from an imported backup file. Reject a wrong
	// length here so a corrupted file fails with a clear error instead of
	// shifting nonce bytes into the ciphertext.
	if len(nonce) != gcmNonceSize {
		return nil, &DetailError{Err: ErrDecryptionFailed, Detail: fmt.Sprintf(
			": nonce is %d bytes, want %d", len(nonce), gcmNonceSize)}
	}

	sealed := make([]byte, 0, len(nonce)+len(ciphertext))
	sealed = append(append(sealed, nonce...), ciphertext...)
	plaintext, err := aead.Open(nil, nil, sealed, aad)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrDecryptionFailed, Cause: err}
	}

	return plaintext, nil
}

// validateEncryptedBackup checks magic bytes and version. The unsalted
// version 1 format has its own error so the operator is told to re-create
// the backup rather than that the file is merely unrecognised.
func validateEncryptedBackup(eb *EncryptedBackup) error {
	if eb == nil || eb.Magic != BackupMagic {
		return ErrInvalidBackup
	}
	if eb.Version == legacyUnsaltedVersion {
		return ErrLegacyBackupFormat
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
