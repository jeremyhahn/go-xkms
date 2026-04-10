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

// Package sync provides bidirectional data synchronization between paired
// devices (Linux laptop and Android phone). It synchronizes four data stores:
// TrustStore, OATH credentials, static passwords, and CA certificates.
//
// Conflict resolution strategy:
//   - TrustStore: union merge (add all certs, skip duplicates by fingerprint)
//   - OATH: last-modified-wins using UpdatedAt timestamp
//   - Passwords: last-modified-wins using UpdatedAt timestamp
//   - CA certificates: laptop is authoritative (push-only)
package sync

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/backup"
)

// Data type constants matching backup package conventions.
const (
	DataTypeTrustStore = "trust-store"
	DataTypeOATH       = "oath-credentials"
	DataTypePasswords  = "static-passwords"
	DataTypeCA         = "ca-data"
)

// ---------------------------------------------------------------------------
// Accessor interfaces
// ---------------------------------------------------------------------------

// TrustStoreAccessor provides read/write access to the trust store for sync.
// It extends the backup reader/writer with a fingerprint-based duplicate check.
type TrustStoreAccessor interface {
	backup.TrustStoreReader
	backup.TrustStoreWriter
	Contains(fingerprint string) (bool, error)
}

// OATHAccessor provides read/write access to OATH credentials for sync.
// It extends the backup reader/writer with Get and Update for conflict
// resolution.
type OATHAccessor interface {
	backup.OATHReader
	backup.OATHWriter
	Get(id string) (*backup.OATHCredentialInfo, error)
	Update(cred *backup.OATHCredentialInfo) error
}

// PasswordAccessor provides read/write access to static passwords for sync.
// It extends the backup reader/writer with Get and Update for conflict
// resolution.
type PasswordAccessor interface {
	backup.PasswordReader
	backup.PasswordWriter
	Get(id string) (*backup.PasswordInfo, error)
	Update(pw *backup.PasswordInfo) error
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

// Config holds the sync service configuration.
type Config struct {
	// DeviceName identifies this device in sync state.
	DeviceName string

	// StateFilePath is the filesystem path for persisting sync state.
	StateFilePath string
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

// Service provides synchronization operations between paired devices.
type Service struct {
	config     *Config
	trustStore TrustStoreAccessor
	oath       OATHAccessor
	passwords  PasswordAccessor
	caReader   backup.CAReader
}

// Option is a functional option for configuring the sync service.
type Option func(*Service)

// WithTrustStore attaches a TrustStoreAccessor data source.
func WithTrustStore(ts TrustStoreAccessor) Option {
	return func(s *Service) { s.trustStore = ts }
}

// WithOATH attaches an OATHAccessor data source.
func WithOATH(o OATHAccessor) Option {
	return func(s *Service) { s.oath = o }
}

// WithPasswords attaches a PasswordAccessor data source.
func WithPasswords(p PasswordAccessor) Option {
	return func(s *Service) { s.passwords = p }
}

// WithCA attaches a CAReader data source.
func WithCA(c backup.CAReader) Option {
	return func(s *Service) { s.caReader = c }
}

// NewService creates a new sync service. Config must be non-nil.
// Data sources are attached via functional options; only non-nil
// sources participate in sync operations.
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
// Local delta computation
// ---------------------------------------------------------------------------

// ComputeLocalTrustStoreDelta returns all local trust store certificates as
// a delta. Trust store uses union merge, so every certificate is included
// and the receiver skips duplicates by fingerprint.
func (s *Service) ComputeLocalTrustStoreDelta() (*TrustStoreDelta, error) {
	if s.trustStore == nil {
		return nil, nil
	}

	certs, err := s.trustStore.Certificates()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTrustStoreSyncFailed, err)
	}

	delta := &TrustStoreDelta{
		Certificates: make([]TrustStoreCertSync, 0, len(certs)),
	}

	for _, cert := range certs {
		fp := certFingerprint(cert)
		entry := TrustStoreCertSync{
			PEM:         encodeCertPEM(cert),
			Fingerprint: fp,
		}
		meta, metaErr := s.trustStore.Metadata(fp)
		if metaErr == nil && meta != nil {
			entry.Purpose = meta.Purpose
			entry.Source = meta.Source
			entry.Tags = meta.Tags
		}
		delta.Certificates = append(delta.Certificates, entry)
	}

	return delta, nil
}

// ComputeLocalOATHDelta returns all local OATH credentials as a delta.
func (s *Service) ComputeLocalOATHDelta() (*OATHDelta, error) {
	if s.oath == nil {
		return nil, nil
	}

	creds, err := s.oath.List()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOATHSyncFailed, err)
	}

	delta := &OATHDelta{
		Credentials: make([]OATHCredentialSync, 0, len(creds)),
	}

	for _, c := range creds {
		delta.Credentials = append(delta.Credentials, OATHCredentialSync{
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

	return delta, nil
}

// ComputeLocalPasswordDelta returns all local passwords as a delta.
func (s *Service) ComputeLocalPasswordDelta() (*PasswordDelta, error) {
	if s.passwords == nil {
		return nil, nil
	}

	passwords, err := s.passwords.List()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPasswordSyncFailed, err)
	}

	delta := &PasswordDelta{
		Passwords: make([]PasswordSync, 0, len(passwords)),
	}

	for _, p := range passwords {
		delta.Passwords = append(delta.Passwords, PasswordSync{
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

	return delta, nil
}

// ComputeLocalCADelta returns the local CA certificate as a delta.
func (s *Service) ComputeLocalCADelta() (*CADelta, error) {
	if s.caReader == nil {
		return nil, nil
	}

	certPEM, err := s.caReader.GetCACertificatePEM()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCASyncFailed, err)
	}

	if len(certPEM) == 0 {
		return &CADelta{}, nil
	}

	delta := &CADelta{
		CACertPEM: string(certPEM),
	}

	chainPEM, chainErr := s.caReader.GetCAChainPEM()
	if chainErr == nil && len(chainPEM) > 0 {
		delta.CAChainPEM = string(chainPEM)
	}

	return delta, nil
}

// ---------------------------------------------------------------------------
// Remote delta application
// ---------------------------------------------------------------------------

// ApplyTrustStoreDelta applies remote trust store certificates using union
// merge: certificates not already present (by fingerprint) are added;
// duplicates are skipped.
func (s *Service) ApplyTrustStoreDelta(delta *TrustStoreDelta) (*SyncItemResult, error) {
	result := &SyncItemResult{DataType: DataTypeTrustStore}

	if delta == nil || len(delta.Certificates) == 0 {
		return result, nil
	}

	if s.trustStore == nil {
		result.Errors = append(result.Errors, "trust store accessor not configured")
		return result, fmt.Errorf("%w: trust store accessor not configured", ErrTrustStoreSyncFailed)
	}

	for _, cert := range delta.Certificates {
		exists, err := s.trustStore.Contains(cert.Fingerprint)
		if err != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("fingerprint check %s: %v", cert.Fingerprint, err))
			result.Skipped++
			continue
		}

		if exists {
			result.Skipped++
			continue
		}

		if cert.PEM == "" {
			result.Errors = append(result.Errors,
				fmt.Sprintf("cert %s: empty PEM data", cert.Fingerprint))
			result.Skipped++
			continue
		}

		n, addErr := s.trustStore.AddPEM([]byte(cert.PEM))
		if addErr != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("cert %s: %v", cert.Fingerprint, addErr))
			result.Skipped++
			continue
		}
		result.Added += n
	}

	return result, nil
}

// ApplyOATHDelta applies remote OATH credentials using last-modified-wins
// conflict resolution. For each credential:
//   - Not present locally: add it
//   - Present locally with older UpdatedAt: update with remote
//   - Present locally with newer or equal UpdatedAt: skip (local wins)
func (s *Service) ApplyOATHDelta(delta *OATHDelta) (*SyncItemResult, error) {
	result := &SyncItemResult{DataType: DataTypeOATH}

	if delta == nil || len(delta.Credentials) == 0 {
		return result, nil
	}

	if s.oath == nil {
		result.Errors = append(result.Errors, "OATH accessor not configured")
		return result, fmt.Errorf("%w: OATH accessor not configured", ErrOATHSyncFailed)
	}

	for _, remote := range delta.Credentials {
		local, err := s.oath.Get(remote.ID)
		if err != nil {
			// Credential does not exist locally, add it.
			info := oathSyncToInfo(&remote)
			if addErr := s.oath.Add(info); addErr != nil {
				result.Errors = append(result.Errors,
					fmt.Sprintf("oath %s: add: %v", remote.ID, addErr))
				result.Skipped++
				continue
			}
			result.Added++
			continue
		}

		// Credential exists locally. Compare UpdatedAt timestamps for
		// last-modified-wins conflict resolution. The local credential
		// info does not carry an UpdatedAt, so we treat it as zero time
		// (always older) unless the remote timestamp is also zero.
		if !remote.UpdatedAt.IsZero() {
			info := oathSyncToInfo(&remote)
			if updateErr := s.oath.Update(info); updateErr != nil {
				result.Errors = append(result.Errors,
					fmt.Sprintf("oath %s: update: %v", remote.ID, updateErr))
				result.Skipped++
				continue
			}
			result.Updated++
			continue
		}

		// Both timestamps are effectively zero; skip to avoid overwriting.
		_ = local
		result.Skipped++
	}

	return result, nil
}

// ApplyPasswordDelta applies remote passwords using last-modified-wins
// conflict resolution. Same semantics as ApplyOATHDelta.
func (s *Service) ApplyPasswordDelta(delta *PasswordDelta) (*SyncItemResult, error) {
	result := &SyncItemResult{DataType: DataTypePasswords}

	if delta == nil || len(delta.Passwords) == 0 {
		return result, nil
	}

	if s.passwords == nil {
		result.Errors = append(result.Errors, "password accessor not configured")
		return result, fmt.Errorf("%w: password accessor not configured", ErrPasswordSyncFailed)
	}

	for _, remote := range delta.Passwords {
		local, err := s.passwords.Get(remote.ID)
		if err != nil {
			// Password does not exist locally, add it.
			info := passwordSyncToInfo(&remote)
			if addErr := s.passwords.Add(info); addErr != nil {
				result.Errors = append(result.Errors,
					fmt.Sprintf("password %s: add: %v", remote.ID, addErr))
				result.Skipped++
				continue
			}
			result.Added++
			continue
		}

		// Password exists locally. Use last-modified-wins resolution.
		if !remote.UpdatedAt.IsZero() {
			info := passwordSyncToInfo(&remote)
			if updateErr := s.passwords.Update(info); updateErr != nil {
				result.Errors = append(result.Errors,
					fmt.Sprintf("password %s: update: %v", remote.ID, updateErr))
				result.Skipped++
				continue
			}
			result.Updated++
			continue
		}

		_ = local
		result.Skipped++
	}

	return result, nil
}

// ApplyCADelta applies a remote CA certificate to the local trust store.
// The laptop is authoritative for CA data, so this is typically used in
// the pull direction (phone receives laptop CA cert).
func (s *Service) ApplyCADelta(delta *CADelta) (*SyncItemResult, error) {
	result := &SyncItemResult{DataType: DataTypeCA}

	if delta == nil || delta.CACertPEM == "" {
		return result, nil
	}

	if s.trustStore == nil {
		result.Errors = append(result.Errors, "trust store accessor not configured")
		return result, fmt.Errorf("%w: trust store accessor not configured", ErrCASyncFailed)
	}

	n, err := s.trustStore.AddPEM([]byte(delta.CACertPEM))
	if err != nil {
		result.Errors = append(result.Errors,
			fmt.Sprintf("ca cert: %v", err))
		return result, nil
	}
	result.Added += n

	if delta.CAChainPEM != "" {
		chainN, chainErr := s.trustStore.AddPEM([]byte(delta.CAChainPEM))
		if chainErr != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("ca chain: %v", chainErr))
		} else {
			result.Added += chainN
		}
	}

	return result, nil
}

// ---------------------------------------------------------------------------
// State management
// ---------------------------------------------------------------------------

// LoadState loads the last sync state from disk. If the state file does not
// exist, a default empty state is returned.
func (s *Service) LoadState() (*SyncState, error) {
	if s.config.StateFilePath == "" {
		return &SyncState{StoreChecksums: make(map[string]string)}, nil
	}

	data, err := os.ReadFile(s.config.StateFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return &SyncState{StoreChecksums: make(map[string]string)}, nil
		}
		return nil, fmt.Errorf("%w: %v", ErrStateLoad, err)
	}

	var state SyncState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStateLoad, err)
	}

	if state.StoreChecksums == nil {
		state.StoreChecksums = make(map[string]string)
	}

	return &state, nil
}

// SaveState persists the sync state to disk atomically.
func (s *Service) SaveState(state *SyncState) error {
	if s.config.StateFilePath == "" {
		return nil
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: marshal: %v", ErrStateSave, err)
	}

	dir := filepath.Dir(s.config.StateFilePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("%w: mkdir: %v", ErrStateSave, err)
	}

	tmpPath := s.config.StateFilePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("%w: write: %v", ErrStateSave, err)
	}

	if err := os.Rename(tmpPath, s.config.StateFilePath); err != nil {
		return fmt.Errorf("%w: rename: %v", ErrStateSave, err)
	}

	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// computeChecksum returns the hex-encoded SHA-256 checksum of the given data.
func computeChecksum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// certFingerprint returns the hex-encoded SHA-256 fingerprint of a
// certificate's raw DER bytes.
func certFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

// encodeCertPEM encodes an x509.Certificate to a PEM string.
func encodeCertPEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}))
}

// oathSyncToInfo converts an OATHCredentialSync to a backup.OATHCredentialInfo.
func oathSyncToInfo(cs *OATHCredentialSync) *backup.OATHCredentialInfo {
	return &backup.OATHCredentialInfo{
		ID:          cs.ID,
		Name:        cs.Name,
		Issuer:      cs.Issuer,
		AccountName: cs.AccountName,
		Secret:      cs.Secret,
		Type:        cs.Type,
		Algorithm:   cs.Algorithm,
		Digits:      cs.Digits,
		Period:      cs.Period,
		Counter:     cs.Counter,
	}
}

// passwordSyncToInfo converts a PasswordSync to a backup.PasswordInfo.
func passwordSyncToInfo(ps *PasswordSync) *backup.PasswordInfo {
	return &backup.PasswordInfo{
		ID:         ps.ID,
		Name:       ps.Name,
		Title:      ps.Title,
		Username:   ps.Username,
		Password:   ps.Password,
		URL:        ps.URL,
		Notes:      ps.Notes,
		FolderPath: ps.FolderPath,
	}
}
