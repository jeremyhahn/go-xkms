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
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"os"
	"strings"
	"sync/atomic"
	"time"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pwimport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/staticpw"
)

// Static password service errors.
var (
	// ErrStaticPWStoreNotSet indicates the store has not been configured.
	ErrStaticPWStoreNotSet = errors.New("staticpw_service: store not configured")

	// ErrStaticPWInvalidID indicates an empty or invalid ID or name was provided.
	ErrStaticPWInvalidID = errors.New("staticpw_service: invalid ID or name")

	// ErrStaticPWInvalidName indicates the name field is required but was empty.
	ErrStaticPWInvalidName = errors.New("staticpw_service: name is required")

	// ErrStaticPWInvalidFolderPath indicates an invalid folder path was provided.
	ErrStaticPWInvalidFolderPath = errors.New("staticpw_service: invalid folder path")

	// ErrStaticPWInvalidExpiresAt indicates the expires_at field could not be parsed.
	ErrStaticPWInvalidExpiresAt = errors.New("staticpw_service: invalid expires_at format")

	// ErrStaticPWReadOnly indicates the entry is read-only and cannot be modified or deleted.
	ErrStaticPWReadOnly = errors.New("staticpw_service: entry is read-only")

	// ErrStaticPWNoClient indicates no transport client has been configured.
	ErrStaticPWNoClient = errors.New("staticpw_service: no connected client")

	// ErrStaticPWInvalidAccessMode indicates an invalid access mode string.
	ErrStaticPWInvalidAccessMode = errors.New("staticpw_service: invalid access mode")

	// ErrStaticPWInvalidGenerateLength indicates a non-positive generate length.
	ErrStaticPWInvalidGenerateLength = errors.New("staticpw_service: generate length must be positive")

	// ErrStaticPWBarrierSealed indicates the barrier is sealed and passwords cannot be accessed.
	ErrStaticPWBarrierSealed = errors.New("staticpw_service: barrier is sealed, unlock required")
)

// algorithmKeySize maps supported encryption algorithm names to their AES key
// sizes in bytes.
var algorithmKeySize = map[string]int{
	"aes-128": 16,
	"aes-192": 24,
	"aes-256": 32,
}

// PasswordStoreStatus is the frontend-facing representation of the password
// store lock/access state.
type PasswordStoreStatus struct {
	AccessMode    string `json:"access_mode"`
	IsLocked      bool   `json:"is_locked"`
	AutoUnsealed  bool   `json:"auto_unsealed"`
	PasswordCount int    `json:"password_count"`
}

// StaticPasswordEntry is the frontend-facing representation of a static password.
type StaticPasswordEntry struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Title           string   `json:"title"`
	Username        string   `json:"username"`
	Password        string   `json:"password"`
	URL             string   `json:"url"`
	MatchPatterns   []string `json:"match_patterns,omitempty"`
	Notes           string   `json:"notes"`
	FolderPath      string   `json:"folder_path"`
	ExpiresAt       string   `json:"expires_at,omitempty"`
	CreatedAt       string   `json:"created_at"`
	UpdatedAt       string   `json:"updated_at"`
	IsExpired       bool     `json:"is_expired"`
	DaysUntilExpiry int      `json:"days_until_expiry"`
	ReadOnly        bool     `json:"read_only"`
}

// AddPasswordParams holds parameters for AddPasswordV2.
type AddPasswordParams struct {
	Name          string   `json:"name"`
	Title         string   `json:"title"`
	Username      string   `json:"username"`
	Password      string   `json:"password"`
	URL           string   `json:"url"`
	MatchPatterns []string `json:"match_patterns,omitempty"`
	Notes         string   `json:"notes"`
	FolderPath    string   `json:"folder_path"`
	ExpiresAt     string   `json:"expires_at"`
	ReadOnly      bool     `json:"read_only"`
}

// UpdatePasswordParams holds parameters for UpdatePasswordV2.
type UpdatePasswordParams struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Title         string   `json:"title"`
	Username      string   `json:"username"`
	Password      string   `json:"password"`
	URL           string   `json:"url"`
	MatchPatterns []string `json:"match_patterns,omitempty"`
	Notes         string   `json:"notes"`
	FolderPath    string   `json:"folder_path"`
	ExpiresAt     string   `json:"expires_at"`
}

// StaticPasswordService exposes static password operations to the frontend.
// It combines local store operations with server-side transport client operations
// for access mode management, locking/unlocking, and password generation.
type StaticPasswordService struct {
	ctx    context.Context
	store  staticpw.Store
	client atomic.Pointer[transport.Client]
}

// NewStaticPasswordService creates a new StaticPasswordService. If store is nil,
// the service will return ErrStaticPWStoreNotSet for all operations that require
// persistence.
func NewStaticPasswordService(store staticpw.Store) *StaticPasswordService {
	return &StaticPasswordService{
		store: store,
	}
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *StaticPasswordService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetStore replaces the static password store. This is used for deferred
// initialization when the data directory is created after construction.
func (s *StaticPasswordService) SetStore(store staticpw.Store) {
	s.store = store
}

// SetClient sets the transport client used for server-side password store
// operations (lock, unlock, status, access mode, generate).
func (s *StaticPasswordService) SetClient(c transport.Client) {
	s.client.Store(&c)
}

// getClient returns the current transport client or ErrStaticPWNoClient.
func (s *StaticPasswordService) getClient() (transport.Client, error) {
	ptr := s.client.Load()
	if ptr == nil {
		return nil, ErrStaticPWNoClient
	}
	return *ptr, nil
}

// getContext returns the service context, falling back to context.Background
// if no context has been set.
func (s *StaticPasswordService) getContext() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

// ListPasswords returns all stored static passwords as frontend entries.
func (s *StaticPasswordService) ListPasswords() ([]StaticPasswordEntry, error) {
	if s.store == nil {
		return nil, ErrStaticPWStoreNotSet
	}

	passwords, err := s.store.List()
	if err != nil {
		// Detect barrier sealed state and return a user-friendly error.
		if err.Error() == "seal: barrier is sealed" || errors.Is(err, ErrStaticPWBarrierSealed) {
			return nil, ErrStaticPWBarrierSealed
		}
		return nil, err
	}

	entries := make([]StaticPasswordEntry, 0, len(passwords))
	for _, pw := range passwords {
		entries = append(entries, staticPWToEntry(pw))
	}
	return entries, nil
}

// GetPassword retrieves a static password by ID or name and returns it as a
// frontend entry.
func (s *StaticPasswordService) GetPassword(idOrName string) (*StaticPasswordEntry, error) {
	if s.store == nil {
		return nil, ErrStaticPWStoreNotSet
	}
	if idOrName == "" {
		return nil, ErrStaticPWInvalidID
	}

	pw, err := s.store.Get(idOrName)
	if err != nil {
		return nil, err
	}

	entry := staticPWToEntry(pw)
	return &entry, nil
}

// AddPassword creates a new static password entry with the given name, password,
// and notes. The name must not be empty. Returns the created entry with its
// generated ID and timestamps. This method is kept for backward compatibility
// and delegates to AddPasswordV2.
func (s *StaticPasswordService) AddPassword(name, password, notes string) (*StaticPasswordEntry, error) {
	return s.AddPasswordV2(AddPasswordParams{
		Name:     name,
		Password: password,
		Notes:    notes,
	})
}

// AddPasswordV2 creates a new static password entry with all supported fields.
func (s *StaticPasswordService) AddPasswordV2(params AddPasswordParams) (*StaticPasswordEntry, error) {
	if s.store == nil {
		return nil, ErrStaticPWStoreNotSet
	}
	if params.Name == "" {
		return nil, ErrStaticPWInvalidName
	}

	pw := &staticpw.StaticPassword{
		Name:          params.Name,
		Title:         params.Title,
		Username:      params.Username,
		Password:      params.Password,
		URL:           params.URL,
		MatchPatterns: params.MatchPatterns,
		Notes:         params.Notes,
		FolderPath:    params.FolderPath,
		ReadOnly:      params.ReadOnly,
	}

	if params.ExpiresAt != "" {
		expiresAt, err := time.Parse(time.RFC3339, params.ExpiresAt)
		if err != nil {
			return nil, ErrStaticPWInvalidExpiresAt
		}
		pw.ExpiresAt = expiresAt
	}

	if err := s.store.Add(pw); err != nil {
		return nil, err
	}

	entry := staticPWToEntry(pw)
	return &entry, nil
}

// UpdatePassword modifies an existing static password entry identified by ID.
// It fetches the current entry, applies the provided field values, and persists
// the update. This method is kept for backward compatibility and delegates to
// UpdatePasswordV2.
func (s *StaticPasswordService) UpdatePassword(id, name, password, notes string) error {
	return s.UpdatePasswordV2(UpdatePasswordParams{
		ID:       id,
		Name:     name,
		Password: password,
		Notes:    notes,
	})
}

// UpdatePasswordV2 modifies an existing static password entry with all
// supported fields.
func (s *StaticPasswordService) UpdatePasswordV2(params UpdatePasswordParams) error {
	if s.store == nil {
		return ErrStaticPWStoreNotSet
	}
	if params.ID == "" {
		return ErrStaticPWInvalidID
	}

	existing, err := s.store.Get(params.ID)
	if err != nil {
		return err
	}

	if existing.ReadOnly {
		return ErrStaticPWReadOnly
	}

	existing.Name = params.Name
	existing.Title = params.Title
	existing.Username = params.Username
	existing.Password = params.Password
	existing.URL = params.URL
	existing.MatchPatterns = params.MatchPatterns
	existing.Notes = params.Notes
	existing.FolderPath = params.FolderPath

	if params.ExpiresAt != "" {
		expiresAt, err := time.Parse(time.RFC3339, params.ExpiresAt)
		if err != nil {
			return ErrStaticPWInvalidExpiresAt
		}
		existing.ExpiresAt = expiresAt
	} else {
		existing.ExpiresAt = time.Time{}
	}

	return s.store.Update(existing)
}

// DeletePassword removes a static password by ID or name. Returns
// ErrStaticPWReadOnly if the entry is read-only.
func (s *StaticPasswordService) DeletePassword(idOrName string) error {
	if s.store == nil {
		return ErrStaticPWStoreNotSet
	}
	if idOrName == "" {
		return ErrStaticPWInvalidID
	}

	existing, err := s.store.Get(idOrName)
	if err != nil {
		return err
	}
	if existing.ReadOnly {
		return ErrStaticPWReadOnly
	}

	return s.store.Delete(idOrName)
}

// DeletePasswordForce removes a static password by ID or name, bypassing
// the read-only check. This is used internally for cascade operations
// (e.g. policy deletion cleaning up auto-generated password entries).
func (s *StaticPasswordService) DeletePasswordForce(idOrName string) error {
	if s.store == nil {
		return ErrStaticPWStoreNotSet
	}
	if idOrName == "" {
		return ErrStaticPWInvalidID
	}
	return s.store.ForceDelete(idOrName)
}

// GeneratePassword produces a cryptographically random password of the requested
// length drawn from the specified charset. It delegates to staticpw.GeneratePassword.
// This is a pure cryptographic operation and does not require a configured store.
func (s *StaticPasswordService) GeneratePassword(length int, charset string) (string, error) {
	return staticpw.GeneratePassword(length, charset)
}

// ListFolders returns all unique folder paths from the store.
func (s *StaticPasswordService) ListFolders() ([]string, error) {
	if s.store == nil {
		return nil, ErrStaticPWStoreNotSet
	}
	return s.store.ListFolders()
}

// CreateFolder persists an empty folder so it survives across app restarts.
func (s *StaticPasswordService) CreateFolder(path string) error {
	if s.store == nil {
		return ErrStaticPWStoreNotSet
	}
	if path == "" {
		return ErrStaticPWInvalidFolderPath
	}
	return s.store.CreateFolder(path)
}

// ListPasswordsByFolder returns all entries in the given folder.
func (s *StaticPasswordService) ListPasswordsByFolder(folderPath string) ([]StaticPasswordEntry, error) {
	if s.store == nil {
		return nil, ErrStaticPWStoreNotSet
	}

	passwords, err := s.store.ListByFolder(folderPath)
	if err != nil {
		return nil, err
	}

	entries := make([]StaticPasswordEntry, 0, len(passwords))
	for _, pw := range passwords {
		entries = append(entries, staticPWToEntry(pw))
	}
	return entries, nil
}

// MovePassword moves a password entry to a new folder.
func (s *StaticPasswordService) MovePassword(id string, folderPath string) error {
	if s.store == nil {
		return ErrStaticPWStoreNotSet
	}
	if id == "" {
		return ErrStaticPWInvalidID
	}
	return s.store.MoveToFolder(id, folderPath)
}

// RenameFolder renames a folder by updating all entries with the old folder
// path prefix to the new path.
func (s *StaticPasswordService) RenameFolder(oldPath string, newPath string) error {
	if s.store == nil {
		return ErrStaticPWStoreNotSet
	}
	if oldPath == "" {
		return ErrStaticPWInvalidFolderPath
	}

	all, err := s.store.List()
	if err != nil {
		return err
	}

	for _, pw := range all {
		if pw.FolderPath == oldPath || strings.HasPrefix(pw.FolderPath, oldPath+"/") {
			newFolder := newPath + pw.FolderPath[len(oldPath):]

			// Delete old entry.
			if delErr := s.store.Delete(pw.ID); delErr != nil {
				return delErr
			}

			// Re-add with new folder path.
			pw.FolderPath = newFolder
			pw.ID = ""
			if addErr := s.store.Add(pw); addErr != nil {
				return addErr
			}
		}
	}

	// Move persisted folder marker from old path to new path.
	_ = s.store.RemoveFolder(oldPath)
	_ = s.store.CreateFolder(newPath)

	return nil
}

// DeleteFolder deletes all entries in the given folder and its subfolders.
func (s *StaticPasswordService) DeleteFolder(folderPath string) error {
	if s.store == nil {
		return ErrStaticPWStoreNotSet
	}
	if folderPath == "" {
		return ErrStaticPWInvalidFolderPath
	}

	all, err := s.store.List()
	if err != nil {
		return err
	}

	for _, pw := range all {
		if pw.FolderPath == folderPath || strings.HasPrefix(pw.FolderPath, folderPath+"/") {
			if delErr := s.store.Delete(pw.ID); delErr != nil {
				return delErr
			}
		}
	}

	// Remove the persisted folder marker (if any).
	_ = s.store.RemoveFolder(folderPath)

	return nil
}

// SearchPasswords searches across title, username, URL, notes, and name
// (case-insensitive) and returns matching entries.
func (s *StaticPasswordService) SearchPasswords(query string) ([]StaticPasswordEntry, error) {
	if s.store == nil {
		return nil, ErrStaticPWStoreNotSet
	}

	all, err := s.store.List()
	if err != nil {
		return nil, err
	}

	lower := strings.ToLower(query)
	entries := make([]StaticPasswordEntry, 0)

	for _, pw := range all {
		if strings.Contains(strings.ToLower(pw.DisplayTitle()), lower) ||
			strings.Contains(strings.ToLower(pw.Username), lower) ||
			strings.Contains(strings.ToLower(pw.URL), lower) ||
			strings.Contains(strings.ToLower(pw.Notes), lower) ||
			strings.Contains(strings.ToLower(pw.Name), lower) {
			entries = append(entries, staticPWToEntry(pw))
		}
	}

	return entries, nil
}

// ---------------------------------------------------------------------------
// Backup operations
// ---------------------------------------------------------------------------

// BackupPasswords exports all stored passwords to filePath. When encrypt is
// true the JSON payload is encrypted with AES-GCM using the provided password
// and algorithm (one of "aes-128", "aes-192", "aes-256"). The encrypted output
// consists of the GCM nonce prepended to the ciphertext.
func (s *StaticPasswordService) BackupPasswords(filePath string, encrypt bool, algorithm string, password string) error {
	if filePath == "" {
		return ErrBackupInvalidPath
	}
	if s.store == nil {
		return ErrStaticPWStoreNotSet
	}

	if encrypt {
		if password == "" {
			return ErrBackupPasswordRequired
		}
		if _, ok := algorithmKeySize[algorithm]; !ok {
			return ErrBackupInvalidAlgorithm
		}
	}

	// List all passwords from the store.
	passwords, err := s.store.List()
	if err != nil {
		return err
	}

	// Convert to frontend entries.
	entries := make([]StaticPasswordEntry, 0, len(passwords))
	for _, pw := range passwords {
		entries = append(entries, staticPWToEntry(pw))
	}

	// Marshal to pretty-printed JSON.
	jsonBytes, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return ErrBackupFailed
	}

	// Write plaintext backup.
	if !encrypt {
		return os.WriteFile(filePath, jsonBytes, 0600)
	}

	// Derive encryption key from password via SHA-256, truncated to the
	// required key size for the selected algorithm.
	keySize := algorithmKeySize[algorithm]
	hash := sha256.Sum256([]byte(password))
	key := hash[:keySize]

	block, err := aes.NewCipher(key)
	if err != nil {
		return ErrBackupFailed
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ErrBackupFailed
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := crand.Read(nonce); err != nil {
		return ErrBackupFailed
	}

	// Seal prepends the nonce to the ciphertext so the file is self-contained.
	encrypted := gcm.Seal(nonce, nonce, jsonBytes, nil)

	return os.WriteFile(filePath, encrypted, 0600)
}

// SaveBackupFileAs opens the native save-file dialog and returns the path
// chosen by the user.
func (s *StaticPasswordService) SaveBackupFileAs() (string, error) {
	return wailsruntime.SaveFileDialog(s.ctx, wailsruntime.SaveDialogOptions{
		DefaultFilename: "xkey-passwords-backup.json",
		Title:           "Save Password Backup",
		Filters: []wailsruntime.FileFilter{
			{DisplayName: "JSON Files", Pattern: "*.json"},
			{DisplayName: "Encrypted Backup", Pattern: "*.enc"},
			{DisplayName: "All Files", Pattern: "*"},
		},
	})
}

// OpenBackupFileDialog opens the native open-file dialog for selecting a
// backup file to restore from.
func (s *StaticPasswordService) OpenBackupFileDialog() (string, error) {
	return wailsruntime.OpenFileDialog(s.ctx, wailsruntime.OpenDialogOptions{
		Title: "Select Password Backup",
		Filters: []wailsruntime.FileFilter{
			{DisplayName: "JSON Files", Pattern: "*.json"},
			{DisplayName: "Encrypted Backup", Pattern: "*.enc"},
			{DisplayName: "All Files", Pattern: "*"},
		},
	})
}

// RestorePasswords imports passwords from a backup file created by
// BackupPasswords. When encrypted is true, the file is first decrypted with
// the given algorithm and password. Existing passwords with the same name are
// skipped (no overwrite). Returns the number of passwords imported.
func (s *StaticPasswordService) RestorePasswords(filePath string, encrypted bool, algorithm string, password string) (int, error) {
	if filePath == "" {
		return 0, ErrRestoreInvalidPath
	}
	if s.store == nil {
		return 0, ErrStaticPWStoreNotSet
	}

	if encrypted {
		if password == "" {
			return 0, ErrBackupPasswordRequired
		}
		if _, ok := algorithmKeySize[algorithm]; !ok {
			return 0, ErrBackupInvalidAlgorithm
		}
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return 0, ErrRestoreInvalidPath
	}

	var jsonBytes []byte
	if encrypted {
		jsonBytes, err = decryptBackup(data, algorithm, password)
		if err != nil {
			return 0, err
		}
	} else {
		jsonBytes = data
	}

	var entries []StaticPasswordEntry
	if err := json.Unmarshal(jsonBytes, &entries); err != nil {
		return 0, ErrRestoreParseFailed
	}

	// Build a set of existing password names for dedup.
	existing, err := s.store.List()
	if err != nil {
		return 0, err
	}
	existingNames := make(map[string]struct{}, len(existing))
	for _, pw := range existing {
		existingNames[pw.Name] = struct{}{}
	}

	imported := 0
	for _, entry := range entries {
		if entry.Name == "" {
			continue
		}
		// Skip duplicates.
		if _, exists := existingNames[entry.Name]; exists {
			continue
		}

		pw := &staticpw.StaticPassword{
			Name:          entry.Name,
			Title:         entry.Title,
			Username:      entry.Username,
			Password:      entry.Password,
			URL:           entry.URL,
			MatchPatterns: entry.MatchPatterns,
			Notes:         entry.Notes,
			FolderPath:    entry.FolderPath,
			ReadOnly:      entry.ReadOnly,
		}

		if entry.ExpiresAt != "" {
			expiresAt, parseErr := time.Parse(time.RFC3339, entry.ExpiresAt)
			if parseErr == nil {
				pw.ExpiresAt = expiresAt
			}
		}

		if addErr := s.store.Add(pw); addErr != nil {
			continue
		}
		existingNames[entry.Name] = struct{}{}
		imported++
	}

	return imported, nil
}

// decryptBackup decrypts an AES-GCM encrypted backup file.
func decryptBackup(data []byte, algorithm string, password string) ([]byte, error) {
	keySize, ok := algorithmKeySize[algorithm]
	if !ok {
		return nil, ErrBackupInvalidAlgorithm
	}

	hash := sha256.Sum256([]byte(password))
	key := hash[:keySize]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrRestoreDecryptFailed
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrRestoreDecryptFailed
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, ErrRestoreDecryptFailed
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrRestoreDecryptFailed
	}

	return plaintext, nil
}

// ---------------------------------------------------------------------------
// Server-side password store operations (via transport client)
// ---------------------------------------------------------------------------

// Unlock unlocks the password store by providing the user PIN. This delegates
// to the server's PasswordStoreUnlock endpoint via the transport client.
func (s *StaticPasswordService) Unlock(pin string) error {
	client, err := s.getClient()
	if err != nil {
		return err
	}
	return client.PasswordStoreUnlock(s.getContext(), &transport.PasswordStoreUnlockRequest{
		UserPIN: pin,
	})
}

// Lock locks the password store, requiring re-authentication before further
// access. This delegates to the server's PasswordStoreLock endpoint.
func (s *StaticPasswordService) Lock() error {
	client, err := s.getClient()
	if err != nil {
		return err
	}
	return client.PasswordStoreLock(s.getContext())
}

// GetStoreStatus returns the current password store status including lock
// state, access mode, and password count.
func (s *StaticPasswordService) GetStoreStatus() (*PasswordStoreStatus, error) {
	client, err := s.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := client.PasswordStoreStatus(s.getContext())
	if err != nil {
		return nil, err
	}

	return &PasswordStoreStatus{
		AccessMode:    resp.AccessMode,
		IsLocked:      resp.IsLocked,
		AutoUnsealed:  resp.AutoUnsealed,
		PasswordCount: resp.PasswordCount,
	}, nil
}

// SetAccessMode sets the password store access mode (e.g., "pin", "open",
// "locked"). The mode string must not be empty.
func (s *StaticPasswordService) SetAccessMode(mode string) error {
	if mode == "" {
		return ErrStaticPWInvalidAccessMode
	}

	client, err := s.getClient()
	if err != nil {
		return err
	}

	return client.PasswordStoreSetAccessMode(s.getContext(), &transport.PasswordStoreSetAccessModeRequest{
		Mode: mode,
	})
}

// TryAutoUnlock attempts to unlock the password store without a PIN by
// sending an empty PIN to the server. This supports auto-unseal scenarios
// where the server uses platform-sealed credentials.
func (s *StaticPasswordService) TryAutoUnlock() error {
	client, err := s.getClient()
	if err != nil {
		return err
	}
	return client.PasswordStoreUnlock(s.getContext(), &transport.PasswordStoreUnlockRequest{
		UserPIN: "",
	})
}

// Generate produces a random password on the server side using the specified
// character class options. The length must be positive.
func (s *StaticPasswordService) Generate(length int, upper, lower, digits, symbols bool) (string, error) {
	if length <= 0 {
		return "", ErrStaticPWInvalidGenerateLength
	}

	client, err := s.getClient()
	if err != nil {
		return "", err
	}

	resp, err := client.PasswordGenerate(s.getContext(), &transport.PasswordGenerateRequest{
		Length:  length,
		Upper:   upper,
		Lower:   lower,
		Digits:  digits,
		Symbols: symbols,
	})
	if err != nil {
		return "", err
	}

	return resp.Password, nil
}

// staticPWToEntry converts a staticpw.StaticPassword to the frontend-facing
// StaticPasswordEntry type, formatting time values as RFC3339 strings and
// computing expiry status.
func staticPWToEntry(pw *staticpw.StaticPassword) StaticPasswordEntry {
	entry := StaticPasswordEntry{
		ID:              pw.ID,
		Name:            pw.Name,
		Title:           pw.DisplayTitle(),
		Username:        pw.Username,
		Password:        pw.Password,
		URL:             pw.URL,
		MatchPatterns:   pw.MatchPatterns,
		Notes:           pw.Notes,
		FolderPath:      pw.FolderPath,
		CreatedAt:       pw.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       pw.UpdatedAt.Format(time.RFC3339),
		DaysUntilExpiry: -1,
		ReadOnly:        pw.ReadOnly,
	}

	if !pw.ExpiresAt.IsZero() {
		entry.ExpiresAt = pw.ExpiresAt.Format(time.RFC3339)
		now := time.Now()
		if pw.ExpiresAt.Before(now) {
			entry.IsExpired = true
			entry.DaysUntilExpiry = 0
		} else {
			remaining := pw.ExpiresAt.Sub(now)
			entry.DaysUntilExpiry = int(math.Ceil(remaining.Hours() / 24))
		}
	}

	return entry
}

// ---------------------------------------------------------------------------
// Import operations (from external password managers)
// ---------------------------------------------------------------------------

// ImportParams holds parameters for importing passwords from external sources.
type ImportParams struct {
	FilePath            string `json:"file_path"`
	Format              string `json:"format"`               // "csv", "xml", "kdbx" or empty for auto-detect
	Password            string `json:"password,omitempty"`   // Required for KDBX files
	TargetFolder        string `json:"target_folder"`        // Optional folder prefix
	SkipDuplicates      bool   `json:"skip_duplicates"`      // Skip existing entries
	OverwriteDuplicates bool   `json:"overwrite_duplicates"` // Overwrite existing entries
	ImportTOTP          bool   `json:"import_totp"`          // Track TOTP imports
}

// ImportResult contains the result of an import operation.
type ImportResult struct {
	Imported     int           `json:"imported"`
	Skipped      int           `json:"skipped"`
	Failed       int           `json:"failed"`
	Errors       []ImportError `json:"errors,omitempty"`
	TOTPImported int           `json:"totp_imported,omitempty"`
	DurationMs   int64         `json:"duration_ms"`
}

// ImportError describes a single import failure.
type ImportError struct {
	EntryName string `json:"entry_name"`
	Error     string `json:"error"`
}

// ImportPreviewEntry is a preview of an entry to be imported.
type ImportPreviewEntry struct {
	Title      string   `json:"title"`
	Username   string   `json:"username"`
	URL        string   `json:"url"`
	FolderPath string   `json:"folder_path"`
	HasTOTP    bool     `json:"has_totp"`
	Tags       []string `json:"tags,omitempty"`
}

// ImportPreviewResult contains the preview of what will be imported.
type ImportPreviewResult struct {
	Entries []ImportPreviewEntry `json:"entries"`
	Total   int                  `json:"total"`
	Format  string               `json:"format"`
}

// OpenImportFileDialog opens the native file dialog for selecting an import file.
func (s *StaticPasswordService) OpenImportFileDialog() (string, error) {
	return wailsruntime.OpenFileDialog(s.ctx, wailsruntime.OpenDialogOptions{
		Title: "Select Password File to Import",
		Filters: []wailsruntime.FileFilter{
			{DisplayName: "KeePass Files", Pattern: "*.kdbx;*.xml;*.csv"},
			{DisplayName: "KDBX Database", Pattern: "*.kdbx"},
			{DisplayName: "KeePass XML Export", Pattern: "*.xml"},
			{DisplayName: "CSV Export", Pattern: "*.csv"},
			{DisplayName: "All Files", Pattern: "*"},
		},
	})
}

// PreviewImport parses the import file and returns a preview of entries
// without actually importing them.
func (s *StaticPasswordService) PreviewImport(params ImportParams) (*ImportPreviewResult, error) {
	if params.FilePath == "" {
		return nil, ErrRestoreInvalidPath
	}
	if s.store == nil {
		return nil, ErrStaticPWStoreNotSet
	}

	importer := s.newImporter()
	opts := s.paramsToImportOptions(params)

	entries, err := importer.Preview(opts)
	if err != nil {
		return nil, err
	}

	result := &ImportPreviewResult{
		Entries: make([]ImportPreviewEntry, 0, len(entries)),
		Total:   len(entries),
		Format:  importer.DetectFormat(params.FilePath),
	}

	for _, e := range entries {
		result.Entries = append(result.Entries, ImportPreviewEntry{
			Title:      e.Title,
			Username:   e.Username,
			URL:        e.URL,
			FolderPath: e.FolderPath,
			HasTOTP:    e.HasTOTP,
			Tags:       e.Tags,
		})
	}

	return result, nil
}

// ImportPasswords imports passwords from an external password manager file.
// Supports CSV, KeePass XML, and KDBX formats.
func (s *StaticPasswordService) ImportPasswords(params ImportParams) (*ImportResult, error) {
	if params.FilePath == "" {
		return nil, ErrRestoreInvalidPath
	}
	if s.store == nil {
		return nil, ErrStaticPWStoreNotSet
	}

	importer := s.newImporter()
	opts := s.paramsToImportOptions(params)

	result, err := importer.Import(opts)
	if err != nil {
		return nil, err
	}

	// Convert to service result type.
	svcResult := &ImportResult{
		Imported:     result.Imported,
		Skipped:      result.Skipped,
		Failed:       result.Failed,
		TOTPImported: result.TOTPImported,
		DurationMs:   result.Duration.Milliseconds(),
	}

	for _, e := range result.Errors {
		svcResult.Errors = append(svcResult.Errors, ImportError{
			EntryName: e.EntryName,
			Error:     e.Error,
		})
	}

	return svcResult, nil
}

// GetSupportedImportFormats returns the list of supported import formats.
func (s *StaticPasswordService) GetSupportedImportFormats() []string {
	return []string{"csv", "xml", "kdbx"}
}

// newImporter creates a new pwimport.Importer with the current store.
func (s *StaticPasswordService) newImporter() *pwimport.Importer {
	return pwimport.NewImporter(s.store)
}

// paramsToImportOptions converts ImportParams to pwimport.ImportOptions.
func (s *StaticPasswordService) paramsToImportOptions(params ImportParams) *pwimport.ImportOptions {
	return &pwimport.ImportOptions{
		FilePath:            params.FilePath,
		Format:              params.Format,
		Password:            params.Password,
		TargetFolder:        params.TargetFolder,
		SkipDuplicates:      params.SkipDuplicates,
		OverwriteDuplicates: params.OverwriteDuplicates,
		ImportTOTP:          params.ImportTOTP,
	}
}
