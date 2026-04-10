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
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/go-tpm/tpm2"
	"golang.org/x/crypto/argon2"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
)

// StorageType indicates where a sealed blob is physically stored.
type StorageType string

const (
	// StorageTypeDisk stores sealed blobs on the filesystem.
	StorageTypeDisk StorageType = "disk"

	// StorageTypeNVRAM stores TPM sealed object blobs in TPM NV RAM.
	StorageTypeNVRAM StorageType = "nvram"
)

// Seal service errors.
var (
	ErrSealTPMNotAvailable    = errors.New("seal_service: TPM not available")
	ErrSealNotSupported       = errors.New("seal_service: sealer does not support sealing")
	ErrSealInvalidLabel       = errors.New("seal_service: label is required")
	ErrSealInvalidData        = errors.New("seal_service: data is required")
	ErrSealBlobNotFound       = errors.New("seal_service: sealed blob not found")
	ErrSealStorageFailed      = errors.New("seal_service: storage operation failed")
	ErrSealDecodeFailed       = errors.New("seal_service: base64 decode failed")
	ErrSealMarshalFailed      = errors.New("seal_service: JSON marshal failed")
	ErrSealUnmarshalFailed    = errors.New("seal_service: JSON unmarshal failed")
	ErrSealInvalidPolicyType  = errors.New("seal_service: invalid policy type")
	ErrSealPasswordRequired   = errors.New("seal_service: password required for this blob")
	ErrSealPolicyMismatch     = errors.New("seal_service: password does not match")
	ErrSealPolicyNotAvailable = errors.New("seal_service: platform policy not configured")
	ErrSealStorageDirNotSet   = errors.New("seal_service: storage directory not configured")
	ErrSealStorageDirRelative = errors.New("seal_service: storage directory must be an absolute path")
	ErrSealBackendNotFound    = errors.New("seal_service: requested backend not registered")
	ErrSealPolicyRequiresTPM  = errors.New("seal_service: PCR-based policies require TPM backend")
	ErrSealMigrationFailed    = errors.New("seal_service: migration failed")
	ErrSealNoClient           = errors.New("seal_service: SDK client not available")
)

// pcrBankAlgMap maps user-facing PCR bank names to TPM algorithm identifiers.
var pcrBankAlgMap = map[string]tpm2.TPMAlgID{
	"sha1":   tpm2.TPMAlgSHA1,
	"sha256": tpm2.TPMAlgSHA256,
	"sha384": tpm2.TPMAlgSHA384,
	"sha512": tpm2.TPMAlgSHA512,
}

// hashAlgIDToStringMap maps TPM hash algorithm IDs to their string names.
var hashAlgIDToStringMap = map[tpm2.TPMAlgID]string{
	tpm2.TPMAlgSHA1:   "sha1",
	tpm2.TPMAlgSHA256: "sha256",
	tpm2.TPMAlgSHA384: "sha384",
	tpm2.TPMAlgSHA512: "sha512",
}

// Argon2id parameters for password hashing.
const (
	argon2Time    = 1
	argon2Memory  = 64 * 1024
	argon2Threads = 4
	argon2KeyLen  = 32
	argon2SaltLen = 16
)

// policyHandler is a function that applies policy-specific seal options.
type policyHandler func(s *SealService, req *SealRequest, opts *types.SealOptions) error

// policyHandlers maps policy types to their handler functions.
var policyHandlers = map[PolicyType]policyHandler{
	PolicyTypeNone:           handlePolicyNone,
	PolicyTypePassword:       handlePolicyPassword,
	PolicyTypePlatformPolicy: handlePolicyPlatformPolicy,
	PolicyTypeCustomPCR:      handlePolicyCustomPCR,
}

// tpmOnlyPolicies defines policy types that require a TPM backend.
var tpmOnlyPolicies = map[PolicyType]struct{}{
	PolicyTypePlatformPolicy: {},
	PolicyTypeCustomPCR:      {},
}

// systemSealLabels identifies labels that belong to the "system" category.
// System blobs cannot be deleted from the Sealed Data UI.
// NOTE: user_pin is intentionally NOT in this list. It is managed via the
// Settings > Security > Auto-unlock toggle, but users may also delete it
// directly from the Sealed Data view, which disables auto-unlock.
var systemSealLabels = map[string]struct{}{
	"password_master_key":    {},
	"auto-unseal-passphrase": {},
	"barrier_password":       {},
}

// classifyCategory returns "system" for well-known internal labels, "user" otherwise.
func classifyCategory(label string) string {
	if _, ok := systemSealLabels[label]; ok {
		return "system"
	}
	return "user"
}

// sealerMetadata holds static metadata for known sealing backends.
type sealerMetadata struct {
	Label          string
	Description    string
	HardwareBacked bool
	SecurityLevel  types.SecurityLevel
}

// knownSealerMeta maps backend names to their display metadata.
// SecurityLevel values: 0=Low (software), 3=VeryHigh (TPM2)
var knownSealerMeta = map[string]sealerMetadata{
	string(types.BackendTypeTPM2): {
		Label:          "TPM 2.0",
		Description:    "Hardware-bound sealing using the Trusted Platform Module. Keys never leave the TPM chip.",
		HardwareBacked: true,
		SecurityLevel:  types.SecurityLevelVeryHigh,
	},
	string(types.BackendTypeSoftware): {
		Label:          "Software AES-256-GCM",
		Description:    "Software-based sealing with a filesystem-protected master key. No special hardware required.",
		HardwareBacked: false,
		SecurityLevel:  types.SecurityLevelLow,
	},
}

// SealerInfo describes an available sealing backend for the frontend.
type SealerInfo struct {
	ID             string            `json:"id"`
	Available      bool              `json:"available"`
	HardwareBacked bool              `json:"hardware_backed"`
	SecurityLevel  uint8             `json:"security_level"` // 0=Low, 1=Medium, 2=High, 3=VeryHigh
	Label          string            `json:"label"`
	Description    string            `json:"description"`
	IsDefault      bool              `json:"is_default"`
	Details        map[string]string `json:"details,omitempty"`
}

// AvailableSealers returns only the sealing backends that are actually
// configured and available (i.e., CanSeal returns true). Backends are
// sorted by SecurityLevel descending (most secure first), then
// alphabetically by ID for stable ordering.
func (s *SealService) AvailableSealers() []SealerInfo {
	var infos []SealerInfo

	client, clientErr := s.getClient()
	if clientErr != nil {
		s.log.Debug("AvailableSealers: no client available", "error", clientErr)
		return infos
	}

	for name, meta := range knownSealerMeta {
		resp, err := client.CanSeal(context.Background(), name)
		if err != nil {
			s.log.Debug("CanSeal check failed", "backend", name, "error", err)
			continue
		}
		if resp == nil || !resp.CanSeal {
			continue
		}

		infos = append(infos, SealerInfo{
			ID:             name,
			Available:      true,
			IsDefault:      name == s.defaultBackend,
			Label:          meta.Label,
			Description:    meta.Description,
			HardwareBacked: meta.HardwareBacked,
			SecurityLevel:  uint8(meta.SecurityLevel),
			Details:        s.sealerDetails(name),
		})
	}

	// Sort alphabetically by label for consistent UI ordering.
	sort.Slice(infos, func(i, j int) bool {
		return infos[i].Label < infos[j].Label
	})

	return infos
}

// sealerDetails returns backend-specific display details for the given backend.
func (s *SealService) sealerDetails(backend string) map[string]string {
	details := make(map[string]string)
	switch backend {
	case string(types.BackendTypeSoftware):
		details["storage_dir"] = s.storageDir
	case string(types.BackendTypeTPM2):
		details["srk_handle"] = "0x81000002"
		details["storage_dir"] = s.storageDir
	}
	return details
}

// SealedBlobEntry is the frontend-facing representation of a sealed blob.
type SealedBlobEntry struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	SizeBytes   int    `json:"size_bytes"`
	PCRBound    bool   `json:"pcr_bound"`
	PolicyType  string `json:"policy_type"`
	CreatedAt   string `json:"created_at"`
	Category    string `json:"category"`
	BackendID   string `json:"backend_id"`   // which backend sealed this blob
	StorageType string `json:"storage_type"` // "disk" or "nvram"
}

// SealRequest holds the parameters for a seal operation.
type SealRequest struct {
	Label       string `json:"label"`
	Data        string `json:"data"`         // base64-encoded plaintext
	PCRs        []int  `json:"pcrs"`         // optional PCR binding
	PCRBank     string `json:"pcr_bank"`     // default "sha256"
	PolicyType  string `json:"policy_type"`  // "none"|"password"|"platform_policy"|"custom_pcr"
	Password    string `json:"password"`     // for PolicyTypePassword
	Backend     string `json:"backend"`      // "tpm2", "software", etc. Empty = default
	StorageType string `json:"storage_type"` // "disk" or "nvram". Empty = default ("disk")
}

// sealedBlobStorage is the internal on-disk representation.
type sealedBlobStorage struct {
	ID          string            `json:"id"`
	Label       string            `json:"label"`
	SizeBytes   int               `json:"size_bytes"`
	PCRBound    bool              `json:"pcr_bound"`
	PCRs        []int             `json:"pcrs,omitempty"`
	PCRBank     string            `json:"pcr_bank,omitempty"`
	PolicyType  string            `json:"policy_type,omitempty"`
	Password    string            `json:"password,omitempty"` // argon2id hash for verification
	Category    string            `json:"category,omitempty"`
	BackendID   string            `json:"backend_id,omitempty"`   // backend registry ID that sealed this blob
	StorageType string            `json:"storage_type,omitempty"` // "disk" or "nvram"
	NVIndex     uint32            `json:"nv_index,omitempty"`     // NV RAM base index (when StorageType = "nvram")
	SealedData  *types.SealedData `json:"sealed_data"`
	CreatedAt   time.Time         `json:"created_at"`
}

// SealService exposes seal/unseal operations to the frontend via the
// go-xkms SDK transport.Client interface. All sealing operations are
// delegated to the SDK client, which handles backend routing.
//
// Backend selection priority (highest to lowest):
//  1. TPM2 -- hardware-bound keys, highest security
//  2. Software -- AES-256-GCM with filesystem-protected master key
//
// The default backend is auto-selected based on what is available.
type SealService struct {
	mu             sync.RWMutex
	ctx            context.Context
	log            *slog.Logger
	storageDir     string
	tpmAccessor    *TPMAccessor // kept for NV RAM operations
	policyService  *PlatformPolicyService
	localClient    xkms.Client        // embedded local client (always available after init)
	clientFunc     func() xkms.Client // remote server client provider
	defaultBackend string             // default backend name
	backend        storage.Backend    // barrier-encrypted storage (nil = direct disk fallback)
	blobPrefix     string             // key prefix for backend storage (e.g. "sealed/")
	auditLog       atomic.Pointer[audit.Logger]
}

// NewSealService creates a new SealService that stores sealed blobs in storageDir.
func NewSealService(storageDir string) *SealService {
	return &SealService{
		log:            slog.Default().With("component", "seal_service"),
		storageDir:     storageDir,
		defaultBackend: string(types.BackendTypeTPM2),
	}
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *SealService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetLocalClient sets the embedded local client for seal/unseal operations.
// The local client is always available after initialization and provides
// access to locally configured backends (software, TPM2, PKCS#11).
func (s *SealService) SetLocalClient(c xkms.Client) {
	s.localClient = c
}

// SetClientFunc sets the function used to obtain a remote SDK client for
// seal/unseal operations when connected to a remote xkmsd server.
func (s *SealService) SetClientFunc(fn func() xkms.Client) {
	s.clientFunc = fn
}

// getClient returns the best available SDK client. It prefers the remote
// server client (when connected) and falls back to the embedded local
// client. Returns ErrSealNoClient if neither is available.
func (s *SealService) getClient() (xkms.Client, error) {
	// Prefer remote server client when connected.
	if s.clientFunc != nil {
		if client := s.clientFunc(); client != nil {
			return client, nil
		}
	}
	// Fall back to embedded local client.
	if s.localClient != nil {
		return s.localClient, nil
	}
	return nil, ErrSealNoClient
}

// SetTPMAccessor sets the shared TPMAccessor used for serialized TPM access.
// The TPM accessor is kept for NV RAM operations but sealing operations
// are now routed through the SDK client.
func (s *SealService) SetTPMAccessor(a *TPMAccessor) {
	s.tpmAccessor = a
}

// SetPlatformPolicyService sets the platform policy service used for
// PolicyTypePlatformPolicy seal operations.
func (s *SealService) SetPlatformPolicyService(svc *PlatformPolicyService) {
	s.policyService = svc
}

// SetBackend sets the storage backend used for blob persistence. When set,
// all blob I/O is routed through this backend (typically the barrier for
// transparent encryption). When nil, blobs are written directly to disk.
func (s *SealService) SetBackend(b storage.Backend, prefix string) {
	s.backend = b
	s.blobPrefix = prefix
}

// Backend returns the current storage backend, or nil if direct disk I/O is used.
func (s *SealService) Backend() storage.Backend {
	return s.backend
}

// SetAuditLogger sets the audit logger for security event logging.
func (s *SealService) SetAuditLogger(l audit.Logger) {
	s.auditLog.Store(&l)
}

// logSealEvent logs a seal-related audit event.
func (s *SealService) logSealEvent(op audit.OperationType, success bool, err error, details map[string]any) {
	if p := s.auditLog.Load(); p != nil {
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		(*p).Log(audit.Entry{
			Timestamp: time.Now(),
			Operation: op,
			Success:   success,
			Error:     errStr,
			Details:   details,
		})
	}
}

// BestSealer returns the most secure available sealer, or nil if none available.
// It picks the sealer with the highest SecurityLevel; ties are broken
// alphabetically by ID for determinism.
func (s *SealService) BestSealer() *SealerInfo {
	sealers := s.AvailableSealers()
	if len(sealers) == 0 {
		return nil
	}
	best := 0
	for i := 1; i < len(sealers); i++ {
		if sealers[i].SecurityLevel > sealers[best].SecurityLevel {
			best = i
		} else if sealers[i].SecurityLevel == sealers[best].SecurityLevel && sealers[i].ID < sealers[best].ID {
			best = i
		}
	}
	return &sealers[best]
}

// SetDefaultBackend sets the default backend used when SealRequest.Backend is empty.
func (s *SealService) SetDefaultBackend(backend string) {
	s.defaultBackend = backend
}

// AutoSelectDefault queries available backends via the SDK and selects
// the highest-security-level backend as the default.
func (s *SealService) AutoSelectDefault() {
	s.autoSelectDefault()
}

// autoSelectDefault picks the best available backend as the default.
// Priority is determined by SecurityLevel: VeryHigh (TPM2) > Low (Software).
func (s *SealService) autoSelectDefault() {
	client, err := s.getClient()
	if err != nil {
		return
	}

	type sealerWithLevel struct {
		name  string
		level types.SecurityLevel
	}
	var available []sealerWithLevel

	ctx := context.Background()
	for name, meta := range knownSealerMeta {
		resp, canErr := client.CanSeal(ctx, name)
		if canErr == nil && resp != nil && resp.CanSeal {
			available = append(available, sealerWithLevel{name: name, level: meta.SecurityLevel})
		}
	}

	if len(available) == 0 {
		return
	}

	// Sort by SecurityLevel descending, then by name for stability.
	sort.Slice(available, func(i, j int) bool {
		if available[i].level != available[j].level {
			return available[i].level > available[j].level
		}
		return available[i].name < available[j].name
	})

	s.defaultBackend = available[0].name
}

// DefaultBackend returns the current default backend name.
func (s *SealService) DefaultBackend() string {
	return s.defaultBackend
}

// SetStorageDir updates the storage directory to newDir. The new directory
// must be an absolute path. This is used during startup to relocate sealed
// blob storage from the initial config directory to the data directory
// (~/.xkey/data/sealed/) once the data directory is available.
func (s *SealService) SetStorageDir(newDir string) error {
	if newDir == "" {
		return ErrSealStorageDirNotSet
	}
	if !filepath.IsAbs(newDir) {
		return ErrSealStorageDirRelative
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.storageDir = newDir
	return os.MkdirAll(newDir, 0700)
}

// StorageDir returns the current storage directory path.
func (s *SealService) StorageDir() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.storageDir
}

// MigrateFrom copies sealed blobs from srcDir into the current storage
// directory. Existing files in the destination are not overwritten. This
// is a non-destructive copy used during startup to migrate blobs from
// the legacy config directory (~/.config/xkey/sealed/) to the data
// directory (~/.xkey/data/sealed/).
func (s *SealService) MigrateFrom(srcDir string) (int, error) {
	if srcDir == "" {
		return 0, ErrSealStorageDirNotSet
	}
	if !filepath.IsAbs(srcDir) {
		return 0, ErrSealStorageDirRelative
	}

	// Nothing to migrate if the source and destination are the same.
	if srcDir == s.storageDir {
		return 0, nil
	}

	// Read source directory entries.
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		// Source directory does not exist; nothing to migrate.
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, ErrSealMigrationFailed
	}
	if len(entries) == 0 {
		return 0, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if mkErr := s.ensureStorageDir(); mkErr != nil {
		return 0, ErrSealMigrationFailed
	}

	migrated := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		dst := filepath.Join(s.storageDir, entry.Name())

		// Do not overwrite existing files in the destination.
		if _, statErr := os.Stat(dst); statErr == nil {
			continue
		}

		src := filepath.Join(srcDir, entry.Name())
		data, readErr := os.ReadFile(src)
		if readErr != nil {
			s.log.Warn("failed to read legacy sealed blob for migration",
				"file", src, "error", readErr)
			continue
		}
		if writeErr := os.WriteFile(dst, data, 0600); writeErr != nil {
			s.log.Warn("failed to write migrated sealed blob",
				"file", dst, "error", writeErr)
			continue
		}
		migrated++
	}

	if migrated > 0 {
		s.log.Info("migrated sealed blobs to data directory",
			"from", srcDir, "to", s.storageDir, "count", migrated)
	}

	return migrated, nil
}

// CanSeal returns true if the default backend is available and supports sealing.
func (s *SealService) CanSeal() (bool, error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in CanSeal", "recover", r)
		}
	}()

	client, err := s.getClient()
	if err != nil {
		return false, nil
	}

	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	resp, err := client.CanSeal(ctx, s.defaultBackend)
	if err != nil {
		return false, nil
	}
	return resp.CanSeal, nil
}

// blobWithTime pairs a frontend entry with its raw creation time for sorting.
type blobWithTime struct {
	entry     SealedBlobEntry
	createdAt time.Time
}

// ListBlobs returns all sealed blob entries sorted by creation time (newest first).
// When a storage backend is configured, blobs are read from the backend.
// Otherwise, blobs are read directly from the storage directory.
func (s *SealService) ListBlobs() (entries []SealedBlobEntry, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in ListBlobs", "recover", r)
			entries = []SealedBlobEntry{}
			retErr = fmt.Errorf("seal_service: panic in ListBlobs: %v", r)
		}
	}()

	s.mu.RLock()
	defer s.mu.RUnlock()

	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	if s.backend != nil {
		return s.listBlobsViaBackend(ctx)
	}

	return s.listBlobsDirect()
}

// listBlobsViaBackend lists blobs through the configured storage backend.
func (s *SealService) listBlobsViaBackend(ctx context.Context) ([]SealedBlobEntry, error) {
	keys, err := s.backend.List(ctx, s.blobPrefix)
	if err != nil {
		s.log.Warn("backend list failed", "error", err)
		return []SealedBlobEntry{}, nil
	}

	var items []blobWithTime
	for _, key := range keys {
		data, readErr := s.backend.Get(ctx, key)
		if readErr != nil {
			continue
		}
		var blob sealedBlobStorage
		if unmarshalErr := json.Unmarshal(data, &blob); unmarshalErr != nil {
			continue
		}
		items = append(items, blobWithTime{
			entry:     blobToEntry(&blob),
			createdAt: blob.CreatedAt,
		})
	}

	return sortAndCollectEntries(items), nil
}

// listBlobsDirect lists blobs by reading the storage directory directly.
func (s *SealService) listBlobsDirect() ([]SealedBlobEntry, error) {
	if err := s.ensureStorageDir(); err != nil {
		s.log.Warn("seal storage directory unavailable", "error", err)
		return []SealedBlobEntry{}, nil
	}

	dirEntries, err := os.ReadDir(s.storageDir)
	if err != nil {
		return []SealedBlobEntry{}, nil
	}

	var items []blobWithTime
	for _, de := range dirEntries {
		if de.IsDir() || filepath.Ext(de.Name()) != ".json" {
			continue
		}
		blob, loadErr := s.loadBlob(filepath.Join(s.storageDir, de.Name()))
		if loadErr != nil {
			s.log.Warn("failed to load sealed blob", "file", de.Name(), "error", loadErr)
			continue
		}
		items = append(items, blobWithTime{
			entry:     blobToEntry(blob),
			createdAt: blob.CreatedAt,
		})
	}

	return sortAndCollectEntries(items), nil
}

// blobToEntry converts an internal sealedBlobStorage to a frontend SealedBlobEntry.
func blobToEntry(blob *sealedBlobStorage) SealedBlobEntry {
	policyType := blob.PolicyType
	if policyType == "" {
		policyType = string(PolicyTypeNone)
	}
	category := blob.Category
	if category == "" {
		category = classifyCategory(blob.Label)
	}
	storageType := blob.StorageType
	if storageType == "" {
		storageType = string(StorageTypeDisk)
	}
	return SealedBlobEntry{
		ID:          blob.ID,
		Label:       blob.Label,
		SizeBytes:   blob.SizeBytes,
		PCRBound:    blob.PCRBound,
		PolicyType:  policyType,
		CreatedAt:   blob.CreatedAt.Format(time.RFC3339),
		Category:    category,
		BackendID:   blob.BackendID,
		StorageType: storageType,
	}
}

// sortAndCollectEntries sorts blob entries newest-first and returns the slice.
func sortAndCollectEntries(items []blobWithTime) []SealedBlobEntry {
	sort.Slice(items, func(i, j int) bool {
		return items[i].createdAt.After(items[j].createdAt)
	})

	entries := make([]SealedBlobEntry, len(items))
	for i, item := range items {
		entries[i] = item.entry
	}

	return entries
}

// SealData seals the provided data using the resolved backend via the
// SDK client and stores the result as a blob. When a storage backend
// is configured, data is persisted through the barrier-encrypted backend.
// Otherwise, the blob is written directly to disk.
func (s *SealService) SealData(req *SealRequest) (entry *SealedBlobEntry, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in SealData", "recover", r)
			entry = nil
			retErr = fmt.Errorf("seal_service: panic in SealData: %v", r)
		}
	}()

	if req == nil || req.Label == "" {
		return nil, ErrSealInvalidLabel
	}
	if req.Data == "" {
		return nil, ErrSealInvalidData
	}

	plaintext, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		return nil, ErrSealDecodeFailed
	}

	// Resolve backend (default to configured backend).
	backend := req.Backend
	if backend == "" {
		backend = s.defaultBackend
	}

	// Resolve policy type (default to "none" for backward compatibility).
	policyTypeStr := req.PolicyType
	if policyTypeStr == "" {
		policyTypeStr = string(PolicyTypeNone)
	}
	pt, ok := policyTypeMap[policyTypeStr]
	if !ok {
		return nil, ErrSealInvalidPolicyType
	}

	// Validate TPM-only policies against backend.
	if _, isTPMOnly := tpmOnlyPolicies[pt]; isTPMOnly && backend != string(types.BackendTypeTPM2) {
		return nil, ErrSealPolicyRequiresTPM
	}

	// Build seal options and apply policy handler (computes PCR selections).
	opts := &types.SealOptions{}
	handler, ok := policyHandlers[pt]
	if !ok {
		return nil, ErrSealInvalidPolicyType
	}
	if err := handler(s, req, opts); err != nil {
		return nil, err
	}

	// Get the SDK client.
	client, err := s.getClient()
	if err != nil {
		return nil, ErrSealBackendNotFound
	}

	// Build SDK SealRequest from the GUI request and policy options.
	sdkReq := &transport.SealRequest{
		Backend: backend,
		Data:    plaintext,
	}

	// Transfer PCR policy from opts to SDK request.
	if opts.TPMPolicy != nil && len(opts.TPMPolicy.PCRSelection.PCRSelections) > 0 {
		sel := opts.TPMPolicy.PCRSelection.PCRSelections[0]
		sdkReq.PCRs = pcrSelectToInts(sel.PCRSelect)
		sdkReq.PCRHashAlg = hashAlgIDToString(sel.Hash)
	}

	// Transfer password if set.
	if opts.Password != nil {
		pwStr, _ := opts.Password.String()
		sdkReq.Password = pwStr
	}

	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	resp, err := client.Seal(ctx, sdkReq)
	if err != nil {
		s.log.Error("seal operation failed", "backend", backend, "error", err)
		s.logSealEvent(audit.OpSealData, false, err, map[string]any{"label": req.Label, "backend": backend})
		return nil, err
	}

	// Map SDK response to SealedData for blob storage.
	sealed := &types.SealedData{
		Backend:    types.BackendType(resp.Backend),
		Ciphertext: resp.Ciphertext,
		Nonce:      resp.Nonce,
		Tag:        resp.Tag,
		TPMPublic:  resp.TPMPublic,
		TPMPrivate: resp.TPMPrivate,
		WrappedDEK: resp.WrappedDEK,
		KeyID:      resp.KeyID,
		Metadata:   resp.Metadata,
	}

	// Generate a unique ID.
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, ErrSealStorageFailed
	}
	id := hex.EncodeToString(idBytes)

	// Resolve storage type (default to "disk").
	storageType := req.StorageType
	if storageType == "" {
		storageType = string(StorageTypeDisk)
	}

	blob := &sealedBlobStorage{
		ID:          id,
		Label:       req.Label,
		SizeBytes:   len(plaintext),
		PCRBound:    len(req.PCRs) > 0 || pt == PolicyTypePlatformPolicy,
		PCRs:        req.PCRs,
		PCRBank:     req.PCRBank,
		PolicyType:  policyTypeStr,
		Category:    classifyCategory(req.Label),
		BackendID:   backend,
		StorageType: storageType,
		SealedData:  sealed,
		CreatedAt:   time.Now(),
	}

	// Hash password for storage if password policy is active.
	if pt == PolicyTypePassword {
		hash, hashErr := hashPassword(req.Password)
		if hashErr != nil {
			return nil, ErrSealStorageFailed
		}
		blob.Password = hash
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.saveBlob(blob); err != nil {
		return nil, err
	}

	result := blobToEntry(blob)
	s.logSealEvent(audit.OpSealData, true, nil, map[string]any{"label": req.Label, "backend": backend})
	return &result, nil
}

// UnsealData unseals a previously sealed blob and returns the data as base64.
// The password parameter is required when the blob was sealed with PolicyTypePassword.
func (s *SealService) UnsealData(id string, password string) (result string, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in UnsealData", "recover", r)
			result = ""
			retErr = fmt.Errorf("seal_service: panic in UnsealData: %v", r)
		}
	}()

	if id == "" {
		return "", ErrSealBlobNotFound
	}

	s.mu.RLock()
	blob, err := s.loadBlobByID(id)
	s.mu.RUnlock()
	if err != nil {
		return "", err
	}

	// Verify password if blob was sealed with password policy.
	if blob.PolicyType == string(PolicyTypePassword) {
		if password == "" {
			return "", ErrSealPasswordRequired
		}
		if !verifyPassword(password, blob.Password) {
			return "", ErrSealPolicyMismatch
		}
	}

	// Determine which backend sealed this data.
	// Priority: stored BackendID > SealedData.Backend > default (backward compat).
	backend := blob.BackendID
	if backend == "" {
		backend = string(blob.SealedData.Backend)
	}
	if backend == "" {
		backend = s.defaultBackend
	}

	client, err := s.getClient()
	if err != nil {
		return "", ErrSealBackendNotFound
	}

	sdkReq := &transport.UnsealRequest{
		Backend:    backend,
		KeyID:      blob.SealedData.KeyID,
		Ciphertext: blob.SealedData.Ciphertext,
		Nonce:      blob.SealedData.Nonce,
		Tag:        blob.SealedData.Tag,
		TPMPublic:  blob.SealedData.TPMPublic,
		TPMPrivate: blob.SealedData.TPMPrivate,
		WrappedDEK: blob.SealedData.WrappedDEK,
		Metadata:   blob.SealedData.Metadata,
	}

	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	resp, err := client.Unseal(ctx, sdkReq)
	if err != nil {
		s.log.Error("unseal operation failed", "backend", backend, "blob_id", id, "error", err)
		s.logSealEvent(audit.OpUnsealData, false, err, map[string]any{"blob_id": id})
		return "", err
	}

	s.logSealEvent(audit.OpUnsealData, true, nil, map[string]any{"blob_id": id})
	return base64.StdEncoding.EncodeToString(resp.Plaintext), nil
}

// DeleteBlob removes a sealed blob from storage.
func (s *SealService) DeleteBlob(id string) error {
	if id == "" {
		return ErrSealBlobNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	if s.backend != nil {
		if err := s.backend.Delete(ctx, s.blobPrefix+id); err != nil {
			s.logSealEvent(audit.OpSealBlobDeleted, false, err, map[string]any{"blob_id": id})
			return ErrSealBlobNotFound
		}
		s.logSealEvent(audit.OpSealBlobDeleted, true, nil, map[string]any{"blob_id": id})
		return nil
	}

	path := s.blobPath(id)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		s.logSealEvent(audit.OpSealBlobDeleted, false, ErrSealBlobNotFound, map[string]any{"blob_id": id})
		return ErrSealBlobNotFound
	}

	if err := os.Remove(path); err != nil {
		s.logSealEvent(audit.OpSealBlobDeleted, false, err, map[string]any{"blob_id": id})
		return ErrSealStorageFailed
	}

	s.logSealEvent(audit.OpSealBlobDeleted, true, nil, map[string]any{"blob_id": id})
	return nil
}

// ensureStorageDir creates the storage directory if it doesn't exist.
// Returns an error if storageDir is empty or not an absolute path.
func (s *SealService) ensureStorageDir() error {
	if s.storageDir == "" {
		return ErrSealStorageDirNotSet
	}
	if !filepath.IsAbs(s.storageDir) {
		return ErrSealStorageDirRelative
	}
	return os.MkdirAll(s.storageDir, 0700)
}

// blobPath returns the file path for a sealed blob.
func (s *SealService) blobPath(id string) string {
	return filepath.Join(s.storageDir, id+".sealed.json")
}

// saveBlob persists a sealed blob. When a storage backend is configured,
// data is written through the backend (barrier-encrypted). Otherwise,
// the blob is written directly to disk as JSON.
func (s *SealService) saveBlob(blob *sealedBlobStorage) error {
	data, err := json.Marshal(blob)
	if err != nil {
		return ErrSealMarshalFailed
	}

	if s.backend != nil {
		ctx := s.ctx
		if ctx == nil {
			ctx = context.Background()
		}
		if putErr := s.backend.Put(ctx, s.blobPrefix+blob.ID, data); putErr != nil {
			return ErrSealStorageFailed
		}
		return nil
	}

	if err := s.ensureStorageDir(); err != nil {
		s.log.Error("failed to create seal storage directory",
			"dir", s.storageDir, "error", err)
		return ErrSealStorageFailed
	}

	path := s.blobPath(blob.ID)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return ErrSealStorageFailed
	}

	return nil
}

// loadBlob reads a sealed blob from a file path.
func (s *SealService) loadBlob(path string) (*sealedBlobStorage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrSealBlobNotFound
	}

	var blob sealedBlobStorage
	if err := json.Unmarshal(data, &blob); err != nil {
		return nil, ErrSealUnmarshalFailed
	}

	return &blob, nil
}

// loadBlobByID finds and loads a sealed blob by its ID.
func (s *SealService) loadBlobByID(id string) (*sealedBlobStorage, error) {
	if s.backend != nil {
		ctx := s.ctx
		if ctx == nil {
			ctx = context.Background()
		}
		data, err := s.backend.Get(ctx, s.blobPrefix+id)
		if err != nil {
			return nil, ErrSealBlobNotFound
		}
		var blob sealedBlobStorage
		if unmarshalErr := json.Unmarshal(data, &blob); unmarshalErr != nil {
			return nil, ErrSealUnmarshalFailed
		}
		return &blob, nil
	}

	path := s.blobPath(id)
	return s.loadBlob(path)
}

// ---------------------------------------------------------------------------
// PCR conversion helpers
// ---------------------------------------------------------------------------

// pcrSelectToInts extracts PCR indices from a TPM PCR select bitmap.
// Each byte contains 8 PCR bits: bit 0 of byte 0 = PCR 0, etc.
func pcrSelectToInts(sel []byte) []int {
	var pcrs []int
	for byteIdx, b := range sel {
		for bit := 0; bit < 8; bit++ {
			if b&(1<<bit) != 0 {
				pcrs = append(pcrs, byteIdx*8+bit)
			}
		}
	}
	return pcrs
}

// hashAlgIDToString converts a TPM hash algorithm ID to its string name.
// Returns "sha256" as the default if the algorithm is not recognized.
func hashAlgIDToString(alg tpm2.TPMAlgID) string {
	if s, ok := hashAlgIDToStringMap[alg]; ok {
		return s
	}
	return "sha256"
}

// ---------------------------------------------------------------------------
// Policy handlers
// ---------------------------------------------------------------------------

// handlePolicyNone performs no additional processing.
func handlePolicyNone(_ *SealService, _ *SealRequest, _ *types.SealOptions) error {
	return nil
}

// handlePolicyPassword validates the password is non-empty. The password
// hash is stored on the blob after sealing, not in the TPM seal options.
func handlePolicyPassword(_ *SealService, req *SealRequest, _ *types.SealOptions) error {
	if req.Password == "" {
		return ErrSealPasswordRequired
	}
	return nil
}

// handlePolicyPlatformPolicy retrieves PCRs from the PlatformPolicyService
// and configures the seal options with the platform policy PCR selection.
func handlePolicyPlatformPolicy(s *SealService, req *SealRequest, opts *types.SealOptions) error {
	if s.policyService == nil {
		return ErrSealPolicyNotAvailable
	}

	pcrs, bank, err := s.policyService.GetPolicyPCRs()
	if err != nil {
		return ErrSealPolicyNotAvailable
	}

	algID, ok := pcrBankAlgMap[bank]
	if !ok {
		algID = tpm2.TPMAlgSHA256
	}

	pcrUints := make([]uint, len(pcrs))
	for i, p := range pcrs {
		pcrUints[i] = uint(p)
	}

	opts.TPMPolicy = &types.TPMSealPolicy{
		PCRSelection: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      algID,
					PCRSelect: tpm2.PCClientCompatible.PCRs(pcrUints...),
				},
			},
		},
		HashAlg: algID,
	}

	// Store the platform policy PCRs on the request for blob metadata.
	req.PCRs = pcrs
	req.PCRBank = bank

	return nil
}

// handlePolicyCustomPCR uses the request's PCRs directly (current behavior).
func handlePolicyCustomPCR(_ *SealService, req *SealRequest, opts *types.SealOptions) error {
	if len(req.PCRs) == 0 {
		return nil
	}

	bank := req.PCRBank
	if bank == "" {
		bank = "sha256"
	}
	algID, ok := pcrBankAlgMap[bank]
	if !ok {
		algID = tpm2.TPMAlgSHA256
	}

	pcrUints := make([]uint, len(req.PCRs))
	for i, p := range req.PCRs {
		pcrUints[i] = uint(p)
	}

	opts.TPMPolicy = &types.TPMSealPolicy{
		PCRSelection: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      algID,
					PCRSelect: tpm2.PCClientCompatible.PCRs(pcrUints...),
				},
			},
		},
		HashAlg: algID,
	}

	return nil
}

// ---------------------------------------------------------------------------
// Password hashing helpers
// ---------------------------------------------------------------------------

// hashPassword creates an argon2id hash of the password with a random salt.
// Format: hex(salt) + ":" + hex(hash).
func hashPassword(password string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", ErrSealStorageFailed
	}
	hash := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(hash), nil
}

// verifyPassword compares a plaintext password against a stored argon2id hash.
func verifyPassword(password, stored string) bool {
	parts := splitPasswordHash(stored)
	if parts == nil {
		return false
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return false
	}
	expectedHash, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}

	computedHash := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return subtle.ConstantTimeCompare(expectedHash, computedHash) == 1
}

// splitPasswordHash splits a "salt:hash" string into its components.
func splitPasswordHash(stored string) []string {
	for i := 0; i < len(stored); i++ {
		if stored[i] == ':' {
			return []string{stored[:i], stored[i+1:]}
		}
	}
	return nil
}
