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

	"golang.org/x/crypto/argon2"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
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
	ErrSealPasswordRequired   = errors.New("seal_service: password required for this blob")
	ErrSealPolicyMismatch     = errors.New("seal_service: password does not match")
	ErrSealStorageDirNotSet   = errors.New("seal_service: storage directory not configured")
	ErrSealStorageDirRelative = errors.New("seal_service: storage directory must be an absolute path")
	ErrSealBackendNotFound    = errors.New("seal_service: requested backend not registered")
	ErrSealPolicyRequiresTPM  = errors.New("seal_service: a TPM policy requires the tpm2 backend")
	ErrSealNoClient           = errors.New("seal_service: SDK client not available")

	// ErrSealBlobBackendIDMissing indicates a sealed blob record on disk has
	// no backend_id. Every blob written by this version sets it; a record
	// without one predates that and cannot be read.
	ErrSealBlobBackendIDMissing = errors.New("seal_service: sealed blob record has no backend_id")

	// ErrSealInvalidBlobID indicates a blob ID supplied by the frontend is
	// not a well-formed blob ID (see validateBlobID). Returned before the ID
	// is joined into a filesystem path by blobPath.
	ErrSealInvalidBlobID = errors.New("seal_service: invalid blob ID")
)

// maxBlobIDLength bounds the length of a blob ID. SealData generates IDs by
// hex-encoding 16 random bytes (32 characters); this cap leaves headroom
// for pre-existing on-disk blobs with hand-assigned, human-readable IDs
// (e.g. records migrated from an earlier version) while still rejecting
// pathological input before it reaches the filesystem.
const maxBlobIDLength = 128

// validateBlobID rejects blob IDs that are not a strict charset: ASCII
// letters, digits, hyphens, and underscores only. Every ID SealData
// generates (hex.EncodeToString of 16 random bytes) satisfies it, as does
// every hand-assigned ID found in on-disk blobs from earlier versions. Blob
// IDs arrive from the frontend and reach the filesystem via blobPath; every
// exported method that accepts one calls validateBlobID first, so path
// traversal segments and separators (e.g. "../../etc/passwd", "a/b", a
// leading ".") can never reach os.Stat, os.Remove, or os.ReadFile.
func validateBlobID(id string) error {
	if id == "" || len(id) > maxBlobIDLength {
		return ErrSealInvalidBlobID
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c == '-' || c == '_':
		default:
			return ErrSealInvalidBlobID
		}
	}
	return nil
}

// Argon2id parameters for password hashing.
const (
	argon2Time    = 1
	argon2Memory  = 64 * 1024
	argon2Threads = 4
	argon2KeyLen  = 32
	argon2SaltLen = 16
)

// sealedObjectPrefix prefixes the name of the TPM sealed object each tpm2
// blob is sealed as. Every blob gets an object of its own, so each carries
// its own policy binding and can be deleted, with its assignment, on its own.
const sealedObjectPrefix = "xkey-sealed-"

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
	SecurityLevel  xkms.SecurityLevel
}

// knownSealerMeta maps backend names to their display metadata.
// SecurityLevel values: 0=Low (software), 3=VeryHigh (TPM2)
var knownSealerMeta = map[string]sealerMetadata{
	string(xkms.BackendTypeTPM2): {
		Label:          "TPM 2.0",
		Description:    "Hardware-bound sealing using the Trusted Platform Module. Keys never leave the TPM chip.",
		HardwareBacked: true,
		SecurityLevel:  xkms.SecurityLevelVeryHigh,
	},
	string(xkms.BackendTypeSoftware): {
		Label:          "Software AES-256-GCM",
		Description:    "Software-based sealing with a filesystem-protected master key. No special hardware required.",
		HardwareBacked: false,
		SecurityLevel:  xkms.SecurityLevelLow,
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
	case string(xkms.BackendTypeSoftware):
		details["storage_dir"] = s.storageDir
	case string(xkms.BackendTypeTPM2):
		details["srk_handle"] = "0x81000002"
		details["storage_dir"] = s.storageDir
	}
	return details
}

// SealedBlobEntry is the frontend-facing representation of a sealed blob.
type SealedBlobEntry struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	SizeBytes int    `json:"size_bytes"`

	// TPMPolicy names the TPM policy the blob is bound to: "platform", a
	// named policy, or empty for none.
	TPMPolicy string `json:"tpm_policy"`

	// PasswordProtected reports whether unsealing takes a password.
	PasswordProtected bool `json:"password_protected"`

	CreatedAt   string `json:"created_at"`
	Category    string `json:"category"`
	BackendID   string `json:"backend_id"`   // which backend sealed this blob
	StorageType string `json:"storage_type"` // "disk" or "nvram"
}

// SealRequest holds the parameters for a seal operation.
type SealRequest struct {
	Label string `json:"label"`
	Data  string `json:"data"` // base64-encoded plaintext

	// TPMPolicy names the TPM policy the blob is bound to (tpm2 backend
	// only): "platform" for the built-in platform policy, a named policy,
	// or empty for none.
	TPMPolicy string `json:"tpm_policy"`

	// Password, when set, is also required to unseal. On the tpm2 backend
	// it is the sealed object's TPM authorization value -- with a policy,
	// the policy's password branch, which unseals even after the PCRs
	// change -- and on other backends a software check.
	Password string `json:"password"`

	Backend     string `json:"backend"`      // "tpm2", "software", etc. Empty = default
	StorageType string `json:"storage_type"` // "disk" or "nvram". Empty = default ("disk")
}

// sealedBlobStorage is the internal on-disk representation.
type sealedBlobStorage struct {
	ID          string           `json:"id"`
	Label       string           `json:"label"`
	SizeBytes   int              `json:"size_bytes"`
	TPMPolicy   string           `json:"tpm_policy,omitempty"`
	HasPassword bool             `json:"has_password,omitempty"`
	Password    string           `json:"password,omitempty"` // argon2id hash; set for non-TPM backends only
	Local       bool             `json:"local,omitempty"`    // sealed through xKey's own backends, not a server
	Category    string           `json:"category,omitempty"`
	BackendID   string           `json:"backend_id,omitempty"`   // backend registry ID that sealed this blob
	StorageType string           `json:"storage_type,omitempty"` // "disk" or "nvram"
	NVIndex     uint32           `json:"nv_index,omitempty"`     // NV RAM base index (when StorageType = "nvram")
	SealedData  *xkms.SealedData `json:"sealed_data"`
	CreatedAt   time.Time        `json:"created_at"`
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
	tpmPolicies    *TPMPolicyService
	localClient    xkms.Client         // embedded local client (always available after init)
	clientFunc     func() xkms.Client  // remote server client provider
	defaultBackend string              // default backend name
	backend        xkms.StorageBackend // barrier-encrypted storage (nil = direct disk fallback)
	blobPrefix     string              // key prefix for backend storage (e.g. "sealed/")
	auditLog       atomic.Pointer[audit.Logger]

	// policy is the enterprise policy section whose UserCanManageSealedData
	// field gates SealData and DeleteBlob. nil in personal mode. See
	// SetPolicy.
	policy atomic.Pointer[config.PolicySection]
}

// NewSealService creates a new SealService that stores sealed blobs in storageDir.
func NewSealService(storageDir string) *SealService {
	return &SealService{
		log:            slog.Default().With("component", "seal_service"),
		storageDir:     storageDir,
		defaultBackend: string(xkms.BackendTypeTPM2),
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
	client, _, err := s.resolveClient()
	return client, err
}

// resolveClient returns the best available SDK client, as getClient does,
// and whether it is the embedded local client.
func (s *SealService) resolveClient() (xkms.Client, bool, error) {
	// Prefer remote server client when connected.
	if s.clientFunc != nil {
		if client := s.clientFunc(); client != nil {
			return client, false, nil
		}
	}
	// Fall back to embedded local client.
	if s.localClient != nil {
		return s.localClient, true, nil
	}
	return nil, false, ErrSealNoClient
}

// SetTPMAccessor sets the shared TPMAccessor used for serialized TPM access.
// The TPM accessor is kept for NV RAM operations but sealing operations
// are now routed through the SDK client.
func (s *SealService) SetTPMAccessor(a *TPMAccessor) {
	s.tpmAccessor = a
}

// SetTPMPolicyService sets the TPM policy service that records, in local
// mode, which named policy each local tpm2 blob is bound to.
func (s *SealService) SetTPMPolicyService(svc *TPMPolicyService) {
	s.tpmPolicies = svc
}

// SetBackend sets the storage backend used for blob persistence. When set,
// all blob I/O is routed through this backend (typically the barrier for
// transparent encryption). When nil, blobs are written directly to disk.
func (s *SealService) SetBackend(b xkms.StorageBackend, prefix string) {
	s.backend = b
	s.blobPrefix = prefix
}

// Backend returns the current storage backend, or nil if direct disk I/O is used.
func (s *SealService) Backend() xkms.StorageBackend {
	return s.backend
}

// SetAuditLogger sets the audit logger for security event logging.
func (s *SealService) SetAuditLogger(l audit.Logger) {
	s.auditLog.Store(&l)
}

// SetPolicy installs the enterprise policy section that gates SealData and
// DeleteBlob. The GUI calls this with config.DefaultPolicy() before SO
// login and the verified section afterward; see startupEnterprisePolicy and
// applyVerifiedEnterprisePolicy in pkg/gui/enterprise_policy.go.
func (s *SealService) SetPolicy(pol *config.PolicySection) {
	s.policy.Store(pol)
}

// requireManageSealedData returns a *PolicyDeniedError, and logs it, if
// enterprise policy's UserCanManageSealedData is false. The request is
// refused either way, but OpPolicyDenied is SeveritySecurity: if the audit
// write itself fails, that failure is joined onto the denial so the caller
// sees both.
func (s *SealService) requireManageSealedData(operation string) error {
	pol := s.policy.Load()
	if pol == nil || pol.UserCanManageSealedData {
		return nil
	}
	err := &PolicyDeniedError{Field: "user_can_manage_sealed_data"}
	if auditErr := s.logSealEvent(audit.OpPolicyDenied, false, err, map[string]any{"operation": operation}); auditErr != nil {
		return errors.Join(err, auditErr)
	}
	return err
}

// logSealEvent logs a seal-related audit event. Seal, unseal, and blob
// deletion are all SeveritySecurity, so the caller must propagate a
// non-nil return and fail the request rather than proceed unaudited.
func (s *SealService) logSealEvent(op audit.OperationType, success bool, err error, details map[string]any) error {
	p := s.auditLog.Load()
	if p == nil {
		return nil
	}
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	return (*p).Log(audit.Entry{
		Timestamp: time.Now(),
		Operation: op,
		Success:   success,
		Error:     errStr,
		Details:   details,
	})
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
// If backend is not a recognized seal-namespace backend ID (i.e. not in
// knownSealerMeta), auto-select the best available backend instead.
// This guards against callers passing raw barrier strategy names
// ("passphrase", "pkcs11") which do not exist as seal backends and would
// cause CanSeal to always return false.
func (s *SealService) SetDefaultBackend(backend string) {
	if _, ok := knownSealerMeta[backend]; !ok {
		s.autoSelectDefault()
		return
	}
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
		level xkms.SecurityLevel
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
			retErr = &MessageError{Msg: fmt.Sprintf("seal_service: panic in ListBlobs: %v", r)}
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
		entry, entryErr := blobToEntry(&blob)
		if entryErr != nil {
			s.log.Warn("skipping sealed blob record", "key", key, "error", entryErr)
			continue
		}
		items = append(items, blobWithTime{
			entry:     entry,
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
		entry, entryErr := blobToEntry(blob)
		if entryErr != nil {
			s.log.Warn("skipping sealed blob record", "file", de.Name(), "error", entryErr)
			continue
		}
		items = append(items, blobWithTime{
			entry:     entry,
			createdAt: blob.CreatedAt,
		})
	}

	return sortAndCollectEntries(items), nil
}

// blobToEntry converts an internal sealedBlobStorage to a frontend
// SealedBlobEntry. Returns ErrSealBlobBackendIDMissing if the record
// predates that field being required; such a record cannot be represented.
func blobToEntry(blob *sealedBlobStorage) (SealedBlobEntry, error) {
	if blob.BackendID == "" {
		return SealedBlobEntry{}, ErrSealBlobBackendIDMissing
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
		ID:                blob.ID,
		Label:             blob.Label,
		SizeBytes:         blob.SizeBytes,
		TPMPolicy:         blob.TPMPolicy,
		PasswordProtected: blob.HasPassword,
		CreatedAt:         blob.CreatedAt.Format(time.RFC3339),
		Category:          category,
		BackendID:         blob.BackendID,
		StorageType:       storageType,
	}, nil
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
//
// On the tpm2 backend the blob is sealed as a TPM object of its own, bound
// to req.TPMPolicy and, when set, to req.Password; a blob sealed locally
// under a named policy is recorded against it, so the policy cannot be
// deleted while the blob exists.
func (s *SealService) SealData(req *SealRequest) (entry *SealedBlobEntry, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in SealData", "recover", r)
			entry = nil
			retErr = &MessageError{Msg: fmt.Sprintf("seal_service: panic in SealData: %v", r)}
		}
	}()

	if err := s.requireManageSealedData("seal_data"); err != nil {
		return nil, err
	}

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
	isTPM := backend == string(xkms.BackendTypeTPM2)
	if req.TPMPolicy != "" && !isTPM {
		return nil, ErrSealPolicyRequiresTPM
	}

	// Generate a unique ID.
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, ErrSealStorageFailed
	}
	id := hex.EncodeToString(idBytes)

	client, local, err := s.resolveClient()
	if err != nil {
		return nil, ErrSealBackendNotFound
	}

	sdkReq := &transport.SealRequest{
		Backend:   backend,
		Data:      plaintext,
		TPMPolicy: req.TPMPolicy,
		// The GUI binding delivers the password as a string, which cannot be
		// wiped; the wire copy made here can be, and is.
		Password: []byte(req.Password),
	}
	defer sdkReq.Password.Wipe()
	objectName := ""
	if isTPM {
		objectName = sealedObjectPrefix + id
		sdkReq.KeyID = objectName
	}

	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	resp, err := client.Seal(ctx, sdkReq)
	if err != nil {
		s.log.Error("seal operation failed", "backend", backend, "error", err)
		// TPM-backed seal failures are also recorded under OpTPMSealFailed so
		// they surface in a TPM-scoped audit query, in addition to the
		// backend-agnostic OpSealData trail every strategy gets.
		if isTPM {
			if auditErr := s.logSealEvent(audit.OpTPMSealFailed, false, err, map[string]any{"label": req.Label}); auditErr != nil {
				return nil, auditErr
			}
		}
		if auditErr := s.logSealEvent(audit.OpSealData, false, err, map[string]any{"label": req.Label, "backend": backend}); auditErr != nil {
			return nil, auditErr
		}
		return nil, err
	}

	if local && isNamedTPMPolicy(req.TPMPolicy) && s.tpmPolicies != nil {
		if err := s.tpmPolicies.assignLocal(ctx, xkms.TPMObjectKindSealed, objectName, req.TPMPolicy); err != nil {
			// An object the registry does not know would keep its policy
			// from ever being deleted safely, so it does not survive.
			return nil, errors.Join(err, s.tpmPolicies.deleteLocalObject(ctx, objectName))
		}
	}

	// Map SDK response to SealedData for blob storage.
	sealed := &xkms.SealedData{
		Backend:    xkms.BackendType(resp.Backend),
		Ciphertext: resp.Ciphertext,
		Nonce:      resp.Nonce,
		Tag:        resp.Tag,
		TPMPublic:  resp.TPMPublic,
		TPMPrivate: resp.TPMPrivate,
		WrappedDEK: resp.WrappedDEK,
		KeyID:      resp.KeyID,
		Metadata:   resp.Metadata,
	}

	// Resolve storage type (default to "disk").
	storageType := req.StorageType
	if storageType == "" {
		storageType = string(StorageTypeDisk)
	}

	blob := &sealedBlobStorage{
		ID:          id,
		Label:       req.Label,
		SizeBytes:   len(plaintext),
		TPMPolicy:   req.TPMPolicy,
		HasPassword: req.Password != "",
		Local:       local,
		Category:    classifyCategory(req.Label),
		BackendID:   backend,
		StorageType: storageType,
		SealedData:  sealed,
		CreatedAt:   time.Now(),
	}

	// The TPM enforces a tpm2 blob's password itself; any other backend
	// gets a software check against an argon2id hash.
	if req.Password != "" && !isTPM {
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

	result, entryErr := blobToEntry(blob)
	if entryErr != nil {
		return nil, entryErr
	}
	if auditErr := s.logSealEvent(audit.OpSealData, true, nil, map[string]any{"label": req.Label, "backend": backend}); auditErr != nil {
		return nil, auditErr
	}
	return &result, nil
}

// isNamedTPMPolicy reports whether policy names a policy created with the
// TPM policy service, rather than none or the built-in platform policy.
func isNamedTPMPolicy(policy string) bool {
	return policy != "" && policy != xkms.TPMPolicyPlatform
}

// UnsealData unseals a previously sealed blob and returns the data as base64.
// The password parameter is required for a blob sealed with a password (on
// the tpm2 backend, a blob bound to a policy may instead unseal through it).
func (s *SealService) UnsealData(id string, password string) (result string, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in UnsealData", "recover", r)
			result = ""
			retErr = &MessageError{Msg: fmt.Sprintf("seal_service: panic in UnsealData: %v", r)}
		}
	}()

	if id == "" {
		return "", ErrSealBlobNotFound
	}
	if err := validateBlobID(id); err != nil {
		return "", err
	}

	s.mu.RLock()
	blob, err := s.loadBlobByID(id)
	s.mu.RUnlock()
	if err != nil {
		return "", err
	}

	// A non-TPM blob's password is checked here; the TPM checks a tpm2
	// blob's password, and with a policy a missing one means the policy
	// branch is tried instead.
	if blob.Password != "" {
		if password == "" {
			return "", ErrSealPasswordRequired
		}
		if !verifyPassword(password, blob.Password) {
			return "", ErrSealPolicyMismatch
		}
	}

	// Determine which backend sealed this data. Required: every blob written
	// by this version records its BackendID.
	if blob.BackendID == "" {
		return "", ErrSealBlobBackendIDMissing
	}
	backend := blob.BackendID

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
	if blob.BackendID == string(xkms.BackendTypeTPM2) {
		sdkReq.Password = []byte(password)
		defer sdkReq.Password.Wipe()
	}

	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	resp, err := client.Unseal(ctx, sdkReq)
	if err != nil {
		s.log.Error("unseal operation failed", "backend", backend, "blob_id", id, "error", err)
		// TPM-backed unseal failures are also recorded under
		// OpTPMUnsealFailed so they surface in a TPM-scoped audit query, in
		// addition to the backend-agnostic OpUnsealData trail every
		// strategy gets.
		if backend == "tpm2" {
			if auditErr := s.logSealEvent(audit.OpTPMUnsealFailed, false, err, map[string]any{"blob_id": id}); auditErr != nil {
				return "", auditErr
			}
		}
		if auditErr := s.logSealEvent(audit.OpUnsealData, false, err, map[string]any{"blob_id": id}); auditErr != nil {
			return "", auditErr
		}
		return "", err
	}

	if auditErr := s.logSealEvent(audit.OpUnsealData, true, nil, map[string]any{"blob_id": id}); auditErr != nil {
		return "", auditErr
	}
	return base64.StdEncoding.EncodeToString(resp.Plaintext), nil
}

// DeleteBlob removes a sealed blob from storage.
func (s *SealService) DeleteBlob(id string) error {
	if err := s.requireManageSealedData("delete_blob"); err != nil {
		return err
	}
	if id == "" {
		return ErrSealBlobNotFound
	}
	if err := validateBlobID(id); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	if err := s.deleteLocalObject(ctx, id); err != nil {
		if auditErr := s.logSealEvent(audit.OpSealBlobDeleted, false, err, map[string]any{"blob_id": id}); auditErr != nil {
			return auditErr
		}
		return err
	}

	if s.backend != nil {
		if err := s.backend.Delete(ctx, s.blobPrefix+id); err != nil {
			if auditErr := s.logSealEvent(audit.OpSealBlobDeleted, false, err, map[string]any{"blob_id": id}); auditErr != nil {
				return auditErr
			}
			return ErrSealBlobNotFound
		}
		return s.logSealEvent(audit.OpSealBlobDeleted, true, nil, map[string]any{"blob_id": id})
	}

	path := s.blobPath(id)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if auditErr := s.logSealEvent(audit.OpSealBlobDeleted, false, ErrSealBlobNotFound, map[string]any{"blob_id": id}); auditErr != nil {
			return auditErr
		}
		return ErrSealBlobNotFound
	}

	if err := os.Remove(path); err != nil {
		if auditErr := s.logSealEvent(audit.OpSealBlobDeleted, false, err, map[string]any{"blob_id": id}); auditErr != nil {
			return auditErr
		}
		return ErrSealStorageFailed
	}

	return s.logSealEvent(audit.OpSealBlobDeleted, true, nil, map[string]any{"blob_id": id})
}

// deleteLocalObject removes the TPM sealed object, and its policy
// assignment, of a blob sealed on xKey's own TPM. Other blobs have no local
// object, and a blob that does not exist is left to the caller's own
// not-found handling. The caller holds s.mu.
func (s *SealService) deleteLocalObject(ctx context.Context, id string) error {
	blob, err := s.loadBlobByID(id)
	if err != nil {
		return nil
	}
	if !blob.Local || blob.BackendID != string(xkms.BackendTypeTPM2) || s.tpmPolicies == nil {
		return nil
	}
	return s.tpmPolicies.deleteLocalObject(ctx, sealedObjectPrefix+blob.ID)
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
