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
	"encoding/base64"
	"errors"
	"log/slog"
)

// Auto-unseal service errors.
var (
	// ErrAutoUnsealTPMNotAvailable indicates the TPM is not present or cannot seal.
	ErrAutoUnsealTPMNotAvailable = errors.New("auto_unseal: TPM not available")

	// ErrAutoUnsealNotConfigured indicates auto-unseal has not been configured.
	ErrAutoUnsealNotConfigured = errors.New("auto_unseal: not configured")

	// ErrAutoUnsealSealFailed indicates the seal operation failed.
	ErrAutoUnsealSealFailed = errors.New("auto_unseal: failed to seal passphrase")

	// ErrAutoUnsealUnsealFailed indicates the unseal operation failed.
	ErrAutoUnsealUnsealFailed = errors.New("auto_unseal: failed to unseal passphrase")

	// ErrAutoUnsealInvalidPassphrase indicates the passphrase does not meet requirements.
	ErrAutoUnsealInvalidPassphrase = errors.New("auto_unseal: invalid passphrase")

	// ErrAutoUnsealMountFailed indicates the volume mount operation failed.
	ErrAutoUnsealMountFailed = errors.New("auto_unseal: failed to mount volume")

	// ErrAutoUnsealAlreadyMounted indicates the volume is already mounted.
	ErrAutoUnsealAlreadyMounted = errors.New("auto_unseal: volume already mounted")

	// ErrAutoUnsealConfigFuncNil indicates the config function has not been set.
	ErrAutoUnsealConfigFuncNil = errors.New("auto_unseal: config function not set")

	// ErrAutoUnsealConfigSaveFuncNil indicates the config save function has not been set.
	ErrAutoUnsealConfigSaveFuncNil = errors.New("auto_unseal: config save function not set")

	// ErrAutoUnsealResealFailed indicates the re-seal operation failed.
	ErrAutoUnsealResealFailed = errors.New("auto_unseal: failed to re-seal passphrase")
)

// autoUnsealMinPassphraseLength is the minimum passphrase length for auto-unseal.
const autoUnsealMinPassphraseLength = 8

// AutoUnsealStatus describes the current state of auto-unseal capability.
type AutoUnsealStatus struct {
	Available  bool   `json:"available"`
	Configured bool   `json:"configured"`
	BlobID     string `json:"blob_id"`
}

// AutoUnsealResult describes the outcome of an auto-unseal operation.
type AutoUnsealResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// AutoUnsealService orchestrates sealed auto-unseal for encrypted storage.
// It coordinates between the SealService (seal/unseal via backend registry)
// and StorageService (LUKS volume operations) to provide transparent startup
// unlocking.
type AutoUnsealService struct {
	ctx        context.Context
	log        *slog.Logger
	sealSvc    *SealService
	storageSvc *StorageService
	configFunc func() *GUIConfigData
	configSave func(*GUIConfigData) error
}

// NewAutoUnsealService creates a new AutoUnsealService.
func NewAutoUnsealService(sealSvc *SealService, storageSvc *StorageService) *AutoUnsealService {
	return &AutoUnsealService{
		log:        slog.Default().With("component", "auto_unseal"),
		sealSvc:    sealSvc,
		storageSvc: storageSvc,
	}
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *AutoUnsealService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetConfigFunc sets the function used to retrieve the current GUI configuration.
func (s *AutoUnsealService) SetConfigFunc(fn func() *GUIConfigData) {
	s.configFunc = fn
}

// SetConfigSaveFunc sets the function used to persist GUI configuration changes.
func (s *AutoUnsealService) SetConfigSaveFunc(fn func(*GUIConfigData) error) {
	s.configSave = fn
}

// GetStatus returns the current auto-unseal status.
func (s *AutoUnsealService) GetStatus() *AutoUnsealStatus {
	status := &AutoUnsealStatus{}

	// Check if the default sealer can seal.
	status.Available, _ = s.sealSvc.CanSeal()

	// Check if auto-unseal is configured via the config.
	if s.configFunc != nil {
		cfg := s.configFunc()
		if cfg != nil && cfg.AutoUnsealEnabled && cfg.AutoUnsealBlobID != "" {
			status.Configured = true
			status.BlobID = cfg.AutoUnsealBlobID
		}
	}

	return status
}

// Enable seals the passphrase with the specified backend and stores the
// configuration for automatic unseal on startup.
func (s *AutoUnsealService) Enable(passphrase string, pcrs []int, pcrBank string, policyType string, policyName string, backend string) (*AutoUnsealResult, error) {
	// Validate passphrase.
	if len(passphrase) < autoUnsealMinPassphraseLength {
		return nil, ErrAutoUnsealInvalidPassphrase
	}

	// Verify sealer can seal.
	canSeal, _ := s.sealSvc.CanSeal()
	if !canSeal {
		return nil, ErrAutoUnsealTPMNotAvailable
	}

	// Verify config functions are set.
	if s.configFunc == nil {
		return nil, ErrAutoUnsealConfigFuncNil
	}
	if s.configSave == nil {
		return nil, ErrAutoUnsealConfigSaveFuncNil
	}

	// Base64-encode the passphrase and seal it via the SealService.
	b64Passphrase := base64.StdEncoding.EncodeToString([]byte(passphrase))

	if pcrBank == "" {
		pcrBank = "sha256"
	}

	req := &SealRequest{
		Label:      "auto-unseal-passphrase",
		Data:       b64Passphrase,
		PCRs:       pcrs,
		PCRBank:    pcrBank,
		PolicyType: policyType,
		Backend:    backend,
	}

	entry, err := s.sealSvc.SealData(req)
	if err != nil {
		s.log.Error("failed to seal passphrase for auto-unseal", "error", err)
		return nil, ErrAutoUnsealSealFailed
	}

	// Update and save configuration.
	cfg := s.configFunc()
	updated := *cfg
	updated.AutoUnsealEnabled = true
	updated.AutoUnsealBlobID = entry.ID
	updated.AutoUnsealPCRs = pcrs
	updated.AutoUnsealPCRBank = pcrBank
	updated.AutoUnsealPolicyType = policyType
	updated.AutoUnsealPolicyName = policyName
	updated.AutoUnsealBackend = backend

	if err := s.configSave(&updated); err != nil {
		// Attempt cleanup: delete the sealed blob since config save failed.
		deleteErr := s.sealSvc.DeleteBlob(entry.ID)
		if deleteErr != nil {
			s.log.Error("failed to clean up sealed blob after config save error",
				"blob_id", entry.ID, "error", deleteErr)
		}
		return nil, err
	}

	s.log.Info("auto-unseal enabled", "blob_id", entry.ID)

	return &AutoUnsealResult{
		Success: true,
		Message: "auto-unseal enabled",
	}, nil
}

// Disable removes the auto-unseal configuration and deletes the sealed blob.
func (s *AutoUnsealService) Disable() error {
	if s.configFunc == nil {
		return ErrAutoUnsealConfigFuncNil
	}
	if s.configSave == nil {
		return ErrAutoUnsealConfigSaveFuncNil
	}

	cfg := s.configFunc()
	if cfg == nil || cfg.AutoUnsealBlobID == "" {
		return ErrAutoUnsealNotConfigured
	}

	blobID := cfg.AutoUnsealBlobID

	// Delete the sealed blob.
	if err := s.sealSvc.DeleteBlob(blobID); err != nil {
		s.log.Warn("failed to delete auto-unseal blob, clearing config anyway",
			"blob_id", blobID, "error", err)
	}

	// Clear config fields.
	updated := *cfg
	updated.AutoUnsealEnabled = false
	updated.AutoUnsealBlobID = ""
	updated.AutoUnsealPCRs = nil
	updated.AutoUnsealPCRBank = ""
	updated.AutoUnsealPolicyType = ""
	updated.AutoUnsealPolicyName = ""
	updated.AutoUnsealBackend = ""

	if err := s.configSave(&updated); err != nil {
		return err
	}

	s.log.Info("auto-unseal disabled", "blob_id", blobID)
	return nil
}

// TryAutoUnseal attempts to unseal the passphrase and unlock the volume.
// It returns a result indicating success or the reason for failure.
// This method does not return an error for expected conditions (not configured,
// already mounted) so the caller can use the result directly.
func (s *AutoUnsealService) TryAutoUnseal() *AutoUnsealResult {
	// Check if auto-unseal is configured.
	if s.configFunc == nil {
		return &AutoUnsealResult{
			Success: false,
			Message: ErrAutoUnsealNotConfigured.Error(),
		}
	}

	cfg := s.configFunc()
	if cfg == nil || !cfg.AutoUnsealEnabled || cfg.AutoUnsealBlobID == "" {
		return &AutoUnsealResult{
			Success: false,
			Message: ErrAutoUnsealNotConfigured.Error(),
		}
	}

	// Check if volume is already mounted.
	status, err := s.storageSvc.GetStatus()
	if err == nil && status != nil && status.IsMounted {
		return &AutoUnsealResult{
			Success: true,
			Message: ErrAutoUnsealAlreadyMounted.Error(),
		}
	}

	// Unseal the passphrase (auto-unseal blobs do not use password policy).
	b64Passphrase, err := s.sealSvc.UnsealData(cfg.AutoUnsealBlobID, "")
	if err != nil {
		s.log.Error("auto-unseal: failed to unseal passphrase",
			"blob_id", cfg.AutoUnsealBlobID, "error", err)
		return &AutoUnsealResult{
			Success: false,
			Message: ErrAutoUnsealUnsealFailed.Error(),
		}
	}

	// Decode the base64-encoded passphrase.
	passphraseBytes, err := base64.StdEncoding.DecodeString(b64Passphrase)
	if err != nil {
		s.log.Error("auto-unseal: failed to decode passphrase", "error", err)
		return &AutoUnsealResult{
			Success: false,
			Message: ErrAutoUnsealUnsealFailed.Error(),
		}
	}

	// Unlock the volume.
	if err := s.storageSvc.UnlockVolume(string(passphraseBytes)); err != nil {
		s.log.Error("auto-unseal: failed to unlock volume", "error", err)
		return &AutoUnsealResult{
			Success: false,
			Message: ErrAutoUnsealMountFailed.Error(),
		}
	}

	s.log.Info("auto-unseal: volume unlocked successfully")
	return &AutoUnsealResult{
		Success: true,
		Message: "volume unlocked via auto-unseal",
	}
}

// Reseal re-seals the auto-unseal passphrase with the current PCR
// values. This should be called during shutdown so the seal reflects
// the current boot measurements and remains valid for the next boot.
//
// The method creates the new sealed blob first and only deletes the
// old one after the config update succeeds, so a failure at any step
// leaves the previous seal intact.
func (s *AutoUnsealService) Reseal() error {
	if s.configFunc == nil {
		return ErrAutoUnsealConfigFuncNil
	}
	if s.configSave == nil {
		return ErrAutoUnsealConfigSaveFuncNil
	}

	cfg := s.configFunc()
	if cfg == nil || !cfg.AutoUnsealEnabled || cfg.AutoUnsealBlobID == "" {
		return ErrAutoUnsealNotConfigured
	}

	oldBlobID := cfg.AutoUnsealBlobID

	// Unseal the current passphrase.
	b64Passphrase, err := s.sealSvc.UnsealData(oldBlobID, "")
	if err != nil {
		s.log.Error("reseal: failed to unseal current passphrase",
			"blob_id", oldBlobID, "error", err)
		return errors.Join(ErrAutoUnsealResealFailed, err)
	}

	pcrBank := cfg.AutoUnsealPCRBank
	if pcrBank == "" {
		pcrBank = "sha256"
	}

	// Re-seal with current PCR values (creates a new blob).
	req := &SealRequest{
		Label:      "auto-unseal-passphrase",
		Data:       b64Passphrase,
		PCRs:       cfg.AutoUnsealPCRs,
		PCRBank:    pcrBank,
		PolicyType: cfg.AutoUnsealPolicyType,
		Backend:    cfg.AutoUnsealBackend,
	}
	entry, err := s.sealSvc.SealData(req)
	if err != nil {
		s.log.Error("reseal: failed to create new sealed blob", "error", err)
		return errors.Join(ErrAutoUnsealResealFailed, err)
	}

	// Update config to point to the new blob.
	updated := *cfg
	updated.AutoUnsealBlobID = entry.ID
	if err := s.configSave(&updated); err != nil {
		// Config save failed; delete the new blob to avoid orphans.
		if deleteErr := s.sealSvc.DeleteBlob(entry.ID); deleteErr != nil {
			s.log.Error("reseal: failed to clean up new blob after config save error",
				"blob_id", entry.ID, "error", deleteErr)
		}
		return err
	}

	// Config saved successfully; now safe to delete the old blob.
	if err := s.sealSvc.DeleteBlob(oldBlobID); err != nil {
		s.log.Warn("reseal: failed to delete old blob (orphaned)",
			"blob_id", oldBlobID, "error", err)
	}

	s.log.Info("reseal: auto-unseal blob refreshed",
		"old_id", oldBlobID, "new_id", entry.ID)
	return nil
}
