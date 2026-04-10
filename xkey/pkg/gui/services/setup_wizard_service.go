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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	filestorage "github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
)

// Valid setup operating modes.
var validSetupModes = map[string]struct{}{
	"standalone": {},
	"server":     {},
	"both":       {},
}

// pinCharset defines the character set used for random PIN generation.
// Includes uppercase, lowercase, digits, and special characters for
// maximum entropy per character in alignment with CTAP2 UTF-8 PIN support.
const pinCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"

// EnvironmentProbe describes the capabilities detected on the system.
type EnvironmentProbe struct {
	TPMAvailable      bool                  `json:"tpm_available"`
	TPMDeviceExists   bool                  `json:"tpm_device_exists"`
	TPMDevicePath     string                `json:"tpm_device_path"`
	TPMInitError      string                `json:"tpm_init_error,omitempty"`
	LUKSAvailable     bool                  `json:"luks_available"`
	ServerReachable   bool                  `json:"server_reachable"`
	ServerAddress     string                `json:"server_address"`
	Platform          string                `json:"platform"`
	SetupComplete     bool                  `json:"setup_complete"`
	StorageExists     bool                  `json:"storage_exists"`
	StorageMounted    bool                  `json:"storage_mounted"`
	BarrierStrategies []BarrierStrategyInfo `json:"barrier_strategies"`
	AvailableSealers  []SealerInfo          `json:"available_sealers"`
	AvailableBackends []BackendInfo         `json:"available_backends"`
}

// GeneratedPINs holds auto-generated PINs for quick setup.
type GeneratedPINs struct {
	SOPin   string `json:"so_pin"`
	UserPin string `json:"user_pin"`
}

// SetupChoices holds the user's selections from the setup wizard.
type SetupChoices struct {
	Mode               string `json:"mode"`
	ServerAddress      string `json:"server_address"`
	ServerProtocol     string `json:"server_protocol"`
	EnableStorage      bool   `json:"enable_storage"`
	StorageSizeGB      int    `json:"storage_size_gb"`
	StoragePass        string `json:"storage_passphrase"`
	EnableMasterPW     bool   `json:"enable_master_password"`
	MasterPassword     string `json:"master_password"`
	TPMSealPasswords   bool   `json:"tpm_seal_passwords"`
	PasswordStoreMode  string `json:"password_store_mode"` // "tpm_sealed", "aes_software", "none"
	SOPin              string `json:"so_pin"`              // SO PIN for TPM hierarchy (empty valid)
	UserPin            string `json:"user_pin"`            // Initial user PIN
	UseUserPinAsMaster bool   `json:"use_user_pin_as_master"`
	SetHierarchyAuth   bool   `json:"set_hierarchy_auth"` // Use SO PIN to set TPM hierarchy passwords
	EnableAutoUnseal   bool   `json:"enable_auto_unseal"`
	StorageType        string `json:"storage_type"`       // "luks" or "barrier"
	BarrierPassword    string `json:"barrier_password"`   // For barrier software strategy
	SealerBackend      string `json:"sealer_backend"`     // "tpm2", "software", "" (auto)
	QuickSetup         bool   `json:"quick_setup"`        // True when quick setup flow is used
	DeploymentMode     string `json:"deployment_mode"`    // "personal" or "enterprise"
	SavePinsToStore    bool   `json:"save_pins_to_store"` // Save PINs to password store (manual setup option)

	// Enterprise policy fields (used by ApplySOProvisioning).
	OrganizationName         string `json:"organization_name"`
	MinPinLength             int    `json:"min_pin_length"`
	PINMaxAttempts           int    `json:"pin_max_attempts"`
	RequireEncryptedStorage  bool   `json:"require_encrypted_storage"`
	RequireTPM               bool   `json:"require_tpm"`
	RequirePlatformPolicy    bool   `json:"require_platform_policy"`
	AllowAutoUnseal          bool   `json:"allow_auto_unseal"`
	AllowTheme               bool   `json:"allow_theme"`
	AllowTrustStore          bool   `json:"allow_trust_store"`
	AllowAuditLog            bool   `json:"allow_audit_log"`
	AllowSealedData          bool   `json:"allow_sealed_data"`
	AllowChangePIN           bool   `json:"allow_change_pin"`
	AllowAPIExplorer         bool   `json:"allow_api_explorer"`
	APIExplorerSandboxPolicy string `json:"api_explorer_sandbox_policy"`

	// FIDO2 enterprise policy fields.
	FIDO2RequireUserPresence bool `json:"fido2_require_user_presence"`
	FIDO2UserIntentCheck     bool `json:"fido2_user_intent_check"`

	// Browser extension enterprise policy fields.
	AllowExtension          bool `json:"allow_extension"`
	ForceExtensionAuth      bool `json:"force_extension_auth"`
	ForceExtensionPairing   bool `json:"force_extension_pairing"`
	ForceExtensionAudit     bool `json:"force_extension_audit"`
	AllowConfigureExtension bool `json:"allow_configure_extension"`
}

// SetupResult describes the outcome of applying wizard choices.
type SetupResult struct {
	Success       bool     `json:"success"`
	Errors        []string `json:"errors"`
	Warnings      []string `json:"warnings"`
	SetupComplete bool     `json:"setup_complete"`
}

// StartupState describes the application startup state for the frontend.
// It tells the frontend whether to show: setup wizard, user onboarding,
// auth login gate, or the main app.
type StartupState struct {
	SetupComplete        bool   `json:"setup_complete"`
	EnterpriseMode       bool   `json:"enterprise_mode"`
	EnterpriseWizardMode string `json:"enterprise_wizard_mode"` // "" | "so_provisioning" | "user_onboarding"
	SOPINSet             bool   `json:"so_pin_set"`
	UserPINSet           bool   `json:"user_pin_set"`
	PolicyVerified       bool   `json:"policy_verified"`
}

// UserOnboardingChoices holds the user's selections during enterprise user onboarding.
type UserOnboardingChoices struct {
	SOPIN           string `json:"so_pin"`
	UserPIN         string `json:"user_pin"`
	BarrierPassword string `json:"barrier_password"`
}

// SetupWizardService orchestrates the first-run setup wizard by delegating
// to existing services (StorageService, PasswordProtectionService, TPMService, etc.).
type SetupWizardService struct {
	ctx               context.Context
	storageSvc        *StorageService
	ppSvc             *PasswordProtectionService
	tpmSvc            *TPMService
	pinSvc            *PINService
	sealSvc           *SealService
	platformPolicySvc *PlatformPolicyService
	autoUnsealSvc     *AutoUnsealService
	barrierSvc        *BarrierService
	staticPwSvc       *StaticPasswordService
	adminSvc          *AdminService
	tpmStatusFn       TPMStatusFunc
	configFunc        func() *GUIConfigData
	configSave        func(*GUIConfigData) error
	eventEmitter      func(events.Event)
	initDataDirFunc   func() error
	postApplyFunc     func()
	configDir         string
}

// NewSetupWizardService creates a new SetupWizardService.
func NewSetupWizardService() *SetupWizardService {
	return &SetupWizardService{}
}

// generateRandomPIN generates a cryptographically random string of the
// specified length using crypto/rand, sampling uniformly from pinCharset.
// The generated PIN is guaranteed to contain at least one character from
// each class (uppercase, lowercase, digit, special) when length >= 4.
func generateRandomPIN(length int) (string, error) {
	if length <= 0 {
		return "", nil
	}

	charsetLen := big.NewInt(int64(len(pinCharset)))

	// Generate candidate until complexity requirements are met.
	// With a 90-char charset and lengths >= 8, failure probability per
	// attempt is negligible, so this rarely loops more than once.
	for attempts := 0; attempts < 100; attempts++ {
		b := make([]byte, length)
		for i := range b {
			idx, err := rand.Int(rand.Reader, charsetLen)
			if err != nil {
				return "", err
			}
			b[i] = pinCharset[idx.Int64()]
		}

		pin := string(b)

		// For PINs >= 4 chars, enforce all character classes are present.
		if length >= 4 && !pinMeetsComplexity(pin) {
			continue
		}

		return pin, nil
	}

	// Should never reach here with reasonable lengths.
	return "", ErrSetupPINGenerationFailed
}

// pinMeetsComplexity checks that the PIN contains at least one character
// from each class: uppercase, lowercase, digit, and special character.
func pinMeetsComplexity(pin string) bool {
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, c := range pin {
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}
	return hasUpper && hasLower && hasDigit && hasSpecial
}

// GenerateSetupPINs generates cryptographically random PINs for quick setup.
// SO PIN: 16 characters with full complexity (uppercase, lowercase, digits,
// special characters). User PIN: 12 characters with full complexity.
// Both PINs are guaranteed to contain at least one character from each class.
func (s *SetupWizardService) GenerateSetupPINs() (*GeneratedPINs, error) {
	soPin, err := generateRandomPIN(16)
	if err != nil {
		return nil, ErrSetupPINGenerationFailed
	}

	userPin, err := generateRandomPIN(12)
	if err != nil {
		return nil, ErrSetupPINGenerationFailed
	}

	return &GeneratedPINs{
		SOPin:   soPin,
		UserPin: userPin,
	}, nil
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *SetupWizardService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetStorageService sets the storage service dependency.
func (s *SetupWizardService) SetStorageService(svc *StorageService) {
	s.storageSvc = svc
}

// SetPasswordProtectionService sets the password protection service dependency.
func (s *SetupWizardService) SetPasswordProtectionService(svc *PasswordProtectionService) {
	s.ppSvc = svc
}

// SetTPMService sets the TPM service dependency.
func (s *SetupWizardService) SetTPMService(svc *TPMService) {
	s.tpmSvc = svc
}

// SetPINService sets the PIN service dependency.
func (s *SetupWizardService) SetPINService(svc *PINService) {
	s.pinSvc = svc
}

// SetSealService sets the seal service dependency.
func (s *SetupWizardService) SetSealService(svc *SealService) {
	s.sealSvc = svc
}

// SetPlatformPolicyService sets the platform policy service dependency.
func (s *SetupWizardService) SetPlatformPolicyService(svc *PlatformPolicyService) {
	s.platformPolicySvc = svc
}

// SetAutoUnsealService sets the auto-unseal service dependency.
func (s *SetupWizardService) SetAutoUnsealService(svc *AutoUnsealService) {
	s.autoUnsealSvc = svc
}

// SetBarrierService sets the barrier service dependency.
func (s *SetupWizardService) SetBarrierService(svc *BarrierService) {
	s.barrierSvc = svc
}

// SetStaticPasswordService sets the static password service for storing
// auto-generated PINs during quick setup.
func (s *SetupWizardService) SetStaticPasswordService(svc *StaticPasswordService) {
	s.staticPwSvc = svc
}

// SetAdminService sets the admin service used for backend discovery.
func (s *SetupWizardService) SetAdminService(svc *AdminService) {
	s.adminSvc = svc
}

// SetTPMStatusFunc sets the TPM status callback.
func (s *SetupWizardService) SetTPMStatusFunc(fn TPMStatusFunc) {
	s.tpmStatusFn = fn
}

// SetConfigFunc sets the callback that returns the current config.
func (s *SetupWizardService) SetConfigFunc(fn func() *GUIConfigData) {
	s.configFunc = fn
}

// SetConfigSaveFunc sets the callback that persists config changes.
func (s *SetupWizardService) SetConfigSaveFunc(fn func(*GUIConfigData) error) {
	s.configSave = fn
}

// SetEventEmitter sets the callback used to emit events to the frontend.
func (s *SetupWizardService) SetEventEmitter(fn func(events.Event)) {
	s.eventEmitter = fn
}

// SetInitDataDirFunc sets the callback that initializes the data directory
// after the LUKS/storage decision has been made. This must be called before
// ApplySetup or SkipSetup to ensure the data directory is created.
func (s *SetupWizardService) SetInitDataDirFunc(fn func() error) {
	s.initDataDirFunc = fn
}

// SetPostApplyFunc sets a callback that runs at the end of ApplySetup,
// after all steps including config save have completed. This allows the
// caller to perform post-setup tasks (e.g. barrier unseal, config reload).
func (s *SetupWizardService) SetPostApplyFunc(fn func()) {
	s.postApplyFunc = fn
}

// SetConfigDir sets the configuration directory path used for enterprise
// mode detection and policy HMAC file operations.
func (s *SetupWizardService) SetConfigDir(dir string) {
	s.configDir = dir
}

// IsSetupComplete returns whether the first-run setup has been completed.
func (s *SetupWizardService) IsSetupComplete() bool {
	if s.configFunc == nil {
		return true // Assume complete if no config function is set.
	}
	cfg := s.configFunc()
	if cfg == nil {
		return true
	}
	return cfg.SetupComplete
}

// ProbeEnvironment checks the system for available capabilities.
func (s *SetupWizardService) ProbeEnvironment() (*EnvironmentProbe, error) {
	probe := &EnvironmentProbe{
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
	}

	// Check TPM availability via the status callback.
	if s.tpmStatusFn != nil {
		deviceExists, available, _ := s.tpmStatusFn()
		probe.TPMAvailable = available
		probe.TPMDeviceExists = deviceExists
	}

	// Enrich with detailed TPM status from the TPMService when available.
	if s.tpmSvc != nil {
		probe.TPMDevicePath = s.tpmSvc.DevicePath()
		if status, err := s.tpmSvc.GetStatus(); err == nil && status != nil {
			probe.TPMDeviceExists = status.DeviceExists
			probe.TPMAvailable = status.Available
			if status.InitError != "" {
				probe.TPMInitError = status.InitError
			}
		}
	}

	// Populate available backends from the admin service when wired.
	if s.adminSvc != nil {
		if backends, err := s.adminSvc.ListBackends(); err == nil {
			probe.AvailableBackends = backends
		}
	}

	// Check LUKS tools availability.
	if _, err := exec.LookPath("cryptsetup"); err == nil {
		probe.LUKSAvailable = true
	}

	// Check storage status.
	if s.storageSvc != nil {
		status, err := s.storageSvc.GetStatus()
		if err == nil && status != nil {
			probe.StorageExists = status.VolumeExists
			probe.StorageMounted = status.IsMounted
		}
	}

	// Probe barrier strategies.
	if s.barrierSvc != nil {
		probe.BarrierStrategies = s.barrierSvc.ProbeStrategies()
	}

	// Probe available sealers.
	if s.sealSvc != nil {
		probe.AvailableSealers = s.sealSvc.AvailableSealers()
	}

	// Check setup complete status.
	if s.configFunc != nil {
		cfg := s.configFunc()
		if cfg != nil {
			probe.SetupComplete = cfg.SetupComplete
			probe.ServerAddress = cfg.ServerAddress
		}
	}

	return probe, nil
}

// setupTotalSteps is the number of progress steps emitted during ApplySetup.
const setupTotalSteps = 10

// emitProgress sends a setup:progress event to the frontend if an emitter is set.
func (s *SetupWizardService) emitProgress(step int, label string) {
	if s.eventEmitter != nil {
		s.eventEmitter(events.NewEvent(events.EventSetupProgress, events.SetupProgressPayload{
			Step:      step,
			TotalStep: setupTotalSteps,
			Label:     label,
		}))
	}
}

// ApplySetup applies the user's wizard choices by delegating to the
// appropriate services and persisting the configuration.
func (s *SetupWizardService) ApplySetup(choices *SetupChoices) (*SetupResult, error) {
	if s.configFunc == nil || s.configSave == nil {
		return nil, ErrSetupStorageFailed
	}

	cfg := s.configFunc()
	if cfg == nil {
		return nil, ErrSetupStorageFailed
	}

	if cfg.SetupComplete {
		return nil, ErrSetupAlreadyComplete
	}

	if _, ok := validSetupModes[choices.Mode]; !ok {
		return nil, ErrSetupInvalidMode
	}

	// Require both SO PIN and User PIN.
	if choices.SOPin == "" {
		return nil, ErrSetupSOPINRequired
	}
	if choices.UserPin == "" {
		return nil, ErrSetupUserPINRequired
	}

	result := &SetupResult{
		Success:  true,
		Errors:   make([]string, 0),
		Warnings: make([]string, 0),
	}

	// Track TPM-specific outcomes for the event payload.
	platformPolicyCreated := false
	tpmSealedPasswords := false

	// Step 1: Apply LUKS encrypted storage (only for LUKS storage type).
	s.emitProgress(1, "Creating encrypted storage")
	if choices.StorageType == "luks" && choices.EnableStorage {
		if s.storageSvc == nil {
			result.Warnings = append(result.Warnings, "storage service unavailable")
		} else {
			params := CreateVolumeParams{
				SizeGB:     choices.StorageSizeGB,
				Passphrase: choices.StoragePass,
			}
			if err := s.storageSvc.CreateVolume(params); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("storage creation failed: %v", err))
				result.Success = false
			}
		}
	}

	// Step 2: Configure PINs.
	s.emitProgress(2, "Configuring PINs")
	userPINSet := false
	soPINSet := false
	if choices.SOPin != "" && s.pinSvc != nil {
		if err := s.pinSvc.SetSOPIN("", choices.SOPin); err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("SO PIN setup: %v", err))
		} else {
			soPINSet = true
		}
	}
	if choices.UserPin != "" && choices.SOPin != "" && s.pinSvc != nil {
		if err := s.pinSvc.SetUserPIN(choices.SOPin, choices.UserPin); err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("User PIN setup: %v", err))
		} else {
			userPINSet = true
		}
	}

	// Step 3: Provision TPM keys (EK, Shared SRK, IAK, IDevID).
	s.emitProgress(3, "Provisioning TPM keys")
	if s.tpmSvc != nil {
		soPIN := ""
		if choices.SetHierarchyAuth {
			soPIN = choices.SOPin
		}
		if err := s.tpmSvc.Install(soPIN); err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("TPM provisioning: %v", err))
		}
	}

	// Step 4: Initialize Platform Key Store (creates Platform SRK).
	s.emitProgress(4, "Initializing platform key store")
	if s.tpmSvc != nil {
		if choices.UserPin != "" {
			// Always create the SRK with the user PIN as its auth value
			// when a PIN is provided, regardless of hierarchy auth settings.
			// The soPIN controls TPM hierarchy passwords (set during Install
			// at step 3), while userPIN sets the SRK's auth value for PIN
			// verification.
			soPIN := ""
			if choices.SetHierarchyAuth {
				soPIN = choices.SOPin
			}
			if err := s.tpmSvc.InitializePlatformKeyStore(
				soPIN, choices.UserPin); err != nil {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("Platform key store init: %v", err))
			}
		} else {
			if err := s.tpmSvc.InitializePlatformKeyStoreWithDefaults(); err != nil {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("Platform key store init: %v", err))
			}
		}
	}

	// Step 5: Apply platform policy.
	s.emitProgress(5, "Creating platform policy")
	if s.platformPolicySvc != nil {
		defaultPCRs := []int{0, 7, 9}
		defaultBank := "sha256"
		if _, err := s.platformPolicySvc.CreatePolicy(defaultPCRs, defaultBank); err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("platform policy creation failed: %v", err))
		} else {
			platformPolicyCreated = true
		}
	} else {
		result.Warnings = append(result.Warnings, "platform policy service unavailable")
	}

	// Auto-fill sealer backend from best available when not explicitly chosen.
	// Must resolve BEFORE barrier init because the barrier strategy depends on it.
	if choices.SealerBackend == "" && s.sealSvc != nil {
		if best := s.sealSvc.BestSealer(); best != nil {
			choices.SealerBackend = best.ID
		}
	}
	// Last-resort fallback: if no sealers are available, default to software.
	if choices.SealerBackend == "" {
		choices.SealerBackend = "software"
	}

	// Step 6: Initialize built-in encryption (barrier).
	// Barrier ALWAYS wraps the base backend (filesystem or LUKS).
	// When LUKS is selected, the barrier encrypts on top of LUKS.
	// NOTE: This step must run AFTER TPM provisioning (steps 3-4) because
	// the TPM2 sealing strategy requires a provisioned SRK.
	s.emitProgress(6, "Initializing built-in encryption")
	barrierInitialized := false
	barrierStrategy := ""
	barrierAutoUnsealBlobID := ""
	if s.barrierSvc == nil {
		result.Warnings = append(result.Warnings, "barrier service unavailable")
	} else {
		// When LUKS is the storage type and the volume was created/unlocked
		// in Step 1, point the barrier at the LUKS mount point so barrier
		// data is physically encrypted by LUKS. At wizard time the volume
		// is already mounted, so plain filestorage on the mount point works.
		// Runtime LUKS lifecycle (unlock/lock) is handled by app.go.
		if choices.StorageType == "luks" && choices.EnableStorage {
			if s.storageSvc != nil {
				status, sErr := s.storageSvc.GetStatus()
				if sErr == nil && status.IsMounted {
					mountPoint := status.MountPoint
					s.barrierSvc.SetBaseBackendFactory(func(_ string) (storage.Backend, error) {
						return filestorage.New(mountPoint)
					})
				}
			}
		}

		// Determine the barrier password. The lock screen always sends the
		// User PIN, so the barrier must be unlockable with the User PIN.
		// When a separate master password is set, prefer it. Otherwise,
		// ALWAYS fall back to the User PIN so the unlock screen works.
		barrierPW := choices.BarrierPassword
		if barrierPW == "" || choices.UseUserPinAsMaster {
			barrierPW = choices.UserPin
		}
		slog.Info("wizard: barrier init attempt",
			"storage_type", choices.StorageType,
			"use_user_pin_as_master", choices.UseUserPinAsMaster,
			"has_barrier_pw", barrierPW != "",
			"has_user_pin", choices.UserPin != "")
		barrierInitialized, barrierStrategy = s.initBarrier(
			barrierPW, choices.SealerBackend, result)
	}

	// Apply sealer backend selection before any seal operations.
	if choices.SealerBackend != "" && s.sealSvc != nil {
		s.sealSvc.SetDefaultBackend(choices.SealerBackend)
	}

	// Step 7: Initialize data directory.
	// NOTE: Must run AFTER barrier init (step 6) so that the static password
	// store can use the barrier as its encrypted backend.
	// This also creates the PINManager and starts the FIDO2 device via
	// postDataDirStartup(). PINs set at step 2 may have failed because
	// the PINManager did not exist yet; retry here.
	s.emitProgress(7, "Initializing data directory")
	dataDirReady := true
	if s.initDataDirFunc != nil {
		if err := s.initDataDirFunc(); err != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("data directory initialization failed: %v", err))
			result.Success = false
			dataDirReady = false
		}
	}

	// Retry PIN setup now that PINManager exists (created in postDataDirStartup).
	// Step 2 may have failed because the PINManager wasn't initialized yet.
	// The PIN backend always needs SO PIN configured for user PIN authorization,
	// regardless of SetHierarchyAuth (which only controls TPM hierarchy passwords
	// during provisioning at step 3).
	if dataDirReady && s.pinSvc != nil {
		if choices.SOPin != "" && !soPINSet {
			if err := s.pinSvc.SetSOPIN("", choices.SOPin); err != nil {
				// SetSOPIN may fail when the TPM2 backend auto-detected a
				// pre-provisioned TPM (soPINSet=true from IsProvisioned).
				// Try ChangeSOPIN from empty hierarchy auth — this handles
				// the case where SetHierarchyAuth was false and the TPM was
				// provisioned without hierarchy auth.
				if chErr := s.pinSvc.ChangeSOPIN("", choices.SOPin); chErr != nil {
					// ChangeSOPIN also failed. The hierarchy auth may already
					// match choices.SOPin (SetHierarchyAuth was true during
					// provisioning). Verify it directly.
					if vErr := s.pinSvc.VerifySOPIN(choices.SOPin); vErr != nil {
						slog.Warn("wizard: deferred SO PIN setup failed",
							"set_error", err, "change_error", chErr, "verify_error", vErr)
						result.Warnings = append(result.Warnings,
							fmt.Sprintf("deferred SO PIN setup: %v", err))
					} else {
						soPINSet = true
						slog.Info("wizard: SO PIN verified (already set from provisioning)")
					}
				} else {
					soPINSet = true
					slog.Info("wizard: SO PIN synced to backend (changed from default)")
				}
			} else {
				soPINSet = true
				slog.Info("wizard: deferred SO PIN setup succeeded")
			}
		}
		if choices.UserPin != "" && choices.SOPin != "" && !userPINSet {
			if err := s.pinSvc.SetUserPIN(choices.SOPin, choices.UserPin); err != nil {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("deferred User PIN setup: %v", err))
			} else {
				userPINSet = true
				slog.Info("wizard: deferred User PIN setup succeeded")

				// Verify the PIN immediately to catch hash/storage inconsistencies.
				// This prevents the "invalid PIN" error on the lock screen after setup.
				if vErr := s.pinSvc.VerifyUserPIN(choices.UserPin); vErr != nil {
					slog.Error("wizard: User PIN verification failed immediately after set",
						"error", vErr)
					result.Warnings = append(result.Warnings,
						fmt.Sprintf("User PIN verification failed after set: %v", vErr))
				} else {
					slog.Info("wizard: User PIN verified after set")
				}
			}
		}
	}

	// Step 8: Configure password protection.
	// In quick-setup personal mode, save auto-generated PINs to the
	// password store so the user can retrieve them after the app locks.
	s.emitProgress(8, "Configuring password protection")
	savePins := (choices.QuickSetup && choices.DeploymentMode == "personal") || choices.SavePinsToStore
	if dataDirReady && savePins && s.staticPwSvc != nil {
		if choices.SOPin != "" {
			if _, err := s.staticPwSvc.AddPasswordV2(AddPasswordParams{
				Name:       "SO PIN",
				Password:   choices.SOPin,
				Notes:      "Security Officer PIN — auto-generated during setup. Required to change the User PIN.",
				FolderPath: "xKey",
			}); err != nil {
				slog.Warn("wizard: failed to save SO PIN to password store", "error", err)
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("failed to save SO PIN to password store: %v", err))
			}
		}
		if choices.UserPin != "" {
			if _, err := s.staticPwSvc.AddPasswordV2(AddPasswordParams{
				Name:       "User PIN",
				Password:   choices.UserPin,
				Notes:      "User PIN — auto-generated during setup. Used to unlock the app.",
				FolderPath: "xKey",
			}); err != nil {
				slog.Warn("wizard: failed to save User PIN to password store", "error", err)
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("failed to save User PIN to password store: %v", err))
			}
		}
	}

	// Step 9: Configure auto-unseal.
	s.emitProgress(9, "Configuring auto-unseal")
	if choices.EnableAutoUnseal {
		if choices.StorageType == "luks" && choices.EnableStorage && choices.StoragePass != "" {
			// LUKS auto-unseal (existing logic).
			if s.autoUnsealSvc != nil {
				policyType := string(PolicyTypeNone)
				policyName := ""
				if platformPolicyCreated {
					policyType = string(PolicyTypePlatformPolicy)
					policyName = "Platform Policy"
				}
				if _, err := s.autoUnsealSvc.Enable(
					choices.StoragePass,
					[]int{0, 7, 9},
					"sha256",
					policyType,
					policyName,
					string(types.BackendTypeTPM2),
				); err != nil {
					result.Warnings = append(result.Warnings,
						fmt.Sprintf("auto-unseal setup: %v", err))
				}
			} else {
				result.Warnings = append(result.Warnings, "auto-unseal service unavailable")
			}
		}
		// Barrier auto-unseal: when using software strategy, seal the
		// barrier password to TPM so the barrier can auto-unseal on restart.
		// TPM2 strategy auto-unseals inherently (no password needed).
		if barrierInitialized && barrierStrategy == "software" {
			barrierPW := choices.BarrierPassword
			if choices.UseUserPinAsMaster && choices.UserPin != "" {
				barrierPW = choices.UserPin
			}
			canSeal, _ := s.sealSvc.CanSeal()
			if barrierPW != "" && s.sealSvc != nil && canSeal {
				policyType := string(PolicyTypeNone)
				if platformPolicyCreated {
					policyType = string(PolicyTypePlatformPolicy)
				}
				req := &SealRequest{
					Label:      "barrier_password",
					Data:       base64.StdEncoding.EncodeToString([]byte(barrierPW)),
					PolicyType: policyType,
				}
				if entry, err := s.sealSvc.SealData(req); err != nil {
					result.Warnings = append(result.Warnings,
						fmt.Sprintf("barrier auto-unseal: %v (manual unlock on restart)", err))
				} else {
					barrierAutoUnsealBlobID = entry.ID
				}
			}
		}
	}

	// Step 10: Save configuration.
	s.emitProgress(10, "Saving configuration")
	updated := *cfg
	if choices.Mode == "server" || choices.Mode == "both" {
		updated.ServerAddress = choices.ServerAddress
		if choices.ServerProtocol != "" {
			updated.ServerProtocol = choices.ServerProtocol
		}
		updated.ServerAutoConnect = true
	}

	updated.SetupComplete = true
	// Always save storage_type as "barrier". Data must never be stored in
	// plain text. If barrier initialization failed during the wizard, the
	// app startup repair logic will detect the missing root key and
	// initialize the barrier on the first unlock.
	updated.StorageType = "barrier"
	updated.SealerBackend = choices.SealerBackend
	// Always persist the intended barrier strategy so that deferred
	// initialization (on next startup) uses the user's chosen strategy
	// (e.g., tpm2) rather than defaulting to software.
	if barrierInitialized {
		updated.BarrierInitialized = true
		updated.BarrierStrategy = barrierStrategy
		updated.BarrierAutoUnsealEnabled = (barrierStrategy == "tpm2")
		if barrierAutoUnsealBlobID != "" {
			updated.BarrierAutoUnsealBlobID = barrierAutoUnsealBlobID
		}
	} else {
		// Barrier init failed — save the intended strategy for deferred init.
		updated.BarrierStrategy = choices.SealerBackend
	}
	if err := s.configSave(&updated); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("config save failed: %v", err))
		result.Success = false
	}
	result.SetupComplete = true

	// Emit setup completed event.
	if s.eventEmitter != nil {
		s.eventEmitter(events.NewEvent(events.EventSetupCompleted, events.SetupCompletedPayload{
			Mode:                  choices.Mode,
			StorageCreated:        choices.EnableStorage && result.Success,
			MasterPWSet:           choices.EnableMasterPW && choices.MasterPassword != "" && result.Success,
			PlatformPolicyCreated: platformPolicyCreated && result.Success,
			TPMSealedPasswords:    tpmSealedPasswords && result.Success,
			UserPINSet:            userPINSet,
			SOPINSet:              soPINSet,
			BarrierInitialized:    barrierInitialized,
			BarrierStrategy:       barrierStrategy,
		}))
	}

	// Post-apply hook: runs after all steps so that the caller can
	// perform post-setup tasks (e.g. barrier unseal, config reload).
	if s.postApplyFunc != nil {
		s.postApplyFunc()
	}

	return result, nil
}

// initBarrier attempts to initialize the barrier with the given strategy,
// handling the case where the barrier already exists (re-run).
//
// If initialization fails, the error is surfaced to the user so they can
// go back and select a different strategy. No automatic fallback is
// performed.
//
// Returns (initialized bool, strategy string).
func (s *SetupWizardService) initBarrier(
	password, strategyID string, result *SetupResult,
) (bool, string) {

	if err := s.barrierSvc.Initialize(password, strategyID); err == nil {
		return true, strategyID
	} else if errors.Is(err, ErrBarrierAlreadyInit) {
		// Barrier was initialized in a prior run. Unseal instead.
		slog.Info("wizard: barrier already initialized, unsealing existing barrier",
			"strategy", strategyID)
		if unsealErr := s.barrierSvc.Unseal(password, strategyID); unsealErr != nil {
			slog.Error("wizard: barrier unseal failed", "error", unsealErr)
			result.Errors = append(result.Errors,
				fmt.Sprintf("barrier unseal failed: %v", unsealErr))
			result.Success = false
			return false, ""
		}
		return true, strategyID
	} else {
		slog.Error("wizard: barrier initialization failed",
			"strategy", strategyID, "error", err)
		result.Errors = append(result.Errors,
			fmt.Sprintf("barrier %s initialization failed: %v", strategyID, err))
		result.Success = false
		return false, ""
	}
}

// SkipSetup marks the setup wizard as complete without making any changes.
func (s *SetupWizardService) SkipSetup() error {
	if s.configFunc == nil || s.configSave == nil {
		return ErrSetupStorageFailed
	}

	cfg := s.configFunc()
	if cfg == nil {
		return ErrSetupStorageFailed
	}

	// Initialize data directory (plain directory, no LUKS).
	if s.initDataDirFunc != nil {
		if err := s.initDataDirFunc(); err != nil {
			return fmt.Errorf("%w: %v", ErrSetupStorageFailed, err)
		}
	}

	updated := *cfg
	updated.SetupComplete = true
	// Always default to barrier so data is never stored in plain text.
	// The barrier will be initialized on the first unlock.
	if updated.StorageType == "" {
		updated.StorageType = "barrier"
	}
	if err := s.configSave(&updated); err != nil {
		return fmt.Errorf("%w: %v", ErrSetupStorageFailed, err)
	}

	// Emit setup skipped event.
	if s.eventEmitter != nil {
		s.eventEmitter(events.NewEvent(events.EventSetupSkipped, events.SetupSkippedPayload{
			Reason: "user skipped setup wizard",
		}))
	}

	return nil
}

// soProvisioningTotalSteps is the number of progress steps emitted during
// SO provisioning.
const soProvisioningTotalSteps = 7

// emitSOProvisioningProgress sends a setup:progress event scoped to SO
// provisioning.
func (s *SetupWizardService) emitSOProvisioningProgress(step int, label string) {
	if s.eventEmitter != nil {
		s.eventEmitter(events.NewEvent(events.EventSetupProgress, events.SetupProgressPayload{
			Step:      step,
			TotalStep: soProvisioningTotalSteps,
			Label:     label,
		}))
	}
}

// userOnboardingTotalSteps is the number of progress steps emitted during
// user onboarding.
const userOnboardingTotalSteps = 4

// emitUserOnboardingProgress sends a setup:progress event scoped to user
// onboarding.
func (s *SetupWizardService) emitUserOnboardingProgress(step int, label string) {
	if s.eventEmitter != nil {
		s.eventEmitter(events.NewEvent(events.EventSetupProgress, events.SetupProgressPayload{
			Step:      step,
			TotalStep: userOnboardingTotalSteps,
			Label:     label,
		}))
	}
}

// GetStartupState determines what the frontend should show at application
// startup. It inspects setup completion status, enterprise mode, PIN state,
// and HMAC file presence to produce a StartupState that the frontend uses
// to route to the correct initial view.
func (s *SetupWizardService) GetStartupState() (result *StartupState, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic in GetStartupState", "recover", r)
			result = nil
			retErr = fmt.Errorf("setup_wizard: panic in GetStartupState: %v", r)
		}
	}()

	state := &StartupState{}

	// Check setup completion via the GUI config bridge.
	if s.configFunc != nil {
		cfg := s.configFunc()
		if cfg != nil {
			state.SetupComplete = cfg.SetupComplete
		}
	}

	// Check enterprise mode via HMAC file existence.
	state.EnterpriseMode = config.IsEnterpriseMode(s.configDir)

	// Check PIN status.
	if s.pinSvc != nil {
		pinStatus, err := s.pinSvc.GetPINStatus()
		if err == nil && pinStatus != nil {
			state.SOPINSet = pinStatus.SOPINSet
			state.UserPINSet = pinStatus.UserPINSet
		}
	}

	// Determine enterprise wizard mode.
	if !state.SetupComplete && state.EnterpriseMode {
		// HMAC file exists but setup is not complete: user onboarding needed.
		if !state.UserPINSet {
			state.EnterpriseWizardMode = "user_onboarding"
		}
	} else if !state.SetupComplete && !state.EnterpriseMode {
		// No HMAC file and setup not complete: SO provisioning needed.
		// Only set this when the configDir is configured so we do not
		// misleadingly advertise enterprise mode for standalone setups.
		if s.configDir != "" {
			state.EnterpriseWizardMode = "so_provisioning"
		}
	}

	return state, nil
}

// ApplySOProvisioning performs the Security Officer provisioning phase of the
// enterprise setup workflow. It configures the SO PIN, initializes barrier
// storage, provisions TPM keys (when available), writes the security policy,
// and computes the policy HMAC. Setup is intentionally left incomplete so
// that user onboarding can finalize it.
func (s *SetupWizardService) ApplySOProvisioning(choices *SetupChoices) (result *SetupResult, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic in ApplySOProvisioning", "recover", r)
			result = nil
			retErr = fmt.Errorf("setup_wizard: panic in ApplySOProvisioning: %v", r)
		}
	}()

	// Validate preconditions.
	if choices.SOPin == "" {
		return nil, ErrSetupSOPINRequired
	}
	if _, ok := validSetupModes[choices.Mode]; !ok {
		return nil, ErrSetupInvalidDeploymentMode
	}

	result = &SetupResult{
		Success:  true,
		Errors:   make([]string, 0),
		Warnings: make([]string, 0),
	}

	// Step 1: Configure SO PIN.
	s.emitSOProvisioningProgress(1, "Configuring SO PIN")
	if s.pinSvc != nil {
		if err := s.pinSvc.SetSOPIN("", choices.SOPin); err != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("SO PIN setup failed: %v", err))
			result.Success = false
		}
	} else {
		result.Errors = append(result.Errors, "PIN service unavailable")
		result.Success = false
	}

	// Step 2: Provision TPM keys (when available).
	s.emitSOProvisioningProgress(2, "Provisioning TPM keys")
	if s.tpmSvc != nil {
		soPIN := choices.SOPin
		if err := s.tpmSvc.Install(soPIN); err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("TPM provisioning: %v", err))
		}
	}

	// Step 3: Initialize Platform Key Store (when TPM available).
	s.emitSOProvisioningProgress(3, "Initializing platform key store")
	if s.tpmSvc != nil {
		if err := s.tpmSvc.InitializePlatformKeyStore(choices.SOPin, ""); err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("Platform key store init: %v", err))
		}
	}

	// Step 4: Initialize barrier storage.
	// NOTE: This step must run AFTER TPM provisioning (steps 2-3) because the
	// TPM2 sealing strategy requires a provisioned SRK to seal the root key.
	s.emitSOProvisioningProgress(4, "Initializing built-in encryption")
	if s.barrierSvc != nil {
		barrierPW := choices.BarrierPassword
		s.initBarrier(barrierPW, choices.SealerBackend, result)
	} else {
		result.Warnings = append(result.Warnings, "barrier service unavailable")
	}

	// Step 5: Initialize data directory.
	s.emitSOProvisioningProgress(5, "Initializing data directory")
	if s.initDataDirFunc != nil {
		if err := s.initDataDirFunc(); err != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("data directory initialization failed: %v", err))
			result.Success = false
		}
	}

	// Step 6: Write security policy to unified config.
	s.emitSOProvisioningProgress(6, "Writing security policy")
	policy := config.DefaultPolicy()

	// Core security requirements — PlatformSRK is always created.
	policy.RequirePlatformPolicy = true
	policy.PlatformPCRs = []int{0, 7, 9}
	policy.PlatformPCRBank = "sha256"
	if choices.StorageType != "" {
		policy.StorageType = choices.StorageType
	}
	if choices.PasswordStoreMode != "" {
		policy.PasswordProtectionMode = choices.PasswordStoreMode
		policy.RequirePasswordProtection = choices.PasswordStoreMode != "none"
	}

	// Enterprise policy fields from SO wizard. Only override the
	// DefaultPolicy() boolean values when the SO explicitly configures
	// an enterprise policy (indicated by a non-empty OrganizationName).
	if choices.MinPinLength > 0 {
		policy.MinPINLength = choices.MinPinLength
	}
	if choices.PINMaxAttempts > 0 {
		policy.PINMaxAttempts = choices.PINMaxAttempts
	}
	if choices.OrganizationName != "" {
		policy.OrganizationName = choices.OrganizationName
		policy.RequireEncryptedStorage = choices.RequireEncryptedStorage
		policy.RequireTPM = choices.RequireTPM
		policy.AllowAutoUnseal = choices.AllowAutoUnseal
		policy.UserCanConfigureTheme = choices.AllowTheme
		policy.UserCanManageTrustStore = choices.AllowTrustStore
		policy.UserCanViewAuditLog = choices.AllowAuditLog
		policy.UserCanManageSealedData = choices.AllowSealedData
		policy.UserCanChangeOwnPIN = choices.AllowChangePIN
		policy.APIExplorerEnabled = choices.AllowAPIExplorer
		if choices.APIExplorerSandboxPolicy != "" {
			policy.APIExplorerSandboxPolicy = choices.APIExplorerSandboxPolicy
		}
		policy.FIDO2RequireUserPresence = choices.FIDO2RequireUserPresence
		policy.FIDO2UserIntentCheck = choices.FIDO2UserIntentCheck
		policy.ExtensionEnabled = choices.AllowExtension
		policy.ExtensionRequireAuthentication = choices.ForceExtensionAuth
		policy.ExtensionRequirePairing = choices.ForceExtensionPairing
		policy.ExtensionForceAudit = choices.ForceExtensionAudit
		policy.UserCanConfigureExtension = choices.AllowConfigureExtension
	}

	// Load the unified config, set the policy section, and save.
	cfg, loadErr := config.Load()
	if loadErr != nil {
		result.Errors = append(result.Errors,
			fmt.Sprintf("config load failed: %v", loadErr))
		result.Success = false
	} else {
		cfg.Policy = *policy
		if saveErr := config.Save(cfg); saveErr != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("config save failed: %v", saveErr))
			result.Success = false
		}
	}

	// Step 7: Compute and write the policy HMAC.
	s.emitSOProvisioningProgress(7, "Computing policy integrity HMAC")
	hmacPath := config.PolicyHMACPath(s.configDir)
	if hmacErr := config.WritePolicyHMAC(policy, choices.SOPin, hmacPath); hmacErr != nil {
		result.Errors = append(result.Errors,
			fmt.Sprintf("policy HMAC write failed: %v", hmacErr))
		result.Success = false
	}

	// Do NOT set SetupComplete = true; user onboarding is still required.
	result.SetupComplete = false

	// Emit SO provisioning completed event.
	if s.eventEmitter != nil {
		s.eventEmitter(events.NewEvent(events.EventSOProvisioningCompleted,
			events.SOProvisioningCompletedPayload{
				OrganizationName: policy.OrganizationName,
				PolicyVersion:    policy.PolicyVersion,
			}))
	}

	return result, nil
}

// ApplyUserOnboarding performs the user onboarding phase of the enterprise
// setup workflow. It verifies the SO PIN, sets the user PIN, initializes or
// unseals barrier storage, and marks setup as complete.
func (s *SetupWizardService) ApplyUserOnboarding(choices *UserOnboardingChoices) (result *SetupResult, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic in ApplyUserOnboarding", "recover", r)
			result = nil
			retErr = fmt.Errorf("setup_wizard: panic in ApplyUserOnboarding: %v", r)
		}
	}()

	// Verify that SO provisioning has been completed.
	if !config.IsEnterpriseMode(s.configDir) {
		return nil, ErrSetupNotSOProvisioned
	}

	result = &SetupResult{
		Success:  true,
		Errors:   make([]string, 0),
		Warnings: make([]string, 0),
	}

	// Step 1: Verify SO PIN.
	s.emitUserOnboardingProgress(1, "Verifying SO PIN")
	if s.pinSvc == nil {
		return nil, ErrPINServiceNotConfigured
	}
	if err := s.pinSvc.VerifySOPIN(choices.SOPIN); err != nil {
		return nil, ErrSetupSOPINVerifyFailed
	}

	// Step 2: Set User PIN.
	s.emitUserOnboardingProgress(2, "Configuring User PIN")
	if err := s.pinSvc.SetUserPIN(choices.SOPIN, choices.UserPIN); err != nil {
		result.Errors = append(result.Errors,
			fmt.Sprintf("User PIN setup failed: %v", err))
		result.Success = false
	}

	// Step 3: Initialize or unseal barrier storage.
	s.emitUserOnboardingProgress(3, "Initializing encrypted storage")
	barrierInitialized := false
	barrierStrategy := ""
	if s.barrierSvc != nil {
		// Determine the barrier password: prefer the explicit barrier password,
		// fall back to the user PIN.
		barrierPW := choices.BarrierPassword
		if barrierPW == "" && choices.UserPIN != "" {
			barrierPW = choices.UserPIN
		}

		// Get the barrier strategy from the config set during SO provisioning.
		if s.configFunc != nil {
			if cfg := s.configFunc(); cfg != nil {
				barrierStrategy = cfg.BarrierStrategy
			}
		}
		if barrierStrategy == "" {
			// Fall back to loading from the unified config.
			if ucfg, loadErr := config.Load(); loadErr == nil {
				barrierStrategy = ucfg.State.BarrierStrategy
			}
		}
		// Default to software if still unknown.
		if barrierStrategy == "" {
			barrierStrategy = "software"
		}

		// Try unseal first (SO provisioning may have already created the barrier).
		if err := s.barrierSvc.Unseal(barrierPW, barrierStrategy); err != nil {
			// Unseal failed; attempt fresh initialization with software fallback.
			barrierInitialized, barrierStrategy = s.initBarrier(
				barrierPW, barrierStrategy, result)
		} else {
			barrierInitialized = true
		}
	}

	// Step 4: Mark setup as complete and save configuration.
	s.emitUserOnboardingProgress(4, "Saving configuration")

	// Update the GUI config bridge.
	if s.configFunc != nil && s.configSave != nil {
		cfg := s.configFunc()
		if cfg != nil {
			updated := *cfg
			updated.SetupComplete = true
			if barrierInitialized {
				updated.BarrierInitialized = true
				updated.BarrierStrategy = barrierStrategy
				updated.BarrierAutoUnsealEnabled = (barrierStrategy == "tpm2")
			}
			if err := s.configSave(&updated); err != nil {
				result.Errors = append(result.Errors,
					fmt.Sprintf("GUI config save failed: %v", err))
				result.Success = false
			}
		}
	}

	// Also update the unified config.
	cfg, loadErr := config.Load()
	if loadErr != nil {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("unified config load failed: %v", loadErr))
	} else {
		cfg.State.SetupComplete = true
		if barrierInitialized {
			cfg.State.BarrierInitialized = true
			cfg.State.BarrierStrategy = barrierStrategy
		}
		if saveErr := config.Save(cfg); saveErr != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("unified config save failed: %v", saveErr))
			result.Success = false
		}
	}

	result.SetupComplete = true

	// Emit user onboarded event.
	if s.eventEmitter != nil {
		s.eventEmitter(events.NewEvent(events.EventUserOnboarded,
			events.UserOnboardedPayload{
				BarrierInitialized: barrierInitialized,
				BarrierStrategy:    barrierStrategy,
			}))
	}

	return result, nil
}

// GetPolicy returns the policy section from the unified configuration as a
// generic map suitable for frontend display. The json marshal/unmarshal round
// trip converts the typed PolicySection to a map[string]any that can be
// serialized by the Wails binding layer without exposing internal Go types.
func (s *SetupWizardService) GetPolicy() (result map[string]any, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic in GetPolicy", "recover", r)
			result = nil
			retErr = fmt.Errorf("setup_wizard: panic in GetPolicy: %v", r)
		}
	}()

	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("setup_wizard: %w", err)
	}

	data, err := json.Marshal(cfg.Policy)
	if err != nil {
		return nil, fmt.Errorf("setup_wizard: policy marshal failed: %w", err)
	}

	policyMap := make(map[string]any)
	if err := json.Unmarshal(data, &policyMap); err != nil {
		return nil, fmt.Errorf("setup_wizard: policy unmarshal failed: %w", err)
	}

	return policyMap, nil
}

// FactoryReset performs a comprehensive device wipe. It requires the SO PIN
// for authorization. All user data, keys, credentials, configuration, and
// security policy are permanently destroyed.
func (s *SetupWizardService) FactoryReset(soPin string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic in FactoryReset", "recover", r)
			retErr = fmt.Errorf("setup_wizard: panic in FactoryReset: %v", r)
		}
	}()

	if soPin == "" {
		return ErrSetupSOPINRequired
	}

	// Verify SO PIN before proceeding.
	if s.pinSvc != nil {
		if err := s.pinSvc.VerifySOPIN(soPin); err != nil {
			return ErrSetupSOPINVerifyFailed
		}
	}

	var errs []string

	// Step 1: TPM factory reset.
	if s.tpmSvc != nil {
		if err := s.tpmSvc.FactoryReset(soPin); err != nil {
			errs = append(errs, fmt.Sprintf("TPM reset: %v", err))
		}
	}

	// Step 2: Remove policy HMAC file (exit enterprise mode).
	if s.configDir != "" {
		hmacPath := config.PolicyHMACPath(s.configDir)
		if err := os.Remove(hmacPath); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Sprintf("HMAC removal: %v", err))
		}
	}

	// Step 3: Remove unified config file.
	configPath := config.ConfigPath()
	if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Sprintf("config removal: %v", err))
	}

	// Step 4: Reset GUI config state.
	if s.configFunc != nil && s.configSave != nil {
		cfg := s.configFunc()
		if cfg != nil {
			// Reset to zero values - setup will be required on next launch.
			reset := &GUIConfigData{}
			if err := s.configSave(reset); err != nil {
				errs = append(errs, fmt.Sprintf("GUI config reset: %v", err))
			}
		}
	}

	// Emit factory reset event.
	if s.eventEmitter != nil {
		s.eventEmitter(events.NewEvent(events.EventSetupSkipped, events.SetupSkippedPayload{
			Reason: "factory reset performed",
		}))
	}

	if len(errs) > 0 {
		return fmt.Errorf("factory reset completed with errors: %s", strings.Join(errs, "; "))
	}

	return nil
}
