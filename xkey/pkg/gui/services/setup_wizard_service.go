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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"os/exec"
	"runtime"
	"strings"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"

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
	BarrierPassword    string `json:"barrier_password"`   // For barrier passphrase strategy
	SealerBackend      string `json:"sealer_backend"`     // "tpm2", "passphrase", "" (auto)
	QuickSetup         bool   `json:"quick_setup"`        // True when quick setup flow is used
	DeploymentMode     string `json:"deployment_mode"`    // "personal" or "enterprise"
	SavePinsToStore    bool   `json:"save_pins_to_store"` // Save the User PIN to the password store (manual setup option); never the SO PIN (#290)
	// SOPINRecorded is the operator's acknowledgement that a wizard-generated
	// SO PIN has been recorded somewhere outside this device. Quick setup
	// refuses to apply until it is true: the SO PIN is shown once and the
	// device keeps no retrievable copy (#290).
	SOPINRecorded bool `json:"so_pin_recorded"`

	// Enterprise policy fields (used by ApplySOProvisioning).
	OrganizationName         string `json:"organization_name"`
	MinPinLength             int    `json:"min_pin_length"`
	PINMaxAttempts           int    `json:"pin_max_attempts"`
	RequireEncryptedStorage  bool   `json:"require_encrypted_storage"`
	RequireTPM               bool   `json:"require_tpm"`
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
// to existing services (StorageService, TPMService, PINService, etc.).
type SetupWizardService struct {
	ctx             context.Context
	storageSvc      *StorageService
	tpmSvc          *TPMService
	pinSvc          *PINService
	sealSvc         *SealService
	tpmPolicySvc    *TPMPolicyService
	barrierAutoSvc  *BarrierAutoUnsealService
	autoUnsealSvc   *AutoUnsealService
	barrierSvc      *BarrierService
	staticPwSvc     *StaticPasswordService
	adminSvc        *AdminService
	tpmStatusFn     TPMStatusFunc
	configFunc      func() *GUIConfigData
	configSave      func(*GUIConfigData) error
	eventEmitter    func(events.Event)
	initDataDirFunc func() error
	configDir       string
}

// NewSetupWizardService creates a new SetupWizardService with its required
// collaborators.
//
// pinSvc is the SO/User PIN credential gate. Every wizard phase authorizes
// against it: ApplySetup and ApplySOProvisioning configure the SO and User
// PINs, ApplyUserOnboarding and FactoryReset verify the SO PIN before a
// destructive operation proceeds. Earlier revisions accepted pinSvc through
// a setter (SetPINService) and guarded each use with "if s.pinSvc != nil",
// so a caller that forgot the setter got a wizard whose credential checks
// silently passed instead of refusing to run -- observed for FactoryReset,
// a full device wipe, in #313. Taking pinSvc here instead makes that class
// of bug impossible to construct: there is no zero-argument constructor to
// forget a setter after.
//
// Every other collaborator (TPM, seal, barrier, platform policy, ...) is
// optional and wired through its own Set*/With* method, because each one
// may legitimately be absent on a given build or host -- e.g. a device with
// no TPM (#510) -- and the corresponding wizard step already degrades to a
// warning or a typed refusal rather than fabricating success when it is
// missing.
func NewSetupWizardService(pinSvc *PINService) (*SetupWizardService, error) {
	if pinSvc == nil {
		return nil, ErrSetupWizardPINServiceRequired
	}
	return &SetupWizardService{pinSvc: pinSvc}, nil
}

// generateRandomPIN generates a cryptographically random string of the
// specified length using crypto/rand, sampling uniformly from pinCharset.
// The generated PIN is guaranteed to contain at least one character from
// each class (uppercase, lowercase, digit, special) when length >= 4.
//
// Candidates are drawn by rejection sampling: each candidate is uniform
// over pinCharset^length, and one that fails the complexity check is
// discarded and redrawn. This keeps the result uniformly distributed over
// the set of complexity-satisfying PINs, and the loop has no attempt cap
// -- a bounded cap can fail outright, however rarely, and for length 4 the
// per-attempt acceptance rate is only ~7% (a 4-character PIN must place a
// distinct character class in each of its 4 positions), so a 100-attempt
// cap failed with probability on the order of 1 in 1,300 calls, which is
// exactly the flake observed in CI (#1210). Every accepted length has a
// strictly positive per-attempt success probability, so the loop below
// terminates with certainty; the only error path left is a genuine
// crypto/rand failure.
func generateRandomPIN(length int) (string, error) {
	if length <= 0 {
		return "", nil
	}

	charsetLen := big.NewInt(int64(len(pinCharset)))

	for {
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
//
// The returned SO PIN is the operator's one chance to record it: the wizard
// displays it once and the device never keeps a retrievable copy (#290).
// ApplySetup only persists what verification needs, through the PIN service.
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

// SetTPMPolicyService sets the TPM policy service the wizard creates the
// barrier auto-unseal policy with.
func (s *SetupWizardService) SetTPMPolicyService(svc *TPMPolicyService) {
	s.tpmPolicySvc = svc
}

// SetBarrierAutoUnsealService sets the service that seals the barrier
// credential under the auto-unseal policy.
func (s *SetupWizardService) SetBarrierAutoUnsealService(svc *BarrierAutoUnsealService) {
	s.barrierAutoSvc = svc
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
const setupTotalSteps = 9

// Barrier auto-unseal policy the wizard creates: a named TPM policy over the
// firmware, Secure Boot and boot-loader PCRs of the SHA-256 bank. The
// built-in platform policy cannot carry auto-unseal.
const (
	wizardAutoUnsealPolicy = "auto-unseal"
	wizardAutoUnsealBank   = "sha256"
)

// wizardAutoUnsealPCRs are the PCRs the wizard's auto-unseal policy selects.
var wizardAutoUnsealPCRs = []uint{0, 7, 9}

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

// sealBackendForBarrierSealer maps a wizard barrier sealer strategy
// ("passphrase"/"tpm2"/"pkcs11") onto the seal feature's own backend namespace
// ("software"/"tpm2"). A passphrase (software-AES) barrier corresponds to the
// software seal backend. Unknown or hardware-token strategies return "" so the
// caller falls back to auto-selecting a valid available seal backend rather
// than pinning the seal feature to an unsupported backend (which makes CanSeal
// return false and disables sealing entirely).
func sealBackendForBarrierSealer(sealer string) string {
	switch sealer {
	case "tpm2":
		return string(xkms.BackendTypeTPM2)
	case "passphrase", "software":
		return string(xkms.BackendTypeSoftware)
	default:
		return ""
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

	// Quick setup applies a wizard-generated SO PIN the operator has never
	// typed. It is displayed once and never persisted on the device (#290),
	// so refuse to apply until the operator has acknowledged recording it
	// out of band. Manual setup needs no acknowledgement: the operator chose
	// and confirmed the SO PIN themselves.
	if choices.QuickSetup && !choices.SOPINRecorded {
		return nil, ErrSetupSOPINNotRecorded
	}

	result := &SetupResult{
		Success:  true,
		Errors:   make([]string, 0),
		Warnings: make([]string, 0),
	}

	// Track TPM-specific outcomes for the event payload.
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
	// soPINSupported reflects the active PIN backend's capability, not a
	// hardcoded strategy comparison — see PINService.SOPINSupported. The
	// tpm2 backend binds all authorization to the PlatformSRK auth value
	// and always rejects SetSOPIN/ChangeSOPIN/VerifySOPIN, so attempting
	// them here would just produce failed audit events on every install.
	soPINSupported := true
	if s.pinSvc != nil {
		soPINSupported = s.pinSvc.SOPINSupported()
	}
	if choices.SOPin != "" && s.pinSvc != nil {
		if !soPINSupported {
			result.Warnings = append(result.Warnings, fmt.Sprintf(
				"SO PIN is not applicable for the %s PIN backend (authorization is bound to platform hardware instead of a separate SO PIN)",
				s.pinSvc.Strategy()))
		} else if err := s.pinSvc.SetSOPIN("", choices.SOPin); err != nil {
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

	// requestedSealerBackend captures the user's explicit strategy choice before
	// auto-fill may overwrite an empty value with the best available sealer.
	// An empty string means "no explicit preference"; "tpm2" / "pkcs11" means
	// the user or quick-setup explicitly requested hardware-backed sealing.
	requestedSealerBackend := choices.SealerBackend
	// requestedHardware is true when the user expressed intent for hardware-backed
	// sealing via a direct backend choice or via the password store mode selection.
	// It is used to detect a silent hardware->passphrase downgrade after barrier init.
	requestedHardware := requestedSealerBackend == "tpm2" ||
		requestedSealerBackend == "pkcs11" ||
		choices.PasswordStoreMode == "tpm_sealed"

	// Auto-fill sealer backend from best available when not explicitly chosen.
	// Must resolve BEFORE barrier init because the barrier strategy depends on it.
	if choices.SealerBackend == "" && s.sealSvc != nil {
		if best := s.sealSvc.BestSealer(); best != nil {
			choices.SealerBackend = best.ID
		}
	}
	// Last-resort fallback: if no sealers are available, default to passphrase.
	if choices.SealerBackend == "" {
		choices.SealerBackend = "passphrase"
	}

	// Step 5: Initialize built-in encryption (barrier).
	// Barrier ALWAYS wraps the base backend (filesystem or LUKS).
	// When LUKS is selected, the barrier encrypts on top of LUKS.
	// NOTE: This step must run AFTER TPM provisioning (steps 3-4) because
	// the TPM2 sealing strategy requires a provisioned SRK.
	s.emitProgress(5, "Initializing built-in encryption")
	barrierInitialized := false
	barrierStrategy := ""
	barrierAutoUnsealEnabled := false
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
					s.barrierSvc.SetBaseBackendFactory(func(_ string) (xkms.StorageBackend, error) {
						return xkms.NewFileStorageBackend(mountPoint)
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
		barrierErrCount := len(result.Errors)
		// Plain assignment, not :=. barrierInitialized and barrierStrategy are
		// declared in the enclosing scope and read after this block; a short
		// declaration here would shadow them and leave those later reads on the
		// zero values.
		var barrierSealedShut bool
		barrierInitialized, barrierStrategy, barrierSealedShut = s.initBarrier(
			barrierPW, choices.SealerBackend, result)

		// Graceful hardware->software fallback. When a hardware sealing strategy
		// (tpm2 / pkcs11) fails to initialize the barrier — e.g. a TPM that was
		// provisioned by a prior install returns TPM_RC_BAD_AUTH / TPM_RC_POLICY_FAIL
		// because its owner/SRK auth no longer matches — retry with the passphrase
		// strategy so first-run setup can still complete with a software-encrypted
		// barrier. Without this, the wizard can never mark setup complete and the
		// user is trapped re-running it on every launch. The barrier is the
		// system's at-rest encryption boundary: a working software barrier
		// (User PIN via Argon2id + AES-256-GCM) is strictly better than leaving
		// the install unconfigured. The original hardware-attempt errors are
		// discarded; the fallback attempt decides success. The downgrade is
		// surfaced as a warning by the block below (barrierStrategy == "passphrase").
		//
		// It must NOT fire when a barrier already exists and would not unseal
		// (barrierSealedShut). That barrier's data is sealed under the strategy
		// it was created with, so a passphrase retry cannot open it; it only
		// fails again, and this block discards the real error
		// (result.Errors[:barrierErrCount]) on its way past. The operator then
		// sees "invalid credentials" for a credential that was never wrong,
		// the run ends with setup_complete false, and the next launch re-runs
		// the wizard and mints a NEW User PIN -- pushing a new hash to the
		// authenticator and stranding the enrolled passkeys. That is #510, and
		// it cost a real authenticator PIN.
		hardwareStrategy := choices.SealerBackend == "tpm2" || choices.SealerBackend == "pkcs11"
		if !barrierInitialized && hardwareStrategy && !barrierSealedShut {
			slog.Warn("wizard: hardware barrier init failed, falling back to passphrase",
				"strategy", choices.SealerBackend)
			result.Errors = result.Errors[:barrierErrCount]
			result.Success = true
			barrierInitialized, barrierStrategy, _ = s.initBarrier(
				barrierPW, "passphrase", result)
			if barrierInitialized {
				// Persist the actual strategy so downstream config, seal-default
				// mapping, and auto-unseal wiring all reflect passphrase/software.
				choices.SealerBackend = "passphrase"
			}
		}

		// Detect a silent hardware->passphrase downgrade. This happens when the
		// user requested hardware-backed sealing (tpm2 / pkcs11 / tpm_sealed) but
		// the hardware strategy was unavailable or failed (e.g. TPM_RC_BAD_AUTH,
		// failed to evict platform SRK) and the auto-fill fallback selected
		// passphrase instead. Surface an explicit warning so the frontend shows
		// the downgrade prominently — a success toast without this warning would
		// leave the user believing their master key is hardware-sealed when it is not.
		if barrierInitialized && requestedHardware && barrierStrategy == "passphrase" {
			requested := requestedSealerBackend
			if requested == "" {
				requested = choices.PasswordStoreMode
			}
			slog.Warn("wizard: sealing strategy downgraded from hardware to passphrase",
				"requested", requested,
				"actual", barrierStrategy)
			result.Warnings = append(result.Warnings,
				fmt.Sprintf(
					"sealing strategy downgraded: requested %q but barrier initialized with %q "+
						"(TPM hardware key sealing is not available — "+
						"to use TPM sealing, clear the TPM or provide the correct SO PIN, "+
						"then re-run the setup wizard)",
					requested, barrierStrategy))
		}
	}

	// Apply the seal-feature default backend. choices.SealerBackend is a BARRIER
	// strategy ("passphrase"/"tpm2"/"pkcs11"); the seal feature uses its own
	// backend namespace ("software"/"tpm2"). Map between them so CanSeal accepts
	// the default — passing the raw "passphrase" strategy made CanSeal reject an
	// unknown backend and permanently disabled the "Seal New Data" action.
	if s.sealSvc != nil {
		if sb := sealBackendForBarrierSealer(choices.SealerBackend); sb != "" {
			s.sealSvc.SetDefaultBackend(sb)
		} else {
			s.sealSvc.AutoSelectDefault()
		}
	}

	// Step 6: Initialize data directory.
	// NOTE: Must run AFTER barrier init (step 6) so that the static password
	// store can use the barrier as its encrypted backend.
	// This also creates the PINManager and starts the FIDO2 device via
	// postDataDirStartup(). PINs set at step 2 may have failed because
	// the PINManager did not exist yet; retry here.
	s.emitProgress(6, "Initializing data directory")
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
	// Software/PKCS#11 backends need SO PIN configured for user PIN
	// authorization, regardless of SetHierarchyAuth (which only controls TPM
	// hierarchy passwords during provisioning at step 3). The tpm2 backend
	// has no SO PIN concept at all (soPINSupported is false), so this block
	// is skipped entirely for it — see the capability check in Step 2 above.
	if dataDirReady && s.pinSvc != nil {
		// Re-evaluate SO PIN capability: initDataDirFunc re-creates the PIN
		// manager, and the strategy may have switched (e.g. software → tpm2
		// once the TPM barrier/platform provisioning completed). The Step 2
		// snapshot is stale by now; retrying SetSOPIN against a backend that
		// does not support SO PINs would emit so_pin_failed audit events on
		// every clean install.
		if soPINSupported && !s.pinSvc.SOPINSupported() {
			soPINSupported = false
			result.Warnings = append(result.Warnings, fmt.Sprintf(
				"SO PIN is not applicable for the %s PIN backend (authorization is bound to platform hardware instead of a separate SO PIN)",
				s.pinSvc.Strategy()))
		}
		if choices.SOPin != "" && !soPINSet && soPINSupported {
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

	// Step 7: Configure password protection.
	// In quick-setup personal mode, save the auto-generated User PIN to the
	// password store so the user can retrieve it after the app locks.
	//
	// The SO PIN is deliberately NOT saved anywhere on the device (#290). It
	// is the recovery credential for a forgotten User PIN, and the password
	// store is unlocked by the User PIN — storing it there would put the
	// recovery credential behind the thing it recovers. The wizard shows the
	// generated SO PIN once and requires the operator to acknowledge
	// recording it out of band (see SOPINRecorded); only the PIN service's
	// verifier persists.
	s.emitProgress(7, "Configuring password protection")
	saveUserPin := (choices.QuickSetup && choices.DeploymentMode == "personal") || choices.SavePinsToStore
	if dataDirReady && saveUserPin && s.staticPwSvc != nil {
		if choices.UserPin != "" {
			if _, err := s.staticPwSvc.AddPassword(AddPasswordParams{
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

	// Step 8: Configure auto-unseal.
	s.emitProgress(8, "Configuring auto-unseal")
	if choices.EnableAutoUnseal {
		if choices.StorageType == "luks" && choices.EnableStorage && choices.StoragePass != "" {
			// LUKS auto-unseal (existing logic).
			if s.autoUnsealSvc != nil {
				if _, err := s.autoUnsealSvc.Enable(
					choices.StoragePass,
					xkms.TPMPolicyPlatform,
					string(xkms.BackendTypeTPM2),
				); err != nil {
					result.Warnings = append(result.Warnings,
						fmt.Sprintf("auto-unseal setup: %v", err))
				}
			} else {
				result.Warnings = append(result.Warnings, "auto-unseal service unavailable")
			}
		}
		// Barrier auto-unseal: seal the barrier password in the TPM under a
		// named policy, so the barrier opens at boot while the platform is in
		// the state the policy approves.
		if barrierInitialized {
			barrierPW := choices.BarrierPassword
			if barrierPW == "" || choices.UseUserPinAsMaster {
				barrierPW = choices.UserPin
			}
			ownerAuth := ""
			if choices.SetHierarchyAuth {
				ownerAuth = choices.SOPin
			}
			if err := s.enableBarrierAutoUnseal(barrierPW, ownerAuth); err != nil {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("barrier auto-unseal: %v (manual unlock on restart)", err))
			} else {
				barrierAutoUnsealEnabled = true
			}
		}
	}

	// Step 9: Save configuration.
	s.emitProgress(9, "Saving configuration")
	updated := *cfg
	if choices.Mode == "server" || choices.Mode == "both" {
		updated.ServerAddress = choices.ServerAddress
		if choices.ServerProtocol != "" {
			updated.ServerProtocol = choices.ServerProtocol
		}
		updated.ServerAutoConnect = true
	}

	// Refuse to mark setup complete when the barrier (the system's only
	// at-rest encryption boundary) was wired but failed to initialize.
	// Persisting SetupComplete=true with BarrierInitialized=false leaves
	// the user in a half-broken state where the saved User PIN cannot
	// recover the barrier and the unlock screen reports "incorrect PIN"
	// forever. When no barrier service is wired (s.barrierSvc == nil,
	// test-only path), preserve the legacy completion behavior.
	updated.StorageType = "barrier"
	// Persist the seal-namespace backend ID ("software"/"tpm2"), not the raw
	// barrier strategy string ("passphrase"/"pkcs11"). Storing the raw strategy
	// causes SetDefaultBackend on next startup to pin the seal service to an
	// unknown backend, making CanSeal return false and disabling the Sealed Data
	// view on every passphrase-barrier install.
	if sb := sealBackendForBarrierSealer(choices.SealerBackend); sb != "" {
		updated.SealerBackend = sb
	} else {
		updated.SealerBackend = choices.SealerBackend
	}
	barrierAttempted := s.barrierSvc != nil
	switch {
	case barrierInitialized:
		updated.SetupComplete = true
		updated.BarrierInitialized = true
		updated.BarrierStrategy = barrierStrategy
		updated.BarrierAutoUnsealEnabled = barrierAutoUnsealEnabled || barrierStrategy == "tpm2"
		result.SetupComplete = true
	case barrierAttempted:
		// Barrier init was attempted with a real service and failed.
		// Persist the intended strategy so the user can retry, but do
		// NOT mark setup complete.
		updated.SetupComplete = false
		updated.BarrierInitialized = false
		if guardErr := s.refuseUnavailableStrategyPersist(choices.SealerBackend); guardErr != nil {
			// tpm2 was requested but this build/host has no usable TPM
			// sealer wired into the barrier. Leave updated.BarrierStrategy
			// untouched (whatever cfg already had, including "") rather
			// than committing a strategy this build can never unseal
			// again (#510 item 1).
			slog.Error("wizard: refusing to persist unavailable barrier strategy",
				"strategy", choices.SealerBackend, "error", guardErr)
			result.Errors = append(result.Errors, guardErr.Error())
		} else {
			updated.BarrierStrategy = choices.SealerBackend
		}
		result.SetupComplete = false
		result.Success = false
		result.Errors = append(result.Errors,
			fmt.Sprintf("barrier %s initialization failed — setup cannot complete; please re-run the wizard with a different sealer backend or resolve the underlying error",
				choices.SealerBackend))
	default:
		// No barrier service wired (test path). Preserve legacy behavior.
		updated.SetupComplete = true
		updated.BarrierStrategy = choices.SealerBackend
		result.SetupComplete = true
	}
	if err := s.configSave(&updated); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("config save failed: %v", err))
		result.Success = false
	}

	// Emit setup completed event.
	if s.eventEmitter != nil {
		s.eventEmitter(events.NewEvent(events.EventSetupCompleted, events.SetupCompletedPayload{
			Mode:               choices.Mode,
			StorageCreated:     choices.EnableStorage && result.Success,
			MasterPWSet:        choices.EnableMasterPW && choices.MasterPassword != "" && result.Success,
			TPMSealedPasswords: tpmSealedPasswords && result.Success,
			UserPINSet:         userPINSet,
			SOPINSet:           soPINSet,
			BarrierInitialized: barrierInitialized,
			BarrierStrategy:    barrierStrategy,
		}))
	}

	return result, nil
}

// enableBarrierAutoUnseal creates the wizard's auto-unseal policy over the
// live PCRs of the local TPM, or reuses it when a previous run created it,
// and seals the barrier credential under it. ownerAuth authorizes defining
// the policy's NV index when the TPM's owner hierarchy has a password.
func (s *SetupWizardService) enableBarrierAutoUnseal(credential, ownerAuth string) error {
	if s.tpmPolicySvc == nil || s.barrierAutoSvc == nil {
		return ErrBarrierAutoUnsealNoPolicyService
	}
	local := s.tpmPolicySvc.Local()
	if local == nil {
		return ErrBarrierAutoUnsealNoPolicyService
	}
	_, err := local.TPMPolicyCreate(context.Background(), &transport.TPMPolicyCreateRequest{
		Name:      wizardAutoUnsealPolicy,
		Branches:  []transport.TPMPolicyBranch{transport.TPMPolicyPCRBranch(wizardAutoUnsealBank, wizardAutoUnsealPCRs)},
		OwnerAuth: ownerAuthBytes(ownerAuth),
	})
	if err != nil && !errors.Is(err, xkms.ErrTPMPolicyExists) {
		return err
	}
	return s.barrierAutoSvc.EnableAutoUnseal(wizardAutoUnsealPolicy, credential)
}

// refuseUnavailableStrategyPersist returns ErrSetupSealStrategyUnavailable
// when strategyID is "tpm2" and the barrier service has no usable TPM
// sealer wired in on this build/host, per the barrier service's own
// availability probe (the same check assembleStrategy uses to decide
// whether Initialize/Unseal can even attempt tpm2). It returns nil for
// every other strategy and whenever no barrier service is wired at all --
// callers that reach it only after a failed attempt already know
// s.barrierSvc is non-nil, but the nil check keeps this safe to call from
// anywhere.
//
// This is the single point that decides whether a failed barrier attempt's
// strategy may still be committed to config for retry. Persisting
// barrier_strategy: tpm2 after a failed attempt on a host with no TPM
// sealer would write a config this build's GUI can never unseal again
// (#510 item 1); every other failure reason (e.g. a wrong password against
// an existing tpm2 barrier) still persists the strategy, since a working
// sealer is wired and the barrier itself is what would not open.
func (s *SetupWizardService) refuseUnavailableStrategyPersist(strategyID string) error {
	if strategyID != string(xkms.StrategyTPM2) || s.barrierSvc == nil {
		return nil
	}
	for _, info := range s.barrierSvc.ProbeStrategies() {
		if info.ID == strategyID {
			if info.Available {
				return nil
			}
			break
		}
	}
	return ErrSetupSealStrategyUnavailable
}

// initBarrier attempts to initialize the barrier with the given strategy,
// handling the case where the barrier already exists (re-run).
//
// If initialization fails, the error is surfaced to the user so they can
// go back and select a different strategy. No automatic fallback is
// performed.
//
// Returns (initialized bool, strategy string, sealedShut bool).
//
// sealedShut distinguishes the two ways this can fail, which are not
// interchangeable and must not be treated alike (#510):
//
//   - Initialize failed and NO barrier exists. Nothing is stored yet, so
//     retrying with another strategy is free and is what the caller's
//     hardware->passphrase fallback is for.
//   - A barrier EXISTS and would not unseal (sealedShut). Its data is already
//     encrypted under the strategy it was sealed with. Retrying with a
//     different strategy cannot open it -- it can only fail a second time, and
//     the second failure reads as "invalid credentials", which sends the
//     operator looking for a wrong password that does not exist.
func (s *SetupWizardService) initBarrier(
	password, strategyID string, result *SetupResult,
) (bool, string, bool) {

	if err := s.barrierSvc.Initialize(password, strategyID); err == nil {
		return true, strategyID, false
	} else if errors.Is(err, ErrBarrierAlreadyInit) {
		// Barrier was initialized in a prior run. Unseal instead.
		slog.Info("wizard: barrier already initialized, unsealing existing barrier",
			"strategy", strategyID)
		if unsealErr := s.barrierSvc.Unseal(password, strategyID); unsealErr != nil {
			slog.Error("wizard: barrier unseal failed", "error", unsealErr)
			result.Errors = append(result.Errors,
				fmt.Sprintf("barrier unseal failed: %v", unsealErr))
			result.Success = false
			return false, "", true
		}
		return true, strategyID, false
	} else {
		slog.Error("wizard: barrier initialization failed",
			"strategy", strategyID, "error", err)
		result.Errors = append(result.Errors,
			fmt.Sprintf("barrier %s initialization failed: %v", strategyID, err))
		result.Success = false
		return false, "", false
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
			return &SentinelCauseError{Sentinel: ErrSetupStorageFailed, Cause: err}
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
		return &SentinelCauseError{Sentinel: ErrSetupStorageFailed, Cause: err}
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
			retErr = &MessageError{Msg: fmt.Sprintf("setup_wizard: panic in GetStartupState: %v", r)}
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
			retErr = &MessageError{Msg: fmt.Sprintf("setup_wizard: panic in ApplySOProvisioning: %v", r)}
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
	policy.PlatformPCRBank = "sha256"
	if choices.StorageType != "" {
		policy.StorageType = choices.StorageType
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
			retErr = &MessageError{Msg: fmt.Sprintf("setup_wizard: panic in ApplyUserOnboarding: %v", r)}
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
	// barrierRequired records that a barrier service is configured, so
	// "not initialized" means it FAILED rather than "there is none". Without
	// the distinction an install with no barrier at all would be refused
	// completion alongside one whose barrier would not open.
	barrierRequired := s.barrierSvc != nil
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
		// Default to passphrase if still unknown.
		if barrierStrategy == "" {
			barrierStrategy = "passphrase"
		}

		// Try unseal first (SO provisioning may have already created the barrier).
		if err := s.barrierSvc.Unseal(barrierPW, barrierStrategy); err != nil {
			// Unseal failed; attempt fresh initialization with software fallback.
			var sealedShut bool
			barrierInitialized, barrierStrategy, sealedShut = s.initBarrier(
				barrierPW, barrierStrategy, result)
			if sealedShut {
				slog.Error("onboarding: existing barrier would not unseal",
					"strategy", barrierStrategy)
			}
		} else {
			barrierInitialized = true
		}
	}

	// An onboarding run that could not open the barrier is not a completed
	// setup, and must not be recorded as one.
	//
	// Every write below this point is a completion write -- SetupComplete in
	// the GUI config and in the unified config, result.SetupComplete, and the
	// UserOnboarded event. They ran unconditionally, so a run whose barrier
	// failed still left the install marked complete with its encrypted storage
	// unusable. Step 2 has already changed the User PIN by this point, so the
	// combination strands the new PIN behind a barrier that was never opened
	// and reports success on the way out -- the same class of harm #510
	// reports for ApplySetup, on the enterprise path.
	//
	// Returning here leaves SetupComplete false, so the wizard runs again and
	// the operator can retry rather than being told an unusable install is
	// finished. result.Errors already carries the unseal or initialization
	// failure from initBarrier; this adds what it means.
	if barrierRequired && !barrierInitialized {
		result.Success = false
		result.SetupComplete = false
		result.Errors = append(result.Errors,
			"setup not marked complete: encrypted storage could not be opened, "+
				"so the User PIN change is not yet backed by a usable barrier - "+
				"resolve the barrier error above and run onboarding again")
		slog.Error("onboarding: refusing to mark setup complete with an unusable barrier",
			"strategy", barrierStrategy, "errors", result.Errors)
		return result, nil
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
			retErr = &MessageError{Msg: fmt.Sprintf("setup_wizard: panic in GetPolicy: %v", r)}
		}
	}()

	cfg, err := config.Load()
	if err != nil {
		return nil, &WrappedError{Msg: "setup_wizard", Err: err}
	}

	data, err := json.Marshal(cfg.Policy)
	if err != nil {
		return nil, &WrappedError{Msg: "setup_wizard: policy marshal failed", Err: err}
	}

	policyMap := make(map[string]any)
	if err := json.Unmarshal(data, &policyMap); err != nil {
		return nil, &WrappedError{Msg: "setup_wizard: policy unmarshal failed", Err: err}
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
			retErr = &MessageError{Msg: fmt.Sprintf("setup_wizard: panic in FactoryReset: %v", r)}
		}
	}()

	if soPin == "" {
		return ErrSetupSOPINRequired
	}

	// Verify SO PIN before proceeding.
	//
	// A missing PIN service is a refusal, not a pass. This check previously sat
	// inside "if s.pinSvc != nil", so a SetupWizardService whose SetPINService
	// setter had not been called accepted any non-empty string as the SO PIN
	// and went on to wipe the TPM. The credential gate on a destructive
	// operation must not be conditional on the collaborator that enforces it
	// having been wired (#313).
	if s.pinSvc == nil {
		return ErrSetupPINServiceUnavailable
	}
	if err := s.pinSvc.VerifySOPIN(soPin); err != nil {
		return ErrSetupSOPINVerifyFailed
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
		return &MessageError{Msg: fmt.Sprintf("factory reset completed with errors: %s", strings.Join(errs, "; "))}
	}

	return nil
}
