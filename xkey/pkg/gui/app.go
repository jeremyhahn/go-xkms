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

package gui

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	tpm2lib "github.com/google/go-tpm/tpm2"
	tpmtransport "github.com/google/go-tpm/tpm2/transport"

	"github.com/jeremyhahn/go-xkms/pkg/autofill"
	backendtpm2 "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	pivfile "github.com/jeremyhahn/go-xkms/pkg/pivcert/file"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	filestorage "github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	tpm2store "github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/sharestore"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator/keybackend"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backendregistry"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/icon"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/nativemsg"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/notify"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/serverregistry"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/tokenstore"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
	"gopkg.in/yaml.v3"
)

// Assets is the embedded filesystem containing the compiled frontend.
// It must be set by the cmd/xkey main package before calling Run().
//
// Example (in cmd/xkey/main.go):
//
//	//go:embed all:frontend/dist
//	var assets embed.FS
//	func init() { gui.Assets = assets }
var Assets fs.FS

// FirmwareVersion is the CTAP2 firmware version reported in GetInfo (key 0x0E).
// Set by the cmd/xkey main package before calling Run() using ParseFirmwareVersion.
var FirmwareVersion uint32

// ParseFirmwareVersion converts a semver string (e.g., "1.2.3") to the
// CTAP2 firmware version encoding: major*10000 + minor*100 + patch.
// Returns 0 for unparseable versions (e.g., "dev").
func ParseFirmwareVersion(version string) uint32 {
	var major, minor, patch uint32
	if _, err := fmt.Sscanf(version, "%d.%d.%d", &major, &minor, &patch); err != nil {
		return 0
	}
	return major*10000 + minor*100 + patch
}

// App is the central Wails v2 application. It wires the config, services,
// tray manager, and Wails lifecycle hooks together.
type App struct {
	ctx    context.Context
	config *GUIConfig
	log    *slog.Logger

	// Services bound to Wails.
	appService               *services.AppService
	phoneService             *services.PhoneService
	fido2Service             *services.FIDO2Service
	fido2DeviceService       *services.FIDO2DeviceService
	oathService              *services.OATHService
	staticPWService          *services.StaticPasswordService
	pivService               *services.PIVService
	tpmService               *services.TPMService
	auditService             *services.AuditService
	auditStore               *audit.BackendStore
	adminService             *services.AdminService
	connectionService        *services.ConnectionService
	keyService               *services.KeyService
	storageService           *services.StorageService
	notificationService      *services.NotificationService
	sealService              *services.SealService
	passwordProtectionSvc    *services.PasswordProtectionService
	platformPolicyService    *services.PlatformPolicyService
	autoUnsealService        *services.AutoUnsealService
	barrierAutoUnsealService *services.BarrierAutoUnsealService
	oidcService              *services.OIDCService
	clipboardService         *services.ClipboardService
	trustService             *services.TrustService
	setupWizardService       *services.SetupWizardService
	pinService               *services.PINService
	barrierService           *services.BarrierService
	authService              *services.AuthService
	browserService           *services.BrowserService
	secureBrowserService     *services.SecureBrowserService
	apiExplorerService       *services.APIExplorerService
	shareService             *services.ShareService
	custodianService         *services.CustodianService
	tenantService            *services.TenantService
	agentService             *services.AgentService
	autofillService          *services.AutoFillService
	pairingService           *services.PairingService
	sealProtectionSvc        *services.SealProtectionService
	appLockService           *services.AppLockService
	pkcs11Service            *services.PKCS11Service
	teamService              *services.TeamService

	// backendRegistry tracks all registered cryptographic backends
	// (local and remote) and their operational state.
	backendRegistry backendregistry.Registry

	// authenticatorInstance is always available after barrier unseal.
	// Shared between FIDO2 device service (USB HID) and autofill service (CTAP2 auth).
	authenticatorInstance *authenticator.Authenticator

	// fido2KeyBackend is the composite FIDO2 key backend that routes credential
	// key operations to the appropriate backend (software, TPM2, PKCS#11, etc.).
	// Backends are registered/unregistered dynamically as they become available.
	fido2KeyBackend *keybackend.CompositeBackend
	screenLockMonitor     *notify.ScreenLockMonitor

	// Expiry checker for static password entries.
	expiryChecker *staticpw.ExpiryChecker

	// Storage backends (closed on shutdown).
	oathStore     oath.Store
	fido2Storage  authenticator.StatefulCredentialStorage
	staticpwStore staticpw.Store
	trustStore    truststore.TrustStore
	pivFileStore    pivcert.PIVCertificateStorage
	pivStorageBE    storage.Backend // underlying storage for creating namespaced PIV stores

	// TPM instance (lazy-initialized, closed on shutdown).
	tpmMu             sync.Mutex
	tpmInstance       tpm2pkg.TrustedPlatformModule
	tpmStorageFactory *tpm2store.StorageFactory
	tpmUnavailable    bool           // true after first probe found no TPM device
	tpmConfigOnce     sync.Once      // ensures config is loaded and logged once
	tpmCachedConfig   tpm2pkg.Config // config loaded by tpmConfigOnce

	// tpmAccessor serializes cross-service TPM access and coordinates
	// shutdown to prevent use-after-close panics.
	tpmAccessor *services.TPMAccessor

	// deviceNotifier is stored for runtime FIDO2 start/stop toggling.
	deviceNotifier notify.Notifier

	// ipcServer exposes autofill + PKCS#11 services to the native messaging
	// host and PKCS#11 module via Unix domain socket.
	ipcServer *ipc.Server

	tray    *TrayManager
	running atomic.Bool

	// trayQuit is set to true when the tray quit menu item initiates
	// shutdown. This allows beforeClose to permit the quit instead
	// of hiding the window when AutoTray is enabled.
	trayQuit atomic.Bool

	// shutdownOnce ensures the shutdown sequence runs exactly once,
	// whether triggered by Wails' OnShutdown callback or by Quit().
	shutdownOnce sync.Once

	// shutdownDone is closed when the shutdown sequence completes.
	shutdownDone chan struct{}

	// dataDir stores the initialized data directory path for getTPM and shutdown.
	dataDir string

	// configDirPath caches the resolved config directory (~/.config/xkey/).
	configDirPath string
}

// configToData converts gui.GUIConfig to services.GUIConfigData to avoid
// import cycles between the gui and services packages.
func configToData(cfg *GUIConfig) *services.GUIConfigData {
	return &services.GUIConfigData{
		AutoTray:                  cfg.AutoTray,
		Theme:                     cfg.Theme,
		StartMinimized:            cfg.StartMinimized,
		Notifications:             cfg.Notifications,
		WindowWidth:               cfg.WindowWidth,
		WindowHeight:              cfg.WindowHeight,
		RememberPosition:          cfg.RememberPosition,
		WindowX:                   cfg.WindowX,
		WindowY:                   cfg.WindowY,
		ServerAddress:             cfg.ServerAddress,
		ServerProtocol:            cfg.ServerProtocol,
		ServerTLSEnabled:          cfg.ServerTLSEnabled,
		ServerTLSSkipVerify:       cfg.ServerTLSSkipVerify,
		ServerTLSCAFile:           cfg.ServerTLSCAFile,
		ServerAutoConnect:         cfg.ServerAutoConnect,
		AutoUnsealEnabled:         cfg.AutoUnsealEnabled,
		AutoUnsealBlobID:          cfg.AutoUnsealBlobID,
		AutoUnsealPCRs:            cfg.AutoUnsealPCRs,
		AutoUnsealPCRBank:         cfg.AutoUnsealPCRBank,
		AutoUnsealPolicyType:      cfg.AutoUnsealPolicyType,
		AutoUnsealPolicyName:      cfg.AutoUnsealPolicyName,
		AutoUnsealBackend:         cfg.AutoUnsealBackend,
		FIDO2AuthenticatorEnabled: cfg.FIDO2AuthenticatorEnabled,
		ClipboardTimeout:          cfg.ClipboardTimeout,
		RequireAuth:               cfg.RequireAuth,
		AppAutoLockMinutes:        cfg.AppAutoLockMinutes,
		AppLockOnScreenLock:       cfg.AppLockOnScreenLock,
		SetupComplete:             cfg.SetupComplete,
		StorageType:               cfg.StorageType,
		BarrierInitialized:        cfg.BarrierInitialized,
		BarrierStrategy:           cfg.BarrierStrategy,
		BarrierAutoUnsealBlobID:   cfg.BarrierAutoUnsealBlobID,
		BarrierAutoUnsealEnabled:  cfg.BarrierAutoUnsealEnabled,
		SealerBackend:             cfg.SealerBackend,
		APIExplorerSandboxPolicy:  cfg.APIExplorerSandboxPolicy,
		BrowserExtensionEnabled:   cfg.BrowserExtensionEnabled,
		DeveloperTools:            cfg.DeveloperTools,
		FIDO2RequireUserPresence:  cfg.FIDO2RequireUserPresence,
		FIDO2UserIntentCheck:      cfg.FIDO2UserIntentCheck,
		AutoFillPolicy:            cfg.AutoFillPolicy,
	}
}

// dataToConfig converts services.GUIConfigData back to gui.GUIConfig.
func dataToConfig(d *services.GUIConfigData) *GUIConfig {
	return &GUIConfig{
		AutoTray:                  d.AutoTray,
		Theme:                     d.Theme,
		StartMinimized:            d.StartMinimized,
		Notifications:             d.Notifications,
		WindowWidth:               d.WindowWidth,
		WindowHeight:              d.WindowHeight,
		RememberPosition:          d.RememberPosition,
		WindowX:                   d.WindowX,
		WindowY:                   d.WindowY,
		ServerAddress:             d.ServerAddress,
		ServerProtocol:            d.ServerProtocol,
		ServerTLSEnabled:          d.ServerTLSEnabled,
		ServerTLSSkipVerify:       d.ServerTLSSkipVerify,
		ServerTLSCAFile:           d.ServerTLSCAFile,
		ServerAutoConnect:         d.ServerAutoConnect,
		AutoUnsealEnabled:         d.AutoUnsealEnabled,
		AutoUnsealBlobID:          d.AutoUnsealBlobID,
		AutoUnsealPCRs:            d.AutoUnsealPCRs,
		AutoUnsealPCRBank:         d.AutoUnsealPCRBank,
		AutoUnsealPolicyType:      d.AutoUnsealPolicyType,
		AutoUnsealPolicyName:      d.AutoUnsealPolicyName,
		AutoUnsealBackend:         d.AutoUnsealBackend,
		FIDO2AuthenticatorEnabled: d.FIDO2AuthenticatorEnabled,
		ClipboardTimeout:          d.ClipboardTimeout,
		RequireAuth:               d.RequireAuth,
		AppAutoLockMinutes:        d.AppAutoLockMinutes,
		AppLockOnScreenLock:       d.AppLockOnScreenLock,
		SetupComplete:             d.SetupComplete,
		StorageType:               d.StorageType,
		BarrierInitialized:        d.BarrierInitialized,
		BarrierStrategy:           d.BarrierStrategy,
		BarrierAutoUnsealBlobID:   d.BarrierAutoUnsealBlobID,
		SealerBackend:             d.SealerBackend,
		BarrierAutoUnsealEnabled:  d.BarrierAutoUnsealEnabled,
		APIExplorerSandboxPolicy:  d.APIExplorerSandboxPolicy,
		BrowserExtensionEnabled:   d.BrowserExtensionEnabled,
		DeveloperTools:            d.DeveloperTools,
		FIDO2RequireUserPresence:  d.FIDO2RequireUserPresence,
		FIDO2UserIntentCheck:      d.FIDO2UserIntentCheck,
		AutoFillPolicy:            d.AutoFillPolicy,
	}
}

// dataDir returns the path to the xKey data directory via unified path
// resolution. The directory is created with 0700 permissions if it does
// not exist.
func dataDir() (string, error) {
	h, err := xhome.Resolve()
	if err != nil {
		return "", err
	}
	return h.EnsureDataDir()
}

// BackendRegistry returns the application's backend registry. It is safe
// for concurrent use and never returns nil after NewApp.
func (a *App) BackendRegistry() backendregistry.Registry {
	return a.backendRegistry
}

// populateBackendRegistry loads the unified config and registers backends
// in the registry. When no BackendsConfig is present, it auto-creates a
// single software backend from the legacy Backend.Default field.
func (a *App) populateBackendRegistry() {
	ucfg, err := config.Load()
	if err != nil {
		// Unified config may not exist (first run). Register a minimal
		// software backend so the registry is never empty.
		a.log.Debug("unified config not available, registering software backend", "error", err)
		a.registerDefaultSoftwareBackend()
		return
	}

	// Auto-populate backends from legacy config if the section is empty.
	ucfg.AutoPopulateBackends()

	registered := 0

	for _, lb := range ucfg.Backends.Local {
		cat := backendregistry.BackendCategory(lb.Category)
		caps := defaultCapabilities(cat)

		backend := &backendregistry.RegisteredBackend{
			ID:           lb.ID,
			Location:     backendregistry.LocationLocal,
			Category:     cat,
			DisplayName:  lb.Name,
			Capabilities: caps,
			Metadata:     make(map[string]string),
		}

		// PKCS#11 backends require PIN authentication before they are usable,
		// so they start offline. Other local backends (software) are ready
		// immediately.
		if cat == backendregistry.CategoryPKCS11 {
			backend.SetState(backendregistry.StateOffline)
		} else {
			backend.SetState(backendregistry.StateReady)
		}

		if regErr := a.backendRegistry.Register(backend); regErr != nil {
			a.log.Warn("failed to register local backend", "id", lb.ID, "error", regErr)
			continue
		}
		registered++
	}

	for _, rb := range ucfg.Backends.Remote {
		backend := &backendregistry.RegisteredBackend{
			ID:          rb.ID,
			Location:    backendregistry.LocationRemote,
			Category:    backendregistry.CategoryXKMS,
			DisplayName: rb.Name,
			Capabilities: map[backendregistry.Capability]bool{
				backendregistry.CapSigning:    true,
				backendregistry.CapEncryption: true,
				backendregistry.CapPasswords:  true,
				backendregistry.CapPIV:        true,
			},
			Metadata: map[string]string{
				"address":  rb.Address,
				"protocol": rb.Protocol,
			},
		}
		backend.SetState(backendregistry.StateOffline)

		if regErr := a.backendRegistry.Register(backend); regErr != nil {
			a.log.Warn("failed to register remote backend", "id", rb.ID, "error", regErr)
			continue
		}
		registered++
	}

	// Apply configured defaults.
	for cap, backendID := range ucfg.Backends.Defaults {
		if setErr := a.backendRegistry.SetDefault(
			backendregistry.Capability(cap), backendID,
		); setErr != nil {
			a.log.Warn("failed to set default backend", "capability", cap, "backend", backendID, "error", setErr)
		}
	}

	// Always register the software backend. It provides local key generation,
	// PIV certificates, FIDO2, passwords, and other core features that must
	// be available regardless of which hardware backends are configured.
	a.registerDefaultSoftwareBackend()

	a.log.Info("backend registry populated", "configured", registered, "software_always", true)
}

// registerDefaultSoftwareBackend ensures the software backend is always
// present in the registry. Software provides core features (local key
// generation, PIV, FIDO2, passwords) that must always be available.
func (a *App) registerDefaultSoftwareBackend() {
	// Check if already registered (e.g., from unified config).
	if _, err := a.backendRegistry.Get("software"); err == nil {
		return // already registered
	}

	backend := &backendregistry.RegisteredBackend{
		ID:           "software",
		Location:     backendregistry.LocationLocal,
		Category:     backendregistry.CategorySoftware,
		DisplayName:  "Local Software",
		Capabilities: defaultCapabilities(backendregistry.CategorySoftware),
		Metadata:     make(map[string]string),
	}
	backend.SetState(backendregistry.StateReady)

	if err := a.backendRegistry.Register(backend); err != nil {
		a.log.Error("failed to register default software backend", "error", err)
	}
}

// defaultCapabilities returns a default capability set for the given
// backend category. Additional capabilities can be discovered at runtime
// (e.g., after PKCS#11 token enumeration).
func defaultCapabilities(cat backendregistry.BackendCategory) map[backendregistry.Capability]bool {
	caps := map[backendregistry.Capability]bool{
		backendregistry.CapSigning:    true,
		backendregistry.CapEncryption: true,
	}
	switch cat {
	case backendregistry.CategorySoftware:
		caps[backendregistry.CapFIDO2] = true
		caps[backendregistry.CapOATH] = true
		caps[backendregistry.CapPasswords] = true
		caps[backendregistry.CapSealing] = true
		caps[backendregistry.CapPIV] = true
	case backendregistry.CategoryTPM2:
		caps[backendregistry.CapFIDO2] = true
		caps[backendregistry.CapSealing] = true
		caps[backendregistry.CapAttestation] = true
		caps[backendregistry.CapPasswords] = true
		caps[backendregistry.CapPIV] = true
	case backendregistry.CategoryPKCS11:
		caps[backendregistry.CapFIDO2] = true
		caps[backendregistry.CapPIV] = true
		caps[backendregistry.CapSealing] = true
		caps[backendregistry.CapOATH] = true
		caps[backendregistry.CapPasswords] = true
	case backendregistry.CategoryPhone:
		caps[backendregistry.CapFIDO2] = true
		caps[backendregistry.CapAttestation] = true
	}
	return caps
}

// restorePKCS11Modules re-registers PKCS#11 modules from the persisted
// config with the PKCS#11 service manager so they are available after restart.
func (a *App) restorePKCS11Modules() {
	ucfg, err := config.Load()
	if err != nil {
		a.log.Debug("restorePKCS11Modules: config not available", "error", err)
		return
	}

	restored := 0
	for _, lb := range ucfg.Backends.Local {
		if lb.Category != "pkcs11" || lb.PKCS11 == nil || lb.PKCS11.LibraryPath == "" {
			continue
		}
		// RegisterModule handles SoftHSM2 auto-config and idempotent re-registration.
		// We call the manager directly (not PKCS11Service.RegisterModule) to avoid
		// re-persisting to config on startup.
		if a.pkcs11Service != nil {
			if _, regErr := a.pkcs11Service.RegisterModuleFromConfig(lb.ID, lb.PKCS11.LibraryPath, lb.Name); regErr != nil {
				a.log.Warn("failed to restore PKCS#11 module from config",
					"id", lb.ID, "library", lb.PKCS11.LibraryPath, "error", regErr)
				continue
			}
			restored++
		}
	}

	if restored > 0 {
		a.log.Info("PKCS#11 modules restored from config", "count", restored)
	}
}

// initLocalPIV initializes the local PIV manager. When barrierBackend
// is non-nil, PIV certificates are stored through the barrier with a
// "piv/" prefix for transparent AES-256-GCM encryption. When
// barrierBackend is nil, a plain filestorage backend is created under
// the given data directory.
//
// Each backend gets its own namespaced PIV certificate store so that
// certificates from one backend (e.g., "software") do not appear when
// listing another (e.g., "tpm2"). The "software" backend uses the root
// storage path for backward compatibility with existing certificates.
// All other backends store certificates under "backends/{category}/".
//
// Stores are registered under both the registry ID and the category
// name so that lookups from the GUI (registry IDs) and from xkms
// (category names) both succeed.
func initLocalPIV(log *slog.Logger, dir string, barrierBackend storage.Backend,
	backendIDs []string, registry backendregistry.Registry) (pivcert.PIVCertificateStorage, storage.Backend, bool) {
	if dir == "" {
		return nil, nil, false
	}

	var pivBackend storage.Backend
	if barrierBackend != nil {
		pivBackend = barrierBackend
	} else {
		pivDir := filepath.Join(dir, "piv")
		if err := os.MkdirAll(pivDir, 0700); err != nil {
			log.Warn("failed to create PIV data directory", "error", err)
			return nil, nil, false
		}

		fb, err := filestorage.New(pivDir)
		if err != nil {
			log.Warn("failed to create PIV storage backend", "error", err)
			return nil, nil, false
		}
		pivBackend = fb
	}

	// The software backend uses the root path (no prefix) for backward
	// compatibility with certificates stored before per-backend namespacing.
	pivFileStore, err := pivfile.NewFileBackend(&pivcert.FileStorageConfig{
		Backend:    pivBackend,
		DEREnabled: true,
		PEMEnabled: true,
	})
	if err != nil {
		log.Warn("failed to create PIV file store", "error", err)
		if barrierBackend == nil {
			closeBackend(log, pivBackend)
		}
		return nil, nil, false
	}

	// Create per-backend PIV stores with namespaced storage paths.
	// The software backend reuses the root-level store for backward
	// compatibility. Other backends (tpm2, pkcs11, etc.) get isolated
	// namespaces under "backends/{category}/" so certificates from one
	// backend never appear when listing another.
	stores := make(map[string]pivcert.PIVCertificateStorage, len(backendIDs)*2)
	for _, id := range backendIDs {
		cat := id
		if registry != nil {
			if rb, regErr := registry.Get(id); regErr == nil {
				cat = string(rb.Category)
			}
		}

		// Software backend uses root path (backward compatible).
		if cat == "software" {
			stores[id] = pivFileStore
			if cat != id {
				stores[cat] = pivFileStore
			}
			continue
		}

		// PKCS#11 backends get on-device cert storage when the user
		// connects the token (via the connect hook). At init time we
		// use file storage as a placeholder.

		// Other backends get a namespaced store.
		ns, nsErr := storage.NewPrefixBackend(pivBackend, "backends/"+cat+"/")
		if nsErr != nil {
			log.Warn("failed to create namespaced PIV backend, using shared store",
				"backend", id, "category", cat, "error", nsErr)
			stores[id] = pivFileStore
			if cat != id {
				stores[cat] = pivFileStore
			}
			continue
		}

		nsStore, nsStoreErr := pivfile.NewFileBackend(&pivcert.FileStorageConfig{
			Backend:    ns,
			DEREnabled: true,
			PEMEnabled: true,
		})
		if nsStoreErr != nil {
			log.Warn("failed to create namespaced PIV store, using shared store",
				"backend", id, "category", cat, "error", nsStoreErr)
			stores[id] = pivFileStore
			if cat != id {
				stores[cat] = pivFileStore
			}
			continue
		}

		stores[id] = nsStore
		if cat != id {
			stores[cat] = nsStore
		}
	}

	// Always ensure "software" is registered as a fallback.
	if _, ok := stores["software"]; !ok {
		stores["software"] = pivFileStore
	}

	// Factory for creating PIV stores on demand when a backend is requested
	// that wasn't pre-registered (e.g., PKCS#11 modules added via admin area).
	storeFactory := func(backendName string) (pivcert.PIVCertificateStorage, error) {
		if backendName == "software" || backendName == "" {
			return pivFileStore, nil
		}

		// PKCS#11 backends get on-device cert storage when the connect
		// hook fires; the store factory returns file storage as a fallback.

		ns, nsErr := storage.NewPrefixBackend(pivBackend, "backends/"+backendName+"/")
		if nsErr != nil {
			return nil, nsErr
		}
		return pivfile.NewFileBackend(&pivcert.FileStorageConfig{
			Backend:    ns,
			DEREnabled: true,
			PEMEnabled: true,
		})
	}

	if err := xkms.InitializePIV(&xkms.PIVManagerConfig{
		Stores:       stores,
		StoreFactory: storeFactory,
	}); err != nil {
		log.Warn("failed to initialize PIV manager", "error", err)
		return nil, nil, false
	}

	log.Info("local PIV storage initialized", "dir", dir,
		"barrier_active", barrierBackend != nil, "backends", len(stores))
	return pivFileStore, pivBackend, true
}

// closeBackend is a helper that closes a storage.Backend and logs any error.
func closeBackend(log *slog.Logger, b storage.Backend) {
	if err := b.Close(); err != nil {
		log.Warn("failed to close storage backend", "error", err)
	}
}

// initializeDataDir creates the data directory structure and opens all
// file-backed stores, wiring them to the services that were constructed
// with nil stores. This must be called AFTER the LUKS/storage decision
// so that ~/.xkey/data/ is created on the correct filesystem.
func (a *App) initializeDataDir() error {
	if a.dataDir != "" {
		return ErrDataDirAlreadyInit
	}

	dir, err := dataDir()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDataDirInit, err)
	}
	a.dataDir = dir

	// Get barrier backend (nil if barrier not active).
	barrierBackend := a.barrierService.GetBackend()

	// OATH store — encrypted via barrier or plain file fallback.
	if barrierBackend != nil {
		oathStore, oathErr := oath.NewBackendStore(barrierBackend, "oath/")
		if oathErr != nil {
			a.log.Warn("failed to create OATH backend store", "error", oathErr)
		} else {
			a.oathStore = oathStore
			a.oathService.SetStore(oathStore)
		}
	} else {
		oathStore, oathErr := oath.NewFileStore(filepath.Join(dir, "oath.json"))
		if oathErr != nil {
			a.log.Warn("failed to open OATH store", "error", oathErr)
		} else {
			a.oathStore = oathStore
			a.oathService.SetStore(oathStore)
		}
	}

	// FIDO2 credential storage — encrypted via barrier or plain file fallback.
	if barrierBackend != nil {
		fido2Storage, fErr := authenticator.NewBackendStorage(barrierBackend, "fido2/xkey/")
		if fErr != nil {
			a.log.Warn("failed to open FIDO2 storage", "error", fErr)
		} else {
			a.fido2Storage = fido2Storage
			a.fido2Service.SetStorage(fido2Storage)
		}
	} else {
		fido2Backend, fErr := filestorage.New(filepath.Join(dir, "fido2"))
		if fErr != nil {
			a.log.Warn("failed to create FIDO2 storage backend", "error", fErr)
		} else {
			fido2Storage, f2Err := authenticator.NewBackendStorage(fido2Backend, "xkey/")
			if f2Err != nil {
				a.log.Warn("failed to open FIDO2 storage", "error", f2Err)
			} else {
				a.fido2Storage = fido2Storage
				a.fido2Service.SetStorage(fido2Storage)
			}
		}
	}

	// FIDO2 RP policy store — encrypted via barrier or plain file fallback.
	if barrierBackend != nil {
		rpPolicyStore, rpErr := authenticator.NewBackendRPPolicyStore(barrierBackend, "fido2/authenticator/rp-policies/")
		if rpErr != nil {
			a.log.Warn("failed to create FIDO2 RP policy store", "error", rpErr)
		} else {
			a.fido2Service.SetRPPolicyStore(rpPolicyStore)
		}
	} else {
		rpBackend, rpErr := filestorage.New(filepath.Join(dir, "fido2"))
		if rpErr != nil {
			a.log.Warn("failed to create FIDO2 RP policy backend", "error", rpErr)
		} else {
			rpPolicyStore, rp2Err := authenticator.NewBackendRPPolicyStore(rpBackend, "xkey/rp-policies/")
			if rp2Err != nil {
				a.log.Warn("failed to create FIDO2 RP policy store", "error", rp2Err)
			} else {
				a.fido2Service.SetRPPolicyStore(rpPolicyStore)
			}
		}
	}

	// Static password storage — encrypted via barrier or plain file fallback.
	if barrierBackend != nil {
		spwStore := staticpw.NewStore(barrierBackend)
		a.staticpwStore = spwStore
		a.staticPWService.SetStore(spwStore)
		a.log.Info("static password store using barrier backend")
	} else {
		spwBackend, spwErr := filestorage.New(filepath.Join(dir, "passwords"))
		if spwErr != nil {
			a.log.Warn("failed to create password file store", "error", spwErr)
		} else {
			spwStore := staticpw.NewStore(spwBackend)
			a.staticpwStore = spwStore
			a.staticPWService.SetStore(spwStore)
			a.log.Info("static password store using file backend (no barrier)")
		}
	}

	// Team store for password sharing — uses barrier backend when available,
	// falls back to file backend otherwise.
	{
		var teamBackend storage.Backend
		if barrierBackend != nil {
			teamBackend = barrierBackend
		} else {
			fb, fbErr := filestorage.New(filepath.Join(dir, "teams"))
			if fbErr != nil {
				a.log.Warn("failed to create team file store", "error", fbErr)
			} else {
				teamBackend = fb
			}
		}
		if teamBackend != nil {
			kvStore, kvErr := kvadapter.New(teamBackend)
			if kvErr != nil {
				a.log.Warn("failed to create team kv adapter", "error", kvErr)
			} else {
				teamStore, tsErr := staticpw.NewDAOTeamStore(kvStore)
				if tsErr != nil {
					a.log.Warn("failed to create team store", "error", tsErr)
				} else {
					a.teamService.SetStore(teamStore)
					a.log.Info("team store initialized")
				}
			}
		}
	}

	// Trust store for trusted CA certificates -- encrypted via barrier or plain file fallback.
	if barrierBackend != nil {
		ts, tsErr := truststore.NewBackendStore(barrierBackend, "trust/")
		if tsErr != nil {
			a.log.Warn("failed to create trust backend store", "error", tsErr)
		} else {
			a.trustStore = ts
			a.trustService.SetStore(ts)
			a.tpmService.SetTrustStore(ts)
			a.phoneService.SetTrustStore(ts)
			a.log.Info("trust store using barrier backend")
		}
	} else {
		trustStorePath := filepath.Join(dir, "trust")
		ts, tsErr := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: trustStorePath})
		if tsErr != nil {
			a.log.Warn("failed to open trust store", "error", tsErr)
		} else {
			a.trustStore = ts
			a.trustService.SetStore(ts)
			a.tpmService.SetTrustStore(ts)
			a.phoneService.SetTrustStore(ts)
		}
	}

	// Export browser trust bundle from the trust store. Bootstrap CA
	// certificates and any certs tagged "browser-export" are written as a
	// PEM bundle to ~/.xkey/data/browser/trust-bundle.pem. The browser
	// service uses this bundle to set SSL_CERT_FILE when launching browsers.
	browserBundlePath := filepath.Join(dir, "browser", "trust-bundle.pem")
	if a.browserService != nil {
		a.browserService.SetTrustBundlePath(browserBundlePath)

		// Only generate the bundle on startup if the user has opted in.
		browserCfg := a.browserService.GetConfig()
		if browserCfg.IncludeTrustBundle {
			if count, bundleErr := a.trustService.ExportBrowserTrustBundle(browserBundlePath); bundleErr != nil {
				a.log.Warn("failed to export browser trust bundle", "error", bundleErr)
			} else if count > 0 {
				a.log.Info("exported browser trust bundle", "certs", count, "path", browserBundlePath)
			}
		}
	}

	// Wire TPM data directory for handle descriptions and CA storage.
	a.tpmService.SetDataDir(dir)

	// OIDC storage — encrypted via barrier or plain file fallback.
	if barrierBackend != nil {
		if oidcErr := a.oidcService.SetBackend(barrierBackend, "oidc/"); oidcErr != nil {
			a.log.Warn("failed to set OIDC barrier backend", "error", oidcErr)
		}
	} else {
		oidcDataDir := filepath.Join(dir, "oidc")
		if mkErr := os.MkdirAll(oidcDataDir, 0700); mkErr != nil {
			a.log.Warn("failed to create OIDC data directory", "error", mkErr)
		} else {
			a.oidcService.SetDataDir(oidcDataDir)
		}
	}

	// Share storage — encrypted via barrier or plain file fallback.
	if barrierBackend != nil {
		ss, ssErr := sharestore.NewBackendShareStore(barrierBackend, "shares/")
		if ssErr != nil {
			a.log.Warn("failed to create share backend store", "error", ssErr)
		} else {
			a.shareService.SetShareStore(ss)
		}
	} else {
		shareDataDir := filepath.Join(dir, "shares")
		if mkErr := os.MkdirAll(shareDataDir, 0700); mkErr != nil {
			a.log.Warn("failed to create share data directory", "error", mkErr)
		} else {
			shareBackend, sbErr := filestorage.New(shareDataDir)
			if sbErr != nil {
				a.log.Warn("failed to create share file backend", "error", sbErr)
			} else {
				ss, ssErr := sharestore.NewBackendShareStore(shareBackend, "")
				if ssErr != nil {
					a.log.Warn("failed to create share file store", "error", ssErr)
				} else {
					a.shareService.SetShareStore(ss)
				}
			}
		}
	}

	// PIV storage — encrypted via barrier or plain file fallback.
	// Collect all local backend IDs with PIV capability so the cert
	// store is registered for each, enabling backend switching.
	var pivBackendIDs []string
	for _, b := range a.backendRegistry.ListByCapability(backendregistry.CapPIV) {
		if b.Location == backendregistry.LocationLocal {
			pivBackendIDs = append(pivBackendIDs, b.ID)
		}
	}
	pivFileStore, pivStorageBE, pivOK := initLocalPIV(a.log, dir, barrierBackend, pivBackendIDs, a.backendRegistry)
	if pivOK {
		a.pivService.SetLocalEnabled(true)
		a.pivFileStore = pivFileStore
		a.pivStorageBE = pivStorageBE
	}

	// Relocate sealed blob storage from config dir to data dir.
	newSealDir := filepath.Join(dir, "sealed")
	legacyCfgSealDir := ""
	if a.configDirPath != "" {
		legacyCfgSealDir = filepath.Join(a.configDirPath, "sealed")
	}
	if err := a.sealService.SetStorageDir(newSealDir); err != nil {
		a.log.Warn("failed to set seal storage directory", "dir", newSealDir, "error", err)
	}
	// Route sealed blob storage through the barrier when active.
	if barrierBackend != nil {
		a.sealService.SetBackend(barrierBackend, "sealed/")
		a.log.Info("sealed blob store using barrier backend")
	}
	if legacyCfgSealDir != "" {
		if migrated, migErr := a.sealService.MigrateFrom(legacyCfgSealDir); migErr != nil {
			a.log.Warn("failed to migrate sealed blobs from config dir",
				"from", legacyCfgSealDir, "error", migErr)
		} else if migrated > 0 {
			a.log.Info("migrated sealed blobs from config dir to data dir",
				"from", legacyCfgSealDir, "to", newSealDir, "count", migrated)
		}
	}

	// Audit store — migrate to barrier-encrypted persistence.
	if barrierBackend != nil {
		if migrateErr := a.auditStore.MigrateBackend(barrierBackend); migrateErr != nil {
			a.log.Warn("failed to migrate audit store to barrier", "error", migrateErr)
		} else {
			a.log.Info("audit store migrated to barrier backend")
		}
	}

	// Migrate old barrier data from config dir to data dir.
	a.migrateBarrierData()

	// NOTE: PIN service is initialized in postDataDirStartup(), which always
	// follows initializeDataDir() in all call paths. No need to call it here.

	// Initialize local key store via embedded SDK.
	// This provides in-process key management without a remote server connection.
	a.initLocalKeyStore(dir)

	// Initialize shared FIDO2 authenticator for autofill CTAP2 authentication.
	// This authenticator is shared between the USB HID virtual device and the
	// browser extension autofill service, so both use the same credentials,
	// PIN, and key backend.
	a.initializeAuthenticator()

	// Initialize pairing verifier for extension identity binding.
	pairingDir := filepath.Join(dir, "extension")
	if mkErr := os.MkdirAll(pairingDir, 0700); mkErr != nil {
		a.log.Warn("failed to create extension pairing directory", "error", mkErr)
	} else {
		pairingStatePath := filepath.Join(pairingDir, "pairing.json")
		verifier, vErr := nativemsg.NewPairingVerifier(pairingStatePath)
		if vErr != nil {
			a.log.Warn("failed to create pairing verifier", "error", vErr)
		} else {
			a.pairingService.SetVerifier(verifier)
			a.log.Info("extension pairing verifier initialized", "state_path", pairingStatePath)
		}
	}

	a.log.Info("data directory initialized", "dir", dir,
		"barrier_active", barrierBackend != nil)
	return nil
}

// initializeAuthenticator creates a shared FIDO2 authenticator instance and
// wires it to both the FIDO2 device service (USB HID) and the autofill service
// (CTAP2 challenge-response). The authenticator uses the FIDO2 storage that was
// already initialized in initializeDataDir(), so credentials and PIN state are
// shared across all consumers.
func (a *App) initializeAuthenticator() {
	if a.fido2Storage == nil {
		a.log.Warn("cannot initialize authenticator: FIDO2 storage unavailable")
		return
	}

	// Read FIDO2 settings from GUI config, with secure defaults.
	requireUP := true
	enableIntentCheck := false
	if a.config != nil {
		requireUP = a.config.FIDO2RequireUserPresence
		enableIntentCheck = a.config.FIDO2UserIntentCheck
	}

	// Initialize the composite FIDO2 key backend. Backends are registered from
	// the go-xkms service via BackendAdapter, which delegates all crypto to the
	// existing KeyProvider implementations. No per-backend FIDO2 code needed.
	composite := keybackend.NewCompositeBackend(types.BackendTypeSoftware)
	a.fido2KeyBackend = composite

	// Register all available go-xkms backends as FIDO2 key backends.
	// When barrier auto-unseal is enabled, wrap each adapter with AutoUVBackend
	// so the authenticator reports built-in user verification (uv=true),
	// allowing Chrome to skip its PIN dialog.
	var autoUVProvider keybackend.BarrierStateProvider
	if a.config.BarrierAutoUnsealEnabled {
		autoUVProvider = &barrierAutoUVProvider{barrier: a.barrierService}
		a.log.Info("auto-UV enabled: FIDO2 backends will report built-in user verification")
	}

	if swBackend, swErr := xkms.GetBackend("software"); swErr == nil {
		adapter := keybackend.NewBackendAdapter(swBackend.KeyProvider(), types.BackendTypeSoftware)
		adapter.SetLogger(a.log)
		var backend keybackend.FIDO2KeyBackend = adapter
		if autoUVProvider != nil {
			backend = keybackend.NewAutoUVBackend(adapter, autoUVProvider)
		}
		composite.Register(types.BackendTypeSoftware, backend)
	}
	if tpm2Backend, tpmErr := xkms.GetBackend("tpm2"); tpmErr == nil {
		adapter := keybackend.NewBackendAdapter(tpm2Backend.KeyProvider(), types.BackendTypeTPM2)
		adapter.SetLogger(a.log)
		var backend keybackend.FIDO2KeyBackend = adapter
		if autoUVProvider != nil {
			backend = keybackend.NewAutoUVBackend(adapter, autoUVProvider)
		}
		composite.Register(types.BackendTypeTPM2, backend)
		a.log.Info("FIDO2 TPM2 key backend registered")
	}

	a.log.Info("FIDO2 composite key backend initialized",
		"default", types.BackendTypeSoftware,
		"backends", composite.Backends())

	// AAGUID: UUIDv5(DNS, "xkey.automatethethings.com") = 5150e208-1ab8-5162-bc67-f5e4f24adefa
	xkeyAAGUID := [16]byte{
		0x51, 0x50, 0xE2, 0x08, 0x1A, 0xB8, 0x51, 0x62,
		0xBC, 0x67, 0xF5, 0xE4, 0xF2, 0x4A, 0xDE, 0xFA,
	}

	auth, err := authenticator.NewAuthenticator(&authenticator.Config{
		Storage:                    a.fido2Storage,
		KeyBackend:                 composite,
		AAGUID:                     xkeyAAGUID,
		EnablePIN:                  true,
		EnableResidentKey:          true,
		EnableCredentialManagement: true,
		EnableHMACSecret:           true,
		RequireUserPresence:        requireUP,
		EnableUserIntentCheck:      enableIntentCheck,
		FirmwareVersion:            a.config.FIDO2FirmwareVersion,
		Logger:                     a.log,
	})
	if err != nil {
		a.log.Warn("failed to create shared authenticator", "error", err)
		return
	}

	a.authenticatorInstance = auth

	// Wire the composite key backend to the FIDO2 service so the frontend
	// can switch the default backend for new credential creation.
	a.fido2Service.SetKeyBackend(composite)

	// Wire to FIDO2 device service so USB HID uses the same authenticator.
	a.fido2DeviceService.SetAuthenticator(auth)

	// Wire to autofill service for CTAP2 challenge-response authentication.
	a.autofillService.SetAuthenticator(auth)

	// Set autofill registration directory for credential persistence.
	if a.dataDir != "" {
		regDir := filepath.Join(a.dataDir, "extension", "autofill")
		if mkErr := os.MkdirAll(regDir, 0700); mkErr != nil {
			a.log.Warn("failed to create autofill registration dir", "error", mkErr)
		} else {
			a.autofillService.SetRegistrationDir(regDir)
		}
	}

	// Apply SO enterprise policy overrides for FIDO2 settings.
	if a.configDirPath != "" && config.IsEnterpriseMode(a.configDirPath) {
		ucfg, loadErr := config.Load()
		if loadErr == nil {
			pol := ucfg.Policy
			auth.SetRequireUserPresence(pol.FIDO2RequireUserPresence)
			auth.SetEnableUserIntentCheck(pol.FIDO2UserIntentCheck)
			a.log.Info("enterprise FIDO2 policy applied",
				"require_user_presence", pol.FIDO2RequireUserPresence,
				"user_intent_check", pol.FIDO2UserIntentCheck)
		}
	}

	// Wire PINVerifier so the authenticator delegates PIN state queries
	// to the pin.Service (single source of truth) instead of internal state.
	auth.SetPINVerifier(a.pinService)
	aaguid := auth.AAGUID()
	a.log.Info("shared FIDO2 authenticator initialized",
		"require_user_presence", auth.Config().RequireUserPresence,
		"user_intent_check", auth.Config().EnableUserIntentCheck,
		"aaguid", fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
			aaguid[0:4], aaguid[4:6], aaguid[6:8], aaguid[8:10], aaguid[10:16]),
		"firmware_version", auth.Config().FirmwareVersion)
}

// initLocalKeyStore sets up the embedded SDK client for local key management.
// It loads backend-specific settings from the unified config (TPM2 device path,
// PKCS#11 library path, etc.) so that AutoInitialize can successfully create
// hardware backends for PIV key generation.
func (a *App) initLocalKeyStore(dataDir string) {
	keysDir := filepath.Join(dataDir, "keys")

	xkms.Reset()

	backendConfigs := a.buildXKMSBackendConfigs()

	if err := xkms.AutoInitialize(&xkms.AutoConfig{
		DataDir:        keysDir,
		DefaultBackend: "software",
		BackendConfigs: backendConfigs,
	}); err != nil {
		a.log.Warn("failed to initialize local key store", "error", err)
		return
	}

	svc, err := xkms.Get()
	if err != nil {
		a.log.Warn("failed to get xkms service for local key store", "error", err)
		return
	}

	localClient, err := xkmssdk.NewEmbedded(svc)
	if err != nil {
		a.log.Warn("failed to create embedded SDK client", "error", err)
		return
	}

	// Replace the xkms TPM2 backend's TPM instance with the shared GUI TPM.
	// AutoInitialize creates a separate TPM2 connection with its own config,
	// PlatformKeyStore, and policy state. This causes policy digest mismatches
	// (TPM_RC_POLICY_FAIL) because the SRK's compound policy was computed
	// using the GUI TPM's PCR config. By sharing the same TPM instance, all
	// seal/unseal operations use identical policy state and SRK auth.
	if tpm2Backend, gbErr := xkms.GetBackend("tpm2"); gbErr == nil && tpm2Backend != nil {
		if kp := tpm2Backend.KeyProvider(); kp != nil {
			if concrete, ok := kp.(*backendtpm2.Backend); ok {
				sharedTPM, tpmErr := a.tpmAccessor.Acquire()
				if tpmErr == nil {
					a.tpmAccessor.Release()
					concrete.SetTPM(sharedTPM)
					a.log.Info("xkms TPM2 backend now uses shared GUI TPM instance")
				}
			}
		}
	}

	a.keyService.SetLocalClient(localClient)
	a.sealService.SetLocalClient(localClient)
	a.sealService.AutoSelectDefault()

	// Wire the PIV backend resolver so PIV key generation uses the
	// actual configured backends (software, TPM2, PKCS11) instead of
	// falling back to software-only generation.
	if err := svc.InitPIVBackendResolver(); err != nil {
		a.log.Warn("failed to initialize PIV backend resolver", "error", err)
	}

	// Register PIV stores for all xkms backends that aren't already in the
	// PIV manager. The GUI backend registry may only contain "software", but
	// AutoInitialize may have successfully created TPM2/PKCS11 backends that
	// need PIV stores for certificate operations. Each non-software backend
	// gets a namespaced store under "backends/{name}/" for certificate isolation.
	if a.pivStorageBE != nil {
		for _, name := range xkms.Backends() {
			if name == "software" {
				// Software uses the root path (backward compatible).
				if a.pivFileStore != nil {
					_ = xkms.RegisterPIVStore(name, a.pivFileStore)
				}
				continue
			}
			ns, nsErr := storage.NewPrefixBackend(a.pivStorageBE, "backends/"+name+"/")
			if nsErr != nil {
				a.log.Warn("failed to create namespaced PIV store", "backend", name, "error", nsErr)
				continue
			}
			nsStore, storeErr := pivfile.NewFileBackend(&pivcert.FileStorageConfig{
				Backend:    ns,
				DEREnabled: true,
				PEMEnabled: true,
			})
			if storeErr != nil {
				a.log.Warn("failed to create PIV file store for backend", "backend", name, "error", storeErr)
				continue
			}
			if regErr := xkms.RegisterPIVStore(name, nsStore); regErr != nil {
				a.log.Debug("PIV store registration failed", "backend", name, "error", regErr)
			} else {
				a.log.Info("registered namespaced PIV store for xkms backend", "backend", name)
			}
		}
	}

	a.log.Info("local key store initialized", "dir", keysDir)
}

// registerPKCS11XKMSBackend dynamically creates and registers a PKCS#11 backend
// with the xkms service. Called when a PKCS#11 token is connected via the admin
// area so PIV key generation and key operations can use the hardware token.
func (a *App) registerPKCS11XKMSBackend(libraryPath string, slotID uint, userPIN, soPin, tokenLabel string) {
	if !xkms.IsInitialized() {
		a.log.Warn("cannot register PKCS#11 xkms backend: xkms not initialized")
		return
	}

	// Check if already registered.
	if _, err := xkms.GetBackend("pkcs11"); err == nil {
		a.log.Debug("PKCS#11 xkms backend already registered")
		return
	}

	factory, ok := xkms.GetBackendFactory(xkms.BackendPKCS11)
	if !ok {
		a.log.Warn("PKCS#11 backend factory not registered")
		return
	}

	cfg := map[string]interface{}{
		"library": libraryPath,
		"slot":    int(slotID),
	}
	if tokenLabel != "" {
		cfg["label"] = tokenLabel
	}
	if userPIN != "" {
		cfg["pin"] = userPIN
	}
	if soPin != "" {
		cfg["so_pin"] = soPin
	}

	// Set key_dir for PKCS#11 key storage.
	if a.dataDir != "" {
		cfg["key_dir"] = filepath.Join(a.dataDir, "keys", "pkcs11")
	}

	kp, err := factory(cfg)
	if err != nil {
		a.log.Warn("failed to create PKCS#11 key provider", "error", err)
		return
	}

	// The factory creates the backend but doesn't authenticate.
	// Login establishes the PKCS#11 session required for all operations.
	type loginer interface{ Login() error }
	if l, ok := kp.(loginer); ok {
		if loginErr := l.Login(); loginErr != nil {
			a.log.Warn("failed to login to PKCS#11 token", "error", loginErr)
			return
		}
	}

	// Create cert storage at the same location used by AutoInitialize.
	keysDir := filepath.Join(a.dataDir, "keys")
	certDir := filepath.Join(keysDir, "certs")
	certStore, csErr := filestorage.New(certDir)
	if csErr != nil {
		a.log.Warn("failed to create cert storage for PKCS#11 backend", "error", csErr)
		return
	}

	ks, ksErr := xkms.New(&xkms.BackendConfig{
		Backend:     kp,
		CertStorage: certStore,
	})
	if ksErr != nil {
		a.log.Warn("failed to create PKCS#11 xkms backend", "error", ksErr)
		return
	}

	if regErr := xkms.RegisterServiceBackend("pkcs11", ks); regErr != nil {
		a.log.Warn("failed to register PKCS#11 xkms backend", "error", regErr)
		return
	}

	// PIV cert storage is registered separately in the connect hook
	// using the manager's existing session (avoids double-initialization).

	a.log.Info("dynamically registered PKCS#11 xkms backend",
		"library", libraryPath, "slot", slotID)
}

// buildXKMSBackendConfigs extracts backend-specific settings from the unified
// xkey config and translates them into the map format expected by the xkms
// backend factory functions. This enables AutoInitialize to successfully create
// TPM2 and PKCS#11 backends that would otherwise fail due to missing device
// paths or library paths.
func (a *App) buildXKMSBackendConfigs() map[xkms.BackendType]map[string]interface{} {
	configs := make(map[xkms.BackendType]map[string]interface{})

	ucfg, err := config.Load()
	if err != nil {
		a.log.Debug("unified config not available for backend configs", "error", err)
		return configs
	}

	for _, lb := range ucfg.Backends.Local {
		switch lb.Category {
		case "tpm2":
			if lb.TPM2 != nil {
				cfg := make(map[string]interface{})
				if lb.TPM2.Device != "" {
					cfg["device"] = lb.TPM2.Device
				}
				if lb.TPM2.Simulator {
					cfg["use_simulator"] = true
				}
				configs[xkms.BackendTPM2] = cfg
			}
		case "pkcs11":
			if lb.PKCS11 != nil {
				cfg := make(map[string]interface{})
				if lb.PKCS11.LibraryPath != "" {
					cfg["library"] = lb.PKCS11.LibraryPath
				}
				if lb.PKCS11.SlotID != 0 {
					cfg["slot"] = lb.PKCS11.SlotID
				}
				configs[xkms.BackendPKCS11] = cfg
			}
		}
	}

	// Fall back to the shared TPM config for the device path when no
	// explicit TPM2 local backend entry exists in the backends section.
	if _, hasTPM2 := configs[xkms.BackendTPM2]; !hasTPM2 {
		if ucfg.TPM.Device != "" {
			configs[xkms.BackendTPM2] = map[string]interface{}{
				"device": ucfg.TPM.Device,
			}
		}
	}

	return configs
}

// migrateBarrierData copies encrypted data from the legacy barrier directory
// (~/.config/xkey/barrier/) to the data directory (~/.xkey/data/) when the
// barrier has been reconfigured to use the data directory.
func (a *App) migrateBarrierData() {
	if a.configDirPath == "" || a.dataDir == "" {
		return
	}

	oldBarrierDir := filepath.Join(a.configDirPath, "barrier")

	// Only migrate if old barrier dir exists.
	entries, err := os.ReadDir(oldBarrierDir)
	if err != nil || len(entries) == 0 {
		return
	}

	// Check if barrier root key exists in old location but not new.
	oldRootKey := filepath.Join(oldBarrierDir, "barrier", "root_key")
	newRootKey := filepath.Join(a.dataDir, "barrier", "root_key")

	if _, statErr := os.Stat(oldRootKey); statErr != nil {
		return // No old root key, nothing to migrate
	}
	if _, statErr := os.Stat(newRootKey); statErr == nil {
		return // New root key already exists, already migrated
	}

	a.log.Info("migrating barrier data from config dir to data dir",
		"from", oldBarrierDir, "to", a.dataDir)

	if walkErr := filepath.WalkDir(oldBarrierDir, func(path string, d fs.DirEntry, wErr error) error {
		if wErr != nil {
			return wErr
		}

		relPath, relErr := filepath.Rel(oldBarrierDir, path)
		if relErr != nil {
			return relErr
		}

		dstPath := filepath.Join(a.dataDir, relPath)

		if d.IsDir() {
			return os.MkdirAll(dstPath, 0700)
		}

		// Don't overwrite existing files.
		if _, existErr := os.Stat(dstPath); existErr == nil {
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}

		if mkErr := os.MkdirAll(filepath.Dir(dstPath), 0700); mkErr != nil {
			return mkErr
		}

		return os.WriteFile(dstPath, data, 0600)
	}); walkErr != nil {
		a.log.Warn("barrier data migration failed", "error", walkErr)
		return
	}

	a.log.Info("barrier data migration complete")
}

// InitializeDataDir is the public Wails-bound method that triggers data
// directory creation. It is called from the setup wizard callback or
// after a manual LUKS unlock.
func (a *App) InitializeDataDir() error {
	if err := a.initializeDataDir(); err != nil {
		return err
	}
	a.EmitEvent(events.NewEvent(events.EventDataDirInitialized, events.DataDirInitializedPayload{
		DataDir: a.dataDir,
	}))
	return nil
}

// PostUnlockInitialize is called after a successful LUKS volume unlock
// to create the data directory inside the newly mounted volume and
// complete the startup sequence.
func (a *App) PostUnlockInitialize() error {
	if err := a.initializeDataDir(); err != nil {
		return err
	}

	a.postDataDirStartup()

	a.EmitEvent(events.NewEvent(events.EventDataDirInitialized, events.DataDirInitializedPayload{
		DataDir: a.dataDir,
	}))
	return nil
}

// PostBarrierUnseal completes the startup sequence after the user manually
// unseals the barrier. This initializes the data directory with the now-
// available barrier backend and starts deferred services (FIDO2, etc.).
func (a *App) PostBarrierUnseal() error {
	if !a.barrierService.IsUnsealed() {
		return ErrBarrierStillSealed
	}

	// Persist barrier state to config so subsequent restarts know the
	// barrier is initialized and can auto-unseal without re-initialization.
	if !a.config.BarrierInitialized {
		a.config.BarrierInitialized = true
		info := a.barrierService.GetSealInfo()
		if info != nil && info.Strategy != "" {
			a.config.BarrierStrategy = info.Strategy
		}
		if err := SaveGUIConfig(a.config); err != nil {
			a.log.Error("failed to persist barrier initialized state", "error", err)
		}
	}

	if err := a.initializeDataDir(); err != nil {
		return err
	}

	a.postDataDirStartup()

	a.EmitEvent(events.NewEvent(events.EventDataDirInitialized, events.DataDirInitializedPayload{
		DataDir: a.dataDir,
	}))
	return nil
}

// NewApp creates a new App with the provided configuration. Pass nil to
// use DefaultGUIConfig.
func NewApp(cfg *GUIConfig) *App {
	if cfg == nil {
		cfg = DefaultGUIConfig()
	}

	log := slog.Default().With("component", "gui")

	// Resolve the config directory (always accessible, outside LUKS).
	cfgDir, cfgDirErr := configDir()
	if cfgDirErr != nil {
		log.Warn("failed to resolve config directory", "error", cfgDirErr)
	}

	appSvc := services.NewAppService(configToData(cfg))
	connSvc := services.NewConnectionService()
	keySvc := services.NewKeyService()
	tpmSvc := services.NewTPMService()

	// Set TPM device path from unified config so the TPMService probes
	// the correct device node. Falls back to /dev/tpmrm0 if not configured.
	if ucfg, ucfgErr := config.Load(); ucfgErr == nil && ucfg.TPM.Device != "" {
		tpmSvc.SetDevicePath(ucfg.TPM.Device)
	}

	storageSvc := services.NewStorageService()
	notifySvc := services.NewNotificationService()

	// Wire privilege elevator for storage and TPM operations.
	// Prefer PolicyKit (pkexec) when available, fall back to sudo.
	var elevator services.Elevator = services.NewPkexecElevator()
	if !elevator.IsAvailable() {
		sudoElev := services.NewSudoElevator("")
		if sudoElev.IsAvailable() {
			elevator = sudoElev
			log.Info("using sudo elevator (pkexec unavailable)")
		} else {
			log.Warn("no privilege elevator available (neither pkexec nor sudo with helper)")
		}
	}
	storageSvc.SetElevator(elevator)
	tpmSvc.SetElevator(elevator)

	// Wire D-Bus desktop notifications with log fallback.
	notifier, notifyErr := notify.NewDBusNotifier(log)
	if notifyErr != nil {
		log.Warn("D-Bus notifications unavailable, using log fallback", "error", notifyErr)
		notifySvc.SetNotifier(notify.NewLogNotifier(log))
	} else {
		notifySvc.SetNotifier(notifier)
	}

	fido2DeviceSvc := services.NewFIDO2DeviceService(log)
	fido2DeviceSvc.SetElevator(elevator)

	// Services start with nil stores (degraded mode).
	// Stores are wired after LUKS mount decision via initializeDataDir().
	staticPWSvc := services.NewStaticPasswordService(nil)
	tpmSvc.SetStaticPasswordService(staticPWSvc)

	// Create sealed data storage in the data directory (~/.xkey/data/sealed/).
	// Sealed blobs are TPM-encrypted and do not need barrier protection,
	// so they are always accessible. The initial path uses the config
	// directory as a fallback until initializeDataDir() relocates to
	// the data directory and migrates any legacy blobs.
	sealStorageDir := ""
	if cfgDir != "" {
		sealStorageDir = filepath.Join(cfgDir, "sealed")
		if err := os.MkdirAll(sealStorageDir, 0700); err != nil {
			log.Warn("failed to create seal storage directory", "dir", sealStorageDir, "error", err)
		}
	}
	sealSvc := services.NewSealService(sealStorageDir)

	// Password protection service starts without a config path.
	// The config path is set by initializeDataDir() after data dir creation.
	ppSvc := services.NewPasswordProtectionService("", staticPWSvc, sealSvc)

	// Seal protection service: global lock/unlock gate for sealed data.
	sealProtSvc := services.NewSealProtectionService(sealSvc)

	// Create platform policy service with config-dir path (outside LUKS).
	policyPath := ""
	if cfgDir != "" {
		policyPath = filepath.Join(cfgDir, "platform.policy")
	}
	platformPolicySvc := services.NewPlatformPolicyService(policyPath)

	// Create auto-unseal service (LUKS volumes).
	autoUnsealSvc := services.NewAutoUnsealService(sealSvc, storageSvc)

	// Create barrier auto-unseal service (PCR policy-based).
	// The policy store and TPM accessor are wired later in initializeDataDir
	// after the barrier is unsealed (chicken-and-egg: store is behind barrier).
	barrierAutoUnsealSvc := services.NewBarrierAutoUnsealService(nil,
		services.WithBarrierAutoUnsealLogger(log),
	)

	// Create OIDC service (data directory wired later by initializeDataDir).
	oidcSvc := services.NewOIDCService(log)

	// Create clipboard service with configured timeout.
	clipboardSvc := services.NewClipboardService()
	clipboardSvc.SetTimeout(cfg.ClipboardTimeout)

	// Create trust service with nil store (wired by initializeDataDir).
	trustSvc := services.NewTrustService(nil)
	trustSvc.SetElevator(elevator)

	// Create setup wizard service.
	setupWizardSvc := services.NewSetupWizardService()

	// Create barrier service for cross-platform encrypted storage.
	barrierSvc := services.NewBarrierService(cfgDir, log)
	if cfg.BarrierStrategy != "" {
		barrierSvc.SetLastStrategy(cfg.BarrierStrategy)
	}

	// Create shared audit store for queryable logging across all services.
	// Initially backed by in-memory storage; migrated to barrier-encrypted
	// persistence in initializeDataDir() after barrier unseal.
	auditStore, auditStoreErr := audit.NewBackendStore(storage.NewMemory(), 10000, slog.Default())
	if auditStoreErr != nil {
		log.Error("failed to create audit store", "error", auditStoreErr)
		panic("audit store initialization failed: " + auditStoreErr.Error())
	}

	// Create PIV service in standalone mode by default. The remote client
	// is set when the ConnectionService establishes a server connection.
	pivSvc := services.NewPIVService(nil, "software")

	pinSvc := services.NewPINService()
	pinSvc.SetBarrierService(barrierSvc)

	// App lock service: global lock that gates the entire app UI.
	appLockSvc := services.NewAppLockService(pinSvc, barrierSvc)
	appLockSvc.SetBarrierStrategy(cfg.BarrierStrategy)
	appLockSvc.SetAutoLockMinutes(cfg.AppAutoLockMinutes)
	appLockSvc.SetLockOnScreenLock(cfg.AppLockOnScreenLock)

	authSvc := services.NewAuthService(pinSvc, cfgDir)

	browserConfigPath := filepath.Join(cfgDir, "browser.json")
	browserSvc, err := services.NewBrowserService(browserConfigPath, log)
	if err != nil {
		// Corrupt config file -- remove and retry with defaults.
		log.Warn("browser config corrupt, resetting to defaults", "error", err)
		_ = os.Remove(browserConfigPath)
		browserSvc, _ = services.NewBrowserService(browserConfigPath, log)
	}

	home, _ := os.UserHomeDir()
	browsersDir := filepath.Join(home, ".xkey", "browsers")
	secureBrowserSvc := services.NewSecureBrowserService(
		browsersDir, browserSvc, trustSvc, log)
	trustSvc.SetOnMutate(func() {
		if err := secureBrowserSvc.Rebuild(); err != nil {
			log.Warn("browser cert rebuild failed", "error", err)
		}
	})

	apiExplorerSvc, err := services.NewAPIExplorerService(&services.ExplorerConfig{
		Logger:       log,
		TokenStore:   tokenstore.NewMemoryTokenStore(),
		Registry:     serverregistry.NewMemoryServerRegistry(),
		TrustStore:   storage.NewMemory(),
		HistoryStore: storage.NewMemory(),
		OIDCService:  oidcSvc,
	})
	if err != nil {
		log.Warn("API explorer service initialization failed", "error", err)
	}

	oathSvc := services.NewOATHService(nil)

	// Create autofill service for browser extension integration.
	autofillSvc := services.NewAutoFillService(staticPWSvc, oathSvc, appLockSvc, auditStore, log)
	if setErr := autofillSvc.SetEnabled(cfg.BrowserExtensionEnabled); setErr != nil {
		log.Warn("failed to enable autofill service", "error", setErr)
	}
	if cfg.AutoFillPolicy != nil {
		_ = autofillSvc.SetPolicy(cfg.AutoFillPolicy)
	}

	// Apply enterprise extension policy overrides.
	if config.IsEnterpriseMode(cfgDir) {
		ucfg, loadErr := config.Load()
		if loadErr == nil {
			pol := ucfg.Policy
			autofillSvc.SetEnterprisePolicy(&services.EnterpriseExtensionPolicy{
				Enabled:               pol.ExtensionEnabled,
				RequireAuthentication: pol.ExtensionRequireAuthentication,
				ForceAudit:            pol.ExtensionForceAudit,
				AllowedDomains:        pol.ExtensionAllowedDomains,
				BlockedDomains:        pol.ExtensionBlockedDomains,
				MaxFillsPerMinute:     pol.ExtensionMaxFillsPerMinute,
			})
		}
	}

	// Create pairing service for extension identity binding.
	pairingSvc := services.NewPairingService(log)

	a := &App{
		config:                   cfg,
		log:                      log,
		configDirPath:            cfgDir,
		shutdownDone:             make(chan struct{}),
		appService:               appSvc,
		phoneService:             services.NewPhoneService(),
		fido2Service:             services.NewFIDO2Service(nil),
		fido2DeviceService:       fido2DeviceSvc,
		oathService:              oathSvc,
		staticPWService:          staticPWSvc,
		pivService:               pivSvc,
		tpmService:               tpmSvc,
		auditService:             services.NewAuditService(auditStore),
		auditStore:               auditStore,
		adminService:             services.NewAdminService(),
		connectionService:        connSvc,
		keyService:               keySvc,
		storageService:           storageSvc,
		notificationService:      notifySvc,
		sealService:              sealSvc,
		passwordProtectionSvc:    ppSvc,
		platformPolicyService:    platformPolicySvc,
		autoUnsealService:        autoUnsealSvc,
		barrierAutoUnsealService: barrierAutoUnsealSvc,
		oidcService:              oidcSvc,
		clipboardService:         clipboardSvc,
		trustService:             trustSvc,
		setupWizardService:       setupWizardSvc,
		pinService:               pinSvc,
		barrierService:           barrierSvc,
		authService:              authSvc,
		browserService:           browserSvc,
		secureBrowserService:     secureBrowserSvc,
		apiExplorerService:       apiExplorerSvc,
		sealProtectionSvc:        sealProtSvc,
		appLockService:           appLockSvc,
		pkcs11Service:            services.NewPKCS11Service(),
		shareService:             services.NewShareService(),
		custodianService:         services.NewCustodianService(),
		tenantService:            services.NewTenantService(),
		agentService:             services.NewAgentService(),
		teamService:              services.NewTeamService(),
		autofillService:          autofillSvc,
		pairingService:           pairingSvc,
		backendRegistry:          backendregistry.NewMemoryRegistry(),
	}

	// Populate backend registry from the unified config. When the backends
	// section is absent, AutoPopulateBackends creates a single entry from
	// the legacy Backend.Default field for backward compatibility.
	a.populateBackendRegistry()

	// Re-register persisted PKCS#11 modules with the PKCS#11 manager so
	// they are available immediately after restart.
	a.restorePKCS11Modules()

	// Create a single shared TPMAccessor for cross-service serialization.
	// All services that need the TPM use the same accessor so that only
	// one TPM command is in-flight at a time.
	tpmAccessor := services.NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule {
		return a.getTPM()
	})
	a.tpmAccessor = tpmAccessor
	tpmSvc.SetTPMAccessor(tpmAccessor)
	sealSvc.SetTPMAccessor(tpmAccessor)
	platformPolicySvc.SetTPMAccessor(tpmAccessor)

	// Apply persisted sealer backend selection (overrides auto-select).
	if cfg.SealerBackend != "" {
		sealSvc.SetDefaultBackend(cfg.SealerBackend)
	}

	// Wire TPM sealer function to barrier service so it can use TPM-based
	// sealing when the TPM is available. The TrustedPlatformModule interface
	// directly implements types.Sealer (Seal, Unseal, CanSeal).
	barrierSvc.SetTPMSealerFunc(func() types.Sealer {
		tpmObj, tpmErr := tpmAccessor.Acquire()
		if tpmErr != nil {
			return nil
		}
		tpmAccessor.Release()
		return tpmObj
	})

	// Wire platform policy into seal service.
	sealSvc.SetPlatformPolicyService(platformPolicySvc)

	// Wire platform policy into TPM service for unified policy menu.
	tpmSvc.SetPlatformPolicyService(platformPolicySvc)

	// Wire auto-unseal config functions.
	autoUnsealSvc.SetConfigFunc(func() *services.GUIConfigData {
		return appSvc.GetConfig()
	})
	autoUnsealSvc.SetConfigSaveFunc(func(data *services.GUIConfigData) error {
		return appSvc.UpdateConfig(data)
	})

	// Wire setup wizard service dependencies.
	setupWizardSvc.SetStorageService(storageSvc)
	setupWizardSvc.SetPasswordProtectionService(ppSvc)
	setupWizardSvc.SetTPMStatusFunc(func() (bool, bool, bool) {
		status, err := tpmSvc.GetStatus()
		if err != nil || status == nil {
			return false, false, false
		}
		return status.DeviceExists, status.Available, status.Provisioned
	})
	setupWizardSvc.SetConfigFunc(func() *services.GUIConfigData {
		return appSvc.GetConfig()
	})
	setupWizardSvc.SetConfigSaveFunc(func(data *services.GUIConfigData) error {
		return appSvc.UpdateConfig(data)
	})
	setupWizardSvc.SetEventEmitter(func(evt events.Event) {
		a.EmitEvent(evt)
	})
	setupWizardSvc.SetTPMService(tpmSvc)
	setupWizardSvc.SetPINService(pinSvc)
	setupWizardSvc.SetSealService(sealSvc)
	setupWizardSvc.SetPlatformPolicyService(platformPolicySvc)
	setupWizardSvc.SetAutoUnsealService(autoUnsealSvc)
	setupWizardSvc.SetBarrierService(barrierSvc)
	setupWizardSvc.SetConfigDir(cfgDir)

	// Wire initDataDirFunc so the wizard triggers data directory creation
	// after the LUKS/storage decision has been made.
	setupWizardSvc.SetInitDataDirFunc(func() error {
		err := a.initializeDataDir()
		if err != nil && !errors.Is(err, ErrDataDirAlreadyInit) {
			return err
		}
		// ErrDataDirAlreadyInit means the data directory is ready; only
		// run postDataDirStartup on a fresh initialization to avoid
		// re-initializing coordinators and stores.
		if err == nil {
			a.postDataDirStartup()
		}
		return nil
	})

	// Wire BrowserService into OIDCService so browser launches respect
	// the user's configured browser settings (Settings → Browser).
	if browserSvc != nil {
		oidcSvc.SetBrowserOpen(func(url string) error {
			return browserSvc.OpenURL(url)
		})
	}

	// Wire KeyService client func to ConnectionService.
	keySvc.SetClientFunc(connSvc.GetClient)
	sealSvc.SetClientFunc(connSvc.GetClient)

	// Wire audit logger to ALL services.
	keySvc.SetAuditLogger(auditStore)
	keySvc.SetRegistry(a.backendRegistry)
	a.fido2Service.SetClientFunc(connSvc.GetClient)
	a.fido2Service.SetAuditLogger(auditStore)
	fido2DeviceSvc.SetAuditLogger(auditStore)
	a.pinService.SetAuditLogger(auditStore)
	a.tpmService.SetAuditLogger(auditStore)
	a.passwordProtectionSvc.SetAuditLogger(auditStore)
	oathSvc.SetAuditLogger(auditStore)
	pairingSvc.SetAuditLogger(auditStore)
	sealSvc.SetAuditLogger(auditStore)
	barrierSvc.SetAuditLogger(auditStore)
	sealProtSvc.SetAuditLogger(auditStore)
	appSvc.SetAuditLogger(auditStore)

	// Wire audit store to AdminService for admin audit queries.
	a.adminService.SetAuditStore(auditStore)

	// Wire AdminService backend discovery via registry and status providers.
	adminSvc := a.adminService
	adminSvc.SetBackendRegistry(a.backendRegistry)
	adminSvc.SetTPMStatusProvider(a.tpmService)
	adminSvc.SetPhoneStatusProvider(a.phoneService)
	adminSvc.SetPKCS11Tester(a.pkcs11Service)
	a.pkcs11Service.SetRegistry(a.backendRegistry)
	a.pkcs11Service.SetConnectHook(func(moduleID, libraryPath string, slotID uint, userPIN, soPin, tokenLabel string) {
		// Dynamically register the connected PKCS#11 token as an xkms backend
		// so PIV key generation and other operations can use it.
		a.registerPKCS11XKMSBackend(libraryPath, slotID, userPIN, soPin, tokenLabel)

		// Create PKCS#11 PIV cert storage that reuses the manager's session.
		// This reads/writes certs directly on the token (NIST SP 800-73-5).
		mgr := a.pkcs11Service.GetManager()
		if mgr != nil {
			if conn, connErr := mgr.GetConnection(moduleID, slotID); connErr == nil {
				p11Store, p11Err := newPKCS11PIVCertStorageFromConnection(conn)
				if p11Err == nil {
					if pivErr := xkms.RegisterPIVStore("pkcs11", p11Store); pivErr != nil {
						a.log.Warn("failed to register PKCS#11 PIV store", "error", pivErr)
					} else {
						a.log.Info("registered PKCS#11 PIV cert storage (on-device)")
					}
					if pivErr := xkms.RegisterPIVStore(moduleID, p11Store); pivErr != nil {
						a.log.Debug("failed to register PIV store under module ID", "error", pivErr)
					}
				} else {
					a.log.Debug("PKCS#11 PIV cert storage not available", "error", p11Err)
				}

				// Register the PKCS#11 token as a FIDO2 key backend by wrapping the
				// go-xkms PKCS#11 KeyProvider via the BackendAdapter.
				// For YubiKey tokens (libykcs11), wrap with the YubiKey provider
				// to handle SO login for key generation.
				if a.fido2KeyBackend != nil {
					// The xkms backend is registered under "pkcs11" (see
				// registerPKCS11XKMSBackend), not the module ID.
				p11Backend, p11Err := xkms.GetBackend("pkcs11")
					if p11Err == nil && p11Backend != nil {
						bt := types.BackendType(moduleID)
						provider := p11Backend.KeyProvider()
						if isYubiKeyLibrary(libraryPath) && wrapYubiKeyProvider != nil {
							if wrapped := wrapYubiKeyProvider(provider); wrapped != nil {
								provider = wrapped
								a.log.Info("FIDO2 adapter: using YubiKey provider",
									"module_id", moduleID)
							}
						}
						adapter := keybackend.NewBackendAdapter(provider, bt)
						adapter.SetLogger(a.log)
						// Attach PIV slot model if the backend supports it.
						type slotModelProvider interface {
							SlotModel() pivcert.SlotModel
						}
						if smp, ok := p11Backend.KeyProvider().(slotModelProvider); ok {
							if sm := smp.SlotModel(); sm != nil {
								adapter.SetSlotModel(sm)
								a.log.Info("FIDO2 adapter: PIV slot model attached",
									"module_id", moduleID)
							}
						}
						a.fido2KeyBackend.Register(bt, adapter)
						a.log.Info("registered PKCS#11 FIDO2 key backend",
							"module_id", moduleID,
							"slot_id", slotID,
							"token_label", tokenLabel)
					} else {
						a.log.Debug("PKCS#11 FIDO2 key backend not available",
							"module_id", moduleID, "error", p11Err)
					}
				}
			}
		}
	})
	a.pkcs11Service.SetDisconnectHook(func(moduleID string, slotID uint) {
		// Unregister the PKCS#11 FIDO2 key backend when the token disconnects.
		if a.fido2KeyBackend != nil {
			a.fido2KeyBackend.Unregister(types.BackendType(moduleID))
			a.log.Info("unregistered PKCS#11 FIDO2 key backend",
				"module_id", moduleID,
				"slot_id", slotID)
		}
	})
	a.pivService.SetRegistry(a.backendRegistry)
	a.pivService.SetBackendTypeFn(func(id string) string {
		info, err := adminSvc.GetBackendInfo(id)
		if err != nil {
			return ""
		}
		return info.Type
	})
	adminSvc.SetConnectionInfoFunc(connSvc.GetConnectionInfo)
	adminSvc.SetRemoteBackendsFunc(func() ([]services.BackendInfo, error) {
		client := connSvc.GetClient()
		if client == nil {
			return nil, services.ErrServerNotConnected
		}
		resp, err := client.ListBackends(a.ctx)
		if err != nil {
			return nil, err
		}
		backends := make([]services.BackendInfo, 0, len(resp.Backends))
		for _, b := range resp.Backends {
			backends = append(backends, services.BackendInfo{
				ID:      b.ID,
				Type:    b.Type,
				Enabled: true,
			})
		}
		return backends, nil
	})

	// Wire PIV registration hook for dynamically configured backends.
	// PKCS#11 on-device cert storage is registered via the connect hook;
	// this handles non-PKCS#11 backends (software, tpm2, etc.).
	adminSvc.SetPIVRegisterFunc(func(backendID, category string) {
		// PKCS#11 backends get on-device cert storage via the connect hook.
		// Don't overwrite it with a file-based store here.
		if category == "pkcs11" {
			return
		}

		store := a.pivFileStore
		if store == nil {
			return
		}
		if err := xkms.RegisterPIVStore(backendID, store); err != nil {
			a.log.Warn("failed to register PIV store for new backend",
				"backend_id", backendID, "error", err)
			return
		}
		// Also register under the category name for xkms lookups.
		if category != "" && category != backendID {
			if err := xkms.RegisterPIVStore(category, store); err != nil {
				a.log.Warn("failed to register PIV store under category",
					"category", category, "error", err)
			}
		}
		a.log.Info("registered PIV store for new backend",
			"backend_id", backendID, "category", category)
	})

	// Wire admin service seal service and config persistence for "Set as Default".
	adminSvc.SetSealService(sealSvc)
	adminSvc.SetConfigUpdateFunc(func(backendID string) error {
		data := appSvc.GetConfig()
		data.SealerBackend = backendID
		return appSvc.UpdateConfig(data)
	})

	// Wire admin service into setup wizard for backend discovery.
	setupWizardSvc.SetAdminService(adminSvc)
	setupWizardSvc.SetStaticPasswordService(staticPWSvc)

	// Wire ConnectionService event emitter.
	connSvc.SetEventEmitter(func(evt events.Event) {
		a.EmitEvent(evt)

		// Update service clients when server connection state changes.
		switch evt.Type {
		case events.EventServerConnected:
			client := connSvc.GetClient()
			pivSvc.SetClient(client)
			a.custodianService.SetClient(client)
			a.tenantService.SetClient(client)
		case events.EventServerDisconnected, events.EventServerError:
			pivSvc.SetClient(nil)
		}
	})

	// Wire ShareService event emitter.
	a.shareService.SetEventEmitter(func(evt events.Event) {
		a.EmitEvent(evt)
	})

	// Wire CustodianService event emitter.
	a.custodianService.SetEventEmitter(func(evt events.Event) {
		a.EmitEvent(evt)
	})

	// Wire TenantService event emitter.
	a.tenantService.SetEventEmitter(func(evt events.Event) {
		a.EmitEvent(evt)
	})

	// Wire AgentService event emitter.
	a.agentService.SetEventEmitter(func(evt events.Event) {
		a.EmitEvent(evt)
	})
	a.pairingService.SetEventEmitter(func(evt events.Event) {
		a.EmitEvent(evt)
	})

	// Wire key count callback for the dashboard (local + remote).
	appSvc.SetKeyCountFunc(func() int {
		total := 0
		if a.oathStore != nil {
			if accounts, err := a.oathService.ListAccounts(); err == nil {
				total += len(accounts)
			}
		}
		if a.fido2Storage != nil {
			if creds, err := a.fido2Service.ListCredentials(); err == nil {
				total += len(creds)
			}
		}
		return total
	})

	// Wire bridge status callback for the dashboard.
	appSvc.SetBridgeStatusFunc(func() bool {
		return a.fido2Service.GetBridgeStatus().Running
	})

	// Wire server connection callbacks for dashboard status.
	appSvc.SetServerConnectedFunc(func() bool {
		return connSvc.IsConnected()
	})
	appSvc.SetServerAddressFunc(func() string {
		info := connSvc.GetConnectionInfo()
		return info.Address
	})
	appSvc.SetRemoteKeyCountFunc(func() int {
		return keySvc.GetKeyCount("server")
	})

	// Wire OATH account count for dashboard inventory.
	appSvc.SetOATHCountFunc(func() int {
		accounts, err := a.oathService.ListAccounts()
		if err != nil {
			return 0
		}
		return len(accounts)
	})

	// Wire FIDO2 credential count for dashboard inventory.
	appSvc.SetFIDO2CountFunc(func() int {
		creds, err := a.fido2Service.ListCredentials()
		if err != nil {
			return 0
		}
		return len(creds)
	})

	// Wire PIV certificate count for dashboard inventory.
	appSvc.SetPIVCertCountFunc(func() int {
		slots, err := a.pivService.GetSlots()
		if err != nil {
			return 0
		}
		count := 0
		for _, slot := range slots {
			if slot.HasCert {
				count++
			}
		}
		return count
	})

	// Wire TPM status for dashboard.
	appSvc.SetTPMStatusFunc(func() (bool, bool, bool) {
		status, err := a.tpmService.GetStatus()
		if err != nil || status == nil {
			return false, false, false
		}
		return status.DeviceExists, status.Available, status.Provisioned
	})

	// Wire storage status for dashboard.
	appSvc.SetStorageStatusFunc(func() (bool, bool) {
		status, err := a.storageService.GetStatus()
		if err != nil || status == nil {
			return false, false
		}
		return status.IsLUKS, status.IsMounted
	})

	// Wire phone connection status for dashboard.
	appSvc.SetPhoneStatusFunc(func() (bool, string) {
		return a.phoneService.IsConnected(), a.phoneService.ConnectedDeviceName()
	})

	// Wire phone status change callback to update systray when phone
	// connect/disconnect events occur.
	a.phoneService.SetStatusChangeFunc(func(connected bool, deviceName string) {
		if a.tray != nil {
			a.tray.UpdatePhoneStatus(connected, deviceName)
		}
	})

	// Wire callbacks to break the gui -> services -> gui import cycle.
	appSvc.SetConfigUpdater(func(data *services.GUIConfigData) error {
		guiCfg := dataToConfig(data)
		if err := guiCfg.Validate(); err != nil {
			return err
		}
		if err := SaveGUIConfig(guiCfg); err != nil {
			return err
		}
		a.config = guiCfg

		// Sync service-level settings when config changes.
		clipboardSvc.SetTimeout(guiCfg.ClipboardTimeout)
		appLockSvc.SetAutoLockMinutes(guiCfg.AppAutoLockMinutes)
		appLockSvc.SetLockOnScreenLock(guiCfg.AppLockOnScreenLock)
		if setErr := autofillSvc.SetEnabled(guiCfg.BrowserExtensionEnabled); setErr != nil {
			a.log.Warn("enterprise policy prevents enabling extension", "error", setErr)
		}
		if guiCfg.AutoFillPolicy != nil {
			_ = autofillSvc.SetPolicy(guiCfg.AutoFillPolicy)
		}

		// Sync sealer backend when config changes.
		if guiCfg.SealerBackend != "" {
			sealSvc.SetDefaultBackend(guiCfg.SealerBackend)
		}

		// Sync FIDO2 authenticator settings.
		a.fido2DeviceService.SetRequireUserPresence(guiCfg.FIDO2RequireUserPresence)
		a.fido2DeviceService.SetUserIntentCheck(guiCfg.FIDO2UserIntentCheck)

		return nil
	})
	// Wire autofill policy persist callback so GUI toggle changes are saved to config.
	autofillSvc.SetPolicyPersistFunc(func(policy *autofill.AutoFillPolicy) error {
		a.config.AutoFillPolicy = policy
		return SaveGUIConfig(a.config)
	})

	appSvc.SetThemeValidator(func(theme string) error {
		return ValidateTheme(theme)
	})

	// Wire window hide function for minimize-to-tray.
	appSvc.SetWindowHideFunc(func() {
		a.HideWindow()
	})

	// Wire FIDO2 authenticator toggle to the App layer.
	appSvc.SetFIDO2ToggleFunc(func(enabled bool) error {
		return a.ToggleFIDO2Authenticator(enabled)
	})

	return a
}

// getTPM returns the cached TPM instance or lazily initializes one.
// Returns nil if the hardware TPM device is not available.
// The result is cached: once we determine the TPM is unavailable,
// subsequent calls return nil immediately without re-logging.
func (a *App) getTPM() tpm2pkg.TrustedPlatformModule {
	a.tpmMu.Lock()
	defer a.tpmMu.Unlock()

	if a.tpmInstance != nil {
		return a.tpmInstance
	}

	// If we already probed and found no TPM, return immediately.
	if a.tpmUnavailable {
		return nil
	}

	// Load and cache TPM config exactly once.
	a.tpmConfigOnce.Do(func() {
		a.tpmCachedConfig = loadTPMConfig(a.log)
		a.tpmCachedConfig.UseSimulator = false
		if a.tpmCachedConfig.Device == "" {
			a.tpmCachedConfig.Device = "/dev/tpmrm0"
		}
	})
	cfg := a.tpmCachedConfig

	if _, err := os.Stat(cfg.Device); err != nil {
		a.log.Debug("TPM device not found", "device", cfg.Device)
		a.tpmUnavailable = true
		return nil
	}

	// Use the initialized data directory for TPM storage.
	// If the data directory hasn't been initialized yet, use an empty
	// path which causes the storage factory to use in-memory storage.
	tpmDataDir := ""
	if a.dataDir != "" {
		tpmDataDir = filepath.Join(a.dataDir, "tpm")
	}

	// Create the TPM storage factory. If it fails (e.g. missing codec_json
	// build tag), proceed without persistent storage — the TPM can still
	// serve property/capability queries with nil BlobStore/Backend.
	var factory *tpm2store.StorageFactory
	factory, err := tpm2store.NewStorageFactory(a.log, tpmDataDir)
	if err != nil {
		a.log.Warn("failed to create TPM storage factory, continuing without persistent storage", "error", err)
	}

	// Detect whether the EK is RSA (0x81010001) or ECC (0x81010002).
	// The DefaultConfig assumes RSA, but many modern TPMs only provision
	// an ECC P-256 EK at the TCG-standard handle 0x81010002.
	if ekHandle := detectEKHandle(a.log, cfg.Device); ekHandle != 0 {
		cfg.EK.Handle = ekHandle
		if ekHandle == 0x81010002 {
			cfg.EK.KeyAlgorithm = "ECDSA"
			cfg.EK.RSAConfig = nil
			cfg.EK.ECCConfig = &tpm2store.ECCConfig{Curve: "P-256"}
			cfg.EK.CertHandle = 0x01C0000A
		}
	}

	// Patch WebKit/JSC signal handlers before opening the TPM.
	// WebKit's JIT engine installs SIGSEGV/SIGBUS handlers without SA_ONSTACK,
	// which Go 1.24+ treats as fatal. By this point the frontend JS has loaded
	// and JSC's JIT has installed its handlers; we fix them here right before
	// TPM operations which may trigger goroutine signals.
	FixSignalHandlers()

	// Build TPM params — use factory backends when available, nil otherwise.
	tpmParams := &tpm2pkg.Params{
		Logger: a.log,
		Config: &cfg,
	}
	if factory != nil {
		tpmParams.BlobStore = factory.BlobStore()
		tpmParams.Backend = factory.KeyBackend()
	}

	tpm, err := tpm2pkg.NewTPM2(tpmParams)
	if err != nil {
		// ErrNotInitialized means the TPM is connected and communicating but
		// has no persistent EK key yet (e.g. manufacturer EK cert in NV RAM
		// only). The returned TPM object is still valid for status/info queries
		// — cache it so the TPM view shows real hardware values.
		if errors.Is(err, tpm2pkg.ErrNotInitialized) && tpm != nil {
			a.log.Info("TPM device connected but not yet provisioned", "device", cfg.Device)
			a.tpmInstance = tpm
			a.tpmStorageFactory = factory
			return a.tpmInstance
		}
		a.log.Warn("failed to open TPM", "error", err)
		if factory != nil {
			factory.Close()
		}
		return nil
	}

	// Initialize the Platform Key Store so the Platform SRK is visible.
	// NewPlatformKeyStore auto-detects prior initialization from the PIN state file.
	if cfg.PlatformSRK != nil && factory != nil {
		pinStatePath := filepath.Join(tpmDataDir, "pin_state.json")
		pks, pksErr := tpm2pkg.NewPlatformKeyStore(a.log, tpm, factory.KeyBackend(), &cfg, pinStatePath)
		if pksErr != nil {
			a.log.Warn("failed to create platform key store", "error", pksErr)
		} else if tpm2Impl, ok := tpm.(*tpm2pkg.TPM2); ok {
			tpm2Impl.SetPlatformKeyStore(pks)
			// Auto-initialize the Platform Key Store (creates Platform SRK)
			// only for returning users (setup already completed). During first-
			// run, the setup wizard creates the SRK with the user PIN as auth
			// in Step 4 — auto-initializing here with empty auth would race
			// with the wizard, leaving the SRK with the wrong auth value and
			// causing PIN verification to fail after setup.
			if !pks.IsInitialized() && a.config.SetupComplete {
				if initErr := pks.InitializeWithDefaults(); initErr != nil {
					a.log.Warn("platform key store auto-init failed", "error", initErr)
				} else {
					a.log.Info("platform key store auto-initialized")
				}
			}
			a.log.Info("platform key store attached", "initialized", pks.IsInitialized())
		}
	}

	a.tpmInstance = tpm
	a.tpmStorageFactory = factory
	a.log.Info("TPM initialized", "device", cfg.Device)
	return a.tpmInstance
}

// Run starts the Wails v2 application. It blocks until the application exits.
func (a *App) Run() error {
	if a.running.Swap(true) {
		return ErrAlreadyRunning
	}

	bindings := []any{
		a,
		a.appService,
		a.phoneService,
		a.fido2Service,
		a.fido2DeviceService,
		a.oathService,
		a.staticPWService,
		a.pivService,
		a.tpmService,
		a.auditService,
		a.adminService,
		a.connectionService,
		a.keyService,
		a.storageService,
		a.notificationService,
		a.sealService,
		a.sealProtectionSvc,
		a.appLockService,
		a.pkcs11Service,
		a.passwordProtectionSvc,
		a.platformPolicyService,
		a.autoUnsealService,
		a.oidcService,
		a.clipboardService,
		a.trustService,
		a.setupWizardService,
		a.pinService,
		a.barrierService,
		a.authService,
		a.shareService,
		a.custodianService,
		a.tenantService,
		a.agentService,
		a.autofillService,
		a.pairingService,
		a.barrierAutoUnsealService,
		a.teamService,
	}
	// Append optional services that may fail initialization.
	if a.browserService != nil {
		bindings = append(bindings, a.browserService)
	}
	if a.secureBrowserService != nil {
		bindings = append(bindings, a.secureBrowserService)
	}
	if a.apiExplorerService != nil {
		bindings = append(bindings, a.apiExplorerService)
	}

	appOpts := &options.App{
		Title:         "xKey",
		Width:         a.config.WindowWidth,
		Height:        a.config.WindowHeight,
		Frameless:     false,
		StartHidden:   a.config.StartMinimized,
		OnStartup:     a.startup,
		OnShutdown:    a.shutdown,
		OnBeforeClose: a.beforeClose,
		Bind:          bindings,
		Linux: &linux.Options{
			Icon:        icon.AppIcon,
			ProgramName: "xkey",
		},
	}

	// Only set asset server if frontend assets are provided.
	if Assets != nil {
		appOpts.AssetServer = &assetserver.Options{
			Assets: Assets,
		}
	}

	return wails.Run(appOpts)
}

// beforeClose is called when the user attempts to close the window.
// If AutoTray is enabled and this is NOT a tray-initiated quit, it
// hides the window instead of quitting. When the tray quit menu item
// sets trayQuit, the close is allowed through so the app actually exits.
func (a *App) beforeClose(ctx context.Context) bool {
	if a.config.AutoTray && !a.trayQuit.Load() {
		wailsruntime.WindowHide(ctx)
		return true // prevent quit
	}
	return false // allow quit
}

// startup is the Wails OnStartup lifecycle callback.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	a.log.Info("xKey GUI starting")

	// Catch SIGTERM/SIGINT/SIGHUP so we run shutdown (LUKS lock,
	// re-seal, TPM close) even when killed by a service manager.
	a.installSignalHandler()

	// Propagate context to all services.
	a.appService.SetContext(ctx)
	a.phoneService.SetContext(ctx)
	a.fido2Service.SetContext(ctx)
	a.fido2DeviceService.SetContext(ctx)
	a.oathService.SetContext(ctx)
	a.staticPWService.SetContext(ctx)
	a.pivService.SetContext(ctx)
	a.tpmService.SetContext(ctx)
	a.auditService.SetContext(ctx)
	a.adminService.SetContext(ctx)
	a.connectionService.SetContext(ctx)
	a.keyService.SetContext(ctx)
	a.storageService.SetContext(ctx)
	a.notificationService.SetContext(ctx)
	a.sealService.SetContext(ctx)
	a.sealProtectionSvc.SetContext(ctx)
	a.appLockService.SetContext(ctx)
	a.pkcs11Service.SetContext(ctx)
	a.passwordProtectionSvc.SetContext(ctx)
	a.platformPolicyService.SetContext(ctx)
	a.autoUnsealService.SetContext(ctx)
	a.oidcService.SetContext(ctx)
	a.clipboardService.SetContext(ctx)
	a.setupWizardService.SetContext(ctx)
	a.trustService.SetContext(ctx)
	a.barrierService.SetContext(ctx)
	a.authService.SetContext(ctx)
	a.shareService.SetContext(ctx)
	a.custodianService.SetContext(ctx)
	a.tenantService.SetContext(ctx)
	a.agentService.SetContext(ctx)
	a.autofillService.SetContext(ctx)
	a.pairingService.SetContext(ctx)
	a.browserService.SetContext(ctx)
	if a.secureBrowserService != nil {
		a.secureBrowserService.SetContext(ctx)
	}
	if a.apiExplorerService != nil {
		a.apiExplorerService.SetContext(ctx)
	}

	// Wire phone event emitter to Wails runtime so phone events reach the frontend.
	a.phoneService.SetEventEmitter(func(evt events.Event) {
		a.EmitEvent(evt)
	})

	// Wire the FIDO2 device service emit function to the Wails runtime.
	a.fido2DeviceService.SetEmitFunc(func(eventType string, data any) {
		wailsruntime.EventsEmit(ctx, eventType, data)
	})

	// Wire the window hide callback so the app minimizes to tray after
	// touch approval, returning focus to the browser.
	a.fido2DeviceService.SetWindowHideFunc(func() {
		a.HideWindow()
	})

	// Wire app lock event emitter.
	a.appLockService.SetEmitFunc(func(eventType string, data any) {
		wailsruntime.EventsEmit(ctx, eventType, data)
	})

	// Start screen lock monitor (D-Bus logind Lock signal).
	// If the system bus is unavailable (headless, CI), we log and continue.
	if a.config.AppLockOnScreenLock {
		slm, slmErr := notify.NewScreenLockMonitor(a.log, func() {
			_ = a.appLockService.Lock()
		})
		if slmErr != nil {
			a.log.Warn("screen lock monitor unavailable", "error", slmErr)
		} else {
			a.screenLockMonitor = slm
		}
	}

	// Create a WailsNotifier wrapped in a FocusNotifier that brings the
	// window to the foreground when touch is required. D-Bus desktop
	// notifications are intentionally omitted for FIDO2 touch — the in-app
	// TouchButton UI is sufficient and avoids a redundant click.
	wailsNotifier := notify.NewWailsNotifier(func(eventType string, data any) {
		wailsruntime.EventsEmit(ctx, eventType, data)
	})
	a.deviceNotifier = notify.NewFocusNotifier(wailsNotifier, func() {
		a.ShowWindow()
	})

	// Initialize platform policy early since the policy file lives in
	// ~/.config/xkey/ (outside any LUKS volume) and must be available
	// before postDataDirStartup or the user navigates to the TPM page.
	if err := a.platformPolicyService.Initialize(); err != nil {
		a.log.Warn("failed to initialize platform policy", "error", err)
	}

	// Set barrier data directory to ~/.xkey/data/ so all encrypted data
	// lives in the data directory, not the config directory.
	if dataDirPath, ddErr := dataDir(); ddErr == nil {
		a.barrierService.SetDataDir(dataDirPath)
	}

	if a.config.SetupComplete {
		// Returning user: handle LUKS auto-unseal or locked state.
		a.startupReturningUser(ctx)
	} else {
		// First run: wizard mode, no data dir init.
		// The wizard will trigger initializeDataDir() after LUKS decision.
		a.log.Info("first run detected, waiting for setup wizard")
	}

	// Auto-connect to server if configured.
	if a.config.ServerAutoConnect && a.config.ServerAddress != "" {
		go func() {
			_, err := a.connectionService.Connect(
				a.config.ServerProtocol,
				a.config.ServerAddress,
				a.config.ServerTLSEnabled,
				a.config.ServerTLSCAFile,
				a.config.ServerSPKIPin,
			)
			if err != nil {
				a.log.Warn("auto-connect failed", "error", err)
			}
		}()
	}

	// Start system tray if auto-tray is enabled.
	if a.config.AutoTray {
		a.tray = NewTrayManager(a)
		go a.tray.Run()
	}
}

// startupReturningUser handles the startup sequence for a user who has
// already completed the setup wizard. It handles LUKS auto-unseal,
// data directory initialization, and post-init services.
func (a *App) startupReturningUser(ctx context.Context) {
	// Lock the app for returning users. The frontend will read this state
	// via GetStatus on mount. Auto-unseal or manual PIN entry unlocks later.
	a.appLockService.LockForStartup()

	// Auto-unseal LUKS volume if configured.
	if a.config.AutoUnsealEnabled && a.config.AutoUnsealBlobID != "" {
		result := a.autoUnsealService.TryAutoUnseal()
		if result.Success {
			a.log.Info("auto-unseal succeeded", "message", result.Message)
			wailsruntime.EventsEmit(ctx, "storage:auto_unseal_success", result)
		} else {
			a.log.Warn("auto-unseal failed", "message", result.Message)
			wailsruntime.EventsEmit(ctx, "storage:auto_unseal_failed", result)
		}
		// Update tray storage status after auto-unseal attempt.
		if a.tray != nil {
			status, err := a.storageService.GetStatus()
			if err == nil && status != nil {
				a.tray.UpdateStorageStatus(status.IsMounted)
			}
		}
	}

	// Check if LUKS exists but is NOT mounted (manual unlock required).
	status, err := a.storageService.GetStatus()
	if err == nil && status != nil && status.IsLUKS && !status.IsMounted {
		// LUKS volume exists but is locked. Emit event for frontend to show
		// unlock dialog. PostUnlockInitialize() will be called after unlock.
		a.log.Info("LUKS volume locked, waiting for manual unlock")
		a.EmitEvent(events.NewEvent(events.EventStorageLUKSLocked, nil))
		return
	}

	// Detect and repair inconsistent config: storage_type says "barrier" but
	// the barrier root key doesn't actually exist on disk. This can happen
	// when a prior buggy startup set BarrierInitialized=true without creating
	// the root key, or when the wizard failed mid-initialization.
	if a.config.StorageType == "barrier" {
		info := a.barrierService.GetSealInfo()
		if info != nil && info.Initialized {
			// Root key exists on disk — ensure config reflects that.
			if !a.config.BarrierInitialized || a.config.BarrierStrategy == "" {
				a.log.Warn("repairing barrier config from disk state")
				a.config.BarrierInitialized = true
				if a.config.BarrierStrategy == "" {
					a.config.BarrierStrategy = info.Strategy
				}
				if err := SaveGUIConfig(a.config); err != nil {
					a.log.Error("failed to persist corrected config", "error", err)
				}
			}
		} else {
			// Root key missing — barrier was never actually created.
			// Keep StorageType="barrier" to respect the security intent,
			// but clear BarrierInitialized so the unlock flow knows to
			// initialize the barrier with the user's PIN.
			a.log.Error("barrier root key missing — barrier will be initialized on first unlock")
			a.config.BarrierInitialized = false
			// The barrier was never created, so any persisted strategy is
			// stale. Prefer the user's sealer backend choice (e.g., tpm2)
			// over whatever strategy was previously saved.
			if a.config.SealerBackend != "" {
				a.config.BarrierStrategy = a.config.SealerBackend
			} else if a.config.BarrierStrategy == "" {
				a.config.BarrierStrategy = "software"
			}
			if err := SaveGUIConfig(a.config); err != nil {
				a.log.Error("failed to persist corrected config", "error", err)
			}
		}
	}

	// Repair missing storage_type: if no storage type is configured, check
	// disk for a barrier root key. If found, enable barrier mode. If not,
	// default to barrier to ensure data is always encrypted.
	if a.config.StorageType == "" {
		info := a.barrierService.GetSealInfo()
		if info != nil && info.Initialized {
			a.log.Warn("found barrier root key on disk, enabling barrier mode")
			a.config.StorageType = "barrier"
			a.config.BarrierInitialized = true
			a.config.BarrierStrategy = info.Strategy
		} else {
			// No storage type set and no root key: default to barrier so
			// data is never stored in plain text. The barrier will be
			// initialized on the first unlock.
			a.log.Warn("no storage type configured, defaulting to barrier for encryption")
			a.config.StorageType = "barrier"
			a.config.BarrierInitialized = false
			if a.config.SealerBackend != "" {
				a.config.BarrierStrategy = a.config.SealerBackend
			} else if a.config.BarrierStrategy == "" {
				a.config.BarrierStrategy = "software"
			}
		}
		if err := SaveGUIConfig(a.config); err != nil {
			a.log.Error("failed to persist corrected config", "error", err)
		}
	}

	// Sync barrier strategy to the app lock service in case the config
	// repair above resolved a missing strategy after NewApp construction.
	a.appLockService.SetBarrierStrategy(a.config.BarrierStrategy)

	// Auto-unseal barrier if configured.
	if a.config.StorageType == "barrier" && a.config.BarrierInitialized {
		unsealed := false

		if a.config.BarrierStrategy == "tpm2" && a.config.BarrierAutoUnsealEnabled {
			// TPM2 strategy: try PCR policy-based auto-unseal first, then
			// fall back to direct TPM unseal (no password needed).
			a.barrierAutoUnsealService.SetBarrier(a.barrierService)
			ok, err := a.barrierAutoUnsealService.TryAutoUnseal(ctx)
			if ok {
				a.log.Info("barrier auto-unsealed via PCR policy")
				a.EmitEvent(events.NewEvent(events.EventBarrierUnlocked, nil))
				a.appLockService.AutoUnlock()
				unsealed = true
			} else if err != nil {
				a.log.Warn("barrier PCR policy auto-unseal failed, trying direct TPM", "error", err)
			}
			// Fallback: direct TPM unseal without PCR policy verification.
			if !unsealed {
				if err := a.barrierService.Unseal("", a.config.BarrierStrategy); err != nil {
					a.log.Warn("barrier auto-unseal failed", "error", err)
				} else {
					a.EmitEvent(events.NewEvent(events.EventBarrierUnlocked, nil))
					a.appLockService.AutoUnlock()
					unsealed = true
				}
			}
		} else {
			// Software strategy: try auto-unseal via TPM-sealed barrier password.
			if a.config.BarrierAutoUnsealEnabled && a.config.BarrierAutoUnsealBlobID != "" {
				b64PW, unsealErr := a.sealService.UnsealData(a.config.BarrierAutoUnsealBlobID, "")
				if unsealErr == nil {
					pwBytes, decErr := base64.StdEncoding.DecodeString(b64PW)
					if decErr == nil {
						if err := a.barrierService.Unseal(string(pwBytes), a.config.BarrierStrategy); err != nil {
							a.log.Warn("barrier auto-unseal with sealed password failed", "error", err)
						} else {
							a.log.Info("barrier auto-unsealed via sealed password")
							a.EmitEvent(events.NewEvent(events.EventBarrierUnlocked, nil))
							a.appLockService.AutoUnlock()
							unsealed = true
						}
					} else {
						a.log.Warn("barrier auto-unseal: failed to decode password", "error", decErr)
					}
				} else {
					a.log.Warn("barrier auto-unseal: failed to unseal password blob", "error", unsealErr)
				}
			}
		}

		if !unsealed {
			a.log.Info("barrier locked, waiting for password")
			a.EmitEvent(events.NewEvent(events.EventBarrierLocked, nil))
		}
	}

	// Register post-unseal hook so that manual unseal (via UnsealDialog)
	// triggers data directory initialization automatically. The hook is set
	// after the auto-unseal attempts above, so those calls to Unseal() do
	// not trigger the hook (avoiding double-init with the code below).
	a.barrierService.SetPostUnsealHook(func() error {
		return a.PostBarrierUnseal()
	})

	// If barrier is configured but not yet usable (either sealed or never
	// initialized), defer data directory initialization until the user
	// provides a password. Starting services now would use plain file
	// fallback storage, storing data in plain text.
	if a.config.StorageType == "barrier" && !a.barrierService.IsUnsealed() {
		if !a.config.BarrierInitialized {
			a.log.Info("barrier not initialized, waiting for user to set password")
		} else {
			a.log.Info("barrier sealed, deferring data directory init until unseal")
		}
		// Emit locked event so the frontend shows the unlock/password dialog.
		a.EmitEvent(events.NewEvent(events.EventBarrierLocked, nil))
		return
	}

	// Initialize data directory (creates ~/.xkey/data/ structure).
	if err := a.initializeDataDir(); err != nil {
		a.log.Warn("failed to initialize data directory", "error", err)
	}

	// Run post-data-dir startup tasks.
	a.postDataDirStartup()
}

// postDataDirStartup runs startup tasks that require the data directory
// to be initialized: password protection, platform policy, trust roots,
// static password migration, FIDO2 device, etc.
func (a *App) postDataDirStartup() {
	// Seed embedded trust roots into the file-based trust store.
	if a.trustStore != nil {
		if count, err := a.trustService.SeedEmbeddedRoots(string(truststore.PurposeAndroidHardware)); err != nil {
			a.log.Warn("failed to seed embedded roots", "error", err)
		} else if count > 0 {
			a.log.Info("seeded embedded trust roots", "count", count)
		}
	}

	// Platform policy is initialized in startup() (before LUKS mount)
	// since the policy file lives outside the LUKS volume.

	// Initialize PIN service for cross-subsystem PIN management.
	a.initPINService()

	// Remove legacy PIN artifacts (pin-state.json, tpm/pin_state.json, user_pin blobs).
	// Idempotent: safe to run on every startup.
	a.migratePINArtifacts()

	// Migrate legacy static password entries.
	if a.staticpwStore != nil {
		migrated, migrateErr := staticpw.MigrateStore(a.staticpwStore)
		if migrateErr != nil {
			a.log.Warn("static password migration failed", "error", migrateErr)
		} else if migrated > 0 {
			a.log.Info("migrated static password entries", "count", migrated)
		}
	}

	// Start password expiry checker (1-hour interval).
	if a.staticpwStore != nil {
		a.expiryChecker = staticpw.NewExpiryChecker(a.staticpwStore, time.Hour, func(pw *staticpw.StaticPassword) {
			a.log.Info("expired password auto-deleted", "id", pw.ID, "name", pw.Name)
			wailsruntime.EventsEmit(a.ctx, "password:expired", map[string]string{
				"id":   pw.ID,
				"name": pw.Name,
			})
		})
		a.expiryChecker.Start()
	}

	// Start the virtual FIDO2 HID device if enabled and storage is available.
	if a.config.FIDO2AuthenticatorEnabled && a.fido2Storage != nil {
		if err := a.fido2DeviceService.Start(a.fido2Storage, a.deviceNotifier); err != nil {
			a.log.Warn("FIDO2 virtual device unavailable", "error", err)
		}
	} else if a.config.FIDO2AuthenticatorEnabled && a.fido2Storage == nil {
		a.fido2DeviceService.SetLastError("FIDO2 storage initialization failed")
	} else if !a.config.FIDO2AuthenticatorEnabled {
		a.fido2DeviceService.SetLastError("authenticator disabled in settings")
	}

	// Start IPC server for native messaging host and PKCS#11 module.
	a.startIPCServer()
}

// initPINService creates a pin.Service with the appropriate backend and
// wires it to the GUI PINService. Prefers TPM2 when available, falls back
// to software-based PIN management.
//
// Backend selection uses two signals:
//  1. In-session: PlatformKeyStore.IsAuthReady() (set when Initialize/ensureSRKAuth
//     succeeds during the wizard)
//  2. Across restarts: GUIConfig.PINStrategy (persisted after first successful selection)
//
// An SRK from a prior TPM owner may exist (IsInitialized=true) but have unknown
// auth. Using IsInitialized alone would select TPM2 and break every PIN check.
func (a *App) initPINService() {
	if a.dataDir == "" {
		a.log.Warn("initPINService: dataDir not set, skipping")
		return
	}

	var backend pin.PINBackend

	// Try TPM2 backend if the TPM is available and the SRK exists.
	tpmImpl, err := a.tpmAccessor.Acquire()
	if err == nil {
		a.tpmAccessor.Release()
		pks := tpmImpl.PlatformKeyStore()
		if pks != nil && pks.IsInitialized() {
			useTPM2 := false

			if pks.IsAuthReady() {
				// Auth was confirmed this session (wizard just ran).
				useTPM2 = true
			} else if a.config.PINStrategy == "tpm2" {
				// A prior session confirmed TPM2 auth — restore that state.
				pks.SetAuthReady(true)
				useTPM2 = true
			}

			if useTPM2 {
				backend = pin.NewTPM2Backend(pks.(*tpm2pkg.PlatformKeyStore))
				a.log.Info("PIN backend: TPM2 (SRK password auth)")
			} else {
				a.log.Warn("PIN backend: TPM2 SRK exists but auth not confirmed, falling back to software")
			}
		}
	}

	// Fall back to software backend.
	if backend == nil {
		pinDir := filepath.Join(a.dataDir, "pin")
		if mkErr := os.MkdirAll(pinDir, 0700); mkErr != nil {
			a.log.Error("initPINService: failed to create PIN directory", "error", mkErr)
			return
		}
		fileStore, fsErr := filestorage.New(pinDir)
		if fsErr != nil {
			a.log.Error("initPINService: failed to create PIN file storage", "error", fsErr)
			return
		}
		hashConfig := pin.AutoDetectHashConfig()
		var swErr error
		backend, swErr = pin.NewSoftwareBackend(fileStore, hashConfig)
		if swErr != nil {
			a.log.Error("initPINService: failed to create software PIN backend", "error", swErr)
			return
		}
		a.log.Info("PIN backend: software (Argon2id/PBKDF2)")
	}

	// Persist the selected strategy so restarts use the same backend.
	strategyID := string(backend.Strategy())
	if a.config.PINStrategy != strategyID {
		a.config.PINStrategy = strategyID
		if saveErr := SaveGUIConfig(a.config); saveErr != nil {
			a.log.Warn("initPINService: failed to persist PIN strategy", "error", saveErr)
		}
	}

	svc := pin.NewService(backend, a.log)

	// Wire FIDO2 hash setter so PIN changes propagate to the authenticator.
	svc.SetFIDO2HashSetter(func(hash []byte) {
		if a.authenticatorInstance != nil {
			a.authenticatorInstance.SetFIDO2PINHash(hash)
		}
	})

	a.pinService.SetPINService(svc)
	a.log.Info("PIN service initialized", "strategy", strategyID)
}

// ToggleFIDO2Authenticator enables or disables the virtual FIDO2 HID
// authenticator at runtime and persists the preference to the GUI config.
func (a *App) ToggleFIDO2Authenticator(enabled bool) error {
	if enabled && !a.fido2DeviceService.IsRunning() {
		if a.fido2Storage == nil {
			return ErrFIDO2StorageUnavailable
		}
		// Start synchronously so the caller (and frontend GetStatus check)
		// sees the final running/error state. Wails dispatches bound method
		// calls in goroutines, so blocking here is safe.
		if err := a.fido2DeviceService.Start(a.fido2Storage, a.deviceNotifier); err != nil {
			a.log.Warn("FIDO2 virtual device start failed", "error", err)
			return err
		}
	} else if !enabled && a.fido2DeviceService.IsRunning() {
		if err := a.fido2DeviceService.Stop(); err != nil {
			return err
		}
	}

	// Persist the preference.
	a.config.FIDO2AuthenticatorEnabled = enabled
	cfg := a.appService.GetConfig()
	updated := *cfg
	updated.FIDO2AuthenticatorEnabled = enabled
	return a.appService.UpdateConfig(&updated)
}

// guiIPCHandler bridges the IPC server to the GUI services. It implements
// ipc.Handler (basic touch/password/status), ipc.AutofillHandler (browser
// extension autofill), and ipc.PairingHandler (extension pairing ceremony),
// allowing the native messaging host and PKCS#11 module to communicate with
// the running GUI application.
type guiIPCHandler struct {
	app *App
}

func (h *guiIPCHandler) HandleTouch() (*ipc.Response, error) {
	return ipc.OKResponse("gui: no pending action"), nil
}

func (h *guiIPCHandler) HandleTypePassword(name string) (*ipc.Response, error) {
	return nil, ipc.ErrHandlerFailed
}

func (h *guiIPCHandler) HandleStatus() (*ipc.Response, error) {
	locked := h.app.appLockService.IsLocked()
	status := "unlocked"
	if locked {
		status = "locked"
	}
	return ipc.OKResponse(status), nil
}

func (h *guiIPCHandler) HandleAutofillSearch(domain string) (*ipc.AutofillResult, error) {
	return h.app.autofillService.HandleAutofillSearch(domain)
}

func (h *guiIPCHandler) HandleAutofillGet(id, challenge string) (*ipc.AutofillResult, error) {
	return h.app.autofillService.HandleAutofillGet(id, challenge)
}

func (h *guiIPCHandler) HandleAutofillTOTP(domain string) (*ipc.AutofillResult, error) {
	return h.app.autofillService.HandleAutofillTOTP(domain)
}

func (h *guiIPCHandler) HandleAutofillTOTPByID(id string) (*ipc.AutofillResult, error) {
	return h.app.autofillService.HandleAutofillTOTPByID(id)
}

func (h *guiIPCHandler) HandleAutofillStatus() (*ipc.AutofillResult, error) {
	return h.app.autofillService.HandleAutofillStatus()
}

func (h *guiIPCHandler) HandleAutofillPolicy() (*ipc.AutofillResult, error) {
	return h.app.autofillService.HandleAutofillPolicy()
}

func (h *guiIPCHandler) HandleAutofillSave(domain, username, password, title string) (*ipc.AutofillResult, error) {
	return h.app.autofillService.HandleAutofillSave(domain, username, password, title)
}

func (h *guiIPCHandler) HandleAutofillIgnoreDomain(domain string) (*ipc.AutofillResult, error) {
	return h.app.autofillService.HandleAutofillIgnoreDomain(domain)
}

// HandleAutofillFocus implements ipc.AutofillHandler by bringing the GUI
// window to the foreground. This allows the browser extension to request
// the xKey window be raised when the user needs to interact with it
// (e.g., to unlock the app before an autofill can proceed).
func (h *guiIPCHandler) HandleAutofillFocus() (*ipc.AutofillResult, error) {
	h.app.ShowWindow()
	return &ipc.AutofillResult{}, nil
}

// HandleUnlock implements ipc.UnlockHandler by delegating to AppLockService.
// This allows the browser extension to unlock the app via IPC using the user PIN.
func (h *guiIPCHandler) HandleUnlock(pin string) (*ipc.UnlockResult, error) {
	if err := h.app.appLockService.Unlock(pin); err != nil {
		return &ipc.UnlockResult{Success: false, Error: err.Error()}, nil
	}
	h.app.log.Info("app unlocked via IPC (browser extension)")
	return &ipc.UnlockResult{Success: true}, nil
}

// HandlePairingNotifyCode receives a pairing code from the native messaging
// host via IPC and emits an extension:pairing_request event so the frontend
// dialog displays the 6-digit code to the user.
func (h *guiIPCHandler) HandlePairingNotifyCode(code, identityKey, origin string) error {
	h.app.log.Info("IPC: pairing code received from native host",
		"code_len", len(code),
		"origin", origin,
		"has_identity_key", identityKey != "",
	)

	h.app.EmitEvent(events.NewEvent(events.EventExtensionPairingRequest, events.ExtensionPairingRequestPayload{
		Code:   code,
		Origin: origin,
	}))

	h.app.log.Info("IPC: pairing request event emitted to frontend")
	return nil
}

// HandlePairingCompleted is called by the native messaging host after the
// extension submits the correct pairing code. It emits an extension:paired
// event so the frontend dialog transitions to the success state and closes.
func (h *guiIPCHandler) HandlePairingCompleted(origin string) error {
	h.app.log.Info("IPC: pairing completed notification received", "origin", origin)

	h.app.EmitEvent(events.NewEvent(events.EventExtensionPaired, events.ExtensionPairedPayload{
		Origin: origin,
	}))

	h.app.log.Info("IPC: pairing completed event emitted to frontend")
	return nil
}

// startIPCServer starts the Unix domain socket IPC server so the native
// messaging host and PKCS#11 module can communicate with the GUI.
func (a *App) startIPCServer() {
	// Guard against double-start (e.g., if PostBarrierUnseal runs after
	// normal startup already started the IPC server).
	if a.ipcServer != nil {
		a.log.Debug("IPC server already running, skipping start")
		return
	}

	socketPath := ipc.DefaultSocketPath()
	handler := &guiIPCHandler{app: a}

	srv, err := ipc.NewServer(socketPath, handler, a.log)
	if err != nil {
		// If another IPC server is already listening on the socket, it is
		// likely a stale process from a previous unclean shutdown. Since
		// the current GUI instance is authoritative, forcefully remove the
		// socket and retry. Any clients connected to the old socket will
		// get connection errors and reconnect to the new instance.
		if errors.Is(err, ipc.ErrSocketCreateFailed) {
			a.log.Warn("IPC socket held by another process, taking over", "socket", socketPath)
			if removeErr := os.Remove(socketPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				a.log.Error("failed to remove stale IPC socket", "error", removeErr)
				return
			}
			srv, err = ipc.NewServer(socketPath, handler, a.log)
		}
		if err != nil {
			a.log.Warn("IPC server unavailable", "error", err)
			return
		}
	}
	a.ipcServer = srv
	srv.SetAuditLogger(a.auditStore)
	a.pairingService.SetIPCProvider(srv)

	go func() {
		if serveErr := srv.Serve(a.ctx); serveErr != nil && !errors.Is(serveErr, ipc.ErrServerClosed) {
			a.log.Error("IPC server error", "error", serveErr)
		}
	}()

	a.log.Info("IPC server started", "socket", socketPath)
}

// shutdown is the Wails OnShutdown lifecycle callback.
func (a *App) shutdown(ctx context.Context) {
	a.shutdownOnce.Do(func() {
		a.log.Info("xKey GUI shutting down")
		a.running.Store(false)

		// Each step has its own timeout to prevent any single operation
		// from blocking the entire shutdown sequence.

		shutdownStep(a.log, "reseal", 3*time.Second, func() error {
			if a.config.AutoUnsealEnabled && a.config.AutoUnsealBlobID != "" {
				return a.autoUnsealService.Reseal()
			}
			return nil
		})

		shutdownStep(a.log, "barrier-seal", 1*time.Second, func() error {
			if a.barrierService != nil {
				return a.barrierService.Seal()
			}
			return nil
		})

		shutdownStep(a.log, "screen-lock-monitor", 1*time.Second, func() error {
			if a.screenLockMonitor != nil {
				return a.screenLockMonitor.Close()
			}
			return nil
		})

		shutdownStep(a.log, "tpm-accessor", 2*time.Second, func() error {
			if a.tpmAccessor != nil {
				a.tpmAccessor.Shutdown()
			}
			return nil
		})

		shutdownStep(a.log, "phone-disconnect", 1*time.Second, func() error {
			if a.phoneService.IsConnected() {
				return a.phoneService.Disconnect(a.phoneService.ConnectedDeviceName())
			}
			return nil
		})

		shutdownStep(a.log, "agent-server-stop", 1*time.Second, func() error {
			status := a.agentService.GetServerStatus()
			if status != nil && status.Running {
				return a.agentService.StopServer()
			}
			return nil
		})

		shutdownStep(a.log, "ipc-server-stop", 1*time.Second, func() error {
			if a.ipcServer != nil {
				return a.ipcServer.Close()
			}
			return nil
		})

		shutdownStep(a.log, "fido2-stop", 1*time.Second, func() error {
			if a.fido2DeviceService.IsRunning() {
				return a.fido2DeviceService.Stop()
			}
			return nil
		})

		shutdownStep(a.log, "server-disconnect", 1*time.Second, func() error {
			if a.connectionService.IsConnected() {
				return a.connectionService.Disconnect()
			}
			return nil
		})

		shutdownStep(a.log, "notifications", 1*time.Second, func() error {
			return a.notificationService.Close()
		})

		shutdownStep(a.log, "oidc", 1*time.Second, func() error {
			return a.oidcService.Close()
		})

		if a.expiryChecker != nil {
			a.expiryChecker.Stop()
		}

		shutdownStep(a.log, "luks-lock", 3*time.Second, func() error {
			status, sErr := a.storageService.GetStatus()
			if sErr != nil || !status.IsMounted {
				return nil
			}
			a.log.Info("locking LUKS encrypted volume")
			return a.storageService.LockVolume()
		})

		// Close storage backends.
		if a.oathStore != nil {
			_ = a.oathStore.Close()
		}
		if closer, ok := a.fido2Storage.(interface{ Close() error }); ok && closer != nil {
			_ = closer.Close()
		}
		if a.staticpwStore != nil {
			_ = a.staticpwStore.Close()
		}
		if a.trustStore != nil {
			_ = a.trustStore.Close()
		}

		// Close the backend registry.
		if a.backendRegistry != nil {
			_ = a.backendRegistry.Close()
		}

		// Close TPM if it was initialized.
		shutdownStep(a.log, "tpm-close", 2*time.Second, func() error {
			a.tpmMu.Lock()
			defer a.tpmMu.Unlock()
			if a.tpmInstance != nil {
				if err := a.tpmInstance.Close(); err != nil {
					a.log.Warn("failed to close TPM", "error", err)
				}
				a.tpmInstance = nil
			}
			a.tpmUnavailable = false
			a.tpmConfigOnce = sync.Once{}
			if a.tpmStorageFactory != nil {
				if err := a.tpmStorageFactory.Close(); err != nil {
					a.log.Warn("failed to close TPM storage factory", "error", err)
				}
				a.tpmStorageFactory = nil
			}
			return nil
		})

		close(a.shutdownDone)
	})
}

// shutdownStep runs fn in a goroutine with a per-step timeout. If the step
// takes longer than the timeout, it logs a warning and continues.
func shutdownStep(log *slog.Logger, name string, timeout time.Duration, fn func() error) {
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		if err != nil {
			log.Warn("shutdown step failed", "step", name, "error", err)
		}
	case <-time.After(timeout):
		log.Warn("shutdown step timed out", "step", name, "timeout", timeout)
	}
}

// EmitEvent sends an event to the frontend via the Wails runtime.
func (a *App) EmitEvent(event events.Event) {
	if a.ctx == nil {
		a.log.Warn("cannot emit event: application not initialized")
		return
	}
	wailsruntime.EventsEmit(a.ctx, string(event.Type), event)
}

// GetStatus returns the current application status.
func (a *App) GetStatus() *services.AppStatus {
	return a.appService.GetStatus()
}

// GetConfig returns the current GUI configuration data.
func (a *App) GetConfig() *services.GUIConfigData {
	return a.appService.GetConfig()
}

// UpdateConfig replaces the GUI configuration and persists it.
func (a *App) UpdateConfig(cfg *services.GUIConfigData) error {
	return a.appService.UpdateConfig(cfg)
}

// GetTheme returns the current theme name.
func (a *App) GetTheme() string {
	return a.appService.GetTheme()
}

// SetTheme updates the theme and persists the configuration.
func (a *App) SetTheme(theme string) error {
	if err := a.appService.SetTheme(theme); err != nil {
		return err
	}
	a.EmitEvent(events.NewEvent(events.EventSettingsChanged, map[string]string{
		"key":   "theme",
		"value": theme,
	}))
	return nil
}

// Quit terminates the application. It sets the trayQuit flag so that
// beforeClose allows the quit through when AutoTray is enabled, then
// runs the shutdown sequence directly and exits. The shutdown is
// protected by sync.Once so it is safe if Wails also calls OnShutdown.
func (a *App) Quit() {
	if a.ctx == nil {
		return
	}

	a.log.Info("quit requested")
	a.trayQuit.Store(true)

	// Show the window and emit a shutting-down event so the frontend
	// can display a shutdown overlay with progress feedback.
	a.ShowWindow()
	wailsruntime.EventsEmit(a.ctx, "app:shutting_down", nil)

	// Safety-net: force exit if shutdown takes too long. Individual
	// steps have their own timeouts, but this ensures we always exit.
	go func() {
		time.Sleep(5 * time.Second)
		a.log.Warn("shutdown timed out after 5s, forcing exit")
		os.Exit(1)
	}()

	a.shutdown(a.ctx)
	os.Exit(0)
}

// installSignalHandler registers a goroutine that catches SIGTERM,
// SIGINT, and SIGHUP to run the shutdown sequence before exiting.
// This ensures the LUKS volume is locked and auto-unseal data is
// re-sealed even when the process is terminated by the OS or a
// service manager.
func (a *App) installSignalHandler() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		sig := <-sigCh
		a.log.Warn("received signal, initiating shutdown", "signal", sig)
		a.shutdown(a.ctx)
		os.Exit(0)
	}()
}

// ShowWindow brings the main window to the foreground and centers it.
// On Linux, WindowShow alone doesn't raise the window due to focus-stealing
// prevention. Setting AlwaysOnTop forces the window manager to activate it;
// the flag is cleared after a short delay so the WM has time to process
// the activation before we remove the hint.
func (a *App) ShowWindow() {
	if a.ctx == nil {
		return
	}
	wailsruntime.WindowUnminimise(a.ctx)
	wailsruntime.WindowShow(a.ctx)
	wailsruntime.WindowCenter(a.ctx)
	wailsruntime.WindowSetAlwaysOnTop(a.ctx, true)
	// Clear always-on-top after a delay so the window manager has time
	// to activate and focus the window before the hint is removed.
	go func() {
		time.Sleep(250 * time.Millisecond)
		if a.ctx != nil {
			wailsruntime.WindowSetAlwaysOnTop(a.ctx, false)
		}
	}()
}

// HideWindow hides the main window (minimize to tray if auto-tray).
func (a *App) HideWindow() {
	if a.ctx == nil {
		return
	}
	wailsruntime.WindowHide(a.ctx)
}

// detectEKHandle probes the TPM for the Endorsement Key at the two standard
// TCG persistent handles: 0x81010001 (RSA 2048) and 0x81010002 (ECC P-256).
// Returns the handle of the first one found, or 0 if neither exists.
func detectEKHandle(log *slog.Logger, device string) uint32 {
	f, err := os.OpenFile(device, os.O_RDWR, 0)
	if err != nil {
		return 0
	}
	defer f.Close()

	t := tpmtransport.FromReadWriter(f)

	// TCG standard persistent EK handles.
	handles := []uint32{0x81010001, 0x81010002}
	for _, h := range handles {
		_, err := tpm2lib.ReadPublic{
			ObjectHandle: tpm2lib.TPMHandle(h),
		}.Execute(t)
		if err == nil {
			log.Debug("detected EK handle", "handle", fmt.Sprintf("0x%08X", h))
			return h
		}
	}

	log.Debug("no standard EK handle found")
	return 0
}

// loadTPMConfig loads TPM configuration from the xKey config file.
// Uses the unified xhome path resolution to locate config.yaml.
// Falls back to DefaultConfig if no config file is found.
func loadTPMConfig(logger *slog.Logger) tpm2pkg.Config {
	cfg := tpm2pkg.DefaultConfig

	h, err := xhome.Resolve()
	if err != nil {
		logger.Debug("cannot resolve xKey home for config, using defaults", "error", err)
		return cfg
	}

	configPath := h.ConfigPath()
	if _, err := os.Stat(configPath); err != nil {
		logger.Debug("no config file found, using TPM defaults", "path", configPath)
		return cfg
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		logger.Warn("failed to read config file, using defaults",
			"path", configPath, "error", err)
		return cfg
	}

	// Parse the full config file to extract the "tpm" section.
	var fileConfig struct {
		TPM tpm2pkg.Config `yaml:"tpm"`
	}
	if err := yaml.Unmarshal(data, &fileConfig); err != nil {
		logger.Warn("failed to parse config file, using defaults",
			"path", configPath, "error", err)
		return cfg
	}

	merged := mergeTPMConfig(cfg, fileConfig.TPM)
	logger.Info("loaded TPM config from file", "path", configPath)
	return merged
}

// mergeTPMConfig overlays non-zero fields from file onto defaults.
// wrapYubiKeyProvider is set by the pkcs11 build tag to wrap a PKCS#11
// KeyProvider with YubiKey-specific behavior (SO login for key generation).
// Returns nil if the provider cannot be wrapped.
var wrapYubiKeyProvider func(inner types.KeyProvider) types.KeyProvider

// isYubiKeyLibrary returns true if the library path points to a YubiKey
// PKCS#11 module (libykcs11).
func isYubiKeyLibrary(libraryPath string) bool {
	return strings.Contains(libraryPath, "ykcs11")
}

func mergeTPMConfig(defaults, file tpm2pkg.Config) tpm2pkg.Config {
	cfg := defaults

	if file.Device != "" {
		cfg.Device = file.Device
	}
	if file.Hash != "" {
		cfg.Hash = file.Hash
	}
	cfg.EncryptSession = file.EncryptSession
	cfg.UseSimulator = file.UseSimulator
	cfg.UseEntropy = file.UseEntropy

	if file.PlatformPCRBank != "" {
		cfg.PlatformPCRBank = file.PlatformPCRBank
	}
	if file.PlatformPCR != 0 {
		cfg.PlatformPCR = file.PlatformPCR
	}
	if len(file.GoldenPCRs) > 0 {
		cfg.GoldenPCRs = file.GoldenPCRs
	}

	// Sub-configs: merge field-by-field so partial YAML entries don't zero
	// out critical defaults like CertHandle.
	if file.EK != nil {
		if cfg.EK == nil {
			cfg.EK = file.EK
		} else {
			if file.EK.Handle != 0 {
				cfg.EK.Handle = file.EK.Handle
			}
			if file.EK.CertHandle != 0 {
				cfg.EK.CertHandle = file.EK.CertHandle
			}
			if file.EK.KeyAlgorithm != "" {
				cfg.EK.KeyAlgorithm = file.EK.KeyAlgorithm
			}
			if file.EK.HierarchyAuth != "" {
				cfg.EK.HierarchyAuth = file.EK.HierarchyAuth
			}
			if file.EK.RSAConfig != nil {
				cfg.EK.RSAConfig = file.EK.RSAConfig
			}
			if file.EK.ECCConfig != nil {
				cfg.EK.ECCConfig = file.EK.ECCConfig
			}
			cfg.EK.Debug = file.EK.Debug
		}
	}
	if file.SSRK != nil {
		cfg.SSRK = file.SSRK
	}
	if file.PlatformSRK != nil {
		cfg.PlatformSRK = file.PlatformSRK
	}
	if file.IAK != nil {
		cfg.IAK = file.IAK
	}
	if file.IDevID != nil {
		cfg.IDevID = file.IDevID
	}

	return cfg
}

// Run is a package-level convenience that creates an App from the loaded
// config and starts the Wails application.
func Run() error {
	cfg, err := LoadGUIConfig()
	if err != nil {
		cfg = DefaultGUIConfig()
	}
	// Apply firmware version from build-time version string.
	if FirmwareVersion > 0 {
		cfg.FIDO2FirmwareVersion = FirmwareVersion
	}
	app := NewApp(cfg)
	return app.Run()
}

// barrierAutoUVProvider implements keybackend.BarrierStateProvider by
// checking whether the barrier service is currently unsealed.
type barrierAutoUVProvider struct {
	barrier *services.BarrierService
}

// IsAutoUVActive returns true when the barrier is unsealed, meaning
// built-in user verification should be reported to FIDO2 clients.
func (p *barrierAutoUVProvider) IsAutoUVActive() bool {
	return p.barrier.IsUnsealed()
}

// Compile-time check.
var _ keybackend.BarrierStateProvider = (*barrierAutoUVProvider)(nil)
