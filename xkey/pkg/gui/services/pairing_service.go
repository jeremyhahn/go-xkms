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
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/nativemsg"
)

// PairingService errors.
var (
	// ErrPairingNotConfigured indicates the PairingVerifier has not been set.
	ErrPairingNotConfigured = errors.New("pairing_service: verifier not configured")

	// ErrPairingFailed indicates the pairing operation failed.
	ErrPairingFailed = errors.New("pairing_service: pairing failed")

	// ErrPairingInvalidIdentityKey indicates an empty or invalid base64 identity key.
	ErrPairingInvalidIdentityKey = errors.New("pairing_service: invalid identity key")

	// ErrPairingInvalidOrigin indicates an empty extension origin.
	ErrPairingInvalidOrigin = errors.New("pairing_service: invalid origin")

	// ErrPairingInvalidCode indicates an empty pairing code.
	ErrPairingInvalidCode = errors.New("pairing_service: invalid code")

	// ErrManifestInstallFailed indicates the native messaging manifest could
	// not be installed.
	ErrManifestInstallFailed = errors.New("pairing_service: manifest install failed")

	// ErrManifestUninstallFailed indicates the native messaging manifest could
	// not be uninstalled.
	ErrManifestUninstallFailed = errors.New("pairing_service: manifest uninstall failed")

	// ErrManifestInvalidBrowser indicates the browser argument is not recognized.
	ErrManifestInvalidBrowser = errors.New("pairing_service: invalid browser")
)

// PairingStatus describes the current extension pairing state for the frontend.
type PairingStatus struct {
	Paired   bool   `json:"paired"`
	Origin   string `json:"origin,omitempty"`
	PairedAt string `json:"paired_at,omitempty"` // ISO 8601
}

// ManifestInfo describes the installation status of a native messaging manifest.
type ManifestInfo struct {
	Browser   string `json:"browser"`
	Name      string `json:"name"` // Display name (e.g., "Chrome", "Brave", "Firefox")
	Installed bool   `json:"installed"`
	Path      string `json:"path"`
}

// ExtensionFullStatus combines IPC server state, manifest installation,
// and pairing state into a single response for the frontend status widget.
type ExtensionFullStatus struct {
	IPCRunning       bool             `json:"ipc_running"`
	IPCSocketPath    string           `json:"ipc_socket_path"`
	PairedExtensions []*PairingStatus `json:"paired_extensions"`
	Manifests        []ManifestInfo   `json:"manifests"`
}

// IPCStatusProvider abstracts IPC server status checks so the pairing
// service does not depend on the ipc package directly.
type IPCStatusProvider interface {
	IsRunning() bool
	SocketPath() string
}

// PairingService manages browser extension pairing for the GUI. It wraps
// the nativemsg.PairingVerifier and emits Wails events so the Svelte
// frontend can react to pairing state changes in real time.
//
// All exported methods are safe for concurrent use.
type PairingService struct {
	ctx         context.Context
	log         *slog.Logger
	verifier    *nativemsg.PairingVerifier
	ipcProvider IPCStatusProvider
	emitter     func(events.Event)
	mu          sync.RWMutex
	auditLog    atomic.Pointer[audit.Logger]
}

// NewPairingService creates a new PairingService with the given logger.
func NewPairingService(log *slog.Logger) *PairingService {
	if log == nil {
		log = slog.Default()
	}
	return &PairingService{
		log: log.With("component", "pairing_service"),
	}
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *PairingService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetVerifier injects the PairingVerifier that manages the underlying
// pairing state and cryptographic verification.
func (s *PairingService) SetVerifier(v *nativemsg.PairingVerifier) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifier = v
}

// SetIPCProvider injects the IPC server status provider.
func (s *PairingService) SetIPCProvider(p IPCStatusProvider) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ipcProvider = p
}

// SetEventEmitter sets the event callback for frontend notifications.
func (s *PairingService) SetEventEmitter(fn func(events.Event)) {
	s.emitter = fn
}

// SetAuditLogger sets the audit logger for security event logging.
func (s *PairingService) SetAuditLogger(l audit.Logger) {
	s.auditLog.Store(&l)
}

// logPairingEvent logs a pairing-related audit event.
func (s *PairingService) logPairingEvent(op audit.OperationType, success bool, err error, details map[string]any) {
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

// IsPaired returns true if an extension is currently paired.
// Reloads from disk to detect pairings from external processes.
func (s *PairingService) IsPaired() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.verifier == nil {
		return false
	}
	_ = s.verifier.Reload()
	return s.verifier.IsPaired()
}

// GetPairingStatus returns the current pairing state for the frontend.
// If no verifier is configured or no extension is paired, it returns
// an unpaired status. For multi-browser support, use GetPairedExtensions.
func (s *PairingService) GetPairingStatus() *PairingStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getPairingStatusLocked()
}

// GetPairedExtensions returns the pairing status for all paired extensions.
// Returns an empty slice if no extensions are paired or verifier is not set.
func (s *PairingService) GetPairedExtensions() []*PairingStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getPairedExtensionsLocked()
}

// RequestPairing starts a new pairing ceremony by generating a 6-digit
// verification code. The identity key must be provided as base64-encoded
// Ed25519 public key. Returns the code to be displayed in the GUI and
// emits an "extension:pairing_request" event.
func (s *PairingService) RequestPairing(identityKeyBase64, origin string) (string, error) {
	if identityKeyBase64 == "" {
		return "", ErrPairingInvalidIdentityKey
	}
	if origin == "" {
		return "", ErrPairingInvalidOrigin
	}

	identityKey, err := base64.StdEncoding.DecodeString(identityKeyBase64)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrPairingInvalidIdentityKey, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.verifier == nil {
		return "", ErrPairingNotConfigured
	}

	code, err := s.verifier.StartPairing(identityKey, origin)
	if err != nil {
		s.log.Error("failed to start pairing",
			"origin", origin,
			"error", err,
		)
		s.logPairingEvent(audit.OpPairingStarted, false, err, map[string]any{"origin": origin})
		return "", fmt.Errorf("%w: %w", ErrPairingFailed, err)
	}

	s.log.Info("pairing ceremony started",
		"origin", origin,
	)

	s.emit(events.EventExtensionPairingRequest, events.ExtensionPairingRequestPayload{
		Code:   code,
		Origin: origin,
	})

	s.logPairingEvent(audit.OpPairingStarted, true, nil, map[string]any{"origin": origin})
	return code, nil
}

// VerifyPairingCode validates the user-entered pairing code against the
// pending ceremony. On success the extension identity is persisted and
// an "extension:paired" event is emitted.
func (s *PairingService) VerifyPairingCode(identityKeyBase64, origin, code string) error {
	if identityKeyBase64 == "" {
		return ErrPairingInvalidIdentityKey
	}
	if origin == "" {
		return ErrPairingInvalidOrigin
	}
	if code == "" {
		return ErrPairingInvalidCode
	}

	identityKey, err := base64.StdEncoding.DecodeString(identityKeyBase64)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPairingInvalidIdentityKey, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.verifier == nil {
		return ErrPairingNotConfigured
	}

	if err := s.verifier.CompletePairing(identityKey, origin, code); err != nil {
		s.log.Error("pairing verification failed",
			"origin", origin,
			"error", err,
		)
		s.logPairingEvent(audit.OpPairingFailed, false, err, map[string]any{"origin": origin})
		return fmt.Errorf("%w: %w", ErrPairingFailed, err)
	}

	s.log.Info("extension paired successfully",
		"origin", origin,
	)

	s.emit(events.EventExtensionPaired, events.ExtensionPairedPayload{
		Origin: origin,
	})

	s.logPairingEvent(audit.OpPairingCompleted, true, nil, map[string]any{"origin": origin})
	return nil
}

// Unpair removes a paired extension identity and emits an "extension:unpaired"
// event. If origin is empty, all extensions are unpaired. If origin is specified,
// only that specific extension is unpaired.
func (s *PairingService) Unpair(origin string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.verifier == nil {
		return ErrPairingNotConfigured
	}

	var err error
	if origin == "" {
		err = s.verifier.UnpairAll()
	} else {
		err = s.verifier.UnpairOrigin(origin)
	}

	if err != nil {
		s.log.Error("failed to unpair extension",
			"origin", origin,
			"error", err,
		)
		s.logPairingEvent(audit.OpPairingUnpaired, false, err, map[string]any{"origin": origin})
		return fmt.Errorf("%w: %w", ErrPairingFailed, err)
	}

	s.log.Info("extension unpaired", "origin", origin)
	s.logPairingEvent(audit.OpPairingUnpaired, true, nil, map[string]any{"origin": origin})

	s.emit(events.EventExtensionUnpaired, events.ExtensionPairedPayload{
		Origin: origin,
	})

	return nil
}

// GetExtensionFullStatus returns the combined status of the IPC server,
// native messaging manifests, and extension pairing for the GUI status
// widget. This is the single source of truth for the frontend to display
// extension connectivity.
//
// The verifier is reloaded from disk before reading state so the GUI
// picks up pairings completed by external native host processes.
func (s *PairingService) GetExtensionFullStatus() *ExtensionFullStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Reload pairing state from disk so that pairings completed by
	// external native host processes (e.g., Firefox host) are visible.
	if s.verifier != nil {
		if err := s.verifier.Reload(); err != nil {
			s.log.Warn("failed to reload pairing state", "error", err)
		}
	}

	status := &ExtensionFullStatus{
		PairedExtensions: s.getPairedExtensionsLocked(),
	}

	// IPC server status.
	if s.ipcProvider != nil {
		status.IPCRunning = s.ipcProvider.IsRunning()
		status.IPCSocketPath = s.ipcProvider.SocketPath()
	}

	// Native messaging manifests.
	manifests := nativemsg.GetManifestStatus()
	status.Manifests = make([]ManifestInfo, len(manifests))
	for i, m := range manifests {
		status.Manifests[i] = ManifestInfo{
			Browser:   string(m.Browser),
			Name:      m.Name,
			Installed: m.Installed,
			Path:      m.Path,
		}
	}

	return status
}

// parseBrowser converts a user-facing browser string to nativemsg.Browser.
// Accepted values: "chrome", "firefox" (case-insensitive).
func parseBrowser(browser string) (nativemsg.Browser, error) {
	switch strings.ToLower(strings.TrimSpace(browser)) {
	case "chrome":
		return nativemsg.BrowserChrome, nil
	case "firefox":
		return nativemsg.BrowserFirefox, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrManifestInvalidBrowser, browser)
	}
}

// InstallManifest installs the native messaging manifest for the specified
// browser. The browser parameter accepts "chrome", "firefox", or "all"
// (case-insensitive). The xkey binary path is resolved via os.Executable().
//
// For "chrome", manifests are auto-installed for all detected Chromium-based
// browsers (Chrome, Brave, Chromium, Edge).
func (s *PairingService) InstallManifest(browser string) error {
	binaryPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("%w: cannot resolve binary path: %v", ErrManifestInstallFailed, err)
	}

	normalized := strings.ToLower(strings.TrimSpace(browser))

	if normalized == "all" {
		var installErr error
		for _, b := range []nativemsg.Browser{nativemsg.BrowserChrome, nativemsg.BrowserFirefox} {
			if err := nativemsg.InstallManifest(b, binaryPath); err != nil {
				s.log.Error("manifest install failed", "browser", b, "error", err)
				installErr = fmt.Errorf("%w: %v", ErrManifestInstallFailed, err)
			} else {
				s.log.Info("manifest installed", "browser", b)
			}
		}
		return installErr
	}

	b, err := parseBrowser(browser)
	if err != nil {
		return err
	}

	if err := nativemsg.InstallManifest(b, binaryPath); err != nil {
		s.log.Error("manifest install failed", "browser", b, "error", err)
		s.logPairingEvent(audit.OpPairingManifest, false, err, map[string]any{"browser": browser, "action": "install"})
		return fmt.Errorf("%w: %v", ErrManifestInstallFailed, err)
	}

	s.log.Info("manifest installed", "browser", b)
	s.logPairingEvent(audit.OpPairingManifest, true, nil, map[string]any{"browser": browser, "action": "install"})
	return nil
}

// UninstallManifest removes the native messaging manifest for the specified
// browser. The browser parameter accepts "chrome", "firefox", or "all"
// (case-insensitive).
//
// For "chrome", manifests are removed from all Chromium-based browser directories.
func (s *PairingService) UninstallManifest(browser string) error {
	normalized := strings.ToLower(strings.TrimSpace(browser))

	if normalized == "all" {
		var uninstallErr error
		for _, b := range []nativemsg.Browser{nativemsg.BrowserChrome, nativemsg.BrowserFirefox} {
			if err := nativemsg.UninstallManifest(b); err != nil {
				if !errors.Is(err, nativemsg.ErrManifestNotFound) {
					s.log.Error("manifest uninstall failed", "browser", b, "error", err)
					uninstallErr = fmt.Errorf("%w: %v", ErrManifestUninstallFailed, err)
				}
			} else {
				s.log.Info("manifest uninstalled", "browser", b)
			}
		}
		return uninstallErr
	}

	b, err := parseBrowser(browser)
	if err != nil {
		return err
	}

	if err := nativemsg.UninstallManifest(b); err != nil {
		s.log.Error("manifest uninstall failed", "browser", b, "error", err)
		s.logPairingEvent(audit.OpPairingManifest, false, err, map[string]any{"browser": browser, "action": "uninstall"})
		return fmt.Errorf("%w: %v", ErrManifestUninstallFailed, err)
	}

	s.log.Info("manifest uninstalled", "browser", b)
	s.logPairingEvent(audit.OpPairingManifest, true, nil, map[string]any{"browser": browser, "action": "uninstall"})
	return nil
}

// getPairingStatusLocked returns pairing status for a single extension,
// for backwards compatibility (caller must hold mu).
func (s *PairingService) getPairingStatusLocked() *PairingStatus {
	if s.verifier == nil {
		return &PairingStatus{Paired: false}
	}
	states := s.verifier.GetStates()
	if len(states) == 0 {
		return &PairingStatus{Paired: false}
	}
	// Return the first one for backwards compat.
	for origin, state := range states {
		return &PairingStatus{
			Paired:   true,
			Origin:   origin,
			PairedAt: state.PairedAt.Format(time.RFC3339),
		}
	}
	return &PairingStatus{Paired: false}
}

// getPairedExtensionsLocked returns pairing status for all paired extensions
// (caller must hold mu).
func (s *PairingService) getPairedExtensionsLocked() []*PairingStatus {
	if s.verifier == nil {
		return nil
	}
	states := s.verifier.GetStates()
	result := make([]*PairingStatus, 0, len(states))
	for origin, state := range states {
		result = append(result, &PairingStatus{
			Paired:   true,
			Origin:   origin,
			PairedAt: state.PairedAt.Format(time.RFC3339),
		})
	}
	return result
}

// emit sends an event to the frontend if an emitter is registered.
func (s *PairingService) emit(eventType events.EventType, payload any) {
	if s.emitter != nil {
		s.emitter(events.Event{
			Type:    eventType,
			Payload: payload,
			Time:    time.Now(),
		})
	}
}
