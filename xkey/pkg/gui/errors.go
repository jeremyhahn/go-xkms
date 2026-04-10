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

// Package gui provides the Wails v2 desktop GUI backend for xKey.
package gui

import "errors"

// GUI operation errors.
var (
	// ErrWindowCreate indicates the application window could not be created.
	ErrWindowCreate = errors.New("gui: failed to create window")

	// ErrWindowShow indicates the application window could not be shown.
	ErrWindowShow = errors.New("gui: failed to show window")

	// ErrWindowHide indicates the application window could not be hidden.
	ErrWindowHide = errors.New("gui: failed to hide window")

	// ErrConfigLoad indicates the GUI configuration could not be loaded.
	ErrConfigLoad = errors.New("gui: failed to load configuration")

	// ErrConfigSave indicates the GUI configuration could not be saved.
	ErrConfigSave = errors.New("gui: failed to save configuration")

	// ErrServiceStart indicates a GUI service could not be started.
	ErrServiceStart = errors.New("gui: failed to start service")

	// ErrServiceStop indicates a GUI service could not be stopped.
	ErrServiceStop = errors.New("gui: failed to stop service")

	// ErrTraySetup indicates the system tray could not be configured.
	ErrTraySetup = errors.New("gui: failed to setup system tray")

	// ErrTrayIconLoad indicates the system tray icon could not be loaded.
	ErrTrayIconLoad = errors.New("gui: failed to load tray icon")

	// ErrEventEmit indicates an event could not be emitted to the frontend.
	ErrEventEmit = errors.New("gui: failed to emit event")

	// ErrNotInitialized indicates the GUI application has not been initialized.
	ErrNotInitialized = errors.New("gui: application not initialized")

	// ErrInvalidTheme indicates the specified theme is not recognized.
	ErrInvalidTheme = errors.New("gui: invalid theme")

	// ErrAlreadyRunning indicates the GUI application is already running.
	ErrAlreadyRunning = errors.New("gui: application already running")

	// ErrShutdown indicates the GUI application is shutting down.
	ErrShutdown = errors.New("gui: application shutting down")

	// ErrInvalidProtocol indicates the server protocol is not recognized.
	ErrInvalidProtocol = errors.New("gui: invalid server protocol")

	// ErrFIDO2StorageUnavailable indicates the FIDO2 credential storage is not available.
	ErrFIDO2StorageUnavailable = errors.New("gui: FIDO2 credential storage unavailable")

	// ErrDataDirInit indicates data directory initialization failed.
	ErrDataDirInit = errors.New("gui: data directory initialization failed")

	// ErrDataDirAlreadyInit indicates data directory was already initialized.
	ErrDataDirAlreadyInit = errors.New("gui: data directory already initialized")

	// ErrBarrierStillSealed indicates the barrier is still sealed when an
	// unseal is required for the operation.
	ErrBarrierStillSealed = errors.New("gui: barrier is still sealed")
)

// validThemes is the set of recognized theme values.
var validThemes = map[string]struct{}{
	ThemeLight:  {},
	ThemeDark:   {},
	ThemeSystem: {},
}

// ValidateTheme checks whether a theme string is a recognized value.
func ValidateTheme(theme string) error {
	if _, ok := validThemes[theme]; !ok {
		return ErrInvalidTheme
	}
	return nil
}
